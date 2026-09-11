"""Summarize a benchmark run from stored data (tools container). Reports measurements, never targets."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, "/app/lib")
from sih_common.chttp import ClickHouseHTTP  # noqa: E402


def prom(query: str) -> float | None:
    url = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090") + "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    try:
        data = json.load(urllib.request.urlopen(url, timeout=10))["data"]["result"]
        return float(data[0]["value"][1]) if data else None
    except Exception:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    c = ClickHouseHTTP(os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123"), os.environ.get("CLICKHOUSE_USER", "sih_reader"),
                       pathlib.Path(os.environ["CLICKHOUSE_PASSWORD_FILE"]).read_text().strip())
    out = []
    for line in pathlib.Path(a.runs).read_text().splitlines():
        r = json.loads(line)
        run = r["run_id"]
        stored = c.query(
            "SELECT count() AS n, min(receiver_received_at) AS first, max(receiver_received_at) AS last, "
            "dateDiff('millisecond', min(receiver_received_at), max(receiver_received_at)) AS span_ms "
            "FROM sih.raw_events FINAL WHERE replay_run_id = {r:String}", {"r": run})[0]
        lat = c.query(
            "SELECT count() AS n, quantilesExact(0.5, 0.9, 0.95, 0.99)(d) AS q, max(d) AS max_ms, countIf(d > 5000) AS over_5s "
            "FROM (SELECT dateDiff('millisecond', evidence_received_at, ts) AS d FROM sih.alert_updates FINAL "
            "      WHERE replay_run_id = {r:String} AND status IN ('new', 'escalated'))", {"r": run})[0]
        span_s = max(1e-9, (stored["span_ms"] or 0) / 1000)
        offered = r["rate"] * r["duration_s"]
        out.append({
            "offered_rate_eps": r["rate"], "offered_records": offered, "stored_records": stored["n"],
            "stored_fraction": stored["n"] / offered if offered else None,
            "accepted_rate_eps_over_span": stored["n"] / span_s,
            "detection_latency_ms": {"samples": lat["n"], "p50": (lat["q"] or [None])[0], "p90": (lat["q"] or [None] * 2)[1],
                                     "p95": (lat["q"] or [None] * 3)[2], "p99": (lat["q"] or [None] * 4)[3],
                                     "max": lat["max_ms"] if lat["n"] else None, "over_5s": lat["over_5s"],
                                     "definition": "Flink emission minus receiver arrival of sufficient evidence (new/escalated updates)"},
            "receiver_dropped_total": prom("sum(receiver_dropped_total)"),
            "link_gap_records_total": prom("max(link_gap_records_total)"),
            "max_backpressure_ms_per_s": prom("max(max_over_time(flink_taskmanager_job_task_backPressuredTimeMsPerSecond[15m]))"),
            "note": "single trial; the plan requires warm-up, >=10 min steady state and repeated trials before declaring a sustainable rate",
        })
    pathlib.Path(a.out).write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
