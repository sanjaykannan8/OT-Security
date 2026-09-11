"""End-to-end scenario check against ground-truth manifests (runs in the `tools` container).

    python tests/e2e/check_scenarios.py --runs runs.jsonl --out e2e.json [--timeout 1800]

For each replay run: wait until the sender finished it and every expected episode has a matching alert
(threat class + entity + one of the expected subtypes), then verify absent-expected entities produced no
alert. Reports receiver-to-alert latency from stored timestamps and onset-to-alert in observation time.
Exit code 1 if any check fails. Nothing here asserts real spoofing/malware; it checks observable outcomes.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, "/app/lib")
from sih_common import timeutil  # noqa: E402
from sih_common.chttp import ClickHouseHTTP  # noqa: E402

FIXTURES = pathlib.Path(os.environ.get("FIXTURES_DIR", "/data/fixtures/pcaps"))


def ch() -> ClickHouseHTTP:
    return ClickHouseHTTP(os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123"), os.environ.get("CLICKHOUSE_USER", "sih_reader"),
                          pathlib.Path(os.environ["CLICKHOUSE_PASSWORD_FILE"]).read_text().strip())


def alerts(c, run_id: str) -> list[dict]:
    return c.query("SELECT threat_class, subtype, severity, status, entity_key, update_seq, detection_method, model_version, "
                   "ts, evidence_received_at, observation_time, replay_time_offset_us "
                   "FROM (SELECT *, JSONExtractInt(alert_json, 'replay_time_offset_us') AS replay_time_offset_us "
                   "      FROM sih.alert_updates FINAL WHERE replay_run_id = {r:String}) ORDER BY ts", {"r": run_id})


def raw_count(c, run_id: str) -> int:
    return int(c.query("SELECT count() AS n FROM sih.raw_events FINAL WHERE replay_run_id = {r:String}", {"r": run_id})[0]["n"])


def sender_progress(c, run_id: str) -> dict | None:
    rows = c.query("SELECT JSONExtractInt(record_json, 'replay_records_total') AS total, "
                   "JSONExtractInt(record_json, 'replay_records_sent') AS sent, "
                   "JSONExtractInt(record_json, 'records_invalid_local_total') AS invalid_local "
                   "FROM sih.sensor_health FINAL WHERE JSONExtractString(record_json, 'replay_run_id') = {r:String} "
                   "ORDER BY health_seq DESC LIMIT 1", {"r": run_id})
    return rows[0] if rows else None


def ms(ts: str) -> int:
    return timeutil.parse_us(ts if ts.endswith("Z") else ts + "Z") // 1000


def check_run(c, run: dict, deadline: float) -> dict:
    manifest = json.loads((FIXTURES / f"{run['scenario']}.manifest.json").read_text())
    episodes = manifest["episodes"]
    result = {"run_id": run["run_id"], "scenario": run["scenario"], "episodes": [], "absent": [], "ok": True}
    found: dict[int, dict] = {}
    finished_at = None
    while time.time() < deadline:
        rows = alerts(c, run["run_id"])
        for i, e in enumerate(episodes):
            if i in found:
                continue
            for a in rows:
                if a["threat_class"] == e["threat_class"] and a["entity_key"] == e["entity_key"] and a["subtype"] in e["expected_subtypes"]:
                    found[i] = a
                    break
        prog = sender_progress(c, run["run_id"])
        if prog and prog["total"] and prog["sent"] >= prog["total"]:
            finished_at = finished_at or time.time()
        # Done when every episode matched and the replay finished (plus a settle period for absent checks).
        if len(found) == len(episodes) and finished_at and time.time() - finished_at > 20:
            break
        if finished_at and time.time() - finished_at > 180:
            break  # evidence can no longer arrive
        time.sleep(10)
    rows = alerts(c, run["run_id"])
    for i, e in enumerate(episodes):
        a = found.get(i)
        entry = {"label": e["label"], "threat_class": e["threat_class"], "entity_key": e["entity_key"], "detected": a is not None}
        if a:
            onset_obs_ms = (manifest["capture_start_us"] + int(e["start_offset_s"] * 1e6) + int(a["replay_time_offset_us"])) // 1000
            entry.update({"subtype": a["subtype"], "severity": a["severity"], "method": a["detection_method"],
                          "model_version": a["model_version"],
                          "receiver_to_alert_ms": ms(a["ts"]) - ms(a["evidence_received_at"]),
                          "onset_to_alert_observation_ms": ms(a["observation_time"]) - onset_obs_ms})
        else:
            result["ok"] = False
        result["episodes"].append(entry)
    for ab in manifest.get("absent_expected", []):
        hits = [a for a in rows if a["threat_class"] == ab["threat_class"] and a["entity_key"] == ab["entity_key"]
                and a["severity"] != "info"]
        result["absent"].append({**ab, "unexpected_alerts": len(hits)})
        if hits:
            result["ok"] = False
    if not episodes:  # benign-only scenario: nothing above info is expected
        noisy = [a for a in rows if a["severity"] != "info"]
        result["benign_false_alerts"] = len(noisy)
        result["benign_false_alert_classes"] = sorted({f"{a['threat_class']}/{a['entity_key']}" for a in noisy})
        result["ok"] = result["ok"] and not noisy
    prog = sender_progress(c, run["run_id"])
    result["sender"] = prog
    result["raw_events_stored"] = raw_count(c, run["run_id"])
    if prog and prog["total"]:
        # Every record the sender replayed must be stored once (invalid-locally records are never sent).
        result["storage_complete"] = result["raw_events_stored"] >= prog["total"] - (prog["invalid_local"] or 0)
        result["ok"] = result["ok"] and result["storage_complete"]
    result["alerts_total"] = len(rows)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=1800)
    a = ap.parse_args()
    runs = [json.loads(line) for line in pathlib.Path(a.runs).read_text().splitlines() if line.strip().startswith("{")]
    c = ch()
    deadline = time.time() + a.timeout
    results = [check_run(c, r, deadline) for r in runs]
    lat = sorted(e["receiver_to_alert_ms"] for r in results for e in r["episodes"] if e.get("receiver_to_alert_ms") is not None)
    summary = {"runs": len(results), "ok": all(r["ok"] for r in results), "episodes": sum(len(r["episodes"]) for r in results),
               "detected": sum(e["detected"] for r in results for e in r["episodes"]),
               "receiver_to_first_alert_ms": {"samples": len(lat), "max": lat[-1] if lat else None,
                                              "p50": lat[len(lat) // 2] if lat else None,
                                              "note": "first matching alert per episode only; see benchmarks for load latency"}}
    pathlib.Path(a.out).write_text(json.dumps({"summary": summary, "results": results}, indent=2))
    print(json.dumps(summary, indent=2))
    sys.exit(0 if summary["ok"] else 1)


if __name__ == "__main__":
    main()
