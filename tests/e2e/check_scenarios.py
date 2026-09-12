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


REJECTED = ("JSONExtractInt(record_json, 'records_invalid_local_total') + "
            "JSONExtractInt(record_json, 'records_rejected_oversize_total')")


def sender_progress(c, run_id: str) -> dict | None:
    """Replay progress of one run from outward sensor-health records.

    Health is sent every few seconds and the sender starts the next run immediately, so the last record
    tagged with this run usually shows it slightly short of complete. The run therefore also counts as
    finished once the same sender (sensor + boot) has reported anything later for another run.
    """
    rows = c.query(
        "SELECT sensor_id, sensor_boot_id, max(health_seq) AS last_seq, "
        "argMax(JSONExtractInt(record_json, 'replay_records_total'), health_seq) AS total, "
        "argMax(JSONExtractInt(record_json, 'replay_records_sent'), health_seq) AS sent, "
        f"argMin({REJECTED}, health_seq) AS rejected_first, argMax({REJECTED}, health_seq) AS rejected_last "
        "FROM sih.sensor_health FINAL WHERE JSONExtractString(record_json, 'replay_run_id') = {r:String} "
        "GROUP BY sensor_id, sensor_boot_id ORDER BY last_seq DESC LIMIT 1", {"r": run_id})
    if not rows:
        return None
    p = rows[0]
    later = c.query(
        f"SELECT count() AS n, argMin({REJECTED}, health_seq) AS rejected_after FROM sih.sensor_health FINAL "
        "WHERE sensor_id = {s:String} AND sensor_boot_id = {b:String} AND health_seq > {q:UInt64} "
        "AND JSONExtractString(record_json, 'replay_run_id') != {r:String}",
        {"s": p["sensor_id"], "b": p["sensor_boot_id"], "q": p["last_seq"], "r": run_id})[0]
    moved_on = later["n"] > 0
    end_rejected = later["rejected_after"] if moved_on else p["rejected_last"]
    return {"total": p["total"], "sent": p["total"] if moved_on else p["sent"],
            "finished": bool(p["total"]) and (moved_on or p["sent"] >= p["total"]),
            "rejected_during_run": max(0, end_rejected - p["rejected_first"])}


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
        if prog and prog["finished"]:
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
    if prog and prog["finished"]:
        # Every record the sender replayed must be stored once; records it rejected locally were never sent.
        result["storage_complete"] = result["raw_events_stored"] >= prog["total"] - prog["rejected_during_run"]
        result["ok"] = result["ok"] and result["storage_complete"]
    else:
        result["storage_complete"] = None
        result["replay_finished"] = False
        result["ok"] = False
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
