#!/usr/bin/env python3
"""Deterministically build schema example vectors and cross-language identifier vectors.

    python schemas/examples/build_examples.py           # (re)write files
    python schemas/examples/build_examples.py --check   # exit 1 if committed files are stale

Outputs examples/<kind>/{valid,invalid}/<name>.json and expectations.json (expected validity and codes).
Alert and feature examples come from the detector's own builders, so detector output is checked against
the frozen schemas.
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for p in ("lib", "flink"):
    sys.path.insert(0, str(ROOT / p))

from sih_common import contracts, ids, timeutil  # noqa: E402
from sih_detect.alerts import alert_record, feature_record, finding  # noqa: E402

SENSOR = "ot-sensor-01"
BOOT = "7f1c2a9e-4b61-4d7e-9a0c-5c1e2f3a4b5d"
RUN = "20260901T100000Z-fixture"
OFFSET_US = 864_000_000_000  # replayed ten days after capture
T0_US = 1_788_256_800_000_000  # 2026-09-01T10:00:00Z


def zline(ts: str, fields: dict) -> str:
    body = json.dumps(fields, separators=(",", ":"))
    return '{"ts":' + ts + ("," + body[1:] if fields else "}")


def event(seq, log_type, ts, zeek, payload, availability=None, reasons=None, *, coverage="both_directions",
          capture="pcap_replay", run=RUN, offset=OFFSET_US, original=None):
    line = original if original is not None else zline(ts, zeek)
    sha = __import__("hashlib").sha256(line.encode()).hexdigest()
    et = timeutil.zeek_ts_to_us(ts)
    emitted = et + offset + 1500
    keep = len(line) <= 4096
    return {
        "event_schema_version": "1.0.0", "event_id": ids.event_id(SENSOR, BOOT, seq, sha), "sensor_id": SENSOR,
        "sensor_boot_id": BOOT, "sequence": seq, "replay_run_id": run, "replay_time_offset_us": offset,
        "log_type": log_type, "event_time": timeutil.format_us(et), "sensor_emitted_at": timeutil.format_us(emitted),
        "receiver_received_at": timeutil.format_us(emitted + 900), "capture_mode": capture,
        "observation_coverage": coverage, "original_record_sha256": sha, "original_record": line if keep else None,
        "original_record_truncated": not keep, "availability": availability or {},
        "availability_reasons": reasons or {}, "payload": payload,
    }


def conn_payload(**over):
    p = {"uid": "CMb1a2b3c4d5e6f7g8", "src_ip": "10.10.1.10", "src_port": 49152, "dst_ip": "10.10.2.5", "dst_port": 502,
         "proto": "tcp", "service": "modbus", "duration_s": 0.021345, "orig_bytes": 12, "resp_bytes": 11, "orig_pkts": 6,
         "resp_pkts": 4, "orig_ip_bytes": 332, "resp_ip_bytes": 223, "history": "ShADadFf", "missed_bytes": 0,
         "conn_state": "SF", "local_orig": True, "local_resp": True}
    p.update(over)
    return p


CONN_ZEEK = {"uid": "CMb1a2b3c4d5e6f7g8", "id.orig_h": "10.10.1.10", "id.orig_p": 49152, "id.resp_h": "10.10.2.5",
             "id.resp_p": 502, "proto": "tcp", "service": "modbus", "duration": 0.021345, "orig_bytes": 12, "resp_bytes": 11,
             "conn_state": "SF", "local_orig": True, "local_resp": True, "missed_bytes": 0, "history": "ShADadFf",
             "orig_pkts": 6, "orig_ip_bytes": 332, "resp_pkts": 4, "resp_ip_bytes": 223}


def dns_payload(**over):
    p = {"uid": "CDn0001", "src_ip": "10.10.1.40", "src_port": 53211, "dst_ip": "10.10.0.53", "dst_port": 53, "proto": "udp",
         "trans_id": 4242, "rtt_s": 0.004, "query": "xjwqkzvbplrtd.com", "query_truncated": False, "qclass": 1, "qtype": 1,
         "qtype_name": "A", "rcode": 3, "rcode_name": "NXDOMAIN", "aa": False, "tc": False, "rd": True, "ra": True,
         "answers": [], "answers_truncated": False, "rejected": False}
    p.update(over)
    return p


def valid_events() -> dict:
    ev = {}
    ev["conn_modbus_sf"] = event(0, "conn", "1788256800.123456", CONN_ZEEK, conn_payload())
    s0z = {"uid": "CS0aaaa1", "id.orig_h": "10.10.1.99", "id.orig_p": 40001, "id.resp_h": "10.10.2.9", "id.resp_p": 502,
           "proto": "tcp", "conn_state": "S0", "local_orig": True, "local_resp": True, "missed_bytes": 0, "history": "S",
           "orig_bytes": 0, "resp_bytes": 0, "orig_pkts": 1, "orig_ip_bytes": 44, "resp_pkts": 0, "resp_ip_bytes": 0}
    ev["conn_s0_genuine_zero"] = event(
        1, "conn", "1788256800.5", s0z,
        conn_payload(uid="CS0aaaa1", src_ip="10.10.1.99", src_port=40001, dst_ip="10.10.2.9", service=None, duration_s=None,
                     orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=0, orig_ip_bytes=44, resp_ip_bytes=0, history="S",
                     conn_state="S0"),
        {"service": "UNKNOWN", "duration_s": "MISSING"}, {"service": "no_protocol_identified", "duration_s": "zeek_field_absent"})
    ev["conn_originator_only"] = event(
        2, "conn", "1788256801.0", {**CONN_ZEEK, "uid": "COrig01", "resp_bytes": 0, "resp_pkts": 0, "resp_ip_bytes": 0},
        conn_payload(uid="COrig01", resp_bytes=None, resp_pkts=None, resp_ip_bytes=None),
        {k: "UNKNOWN" for k in ("resp_bytes", "resp_pkts", "resp_ip_bytes")},
        {k: "direction_not_observed" for k in ("resp_bytes", "resp_pkts", "resp_ip_bytes")}, coverage="originator_only")
    fu_zeek = {"uid": "CFup0001", "id.orig_h": "10.10.1.30", "id.orig_p": 51000, "id.resp_h": "203.0.113.77", "id.resp_p": 443,
               "proto": "tcp", "service": "ssl", "duration": 10.0, "orig_bytes": 4500000, "resp_bytes": 40960,
               "orig_pkts": 3100, "resp_pkts": 1500, "orig_ip_bytes": 4624000, "resp_ip_bytes": 100960, "history": "ShADad",
               "snapshot_seq": 2, "snapshot_interval": 5.0}
    ev["flow_update_upload"] = event(3, "flow_update", "1788256840.0", fu_zeek, {
        "uid": "CFup0001", "src_ip": "10.10.1.30", "src_port": 51000, "dst_ip": "203.0.113.77", "dst_port": 443, "proto": "tcp",
        "service": "ssl", "duration_s": 10.0, "orig_bytes": 4500000, "resp_bytes": 40960, "orig_pkts": 3100, "resp_pkts": 1500,
        "orig_ip_bytes": 4624000, "resp_ip_bytes": 100960, "history": "ShADad", "snapshot_seq": 2, "snapshot_interval_s": 5.0})
    dnsz = {"uid": "CDn0001", "id.orig_h": "10.10.1.40", "id.orig_p": 53211, "id.resp_h": "10.10.0.53", "id.resp_p": 53,
            "proto": "udp", "trans_id": 4242, "rtt": 0.004, "query": "xjwqkzvbplrtd.com", "qclass": 1, "qtype": 1,
            "qtype_name": "A", "rcode": 3, "rcode_name": "NXDOMAIN", "AA": False, "TC": False, "RD": True, "RA": True,
            "Z": 0, "rejected": False}
    ev["dns_nxdomain"] = event(4, "dns", "1788256802.0", dnsz, dns_payload())
    noresp = {k: v for k, v in dnsz.items() if k not in ("rtt", "rcode", "rcode_name")}
    ev["dns_no_response"] = event(
        5, "dns", "1788256803.0", {**noresp, "uid": "CDn0002", "query": "historian-01.plant.local", "RA": False},
        dns_payload(uid="CDn0002", query="historian-01.plant.local", rtt_s=None, rcode=None, rcode_name=None, ra=False, answers=None),
        {"rtt_s": "MISSING", "rcode": "MISSING", "rcode_name": "MISSING", "answers": "MISSING"},
        {"rtt_s": "no_response_observed", "rcode": "no_response_observed", "rcode_name": "no_response_observed",
         "answers": "no_response_observed"})
    sslz = {"uid": "CTls0001", "id.orig_h": "10.10.1.50", "id.orig_p": 50123, "id.resp_h": "198.51.100.20", "id.resp_p": 8443,
            "version": "TLSv10", "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA", "resumed": False, "established": False, "ssl_history": "Ch"}
    ev["ssl_tls10_no_sni"] = event(6, "ssl", "1788256804.0", sslz, {
        "uid": "CTls0001", "src_ip": "10.10.1.50", "src_port": 50123, "dst_ip": "198.51.100.20", "dst_port": 8443,
        "version": "TLSv10", "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA", "curve": None, "server_name": None, "resumed": False,
        "established": False, "next_protocol": None, "ssl_history": "Ch", "validation_status": None, "cert_chain_len": None,
        "sni_matches_cert": None},
        {"curve": "UNKNOWN", "server_name": "MISSING", "next_protocol": "NOT_APPLICABLE", "validation_status": "UNKNOWN",
         "cert_chain_len": "UNKNOWN", "sni_matches_cert": "UNKNOWN"},
        {"curve": "zeek_field_absent", "server_name": "not_sent_by_client", "next_protocol": "alpn_not_negotiated",
         "validation_status": "validation_not_configured", "cert_chain_len": "no_certificate_observed",
         "sni_matches_cert": "zeek_field_absent"})
    ev["weird_not_connection_scoped"] = event(7, "weird", "1788256805.0", {"name": "truncated_IPv6", "notice": False, "peer": "zeek"}, {
        "uid": None, "src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None, "name": "truncated_IPv6", "addl": None,
        "notice": False, "peer": "zeek", "source": None},
        {"uid": "NOT_APPLICABLE", "src_ip": "NOT_APPLICABLE", "src_port": "NOT_APPLICABLE", "dst_ip": "NOT_APPLICABLE",
         "dst_port": "NOT_APPLICABLE", "addl": "NOT_APPLICABLE", "source": "NOT_APPLICABLE"},
        {"uid": "not_connection_scoped", "src_ip": "not_connection_scoped", "src_port": "not_connection_scoped",
         "dst_ip": "not_connection_scoped", "dst_port": "not_connection_scoped", "addl": "no_additional_info",
         "source": "zeek_field_absent"})
    big = {**CONN_ZEEK, "uid": "CBig0001", "vendor_note": "x" * 5000}
    ev["conn_original_truncated"] = event(8, "conn", "1788256806.0", big, conn_payload(uid="CBig0001"))
    ev["dns_synthetic_tail"] = event(9, "dns", "1788256807.0", {**dnsz, "uid": "CSyn0001"}, dns_payload(uid="CSyn0001"),
                                     capture="synthetic_log", run=None, offset=0)
    return ev


def invalid_events(valid: dict) -> dict:
    base = valid["conn_modbus_sf"]
    dns = valid["dns_nxdomain"]

    def mut(src, fn):
        e = copy.deepcopy(src)
        fn(e)
        return e

    return {
        "missing_sensor_id": (mut(base, lambda e: e.pop("sensor_id")), ["schema"]),
        "unknown_envelope_field": (mut(base, lambda e: e.update(extra=1)), ["schema"]),
        "unsupported_version": (mut(base, lambda e: e.update(event_schema_version="2.0.0")), ["unsupported_schema_version"]),
        "unknown_log_type": (mut(base, lambda e: e.update(log_type="http")), ["schema"]),
        "bad_capture_mode": (mut(base, lambda e: e.update(capture_mode="live")), ["schema"]),
        "timestamp_with_offset": (mut(base, lambda e: e.update(event_time="2026-09-01T15:30:00.123456+05:30")), ["schema"]),
        "negative_bytes": (mut(base, lambda e: e["payload"].update(orig_bytes=-1)), ["schema"]),
        "port_out_of_range": (mut(base, lambda e: e["payload"].update(dst_port=70000)), ["schema"]),
        "missing_payload_key": (mut(base, lambda e: e["payload"].pop("history")), ["schema"]),
        "unknown_payload_key": (mut(base, lambda e: e["payload"].update(foo=1)), ["schema"]),
        "null_without_availability": (mut(base, lambda e: e["payload"].update(resp_bytes=None)), ["availability_null"]),
        "availability_on_value": (mut(base, lambda e: e.update(availability={"orig_bytes": "MISSING"})), ["availability_on_value"]),
        "reason_without_availability": (mut(base, lambda e: e.update(availability_reasons={"orig_bytes": "zeek_field_absent"})),
                                        ["reason_without_availability"]),
        "availability_state_available": (mut(base, lambda e: (e["payload"].update(resp_bytes=None),
                                                               e.update(availability={"resp_bytes": "AVAILABLE"}))), ["schema"]),
        "bad_ip": (mut(base, lambda e: e["payload"].update(src_ip="10.0.0.256")), ["schema"]),
        "sensor_id_uppercase": (mut(base, lambda e: e.update(sensor_id="OT-SENSOR-01")), ["schema"]),
        "original_record_oversize": (mut(base, lambda e: e.update(original_record="x" * 5000)), ["schema"]),
        "sequence_as_string": (mut(base, lambda e: e.update(sequence="12")), ["schema"]),
        "payload_type_mismatch": (mut(base, lambda e: e.update(log_type="dns")), ["schema"]),
        "original_null_not_truncated": (mut(base, lambda e: e.update(original_record=None)), ["original_record_null"]),
        "oversize_query": (mut(dns, lambda e: e["payload"].update(query="a" * 300)), ["schema"]),
    }


EV = {"obs_ms": 1788256830000, "event_time_us": 1788256830000000 - OFFSET_US, "offset_us": OFFSET_US,
      "received_us": 1788256830000900, "sensor_id": SENSOR, "run": RUN}


def valid_alerts() -> dict:
    scan = finding(detector="scan", threat_class="scan", subtype="horizontal_scan", entity_type="src_host", entity_key="10.10.1.99",
                   severity="medium", score=0.72, method="rule", detector_version="scan-1.0.0",
                   feature_schema_version="scan_features-1.0.0", first={**EV, "obs_ms": EV["obs_ms"] - 20000}, last=EV,
                   window_start_ms=EV["obs_ms"] - 30000, window_end_ms=EV["obs_ms"],
                   observed={"distinct_count": 24, "distinct_pairs": 24, "failed_ratio": 1.0, "authorized_scanner": False},
                   thresholds={"distinct_threshold": 20, "horizon_s": 30.0}, coverage="both_directions", src_ip="10.10.1.99",
                   dst_port=502, protocol="tcp", raw_event_ids=[ids.derived_id("event", "x", i) for i in range(3)],
                   evidence_count=24, top_features=[("horizontal_distinct", 24, None, "count")],
                   explanation="Source 10.10.1.99 contacted 24 distinct hosts on port 502/tcp within 30s (threshold 20).")
    dga = finding(detector="dns", threat_class="dga", subtype="dga_domain", entity_type="src_domain",
                  entity_key="10.10.1.40|xjwqkzvbplrtd.com", severity="medium", score=0.987, method="model",
                  model_version="dga-lr-1.0.0-sim", calibration_status="simulation_only", confidence_kind="heuristic_score",
                  model_eligible=True, detector_version="dga-1.0.0", feature_schema_version="dga_lexical-1.0.0", first=EV,
                  last=EV, window_start_ms=EV["obs_ms"] - 1000, window_end_ms=EV["obs_ms"],
                  observed={"query": "xjwqkzvbplrtd.com", "nxdomain": True, "model_score": 0.987},
                  thresholds={"decision_threshold": 0.93}, coverage="both_directions", src_ip="10.10.1.40", protocol="udp",
                  raw_event_ids=[ids.derived_id("event", "dga")], evidence_count=1,
                  top_features=[("sld_bigram_logprob_mean", -4.2, 1.8, None), ("sld_entropy", 3.7, 0.9, None)],
                  explanation="Model dga-lr-1.0.0-sim scored the name xjwqkzvbplrtd.com at 0.987; simulation_only, not a probability.")
    exfil = finding(detector="exfil", threat_class="exfiltration", subtype="sustained_upload", entity_type="src_host",
                    entity_key="10.10.1.30", severity="high", score=None, method="statistical", detector_version="exfil-1.0.0",
                    feature_schema_version="exfil_features-1.0.0", first=EV, last=EV, window_start_ms=EV["obs_ms"] - 25000,
                    window_end_ms=EV["obs_ms"], observed={"outbound_bytes_window": 13500000, "out_in_ratio": None},
                    thresholds={"min_bytes_window": 10000000}, baseline={"window_bytes_mean": None}, unavailable=["out_in_ratio"],
                    coverage="originator_only", src_ip="10.10.1.30", dst_ip="203.0.113.77", dst_port=443, protocol="tcp",
                    raw_event_ids=[], evidence_count=6, explanation="Local host 10.10.1.30 sent 13.5 MB over 25s.")
    inc = lambda f: ids.incident_id(f["threat_class"], f["entity_type"], f["entity_key"], (f["window_start_ms"] // 1000) * 1000)  # noqa: E731
    now = EV["obs_ms"] + 700
    return {"scan_rule_heuristic": alert_record(scan, inc(scan), 1, "new", now_ms=now),
            "dga_model_simulation_only": alert_record(dga, inc(dga), 2, "escalated", now_ms=now),
            "exfil_confidence_unavailable": alert_record(exfil, inc(exfil), 1, "new", now_ms=now)}


def invalid_alerts(valid: dict) -> dict:
    scan, dga = valid["scan_rule_heuristic"], valid["dga_model_simulation_only"]

    def mut(src, fn):
        a = copy.deepcopy(src)
        fn(a)
        return a

    return {
        "confidence_null_with_heuristic": (mut(scan, lambda a: a.update(confidence=None)), ["confidence_consistency"]),
        "calibrated_probability_simulation": (mut(dga, lambda a: a.update(confidence_kind="calibrated_probability")),
                                              ["calibration_consistency"]),
        "rule_with_model_version": (mut(scan, lambda a: a.update(model_version="dga-lr-1.0.0-sim")), ["model_version_consistency"]),
        "window_end_before_start": (mut(scan, lambda a: a.update(window_start="2026-09-11T10:00:40.000000Z",
                                                                  window_end="2026-09-11T10:00:30.000000Z")), ["time_order"]),
        "unknown_threat_class": (mut(scan, lambda a: a.update(threat_class="ransomware")), ["schema"]),
        "missing_evidence_field": (mut(scan, lambda a: a["evidence"].pop("raw_event_ids")), ["schema"]),
        "unsupported_version": (mut(scan, lambda a: a.update(alert_schema_version="9.0.0")), ["unsupported_schema_version"]),
    }


def features() -> tuple[dict, dict]:
    def fixed(fr):
        fr["computed_at"] = "2026-09-11T10:00:30.500000Z"
        return fr
    scan = fixed(feature_record("scan", "scan_features-1.0.0", "src_host", "10.10.1.99", SENSOR, 1788256800000, 1788256830000,
                                {"distinct_pairs": 4096, "distinct_hosts": 300, "failed_ratio": None}, {"failed_ratio": "UNKNOWN"},
                                ["distinct_pairs"]))
    dns = fixed(feature_record("dns", "dns_features-1.0.0", "src_domain", "10.10.1.50|exfil-example.org", SENSOR, 1788256800000,
                               1788256830000, {"queries": 60, "unique_subdomains": 60, "dga_score": None}, {"dga_score": "NOT_APPLICABLE"}))
    bad_null = copy.deepcopy(scan)
    bad_null["availability"] = {}
    bad_capped = copy.deepcopy(scan)
    bad_capped["capped"] = ["failed_ratio"]
    bad_value = copy.deepcopy(dns)
    bad_value["availability"]["queries"] = "MISSING"
    return ({"scan_capped_lower_bound": scan, "dns_score_not_applicable": dns},
            {"null_without_availability": (bad_null, ["availability_null"]), "capped_without_value": (bad_capped, ["capped_unknown"]),
             "availability_on_value": (bad_value, ["availability_on_value"])})


def others() -> dict:
    health = {"health_schema_version": "1.0.0", "sensor_id": SENSOR, "sensor_boot_id": BOOT, "health_seq": 12,
              "emitted_at": "2026-09-11T10:00:05.000000Z", "received_at": "2026-09-11T10:00:05.000900Z", "sender_state": "running",
              "mode": "replay", "replay_run_id": RUN, "last_sequence_sent": 1041, "records_read_total": 1042,
              "frames_sent_total": 1100, "records_rejected_oversize_total": 0, "records_invalid_local_total": 1,
              "spool_bytes": 40000, "spool_max_bytes": 268435456, "tail_lag_bytes": None, "files_tracked": 0,
              "zeek_status": "finished", "replay_records_total": 5000, "replay_records_sent": 1042}
    inv = {"invalid_schema_version": "1.0.0",
           "invalid_id": ids.invalid_id("receiver", "schema_violation", "0" * 64, "inject-test", BOOT, 3),
           "detected_at": "2026-09-11T10:00:06.000000Z", "stage": "receiver", "reason_code": "schema_violation",
           "detail": "payload: 'uid' is a required property", "sensor_id": "inject-test", "sensor_boot_id": BOOT, "sequence": 3,
           "raw_sha256": "0" * 64, "raw_size_bytes": 64, "raw_excerpt": "{\"event_schema_version\":\"1.0.0\",\"payload\":{}}"}
    dep = {"deployment_manifest_version": "1.0.0", "updated_at": "2026-09-11T09:00:00.000000Z",
           "note": "example only; the real manifest is written by model-training",
           "models": {"dga": {"enabled": True, "version": "dga-lr-1.0.0-sim", "model_sha256": "a" * 64, "metadata_sha256": "b" * 64}}}
    return {"sensor_health": {"replay_running": health}, "invalid_event": {"schema_violation": inv},
            "deployment_manifest": {"dga_enabled": dep}}


def id_vectors() -> dict:
    cases = [("event", (SENSOR, BOOT, 5, "ab" * 32)), ("incident", ("scan", "src_host", "10.10.1.99", 1788256800000)),
             ("update", ("5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a99", 3)), ("alert", ("scan", "src_host", "10.10.1.99", 1788256830000, "horizontal_scan")),
             ("feature", ("dns", "src_domain", "10.10.1.50|exfil-example.org", 1788256830000)),
             ("invalid", ("receiver", "frame_malformed", None, None, None, None))]
    return {"note": "UUIDv5(namespace, '|'.join(parts)); null parts are empty strings",
            "vectors": [{"namespace": n, "namespace_uuid": str(ids.NAMESPACES[n]), "name": ids.join_name(*parts),
                         "uuid": ids.derived_id(n, *parts)} for n, parts in cases]}


def build() -> dict[str, str]:
    files: dict[str, str] = {}
    expectations: dict[str, dict] = {}

    def add(kind, validity, name, obj, codes=None):
        rel = f"{kind}/{validity}/{name}.json"
        files[rel] = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
        expectations[rel] = {"kind": kind, "valid": validity == "valid", "codes": codes or []}

    ve = valid_events()
    for n, o in ve.items():
        add("event", "valid", n, o)
    for n, (o, c) in invalid_events(ve).items():
        add("event", "invalid", n, o, c)
    va = valid_alerts()
    for n, o in va.items():
        add("alert", "valid", n, o)
    for n, (o, c) in invalid_alerts(va).items():
        add("alert", "invalid", n, o, c)
    vf, inf = features()
    for n, o in vf.items():
        add("feature", "valid", n, o)
    for n, (o, c) in inf.items():
        add("feature", "invalid", n, o, c)
    for kind, items in others().items():
        for n, o in items.items():
            add(kind, "valid", n, o)
    files["expectations.json"] = json.dumps(expectations, indent=2, sort_keys=True) + "\n"
    files["id_vectors.json"] = json.dumps(id_vectors(), indent=2) + "\n"
    return files


def main() -> None:
    files = build()
    existing = {str(p.relative_to(HERE)).replace("\\", "/"): p for p in HERE.rglob("*.json")}
    if "--check" in sys.argv:
        stale = [k for k, v in files.items() if k not in existing or existing[k].read_text(encoding="utf-8") != v]
        extra = [k for k in existing if k not in files]
        if stale or extra:
            print(f"stale: {stale}\nunexpected: {extra}")
            sys.exit(1)
        print("examples up to date")
        return
    for k, p in existing.items():
        if k not in files:
            p.unlink()
    for rel, text in files.items():
        path = HERE / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    # Sanity: every example validates exactly as expected.
    exp = json.loads(files["expectations.json"])
    for rel, e in exp.items():
        errs = contracts.validate(e["kind"], json.loads(files[rel]))
        ok = (not errs) if e["valid"] else bool(errs) and set(e["codes"]) <= contracts.codes(errs)
        if not ok:
            raise SystemExit(f"example {rel} does not validate as expected: {errs}")
    print(f"wrote {len(files)} files")


if __name__ == "__main__":
    main()
