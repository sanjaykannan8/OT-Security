import json
import threading

import pytest

from sih_consumers.base import Item, PermanentWriteError, Poison, durable_write
from sih_consumers.clickhouse_sinks import alert_rows, raw_rows
from sih_consumers.notifier import NotifierSink
from sih_detect.alerts import alert_record, finding
from sih_sender.normalizer import ZeekNormalizer

BOOT = "7f1c2a9e-4b61-4d7e-9a0c-5c1e2f3a4b5d"


def sample_alert(status="new", seq=1, severity="high") -> bytes:
    ev = {"obs_ms": 1788256800000, "event_time_us": 1788256800000000, "offset_us": 0,
          "received_us": 1788256800000500, "sensor_id": "ot-sensor-01", "run": None}
    f = finding(detector="scan", threat_class="scan", subtype="horizontal_scan", entity_type="src_host",
                entity_key="10.10.1.99", severity=severity, score=0.8, method="rule", detector_version="scan-1.0.0",
                feature_schema_version="scan_features-1.0.0", first=ev, last=ev, window_start_ms=ev["obs_ms"] - 1000,
                window_end_ms=ev["obs_ms"], observed={"x": 1}, thresholds={"t": 2}, explanation="<b>text</b>")
    return json.dumps(alert_record(f, "5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a99", seq, status, now_ms=1788256801000)).encode()


def test_alert_rows_validate_and_poison():
    rows = alert_rows(sample_alert())
    assert rows[0]["entity_key"] == "10.10.1.99" and rows[0]["update_seq"] == 1
    with pytest.raises(Poison):
        alert_rows(b"{not json")
    with pytest.raises(Poison):
        alert_rows(b'{"alert_schema_version":"1.0.0"}')


def test_raw_rows_observation_time():
    z = ZeekNormalizer("both_directions")
    line = ('{"ts":1788256800.0,"uid":"C1","id.orig_h":"10.0.0.1","id.orig_p":1,"id.resp_h":"10.0.0.2","id.resp_p":2,'
            '"proto":"tcp","duration":2.0,"conn_state":"SF"}')
    ev = json.loads(z.envelope(z.normalize("conn", line), "ot-sensor-01", BOOT, 0, "r", 1_000_000, "pcap_replay"))
    ev["receiver_received_at"] = "2026-09-11T10:00:00.000000Z"
    row = raw_rows(json.dumps(ev).encode())[0]
    assert row["observation_time"] == "2026-09-01T10:00:03.000000Z"


class FlakySink:
    name = "flaky"

    def __init__(self, fail_times=2, reject=None):
        self.fail_times, self.reject, self.written, self.quarantined = fail_times, reject, [], []

    def write(self, rows):
        if self.fail_times:
            self.fail_times -= 1
            raise ConnectionError("down")
        if self.reject and any(r == self.reject for r in rows):
            raise PermanentWriteError("bad row")
        self.written += rows

    def quarantine(self, items):
        self.quarantined += items


def test_durable_write_retries_transient_and_isolates_rejected(monkeypatch):
    stop = threading.Event()
    monkeypatch.setattr(stop, "wait", lambda t: False)
    s = FlakySink(fail_times=2, reject={"id": 2})
    items = [Item("t", 0, i, b"p", [{"id": i}]) for i in range(4)]
    assert durable_write(s, items, stop)
    assert s.written == [{"id": 0}, {"id": 1}, {"id": 3}]
    assert [q[2] for q in s.quarantined] == [2]


def test_notifier_is_idempotent_on_update_id(tmp_path):
    n = NotifierSink(str(tmp_path), "medium")
    rows = n.transform(sample_alert())
    n.write(rows)
    n.write(n.transform(sample_alert()))  # replay
    assert n.count() == 1
    assert n.transform(sample_alert(status="updated", seq=2)) == []
    assert n.transform(sample_alert(severity="low")) == []
    lines = (tmp_path / "notifications.jsonl").read_text().splitlines()
    assert len(lines) == 1 and "<b>text</b>" in json.loads(lines[0])["message"]  # stored as text, never rendered
