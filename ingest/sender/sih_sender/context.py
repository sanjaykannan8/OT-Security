"""Sender settings, shared state and counters."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sih_common import env
from sih_common.linkframe import TYPE_EVENT, RecordTooLarge
from sih_sender.link import LinkWriter
from sih_sender.normalizer import NormalizationError, ZeekNormalizer
from sih_sender.state import SenderState

log = logging.getLogger("sender")
_SENSOR_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


@dataclass
class Settings:
    sensor_id: str = ""
    mode: str = "replay"
    capture_mode: str = "pcap_replay"
    coverage: str = "both_directions"
    input_dir: str = "/data/zeek-logs"
    state_dir: str = "/data/sender-state"
    replay_speed: float = 1.0
    max_replay_records: int = 1_000_000
    spool_max_bytes: int = 256 * 1024 * 1024
    health_interval_s: float = 5.0
    persist_every: int = 200

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            sensor_id=env.required("SENSOR_ID"),
            mode=env.env_str("SENDER_MODE", "replay"),
            capture_mode=env.env_str("SENDER_CAPTURE_MODE", "pcap_replay"),
            coverage=env.env_str("SENDER_OBSERVATION_COVERAGE", "both_directions"),
            input_dir=env.env_str("SENDER_INPUT_DIR", "/data/zeek-logs"),
            state_dir=env.env_str("SENDER_STATE_DIR", "/data/sender-state"),
            replay_speed=env.env_float("SENDER_REPLAY_SPEED", 1.0),
            max_replay_records=env.env_int("SENDER_MAX_REPLAY_RECORDS", 1_000_000),
            spool_max_bytes=env.env_int("SENDER_SPOOL_MAX_BYTES", 256 * 1024 * 1024),
            health_interval_s=env.env_float("SENDER_HEALTH_INTERVAL_S", 5.0),
            persist_every=env.env_int("SENDER_PERSIST_EVERY", 200),
        )

    def validate(self) -> None:
        if not _SENSOR_ID.fullmatch(self.sensor_id or ""):
            raise ValueError("SENSOR_ID must match ^[a-z0-9][a-z0-9-]{0,62}$")
        if self.mode not in ("tail", "replay"):
            raise ValueError("SENDER_MODE must be tail or replay")
        if self.capture_mode not in ("pcap_replay", "synthetic_log", "passive_live"):
            raise ValueError(f"invalid SENDER_CAPTURE_MODE {self.capture_mode}")
        if self.coverage not in ("both_directions", "originator_only", "responder_only", "unknown"):
            raise ValueError(f"invalid SENDER_OBSERVATION_COVERAGE {self.coverage}")
        if self.replay_speed <= 0:
            raise ValueError("SENDER_REPLAY_SPEED must be positive")


class SenderContext:
    def __init__(self, settings: Settings, state: SenderState, link: LinkWriter):
        settings.validate()
        self.cfg = settings
        self.state = state
        self.link = link
        self.normalizer = ZeekNormalizer(settings.coverage)
        self.records_read = 0
        self.rejected_oversize = 0
        self.invalid_local = 0
        self.tail_lag_bytes: int | None = None
        self.files_tracked = 0
        self.backlog_bytes = 0
        self.zeek_status = "unknown"
        self.sender_state = "running"

    def send_record(self, log_type: str, line: str, sequence: int, run_id: str | None, offset_us: int) -> bool:
        """Normalize and send one record. Returns False when the record was rejected locally."""
        self.records_read += 1
        try:
            n = self.normalizer.normalize(log_type, line)
        except NormalizationError as e:
            self.invalid_local += 1
            if self.invalid_local <= 20 or self.invalid_local % 1000 == 0:
                log.warning("record rejected by normalizer: %s (log_type=%s, total=%d)", e, log_type, self.invalid_local)
            return False
        try:
            env_bytes = self.normalizer.envelope(n, self.cfg.sensor_id, self.state.boot_id, sequence, run_id,
                                                 offset_us, self.cfg.capture_mode)
            self.link.send(TYPE_EVENT, self.cfg.sensor_id, self.state.boot_id, sequence, env_bytes)
            return True
        except RecordTooLarge:
            self.rejected_oversize += 1
            log.warning("record rejected: exceeds link record limit (log_type=%s, sequence=%d)", log_type, sequence)
            return False
