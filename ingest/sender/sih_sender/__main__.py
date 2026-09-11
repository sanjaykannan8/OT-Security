"""Sender entrypoint: `python -m sih_sender`.

Opens no listening socket and no HTTP endpoint. Its health leaves the observation side only as outward
sensor-health frames; a local heartbeat file backs the container healthcheck.
"""
from __future__ import annotations

import logging
import pathlib
import signal
import threading

from sih_common import env, log as jlog, timeutil
from sih_common.linkframe import TYPE_HEALTH
from sih_sender.context import SenderContext, Settings
from sih_sender.link import LinkWriter
from sih_sender.normalizer import dumps
from sih_sender.replay import ReplayMode
from sih_sender.state import SenderState
from sih_sender.tail import TailMode

log = logging.getLogger("sender")


def health_record(ctx: SenderContext) -> dict:
    run = ctx.state.current_run
    last = ctx.link.last_sequence_sent
    return {
        "health_schema_version": "1.0.0",
        "sensor_id": ctx.cfg.sensor_id,
        "sensor_boot_id": ctx.state.boot_id,
        "health_seq": ctx.state.next_health_seq(),
        "emitted_at": timeutil.format_us(timeutil.now_us()),
        "sender_state": ctx.sender_state,
        "mode": ctx.cfg.mode,
        "replay_run_id": run["run_id"] if run else None,
        "last_sequence_sent": last if last >= 0 else None,
        "records_read_total": ctx.records_read,
        "frames_sent_total": ctx.link.frames_sent,
        "records_rejected_oversize_total": ctx.rejected_oversize,
        "records_invalid_local_total": ctx.invalid_local,
        "spool_bytes": max(0, int(ctx.backlog_bytes)),
        "spool_max_bytes": ctx.cfg.spool_max_bytes,
        "tail_lag_bytes": ctx.tail_lag_bytes,
        "files_tracked": ctx.files_tracked,
        "zeek_status": "unknown" if ctx.cfg.mode == "tail" else ctx.zeek_status,
        "replay_records_total": run["total"] if run else None,
        "replay_records_sent": run["next_index"] if run else None,
    }


def send_health(ctx: SenderContext, heartbeat: pathlib.Path) -> None:
    try:
        rec = health_record(ctx)
        ctx.link.send(TYPE_HEALTH, ctx.cfg.sensor_id, ctx.state.boot_id, rec["health_seq"], dumps(rec))
        heartbeat.touch()
    except Exception:  # health must never kill the sender
        log.exception("health send failed")


def main() -> None:
    jlog.setup("sender")
    settings = Settings.from_env()
    state = SenderState.load(pathlib.Path(settings.state_dir))
    link = LinkWriter(env.env_str("LINK_TARGET_HOST", "receiver"), env.env_int("LINK_TARGET_PORT", 9500),
                      env.secret_file("LINK_KEY_FILE"), env.env_int("LINK_REDUNDANCY", 1),
                      env.env_float("LINK_MAX_FRAMES_PER_SEC", 20000.0))
    ctx = SenderContext(settings, state, link)
    log.info("sender starting", extra=jlog.kv(sensor_id=settings.sensor_id, boot_id=state.boot_id, mode=settings.mode,
                                               capture_mode=settings.capture_mode, coverage=settings.coverage))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    heartbeat = pathlib.Path(env.env_str("SENDER_HEARTBEAT_FILE", "/tmp/sender.alive"))

    def health_loop():
        while not stop.wait(settings.health_interval_s):
            send_health(ctx, heartbeat)

    send_health(ctx, heartbeat)
    threading.Thread(target=health_loop, name="health", daemon=True).start()
    try:
        (TailMode(ctx) if settings.mode == "tail" else ReplayMode(ctx)).run(stop)
    finally:
        ctx.sender_state = "stopping"
        send_health(ctx, heartbeat)
        state.save()
        link.close()
        log.info("sender stopped")


if __name__ == "__main__":
    main()
