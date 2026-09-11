"""Receiver entrypoint: `python -m sih_receiver`."""
from __future__ import annotations

import logging
import pathlib
import signal
import socket
import threading
import time

from prometheus_client import REGISTRY, start_http_server

from sih_common import env, log as jlog, timeutil
from sih_receiver.core import ReceiverCore
from sih_receiver.publisher import Publisher, kafka_producer_factory

log = logging.getLogger("receiver")


def main() -> None:
    jlog.setup("receiver")
    core = ReceiverCore(
        pathlib.Path(env.env_str("RECEIVER_STATE_DIR", "/data/receiver")),
        env.secret_file("LINK_KEY_FILE"),
        env.env_int("RECEIVER_SPOOL_MAX_BYTES", 1024 * 1024 * 1024),
        env.env_int("RECEIVER_SEGMENT_BYTES", 64 * 1024 * 1024),
        registry=REGISTRY,
    )
    pub = Publisher(core.spool, core.state_dir / "publisher.cursor",
                    kafka_producer_factory(env.env_str("KAFKA_BOOTSTRAP", "redpanda:9092")),
                    core.m.published, core.m.publish_errors)
    pub.start()
    start_http_server(env.env_int("RECEIVER_METRICS_PORT", 9101))

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    port = env.env_int("RECEIVER_BIND_PORT", 9500)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(0.1)
    log.info("receiver listening", extra=jlog.kv(port=port, spool_bytes=core.spool.total_bytes))
    last = 0.0
    try:
        while not stop.is_set():
            try:
                data, _addr = sock.recvfrom(65535)
                core.handle_datagram(data, timeutil.now_us())
            except socket.timeout:
                pass
            except Exception:
                log.exception("unexpected error handling datagram")
            now = time.monotonic()
            if now - last >= 0.1:
                core.housekeeping()
                core.m.backlog.set(pub.backlog_bytes())
                core.m.publisher_healthy.set(1 if pub.healthy else 0)
                last = now
    finally:
        core.housekeeping()
        pub.stop()
        pub.join(timeout=10)
        core.spool.close()
        sock.close()
        log.info("receiver stopped")


if __name__ == "__main__":
    main()
