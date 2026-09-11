"""Run one pipeline per container: `python -m sih_consumers <pipeline>`.

Pipelines: raw-clickhouse, features-clickhouse, alerts-clickhouse, aux-clickhouse (invalid + health),
alerts-notifier, alerts-opensearch, archive-exporter.
"""
from __future__ import annotations

import logging
import signal
import sys
import threading

from prometheus_client import start_http_server

from sih_common import env, log as jlog
from sih_consumers.base import run_consumer
from sih_consumers.clickhouse_sinks import (ClickHouseSink, alert_rows, feature_rows, health_rows, invalid_rows,
                                            raw_rows)

log = logging.getLogger("consumers")


def pipelines(name: str):
    if name == "raw-clickhouse":
        return [("raw-events.v1", "raw-clickhouse-v1", lambda: ClickHouseSink(name, "sih.raw_events", raw_rows))]
    if name == "features-clickhouse":
        return [("features.v1", "features-clickhouse-v1", lambda: ClickHouseSink(name, "sih.features", feature_rows))]
    if name == "alerts-clickhouse":
        return [("alerts.v1", "alerts-clickhouse-v1", lambda: ClickHouseSink(name, "sih.alert_updates", alert_rows))]
    if name == "aux-clickhouse":
        return [("invalid-events.v1", "invalid-clickhouse-v1", lambda: ClickHouseSink("invalid-clickhouse", "sih.invalid_events", invalid_rows)),
                ("sensor-health.v1", "health-clickhouse-v1", lambda: ClickHouseSink("health-clickhouse", "sih.sensor_health", health_rows))]
    if name == "alerts-notifier":
        from sih_consumers.notifier import NotifierSink
        return [("alerts.v1", "alerts-notifier-v1", NotifierSink)]
    if name == "alerts-opensearch":
        from sih_consumers.opensearch_sink import OpenSearchSink
        return [("alerts.v1", "alerts-opensearch-v1", OpenSearchSink)]
    raise SystemExit(f"unknown pipeline {name}")


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        raise SystemExit(__doc__)
    name = argv[1]
    jlog.setup(name)
    start_http_server(env.env_int("METRICS_PORT", 9102))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if name == "archive-exporter":
        from sih_consumers.archive import run_loop
        run_loop(stop)
        return
    bootstrap = env.env_str("KAFKA_BOOTSTRAP", "redpanda:9092")
    threads = []
    for topic, group, factory in pipelines(name):
        def target(topic=topic, group=group, factory=factory):
            while not stop.is_set():
                try:
                    run_consumer(factory(), topic, group, bootstrap, stop)
                except Exception:
                    log.exception("consumer crashed; restarting in 5s")
                    stop.wait(5)
        t = threading.Thread(target=target, name=f"{name}:{topic}", daemon=True)
        t.start()
        threads.append(t)
    while not stop.is_set():
        stop.wait(1)
    for t in threads:
        t.join(timeout=15)


if __name__ == "__main__":
    main(sys.argv)
