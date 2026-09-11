"""PyFlink detection job topology.

    flink run -d -py /opt/sih/flink/sih_detect/job.py -pyfs /opt/sih/lib,/opt/sih/flink

Every stateful operator has an explicit, stable uid. Watermarks come from Kafka record timestamps
(observation time set by the receiver), generated per partition inside the Java source.
"""
from __future__ import annotations

import logging

from pyflink.common import Duration, Types, WatermarkStrategy
from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream import OutputTag, StreamExecutionEnvironment
from pyflink.datastream.connectors.base import DeliveryGuarantee
from pyflink.datastream.connectors.kafka import (KafkaOffsetsInitializer, KafkaRecordSerializationSchema, KafkaSink,
                                                 KafkaSource)
from pyflink.datastream.functions import KeyedProcessFunction, MapFunction, ProcessFunction, RuntimeContext
from pyflink.datastream.state import MapStateDescriptor, ValueStateDescriptor

from sih_detect.alerts import to_json
from sih_detect.beacon import BeaconLogic
from sih_detect.config import DetectConfig
from sih_detect.ddos import DdosLogic
from sih_detect.dns import DgaBurstLogic, DnsDomainLogic, DnsScorer
from sih_detect.encrypted import EncryptedLogic
from sih_detect.events import Invalid, flow_key, invalid_record, parse
from sih_detect.exfil import ExfilLogic
from sih_detect.flowdelta import FlowDeltaLogic
from sih_detect.incidents import IncidentLogic
from sih_detect.reference import AssetInventory
from sih_detect.scan import ScanLogic

FEATURES = OutputTag("features", Types.STRING())
INVALID = OutputTag("invalid", Types.STRING())
PICKLED = Types.PICKLED_BYTE_ARRAY()
INFER_BUCKETS = (0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05)


class _Ctx:
    def __init__(self, fn: "LogicFunction", ctx):
        self.fn, self.ctx = fn, ctx

    def value(self, name):
        return self.fn.values[name]

    def map(self, name):
        return self.fn.maps[name]

    def timer(self, ts_ms: int):
        self.ctx.timer_service().register_event_time_timer(int(ts_ms))

    def metric(self, name: str, n: int = 1):
        c = self.fn.counters.get(name)
        if c is None:
            c = self.fn.counters[name] = self.fn.metric_group.counter("sih_" + name)
        c.inc(n)

    def watermark(self) -> int:
        return self.ctx.timer_service().current_watermark()


class LogicFunction(KeyedProcessFunction):
    """Adapts a detector logic object (see sih_detect.harness) to a PyFlink keyed operator."""

    def __init__(self, factory):
        self.factory = factory
        self.logic = None

    def open(self, runtime_context: RuntimeContext):
        self.logic = self.factory()
        self.logic.open()
        self.values = {n: runtime_context.get_state(ValueStateDescriptor(n, PICKLED)) for n in self.logic.value_states}
        self.maps = {n: runtime_context.get_map_state(MapStateDescriptor(n, Types.STRING(), PICKLED))
                     for n in self.logic.map_states}
        self.metric_group = runtime_context.get_metrics_group()
        self.counters = {}
        self._findings = self.metric_group.counter("sih_findings")
        self._features = self.metric_group.counter("sih_feature_records")

    def _emit(self, outputs):
        for tag, obj in outputs:
            if tag == "out":
                self._findings.inc()
                yield obj
            elif tag == "feature":
                self._features.inc()
                yield FEATURES, to_json(obj)

    def process_element(self, value, ctx: "KeyedProcessFunction.Context"):
        yield from self._emit(self.logic.on_event(_Ctx(self, ctx), ctx.get_current_key(), value))

    def on_timer(self, timestamp: int, ctx: "KeyedProcessFunction.OnTimerContext"):
        yield from self._emit(self.logic.on_timer(_Ctx(self, ctx), ctx.get_current_key(), timestamp))


class ParseFunction(ProcessFunction):
    def open(self, runtime_context: RuntimeContext):
        mg = runtime_context.get_metrics_group()
        self.ok = mg.counter("sih_events_parsed")
        self.bad = mg.counter("sih_events_invalid")

    def process_element(self, value, ctx):
        try:
            ev = parse(value)
        except Invalid as e:
            self.bad.inc()
            yield INVALID, to_json(invalid_record(value, e.reason, e.detail))
            return
        self.ok.inc()
        yield ev


class DnsScoreFunction(ProcessFunction):
    """Loads the ONNX model once per operator instance; rules-only when it is unavailable."""

    def __init__(self, cfg: DetectConfig):
        self.cfg = cfg

    def open(self, runtime_context: RuntimeContext):
        self.scorer = DnsScorer(self.cfg, AssetInventory.load(self.cfg.inventory_path))
        self.scorer.open()
        mg = runtime_context.get_metrics_group()
        model = self.scorer.model
        mg.gauge("sih_model_active", lambda: 1 if model.active else 0)
        mg.gauge("sih_model_errors", lambda: model.errors_total)
        self.inferences = mg.counter("sih_model_inferences")
        self.abstained = mg.counter("sih_model_abstained")
        self.infer_sum_us = mg.counter("sih_model_inference_us_sum")
        self.buckets = [(b, mg.add_group("le", str(b)).counter("sih_model_inference_seconds_bucket")) for b in INFER_BUCKETS]
        self.bucket_inf = mg.add_group("le", "+Inf").counter("sih_model_inference_seconds_bucket")

    def process_element(self, ev, ctx):
        o = self.scorer.observe(ev)
        if o["p"] is not None:
            self.inferences.inc()
            secs = o["infer_s"]
            self.infer_sum_us.inc(int(secs * 1e6))
            for bound, counter in self.buckets:
                if secs <= bound:
                    counter.inc()  # cumulative buckets: count in every bucket >= the value
            self.bucket_inf.inc()
        elif o["vec"] is not None:
            self.abstained.inc()
        o["vec"] = None if o["p"] is not None else o["vec"]  # keep the vector only for the rules-only fallback
        yield o


class ToJson(MapFunction):
    def map(self, value):
        return to_json(value)


def kafka_sink(cfg: DetectConfig, topic: str) -> KafkaSink:
    return (KafkaSink.builder()
            .set_bootstrap_servers(cfg.kafka_bootstrap)
            .set_record_serializer(KafkaRecordSerializationSchema.builder()
                                   .set_topic(topic)
                                   .set_value_serialization_schema(SimpleStringSchema())
                                   .build())
            .set_delivery_guarantee(DeliveryGuarantee.AT_LEAST_ONCE)
            .set_property("acks", "all")
            .set_property("linger.ms", "5")
            .set_property("compression.type", "lz4")
            .build())


def model_info(cfg: DetectConfig) -> dict:
    """Threshold/calibration of the selected model, read at graph build time for the DNS window operator."""
    import json
    import pathlib
    try:
        root = pathlib.Path(cfg.model_root)
        sel = json.loads((root / "deployment.json").read_text())["models"]["dga"]
        meta = json.loads((root / "dga" / sel["version"] / "metadata.json").read_text())
        return {"threshold": float(meta["decision_threshold"]), "calibration_status": meta["calibration"]["status"],
                "confidence_kind": meta["calibration"]["confidence_kind"]}
    except Exception:
        return {}


def build(env: StreamExecutionEnvironment, cfg: DetectConfig) -> None:
    source = (KafkaSource.builder()
              .set_bootstrap_servers(cfg.kafka_bootstrap)
              .set_topics(cfg.raw_topic)
              .set_group_id(cfg.group_id)
              .set_starting_offsets(KafkaOffsetsInitializer.earliest())
              .set_value_only_deserializer(SimpleStringSchema())
              .set_property("commit.offsets.on.checkpoint", "true")
              .set_property("partition.discovery.interval.ms", "60000")
              .build())
    watermarks = (WatermarkStrategy.for_bounded_out_of_orderness(Duration.of_millis(cfg.out_of_orderness_ms))
                  .with_idleness(Duration.of_millis(cfg.idleness_ms)))
    raw = env.from_source(source, watermarks, "raw-events").uid("src-raw-events")

    parsed = raw.process(ParseFunction(), output_type=PICKLED).uid("normalize").name("normalize")
    invalid = parsed.get_side_output(INVALID)

    inv_path = cfg.inventory_path
    info = model_info(cfg)

    def logic(cls, **kw):
        return LogicFunction(lambda: cls(cfg, AssetInventory.load(inv_path), **kw))

    conn_like = parsed.filter(lambda e: e["log_type"] in ("conn", "flow_update")).name("conn-like")
    deltas = (conn_like.key_by(flow_key, key_type=Types.STRING())
              .process(LogicFunction(lambda: FlowDeltaLogic(cfg)), output_type=PICKLED).uid("flow-delta").name("flow-delta"))
    new_flows = deltas.filter(lambda d: d["new_flow"]).name("new-flows")

    scan = new_flows.key_by(lambda d: d["src"], key_type=Types.STRING()).process(logic(ScanLogic), output_type=PICKLED) \
        .uid("detect-scan").name("detect-scan")
    ddos = deltas.key_by(lambda d: d["dst"], key_type=Types.STRING()).process(logic(DdosLogic), output_type=PICKLED) \
        .uid("detect-ddos").name("detect-ddos")
    beacon = new_flows.key_by(lambda d: f"{d['src']}|{d['dst']}|{d['dport']}|{d['proto']}", key_type=Types.STRING()) \
        .process(logic(BeaconLogic), output_type=PICKLED).uid("detect-beacon").name("detect-beacon")
    exfil_logic = ExfilLogic(cfg, AssetInventory.load(inv_path))
    exfil = deltas.filter(exfil_logic.eligible).name("exfil-eligible") \
        .key_by(lambda d: d["src"], key_type=Types.STRING()).process(logic(ExfilLogic), output_type=PICKLED) \
        .uid("detect-exfil").name("detect-exfil")
    tls = parsed.filter(lambda e: e["log_type"] == "ssl").name("ssl") \
        .key_by(lambda e: f"{e['p']['src_ip']}|{e['p']['dst_ip']}|{e['p'].get('dst_port')}", key_type=Types.STRING()) \
        .process(logic(EncryptedLogic), output_type=PICKLED).uid("detect-encrypted").name("detect-encrypted")
    dns_obs = parsed.filter(lambda e: e["log_type"] == "dns").name("dns") \
        .process(DnsScoreFunction(cfg), output_type=PICKLED).uid("dns-score").name("dns-score")
    dns_domain = dns_obs.filter(lambda o: o["registrable"] is not None).name("dns-registrable") \
        .key_by(lambda o: f"{o['src']}|{o['registrable']}", key_type=Types.STRING()) \
        .process(logic(DnsDomainLogic, model_info=info), output_type=PICKLED).uid("detect-dns-domain").name("detect-dns-domain")
    dga_burst = dns_obs.filter(lambda o: o["nx"] and o["registrable"] is not None).name("dns-nxdomain") \
        .key_by(lambda o: o["src"], key_type=Types.STRING()) \
        .process(logic(DgaBurstLogic), output_type=PICKLED).uid("detect-dga-burst").name("detect-dga-burst")

    detectors = [scan, ddos, beacon, exfil, tls, dns_domain, dga_burst]
    findings = detectors[0].union(*detectors[1:])
    alerts = (findings.key_by(lambda f: f"{f['threat_class']}|{f['entity_type']}|{f['entity_key']}", key_type=Types.STRING())
              .process(LogicFunction(lambda: IncidentLogic(cfg)), output_type=PICKLED).uid("incident").name("incident"))

    alerts.map(ToJson(), output_type=Types.STRING()).uid("alerts-json").name("alerts-json") \
        .sink_to(kafka_sink(cfg, cfg.alerts_topic)).uid("sink-alerts").name("sink-alerts")
    feature_streams = [d.get_side_output(FEATURES) for d in detectors]
    feature_streams[0].union(*feature_streams[1:]) \
        .sink_to(kafka_sink(cfg, cfg.features_topic)).uid("sink-features").name("sink-features")
    invalid.sink_to(kafka_sink(cfg, cfg.invalid_topic)).uid("sink-invalid").name("sink-invalid")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    cfg = DetectConfig.from_env()
    env = StreamExecutionEnvironment.get_execution_environment()
    # Also set in cluster config (execution.checkpointing.*); repeated here so the job never runs unchecked.
    env.enable_checkpointing(10_000)
    build(env, cfg)
    env.execute("sih-detection")


if __name__ == "__main__":
    main()
