"""PyFlink detection job topology.

    flink run -d -py /opt/sih/flink/sih_detect/job.py -pyfs /opt/sih/lib,/opt/sih/flink

Every stateful operator has an explicit, stable uid. Watermarks come from Kafka record timestamps
(observation time set by the receiver), generated per partition inside the Java source.
Operator classes live in sih_detect.flink_ops (see the note there on why they must not be defined here).
"""
from __future__ import annotations

import json
import logging
import pathlib

from pyflink.common import Duration, Types, WatermarkStrategy
from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.datastream.connectors.base import DeliveryGuarantee
from pyflink.datastream.connectors.kafka import (KafkaOffsetsInitializer, KafkaRecordSerializationSchema, KafkaSink,
                                                 KafkaSource)

from sih_detect.beacon import BeaconLogic
from sih_detect.config import DetectConfig
from sih_detect.ddos import DdosLogic
from sih_detect.dns import DgaBurstLogic, DnsDomainLogic
from sih_detect.encrypted import EncryptedLogic
from sih_detect.events import flow_key
from sih_detect.exfil import ExfilLogic
from sih_detect.flink_ops import FEATURES, INVALID, DnsScoreFunction, LogicFunction, ParseFunction, ToJson, pickled
from sih_detect.flowdelta import FlowDeltaLogic
from sih_detect.incidents import IncidentLogic
from sih_detect.reference import AssetInventory
from sih_detect.scan import ScanLogic


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

    parsed = raw.process(ParseFunction(), output_type=pickled()).uid("normalize").name("normalize")
    invalid = parsed.get_side_output(INVALID)

    inv_path = cfg.inventory_path
    info = model_info(cfg)

    def logic(cls, **kw):
        return LogicFunction(lambda: cls(cfg, AssetInventory.load(inv_path), **kw))

    conn_like = parsed.filter(lambda e: e["log_type"] in ("conn", "flow_update")).name("conn-like")
    deltas = (conn_like.key_by(flow_key, key_type=Types.STRING())
              .process(LogicFunction(lambda: FlowDeltaLogic(cfg)), output_type=pickled()).uid("flow-delta").name("flow-delta"))
    new_flows = deltas.filter(lambda d: d["new_flow"]).name("new-flows")

    scan = new_flows.key_by(lambda d: d["src"], key_type=Types.STRING()).process(logic(ScanLogic), output_type=pickled()) \
        .uid("detect-scan").name("detect-scan")
    ddos = deltas.key_by(lambda d: d["dst"], key_type=Types.STRING()).process(logic(DdosLogic), output_type=pickled()) \
        .uid("detect-ddos").name("detect-ddos")
    beacon = new_flows.key_by(lambda d: f"{d['src']}|{d['dst']}|{d['dport']}|{d['proto']}", key_type=Types.STRING()) \
        .process(logic(BeaconLogic), output_type=pickled()).uid("detect-beacon").name("detect-beacon")
    exfil_logic = ExfilLogic(cfg, AssetInventory.load(inv_path))
    exfil = deltas.filter(exfil_logic.eligible).name("exfil-eligible") \
        .key_by(lambda d: d["src"], key_type=Types.STRING()).process(logic(ExfilLogic), output_type=pickled()) \
        .uid("detect-exfil").name("detect-exfil")
    tls = parsed.filter(lambda e: e["log_type"] == "ssl").name("ssl") \
        .key_by(lambda e: f"{e['p']['src_ip']}|{e['p']['dst_ip']}|{e['p'].get('dst_port')}", key_type=Types.STRING()) \
        .process(logic(EncryptedLogic), output_type=pickled()).uid("detect-encrypted").name("detect-encrypted")
    dns_obs = parsed.filter(lambda e: e["log_type"] == "dns").name("dns") \
        .process(DnsScoreFunction(cfg), output_type=pickled()).uid("dns-score").name("dns-score")
    dns_domain = dns_obs.filter(lambda o: o["registrable"] is not None).name("dns-registrable") \
        .key_by(lambda o: f"{o['src']}|{o['registrable']}", key_type=Types.STRING()) \
        .process(logic(DnsDomainLogic, model_info=info), output_type=pickled()).uid("detect-dns-domain").name("detect-dns-domain")
    dga_burst = dns_obs.filter(lambda o: o["nx"] and o["registrable"] is not None).name("dns-nxdomain") \
        .key_by(lambda o: o["src"], key_type=Types.STRING()) \
        .process(logic(DgaBurstLogic), output_type=pickled()).uid("detect-dga-burst").name("detect-dga-burst")

    detectors = [scan, ddos, beacon, exfil, tls, dns_domain, dga_burst]
    findings = detectors[0].union(*detectors[1:])
    alerts = (findings.key_by(lambda f: f"{f['threat_class']}|{f['entity_type']}|{f['entity_key']}", key_type=Types.STRING())
              .process(LogicFunction(lambda: IncidentLogic(cfg)), output_type=pickled()).uid("incident").name("incident"))

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
