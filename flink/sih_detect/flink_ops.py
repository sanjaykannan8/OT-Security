"""PyFlink operator classes.

They live in an importable module, not in job.py: cloudpickle serializes classes defined in the submitted
`__main__` script by value, together with the module globals they use (TypeInformation and OutputTag
objects that hold py4j/Java references and locks), which fails. Classes from an importable module are
pickled by reference and re-imported on the Python workers (the module ships via -pyfs).
"""
from __future__ import annotations

from pyflink.common import Types
from pyflink.datastream import OutputTag
from pyflink.datastream.functions import KeyedProcessFunction, MapFunction, ProcessFunction, RuntimeContext
from pyflink.datastream.state import MapStateDescriptor, ValueStateDescriptor

from sih_detect.alerts import to_json
from sih_detect.config import DetectConfig
from sih_detect.dns import DnsScorer
from sih_detect.events import Invalid, invalid_record, parse
from sih_detect.reference import AssetInventory

FEATURES = OutputTag("features", Types.STRING())
INVALID = OutputTag("invalid", Types.STRING())
INFER_BUCKETS = (0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05)


def pickled():
    """A fresh TypeInformation per use (instances get bound to Java objects during graph building)."""
    return Types.PICKLED_BYTE_ARRAY()


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
        self.values = {n: runtime_context.get_state(ValueStateDescriptor(n, pickled())) for n in self.logic.value_states}
        self.maps = {n: runtime_context.get_map_state(MapStateDescriptor(n, Types.STRING(), pickled()))
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
