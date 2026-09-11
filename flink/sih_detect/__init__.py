"""PyFlink detection job: bounded keyed features, rules, local ONNX scoring and incident correlation.

Detector logic is plain Python over Flink-shaped state objects (ValueState: value/update/clear;
MapState: get/put/remove/contains/items/keys/is_empty/clear) so it runs unchanged inside PyFlink and in
the in-memory test harness (sih_detect.harness).
"""
