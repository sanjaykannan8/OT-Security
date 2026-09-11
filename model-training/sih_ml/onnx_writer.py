"""Minimal ONNX protobuf writer for the standardized logistic-regression graph.

Writing the few messages we need by hand avoids converter dependencies and keeps the exported graph
explicit: features -> Sub(mean) -> Div(scale) -> MatMul(W) -> Add(B) -> Sigmoid -> p_dga.
Field numbers follow onnx/onnx.proto (ModelProto, GraphProto, NodeProto, TensorProto, ValueInfoProto).
"""
from __future__ import annotations

import struct

IR_VERSION = 8
OPSET = 13
FLOAT = 1  # TensorProto.DataType.FLOAT


def _varint(n: int) -> bytes:
    if n < 0:
        n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _key(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _int(field: int, n: int) -> bytes:
    return _key(field, 0) + _varint(n)


def _bytes(field: int, data: bytes) -> bytes:
    return _key(field, 2) + _varint(len(data)) + data


def _str(field: int, s: str) -> bytes:
    return _bytes(field, s.encode("utf-8"))


def tensor(name: str, dims: list[int], values: list[float]) -> bytes:
    body = b"".join(_int(1, d) for d in dims) + _int(2, FLOAT) + _str(8, name)
    body += _bytes(9, struct.pack("<%df" % len(values), *values))
    return body


def value_info(name: str, dims: list) -> bytes:
    shape = b""
    for d in dims:
        dim = _str(2, d) if isinstance(d, str) else _int(1, d)
        shape += _bytes(1, dim)
    tensor_type = _int(1, FLOAT) + _bytes(2, shape)
    return _str(1, name) + _bytes(2, _bytes(1, tensor_type))


def node(op: str, inputs: list[str], outputs: list[str], name: str) -> bytes:
    return b"".join(_str(1, i) for i in inputs) + b"".join(_str(2, o) for o in outputs) + _str(3, name) + _str(4, op)


def logistic_model(means: list[float], scales: list[float], coefficients: list[float], intercept: float,
                   input_name: str = "features", output_name: str = "p_dga", doc: str = "",
                   metadata: dict[str, str] | None = None) -> bytes:
    d = len(coefficients)
    if not (len(means) == len(scales) == d):
        raise ValueError("means, scales and coefficients must have the same length")
    graph = b"".join([
        _bytes(1, node("Sub", [input_name, "mean"], ["centered"], "standardize_sub")),
        _bytes(1, node("Div", ["centered", "scale"], ["z"], "standardize_div")),
        _bytes(1, node("MatMul", ["z", "W"], ["logit0"], "linear")),
        _bytes(1, node("Add", ["logit0", "B"], ["logit"], "bias")),
        _bytes(1, node("Sigmoid", ["logit"], [output_name], "sigmoid")),
        _str(2, "dga_logistic"),
        _bytes(5, tensor("mean", [d], means)),
        _bytes(5, tensor("scale", [d], scales)),
        _bytes(5, tensor("W", [d, 1], coefficients)),
        _bytes(5, tensor("B", [1], [intercept])),
        _bytes(11, value_info(input_name, ["batch", d])),
        _bytes(12, value_info(output_name, ["batch", 1])),
    ])
    model = _int(1, IR_VERSION) + _str(2, "sih_ml.onnx_writer") + _str(3, "1.0.0") + _str(4, "org.sih")
    model += _int(5, 1) + _str(6, doc) + _bytes(7, graph) + _bytes(8, _str(1, "") + _int(2, OPSET))
    for k, v in (metadata or {}).items():
        model += _bytes(14, _str(1, k) + _str(2, v))
    return model
