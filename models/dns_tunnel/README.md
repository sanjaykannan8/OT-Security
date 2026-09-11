# dns_tunnel

Status: **no ONNX model**. Rules/statistics only: unique-subdomain count, length and entropy per source/domain window (flink/sih_detect/dns.py). A GBDT challenger needs labelled tunnel captures (e.g. CIC-Bell-DNS-EXF-2021 re-extracted through Zeek).

This directory intentionally holds no model files. Adding one requires a trained, evaluated bundle written by model-training (see models/dga/README.md) and a deployment-manifest entry.
