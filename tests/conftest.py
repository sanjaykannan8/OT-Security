"""Make every component package importable for tests (mirrors PYTHONPATH in docker/python/Dockerfile)."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for rel in ("lib", "ingest/sender", "ingest/receiver", "flink", "consumers", "backend", "data-generator", "model-training"):
    p = str(ROOT / rel)
    if p not in sys.path:
        sys.path.insert(0, p)
