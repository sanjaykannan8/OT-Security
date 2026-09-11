"""Write scenario PCAPs and ground-truth manifests to local files.

    python -m sih_datagen.pcap --out /data/fixtures/pcaps [--scenario all|name ...]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib

from sih_datagen.scenarios import SCENARIOS


def generate(out: pathlib.Path, names: list[str]) -> list[dict]:
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for name in names:
        cap, manifest = SCENARIOS[name]()
        pcap_path = out / f"{name}.pcap"
        info = cap.write(pcap_path)
        manifest.update(info)
        manifest["pcap_sha256"] = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
        manifest["pcap_bytes"] = pcap_path.stat().st_size
        (out / f"{name}.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        results.append({"scenario": name, "packets": info["packets"], "bytes": manifest["pcap_bytes"]})
    return results


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/data/fixtures/pcaps")
    ap.add_argument("--scenario", nargs="*", default=["all"])
    a = ap.parse_args(argv)
    names = sorted(SCENARIOS) if a.scenario in (["all"], []) else a.scenario
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        raise SystemExit(f"unknown scenario(s) {unknown}; choose from {sorted(SCENARIOS)}")
    for r in generate(pathlib.Path(a.out), names):
        print(json.dumps(r))


if __name__ == "__main__":
    main()
