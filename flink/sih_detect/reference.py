"""Packaged offline reference data (asset inventory). Never fetched or enriched at runtime."""
from __future__ import annotations

import json
import pathlib

from sih_common.iputil import NetSet


class AssetInventory:
    def __init__(self, doc: dict):
        self.version = doc.get("inventory_version", "unknown")
        self.local = NetSet(doc.get("local_nets", []))
        self.assets = {a["ip"]: a for a in doc.get("assets", [])}
        self.periodic = {(p["src"], p["dst"], int(p["dst_port"]), p.get("proto", "tcp")) for p in doc.get("known_periodic", [])}
        self.bulk = {(b["src"], b["dst"]) for b in doc.get("known_bulk_transfer", [])}
        self.scanners = set(doc.get("authorized_scanners", []))
        self.allow_domains = tuple(d.lower().strip(".") for d in doc.get("allow_domains", []))

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "AssetInventory":
        p = pathlib.Path(path)
        if not p.exists():
            return cls({})
        return cls(json.loads(p.read_text(encoding="utf-8")))

    def is_local(self, ip: str | None) -> bool:
        return self.local.contains(ip)

    def role(self, ip: str | None) -> str | None:
        a = self.assets.get(ip or "")
        return a.get("role") if a else None

    def known_periodic(self, src, dst, port, proto) -> bool:
        return (src, dst, int(port) if port is not None else -1, proto) in self.periodic

    def known_bulk(self, src, dst) -> bool:
        return (src, dst) in self.bulk

    def authorized_scanner(self, ip) -> bool:
        return ip in self.scanners

    def domain_allowlisted(self, name: str | None) -> bool:
        if not name:
            return False
        n = name.lower().rstrip(".")
        return any(n == d or n.endswith("." + d) for d in self.allow_domains)
