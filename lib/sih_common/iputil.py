"""IP literal checks. The ipaddress module never performs name resolution."""
from __future__ import annotations

import ipaddress
from functools import lru_cache


def is_ip(text) -> bool:
    if not isinstance(text, str) or not 2 <= len(text) <= 45 or "%" in text:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=65536)
def parse(text: str):
    return ipaddress.ip_address(text)


class NetSet:
    """A set of CIDR networks (e.g. local nets from the packaged asset inventory)."""

    def __init__(self, cidrs):
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]

    def contains(self, ip: str | None) -> bool:
        if not ip or not is_ip(ip):
            return False
        addr = parse(ip)
        return any(addr.version == n.version and addr in n for n in self.nets)
