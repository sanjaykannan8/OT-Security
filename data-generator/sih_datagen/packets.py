"""Hand-built Ethernet/IPv4/TCP/UDP frames, DNS messages, TLS hellos and a PCAP writer.

All timestamps are integer microseconds. Packets are buffered and written in timestamp order so Zeek sees a
monotonic capture.
"""
from __future__ import annotations

import random
import socket
import struct

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _mac(ip: str) -> bytes:
    return b"\x02\x00" + socket.inet_aton(ip)


class Capture:
    def __init__(self):
        self.items: list[tuple[int, int, bytes]] = []
        self._n = 0
        self._ipid = 1

    def __len__(self) -> int:
        return len(self.items)

    def _ip(self, ts_us: int, src: str, dst: str, proto: int, l4: bytes) -> None:
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), self._ipid & 0xFFFF, 0x4000, 64, proto, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
        hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
        self._ipid += 1
        self.items.append((int(ts_us), self._n, _mac(dst) + _mac(src) + b"\x08\x00" + hdr + l4))
        self._n += 1

    def tcp(self, ts_us: int, src: str, sport: int, dst: str, dport: int, seq: int, ack: int, flags: int, data: bytes = b"") -> None:
        hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(data))
        c = _csum(pseudo + hdr + data)
        self._ip(ts_us, src, dst, 6, hdr[:16] + struct.pack("!H", c) + hdr[18:] + data)

    def udp(self, ts_us: int, src: str, sport: int, dst: str, dport: int, data: bytes) -> None:
        length = 8 + len(data)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, length)
        c = _csum(pseudo + struct.pack("!HHHH", sport, dport, length, 0) + data) or 0xFFFF
        self._ip(ts_us, src, dst, 17, struct.pack("!HHHH", sport, dport, length, c) + data)

    def raw_ip(self, ts_us: int, frame: bytes) -> None:
        """A deliberately malformed Ethernet frame (for weird/malformed scenarios)."""
        self.items.append((int(ts_us), self._n, frame))
        self._n += 1

    def write(self, path) -> dict:
        self.items.sort(key=lambda x: (x[0], x[1]))
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, _, frame in self.items:
                f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(frame), len(frame)))
                f.write(frame)
        return {"packets": len(self.items), "first_us": self.items[0][0] if self.items else None,
                "last_us": self.items[-1][0] if self.items else None}


class TcpFlow:
    """Sequence-correct TCP conversation between a client and a server."""

    def __init__(self, cap: Capture, cli: str, sport: int, srv: str, dport: int, rng: random.Random, rtt_us: int = 1000):
        self.cap, self.cli, self.sport, self.srv, self.dport, self.rtt = cap, cli, sport, srv, dport, rtt_us
        self.cs = rng.randrange(1 << 32)
        self.ss = rng.randrange(1 << 32)

    def open(self, t: int) -> int:
        c = self.cap
        c.tcp(t, self.cli, self.sport, self.srv, self.dport, self.cs, 0, SYN)
        self.cs += 1
        c.tcp(t + self.rtt // 2, self.srv, self.dport, self.cli, self.sport, self.ss, self.cs, SYN | ACK)
        self.ss += 1
        c.tcp(t + self.rtt, self.cli, self.sport, self.srv, self.dport, self.cs, self.ss, ACK)
        return t + self.rtt

    def send(self, t: int, from_client: bool, payload: bytes, mss: int = 1448, gap_us: int = 50) -> int:
        c = self.cap
        segs = [payload[i:i + mss] for i in range(0, len(payload), mss)] or [b""]
        for i, seg in enumerate(segs):
            if from_client:
                c.tcp(t, self.cli, self.sport, self.srv, self.dport, self.cs, self.ss, PSH | ACK, seg)
                self.cs += len(seg)
            else:
                c.tcp(t, self.srv, self.dport, self.cli, self.sport, self.ss, self.cs, PSH | ACK, seg)
                self.ss += len(seg)
            if i % 2 == 1 or i == len(segs) - 1:
                ta = t + self.rtt // 2
                if from_client:
                    c.tcp(ta, self.srv, self.dport, self.cli, self.sport, self.ss, self.cs, ACK)
                else:
                    c.tcp(ta, self.cli, self.sport, self.srv, self.dport, self.cs, self.ss, ACK)
            t += gap_us
        return t + self.rtt

    def close(self, t: int) -> int:
        c = self.cap
        c.tcp(t, self.cli, self.sport, self.srv, self.dport, self.cs, self.ss, FIN | ACK)
        self.cs += 1
        c.tcp(t + self.rtt // 2, self.srv, self.dport, self.cli, self.sport, self.ss, self.cs, FIN | ACK)
        self.ss += 1
        c.tcp(t + self.rtt, self.cli, self.sport, self.srv, self.dport, self.cs, self.ss, ACK)
        return t + self.rtt


def syn_probe(cap: Capture, t: int, src: str, sport: int, dst: str, dport: int, rng: random.Random, answer: str | None) -> None:
    """A SYN with an optional reply: 'rst' (closed port), 'synack' (open, prober then resets) or None."""
    seq = rng.randrange(1 << 32)
    cap.tcp(t, src, sport, dst, dport, seq, 0, SYN)
    if answer == "rst":
        cap.tcp(t + 400, dst, dport, src, sport, 0, seq + 1, RST | ACK)
    elif answer == "synack":
        sseq = rng.randrange(1 << 32)
        cap.tcp(t + 400, dst, dport, src, sport, sseq, seq + 1, SYN | ACK)
        cap.tcp(t + 800, src, sport, dst, dport, seq + 1, 0, RST)


# ------------------------------------------------------------------ DNS

def _name(qname: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in qname.rstrip(".").split(".")) + b"\x00"


def dns_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _name(qname) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, qname: str, qtype: int = 1, rcode: int = 0, answers: list[tuple[int, int, bytes]] = ()) -> bytes:
    flags = 0x8000 | 0x0100 | 0x0080 | (rcode & 0xF)
    body = _name(qname) + struct.pack("!HH", qtype, 1)
    for rtype, ttl, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0) + body


def a_record(ip: str, ttl: int = 300) -> tuple[int, int, bytes]:
    return (1, ttl, socket.inet_aton(ip))


def txt_record(text: bytes, ttl: int = 60) -> tuple[int, int, bytes]:
    return (16, ttl, bytes([len(text)]) + text)


def dns_exchange(cap: Capture, t: int, client: str, resolver: str, qname: str, rng: random.Random, qtype: int = 1,
                 rcode: int = 0, answers=(), rtt_us: int = 3000) -> None:
    sport = rng.randint(20000, 60999)
    txid = rng.randrange(1 << 16)
    cap.udp(t, client, sport, resolver, 53, dns_query(txid, qname, qtype))
    cap.udp(t + rtt_us, resolver, 53, client, sport, dns_response(txid, qname, qtype, rcode, list(answers)))


# ------------------------------------------------------------------ TLS (metadata only; payloads are random bytes)

def _len3(n: int) -> bytes:
    return n.to_bytes(3, "big")


def client_hello(rng: random.Random, version: int = 0x0301, sni: str | None = None, tls13: bool = False) -> bytes:
    ciphers = [0x1301, 0x1302, 0xC02F] if tls13 else [0x002F, 0x0035, 0x000A]
    exts = b""
    if sni:
        name = sni.encode("ascii")
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        lst = struct.pack("!H", len(entry)) + entry
        exts += struct.pack("!HH", 0x0000, len(lst)) + lst
    if tls13:
        exts += struct.pack("!HHB", 0x002B, 3, 2) + struct.pack("!H", 0x0304)
        exts += struct.pack("!HHH", 0x000A, 4, 2) + struct.pack("!H", 0x001D)
        share = struct.pack("!HH", 0x001D, 32) + bytes(rng.randrange(256) for _ in range(32))
        exts += struct.pack("!HHH", 0x0033, len(share) + 2, len(share)) + share
    body = struct.pack("!H", 0x0303 if tls13 else version) + bytes(rng.randrange(256) for _ in range(32)) + b"\x00"
    body += struct.pack("!H", 2 * len(ciphers)) + b"".join(struct.pack("!H", c) for c in ciphers) + b"\x01\x00"
    if exts:
        body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + _len3(len(body)) + body
    return b"\x16" + struct.pack("!HH", 0x0301 if tls13 else version, len(hs)) + hs


def server_hello(rng: random.Random, version: int = 0x0301, cipher: int = 0x002F, tls13: bool = False) -> bytes:
    exts = b""
    if tls13:
        cipher = 0x1301
        exts = struct.pack("!HHH", 0x002B, 2, 0x0304)
        share = struct.pack("!HH", 0x001D, 32) + bytes(rng.randrange(256) for _ in range(32))
        exts += struct.pack("!HH", 0x0033, len(share)) + share
    body = struct.pack("!H", 0x0303 if tls13 else version) + bytes(rng.randrange(256) for _ in range(32)) + b"\x00"
    body += struct.pack("!H", cipher) + b"\x00"
    if exts:
        body += struct.pack("!H", len(exts)) + exts
    hs = b"\x02" + _len3(len(body)) + body
    return b"\x16" + struct.pack("!HH", 0x0303 if tls13 else version, len(hs)) + hs


def change_cipher_spec(version: int) -> bytes:
    return b"\x14" + struct.pack("!HH", version, 1) + b"\x01"


def app_data(rng: random.Random, version: int, n: int) -> bytes:
    return b"\x17" + struct.pack("!HH", version, n) + bytes(rng.randrange(256) for _ in range(n))


def tls_session(cap: Capture, t: int, cli: str, sport: int, srv: str, dport: int, rng: random.Random, *,
                version: int = 0x0301, sni: str | None = None, tls13: bool = False, up: int = 400, down: int = 1200) -> int:
    f = TcpFlow(cap, cli, sport, srv, dport, rng)
    t = f.open(t)
    t = f.send(t, True, client_hello(rng, version, sni, tls13))
    rec_ver = 0x0303 if tls13 else version
    t = f.send(t, False, server_hello(rng, version, tls13=tls13) + change_cipher_spec(rec_ver))
    t = f.send(t, True, change_cipher_spec(rec_ver) + app_data(rng, rec_ver, up))
    t = f.send(t, False, app_data(rng, rec_ver, down))
    return f.close(t + 2000)
