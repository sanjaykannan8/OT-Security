"""DGA lexical features (contract: schemas/features/dga_lexical.v1.json).

One implementation shared by model training and the PyFlink runtime, so train/serve feature order and
formulas cannot drift. The only learned preprocessing input is the benign character-bigram log-probability
table, which ships inside the model bundle (preprocessing.json).
"""
from __future__ import annotations

import math
from collections import Counter

FEATURE_SCHEMA_VERSION = "dga_lexical-1.0.0"
HASH_BUCKETS = 32

# Offline, packaged approximation of the public suffix list: multi-label suffixes that commonly appear in
# the fixtures and in Indian/industrial contexts. Documented limitation: unknown multi-label suffixes are
# treated as single-label TLDs.
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "net.cn", "org.cn", "com.sg", "com.my", "co.nz", "co.za", "com.mx", "com.tr", "co.kr",
    "com.hk", "com.tw", "co.id", "com.ar", "com.sa", "com.eg", "co.th",
})
NON_REGISTRABLE = frozenset({"local", "localdomain", "lan", "internal", "home", "arpa", "corp", "intranet", "test", "invalid"})

SYMBOLS = "abcdefghijklmnopqrstuvwxyz0123456789-^$?"
SYMBOL_INDEX = {c: i for i, c in enumerate(SYMBOLS)}
N_SYMBOLS = len(SYMBOLS)
VOWELS = frozenset("aeiou")
CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")
HEX = frozenset("0123456789abcdef")

FEATURE_NAMES = [
    "sld_len", "sld_entropy", "sld_digit_ratio", "sld_vowel_ratio", "sld_consonant_ratio",
    "sld_max_consonant_run", "sld_max_digit_run", "sld_hyphen_count", "sld_unique_char_ratio", "sld_hex_ratio",
    "query_len", "subdomain_depth", "suffix_label_count", "sld_bigram_logprob_mean",
] + [f"sld_bigram_hash_{i:02d}" for i in range(HASH_BUCKETS)]
DIMENSION = len(FEATURE_NAMES)
MIN_SLD_LEN = 6


class NotEligible(Exception):
    """The query cannot be scored; `reason` is recorded as the model-eligibility reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def normalize_name(query) -> str:
    if not isinstance(query, str) or not query:
        raise NotEligible("query_unavailable")
    name = query.strip().lower().rstrip(".")
    if not name or len(name) > 253:
        raise NotEligible("query_out_of_range")
    return name


def split_registrable(name: str) -> tuple[str, str, str, list[str]]:
    """Return (registrable_domain, sld_label, suffix, subdomain_labels)."""
    labels = name.split(".")
    if len(labels) < 2 or any(not lab for lab in labels):
        raise NotEligible("not_registrable")
    if labels[-1] in NON_REGISTRABLE or all(ch.isdigit() for lab in labels for ch in lab):
        raise NotEligible("not_registrable")
    if ":" in name:
        raise NotEligible("not_registrable")
    suffix_len = 2 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 1
    if len(labels) < suffix_len + 1:
        raise NotEligible("not_registrable")
    suffix = ".".join(labels[-suffix_len:])
    sld = labels[-suffix_len - 1]
    return f"{sld}.{suffix}", sld, suffix, labels[:-suffix_len - 1]


def registrable_or_none(query) -> str | None:
    try:
        return split_registrable(normalize_name(query))[0]
    except NotEligible:
        return None


def fnv1a32(text: str) -> int:
    h = 0x811C9DC5
    for b in text.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def entropy(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _max_run(s: str, charset) -> int:
    best = run = 0
    for ch in s:
        run = run + 1 if ch in charset else 0
        best = max(best, run)
    return best


def _symbol(ch: str) -> int:
    return SYMBOL_INDEX.get(ch, SYMBOL_INDEX["?"])


def bigrams(sld: str) -> list[tuple[int, int]]:
    seq = [SYMBOL_INDEX["^"]] + [_symbol(c) for c in sld] + [SYMBOL_INDEX["$"]]
    return list(zip(seq, seq[1:]))


def fit_bigram_table(benign_slds) -> list[list[float]]:
    """Add-one smoothed natural-log P(next | previous) from benign training labels only."""
    counts = [[1] * N_SYMBOLS for _ in range(N_SYMBOLS)]
    for sld in benign_slds:
        for a, b in bigrams(sld):
            counts[a][b] += 1
    table = []
    for row in counts:
        total = sum(row)
        table.append([math.log(c / total) for c in row])
    return table


def extract(query, bigram_table) -> tuple[list[float], dict]:
    """Feature vector in contract order plus explanation context. Raises NotEligible."""
    name = normalize_name(query)
    registrable, sld, suffix, sub = split_registrable(name)
    n = len(sld)
    if n < MIN_SLD_LEN:
        raise NotEligible("label_too_short")
    grams = bigrams(sld)
    hashed = [0.0] * HASH_BUCKETS
    lp = 0.0
    for a, b in grams:
        hashed[fnv1a32(SYMBOLS[a] + SYMBOLS[b]) % HASH_BUCKETS] += 1.0
        lp += bigram_table[a][b]
    hashed = [h / len(grams) for h in hashed]
    vec = [
        float(min(n, 63)),
        entropy(sld),
        sum(c.isdigit() for c in sld) / n,
        sum(c in VOWELS for c in sld) / n,
        sum(c in CONSONANTS for c in sld) / n,
        float(min(_max_run(sld, CONSONANTS), 63)),
        float(min(_max_run(sld, "0123456789"), 63)),
        float(min(sld.count("-"), 10)),
        len(set(sld)) / n,
        sum(c in HEX for c in sld) / n,
        float(min(len(name), 253)),
        float(min(len(sub), 10)),
        float(suffix.count(".") + 1),
        lp / len(grams),
    ] + hashed
    info = {"registrable": registrable, "sld": sld, "suffix": suffix, "subdomain_depth": len(sub)}
    return vec, info


def lexical_rule(vec: list[float]) -> bool:
    """Rules-only fallback used when no model is active (heuristic, uncalibrated)."""
    length, ent, digit_ratio, _v, _c, cons_run = vec[0], vec[1], vec[2], vec[3], vec[4], vec[5]
    return length >= 10 and ent >= 3.3 and (digit_ratio >= 0.2 or cons_run >= 4)
