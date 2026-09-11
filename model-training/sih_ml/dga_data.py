"""Deterministic, simulation-only DGA training data.

No downloaded corpus is used. Benign second-level labels are composed from an embedded vocabulary with
common naming patterns; DGA labels come from generic algorithm styles (not reimplementations of real
malware). Splits use disjoint seeds, a held-out vocabulary for benign test names, and held-out DGA styles,
so reported results show generalisation limits honestly. Everything produced here is labelled
simulation-trained.
"""
from __future__ import annotations

import random
import string

GENERATOR_VERSION = "sih_ml.dga_data-1.0.0"

WORDS = """water power grid plant steel energy solar wind river valley green blue red north south east west city metro
smart data cloud net web tech soft info media news shop store market trade bank pay card money health care life home
house garden food fresh farm auto car motor drive road travel tour trip air sky star moon sun light bright fast quick
easy simple best prime global world national united central royal golden silver iron stone rock wood forest ocean sea
lake island mountain hill park school college academy learn study book library press print paper design studio art
music sound video film photo game play sport team club group partner service support help secure safe guard shield
control system network link connect signal wave radio mobile phone mail post message chat social friend people family
kids baby pet dog cat bird fish horse lion tiger bear eagle fox wolf apple orange mango berry coffee tea bread pizza
kitchen chef taste spice sugar salt honey milk cheese clinic doctor pharma medic dental vision eye smile beauty style
fashion wear shoe bag gift toy craft tool parts supply factory industry machine robot engine process valve pump sensor
meter panel switch cable wire fiber pipe tank boiler turbine reactor chemical oil gas fuel mining metal cement glass
plastic rubber textile cotton paint color logic micro nano quantum digital virtual cyber alpha beta delta omega nova
vertex apex summit peak core edge hub base point zone area space place land port harbor bridge tower gate door window
room office desk work job career talent skill expert pro master legend hero magic dream hope joy peace love heart mind
soul spirit faith truth""".split()

SUFFIXES = ["tech", "net", "online", "systems", "group", "labs", "cloud", "hub", "app", "ops", "works", "india", "global"]
BENIGN_TLDS = ["com", "net", "org", "io", "in", "co.in", "de", "co.uk", "info", "biz", "gov.in", "ac.in"]
DGA_TLDS = ["com", "net", "org", "info", "biz", "ru", "top", "xyz"]
CONSONANTS = "bcdfghjklmnpqrstvwxyz"
VOWELS = "aeiou"

TRAIN_FAMILIES = ("uniform", "hexhash", "alnum")
HELDOUT_FAMILIES = ("pronounceable", "dictionary", "base32")


def split_vocabulary(seed: int = 7) -> dict[str, list[str]]:
    words = sorted(set(WORDS))
    random.Random(seed).shuffle(words)
    n = len(words)
    return {"train": words[: int(n * 0.6)], "val": words[int(n * 0.6): int(n * 0.8)], "test": words[int(n * 0.8):]}


def benign_sld(rng: random.Random, words: list[str]) -> str:
    r = rng.random()
    w1, w2 = rng.choice(words), rng.choice(words)
    if r < 0.25:
        s = w1 + rng.choice(SUFFIXES) if len(w1) < 6 else w1
    elif r < 0.55:
        s = w1 + w2
    elif r < 0.65:
        s = w1 + str(rng.randint(1, 9999))
    elif r < 0.75:
        s = f"{w1}-{w2}"
    elif r < 0.85:
        s = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(2, 4))) + w1
    else:
        s = w1 + rng.choice(SUFFIXES)
    return s[:63]


def dga_sld(rng: random.Random, family: str, words: list[str]) -> str:
    if family == "uniform":
        return "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(10, 20)))
    if family == "hexhash":
        return "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(16, 32)))
    if family == "alnum":
        return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(rng.randint(10, 18)))
    if family == "pronounceable":
        n = rng.randint(8, 14)
        return "".join(rng.choice(CONSONANTS) if i % 2 == 0 else rng.choice(VOWELS) for i in range(n))
    if family == "dictionary":
        return "".join(rng.choice(words) for _ in range(rng.randint(2, 3)))[:63]
    if family == "base32":
        return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(rng.randint(16, 26)))
    raise ValueError(family)


def fqdn(rng: random.Random, sld: str, tlds: list[str]) -> str:
    sub = rng.choice(["", "", "", "www.", "api.", "mail.", "cdn.", "portal."])
    return f"{sub}{sld}.{rng.choice(tlds)}"


def make_split(seed: int, n_benign: int, dga_counts: dict[str, int], words: list[str],
               dict_words: list[str]) -> list[tuple[str, int, str]]:
    """(query, label, family) rows; label 1 = DGA. Deterministic for a given seed."""
    rng = random.Random(seed)
    rows = [(fqdn(rng, benign_sld(rng, words), BENIGN_TLDS), 0, "benign") for _ in range(n_benign)]
    for family, n in dga_counts.items():
        rows += [(fqdn(rng, dga_sld(rng, family, dict_words), DGA_TLDS), 1, family) for _ in range(n)]
    rng.shuffle(rows)
    return rows


def build_datasets(scale: float = 1.0) -> dict[str, list[tuple[str, int, str]]]:
    vocab = split_vocabulary()
    s = lambda n: max(50, int(n * scale))  # noqa: E731
    splits = {
        "train": make_split(101, s(20000), {f: s(6667) for f in TRAIN_FAMILIES}, vocab["train"], vocab["train"]),
        "val": make_split(202, s(5000), {f: s(1667) for f in TRAIN_FAMILIES}, vocab["val"], vocab["val"]),
        "test": make_split(303, s(5000), {**{f: s(1000) for f in TRAIN_FAMILIES}, **{f: s(1000) for f in HELDOUT_FAMILIES}},
                           vocab["test"], vocab["test"]),
    }
    # Remove exact query overlap so no test/val name was seen in training.
    seen = {q for q, _, _ in splits["train"]}
    for name in ("val", "test"):
        splits[name] = [r for r in splits[name] if r[0] not in seen]
        seen |= {q for q, _, _ in splits[name]}
    return splits
