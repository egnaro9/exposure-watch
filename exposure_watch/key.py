"""The answer key, as frozen before any agent ran, and with its errata.

eval/ground_truth.json is never edited after a live run has scored against it.
A label found wrong later goes in eval/errata.json with what it was, what it is
now, why, and how the error was found. Reports score every shape against both,
so a reader can see exactly what the corrections changed and judge whether a
correction made after seeing agent output was earned.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from .data import current

# None means "the current data set's file"; tests point these at temporary files.
KEY: Optional[Path] = None
ERRATA: Optional[Path] = None


def errata() -> List[dict]:
    f = ERRATA or current().errata
    return json.loads(f.read_text(encoding="utf-8"))["errata"] if f.exists() else []


def load_pairs(with_errata: bool = True) -> List[dict]:
    pairs = json.loads((KEY or current().key).read_text(encoding="utf-8"))["pairs"]
    if not with_errata:
        return pairs
    fixes = {(e["item"], e["cve"]): e for e in errata()}
    out = []
    for p in pairs:
        e = fixes.pop((p["item"], p["cve"]), None)
        if e:
            if e["was"] != p["truth"]:
                raise ValueError(f"erratum for {p['item']} {p['cve']} says it was {e['was']!r}, key says {p['truth']!r}")
            p = {**p, "truth": e["now"], "erratum": e["why"]}
        out.append(p)
    if fixes:
        raise ValueError(f"errata name pairs that are not in the key: {sorted(fixes)}")
    return out
