"""Version handling for the formats vendors actually ship.

NVD describes affected software two ways: a range on the CPE version field
(versionStartIncluding, versionEndExcluding, ...) or an explicit list of
(version, update) pairs. Inventories record versions the way an administrator
writes them: "13.1-49.13", "17.9.4a", "10.2.9-h1", "22.6R2", "2019 CU8".

Comparison is token by token: numbers numerically, letters alphabetically.
When a number meets a letter at the same position the letter sorts first,
which is pre-release order ("2.0-beta9" before "2.0.1"). When one version is
a prefix of the other, the shorter sorts first, which is rebuild order
("17.9.4" before "17.9.4a"), unless the rest is only zeros ("2.4" equals
"2.4.0"). Both rules are stated because each is wrong for
some vendor; the answer key in eval/ records which pairs exercise them.
"""
from __future__ import annotations

import re
from typing import List, Tuple, Union

Token = Union[int, str]
_TOKEN = re.compile(r"\d+|[a-z]+")


def tokens(v: str) -> List[Token]:
    return [int(t) if t.isdigit() else t for t in _TOKEN.findall(v.lower())]


def compare(a: str, b: str) -> int:
    """-1, 0 or 1, as a is before, equal to, or after b."""
    ta, tb = tokens(a), tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            return -1 if x < y else 1
        return -1 if isinstance(x, str) else 1
    if len(ta) == len(tb):
        return 0
    # "2.4" and "2.4.0" are the same release. NVD starts the Log4Shell range at
    # 2.4.0, so without this an inventory's "2.4" fell outside it as not_affected.
    if all(t == 0 for t in (ta[len(tb):] or tb[len(ta):])):
        return 0
    return -1 if len(ta) < len(tb) else 1


def in_range(v: str, start: str = "", start_incl: bool = True,
             end: str = "", end_incl: bool = False) -> bool:
    if start:
        c = compare(v, start)
        if c < 0 or (c == 0 and not start_incl):
            return False
    if end:
        c = compare(v, end)
        if c > 0 or (c == 0 and not end_incl):
            return False
    return True


def split_update(vendor: str, product: str, written: str) -> Tuple[str, str]:
    """Split an administrator-written version into NVD's (version, update).

    The update is "-" when the vendor's scheme has one and this build carries
    none, and "*" when the scheme has no update field at all.
    """
    s = written.strip()
    m = re.fullmatch(r"(\d{4})\s*CU\s*(\d+)", s, re.I)            # Exchange: 2019 CU8
    if m:
        return m.group(1), f"cumulative_update_{m.group(2)}"
    if product.lower() == "pan-os":                                 # PAN-OS: 10.2.9-h1
        m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(h\d+))?", s, re.I)
        if m:
            return m.group(1), (m.group(2) or "-").lower()
    if vendor.lower() == "ivanti":                                  # Ivanti: 22.6R2
        m = re.fullmatch(r"(\d+\.\d+)R(\d+(?:\.\d+)*)", s, re.I)
        if m:
            return m.group(1), f"r{m.group(2)}"
    # Log4j: 2.0-beta9, also written 2.0.beta9 or 2.0beta9. NVD lists it as
    # log4j:2.0:beta9, so left whole it never equals a row, and Log4Shell's first
    # vulnerable release came back not_affected.
    if product.lower() == "log4j":
        m = re.fullmatch(r"(\d+(?:\.\d+)*)[-.]?((?:alpha|beta|rc)\d+)", s, re.I)
        if m:
            return m.group(1), m.group(2).lower()
    return s, "*"
