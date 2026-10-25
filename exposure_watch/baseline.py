"""The no-agent baseline: match the item against NVD's CPE rows in code.

This is what a careful engineer writes without a model: an alias table from
the inventory's product names to NVD's CPE names, then a range or exact-list
check. It never says "conditional", because nothing in a CPE row records that
exposure depends on a feature being switched on. Every agent shape is scored
against this, so an agent has to beat plain code to justify its cost.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Tuple

from .data import Item, config_line, current, nvd_description, vulnerable_rows
from .versions import in_range, range_version, split_update, compare

# inventory (vendor, product) -> NVD "vendor:product" names that describe it
ALIASES: Dict[Tuple[str, str], List[str]] = {
    ("Apache", "Log4j"): ["apache:log4j"],
    ("Progress", "MOVEit Transfer"): ["progress:moveit_transfer"],
    ("Citrix", "NetScaler ADC"): ["citrix:netscaler_application_delivery_controller"],
    ("Atlassian", "Confluence Server"): ["atlassian:confluence_server"],
    ("Atlassian", "Confluence Data Center"): ["atlassian:confluence_data_center"],
    ("Microsoft", "Exchange Server"): ["microsoft:exchange_server"],
    ("Palo Alto Networks", "PAN-OS"): ["paloaltonetworks:pan-os"],
    ("Cisco", "IOS XE"): ["cisco:ios_xe"],
    ("F5", "BIG-IP LTM"): ["f5:big-ip_local_traffic_manager"],
    ("GitLab", "GitLab Community Edition"): ["gitlab:gitlab"],
    ("Ivanti", "Connect Secure"): ["ivanti:connect_secure"],
    ("PaperCut", "PaperCut NG"): ["papercut:papercut_ng"],
}



def aliases() -> Dict[Tuple[str, str], List[str]]:
    """The table above, plus the current data set's own aliases if it has any.
    The held-out set's aliases are written by tools/heldout_build.py from KEV and
    NVD names before any verdict exists, so they carry no answer."""
    out = dict(ALIASES)
    f = current().aliases
    if f is not None and f.exists():
        out.update(_alias_file(f, f.stat().st_mtime_ns))
    return out


def names_for(vendor: str, product: str) -> List[str]:
    """The NVD names for an inventory product. Case is ignored: an administrator
    who writes "log4j" means the same product as "Log4j". Every lookup goes
    through here, so the matcher, the planted suite and retrieval agree."""
    folded = {(v.casefold(), p.casefold()): n for (v, p), n in aliases().items()}
    return folded.get((vendor.casefold(), product.casefold()), [])


@lru_cache(maxsize=None)
def _alias_file(f: Path, mtime_ns: int) -> Dict[Tuple[str, str], List[str]]:
    """One alias file's entries, read once per path and modification time."""
    out = {}
    for a in json.loads(f.read_text(encoding="utf-8"))["aliases"]:
        out[(a["vendor"], a["product"])] = a["nvd"]
    return out


_RANGE_KEYS = ("versionStartIncluding", "versionStartExcluding",
               "versionEndIncluding", "versionEndExcluding")


def judge(item: Item, cve: str) -> Tuple[str, str]:
    """('affected' | 'not_affected' | 'unknown', the row or reason that decided it).

    An affected verdict returns the deciding row exactly as the agent sees it."""
    names = names_for(item.vendor, item.product)
    if not names:
        return "unknown", "no alias for this product"
    version, update = split_update(item.vendor, item.product, item.version)
    for m in vulnerable_rows(cve):
        f = m["criteria"].split(":")
        if f"{f[3]}:{f[4]}" in names and covers(m, version, update):
            return "affected", config_line(m)
    return "not_affected", "no vulnerable row matched"


def covers(m: dict, version: str, update: str) -> bool:
    """Whether one vulnerable row describes a (version, update) as split_update
    gives it: a range that contains it, or an exact version and update equal to
    it. Whether the row is about the item's product is the caller's question."""
    if any(m.get(k) for k in _RANGE_KEYS):
        ranged = range_version(version, update)
        return in_range(ranged,
                        start=m.get("versionStartIncluding") or m.get("versionStartExcluding") or "",
                        start_incl=bool(m.get("versionStartIncluding")),
                        end=m.get("versionEndIncluding") or m.get("versionEndExcluding") or "",
                        end_incl=bool(m.get("versionEndIncluding")))
    row_version, row_update = m["criteria"].split(":")[5:7]
    if row_version in ("*", "-") or compare(version, row_version) != 0:
        return False
    return row_update == "*" or row_update == update or (row_update == "-" and update in ("-", "*"))


# A description phrase that makes exposure depend on something the inventory
# does not record. WRITTEN AFTER READING THESE 12 DESCRIPTIONS: it is tuned on
# the test set, so the code+keywords score is an upper bound for this approach,
# not a measurement of it. A held-out set of CVEs is what would measure it.
CONDITION = re.compile(r"\bfeature\b|\bwhen configured\b|\bconfigured as\b|\bwhen exposed\b", re.I)


def judge_with_keywords(item: Item, cve: str) -> Tuple[str, str]:
    """The baseline, plus one rule: an affected verdict whose NVD description
    names a feature or configuration condition becomes conditional."""
    verdict, why = judge(item, cve)
    if verdict == "affected":
        m = CONDITION.search(nvd_description(cve))
        if m:
            return "conditional", f"{why}; description condition: {m.group(0)!r}"
    return verdict, why


def nearest_row(item: Item, cve: str) -> str:
    """For an item no row matches, the row of its own product that comes closest
    below it: the range that ends just before its version, or the highest listed
    (version, update) not above it. If every row is above the item, the range
    that starts lowest. The best single passage for "not affected"; empty when
    the product has no row at all."""
    names = names_for(item.vendor, item.product)
    version, update = split_update(item.vendor, item.product, item.version)
    ranged = range_version(version, update)
    best, best_key, above, above_start = "", None, "", None
    for m in vulnerable_rows(cve):
        f = m["criteria"].split(":")
        if f"{f[3]}:{f[4]}" not in names:
            continue
        if any(m.get(k) for k in _RANGE_KEYS):
            start = m.get("versionStartIncluding") or m.get("versionStartExcluding") or ""
            if start and compare(start, ranged) > 0 and (above_start is None or compare(start, above_start) < 0):
                above, above_start = config_line(m), start
            end = m.get("versionEndIncluding") or m.get("versionEndExcluding") or ""
            if not end or compare(end, ranged) > 0:
                continue
            k = (end, "")
        else:
            row = range_version(f[5], f[6])
            if f[5] in ("*", "-") or compare(row, ranged) > 0:
                continue
            k = (row, "")
        if best_key is None or compare(k[0], best_key[0]) > 0 or (
                compare(k[0], best_key[0]) == 0 and compare(k[1], best_key[1]) > 0):
            best, best_key = config_line(m), k
    return best or above
