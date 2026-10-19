"""Load the frozen public data and render the source documents agents may quote.

Everything an agent is allowed to rely on is rendered here as plain text, and
the verifier checks quotes against exactly these strings. If a fact is not in
one of these documents, the pipeline does not know it.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

KEV_FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
              "shortDescription", "requiredAction", "dueDate",
              "knownRansomwareCampaignUse", "notes")


@dataclass(frozen=True)
class Item:
    id: str
    vendor: str
    product: str
    version: str
    where: str


def load_inventory(path: Path) -> List[Item]:
    with open(path, newline="", encoding="utf-8") as f:
        return [Item(r["id"], r["vendor"], r["product"], r["version"], r["where"])
                for r in csv.DictReader(f)]


@lru_cache(maxsize=1)
def kev_index() -> Dict[str, dict]:
    d = json.loads((FIXTURES / "kev_catalog.json").read_text(encoding="utf-8"))
    return {v["cveID"]: v for v in d["vulnerabilities"]}


def kev_text(cve: str) -> str:
    e = kev_index()[cve]
    return "\n".join(f"{k}: {e.get(k, '')}" for k in KEV_FIELDS)


@lru_cache(maxsize=None)
def nvd_record(cve: str) -> dict:
    d = json.loads((FIXTURES / "nvd" / f"{cve}.json").read_text(encoding="utf-8"))
    return d["vulnerabilities"][0]["cve"]


def nvd_description(cve: str) -> str:
    return next(x["value"] for x in nvd_record(cve)["descriptions"] if x["lang"] == "en")


def vulnerable_rows(cve: str) -> List[dict]:
    rows = []
    for cfg in nvd_record(cve).get("configurations", []):
        for node in cfg["nodes"]:
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    rows.append(m)
    return rows


def _words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower()))


def nvd_config_text(cve: str, item: Item) -> str:
    """The vulnerable CPE rows that share a word with the item's vendor or
    product, one per line. Log4j's record alone carries 396 rows across every
    product that bundles it; the agent gets the ones that could be its item."""
    want = _words(item.vendor) | _words(item.product)
    lines = []
    for m in vulnerable_rows(cve):
        f = m["criteria"].split(":")
        if not (_words(f[3]) | _words(f[4].replace("_", " "))) & want:
            continue
        lines.append(config_line(m))
    return "\n".join(lines)


def config_line(m: dict) -> str:
    """One CPE row as the agent sees it: criteria, then any version bounds."""
    parts = [m["criteria"]]
    for k in ("versionStartIncluding", "versionStartExcluding",
              "versionEndIncluding", "versionEndExcluding"):
        if m.get(k):
            parts.append(f"{k}={m[k]}")
    return " | ".join(parts)


def sources_for(item: Item, cve: str) -> Dict[str, str]:
    """The three documents a claim may cite, by name."""
    return {"kev": kev_text(cve), "nvd_description": nvd_description(cve),
            "nvd_config": nvd_config_text(cve, item)}
