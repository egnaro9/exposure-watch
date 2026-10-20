"""Build the held-out set exactly as eval/heldout/PREREG.md says, with no hand-picking.

    python tools/heldout_build.py fetch    # KEV catalog + one NVD record per candidate (network)
    python tools/heldout_build.py build    # selection, inventory, aliases, labeling packet (offline)

fetch saves what it downloads under fixtures/heldout/ and never edits it afterwards.
build reads only those files, so anyone can rerun it and get the same set. Every
exclusion is counted by reason in eval/heldout/selection.json.

The build intent (inside or outside the affected range) is written to
eval/heldout/build_intent.json. It is not the answer key: the key comes from
three blind labelers who never see it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from exposure_watch import data                     # noqa: E402
from exposure_watch.versions import compare          # noqa: E402

FIX = ROOT / "fixtures" / "heldout"
OUT = ROOT / "eval" / "heldout"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
WINDOW = ("2026-07-01", "2026-10-19")       # dateAdded, inclusive; NVD published must be >= the start
CAP, FLOOR = 30, 15
SEED = 20261019
UA = {"User-Agent": "exposure-watch held-out builder (github.com/egnaro9/exposure-watch)"}
RANGE_KEYS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")


def get(url: str) -> bytes:
    for attempt in range(6):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 500, 502, 503, 504) and attempt < 5:
                time.sleep(15 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            if attempt < 5:
                time.sleep(15 * (attempt + 1))
                continue
            raise
    raise RuntimeError("unreachable")


def candidates(kev: dict, start: str, end: str) -> list:
    return sorted((v for v in kev["vulnerabilities"] if start <= v["dateAdded"] <= end),
                  key=lambda v: (v["dateAdded"], v["cveID"]), reverse=True)


def cmd_fetch(a) -> None:
    (FIX / "nvd").mkdir(parents=True, exist_ok=True)
    kev_path = FIX / "kev_catalog.json"
    if not kev_path.exists():
        kev_path.write_bytes(get(KEV_URL))
    kev = json.loads(kev_path.read_text(encoding="utf-8"))
    cands = candidates(kev, a.start, WINDOW[1])
    print(f"KEV {kev.get('catalogVersion')} sha256 {hashlib.sha256(kev_path.read_bytes()).hexdigest()}: "
          f"{len(cands)} added {a.start}..{WINDOW[1]}", flush=True)
    for n, v in enumerate(cands, 1):
        p = FIX / "nvd" / f"{v['cveID']}.json"
        if p.exists():
            continue
        p.write_bytes(get(NVD_URL.format(v["cveID"])))
        print(f"{n}/{len(cands)} {v['cveID']}", flush=True)
        time.sleep(6.5)            # NVD allows 5 unauthenticated requests per 30 seconds


def words(s: str) -> set:
    return set(re.findall(r"[a-z0-9]+", s.lower().replace("_", " ")))


def nvd_cve(cve: str):
    p = FIX / "nvd" / f"{cve}.json"
    if not p.exists():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    vs = d.get("vulnerabilities") or []
    return vs[0]["cve"] if vs else None


def vulnerable(rec: dict) -> list:
    return [m for c in rec.get("configurations", []) for n in c["nodes"]
            for m in n.get("cpeMatch", []) if m.get("vulnerable")]


def choose_product(kev_entry: dict, rows: list):
    groups = {}
    for m in rows:
        f = m["criteria"].split(":")
        if f[2] in ("a", "o"):
            groups.setdefault(f"{f[3]}:{f[4]}", []).append(m)
    if not groups:
        return None, {}
    want = words(kev_entry["vendorProject"]) | words(kev_entry["product"])
    order = list(groups)
    scored = {g: len(words(g.replace(":", " ")) & want) for g in groups}
    best = max(order, key=lambda g: (scored[g], len(groups[g]), -order.index(g)))
    return best, {"scores": scored, "rows": groups[best]}


def bump(v: str, step: int):
    """The version with its last number moved by step, keeping the rest as written."""
    ms = list(re.finditer(r"\d+", v))
    if not ms:
        return None
    m = ms[-1]
    n = int(m.group()) + step
    if n < 0:
        return None
    return v[:m.start()] + str(n).zfill(len(m.group()) if m.group().startswith("0") else 0) + v[m.end():]


def build_versions(rows: list) -> dict:
    ranged = [m for m in rows if any(m.get(k) for k in RANGE_KEYS)]
    if ranged:
        def upper(m):
            return m.get("versionEndIncluding") or m.get("versionEndExcluding") or ""
        open_top = [m for m in ranged if not upper(m)]
        pick = open_top[0] if open_top else max(ranged, key=lambda m: _Key(upper(m)))
        out = {"row": data.config_line(pick), "inside": None, "outside": None}
        if pick.get("versionStartIncluding"):
            out["inside"], out["inside_rule"] = pick["versionStartIncluding"], "versionStartIncluding"
        elif pick.get("versionEndIncluding"):
            out["inside"], out["inside_rule"] = pick["versionEndIncluding"], "versionEndIncluding"
        elif pick.get("versionEndExcluding"):
            out["inside"], out["inside_rule"] = bump(pick["versionEndExcluding"], -1), "versionEndExcluding minus one"
        if pick.get("versionEndExcluding"):
            out["outside"], out["outside_rule"] = pick["versionEndExcluding"], "versionEndExcluding"
        elif pick.get("versionEndIncluding"):
            out["outside"], out["outside_rule"] = bump(pick["versionEndIncluding"], 1), "versionEndIncluding plus one"
        return out
    exact = []
    for m in rows:
        f = m["criteria"].split(":")
        if f[5] not in ("*", "-"):
            exact.append((f[5], f[6], m))
    if not exact:
        return {"row": None, "inside": None, "outside": None}
    ver, upd, m = max(exact, key=lambda t: (_Key(t[0]), _Key(t[1] if t[1] not in ("*", "-") else "")))
    written = ver if upd in ("*", "-") else f"{ver} {upd}"
    return {"row": data.config_line(m), "inside": written, "inside_rule": "highest exact version",
            "outside": None, "outside_rule": "exact versions only: one item"}


class _Key:
    def __init__(self, v): self.v = v
    def __lt__(self, o): return compare(self.v, o.v) < 0
    def __eq__(self, o): return compare(self.v, o.v) == 0


def inventory_name(v: dict, prod: str):
    """The vendor and product an administrator would write. PREREG amendment 1:
    KEV's "Multiple Products" is not a product anyone records, so such an item
    takes the chosen NVD product's name, underscores read as spaces."""
    product = v["product"].strip()
    if product.lower() == "multiple products":
        product = prod.split(":", 1)[1].replace("_", " ")
    return v["vendorProject"].strip(), product


def cmd_build(a) -> None:
    kev = json.loads((FIX / "kev_catalog.json").read_text(encoding="utf-8"))
    excluded, kept = {}, []
    for v in candidates(kev, a.start, WINDOW[1]):
        cve = v["cveID"]
        rec = nvd_cve(cve)
        reason = None
        if rec is None:
            reason = "no_nvd_record"
        elif rec.get("published", "")[:10] < a.start:
            reason = "nvd_published_before_window"
        else:
            rows = vulnerable(rec)
            if not rows:
                reason = "no_vulnerable_cpe_rows"
            else:
                prod, info = choose_product(v, rows)
                if prod is None:
                    reason = "no_application_or_os_row"
        if reason:
            excluded.setdefault(reason, []).append(cve)
            continue
        kept.append((v, rec, prod, info))

    selection = {"window": [a.start, WINDOW[1]], "kev_catalogVersion": kev.get("catalogVersion"),
                 "kev_sha256": hashlib.sha256((FIX / "kev_catalog.json").read_bytes()).hexdigest(),
                 "candidates": sum(len(x) for x in excluded.values()) + len(kept),
                 "excluded": {k: {"count": len(x), "cves": x} for k, x in sorted(excluded.items())},
                 "eligible": len(kept)}
    if len(kept) < FLOOR:
        selection["note"] = f"only {len(kept)} eligible: PREREG says move the window start back one month"
        _write(OUT / "selection.json", selection)
        raise SystemExit(selection["note"])
    kept = kept[:CAP]
    selection["selected"] = [v["cveID"] for v, *_ in kept]
    selection["dropped_by_cap"] = max(0, selection["eligible"] - CAP)

    data.use("heldout")
    construction, inventory, intent, aliases = [], [], [], {}
    n = 0
    for v, rec, prod, info in kept:
        vers = build_versions(info["rows"])
        vendor, product = inventory_name(v, prod)
        entry = {"cve": v["cveID"], "kev_vendor": v["vendorProject"], "kev_product": v["product"],
                 "inventory_vendor": vendor, "inventory_product": product,
                 "nvd_product": prod, "product_scores": info["scores"], **vers, "manual": []}
        aliases.setdefault((vendor, product), [])
        if prod not in aliases[(vendor, product)]:
            aliases[(vendor, product)].append(prod)
        for side, expect in (("inside", "affected"), ("outside", "not_affected")):
            ver = vers.get(side)
            if not ver:
                entry["manual"].append(f"{side}: no version by rule; this vulnerability gets no {side} item")
                continue
            n += 1
            iid = f"ho-{n:02d}"
            inventory.append({"id": iid, "vendor": vendor, "product": product,
                              "version": ver, "where": f"host-{n:02d}"})
            intent.append({"item": iid, "cve": v["cveID"], "built": side, "expect": expect,
                           "rule": vers.get(f"{side}_rule")})
        construction.append(entry)

    _write(OUT / "selection.json", selection)
    _write(OUT / "construction.json", {"note": "How each item was built, by the rules in PREREG.md. "
                                       "'manual' lists anything the rules could not decide.",
                                       "vulnerabilities": construction})
    _write(OUT / "aliases.json", {"note": "Inventory (KEV) names to the NVD product the build chose. "
                                  "Written before any verdict existed.",
                                  "aliases": [{"vendor": k[0], "product": k[1], "nvd": sorted(x)}
                                              for k, x in sorted(aliases.items())]})
    _write(OUT / "build_intent.json", {"note": "Which side of the range each item was built on. NOT the answer key; "
                                       "the labelers never see this file.", "pairs": intent})
    with open(OUT / "inventory.csv", "w", newline="", encoding="utf-8") as f:
        f.write("id,vendor,product,version,where\n")
        for r in inventory:
            f.write(",".join(_csv(r[k]) for k in ("id", "vendor", "product", "version", "where")) + "\n")

    inv = {i.id: i for i in data.load_inventory(OUT / "inventory.csv")}
    pairs = [(p["item"], p["cve"]) for p in intent]
    random.Random(SEED).shuffle(pairs)
    packet, pair_map = [], {}
    for k, (iid, cve) in enumerate(pairs, 1):
        pid = f"P{k:02d}"
        it = inv[iid]
        pair_map[pid] = {"item": iid, "cve": cve}
        packet.append({"pair_id": pid, "item": {"vendor": it.vendor, "product": it.product,
                                                "version_as_recorded": it.version, "deployed_as": it.where},
                       "cve": cve, "documents": data.sources_for(it, cve)})
    _write(OUT / "key_audit" / "packet.json", {"pairs": packet})
    _write(ROOT / "eval" / "heldout_private" / "pair_map.json", pair_map)
    print(json.dumps({k: selection[k] for k in ("candidates", "eligible", "dropped_by_cap")}
                     | {"excluded": {k: x["count"] for k, x in selection["excluded"].items()},
                        "pairs": len(intent),
                        "manual": [(c["cve"], c["manual"]) for c in construction if c["manual"]]}, indent=1))


def _csv(s: str) -> str:
    return f'"{s}"' if ("," in s or '"' in s) else s


def _write(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=1) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("fetch", "build"))
    ap.add_argument("--start", default=WINDOW[0], help="window start; PREREG allows moving it back only if too few qualify")
    a = ap.parse_args()
    cmd_fetch(a) if a.cmd == "fetch" else cmd_build(a)


if __name__ == "__main__":
    main()
