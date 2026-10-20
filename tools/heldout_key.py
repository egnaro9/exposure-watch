"""Turn the blind labeling workflow's output into the held-out answer key.

    python tools/heldout_key.py RESULT.json

RESULT.json is what eval/heldout/key_audit/workflow.js returned. A pair's truth
is the labelers' label when all three agree, else the adjudicator's ruling, as
PREREG.md says. The build intent is never read here. Writes:

  eval/heldout/ground_truth.json        the key, frozen once pushed
  eval/heldout/key_audit/labels.json    every label, quote and reasoning, by pair
  eval/heldout/key_audit/rulings.json   every adjudication, in full
  eval/heldout/key_audit/pair_map.json  P-id to (item, cve), published with the key
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HO = ROOT / "eval" / "heldout"


def main(path: str) -> int:
    res = json.loads(Path(path).read_text(encoding="utf-8"))
    pair_map = json.loads((ROOT / "eval" / "heldout_private" / "pair_map.json").read_text(encoding="utf-8"))
    if res.get("missing"):
        raise SystemExit(f"labels missing, rerun those labelers before freezing: {res['missing']}")
    rulings = {r["pair_id"]: r for r in res["adjudicated"]}
    pairs = []
    for row in res["table"]:
        pid = row["id"]
        if row["unanimous"]:
            truth, basis = next(iter(row["labels"].values())), "unanimous (A, B, C)"
        elif pid in rulings:
            truth = rulings[pid]["final_label"]
            basis = "adjudicated; labelers said " + ", ".join(f"{k} {v}" for k, v in sorted(row["labels"].items()))
        else:
            raise SystemExit(f"{pid} is disputed and has no ruling")
        m = pair_map[pid]
        pairs.append({"item": m["item"], "cve": m["cve"], "truth": truth, "basis": basis, "pair_id": pid})
    pairs.sort(key=lambda p: p["item"])
    _write(HO / "ground_truth.json", {
        "note": ("Held-out key. Each label is three blind labelers' unanimous answer, or a neutral "
                 "adjudicator's ruling where they disagreed (eval/heldout/key_audit/). Frozen before the "
                 "code or any agent ran on this set; corrections go in errata.json."),
        "pairs": pairs})
    _write(HO / "key_audit" / "labels.json", res["labels"])
    _write(HO / "key_audit" / "rulings.json", res["adjudicated"])
    _write(HO / "key_audit" / "pair_map.json", pair_map)
    _write(HO / "key_audit" / "outside_notes.json", res.get("outside_notes", []))
    counts = {}
    for p in pairs:
        counts[p["truth"]] = counts.get(p["truth"], 0) + 1
    print(json.dumps({"pairs": len(pairs), "by_truth": counts,
                      "unanimous": sum(r["unanimous"] for r in res["table"]),
                      "adjudicated": len(rulings)}, indent=1))
    return 0


def _write(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
