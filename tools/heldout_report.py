"""The analysis PREREG.md commits to, computed from a held-out run's report.

    python tools/heldout_report.py runs/heldout/report.json

Prints the pre-registered comparison (code+keywords against agent+verify+skeptic:
correct, missed, and an exact two-sided McNemar test on the pairs where exactly
one of them is correct), and sorts every frozen-code error by kind:

  condition   the key and the code disagree only about whether exposure depends
              on a feature (affected vs conditional): the keyword rule's job
  version     the code put the version on the wrong side of the range, or could
              not read it: the version handling's job
  alias       the code had no alias for the product
  unsettled   the key says the documents do not settle it, and the code answered

No model is involved; it only reads the report.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from math import comb
from pathlib import Path

A, B = "code+keywords", "agent+verify+skeptic"


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact p-value: b and c are the counts of discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def kind(r: dict) -> str:
    if "no alias" in r["note"]:
        return "alias"
    if r["truth"] == "unknown":
        return "unsettled"
    if {r["final"], r["truth"]} == {"affected", "conditional"}:
        return "condition"
    return "version"


def main(path: str) -> int:
    rep = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = rep["results"]
    by = {}
    for r in rows:
        by.setdefault((r["item"], r["cve"]), {})[r["shape"]] = r
    a_only = sum(1 for s in by.values() if s[A]["outcome"] == "correct" and s[B]["outcome"] != "correct")
    b_only = sum(1 for s in by.values() if s[B]["outcome"] == "correct" and s[A]["outcome"] != "correct")
    out = {
        "pairs": len(by),
        "summary": rep["summary"],
        "preregistered_comparison": {
            "shapes": [A, B],
            "correct": [rep["summary"][A]["correct"], rep["summary"][B]["correct"]],
            "missed": [rep["summary"][A]["missed"], rep["summary"][B]["missed"]],
            f"only_{A}_correct": a_only,
            f"only_{B}_correct": b_only,
            "mcnemar_exact_two_sided_p": round(mcnemar_exact(a_only, b_only), 4),
        },
        "frozen_code_errors": {},
    }
    for shape in ("code", "code+keywords"):
        errs = [r for r in rows if r["shape"] == shape and r["outcome"] != "correct"]
        out["frozen_code_errors"][shape] = {
            "by_kind": dict(Counter(kind(r) for r in errs)),
            "pairs": [{"item": r["item"], "cve": r["cve"], "truth": r["truth"], "said": r["final"],
                       "kind": kind(r), "why": r["note"]} for r in errs],
        }
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "runs/heldout/report.json"))
