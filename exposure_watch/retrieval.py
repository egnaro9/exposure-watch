"""Does the agent ever see the row that decides its answer?

nvd_config_text hands the agent only the CPE rows that share a word with the
item's vendor or product. That filter could drop the deciding row, and an agent
cannot quote what it was never shown. This counts, per pair, the rows that
describe the item (by the baseline's alias table) and how many survived the
filter. No model is involved.

Caveat stated where the number is used: "describes the item" comes from the
same alias table the baseline uses, so this checks the filter against our own
reading of NVD, not against an independent one.
"""
from __future__ import annotations

from typing import Dict, List

from .baseline import ALIASES
from .data import Item, nvd_config_text, vulnerable_rows


def recall(pairs: List[dict], inventory: Dict[str, Item]) -> dict:
    per, relevant_total, kept_total, shown_total = [], 0, 0, 0
    for p in pairs:
        item, cve = inventory[p["item"]], p["cve"]
        names = ALIASES[(item.vendor, item.product)]
        relevant = [m["criteria"] for m in vulnerable_rows(cve)
                    if ":".join(m["criteria"].split(":")[3:5]) in names]
        shown = [l.split(" | ")[0] for l in nvd_config_text(cve, item).splitlines() if l]
        kept = [c for c in relevant if c in shown]
        relevant_total, kept_total, shown_total = (relevant_total + len(relevant),
                                                   kept_total + len(kept), shown_total + len(shown))
        per.append({"item": item.id, "cve": cve, "relevant_rows": len(relevant),
                    "kept": len(kept), "shown": len(shown)})
    return {"relevant_rows": relevant_total, "kept": kept_total, "rows_shown": shown_total,
            "pairs_with_a_dropped_row": [x for x in per if x["kept"] < x["relevant_rows"]],
            "pairs_with_no_relevant_row": [x for x in per if x["relevant_rows"] == 0]}
