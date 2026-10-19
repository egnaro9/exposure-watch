"""Planted-error measurement: break correct answers on purpose, count what each check catches.

Base answers are reference answers built from the answer key: the right verdict
plus one claim quoting the NVD row or passage that decides it. Each is mutated
five ways, one defect per mutant:

  quote_altered    one digit in the quote changed            (verifier should catch)
  wrong_source     a real quote credited to the wrong document (verifier should catch)
  invented_cve     the claim cites a CVE no source mentions    (verifier should catch)
  wrong_cve        the answer is about a different CVE         (verifier should catch)
  verdict_flipped  the opposite verdict, same real quote       (verifier CANNOT catch; skeptic's job)

The last class is the point. A verifier that only checks evidence passes a
wrong conclusion that cites real text, and this suite measures that gap
instead of describing it.
"""
from __future__ import annotations

import copy
import re
from typing import Dict, List, Optional

from pathlib import Path

from . import agents
from .baseline import CONDITION, judge, nearest_row
from .data import Item, sources_for, nvd_description
from .pipeline import _each
from .verify import check

FLIP = {"affected": "not_affected", "not_affected": "affected", "conditional": "not_affected",
        "unknown": "affected"}


def reference_answer(item: Item, cve: str, truth: str) -> Optional[dict]:
    src = sources_for(item, cve)
    verdict, row = judge(item, cve)
    if truth == "conditional":
        quote = next((s.strip() for s in re.split(r"(?<=\.)\s+", nvd_description(cve))
                      if CONDITION.search(s)), "")
        return {"cve": cve, "verdict": "conditional", "claims": [
            {"text": "exposure depends on a feature or configuration", "source": "nvd_description",
             "quote": quote[:160]}]}
    if truth == "unknown":
        first = re.split(r"(?<=\.)\s+", nvd_description(cve))[0]
        return {"cve": cve, "verdict": "unknown", "claims": [
            {"text": "the description and the configuration rows disagree at this version",
             "source": "nvd_description", "quote": first[:160]}]}
    if verdict == "affected":
        assert row in src["nvd_config"].splitlines(), f"deciding row not shown to the agent: {row}"
        return {"cve": cve, "verdict": "affected", "claims": [
            {"text": "the installed version falls in this row", "source": "nvd_config", "quote": row}]}
    line = nearest_row(item, cve)
    if line:
        return {"cve": cve, "verdict": "not_affected", "claims": [
            {"text": "the closest affected row for this product stops below the installed version",
             "source": "nvd_config", "quote": line}]}
    return None


def mutants(ans: dict) -> Dict[str, dict]:
    out = {}
    q = ans["claims"][0]["quote"]
    m = copy.deepcopy(ans)
    digit = re.search(r"\d", q)
    if digit:
        i = digit.start()
        m["claims"][0]["quote"] = q[:i] + str((int(q[i]) + 1) % 10) + q[i + 1:]
        out["quote_altered"] = m
    m = copy.deepcopy(ans)
    m["claims"][0]["source"] = "kev" if ans["claims"][0]["source"] != "kev" else "nvd_config"
    out["wrong_source"] = m
    m = copy.deepcopy(ans)
    m["claims"][0]["text"] += " (see also CVE-2099-00001)"
    out["invented_cve"] = m
    m = copy.deepcopy(ans)
    m["cve"] = "CVE-2099-00002"
    out["wrong_cve"] = m
    m = copy.deepcopy(ans)
    m["verdict"] = FLIP[ans["verdict"]]
    out["verdict_flipped"] = m
    return out


def verifier_catches(mutant: dict, cve: str, src: Dict[str, str]) -> bool:
    """Caught means the verifier did something about the defect: dropped the bad
    claim, flagged a problem, or refused the verdict. An "unknown" verdict needs
    no evidence, so for it a dropped claim is the only possible catch."""
    c = check(mutant, cve, src)
    return (not c.supported) or bool(c.problems) or bool(c.dropped)


def run_verifier_side(pairs: List[dict], inventory: Dict[str, Item]) -> Dict[str, dict]:
    tally: Dict[str, dict] = {}
    for p in pairs:
        item, cve = inventory[p["item"]], p["cve"]
        base = reference_answer(item, cve, p["truth"])
        if base is None:
            continue
        src = sources_for(item, cve)
        assert not verifier_catches(base, cve, src), f"reference answer for {p} fails its own check"
        for name, mut in mutants(base).items():
            t = tally.setdefault(name, {"planted": 0, "caught_by_verifier": 0})
            t["planted"] += 1
            t["caught_by_verifier"] += verifier_catches(mut, cve, src)
    return tally


def run_skeptic_side(pairs: List[dict], inventory: Dict[str, Item], run_dir: Path,
                     live_skeptic: Optional[agents.ClaudeCLI] = None) -> Dict[str, dict]:
    """The other half: hand the skeptic each correct reference answer and its
    verdict-flipped twin, both citing the same real passage.

    A flip the skeptic does not accept is caught. A correct answer it does not
    accept is a false rejection, which in the pipeline sends a right answer to a
    person for nothing. Both rates matter; a skeptic that rejects everything
    catches every flip.
    """
    d = run_dir / "planted_skeptic"
    jobs = []
    for p in pairs:
        item, cve = inventory[p["item"]], p["cve"]
        base = reference_answer(item, cve, p["truth"])
        if base is None:
            continue
        src = sources_for(item, cve)
        for kind, ans in (("control", base), ("verdict_flipped", mutants(base)["verdict_flipped"])):
            jobs.append((f"{item.id}__{cve}__{kind}", kind, item, cve, src, ans))
    recs = _each(lambda j: agents.fetch(live_skeptic, d, j[0], agents.SKEPTIC_SYSTEM,
                                        agents.skeptic_prompt(j[2], j[3], j[4], j[5]), agents.SKEPTIC_SCHEMA),
                 jobs, live_skeptic is not None)
    tally = {k: {"shown": 0, "not_accepted": 0, "cost_usd": 0.0} for k in ("control", "verdict_flipped")}
    for j, r in zip(jobs, recs):
        s = r["answer"]
        t = tally[j[1]]
        t["shown"] += 1
        t["not_accepted"] += not (s["agree"] and s["verdict"] == j[5]["verdict"])
        t["cost_usd"] = round(t["cost_usd"] + (r["cost_usd"] or 0.0), 4)
    return tally
