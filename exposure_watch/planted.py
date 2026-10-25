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
from .data import Item, current, load_inventory, sources_for, nvd_description
from .pipeline import _each
from .verify import accepts, check

FLIP = {"affected": "not_affected", "not_affected": "affected", "conditional": "not_affected",
        "unknown": "affected"}


def key_evidence() -> Optional[Dict[tuple, dict]]:
    """For a set whose key was made by blind labelers (eval/heldout/key_audit/), the
    passage the key itself rests on: the adjudicator's quote where there was a
    ruling, else the first labeler's verbatim quote for the key's label. Reference
    answers built from it do not depend on the keyword rule or the matcher, which
    were tuned on the original set. None for a set without such files."""
    import json
    d = current().key.parent / "key_audit"
    if not (d / "labels.json").exists():
        return None
    labels = json.loads((d / "labels.json").read_text(encoding="utf-8"))
    rulings = {r["pair_id"]: r for r in json.loads((d / "rulings.json").read_text(encoding="utf-8"))}
    pair_map = json.loads((d / "pair_map.json").read_text(encoding="utf-8"))
    truth = {(p["item"], p["cve"]): p["truth"] for p in json.loads(current().key.read_text(encoding="utf-8"))["pairs"]}
    inv = {i.id: i for i in load_inventory(current().inventory)}
    out = {}
    for pid, m in pair_map.items():
        k = (m["item"], m["cve"])
        src = sources_for(inv[m["item"]], m["cve"])
        cands = [rulings[pid]] if pid in rulings else [l for l in labels[pid] if l["label"] == truth[k]]
        for c in cands:
            if " ".join(c["deciding_quote"].split()) in " ".join(src[c["source"]].split()):
                out[k] = {"source": c["source"], "quote": c["deciding_quote"]}
                break
    return out


def reference_answer(item: Item, cve: str, truth: str, evidence: Optional[dict] = None) -> Optional[dict]:
    if evidence is not None:
        return {"cve": cve, "verdict": truth, "claims": [
            {"text": "the passage the answer key rests on", "source": evidence["source"],
             "quote": evidence["quote"]}]}
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
    claim, flagged a problem, or refused the verdict. The pipeline sends anything
    that does not pass to a person. An "unknown" verdict needs no evidence, so it
    is never refused: for it only a dropped claim or a flagged problem counts."""
    c = check(mutant, cve, src)
    return (not c.passed) or bool(c.dropped)


def run_verifier_side(pairs: List[dict], inventory: Dict[str, Item],
                      evidence: Optional[Dict[tuple, dict]] = None) -> Dict[str, dict]:
    tally: Dict[str, dict] = {}
    for p in pairs:
        item, cve = inventory[p["item"]], p["cve"]
        ev = evidence.get((p["item"], cve)) if evidence is not None else None
        if evidence is not None and ev is None:
            tally.setdefault("skipped_no_verbatim_key_quote", {"pairs": 0})["pairs"] += 1
            continue
        base = reference_answer(item, cve, p["truth"], ev)
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
    catches every flip. Accepting means what it means in the pipeline
    (verify.accepts): agreeing, reaching the same verdict, and quoting a passage
    the verifier finds.
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
    # Reference answers come from today's matcher. If a matcher change stops one
    # being built, its recorded answers would silently drop out of the tally.
    if live_skeptic is None and d.exists():
        unused = sorted({f.stem for f in d.glob("*.json")} - {j[0] for j in jobs})
        if unused:
            raise RuntimeError(f"{len(unused)} recorded answers in {d} match no reference answer built now, "
                               f"e.g. {unused[:2]}: the matcher changed what this suite plants")
    recs = _each(lambda j: agents.fetch(live_skeptic, d, j[0], agents.SKEPTIC_SYSTEM,
                                        agents.skeptic_prompt(j[2], j[3], j[4], j[5]), agents.SKEPTIC_SCHEMA),
                 jobs, live_skeptic is not None)
    tally = {k: {"shown": 0, "not_accepted": 0, "cost_usd": 0.0} for k in ("control", "verdict_flipped")}
    for j, r in zip(jobs, recs):
        s = r["answer"]
        t = tally[j[1]]
        t["shown"] += 1
        t["not_accepted"] += not accepts(s, j[5]["verdict"], j[3], j[4])
        t["cost_usd"] = round(t["cost_usd"] + r["cost_usd"], 4)     # a cost is never missing: see agents
    return tally
