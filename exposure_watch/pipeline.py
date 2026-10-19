"""Run the four shapes over the same pairs and score them against the answer key.

Shapes, cheapest first:
  code                   the no-agent baseline in baseline.py
  code+keywords          the baseline plus one description-keyword rule (tuned on this set; an upper bound)
  agent                  one triage agent, its verdict taken as given
  agent+verify           the same answers, kept only if the verifier can find their quotes
  agent+verify+skeptic   survivors reviewed by a skeptic agent; a disagreement goes to a person

The three agent shapes share one set of triage answers, so they differ only in
what checks the answers, never in which answers they got.

Outcomes are scored by what they would cost an operator, not just right or wrong:
  correct      the verdict matches the answer key
  escalated    sent to a person (needs_human or unknown): slower, never silently wrong
  overcalled   "affected" where exposure is conditional: safe, extra work
  undercalled  "conditional" where the version is plainly affected: a person still looks
  false_alarm  affected or conditional where the item is not exposed
  missed       not_affected where the item is exposed: the expensive one
  overconfident  a definite verdict where the documents do not settle it

When the key says "unknown" (the documents conflict or are silent), sending the
pair to a person is the right answer, so needs_human scores as correct there.
"""
from __future__ import annotations

import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

from . import agents
from .baseline import judge, judge_with_keywords
from .data import Item, sources_for
from .verify import check

SHAPES = ("code", "code+keywords", "agent", "agent+verify", "agent+verify+skeptic")


def outcome(final: str, truth: str) -> str:
    if final == truth:
        return "correct"
    if final in ("needs_human", "unknown"):
        return "correct" if truth == "unknown" else "escalated"
    if truth == "unknown":
        return "overconfident"
    if truth == "conditional" and final == "affected":
        return "overcalled"
    if truth == "affected" and final == "conditional":
        return "undercalled"
    if truth == "not_affected":
        return "false_alarm"
    return "missed"


@dataclass
class Result:
    item: str
    cve: str
    truth: str
    shape: str
    final: str
    outcome: str
    cost_usd: float
    latency_s: float
    note: str = ""


def key(item: Item, cve: str) -> str:
    return f"{item.id}__{cve}"


def _each(fn, xs, live: bool) -> list:
    """Map fn over xs in order; live calls run four at a time, replays run inline."""
    if not live:
        return [fn(x) for x in xs]
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(fn, xs))


def run(pairs: List[dict], inventory: Dict[str, Item], run_dir: Path,
        live_triage: Optional[agents.ClaudeCLI] = None,
        live_skeptic: Optional[agents.ClaudeCLI] = None) -> List[Result]:
    """Score every shape on every pair. With no live backend, replay run_dir.

    Triage runs for every pair first, then the skeptic for the answers the
    verifier kept. Any failed call stops the run rather than being scored: an
    outage is not an escalation. Answers already saved are reused, so a rerun
    pays only for what is missing.
    """
    tri_dir, sk_dir = run_dir / "triage", run_dir / "skeptic"
    jobs = []
    for p in pairs:
        item, cve = inventory[p["item"]], p["cve"]
        jobs.append((p, item, cve, key(item, cve), sources_for(item, cve)))

    tris = _each(lambda j: agents.fetch(live_triage, tri_dir, j[3], agents.TRIAGE_SYSTEM,
                                        agents.triage_prompt(j[1], j[2], j[4]), agents.ANSWER_SCHEMA),
                 jobs, live_triage is not None)
    checks = [check(t["answer"], j[2], j[4]) for j, t in zip(jobs, tris)]
    to_skeptic = [i for i, c in enumerate(checks) if c.supported and c.verdict != "unknown"]
    sks = dict(zip(to_skeptic, _each(
        lambda i: agents.fetch(live_skeptic, sk_dir, jobs[i][3], agents.SKEPTIC_SYSTEM,
                               agents.skeptic_prompt(jobs[i][1], jobs[i][2], jobs[i][4],
                                                     {**tris[i]["answer"], "claims": checks[i].kept}),
                               agents.SKEPTIC_SCHEMA),
        to_skeptic, live_skeptic is not None)))

    results: List[Result] = []
    for i, ((p, item, cve, k, src), tri, chk) in enumerate(zip(jobs, tris, checks)):
        truth = p["truth"]
        v, why = judge(item, cve)
        results.append(Result(item.id, cve, truth, "code", v, outcome(v, truth), 0.0, 0.0, why))
        vk, whyk = judge_with_keywords(item, cve)
        results.append(Result(item.id, cve, truth, "code+keywords", vk, outcome(vk, truth), 0.0, 0.0, whyk))

        ans = tri["answer"]
        results.append(Result(item.id, cve, truth, "agent", ans["verdict"],
                              outcome(ans["verdict"], truth), tri["cost_usd"], tri["latency_s"]))

        v2 = chk.verdict if chk.supported else "needs_human"
        results.append(Result(item.id, cve, truth, "agent+verify", v2, outcome(v2, truth),
                              tri["cost_usd"], tri["latency_s"], "; ".join(chk.problems)))

        if i not in sks:
            v3, cost, lat, note = v2, tri["cost_usd"], tri["latency_s"], "not sent to skeptic"
        else:
            sk = sks[i]
            s = sk["answer"]
            v3 = chk.verdict if (s["agree"] and s["verdict"] == chk.verdict) else "needs_human"
            cost, lat = tri["cost_usd"] + sk["cost_usd"], tri["latency_s"] + sk["latency_s"]
            note = s["reason"][:200]
        results.append(Result(item.id, cve, truth, "agent+verify+skeptic", v3,
                              outcome(v3, truth), cost, lat, note))
    return results


def summarize(results: List[Result]) -> Dict[str, dict]:
    out = {}
    for shape in SHAPES:
        rs = [r for r in results if r.shape == shape]
        if not rs:
            continue
        c = Counter(r.outcome for r in rs)
        out[shape] = {"pairs": len(rs), **{k: c.get(k, 0) for k in
                      ("correct", "escalated", "overcalled", "undercalled", "false_alarm", "missed",
                       "overconfident")},
                      "cost_usd": round(sum(r.cost_usd for r in rs), 4),
                      "mean_latency_s": round(sum(r.latency_s for r in rs) / len(rs), 2)}
    return out


def write_report(results: List[Result], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"summary": summarize(results),
                                "results": [asdict(r) for r in results]}, indent=1), encoding="utf-8")
