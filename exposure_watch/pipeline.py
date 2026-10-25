"""Run the five shapes over the same pairs and score them against the answer key.

Shapes, cheapest first:
  code                   the no-agent baseline in baseline.py
  code+keywords          the baseline plus one description-keyword rule (tuned on this set; an upper bound)
  agent                  one triage agent, its verdict taken as given
  agent+verify           the same answers, kept only if at least one quote survives the
                         verifier (bad claims are dropped) and nothing is flagged (a wrong
                         CVE, a verdict outside the four)
  agent+verify+skeptic   survivors reviewed by a skeptic agent; a disagreement, or a skeptic
                         quote the verifier cannot find, goes to a person

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

The matcher is versioned like the key. A run directory may hold matcher.json:
the code shapes' verdicts as that run published them, with the matcher commit
that produced them. A replay scores the code shapes from it, so a later fix to
the matcher cannot rewrite a published result; scoring the current matcher on
the same pairs is a separate report, where the fix shows up as a delta.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

from . import agents
from .baseline import judge, judge_with_keywords
from .data import Item, sources_for
from .verify import accepts, check, check_review

SHAPES = ("code", "code+keywords", "agent", "agent+verify", "agent+verify+skeptic")
CODE_SHAPES = ("code", "code+keywords")
MATCHER_FILE = "matcher.json"
MATCHER_SOURCES = ("baseline.py", "versions.py")


def matcher_sha256() -> str:
    """The current matcher, identified by the source of the two files that decide the code shapes."""
    h = hashlib.sha256()
    for name in MATCHER_SOURCES:
        h.update((Path(__file__).parent / name).read_bytes())
    return h.hexdigest()


def recorded_matcher(run_dir: Path) -> Optional[dict]:
    f = run_dir / MATCHER_FILE
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


def current_verdicts(item: Item, cve: str) -> Dict[str, list]:
    v, why = judge(item, cve)
    vk, whyk = judge_with_keywords(item, cve)
    return {"code": [v, why], "code+keywords": [vk, whyk]}


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
    triage_model: str = ""      # the model that answered, as the CLI resolved it, not as requested
    skeptic_model: str = ""


def key(item: Item, cve: str) -> str:
    return f"{item.id}__{cve}"


def _each(fn, xs, live: bool) -> list:
    """Map fn over xs in order; live calls run four at a time, replays run inline."""
    if not live:
        return [fn(x) for x in xs]
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(fn, xs))


def record_matcher(pairs: List[dict], inventory: Dict[str, Item], run_dir: Path, commit: str) -> dict:
    """Save the current matcher's code-shape verdicts for these pairs as run_dir's matcher.json."""
    rec = {"commit": commit, "sha256": matcher_sha256(), "verdicts": {}}
    for p in pairs:
        item = inventory[p["item"]]
        rec["verdicts"][key(item, p["cve"])] = current_verdicts(item, p["cve"])
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / MATCHER_FILE).write_text(json.dumps(rec, indent=1), encoding="utf-8")
    return rec


def matcher_header(run_dir: Path, matcher: str) -> dict:
    """What a report says about the matcher that scored its code shapes."""
    rec = recorded_matcher(run_dir) if matcher == "recorded" else None
    if rec is None:
        return {"matcher": "current code", "sha256": matcher_sha256()}
    return {"matcher": f"recorded in {MATCHER_FILE}", "commit": rec["commit"], "sha256": rec["sha256"]}


def run(pairs: List[dict], inventory: Dict[str, Item], run_dir: Path,
        live_triage: Optional[agents.ClaudeCLI] = None,
        live_skeptic: Optional[agents.ClaudeCLI] = None,
        matcher: str = "recorded") -> List[Result]:
    """Score every shape on every pair. With no live backend, replay run_dir.

    Triage runs for every pair first, then the skeptic for the answers that
    passed the verifier. Any failed call stops the run rather than being scored: an
    outage is not an escalation. Answers already saved are reused, so a rerun
    pays only for what is missing.

    The code shapes come from run_dir's matcher.json when it has one and
    matcher is "recorded"; otherwise, or with matcher="current", from the code
    as it is now. A live run with no matcher.json records one first.
    """
    tri_dir, sk_dir = run_dir / "triage", run_dir / "skeptic"
    jobs = []
    for p in pairs:
        item, cve = inventory[p["item"]], p["cve"]
        jobs.append((p, item, cve, key(item, cve), sources_for(item, cve)))
    if live_triage is not None and recorded_matcher(run_dir) is None:
        record_matcher(pairs, inventory, run_dir, commit=_git_head())
    rec = recorded_matcher(run_dir) if matcher == "recorded" else None
    if rec is not None:
        missing = [j[3] for j in jobs if j[3] not in rec["verdicts"]]
        if missing:
            raise KeyError(f"{run_dir / MATCHER_FILE} has no verdict for {missing[:3]}: "
                           f"score these with matcher='current', do not substitute")

    tris = _each(lambda j: agents.fetch(live_triage, tri_dir, j[3], agents.TRIAGE_SYSTEM,
                                        agents.triage_prompt(j[1], j[2], j[4]), agents.ANSWER_SCHEMA),
                 jobs, live_triage is not None)
    checks = [check(t["answer"], j[2], j[4]) for j, t in zip(jobs, tris)]
    to_skeptic = [i for i, c in enumerate(checks) if c.passed and c.verdict != "unknown"]
    sks = dict(zip(to_skeptic, _each(
        lambda i: agents.fetch(live_skeptic, sk_dir, jobs[i][3], agents.SKEPTIC_SYSTEM,
                               agents.skeptic_prompt(jobs[i][1], jobs[i][2], jobs[i][4],
                                                     {**tris[i]["answer"], "claims": checks[i].kept}),
                               agents.SKEPTIC_SCHEMA),
        to_skeptic, live_skeptic is not None)))

    results: List[Result] = []
    for i, ((p, item, cve, k, src), tri, chk) in enumerate(zip(jobs, tris, checks)):
        truth = p["truth"]
        verdicts = rec["verdicts"][k] if rec is not None else current_verdicts(item, cve)
        for shape in CODE_SHAPES:
            v, why = verdicts[shape]
            results.append(Result(item.id, cve, truth, shape, v, outcome(v, truth), 0.0, 0.0, why))

        ans, tm = tri["answer"], tri.get("model", "")
        results.append(Result(item.id, cve, truth, "agent", ans["verdict"],
                              outcome(ans["verdict"], truth), tri["cost_usd"], tri["latency_s"], "", tm))

        v2 = chk.verdict if chk.passed else "needs_human"
        results.append(Result(item.id, cve, truth, "agent+verify", v2, outcome(v2, truth),
                              tri["cost_usd"], tri["latency_s"], "; ".join(chk.problems), tm))

        if i not in sks:
            v3, cost, lat, note, sm = v2, tri["cost_usd"], tri["latency_s"], "not sent to skeptic", ""
        else:
            sk = sks[i]
            s, sm = sk["answer"], sk.get("model", "")
            v3 = chk.verdict if accepts(s, chk.verdict, cve, src) else "needs_human"
            cost, lat = tri["cost_usd"] + sk["cost_usd"], tri["latency_s"] + sk["latency_s"]
            dropped = check_review(s, cve, src).dropped
            note = s["reason"][:200] + (f" (skeptic's quote dropped: {dropped[0]['reason']})" if dropped else "")
        results.append(Result(item.id, cve, truth, "agent+verify+skeptic", v3,
                              outcome(v3, truth), cost, lat, note, tm, sm))
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


def write_report(results: List[Result], path: Path, header: Optional[dict] = None, **extra) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {**({"matcher": header} if header else {}), "summary": summarize(results), **extra,
            "results": [asdict(r) for r in results]}
    path.write_text(json.dumps(body, indent=1), encoding="utf-8")


def changed(frozen: List[Result], current: List[Result]) -> List[str]:
    """The code-shape verdicts the current matcher gives differently from the recorded one."""
    was = {(r.item, r.cve, r.shape): r for r in frozen if r.shape in CODE_SHAPES}
    return [f"{r.item} {r.cve} {r.shape}: {was[(r.item, r.cve, r.shape)].final} -> {r.final}"
            for r in current if r.shape in CODE_SHAPES and r.final != was[(r.item, r.cve, r.shape)].final]


def _git_head() -> str:
    """The commit a live run's matcher came from, marked "+uncommitted" when the
    matcher's files differ from it, since then that commit is not what ran."""
    import subprocess
    here = Path(__file__).resolve().parent
    try:
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=here,
                              capture_output=True, text=True, timeout=10)
        dirty = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", *MATCHER_SOURCES], cwd=here,
                               capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if head.returncode != 0:
        return "unknown"
    return head.stdout.strip() + ("+uncommitted" if dirty.returncode != 0 else "")
