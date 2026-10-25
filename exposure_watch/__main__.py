"""python -m exposure_watch [--set original|heldout] {run,planted,retrieval} ...

  run      score every shape on the answer key. --live calls agents through the
           Claude Code CLI and records every answer under --run; without --live
           it replays the recorded answers, so anyone can re-score a run.
  planted  the planted-error measurement. Alone it runs the verifier side (no
           model). With --skeptic it also hands the skeptic each correct answer
           and its verdict-flipped twin; --live calls the model, else it replays.
  retrieval  whether every NVD row describing an item reaches the agent (no model).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import agents
from .data import SETS, current, load_inventory, use
from .key import errata, load_pairs
from .pipeline import (CODE_SHAPES, changed, matcher_header, recorded_matcher, run, summarize,
                       write_report)
from .planted import key_evidence, run_skeptic_side, run_verifier_side
from .retrieval import recall


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="exposure_watch", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set", choices=sorted(SETS), default="original",
                    help="which evaluation set to use (default: the original 22 pairs)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--run", type=Path, required=True, help="directory holding recorded answers")
    r.add_argument("--live", action="store_true")
    r.add_argument("--triage-model", default=agents.TRIAGE_MODEL)
    r.add_argument("--skeptic-model", default=agents.SKEPTIC_MODEL)
    pl = sub.add_parser("planted")
    pl.add_argument("--skeptic", action="store_true")
    pl.add_argument("--run", type=Path)
    pl.add_argument("--live", action="store_true")
    pl.add_argument("--skeptic-model", default=agents.SKEPTIC_MODEL)
    sub.add_parser("retrieval")
    return ap


def main(argv=None) -> int:
    ap = parser()
    a = ap.parse_args(argv)

    use(a.set)
    inv = {i.id: i for i in load_inventory(current().inventory)}
    pairs = load_pairs(with_errata=True)
    if a.cmd == "retrieval":
        print(json.dumps(recall(pairs, inv), indent=1))
        return 0
    if a.cmd == "planted":
        evidence = key_evidence()
        out = {"verifier": run_verifier_side(pairs, inv, evidence)}
        if a.skeptic:
            if not a.run:
                ap.error("planted --skeptic needs --run DIR")
            sk = agents.ClaudeCLI(a.skeptic_model) if a.live else None
            out["skeptic"] = run_skeptic_side(pairs, inv, a.run, sk, evidence)
        print(json.dumps(out, indent=1))
        return 0
    tri = agents.ClaudeCLI(a.triage_model) if a.live else None
    sk = agents.ClaudeCLI(a.skeptic_model) if a.live else None
    results = run(pairs, inv, a.run, tri, sk)
    header = matcher_header(a.run, "recorded")
    write_report(results, a.run / "report.json", header)
    out = {"with_errata": summarize(results)}
    if errata():
        frozen = run(load_pairs(with_errata=False), inv, a.run)   # replays the answers just saved
        write_report(frozen, a.run / "report_frozen_key.json", header)
        out["frozen_key"] = summarize(frozen)
        out["errata"] = [f"{e['item']} {e['cve']}: {e['was']} -> {e['now']}" for e in errata()]
    if recorded_matcher(a.run) is not None:
        now = [r for r in run(pairs, inv, a.run, matcher="current") if r.shape in CODE_SHAPES]
        delta = changed(results, now)
        write_report(now, a.run / "report_current_matcher.json", matcher_header(a.run, "current"),
                     changed_from_recorded=delta)
        out["current_matcher"] = {"summary": summarize(now), "changed_from_recorded": delta}
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
