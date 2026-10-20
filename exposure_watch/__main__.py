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
from .pipeline import run, summarize, write_report
from .planted import key_evidence, run_skeptic_side, run_verifier_side
from .retrieval import recall


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="exposure_watch", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set", choices=sorted(SETS), default="original",
                    help="which evaluation set to use (default: the original 22 pairs)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--run", type=Path, required=True, help="directory holding recorded answers")
    r.add_argument("--live", action="store_true")
    r.add_argument("--triage-model", default="sonnet")
    r.add_argument("--skeptic-model", default="opus")
    pl = sub.add_parser("planted")
    pl.add_argument("--skeptic", action="store_true")
    pl.add_argument("--run", type=Path)
    pl.add_argument("--live", action="store_true")
    pl.add_argument("--skeptic-model", default="opus")
    sub.add_parser("retrieval")
    a = ap.parse_args(argv)

    use(a.set)
    inv = {i.id: i for i in load_inventory(current().inventory)}
    pairs = load_pairs(with_errata=True)
    if a.cmd == "retrieval":
        print(json.dumps(recall(pairs, inv), indent=1))
        return 0
    if a.cmd == "planted":
        out = {"verifier": run_verifier_side(pairs, inv, key_evidence())}
        if a.skeptic:
            if not a.run:
                ap.error("planted --skeptic needs --run DIR")
            sk = agents.ClaudeCLI(a.skeptic_model) if a.live else None
            out["skeptic"] = run_skeptic_side(pairs, inv, a.run, sk)
        print(json.dumps(out, indent=1))
        return 0
    tri = agents.ClaudeCLI(a.triage_model) if a.live else None
    sk = agents.ClaudeCLI(a.skeptic_model) if a.live else None
    results = run(pairs, inv, a.run, tri, sk)
    write_report(results, a.run / "report.json")
    out = {"with_errata": summarize(results)}
    if errata():
        frozen = run(load_pairs(with_errata=False), inv, a.run)   # replays the answers just saved
        write_report(frozen, a.run / "report_frozen_key.json")
        out["frozen_key"] = summarize(frozen)
        out["errata"] = [f"{e['item']} {e['cve']}: {e['was']} -> {e['now']}" for e in errata()]
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
