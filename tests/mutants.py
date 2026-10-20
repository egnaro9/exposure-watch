"""Break the code on purpose and confirm the tests notice.

A test that passes is only evidence if it would fail when the thing it guards
is broken. Each mutant below makes one deliberate change to one module, runs
the tests aimed at it, and expects at least one failure. The source is always
restored, even if the run is interrupted.

    python tests/mutants.py

Prints KILLED or SURVIVED per mutant and exits non-zero if any survived.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "exposure_watch"

# (name, file, exact text to replace, replacement, pytest -k selector)
MUTANTS = [
    ("versions: shorter prefix sorts last", "versions.py",
     "return -1 if len(ta) < len(tb) else 1", "return 1 if len(ta) < len(tb) else -1", "compare"),
    ("versions: end bound treated as inclusive", "versions.py",
     "if c > 0 or (c == 0 and not end_incl):", "if c > 0:", "exclusive"),
    ("verify: quotes no longer checked against the document", "verify.py",
     "elif quote not in _norm(sources[src]):", "elif False:", "bad_evidence or real_quote"),
    ("verify: wrong CVE no longer flagged", "verify.py",
     'if answer.get("cve") != cve:', "if False:", "wrong_cve"),
    ("scoring: escalating an unsettled pair no longer counts as correct", "pipeline.py",
     'return "correct" if truth == "unknown" else "escalated"', 'return "escalated"', "outcome"),
    ("agents: saved answers ignored, every call made again", "agents.py",
     'if (run_dir / f"{key}.json").exists():', "if False:", "rerun"),
    ("agents: answers from another model reused", "agents.py",
     'if backend and rec.get("requested_model") != backend.model:', "if False:", "mix"),
    ("agents: answers to a changed prompt reused", "agents.py",
     'if "prompt_sha256" in rec and rec["prompt_sha256"] != asked:', "if False:", "changed_question"),
    ("data: rows kept only when the vendor name matches", "data.py",
     'if not (_words(f[3]) | _words(f[4].replace("_", " "))) & want:',
     "if not (_words(f[3]) & _words(item.vendor)):", "reaches_the_agent"),
    ("key: an erratum may misstate the label it replaces", "key.py",
     'if e["was"] != p["truth"]:', "if False:", "erratum"),
    ("key: an erratum for a missing pair is ignored", "key.py",
     "    if fixes:\n", "    if False:\n", "erratum"),
    ("key: the frozen key also gets the errata", "key.py",
     "    if not with_errata:\n        return pairs\n", "", "errata"),
    ("planted: not-affected reference quotes the first row shown", "planted.py",
     "    line = nearest_row(item, cve)\n",
     '    line = src["nvd_config"].splitlines()[0] if src["nvd_config"] else ""\n', "decides"),
    ("baseline: rebuild letters ignored, 17.9.4a equals 17.9.4", "versions.py",
     '_TOKEN = re.compile(r"\\d+|[a-z]+")', '_TOKEN = re.compile(r"\\d+")', "baseline or compare"),    ("data: switching sets keeps the old catalog cached", "data.py",
     "    kev_index.cache_clear()\n", "", "switching"),
    ("baseline: a data set's own aliases ignored", "baseline.py",
     '            out[(a["vendor"], a["product"])] = a["nvd"]\n', "            pass\n", "aliases_extend"),
    ("key: the key path ignores the data set", "key.py",
     "(KEY or current().key)", '(KEY or current().fixtures.parent / "eval" / "ground_truth.json")', "key_follows"),
    ("baseline: the keyword rule edited", "baseline.py",
     r'\bconfigured as\b|', "", "keyword_rule_is_frozen or keywords"),
]


def run_one(name: str, fname: str, old: str, new: str, selector: str) -> bool:
    path = PKG / fname
    src = path.read_text(encoding="utf-8")
    if src.count(old) != 1:
        raise SystemExit(f"mutant {name!r}: expected text not found exactly once in {fname}; update tests/mutants.py")
    try:
        path.write_text(src.replace(old, new), encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-k", selector],
                           cwd=ROOT, capture_output=True, text=True)
        out = r.stdout + r.stderr
        if "error" in out.lower().split("short test summary")[-1] and " failed" not in out:
            raise SystemExit(f"mutant {name!r} broke collection or import, not behaviour:\n{out[-800:]}")
        if r.returncode != 0 and " failed" not in out:
            raise SystemExit(f"mutant {name!r}: pytest exited {r.returncode} with no failing test:\n{out[-800:]}")
        return r.returncode != 0
    finally:
        path.write_text(src, encoding="utf-8")


def main() -> int:
    survived = 0
    for m in MUTANTS:
        killed = run_one(*m)
        survived += not killed
        print(f"{'KILLED  ' if killed else 'SURVIVED'}  {m[0]}")
    print(f"\n{len(MUTANTS) - survived} of {len(MUTANTS)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
