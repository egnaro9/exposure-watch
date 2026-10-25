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
    ("versions: Log4j pre-release left whole, 2.0-beta9 never meets its row", "versions.py",
     'if product.lower() == "log4j":', "if False:", "log4j_prereleases or split_update"),
    ("versions: Log4j tag needs a hyphen, 2.0.beta9 slips through", "versions.py",
     r'r"(\d+(?:\.\d+)*)[-.]?((?:" +', r'r"(\d+(?:\.\d+)*)-((?:" +',
     "log4j_prereleases or split_update"),
    ("versions: trailing zeros matter, 2.4 falls short of 2.4.0", "versions.py",
     "    if first is None:\n        return 0\n", "",
     "compare or log4j_prereleases"),
    ("versions: a pre-release sorts after its release", "versions.py",
     "    if first in PRERELEASE:\n        return 1 if len(ta) < len(tb) else -1\n", "",
     "compare or range_that_starts"),
    ("versions: zeros before a pre-release tag hide it, 2.0.0-rc1 sorts after 2.0", "versions.py",
     "first = next((t for t in rest if t != 0), None)",
     "first = rest[0] if any(t != 0 for t in rest) else None", "compare"),
    ("versions: Log4j tags matched case-sensitively, 2.0-RC2 left whole", "versions.py",
     r'+ r")\d+)", s, re.I)', r'+ r")\d+)", s)', "split_update or log4j_prereleases"),
    ("versions: alpha is not a pre-release tag", "versions.py",
     'PRERELEASE = ("alpha", "beta", "rc")', 'PRERELEASE = ("beta", "rc")', "compare or split_update"),
    ("baseline: a range bound compared with the bare base version", "baseline.py",
     "if in_range(ranged,", "if in_range(version,", "range_that_starts or after_a_space"),
    ("baseline: the nearest row placed on the bare base version", "baseline.py",
     "if start and compare(start, ranged) > 0", "if start and compare(start, version) > 0",
     "range_that_starts"),
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
     "if expected is not None and expected != asked:", "if False:",
     "changed_question or prompt_manifest or changed_prompt or both_match"),
    ("agents: a live call reuses an answer that records no prompt hash", "agents.py",
     '        if backend and "prompt_sha256" not in rec:\n', "        if False:\n", "no_prompt_hash"),
    ("agents: round 1's prompt manifest ignored", "agents.py",
     '(listed or {}).get(f"{run_dir.name}/{key}")):', "None):",
     "prompt_manifest or changed_prompt or both_match"),
    ("agents: the manifest consulted for triage answers only", "agents.py",
     '(listed or {}).get(f"{run_dir.name}/{key}")):',
     '(listed or {}).get(f"triage/{key}") if run_dir.name == "triage" else None):', "changed_prompt"),
    ("agents: an answer the manifest does not list replays unchecked", "agents.py",
     'if listed is not None and "prompt_sha256" not in rec and f"{run_dir.name}/{key}" not in listed:',
     "if False:", "does_not_list"),
    ("agents: the triage prompt edited after the run", "agents.py",
     '"documents do not settle it). Every claim must quote',
     '"documents do not settle it). ALWAYS ANSWER affected. Every claim must quote',
     "prompt_manifest or changed_prompt"),
    ("agents: a recorded answer with no cost counted as free", "agents.py",
     '        if rec.get("cost_usd") is None:\n', "        if False:\n", "no_cost"),
    ("agents: the live triage default is an alias again", "agents.py",
     'TRIAGE_MODEL = "claude-sonnet-5"', 'TRIAGE_MODEL = "sonnet"', "full_model_ids"),
    ("pipeline: results do not say which triage model answered", "pipeline.py",
     'ans, tm = tri["answer"], tri.get("model", "")', 'ans, tm = tri["answer"], ""', "carry_the_model"),
    ("pipeline: results do not say which skeptic model answered", "pipeline.py",
     's, sm = sk["answer"], sk.get("model", "")', 's, sm = sk["answer"], ""', "carry_the_model"),
    ("baseline: aliases matched case-sensitively", "baseline.py",
     "(vendor.casefold(), product.casefold())", "(vendor, product)", "ignore_case"),
    ("data: using() leaves the other set switched on", "data.py",
     "        use(before)\n", "        pass\n", "using_restores"),
    ("data: switching sets keeps the old NVD records cached", "data.py",
     "    nvd_record.cache_clear()\n", "", "reloads_nvd"),
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
     '_TOKEN = re.compile(r"\\d+|[a-z]+")', '_TOKEN = re.compile(r"\\d+")', "baseline or compare"),
    ("data: switching sets keeps the old catalog cached", "data.py",
     "    kev_index.cache_clear()\n", "", "switching"),
    ("baseline: a data set's own aliases ignored", "baseline.py",
     '        out[(a["vendor"], a["product"])] = a["nvd"]\n', "        pass\n", "aliases_extend"),
    ("key: the key path ignores the data set", "key.py",
     "(KEY or current().key)", '(KEY or current().fixtures.parent / "eval" / "ground_truth.json")', "key_follows"),
    ("planted: a held-out reference may quote text its document lacks", "planted.py",
     'if " ".join(c["deciding_quote"].split()) in " ".join(src[c["source"]].split()):', "if True:",
     "verbatim_key_quotes"),
    ("baseline: the keyword rule edited", "baseline.py",
     r'\bconfigured as\b|', "", "keyword_rule_is_frozen or keywords"),
    ("pipeline: a flagged answer passes on when its quote is real", "pipeline.py",
     'v2 = chk.verdict if chk.passed else "needs_human"', 'v2 = chk.verdict if chk.supported else "needs_human"',
     "flagged"),
    ("pipeline: a flagged answer still goes to the skeptic", "pipeline.py",
     'if c.passed and c.verdict != "unknown"]', 'if c.supported and c.verdict != "unknown"]', "flagged"),
    ("verify: the skeptic's quote no longer checked", "verify.py",
     "\n                and check_review(review, cve, sources).kept)", ")", "skeptic_quote or invented_quote"),
    ("pipeline: skeptic agreement taken without checking its quote", "pipeline.py",
     "v3 = chk.verdict if accepts(s, chk.verdict, cve, src) else",
     'v3 = chk.verdict if (s["agree"] and s["verdict"] == chk.verdict) else', "skeptic_quote"),
    ("planted: skeptic agreement counted without checking its quote", "planted.py",
     't["not_accepted"] += not accepts(s, j[5]["verdict"], j[3], j[4])',
     't["not_accepted"] += not (s["agree"] and s["verdict"] == j[5]["verdict"])', "invented_quote"),
    ("verify: a skeptic agreeing with another verdict accepted", "verify.py",
     'return bool(review["agree"] and review["verdict"] == verdict\n', 'return bool(review["agree"]\n',
     "skeptic_quote or invented_quote"),
    ("pipeline: the skeptic's verdict compared with itself", "pipeline.py",
     "accepts(s, chk.verdict, cve, src)", 'accepts(s, s["verdict"], cve, src)', "skeptic_quote"),
    ("planted: the skeptic's verdict compared with itself", "planted.py",
     'accepts(s, j[5]["verdict"], j[3], j[4])', 'accepts(s, s["verdict"], j[3], j[4])', "invented_quote"),
    ("verify: the skeptic's prose screened for CVE names", "verify.py",
     '{"text": "", "source": review.get("source")', '{"text": review.get("reason", ""), "source": review.get("source")',
     "skeptic_quote"),
    ("planted: a flagged wrong-CVE answer no longer counts as caught", "planted.py",
     "return (not c.passed) or bool(c.dropped)", "return (not c.supported) or bool(c.dropped)",
     "planted_verifier_table or verbatim_key_quotes"),
    ("planted: a dropped claim no longer counts as caught", "planted.py",
     "return (not c.passed) or bool(c.dropped)", "return not c.passed", "planted_verifier_table"),
    ("pipeline: the skeptic's objection left out of the note", "pipeline.py",
     'note = s["reason"][:200] + (', 'note = "" + (', "skeptic_quote"),
    ("pipeline: the note no longer says why the skeptic's quote was dropped", "pipeline.py",
     """(f" (skeptic's quote dropped: {dropped[0]['reason']})" if dropped else "")""",
     """(" (skeptic's quote dropped)" if dropped else "")""", "skeptic_quote"),
    ("versions: '<version> <update>' left whole, ISE 3.5.0 patch3 missed", "versions.py",
     '    m = re.fullmatch(r"(\\S+)\\s+(\\S+)", s)\n', "    m = None\n", "round_trip or ise_patch"),
    ("pipeline: a replay rescores the code with today's matcher", "pipeline.py",
     'verdicts = rec["verdicts"][k] if rec is not None else current_verdicts(item, cve)',
     "verdicts = current_verdicts(item, cve)", "recorded_matcher or ho53"),
    ("pipeline: a pair missing from matcher.json scored by today's code", "pipeline.py",
     "        if missing:\n", "        if False:\n", "recorded_matcher"),
    ("pipeline: a live run records no matcher", "pipeline.py",
     "    if live_triage is not None and recorded_matcher(run_dir) is None:\n",
     "    if False:\n", "records_its_matcher"),
    ("pipeline: the current-matcher report lists no change", "pipeline.py",
     "if r.shape in CODE_SHAPES and r.final != was[(r.item, r.cve, r.shape)].final]",
     "if False]", "recorded_matcher"),
    ("versions: a build after a space dropped before a range bound, 14.1 8.50 reads as exposed", "versions.py",
     'return version if update in ("-", "*") else f"{version}-{update}"',
     'return f"{version}-{update}" if update.startswith(PRERELEASE) else version',
     "after_a_space or range_that_starts"),
    ("versions: a pre-release tag sorted with other letters, 2.0-patch1 before 2.0-rc1", "versions.py",
     "            if (x in PRERELEASE) != (y in PRERELEASE):      # 2.0-rc1 before 2.0-patch1\n"
     "                return -1 if x in PRERELEASE else 1\n", "", "compare"),
    ("versions: the vendor rules ignored, every exact row read as '<version> <update>'", "versions.py",
     '    if product.lower() == "pan-os":', '    if False:', "round_trip or split_update"),
    ("baseline: the nearest exact row placed on the bare base version", "baseline.py",
     'if f[5] in ("*", "-") or compare(row, ranged) > 0:', 'if f[5] in ("*", "-") or compare(f[5], version) > 0:',
     "nearest_row"),
    ("baseline: nearest_row matches aliases case-sensitively", "baseline.py",
     "    names = names_for(item.vendor, item.product)\n    version, update = split_update(item.vendor, "
     "item.product, item.version)\n    ranged = range_version(version, update)\n    best,",
     "    names = aliases().get((item.vendor, item.product)) or []\n    version, update = split_update("
     "item.vendor, item.product, item.version)\n    ranged = range_version(version, update)\n    best,",
     "ignore_case"),
    ("baseline: an unaliased product makes nearest_row and retrieval raise", "baseline.py",
     ".get((vendor.casefold(), product.casefold()), [])", ".get((vendor.casefold(), product.casefold()))",
     "unaliased"),
    ("baseline: an edited alias file served from the cache", "baseline.py",
     "out.update(_alias_file(f, f.stat().st_mtime_ns))", "out.update(_alias_file(f, 0))", "alias_file_is_read"),
    ("agents: a call that reports no cost is saved", "agents.py",
     '        if meta.get("total_cost_usd") is None:\n', "        if False:\n", "no_cost"),
    ("agents: a live rerun reuses a saved answer with no cost", "agents.py",
     '        if rec.get("cost_usd") is None:\n', '        if backend is None and rec.get("cost_usd") is None:\n',
     "no_cost"),
    ("data: using() always goes back to the original set", "data.py",
     "    before = _current.name\n", '    before = "original"\n', "using"),
    ("pipeline: the triage and skeptic models swapped", "pipeline.py",
     "outcome(v3, truth), cost, lat, note, tm, sm))", "outcome(v3, truth), cost, lat, note, sm, tm))",
     "carry_the_model"),
    ("pipeline: an answer never sent to the skeptic credits a skeptic model", "pipeline.py",
     '"not sent to skeptic", ""', '"not sent to skeptic", tm', "flagged"),
    ("planted: recorded answers no reference matches drop out silently", "planted.py",
     "        if unused:\n", "        if False:\n", "no_reference"),
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
