"""Write each run's matcher.json from the code-shape results that run published.

    python tools/record_matcher.py

Used once, on 2026-10-24, when the matcher started being versioned like the key.
The verdicts are read from report.json as committed at 2d38744, the last commit
before matcher.json existed, and checked against report_frozen_key.json where it
exists: the code shapes do not depend on the key, so both must agree. The sha256
is of baseline.py + versions.py at the commit each record names. Rerunning it
rewrites the two files with the same bytes.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

repo = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
PUBLISHED = "2d38744"


def show(path, rev):
    return subprocess.run(["git", "show", f"{rev}:{path}"], cwd=repo, capture_output=True, check=True).stdout


def sha_at(rev):
    h = hashlib.sha256()
    for name in ("baseline.py", "versions.py"):
        h.update(show(f"exposure_watch/{name}", rev))
    return h.hexdigest()


PROVENANCE = {
    "runs/2026-10-16": ("5c7c733", "2026-10-24, from the code-shape results this run published in report.json "
                        "(as committed at 2d38744). The run itself, on 2026-10-16, predates the repository, so no "
                        "record of the code on that day exists: 5c7c733 is the first commit, and its matcher "
                        "reproduces all 22 verdicts, as has every commit since."),
    "runs/heldout": ("bfbab91", "2026-10-24, from the code-shape results this run published in report.json "
                     "(as committed at 2d38744). eval/heldout/PREREG.md names the code at freeze as bfbab91, "
                     "with exposure_watch/ unchanged since fd3841f; the run was ecb632b, whose matcher is the "
                     "same, and every commit up to 2d38744 replayed these 57 verdicts byte for byte."),
}

for run, (commit, recorded) in PROVENANCE.items():
    verdicts = {}
    for report in ("report.json", "report_frozen_key.json"):
        try:
            rep = json.loads(show(f"{run}/{report}", PUBLISHED))
        except subprocess.CalledProcessError:
            continue
        for r in rep["results"]:
            if r["shape"] not in ("code", "code+keywords"):
                continue
            got = [r["final"], r["note"]]
            prev = verdicts.setdefault(f"{r['item']}__{r['cve']}", {}).setdefault(r["shape"], got)
            assert prev == got, (run, r["item"], r["shape"], prev, got)
    rec = {"commit": commit, "sha256": sha_at(commit), "recorded": recorded, "verdicts": verdicts}
    (repo / run / "matcher.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
    print(run, len(verdicts), "pairs, matcher", commit)
