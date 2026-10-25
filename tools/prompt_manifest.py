"""Check, or first write, runs/2026-10-16/prompt_manifest.json.

    python tools/prompt_manifest.py            check every hash against the code now
    python tools/prompt_manifest.py COMMIT     write it, when it does not exist yet

Round 1's 44 triage and skeptic answers were saved before answers carried the
hash of the prompt that produced them. This replays the run and takes, for each
answer, the hash of the prompt the code asks today. The manifest is computed
from the code, not recorded at call time, and the file says so. It was written
once, on 2026-10-24, from the code at 2d38744; the same 44 hashes reproduce at
every commit back to 5c7c733.
"""
import hashlib
import json
import sys
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo))

from exposure_watch import agents  # noqa: E402
from exposure_watch.data import load_inventory  # noqa: E402
from exposure_watch.key import load_pairs  # noqa: E402
from exposure_watch.pipeline import run  # noqa: E402

run_dir = repo / "runs" / "2026-10-16"
path = run_dir / agents.MANIFEST
seen = {}
replay = agents.fetch


def hashing_fetch(backend, d, key, system, prompt, schema):
    h = hashlib.sha256(json.dumps([system, prompt, schema], sort_keys=True).encode()).hexdigest()
    assert seen.setdefault(f"{d.name}/{key}", h) == h, key
    return replay(backend, d, key, system, prompt, schema)


agents.fetch = hashing_fetch
inv = {i.id: i for i in load_inventory(repo / "examples" / "inventory.csv")}
for with_errata in (True, False):
    run(load_pairs(with_errata=with_errata), inv, run_dir)
assert len(seen) == 44, len(seen)

if path.exists():
    listed = json.loads(path.read_text(encoding="utf-8"))["prompts"]
    bad = sorted(k for k in seen if listed.get(k) != seen[k])
    print(f"{len(seen) - len(bad)} of {len(seen)} hashes match; differ: {bad}")
    raise SystemExit(1 if bad else 0)
if len(sys.argv) < 2:
    raise SystemExit("no manifest yet: pass the commit the code was taken from")
path.write_text(json.dumps({
    "computed": f"computed from code at {sys.argv[1]}, not recorded at call time",
    "why": "These 44 answers were saved before answers carried the hash of the prompt that produced "
           "them. Each hash here is of the prompt the code at that commit asks, so a later change to a "
           "prompt, a schema or the documents fails the replay instead of passing silently. It cannot "
           "show that the prompt asked on 2026-10-16 was this one.",
    "prompts": dict(sorted(seen.items()))}, indent=1), encoding="utf-8")
print("wrote", len(seen), "hashes")
