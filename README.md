# exposure-watch

Does an AI agent beat plain code at deciding whether a piece of installed software is exposed to a known-exploited vulnerability? This repo measures it on 22 inventory and CVE pairs, scores five approaches against one answer key, and reports what each one costs.

**Short answer, on this set: no.** A plain matcher plus one keyword rule scored as well as the best agent pipeline, at zero cost. What the agents did do was find one clear error in my answer key and flag a second label that turned out to be contested. That result is the more useful one, and it is written up below with the evidence.

## Results (run 2026-10-16)

22 pairs: 20 inventory items checked against 12 CISA KEV vulnerabilities. For ten of the vulnerabilities there is one install inside the affected range and one outside it; GitLab and Ivanti have one install each. Triage agent: `claude-sonnet-5`. Skeptic: `claude-opus-5`. Both run through the Claude Code CLI with no tools and no web access, so the only documents they can read are the three they are handed. They still carry background knowledge from training.

Scored against the corrected key ([errata](eval/errata.json)):

| Approach | Correct | Over-called | Over-confident | Missed | Cost, 22 pairs | Mean time per pair |
|---|---:|---:|---:|---:|---:|---:|
| code | 18 | 3 | 1 | 0 | $0 | not timed |
| code + keywords ¹ | 21 | 0 | 1 | 0 | $0 | not timed |
| agent | 20 | 1 | 1 | 0 | $1.87 | 11.9 s |
| agent + verify | 20 | 1 | 1 | 0 | $1.87 | 11.9 s |
| agent + verify + skeptic | 21 ² | 1 | 0 | 0 | $4.73 | 29.7 s |

Scored against the key exactly as it was frozen before the run:

| Approach | Correct | Escalated | Over-called | Under-called | Missed |
|---|---:|---:|---:|---:|---:|
| code | 20 | 0 | 2 | 0 | 0 |
| code + keywords ¹ | 21 | 0 | 0 | 1 | 0 |
| agent | 20 | 0 | 1 | 1 | 0 |
| agent + verify | 20 | 0 | 1 | 1 | 0 |
| agent + verify + skeptic | 19 | 1 | 1 | 1 | 0 |

¹ The keyword rule was written after reading these 12 descriptions, so it is tuned on the test set. Its score is an upper bound for that approach, not a measurement of it.
² One of the 21 is the MOVEit pair, which the skeptic sent to a person. Under the corrected key that is the right answer.

What the columns mean, in terms of what each mistake costs whoever acts on it:

- **Over-called**: said "affected" where exposure depends on a feature the inventory does not record. Safe, and it creates extra work.
- **Under-called**: said "conditional" where the key says plainly affected. A person still looks.
- **Over-confident**: gave a firm verdict where the documents do not settle the question.
- **Missed**: said "not affected" for an exposed item. This is the expensive one, and **no approach did it on any pair.**

## What the agents found

**Citrix Bleed (CVE-2023-4966).** My key said the NetScaler at 13.1-49.13 was affected. The triage agent said conditional, and the skeptic agreed. NVD and KEV both limit exposure to an appliance "configured as a Gateway ... or AAA virtual server", which the inventory does not record. By the key's own definition of conditional, the key was wrong.

**MOVEit Transfer (CVE-2023-34362).** The triage agent said the 2023.0.1 install was affected, citing the NVD configuration row. The skeptic refused: NVD's description names 2023.0.1 as the fix ("before ... 2023.0.1 (15.0.1)"), while NVD's own configuration row includes it (`versionEndExcluding=2023.0.2`). Every Transfer row is one patch above the description. The two documents disagree at exactly this version, and the skeptic sent the pair to a person. Neither the matcher nor the triage agent noticed.

**How the key was corrected.** Changing an answer key after seeing agent output is how evaluations quietly flatter themselves, so neither label was changed on my judgment. Three labelers (`claude-opus-5-5`) re-derived all 22 labels without seeing the key or any agent answer, working from the documents and the verdict definitions. Like the agents, they bring background knowledge from training. A neutral adjudicator then ruled on any pair where they disagreed with each other or with the key. They agreed with the key on 20 pairs. Every label, both rulings, the packet the labelers saw and the script that ran them are in [`eval/key_audit/`](eval/key_audit).

- Citrix: 3 of 3 labelers said conditional, and the adjudicator agreed.
- MOVEit: the labelers split 2 to 1 for affected. The adjudicator ruled unknown, because the definitions give no precedence between the two documents. **This one is contestable.** All three labelers also noted, from background knowledge rather than the documents, that the vendor advisory names 2023.0.1 as fixed for this CVE.

The original key is untouched in [`eval/ground_truth.json`](eval/ground_truth.json) (sha256 `eb7723e173ed33d8a7a0e9faf461d8303fb2d778993abeb894a2ddcafe343e65`), and both tables above are always reported side by side.

## The checks, measured with planted errors

Each check was tested by breaking correct answers on purpose and counting what it caught (`python -m exposure_watch planted`).

| Planted defect | Planted | Verifier caught | Skeptic caught |
|---|---:|---:|---:|
| Quote altered by one digit | 19 | 19 | |
| Real quote credited to the wrong document | 22 | 22 | |
| Claim cites a CVE no document mentions | 22 | 22 | |
| Answer is about a different CVE | 22 | 22 | |
| Opposite verdict, same real quote | 22 | 0 | 22 |
| Correct answer, as a control (lower is better) | 22 | | 2 rejected |

The verifier is deterministic and checks evidence, not conclusions: a wrong verdict that quotes real text passes it every time, by design. That gap is the skeptic's job. The control row is what keeps the skeptic honest, because a skeptic that rejects everything would catch every flip.

The skeptic rejected two correct answers. On IOS XE it holds that the web UI sentence names the vulnerable component rather than stating a configuration condition, and it reached the same verdict in the live run. On MOVEit it argued against whichever answer it was shown: in the live run it rejected "affected" because of the document conflict, and here it rejected "unknown" by treating the configuration row as authoritative. That pair is contested, and the skeptic behaves like it. The skeptic side cost $5.58 for 44 calls.

The first run of this measurement scored the skeptic as rejecting three correct answers. Two of those were my reference answers citing the wrong NVD row, and the skeptic was right to reject them. The references were fixed, a test now checks that every affected or not-affected reference answer (18 of the 22) cites the row that decides it, and the measurement was run again from scratch. The superseded run is kept in [`runs/2026-10-16/planted_skeptic_v1_superseded/`](runs/2026-10-16/planted_skeptic_v1_superseded).

## Read this before quoting a number

- **22 pairs is small.** One pair is 4.5 points. These are directions, not rates.
- **The key and the baseline read the same NVD rows.** The matcher scores well partly because the key was built from the data it matches against.
- **The corrections favour the approaches that prompted them.** Both keys are shown for that reason.
- **The labelers are Claude models, like the agents.** Their errors may be correlated with the agents' errors. Every label and ruling is published in `eval/key_audit/`, so a person can check them.
- **The keyword rule is tuned on this set.** A held-out set of CVEs is what would measure it, and that is the next step. Its rules, and my prediction, are fixed in advance in [`eval/heldout/PREREG.md`](eval/heldout/PREREG.md).
- **The inventory records version only.** The labelers, drawing on background knowledge, flagged real exposures it cannot see: an Exchange CU8 server with the March 2021 update looks identical to an unpatched one; an Ivanti box with the mitigation XML imported looks unmitigated; F5 exposure depends on whether iControl REST is reachable. A real deployment needs patch level and configuration fields, not just versions.
- **Retrieval was checked.** Every NVD row that describes the item reaches the agent (284 of 284 across the 22 pairs). The agent also sees 195 rows about neighbouring products and has to read past them (`python -m exposure_watch retrieval`). Which rows describe an item comes from the matcher's own alias table, so this checks the filter against my reading of NVD, not an independent one.
- **Costs are as reported by the Claude Code CLI** (`total_cost_usd` per call), summed over the 22 pairs.

## Run it

Python 3.10 or later. Nothing outside the standard library is needed to score.

```
python -m exposure_watch run --run runs/2026-10-16
```

That replays the recorded answers in `runs/2026-10-16/` and rescores every approach against both keys, with no model and no key needed. To run the agents yourself, sign in to the Claude Code CLI and add `--live` with a fresh `--run` directory. A rerun pays only for answers that directory does not already hold.

```
python -m exposure_watch planted
python -m exposure_watch retrieval
pip install -e ".[dev]" && pytest
python tests/mutants.py
```

The tests cover version comparison, the matcher, the verifier, scoring, the answer cache, the errata loader and the replay path. `tests/mutants.py` breaks the code in 14 specific ways, one at a time, and confirms that a test fails each time; it refuses to count a change that only stops the code from loading.

## Data

- `fixtures/kev_catalog.json`: CISA Known Exploited Vulnerabilities catalog, version 2026.10.16, 1,748 entries, sha256 `b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d`.
- `fixtures/nvd/`: the NVD API 2.0 records for the 12 CVEs.
- `examples/inventory.csv`: 20 made-up inventory items.
- `eval/ground_truth.json`: the 22-pair key as frozen before the first run. `eval/errata.json`: corrections, with reasons and how each was found.

Both data sources are public US government data.

## Layout

```
exposure_watch/versions.py   version comparison for the formats vendors ship
exposure_watch/data.py       loads the fixtures and renders the three documents
exposure_watch/baseline.py   the matcher, and the keyword rule
exposure_watch/verify.py     the deterministic evidence check
exposure_watch/agents.py     the two agent roles and the CLI backend
exposure_watch/pipeline.py   runs and scores the five approaches
exposure_watch/planted.py    planted-error measurement
exposure_watch/retrieval.py  checks that the deciding rows reach the agent
exposure_watch/key.py        the frozen key and its errata
eval/key_audit/              the blind relabel: packet, labels, rulings, script
runs/2026-10-16/             every recorded answer, replayable without a model
tests/mutants.py             deliberate bugs the tests must catch
docs/HARNESS.md              how I run agents on real work
```

## License

MIT. Built independently by Erik Hill from public data.
