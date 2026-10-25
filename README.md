# exposure-watch

Does an AI agent beat plain code at deciding whether a piece of installed software is exposed to a known-exploited vulnerability? This repo measures it on 22 inventory and CVE pairs, then on a pre-registered held-out set of 57, scores five approaches against an answer key, and reports what each one costs.

**Short answer, on this set: no.** A plain matcher plus one keyword rule scored as well as the best agent pipeline, at zero cost. What the agents did do was find one clear error in my answer key and flag a second label that turned out to be contested. That result is the more useful one, and it is written up below with the evidence.

**Then a held-out set: on correct answers, still a tie; on wrong answers, not.** The keyword rule was written after reading the first 12 descriptions, so I pre-registered a second set of 30 vulnerabilities and pushed its answer key before anything ran on it. On those 57 pairs the agent pipeline with a skeptic was the only approach that was never wrong: 47 correct and 10 sent to a person, against code + keywords' 45 correct and 12 wrong, one of them a missed exposure, scored as the code was frozen before the run. The keyword rule caught 2 of the 12 pairs it exists for. [Details below](#held-out-set-run-2026-10-19).

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
- **Missed**: said "not affected" for an exposed item. This is the expensive one. No approach did it on these 22 pairs; on the held-out set below, four of the five did, scoring the code as frozen.

## What the agents found

**Citrix Bleed (CVE-2023-4966).** My key said the NetScaler at 13.1-49.13 was affected. The triage agent said conditional, and the skeptic agreed. NVD and KEV both limit exposure to an appliance "configured as a Gateway ... or AAA virtual server", which the inventory does not record. By the key's own definition of conditional, the key was wrong.

**MOVEit Transfer (CVE-2023-34362).** The triage agent said the 2023.0.1 install was affected, citing the NVD configuration row. The skeptic refused: NVD's description names 2023.0.1 as the fix ("before ... 2023.0.1 (15.0.1)"), while NVD's own configuration row includes it (`versionEndExcluding=2023.0.2`). Every Transfer row is one patch above the description. The two documents disagree at exactly this version, and the skeptic sent the pair to a person. Neither the matcher nor the triage agent noticed.

**How the key was corrected.** Changing an answer key after seeing agent output is how evaluations quietly flatter themselves, so neither label was changed on my judgment. Three labelers (`claude-opus-5-5`) re-derived all 22 labels without seeing the key or any agent answer, working from the documents and the verdict definitions. Like the agents, they bring background knowledge from training. A neutral adjudicator then ruled on any pair where they disagreed with each other or with the key. They agreed with the key on 20 pairs. Every label, both rulings, the packet the labelers saw and the script that ran them are in [`eval/key_audit/`](eval/key_audit).

- Citrix: 3 of 3 labelers said conditional, and the adjudicator agreed.
- MOVEit: the labelers split 2 to 1 for affected. The adjudicator ruled unknown, because the definitions give no precedence between the two documents. **This one is contestable.** All three labelers also noted, from background knowledge rather than the documents, that the vendor advisory names 2023.0.1 as fixed for this CVE.

The original key is untouched in [`eval/ground_truth.json`](eval/ground_truth.json) (sha256 `eb7723e173ed33d8a7a0e9faf461d8303fb2d778993abeb894a2ddcafe343e65`), and both tables above are always reported side by side.

## The checks, measured with planted errors

Each check was tested by breaking correct answers on purpose and counting what it caught (`python -m exposure_watch planted`; add `--skeptic --run runs/2026-10-16` for the skeptic column).

| Planted defect | Planted | Verifier caught | Skeptic caught |
|---|---:|---:|---:|
| Quote altered by one digit | 19 | 19 | |
| Real quote credited to the wrong document | 22 | 22 | |
| Claim cites a CVE no document mentions | 22 | 22 | |
| Answer is about a different CVE | 22 | 22 | |
| Opposite verdict, same real quote | 22 | 0 | 22 |
| Correct answer, as a control (lower is better) | 22 | | 2 rejected |

The verifier is deterministic and checks evidence, not conclusions: a wrong verdict that quotes real text passes it every time, by design. That gap is the skeptic's job. The control row is what keeps the skeptic honest, because a skeptic that rejects everything would catch every flip.

Until 2026-10-24 one row of the verifier column claimed more than the pipeline did: an answer about a different CVE counted as caught because the verifier flagged it, yet agent + verify passed its verdict on when the quote was real, and with the skeptic it reached a person only if the skeptic disagreed. The skeptic's agreement was also taken without checking the passage it quoted. Now a flagged answer goes straight to a person, and the skeptic's agreement counts only if it reaches the same verdict and its quote survives the same check as the triage agent's. No recorded answer in either run triggers either change, so both score exactly as before; the tests and `tests/mutants.py` are what exercise the new checks.

The skeptic rejected two correct answers. On IOS XE it holds that the web UI sentence names the vulnerable component rather than stating a configuration condition, and it reached the same verdict in the live run. On MOVEit it argued against whichever answer it was shown: in the live run it rejected "affected" because of the document conflict, and here it rejected "unknown" by treating the configuration row as authoritative. That pair is contested, and the skeptic behaves like it. The skeptic side cost $5.58 for 44 calls.

The first run of this measurement scored the skeptic as rejecting three correct answers. Two of those were my reference answers citing the wrong NVD row, and the skeptic was right to reject them. The references were fixed, a test now checks that every affected or not-affected reference answer (18 of the 22) cites the row that decides it, and the measurement was run again from scratch. The superseded run is kept in [`runs/2026-10-16/planted_skeptic_v1_superseded/`](runs/2026-10-16/planted_skeptic_v1_superseded).

## Held-out set (run 2026-10-19)

The keyword rule above was written after reading the 12 descriptions it is scored on, so its 21 was an upper bound. To measure it, I wrote the rules for a second set down first and pushed each step before the next one existed: the pre-registration ([`eval/heldout/PREREG.md`](eval/heldout/PREREG.md), commit `fd3841f`), the selected vulnerabilities and inventory (`bfbab91`), the answer key (`9ec6ecc`), then the run (`ecb632b`). The matcher's logic, the keyword rule, the version handling, the verifier, the prompts and the scoring are byte-identical to round 1. The only code changes are the plumbing that loads a second set and an alias lookup that reads that set's aliases file.

- **The set.** The 30 most recently added KEV vulnerabilities from 2026-07-01 to 2026-10-19 that NVD first published on or after 2026-07-01. Each gets up to two inventory items built by rule, one inside the affected range and one at the first fixed version: 57 pairs. The rules, and two amendments made before labeling, are in the pre-registration.
- **The key.** Three blind labelers (`claude-opus-5-5`) labeled every pair from the same three documents the agents see, without seeing how an item was built. They agreed on 54, and a neutral adjudicator ruled on 3: 24 affected, 21 not affected, 12 conditional. None of them recognised any of these CVEs. Details in [`eval/heldout/key_audit/`](eval/heldout/key_audit).
- **The run.** One live run with the same models and prompts as round 1. It replays without a model: `python -m exposure_watch --set heldout run --run runs/heldout`.

| Approach | Correct | Sent to a person | Over-called | Under-called | Missed | Cost, 57 pairs | Mean time per pair |
|---|---:|---:|---:|---:|---:|---:|---:|
| code | 44 | 0 | 12 | 0 | 1 | $0 | not timed |
| code + keywords | 45 | 0 | 10 | 1 | 1 | $0 | not timed |
| agent | 48 | 3 | 2 | 1 | 3 | $13.36 | 12.0 s |
| agent + verify | 48 | 3 | 2 | 1 | 3 | $13.36 | 12.0 s |
| agent + verify + skeptic | 47 | 10 | 0 | 0 | 0 | $33.34 | 29.8 s |

No approach raised a false alarm. The key has no "unknown" labels, so no approach could be over-confident.

What it shows:

- **On correct answers, still a tie.** The pre-registered comparison is code + keywords against agent + verify + skeptic: 45 against 47. They disagree on 6 pairs, 2 one way and 4 the other, and the exact McNemar p is 0.69. Fifty-seven pairs cannot tell those two apart.
- **The difference is where the errors go.** Code + keywords gave 12 wrong answers, each a firm verdict with nothing to warn whoever reads it, and one of them missed an exposed item. Agent + verify + skeptic gave none: the 10 pairs it was not sure of went to a person. That is what $33.34, about $0.58 a pair, bought on this set. In round 1 the same pipeline cost about $0.22 a pair.
- **The keyword rule did not carry over.** Twelve pairs depend on something the inventory does not record: an edition (NetScaler FIPS; the Acronis cPanel plugin rather than Plesk or DirectAdmin), a feature that has to be switched on (Cisco's AMP file reputation, an F5 OAuth setup, Check Point site-to-site VPN), or how the software was installed (Zammad's DEB and RPM packages). The rule caught 2 of the 12. It also fired once where the key says plainly affected, because a Windows description says an attacker can "bypass a security feature".
- **The version handling did not fully carry over either.** The code missed one exposed item: Cisco ISE recorded as `3.5.0 patch3`, which NVD lists as version 3.5.0 with update `patch3`. `split_update` knows only the update formats of round 1's vendors, so it compared the whole string and matched nothing. My build rule wrote that version string, so a real inventory might spell it differently, and a one-line parser change would catch this case. The point is that the frozen code did not. That change is now made, and it shows only in `runs/heldout/report_current_matcher.json`: the current matcher gets code 45 correct and none missed, and code + keywords 46 and none missed. Those are not held-out measurements. The fix was written after seeing this miss, it reads the build rule's spelling, and Cisco's own spellings such as `3.5.0 Patch 3` would still miss. The table above, and the pre-registered comparison, stay as the frozen code scored them.
- **The single agent missed three exposed items, and the skeptic caught all three.** All three are NetScaler builds that NVD's standard row places at the fix while its FIPS row still covers them. The agent read the standard row and said not affected, quoting it correctly, so the verifier passed them. The skeptic sent all three to a person. That is round 1's division of labour again: the verifier catches invented evidence, the skeptic catches real evidence attached to the wrong verdict.
- **What the skeptic costs besides money.** It agreed with the triage agent on 47 of its 54 reviews, and it sent one correct answer to a person (Check Point Gaia R80, conditional).
- **Three of the agent's "send to a person" answers are a build-rule artifact.** They are NetScaler items recorded as a bare `14.1`, which is what the rule writes when a range starts at `14.1`; a real NetScaler reports a build number. The key calls them affected or conditional, and the agent said the version alone does not settle it. That reading is defensible, and the key does not reward it.

My predictions, from the pre-registration:

1. The keyword rule loses its tie. Right in direction only: 45 against 47 is not a difference this set can show.
2. The frozen code makes at least one version-format error. Right: Cisco ISE.
3. Agent + verify + skeptic misses no exposed item. Right, on both sets.

Checks on this set, no model needed: the verifier caught all 223 planted evidence defects (52 altered quotes, and 57 each of wrong document, invented CVE and wrong CVE) and none of the 57 flipped verdicts, as designed. Reference answers here quote the passage the labelers cited, because round 1's way of building them leans on the keyword rule. Retrieval: all 1,396 NVD rows that describe the items reach the agent, along with 594 rows about neighbouring products.

## Read this before quoting a number

- **22 pairs is small, and 57 is not large.** One pair is 4.5 points in round 1 and 1.8 on the held-out set. These are directions, not rates.
- **The key and the baseline read the same NVD rows.** The matcher scores well partly because the key was built from the data it matches against.
- **The corrections favour the approaches that prompted them.** Both keys are shown for that reason.
- **The labelers are Claude models, like the agents.** Their errors may be correlated with the agents' errors. Every label and ruling is published in `eval/key_audit/`, so a person can check them.
- **The keyword rule is tuned on round 1's set.** The held-out set measured it: it caught 2 of 12 conditional pairs there.
- **Both keys take the documents as the truth.** A label says what KEV and NVD support, not what a vendor advisory or a running system would show.
- **The inventory records version only.** The labelers, drawing on background knowledge, flagged real exposures it cannot see: an Exchange CU8 server with the March 2021 update looks identical to an unpatched one; an Ivanti box with the mitigation XML imported looks unmitigated; F5 exposure depends on whether iControl REST is reachable. A real deployment needs patch level and configuration fields, not just versions.
- **Retrieval was checked.** Every NVD row that describes the item reaches the agent (284 of 284 across the 22 pairs). The agent also sees 195 rows about neighbouring products and has to read past them (`python -m exposure_watch retrieval`). Which rows describe an item comes from the matcher's own alias table, so this checks the filter against my reading of NVD, not an independent one.
- **Costs are as reported by the Claude Code CLI** (`total_cost_usd` per call), summed over the 22 pairs.

## Run it

Python 3.10 or later. Nothing outside the standard library is needed to score.

```
python -m exposure_watch run --run runs/2026-10-16
```

That replays the recorded answers in `runs/2026-10-16/` and rescores every approach against both keys, with no model and no key needed. To run the agents yourself, sign in to the Claude Code CLI and add `--live` with a fresh `--run` directory. A rerun pays only for answers that directory does not already hold. A live run asks for full model IDs by default (`claude-sonnet-5`, `claude-opus-5`); round 1 asked for the aliases `sonnet` and `opus`, which the CLI resolved to those two. Every result records the model that answered.

The matcher is versioned like the key. Each run's `matcher.json` holds the verdicts its two code approaches published and the commit of the matcher behind them: `bfbab91` for the held-out run, as the pre-registration names it, and for round 1, which ran before the repository existed, the first commit, `5c7c733`, which reproduces all 22. A replay scores those approaches from that file, so a later fix to the matcher cannot rewrite a published score table. The same command writes `report_current_matcher.json`: today's matcher on the same pairs, with every verdict it changes listed. That report carries a hash of the matcher's source, so CI fails on any edit to `baseline.py` or `versions.py` until it is regenerated, and every matcher change shows up in review. The planted-error suite still builds its reference answers with today's matcher, and it refuses to replay if a recorded answer no longer has one.

Round 1's answers were saved before answers carried the hash of their prompt, so `runs/2026-10-16/prompt_manifest.json` holds those hashes. They were computed from the code at commit `2d38744`, not recorded at call time, and they reproduce at every commit back to `5c7c733`. A changed prompt fails either kind of replay, and a test fails if the manifest goes missing or stops listing an answer. `tools/record_matcher.py` and `tools/prompt_manifest.py` rebuild and check both files.

```
python -m exposure_watch planted
python -m exposure_watch retrieval
python -m exposure_watch --set heldout run --run runs/heldout
python tools/heldout_report.py runs/heldout/report.json
pip install -e ".[dev]" && pytest
python tests/mutants.py
```

The tests cover version comparison, the matcher, the verifier, scoring, the answer cache, the errata loader and the replay path, and they run every version row and range bound of every product the alias tables know, in all 130 NVD records of both sets, through the matcher and back, in the build rule's spelling and in the vendor's own. `tests/mutants.py` breaks the code in 71 specific ways, one at a time, and confirms that a test fails each time; it refuses to count a change that only stops the code from loading.

## Data

- `fixtures/kev_catalog.json`: CISA Known Exploited Vulnerabilities catalog, version 2026.10.16, 1,748 entries, sha256 `b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d`.
- `fixtures/nvd/`: the NVD API 2.0 records for the 12 CVEs.
- `examples/inventory.csv`: 20 made-up inventory items.
- `eval/ground_truth.json`: the 22-pair key as frozen before the first run. `eval/errata.json`: corrections, with reasons and how each was found.
- `fixtures/heldout/`: the same KEV release, and the NVD records of all 118 candidates the held-out rules considered. `eval/heldout/`: the pre-registration, how the set was selected and built, its inventory, aliases and key.

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
eval/heldout/                the held-out set: pre-registration, selection, inventory, key
tools/                       builds the held-out set, freezes its key, runs its analysis, records the matcher and prompts
runs/2026-10-16/             every recorded answer, replayable without a model
runs/heldout/                the held-out run, replayable the same way
tests/mutants.py             deliberate bugs the tests must catch
docs/HARNESS.md              how I run agents on real work
```

## License

MIT. Built independently by Erik Hill from public data.
