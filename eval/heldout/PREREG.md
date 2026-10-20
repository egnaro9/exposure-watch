# Held-out set: pre-registration

Written 2026-10-19, before any held-out data was fetched, any answer key existed, or any approach ran on it.

## The question

On the first 22 pairs, a plain matcher plus one keyword rule scored as well as the best agent pipeline (21 correct each, against the corrected key). The keyword rule was written after reading those 12 descriptions, so its score there is an upper bound, not a measurement. This set measures it. The same question applies to the version handling in `versions.py`, which was also written against those 12 vulnerabilities.

So: on vulnerabilities none of this code was written against, does the frozen code still match the agent pipeline?

## What is frozen

- The keyword rule (`baseline.CONDITION`), the matcher (`baseline.judge`), the version comparison and `split_update` (`versions.py`), the verifier, both agent prompts and schemas, and the scoring. They stay as they were at commit 5c7c733. The only code change allowed is plumbing to load a second data set, plus an alias lookup that reads the held-out aliases from a data file.
- The models: triage `claude-sonnet-5`, skeptic `claude-opus-5`, the same as round 1, called the same way through the Claude Code CLI.
- Nothing about the code or the prompts changes after the key is frozen. One live run. A rerun only fills calls that failed. Nothing is rerun to improve a number.

## Selection rule

1. Fetch the CISA KEV catalog on 2026-10-19 and record its version and sha256.
2. Candidates: entries with `dateAdded` from 2026-07-01 through 2026-10-19, whose NVD record was first published on or after 2026-07-01. The point of the date floor is that these vulnerabilities were not public when the models were trained. I do not know either model's training cutoff, so this reduces the background-knowledge problem rather than ruling it out, and the labelers' outside-knowledge notes will show whether a capable model recognises them.
3. Fetch each candidate's NVD API 2.0 record. Exclude, and count by reason:
   - no NVD record;
   - no vulnerable CPE rows (NVD has not analysed it yet). The code baseline has nothing to read without them, so these are out of scope for this comparison, and their count is reported because it is a finding about the data on its own;
   - no application or operating-system row (`a` or `o`) for the product.
4. If more than 30 remain, keep the 30 most recently added (then by CVE ID). If fewer than 15 remain, move the start of both date windows back one month at a time until at least 15 remain, and report the earlier ones separately as possibly inside training data.

## Building the inventory

All mechanical, by `tools/heldout_build.py`, so no item is chosen with an answer in mind:

- **Product.** Group the vulnerable `a`/`o` rows by NVD vendor:product. Pick the group whose name shares the most words with KEV's vendorProject and product; ties go to the group with more rows, then to the first in the record.
- **Item names.** The inventory item uses KEV's vendorProject and product, as an administrator would write them. The alias from that name to the chosen NVD product goes in `eval/heldout/aliases.json`. That alias is the setup step a careful engineer does once per product; it does not depend on any verdict.
- **Versions.** Take the chosen product's range row with the highest upper bound. Inside the range: `versionStartIncluding` if present, else `versionEndIncluding` if present, else `versionEndExcluding` with its last number reduced by one. Outside the range: `versionEndExcluding` (the first fixed version), else `versionEndIncluding` with its last number raised by one. A product described only by exact versions gets one item, at the highest listed version. Any case these rules cannot build is decided by hand, written down with the reason in `eval/heldout/construction.json`, before labeling starts.
- Each vulnerability then gives up to two pairs: one item built inside the range, one built outside. The build intent is recorded, but it is not the answer key.

## The answer key

- Three blind labelers (`claude-opus-5-5`) each label every pair from a packet holding only the item and the three documents the agents see, with the same verdict definitions as round 1. They do not see the build intent, the code's output or any agent answer. Pair order and IDs are shuffled, and the map is kept outside their reach.
- If all three agree, that is the label. If any disagree, one neutral adjudicator rules on that pair from the documents and the three anonymised labels.
- The key is then frozen, its sha256 written below, and pushed publicly before the code or any agent runs on this set. Errata after that go in `eval/heldout/errata.json`, and every report scores against both the frozen key and the corrected one, as in round 1.

## What gets reported

- All five approaches against the held-out key: correct, escalated, over-called, under-called, false alarm, missed and over-confident, cost and time.
- The pre-registered comparison is `code+keywords` against `agent+verify+skeptic`: correct counts, missed counts, and an exact McNemar test on the pairs where they disagree. With this many pairs a difference of a few pairs is not a finding, and the report will say so if that is what happens.
- Every frozen-code error, sorted into version-format gaps (the parser did not understand the vendor's version string) and condition misses (the keyword rule did or did not fire).
- Retrieval recall on the held-out set, and the verifier-side planted-error measurement (no model needed).
- How many candidates were excluded at each step.

## My prediction, written before the data

- The keyword rule loses its tie: `agent+verify+skeptic` gets more pairs correct than `code+keywords`.
- The frozen code makes at least one version-format error on vendors it was not written for.
- `agent+verify+skeptic` misses no exposed item, as in round 1.

If the code ties or wins again, that is the result and the write-up says so.

## Amendments

Each made before labeling started, before the code or any agent ran on this set, and after the original text was pushed (commit fd3841f).

1. **2026-10-19, after the first build: item names.** The rule above names each item with KEV's vendorProject and product "as an administrator would write them". For five vulnerabilities KEV's product is "Multiple Products", which no inventory records, and one product name carried a trailing space. Change: a "Multiple Products" item takes the chosen NVD product's name with underscores read as spaces (for example "crowd", "multi-domain security management"), and names are trimmed. The alias for that name points at the same NVD product the rule already chose, so no verdict-relevant choice changed. Applied in `tools/heldout_build.py`, `inventory_name`.
2. **2026-10-19: one vulnerability builds no items.** CVE-2026-58704 (Google Pixel) has a single NVD row, `cpe:2.3:o:google:android:-`, with no version, so neither rule can build an item and it contributes no pairs. It stays among the 30 selected and is not replaced, because the cap counts vulnerabilities and backfilling would be a second selection step the rule does not have.

## Frozen hashes

Filled in when the key was frozen, 2026-10-19, before the code or any agent ran on this set. `tests/test_core.py` fails if the key file stops matching its hash.

- KEV catalog `fixtures/heldout/kev_catalog.json`: catalogVersion 2026.10.16, sha256 `b6e27975f6635ecfc546fbd4fd6e444ba63a07ab2abc8876229d77fe083d357d` (the same release round 1 used; CISA had not published a newer one on 2026-10-19).
- Answer key `eval/heldout/ground_truth.json`: sha256 `0e3024fd2c6099b7c44e12ead10a166dfc19999ca67d61ce61c45e56527a0df8`. 57 pairs: 24 affected, 21 not_affected, 12 conditional. 54 unanimous, 3 adjudicated.
- Code at freeze: commit `bfbab91` (exposure_watch/ unchanged since `fd3841f`).
