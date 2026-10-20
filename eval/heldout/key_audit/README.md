# How the held-out key was made

Workflow run `wf_6910685e-337`, script `workflow.js` in this directory, 2026-10-19. Nine agents, all `claude-opus-5-5` (read from the agent transcripts, not assumed): three labelers, each covering all 57 pairs in two chunks, and one adjudicator per disputed pair. The labelers read only a copy of `packet.json` placed in its own directory; the build intent and the pair map were elsewhere.

- 54 pairs unanimous. 3 adjudicated: P34 affected, P41 conditional, P52 conditional (two labelers said affected, one conditional, each time). Rulings in full in `rulings.json`.
- Every deciding quote was checked against the document it names, the same way the verifier checks agents: 172 of 174 are verbatim. The two that are not (P31, labelers A and C) dropped the `a:` part from `cpe:2.3:a:atlassian:crowd:...`. Both labels match the third labeler's and the row they meant.
- Outside knowledge: 58 notes, and none says the labeler recognised the CVE. Most read "I do not recognise this CVE ID". This is consistent with the selection floor (published to NVD on or after 2026-07-01); it is not proof that the triage and skeptic models lack background knowledge.
- Against the build intent (`../build_intent.json`), which the labelers never saw: 43 pairs match. 12 built as affected or not_affected were labeled conditional, and 2 built outside the chosen range were labeled affected because another row for the same product covers them. The key is the labelers', not the build intent.

Files: `labels.json` (every label, quote and reasoning), `rulings.json`, `pair_map.json` (P-id to item and CVE), `outside_notes.json`, `packet.json`.
