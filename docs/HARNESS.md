# How I run agents on real work

This is a case study of the harness I built for my own product work. It is not part of exposure-watch's code; it is here because it describes how I run agents.

A self-directed system that lets AI agents **plan, build, review, and validate their own changes** to two real products: an Android game shipped to Google Play, and a second, larger game in development. A human is on every step that can't be undone.

Built solo, from first principles, since spring 2026. It's built to *ship*, not to gold-plate: every gate below exists so I can move fast without shipping something broken. This document describes the **architecture**; the harness and product source are private.

> Built by **Erik Hill**, agentic systems engineer.
> Portfolio → https://egnaro9.github.io · LinkedIn → https://linkedin.com/in/erik-hill-98895575

---

## The problem
Coding agents are easy to demo and hard to *trust*. The moment they touch a real codebase, meaning deploys, commits and user-facing changes, you need what any production system needs: review, tests, gates, and a way to catch your own regressions. This harness is my answer.

## The loop
Work moves through five stages, each handing off automatically:

```
Strategy → Execution → Critic → Ops        (+ Evaluation, asynchronous)
```

- **Strategy** plans the change.
- **Execution** builds it.
- **Critic** reviews it in *cold context*, a fresh model with no memory of building it, so it catches what the builder rationalized away.
- **Ops** ships it, behind a human gate.
- **Evaluation** is the fifth role but not a fifth step: it scores completed batches out of band rather than gating each change, so a slow scoring pass never blocks the loop.

The manager hands each stage to a fresh subagent pinned to the model that role needs, so the loop advances without a human babysitting each handoff. Every irreversible step still waits for me.

## The manager, and where I sit
Above the five stages sits one **orchestration layer** that I direct: it plans each unit of work, routes it to the right role and model, and holds the system's state between steps. I designed the roles, the gates, and the routing; the harness runs them. I'm inside the loop as its judgment and authority, and the manager extends that across many parallel agents.

## Per-role model routing
Not every stage needs the same brain. Reasoning-heavy judgment (Strategy, Critic, Evaluation) runs on a stronger, colder model; routine execution runs on a faster one. A **model-gate** refuses to let a judgment role run on an under-powered model.

## The oracle: correctness you can *prove*
The money question for any agentic system: how do you know it didn't break something?

- **Differential oracle** *(designed, pre-launch)*: the core logic already exists **twice**: a reference build and a performance-critical native port that's authoritative on device. Two independent implementations of the same rules make each one the other's oracle, which is what catches a "fixed one side, not the other" divergence. Wiring them into an automated gate is pre-launch work; the technique itself is built and runnable in [evals-differential-oracle](https://github.com/egnaro9/evals-differential-oracle).
- **Logic invariants**: core rules (e.g. *"checking one cell for a match always agrees with scanning the whole board"*) are enforced as **property-based tests over the native engine**, the implementation that's authoritative on device. 51 tests (16 of them property-based, over random inputs), device-free, one command, green as of the last run on 2026-08-06.
- **On-device validation**: adb-driven tests confirm behavior on real hardware, not just in a mock.

## The evidence trail: product changes leave proof
Speed only counts if you can show the work held. A closed product change leaves a durable, machine-checkable proof; harness-only and planning work is exempt:

- **NO-PROOF-NO-CLOSE.** Before a product work item closes, the closing role runs a check that its proof is on disk, and a stop hook objects when product files changed with no proof on record.
- **Provenance-bound proof.** On-device validation screenshots are sanitized (sensitive regions blacked out), and provenance manifests bind each image to the exact git SHA, screen dimensions, and redaction method that produced it, so an artifact traces back to the commit it proves.
- **Human-gated checkpoints.** Each checkpoint records scoped git staging (explicit paths only), a commit/SHA trail across the repos it touches, an artifact-registry audit, and an explicit operator approval.
- **Periodic self-eval.** An independent evaluation role scores the system's health with a delta versus the prior period and a failure taxonomy; regressions feed a failure registry that drives fixes.

## The autonomy ladder
Trust is earned in named levels, **L0 to L4**. The rule: higher levels remove *clicks* (auto-launching the safe steps), never *gates*.

```
L0 Manual → L1 Assisted → L2 Manager-driven handoffs (current) → L3 Auto-advance launches → L4 Lights-out
```

A human still approves anything irreversible or outward-facing. **Reliability earns launch-automation; it never earns gate-removal.**

## Safety gates
Every irreversible action (device deploys, git commits and pushes) waits for an explicit human approval phrase. The agent can't self-grant. The gates are *structural* (a deny-floor, a cold critic, device validation, an approval-gated checkpoint), not just good intentions.

## Operating record (spring to summer 2026)
From the on-disk archive: ~200 completed work-arcs · ~190 human-gated checkpoints · 74 independent cold-critic reviews · 13 periodic self-evaluations · a ~200-file sanitized proof archive with ~90 provenance manifests · a failure registry with per-item root-cause fixes.

## Verifiable outcomes (all public)
The same operator + harness, on public work you can check:
- An arcade game, **Tap Dodge Rush** under SeraphLight Studios, shipped end-to-end to [Google Play](https://play.google.com/store/apps/details?id=com.seraphlight.tapdodgerush).
- A one-character fix **merged upstream into TeaVM** (the Java-to-JavaScript compiler), closing a long-dormant issue.
- A **live public model-drift board** grading 17 models across 5 labs daily on a frozen, deterministically-graded suite: no LLM-as-judge, so the grader adds no noise of its own.
- Other public repos, including a [differential-oracle testing project](https://github.com/egnaro9/evals-differential-oracle) and a Model Context Protocol server built from the spec.

## What I take from it
- Evals and oracles are the hard, valuable part; getting a demo to work *once* is not the job.
- Cold, independent review beats a model grading its own homework.
- Autonomy is safe when the gates sit on the irreversible steps, not on the competence.
- Build to ship: the gates exist so speed doesn't cost you correctness.
