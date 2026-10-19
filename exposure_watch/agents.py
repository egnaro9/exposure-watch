"""The two agent roles and the backends that run them.

Roles. The triage agent reads one inventory item, one CVE, and three source
documents, and answers with a verdict and quoted claims. The skeptic reads the
same documents plus the triage answer and tries to refute it. Neither has
tools, web access, or anything but the text it is handed.

Backends. ClaudeCLI runs each call through the Claude Code command line, so a
run needs a signed-in `claude`, not an API key. Recorded replays saved answers,
so anyone can re-score a run, and CI runs, without calling a model. Every live
call is saved with its cost, latency and model, which is what the shapes are
compared on.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional

from .data import Item

ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "cve": {"type": "string"},
        "verdict": {"type": "string", "enum": ["affected", "not_affected", "conditional", "unknown"]},
        "claims": {"type": "array", "items": {"type": "object", "properties": {
            "text": {"type": "string"},
            "source": {"type": "string", "enum": ["kev", "nvd_description", "nvd_config"]},
            "quote": {"type": "string"},
        }, "required": ["text", "source", "quote"]}},
    },
    "required": ["cve", "verdict", "claims"],
}

SKEPTIC_SCHEMA = {
    "type": "object",
    "properties": {
        "agree": {"type": "boolean"},
        "verdict": {"type": "string", "enum": ["affected", "not_affected", "conditional", "unknown"]},
        "reason": {"type": "string"},
        "source": {"type": "string", "enum": ["kev", "nvd_description", "nvd_config"]},
        "quote": {"type": "string"},
    },
    "required": ["agree", "verdict", "reason", "source", "quote"],
}

TRIAGE_SYSTEM = (
    "You decide whether one installed software item is exposed to one known-exploited "
    "vulnerability. Use only the three documents provided; you have no other knowledge "
    "of this software. Verdicts: affected (the installed version is in an affected range "
    "or list), not_affected (it is not), conditional (the version is affected but exposure "
    "depends on a feature or configuration the inventory does not record), unknown (the "
    "documents do not settle it). Every claim must quote a passage copied exactly from the "
    "named document. Do not paraphrase inside a quote."
)

SKEPTIC_SYSTEM = (
    "You review another analyst's exposure verdict. Your job is to find the strongest reason "
    "it is wrong, using only the documents provided. Agree only if the documents support the "
    "verdict and no other verdict fits better. Quote the single passage that decides it, "
    "copied exactly from the named document."
)


def triage_prompt(item: Item, cve: str, sources: Dict[str, str]) -> str:
    return (f"Inventory item {item.id}: {item.vendor} {item.product}, version as recorded by "
            f"the administrator: {item.version!r} (deployed as {item.where}).\n"
            f"Vulnerability: {cve}\n\n" + _docs(sources))


def skeptic_prompt(item: Item, cve: str, sources: Dict[str, str], answer: dict) -> str:
    return triage_prompt(item, cve, sources) + "\n\nANALYST ANSWER TO REVIEW:\n" + json.dumps(answer, indent=1)


def _docs(sources: Dict[str, str]) -> str:
    return "\n\n".join(f"=== DOCUMENT {k} ===\n{v}" for k, v in sources.items())


class ClaudeCLI:
    """One `claude -p` call per answer: no tools, no MCP, no saved session."""

    def __init__(self, model: str):
        self.model = model

    def ask(self, system: str, prompt: str, schema: dict) -> dict:
        cmd = ["claude", "-p", "--tools", "", "--strict-mcp-config", "--no-session-persistence",
               "--disable-slash-commands", "--system-prompt", system, "--model", self.model,
               "--output-format", "json", "--json-schema", json.dumps(schema)]
        t0 = time.time()
        p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=600)
        try:
            meta = json.loads(p.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(f"claude exited {p.returncode} without JSON: {p.stderr.strip()[:200]}")
        if meta.get("is_error"):
            raise RuntimeError(f"claude call failed: {str(meta.get('result'))[:200]}")
        if meta.get("structured_output") is None:
            raise RuntimeError(f"no structured answer returned: {str(meta.get('result'))[:200]}")
        return {"answer": meta["structured_output"],
                "cost_usd": meta.get("total_cost_usd"),
                "latency_s": round(time.time() - t0, 2),
                "requested_model": self.model,
                "model": next(iter(meta.get("modelUsage") or {}), self.model)}


class Recorded:
    """Replays answers saved by a live run. Missing keys fail loudly."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir

    def load(self, key: str) -> dict:
        p = self.run_dir / f"{key}.json"
        if not p.exists():
            raise FileNotFoundError(f"no recorded answer {p}: re-run live, do not substitute")
        return json.loads(p.read_text(encoding="utf-8"))


def fetch(backend: Optional[ClaudeCLI], run_dir: Path, key: str,
          system: str, prompt: str, schema: dict) -> dict:
    """A saved answer if this run already has one, else a live call that is saved.

    Without a backend this is a pure replay. With one, a rerun after a failure
    pays only for the calls that are missing. A saved answer is never reused
    for a different model or, when it records one, a different prompt.
    """
    asked = hashlib.sha256(json.dumps([system, prompt, schema], sort_keys=True).encode()).hexdigest()
    if (run_dir / f"{key}.json").exists():
        rec = Recorded(run_dir).load(key)
        if backend and rec.get("requested_model") != backend.model:
            raise RuntimeError(f"{run_dir}/{key}.json was answered by {rec.get('requested_model')!r}, "
                               f"not {backend.model!r}: use a fresh --run directory")
        if "prompt_sha256" in rec and rec["prompt_sha256"] != asked:
            raise RuntimeError(f"{run_dir}/{key}.json answers a different question than the one "
                               f"asked now: use a fresh --run directory")
        return rec
    if backend is None:
        return Recorded(run_dir).load(key)
    rec = {**backend.ask(system, prompt, schema), "prompt_sha256": asked}
    save(run_dir, key, rec)
    return rec


def save(run_dir: Path, key: str, record: dict) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / f"{key}.json").write_text(json.dumps(record, indent=1), encoding="utf-8")
