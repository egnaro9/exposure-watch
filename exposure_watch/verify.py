"""Deterministic checks on an agent's answer. No model is involved here.

An agent answer is a verdict plus claims. Each claim names one source document
and quotes it. The verifier keeps a claim only if its quote is, character for
character after whitespace is collapsed, a substring of the document it names.
A verdict other than "unknown" with no surviving claim is unsupported, and an
unsupported verdict never reaches a person as an answer.

This catches fabricated and misattributed evidence. It cannot catch a verdict
that is wrong but cites real text: a correct quote attached to the wrong
conclusion passes every check here. That gap is the skeptic's job, and the
planted-error suite in eval/ measures both halves separately.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

VERDICTS = ("affected", "not_affected", "conditional", "unknown")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


def _norm(s: str) -> str:
    return " ".join(s.split())


@dataclass
class Checked:
    verdict: str
    kept: List[dict] = field(default_factory=list)
    dropped: List[dict] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)

    @property
    def supported(self) -> bool:
        return self.verdict == "unknown" or bool(self.kept)


def check(answer: dict, cve: str, sources: Dict[str, str]) -> Checked:
    verdict = answer.get("verdict")
    out = Checked(verdict=verdict if verdict in VERDICTS else "unknown")
    if verdict not in VERDICTS:
        out.problems.append(f"verdict {verdict!r} is not one of {VERDICTS}")
    if answer.get("cve") != cve:
        out.problems.append(f"answer is about {answer.get('cve')!r}, not {cve}")
    for claim in answer.get("claims", []):
        src, quote = claim.get("source"), _norm(claim.get("quote", ""))
        reason = None
        if src not in sources:
            reason = f"cites unknown source {src!r}"
        elif len(quote) < 8:
            reason = "quote too short to check"
        elif quote not in _norm(sources[src]):
            reason = f"quote not found in {src}"
        else:
            others = set(CVE_ID.findall(claim.get("text", ""))) - {cve}
            if others - set(CVE_ID.findall(" ".join(sources.values()))):
                reason = f"names a CVE absent from every source: {sorted(others)}"
        (out.dropped if reason else out.kept).append({**claim, **({"reason": reason} if reason else {})})
    if not out.supported:
        out.problems.append("no claim survived, so the verdict is unsupported")
    return out
