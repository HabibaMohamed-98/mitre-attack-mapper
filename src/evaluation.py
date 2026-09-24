"""
evaluation.py — small, pure helpers for scoring the pipeline against known labels.

The whole point of evaluation here is to answer "how good is the system, really?"
using logs whose CORRECT technique we already know (sample_logs.json). And to do
it in the way CLAUDE.md insists on: measure RETRIEVAL and GENERATION SEPARATELY,
so when an answer is wrong we know which half to fix.

This module is just the scoring logic (strings in -> verdicts out). It does no
searching and no LLM calls — that lives in scripts/evaluate.py — so these
functions are trivial to reason about and test.

Two ideas we score with:
  - EXACT match: predicted ID == expected ID (e.g. T1003.001 == T1003.001).
  - FAMILY match: same base technique, ignoring the sub-technique (e.g. T1053
    "counts" for T1053.005). ATT&CK sub-techniques are variants of a parent, so a
    family match is "right area, wrong specific variant" — worth tracking, but
    weaker than an exact hit.
"""

import re

# ATT&CK technique IDs look like T1003 or T1003.001. This finds them in free text.
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def family(technique_id: str) -> str:
    """Return the parent technique id: 'T1053.005' -> 'T1053', 'T1055' -> 'T1055'."""
    return technique_id.split(".", 1)[0]


def extract_predicted_ids(answer: str) -> list[str]:
    """
    Pull the technique IDs the LLM actually chose out of its free-text answer.

    Our prompt asks the model to write lines like "Technique: T1003.001 LSASS
    Memory". We first look for IDs on those "Technique:" lines (the model's real
    picks). If we find none that way, we fall back to any T-code in the text.
    Order is preserved and duplicates removed, so the FIRST id is the model's
    primary answer.
    """
    picks: list[str] = []
    saw_technique_line = False
    for line in answer.splitlines():
        # Only trust the ID the model put RIGHT AFTER "Technique:" — that's its
        # label. IDs later on the line (or elsewhere) are explanation, not picks.
        # The `\**` bits tolerate markdown bold like "**Technique:**".
        if re.match(r"\s*\**\s*technique\s*\**\s*:", line, flags=re.IGNORECASE):
            saw_technique_line = True
            label = re.match(
                r"\s*\**\s*technique\s*\**\s*:\s*\**\s*(T\d{4}(?:\.\d{3})?)\b",
                line,
                flags=re.IGNORECASE,
            )
            if label:
                picks.append(label.group(1))

    if not saw_technique_line:
        # Fallback ONLY when the model ignored our format entirely. If it DID write
        # a "Technique:" line with no ID (e.g. "Technique: None — no candidate
        # fits"), that's a deliberate "no match" and must stay empty — otherwise
        # IDs it mentions while explaining WHY nothing fits would be miscounted
        # as picks (and the benign log would look like a false positive).
        picks = _TECHNIQUE_ID.findall(answer)

    # De-duplicate while preserving order (first pick stays first).
    seen: set[str] = set()
    ordered: list[str] = []
    for pid in picks:
        if pid not in seen:
            seen.add(pid)
            ordered.append(pid)
    return ordered


def is_exact_hit(expected_id: str, predicted_ids: list[str]) -> bool:
    """True if the exact expected ID is among the predictions."""
    return expected_id in predicted_ids


def is_family_hit(expected_id: str, predicted_ids: list[str]) -> bool:
    """True if any prediction is in the same technique family as expected."""
    want = family(expected_id)
    return any(family(pid) == want for pid in predicted_ids)
