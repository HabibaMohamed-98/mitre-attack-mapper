"""
answer_parser.py — turn the LLM's text answer into structured data.

The LLM writes its answer as text, in the format the prompt asks for:

    Technique: T1003.001 LSASS Memory
    Evidence: "mimi.exe ... TargetImage=lsass.exe"
    Mitigation: M1043 Credential Access Protection — how it helps

The API returns JSON, so this module splits that text into a list of
{technique_id, technique_name, evidence, mitigation_id, mitigation} records.
It tolerates the small format variations models produce (markdown bold like
"**Technique:**", backticks, extra spaces).

It also CHECKS THE GROUNDING RULE after the fact: every technique ID the LLM
names must be one of the candidates it was shown, and its mitigation must be one
listed for that technique. The prompt already demands this; the check makes any
slip visible instead of silently trusting the model.

Pure text in -> data out: no models, no network. Easy to test on its own.
"""

import re

_LABEL = re.compile(r"^[\s*_`>-]*(technique|evidence|mitigation)[\s*_`]*:[\s*_`]*(.*)$", re.IGNORECASE)
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_MITIGATION_ID = re.compile(r"\bM\d{4}\b")


def _clean(value: str) -> str:
    """Strip leftover markdown (bold markers, backticks) and surrounding quotes."""
    value = value.strip().strip("*_` ").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.strip()


def parse_answer(answer: str, candidates: list[dict]) -> list[dict]:
    """
    Split the LLM's answer into one record per technique it chose.

    `candidates` are the technique records the LLM was shown (each has attack_id
    and mitigations like "M1043: Credential Access Protection"); they're used to
    check grounding. Returns [] when the LLM said nothing fits.
    """
    shown = {c["attack_id"]: c for c in candidates}
    results: list[dict] = []
    current: dict | None = None

    for line in answer.splitlines():
        match = _LABEL.match(line)
        if not match:
            continue
        label, value = match.group(1).lower(), _clean(match.group(2))

        if label == "technique":
            technique_id = _TECHNIQUE_ID.search(value)
            if not technique_id:        # e.g. "Technique: None — nothing fits"
                current = None
                continue
            tid = technique_id.group(0)
            name = _clean(value[technique_id.end():].lstrip(" —-:"))
            current = {
                "technique_id": tid,
                "technique_name": name or shown.get(tid, {}).get("name", ""),
                "evidence": "",
                "mitigation_id": "",
                "mitigation": "",
                # Grounding check: was this ID actually among the options shown?
                "grounded": tid in shown,
                # Set once a mitigation with an M-ID is seen (None = no M-ID given).
                "mitigation_grounded": None,
            }
            results.append(current)
        elif current is not None and label == "evidence":
            current["evidence"] = value
        elif current is not None and label == "mitigation":
            current["mitigation"] = value
            mitigation_id = _MITIGATION_ID.search(value)
            if mitigation_id:
                current["mitigation_id"] = mitigation_id.group(0)
                allowed = shown.get(current["technique_id"], {}).get("mitigations", [])
                # Grounding check: is it one of this technique's real mitigations?
                current["mitigation_grounded"] = any(
                    m.startswith(mitigation_id.group(0)) for m in allowed
                )

    return results
