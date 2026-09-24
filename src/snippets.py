"""
snippets.py — turn a technique record into ONE clean text snippet to search over.

Why snippets: our embedding model and keyword search work on *text*. So for
each technique we stitch its most identifying fields into a single, tidy string.
That string is what gets embedded (for semantic search) and indexed for keyword
search. The ATT&CK ID is ALSO kept separately as metadata so we can always point
back to the exact technique — we never rely on parsing it out of the text.

We deliberately include:
  - the ATT&CK ID (so exact-ID keyword searches like "T1003" hit)
  - the name (short, high-signal)
  - the tactic(s) (the attacker's goal — good semantic context)
  - the description (the bulk of the meaning)

We deliberately DO NOT stuff mitigations into the search text: we search to find
the right technique, and only THEN show its mitigations. Mixing mitigation prose
in would blur what each snippet is "about". Mitigations still travel alongside as
metadata.

This module is pure text-shaping: a technique dict in → a string (and a metadata
dict) out. No models, no files — trivially testable.
"""

import re

from src.attack_data import Technique


def clean_description(text: str) -> str:
    """
    Strip formatting noise out of an ATT&CK description, keeping the meaning.

    MITRE's descriptions are written for the website, so they're full of:
      - citation markers:  "(Citation: Talos Olympic Destroyer 2018)"  (~93% of them)
      - markdown links:    "[Data Destruction](https://attack.mitre.org/techniques/T1485)"
      - HTML code tags:    "<code>C:\\Windows\\System32\\sethc.exe</code>"
    None of that describes attacker behaviour, but search still "reads" it: every
    citation adds the same filler words to hundreds of snippets, and long Windows
    paths make techniques that happen to quote paths match every log that has paths.

    We keep the useful part of each: the link's visible text ("Data Destruction")
    and the file NAME from a path ("sethc.exe") — only the noise goes.
    """
    text = re.sub(r"\(Citation:[^)]*\)", "", text)                 # drop citations
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)            # [text](url) -> text
    text = re.sub(r"</?code>", "", text)                             # drop <code> tags
    # File paths -> file name (C:\a\b\x.exe -> x.exe). The drive letter is REQUIRED
    # so registry paths (HKLM\...\CurrentVersion\Run) keep their meaningful keys.
    text = re.sub(r"\b[A-Za-z]:(?:\\[\w .$-]+)*\\([\w.-]+)", r"\1", text)
    text = re.sub(r"[ \t]+", " ", text)                              # tidy spaces
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def build_snippet(technique: Technique) -> str:
    """
    Build the single searchable text string for one technique.

    Example output:
        "T1003 | OS Credential Dumping | Tactic: Credential Access
         Adversaries may attempt to dump credentials ..."
    """
    # Join multiple tactics with commas; fall back to a clear placeholder.
    tactics = ", ".join(technique["tactics"]) or "Unknown"

    # A compact, readable header line followed by the CLEANED description.
    header = f"{technique['attack_id']} | {technique['name']} | Tactic: {tactics}"
    return f"{header}\n{clean_description(technique['description'])}".strip()


def build_record(technique: Technique) -> dict:
    """
    Build the full record we hand to the store: the snippet text PLUS metadata.

    Keeping metadata (id, name, tactics, mitigations) next to the text means a
    search hit can immediately report the real ID, name, and grounded
    mitigations — without re-parsing anything out of the snippet.

    Mitigations are flattened to strings ("M1040: Behavior Prevention...") because
    the store column is a simple list of strings; the structured form still lives
    in attack_data if we need it.
    """
    return {
        "attack_id": technique["attack_id"],
        "name": technique["name"],
        "tactics": technique["tactics"],
        "is_subtechnique": technique["is_subtechnique"],
        "mitigations": [
            f"{m['id']}: {m['name']}" for m in technique["mitigations"]
        ],
        "text": build_snippet(technique),
    }


# Quick manual check: `./venv/bin/python -m src.snippets`
if __name__ == "__main__":
    from src.attack_data import extract_techniques

    first = extract_techniques()[0]
    print("Snippet:\n")
    print(build_snippet(first))
    print("\nFull record keys:", list(build_record(first).keys()))
