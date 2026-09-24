"""
attack_data.py — extract clean technique records from the ATT&CK STIX data.

This module is the "extract" half of Phase A. It does NOT embed or index
anything (that's vector_store.py) — it only turns MITRE's raw STIX catalog
into simple Python dictionaries that the rest of the system can use.

For each Enterprise technique AND sub-technique we pull out:
  - attack_id     e.g. "T1003" or "T1055.011"   (the human-facing ID)
  - name          e.g. "OS Credential Dumping"
  - description   the full prose description
  - tactics       e.g. ["Credential Access"]     (the "why" / attacker goal)
  - is_subtechnique  True/False
  - mitigations   e.g. [{"id": "M1040", "name": "Behavior Prevention..."}]

Why a module (not a script): extraction is a reusable step. The index builder
imports `extract_techniques()`; a future eval or API can too. Keeping it pure
(data in → data out, no printing, no files) makes it easy to test.

STIX background (just enough to follow the code):
  - A "technique" is a STIX object of type `attack-pattern`.
  - Its ATT&CK ID (T1003) lives inside `external_references`, not as a plain
    field — so we ask MITRE's library for it via `get_attack_id()`.
  - Tactics are stored as `kill_chain_phases` and resolved to friendly names.
  - Mitigations are SEPARATE objects (`course-of-action`) connected to the
    technique by a "mitigates" RELATIONSHIP. We follow that relationship rather
    than guessing — this is the "follow the STIX relationships" the brief asks for.
"""

from pathlib import Path
from typing import Optional, TypedDict

from mitreattack.stix20 import MitreAttackData


# Default location of the STIX file (downloaded in Checkpoint 1a).
# Path(__file__).parent.parent walks from src/ up to the project root.
PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_STIX_FILE = PROJECT_ROOT / "data" / "enterprise-attack.json"


# TypedDict just documents the shape of the dictionaries we return. It behaves
# like a normal dict at runtime but tells readers (and editors) what keys exist.
class Mitigation(TypedDict):
    id: str      # ATT&CK mitigation ID, e.g. "M1040"
    name: str    # e.g. "Behavior Prevention on Endpoint"


class Technique(TypedDict):
    attack_id: str
    name: str
    description: str
    tactics: list[str]
    is_subtechnique: bool
    mitigations: list[Mitigation]


def load_attack(stix_file: Optional[Path] = None) -> MitreAttackData:
    """
    Open the STIX file with MITRE's official loader and return the handle.

    Kept as its own function so callers that want the raw MitreAttackData object
    (for relationships we haven't wrapped yet) can reuse it.
    """
    path = stix_file or DEFAULT_STIX_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"ATT&CK STIX file not found at {path}. "
            "Run scripts/load_attack_data.py first to download it."
        )
    return MitreAttackData(str(path))


def _extract_tactics(attack: MitreAttackData, technique) -> list[str]:
    """
    Return the friendly tactic names for a technique, e.g. ["Credential Access"].

    A technique can belong to several tactics (its "kill chain phases").
    """
    tactics = attack.get_tactics_by_technique(technique.id)
    # Each tactic object has a `name` like "Credential Access".
    return [t["name"] for t in tactics]


def _extract_mitigations(attack: MitreAttackData, technique) -> list[Mitigation]:
    """
    Follow the "mitigates" relationships to list this technique's mitigations.

    get_mitigations_mitigating_technique() returns a list of {"object": ...}
    entries, where `object` is the mitigation (a STIX course-of-action).
    """
    results: list[Mitigation] = []
    for entry in attack.get_mitigations_mitigating_technique(technique.id):
        mitigation_obj = entry["object"]
        results.append(
            {
                "id": attack.get_attack_id(mitigation_obj.id),  # e.g. "M1040"
                "name": mitigation_obj.name,
            }
        )
    return results


def extract_techniques(stix_file: Optional[Path] = None) -> list[Technique]:
    """
    Extract every active Enterprise technique + sub-technique as clean records.

    `remove_revoked_deprecated=True` drops techniques MITRE has retired or
    replaced, so we only index ones that are currently valid.
    """
    attack = load_attack(stix_file)
    raw_techniques = attack.get_techniques(remove_revoked_deprecated=True)

    techniques: list[Technique] = []
    for tech in raw_techniques:
        techniques.append(
            {
                "attack_id": attack.get_attack_id(tech.id),
                "name": tech.name,
                "description": tech.get("description", "") or "",
                "tactics": _extract_tactics(attack, tech),
                # STIX marks sub-techniques with x_mitre_is_subtechnique=True.
                "is_subtechnique": bool(
                    tech.get("x_mitre_is_subtechnique", False)
                ),
                "mitigations": _extract_mitigations(attack, tech),
            }
        )

    return techniques


def revoked_replacements(stix_file: Optional[Path] = None) -> dict[str, str]:
    """
    Map each REVOKED technique ID to the ID MITRE replaced it with.

    ATT&CK evolves: MITRE sometimes retires a technique and moves it under a new
    ID, recording that with a "revoked-by" relationship. E.g. in the current
    release T1070.001 (Clear Windows Event Logs) is revoked by T1685.005. Labels
    written against an older ATT&CK version still use the old ID, so the eval
    uses this map to also accept the official replacement. We only follow what
    MITRE's own data says — no hand-written equivalences.
    """
    attack = load_attack(stix_file)
    replacements: dict[str, str] = {}
    for tech in attack.get_techniques(remove_revoked_deprecated=False):
        if not tech.get("revoked", False):
            continue
        new_obj = attack.get_revoking_object(tech.id)
        if new_obj is not None:
            replacements[attack.get_attack_id(tech.id)] = attack.get_attack_id(new_obj.id)
    return replacements


# Allow a quick manual check: `./venv/bin/python -m src.attack_data`
if __name__ == "__main__":
    items = extract_techniques()
    print(f"Extracted {len(items)} techniques.")
    sample = items[0]
    print("\nExample record:")
    for key, value in sample.items():
        print(f"  {key}: {value}")
