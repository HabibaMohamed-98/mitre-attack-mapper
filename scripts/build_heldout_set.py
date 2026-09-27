"""
build_heldout_set.py — build a HELD-OUT test set from Atomic Red Team.

Why: sample_logs.json guided our design choices, so scores on it are optimistic.
To measure honestly we need labelled inputs the system (and its designers) have
never been tuned on. Atomic Red Team (Red Canary, MIT licensed) publishes attack
tests filed under the exact ATT&CK technique each one exercises — expert labels,
written independently of this project.

What this script does:
  1. Reads data/external/atomic_index.yaml (download it first; see below).
  2. Keeps tests that run a real command (cmd / PowerShell / sh / bash).
  3. Picks ONE test per technique, at random with a fixed seed — no hand-picking,
     and no single technique dominating the score.
  4. Turns each test's command into a process-creation log line, e.g.
       Process creation: Image=C:\\...\\powershell.exe CommandLine=<command>
     because the command line is exactly what process telemetry (Sysmon Event 1 /
     Windows 4688) records.
  5. SCRUBS LABEL LEAKS: Atomic commands often reference their own folder, e.g.
     "PathToAtomicsFolder\\T1003.001\\bin\\...". Left in, keyword search would find
     the answer by matching the ID string. Every technique ID and the Atomic folder
     name are removed from the input.
  6. Drops techniques MITRE has retired without a replacement (nobody could get
     those "right" against the current ATT&CK data).
  7. Writes data/heldout_atomic.json (same format as sample_logs.json; gitignored,
     and fully reproducible from the source file's checksum + the seed).

Download the source (6.6 MB) first:
  curl -L -o data/external/atomic_index.yaml \\
    https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml

Run:
  ./venv/bin/python scripts/build_heldout_set.py                       # seed-42 set
  # A NEW, non-overlapping set: different seed + skip tests other sets already used
  ./venv/bin/python scripts/build_heldout_set.py --seed 7 --out data/dev_atomic.json \
      --exclude data/heldout_atomic.json

Limitation (honest): the input is a command line, not a full event — real logs
also carry parent process, user, host, etc. So this measures "can the system map
the command an attacker ran", which is the core signal in process telemetry.
"""

import hashlib
import json
import random
import re
import sys
from datetime import date
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.attack_data import load_attack, revoked_replacements   # noqa: E402

PROJECT_ROOT = Path(__file__).parent.parent
SOURCE_FILE = PROJECT_ROOT / "data" / "external" / "atomic_index.yaml"
OUTPUT_FILE = PROJECT_ROOT / "data" / "heldout_atomic.json"

DEFAULT_SEED = 42         # fixed, so the same sample is drawn every time
MAX_COMMAND_CHARS = 600   # keep inputs log-line sized (and LLM prompts small)

# The process image a log would show for each Atomic executor type.
EXECUTOR_IMAGES = {
    "command_prompt": r"C:\Windows\System32\cmd.exe",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "sh": "/bin/sh",
    "bash": "/bin/bash",
}

# No trailing word boundary on purpose: IDs inside file names ("T1003.001_out.txt",
# "T1059-test.ps1") must be caught too.
_TECHNIQUE_ID = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def technique_id_of(technique: dict) -> str | None:
    """Pull the ATT&CK ID (e.g. 'T1003.001') out of the technique's references."""
    for ref in technique.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def fill_arguments(command: str, input_arguments: dict | None) -> str:
    """Replace Atomic placeholders like #{output_file} with their default values."""
    for name, spec in (input_arguments or {}).items():
        default = str((spec or {}).get("default", ""))
        command = command.replace("#{" + name + "}", default)
    return command


def scrub(command: str) -> str:
    """Remove label leaks and tidy the command into one log-sized line."""
    command = re.sub(r"\$?PathToAtomicsFolder", "C:\\tools", command, flags=re.IGNORECASE)
    command = re.sub(r"atomic[-_ ]?red[-_ ]?team", "tools", command, flags=re.IGNORECASE)
    command = re.sub(r"atomic", "test", command, flags=re.IGNORECASE)   # e.g. "AtomicTest.txt"
    command = _TECHNIQUE_ID.sub("x", command)                 # no ATT&CK IDs in the input
    command = re.sub(r"\s*\n\s*", " ; ", command.strip())      # multi-line -> one line
    command = re.sub(r"[ \t]+", " ", command)
    if len(command) > MAX_COMMAND_CHARS:
        command = command[:MAX_COMMAND_CHARS].rstrip() + " ..."
    return command


def _arg(flag: str) -> list[str]:
    """All values given for a repeatable flag, e.g. --exclude a.json --exclude b.json."""
    return [sys.argv[i + 1] for i, a in enumerate(sys.argv[:-1]) if a == flag]


def used_test_ids(paths: list[str]) -> set[str]:
    """
    The Atomic test IDs already used by other sets. Excluding them is what keeps a
    new set genuinely unseen: 91 techniques have only ONE usable test, so a new
    random seed alone would re-draw the exact same command for those.
    """
    used: set[str] = set()
    for path in paths:
        for s in json.loads(Path(path).read_text())["samples"]:
            used.add(s.get("atomic_guid") or s["id"].removeprefix("art-"))
    return used


def main() -> None:
    seed = int((_arg("--seed") or [DEFAULT_SEED])[0])
    output_file = PROJECT_ROOT / (_arg("--out") or [str(OUTPUT_FILE.relative_to(PROJECT_ROOT))])[0]
    excluded = used_test_ids(_arg("--exclude"))

    if not SOURCE_FILE.exists():
        sys.exit(f"Missing {SOURCE_FILE}. Download it first (see this script's docstring).")

    raw = SOURCE_FILE.read_bytes()
    source_sha256 = hashlib.sha256(raw).hexdigest()
    index = yaml.safe_load(raw)

    # Which technique IDs can our system possibly answer? Active ones, plus revoked
    # ones MITRE replaced (the eval accepts the replacement).
    attack = load_attack()
    active = {attack.get_attack_id(t.id) for t in attack.get_techniques(remove_revoked_deprecated=True)}
    replaced = revoked_replacements()

    # Collect usable tests per technique. The index files each technique under every
    # tactic it belongs to, so de-duplicate by technique ID.
    tests_by_technique: dict[str, tuple[str, list[dict]]] = {}
    for tactic_techniques in index.values():
        for entry in tactic_techniques.values():
            tech_id = technique_id_of(entry["technique"])
            if not tech_id or tech_id in tests_by_technique:
                continue
            usable = [
                t for t in entry.get("atomic_tests", [])
                if t.get("executor", {}).get("name") in EXECUTOR_IMAGES
                and (t["executor"].get("command") or "").strip()
                # skip tests another set already used (full GUID, or the 8-char
                # prefix older sets stored in their "id")
                and t.get("auto_generated_guid", "") not in excluded
                and t.get("auto_generated_guid", "")[:8] not in excluded
            ]
            if usable:
                tests_by_technique[tech_id] = (entry["technique"].get("name", ""), usable)

    rng = random.Random(seed)
    samples = []
    dropped_retired = 0
    for tech_id in sorted(tests_by_technique):              # sorted -> deterministic
        name, tests = tests_by_technique[tech_id]
        if tech_id not in active and tech_id not in replaced:
            dropped_retired += 1
            continue
        test = rng.choice(tests)
        command = scrub(fill_arguments(test["executor"]["command"], test.get("input_arguments")))
        image = EXECUTOR_IMAGES[test["executor"]["name"]]
        samples.append({
            "id": f"art-{test.get('auto_generated_guid', '')[:8]}",
            "log": f"Process creation: Image={image} CommandLine={command}",
            "atomic_guid": test.get("auto_generated_guid", ""),
            "expected_technique_id": tech_id,
            "expected_technique_name": name,
            "difficulty": "unknown",
            "note": f"Atomic Red Team test: {test.get('name', '')}",
        })

    rng.shuffle(samples)  # so `--limit N` in the eval takes a random, unbiased subset

    output_file.write_text(json.dumps({
        "about": {
            "what": "Held-out test set built from Atomic Red Team (MIT licensed). One "
                    "randomly chosen command-line test per ATT&CK technique, turned "
                    "into a process-creation log line, technique IDs scrubbed.",
            "source": "https://github.com/redcanaryco/atomic-red-team (atomics/Indexes/index.yaml)",
            "source_sha256": source_sha256,
            "seed": seed,
            "excluded_sets": _arg("--exclude"),
            "built_on": date.today().isoformat(),
            "rule": "Do not tune the pipeline on this set. If you do, draw a new one "
                    "with a different seed and treat this one as seen.",
        },
        "samples": samples,
    }, indent=2))

    print(f"Techniques with usable command tests : {len(tests_by_technique)}")
    print(f"Dropped (retired, no replacement)    : {dropped_retired}")
    print(f"Tests excluded (used by other sets)  : {len(excluded)}")
    print(f"Samples written                      : {len(samples)} -> {output_file.relative_to(PROJECT_ROOT)}")
    print(f"Source sha256                        : {source_sha256[:16]}...  seed={seed}")


if __name__ == "__main__":
    main()
