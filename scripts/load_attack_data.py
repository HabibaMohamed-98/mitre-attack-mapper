"""
Checkpoint 1a — Load the MITRE ATT&CK data and print a few techniques.

This is the very first piece of the RAG system. It does ONE thing:
prove that we can download and read MITRE ATT&CK's data on this machine.
No embeddings, no search, no LLM yet — those come in later checkpoints.

What's happening, step by step (read the comments — this is a learning project):

  1. Make sure we have the ATT&CK data file on disk (download it once if not).
  2. Load that file using MITRE's OWN official Python library
     (`mitreattack-python`), instead of hand-parsing the raw JSON ourselves.
  3. Ask the library for the list of "techniques" (attacker behaviours like
     "OS Credential Dumping").
  4. Print a handful of them so we can see real data in the terminal.

Run it from the project root with:

    ./venv/bin/python scripts/load_attack_data.py
"""

# --- Standard library imports (come with Python, nothing to install) ---
import urllib.request          # to download the data file over HTTPS
from pathlib import Path       # a nicer way to handle file paths than raw strings

# --- Third-party import: MITRE's official ATT&CK library (from requirements.txt) ---
# MitreAttackData is a helper class that loads a STIX file and gives us tidy
# methods like .get_techniques() so we don't have to understand STIX's internals.
from mitreattack.stix20 import MitreAttackData


# ---------------------------------------------------------------------------
# Configuration: where the data lives, and where we get it from.
# ---------------------------------------------------------------------------

# ATT&CK is published in three "domains". We want ENTERPRISE (Windows/Linux/mac/
# cloud attacks) as the CLAUDE.md brief specifies.
#
# STIX 2.1 is just the data format MITRE publishes in — think of it as a big,
# structured JSON catalog of everything in ATT&CK. This URL always points at
# the current published Enterprise file in MITRE's official data repository.
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# We keep the downloaded file under data/. The .gitignore ignores data/*.json
# because this file is large (~35 MB) and can always be re-downloaded.
#
# Path(__file__) is THIS script's location; ".parent.parent" walks up from
# scripts/ to the project root, so the path works no matter where we run it from.
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
STIX_FILE = DATA_DIR / "enterprise-attack.json"


def ensure_data_downloaded() -> Path:
    """
    Make sure the ATT&CK STIX file exists on disk. Download it once if missing.

    Returns the path to the local file.
    """
    # Create the data/ folder if it isn't there yet (safe to call every time).
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Only download if we don't already have the file — no need to re-fetch
    # ~35 MB every run.
    if STIX_FILE.exists():
        print(f"[ok] ATT&CK data already present: {STIX_FILE}")
        return STIX_FILE

    print(f"[..] Downloading ATT&CK Enterprise STIX data (~50 MB, one time)...")
    print(f"     from: {STIX_URL}")

    # Download to a temporary ".part" file first and rename it only once the
    # download is complete. If the connection drops halfway, no half-finished
    # file is left under the real name (which the check above would otherwise
    # mistake for a finished download next time).
    partial = STIX_FILE.with_name(STIX_FILE.name + ".part")
    try:
        urllib.request.urlretrieve(STIX_URL, partial)
        partial.replace(STIX_FILE)
    finally:
        partial.unlink(missing_ok=True)

    print(f"[ok] Saved to: {STIX_FILE}")
    return STIX_FILE


def first_line(text: str) -> str:
    """
    Return just the first line of a (possibly multi-paragraph) description.

    ATT&CK descriptions can be long and full of citations; for this sanity
    check we only want a short taste, so we grab the first line and trim it.
    """
    if not text:
        return "(no description)"
    # Split on the first newline and take what's before it, then strip whitespace.
    return text.strip().splitlines()[0].strip()


def main() -> None:
    # Step 1 + 2: make sure the file is here, then hand it to MITRE's loader.
    stix_path = ensure_data_downloaded()

    print("\n[..] Loading the STIX data with mitreattack-python...")
    # This parses the whole catalog into memory. Takes a few seconds.
    attack = MitreAttackData(str(stix_path))

    # Step 3: ask the library for all techniques.
    #
    # remove_revoked_deprecated=True filters out techniques MITRE has retired or
    # replaced, so we only see ones that are currently "live". We'll want the
    # same filter later when we build the searchable library.
    techniques = attack.get_techniques(remove_revoked_deprecated=True)
    print(f"[ok] Loaded {len(techniques)} active techniques.\n")

    # Step 4: print the first few so we can SEE real data.
    print("=" * 70)
    print("A few MITRE ATT&CK techniques (ID — name — first line of description):")
    print("=" * 70)

    # Show the first 8 techniques. Each `tech` is a STIX object; we pull out the
    # human-friendly fields we care about.
    for tech in techniques[:8]:
        # The ATT&CK ID (like "T1003") isn't a top-level field in STIX — it lives
        # in the object's "external_references" list, tagged as the mitre-attack
        # source. MITRE's library gives us a helper for exactly this.
        attack_id = attack.get_attack_id(tech.id)

        # These fields ARE top-level on the STIX object, so we can read them directly.
        name = tech.name
        description_line = first_line(tech.get("description", ""))

        print(f"\n  {attack_id}  —  {name}")
        print(f"      {description_line}")

    print("\n" + "=" * 70)
    print("Success — we can read MITRE ATT&CK data. Checkpoint 1a done.")
    print("=" * 70)


# This guard means main() only runs when we execute the file directly
# (not if something later imports it as a module).
if __name__ == "__main__":
    main()
