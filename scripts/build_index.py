"""
build_index.py — the repeatable "build the searchable library" command.

This wires the Phase A pieces together, in order:

    extract techniques  ->  build snippets  ->  embed  ->  index (LanceDB)

Run it whenever you want to (re)build the index from scratch:

    ./venv/bin/python scripts/build_index.py

It's idempotent: running it again overwrites the old index rather than
duplicating it. When it finishes it prints how many techniques were indexed.
"""

# Make sure we can import the `src` package when running this file directly.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.attack_data import extract_techniques        # noqa: E402
from src.snippets import build_record                  # noqa: E402
from src.embedder import Embedder, MODEL_NAME          # noqa: E402
from src.vector_store import build_index               # noqa: E402


def main() -> None:
    # Step 1 — EXTRACT: read STIX, get clean technique records.
    print("[1/4] Extracting techniques from ATT&CK STIX data...")
    techniques = extract_techniques()
    print(f"      -> {len(techniques)} techniques (incl. sub-techniques).")

    # Step 2 — SNIPPETS: turn each technique into searchable text + metadata.
    print("[2/4] Building one clean text snippet per technique...")
    records = [build_record(t) for t in techniques]

    # Step 3 — EMBED: turn each snippet's text into a vector (local model).
    print(f"[3/4] Embedding snippets locally with {MODEL_NAME} ...")
    print("      (first run downloads the ~80 MB model; this can take a minute)")
    embedder = Embedder()
    texts = [r["text"] for r in records]
    vectors = embedder.embed(texts, show_progress=True)

    # Step 4 — INDEX: write records + vectors into the hybrid-search store.
    print("[4/4] Writing records + vectors into the LanceDB index...")
    count = build_index(records, vectors)

    print("\n" + "=" * 60)
    print(f"Index built successfully: {count} techniques indexed.")
    print("Try a manual search:  ./venv/bin/python scripts/search.py \"dumped LSASS memory for passwords\"")
    print("=" * 60)


if __name__ == "__main__":
    main()
