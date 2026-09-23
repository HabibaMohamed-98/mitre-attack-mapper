"""
search.py — run ONE manual similarity search by hand, to sanity-check the index.

This is how you confirm the library actually works: type a plain-language query
and see whether relevant ATT&CK techniques come back.

    ./venv/bin/python scripts/search.py "someone dumped LSASS memory to steal passwords"

It embeds your query with the SAME local model used to build the index, then asks
the store for the closest techniques by meaning (semantic search). For contrast,
it also shows the top keyword (BM25) hit, proving the store does both modes.

No LLM is involved — this is pure retrieval, exactly as the checkpoint intends.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.embedder import Embedder                      # noqa: E402
from src.vector_store import open_store                # noqa: E402


def main() -> None:
    # Take the query from the command line; fall back to a sensible default so
    # running the script with no args still demonstrates something.
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
    else:
        query = "someone dumped LSASS memory to steal account passwords"
        print(f"(no query given — using a demo query)\n")

    print(f'Query: "{query}"\n')

    # Open the store and the embedding model.
    store = open_store()
    print(f"Index holds {store.count()} techniques.\n")
    embedder = Embedder()

    # SEMANTIC search: match by meaning.
    query_vector = embedder.embed_one(query)
    results = store.semantic_search(query_vector, k=5)

    print("Top 5 by SEMANTIC similarity (meaning):")
    print("-" * 60)
    for rank, r in enumerate(results, start=1):
        tactics = ", ".join(r["tactics"]) or "Unknown"
        print(f"{rank}. {r['attack_id']}  {r['name']}   [{tactics}]")
        # Show the first line of the snippet's description part for a taste.
        desc_line = r["text"].split("\n", 1)[-1].strip()
        print(f"     {desc_line[:160]}")
        if r["mitigations"]:
            print(f"     Mitigations: {', '.join(r['mitigations'][:3])}"
                  + (" ..." if len(r["mitigations"]) > 3 else ""))
    print()

    # KEYWORD search: match by exact words (shows the store's other mode).
    kw = store.keyword_search(query, k=1)
    if kw:
        print("Top KEYWORD (BM25) hit for the same query:")
        print("-" * 60)
        print(f"   {kw[0]['attack_id']}  {kw[0]['name']}")


if __name__ == "__main__":
    main()
