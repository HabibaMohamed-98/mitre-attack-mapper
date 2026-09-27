"""
vector_store.py — build and search the hybrid-search index.

This is the "embed and index it" half of Phase A (kept separate from the
"extract the data" half in attack_data.py, as the brief asks).

Store choice (brief asks for one that does BOTH vector and keyword search, and a
short justification):
  LanceDB — a mainstream, well-documented, open-source store that is *embedded*
  (just a folder on disk, no server or Docker to run), and supports BOTH vector
  (semantic) search AND a real full-text keyword index (BM25, via Tantivy) in the
  SAME table. That's exactly what we need for hybrid search next checkpoint, with
  zero infra to manage on a laptop. Runs fine CPU-only.

This module gives us three things:
  - build_index(...)      : create/replace the table from records + vectors
  - open_store(...)       : reopen the existing table
  - VectorStore.semantic_search / keyword_search : the two search modes

We store each technique as a row with: the snippet `text`, its `vector`, and
metadata (attack_id, name, tactics, mitigations). Vector search ranks by meaning;
keyword search ranks by exact words (T-codes, "LSASS", etc.). Hybrid = both,
merged — that's Checkpoint 2, but the store is ready for it now.
"""

from pathlib import Path
from typing import Optional

import lancedb
import pyarrow as pa

from src.embedder import EMBEDDING_DIM

# Where the index lives on disk. It's derived data (rebuildable from the STIX
# file), so it's git-ignored, like the STIX download.
PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_DB_DIR = PROJECT_ROOT / "data" / "lancedb"
TABLE_NAME = "techniques"


def _schema() -> pa.Schema:
    """
    Declare the table's columns explicitly.

    We spell out the schema (rather than letting LanceDB guess from the first
    row) so the vector width is fixed at EMBEDDING_DIM and the list columns have
    a defined type — this avoids surprises and makes the store self-describing.
    """
    return pa.schema(
        [
            pa.field("attack_id", pa.string()),
            pa.field("name", pa.string()),
            pa.field("tactics", pa.list_(pa.string())),
            pa.field("is_subtechnique", pa.bool_()),
            pa.field("mitigations", pa.list_(pa.string())),
            pa.field("text", pa.string()),
            # Snippet + real-world examples; used ONLY by keyword search.
            pa.field("keyword_text", pa.string()),
            # Fixed-size vector column — this is what enables vector search.
            pa.field("vector", pa.list_(pa.float32(), EMBEDDING_DIM)),
        ]
    )


def build_index(
    records: list[dict],
    vectors: list[list[float]],
    db_dir: Optional[Path] = None,
) -> int:
    """
    Create (or overwrite) the index from records + their embedding vectors.

    `records` are the metadata+text dicts from snippets.build_record(); `vectors`
    is the matching list of embeddings (same order, same length). We attach each
    vector to its record and write them all as one table, then build the
    full-text keyword index on the `text` column.

    Returns the number of rows indexed.
    """
    if len(records) != len(vectors):
        raise ValueError(
            f"records ({len(records)}) and vectors ({len(vectors)}) "
            "must be the same length."
        )

    db_dir = db_dir or DEFAULT_DB_DIR
    db_dir.mkdir(parents=True, exist_ok=True)
    db = lancedb.connect(str(db_dir))

    # Attach each vector to its record row.
    rows = []
    for record, vector in zip(records, vectors):
        rows.append({**record, "vector": vector})

    # mode="overwrite" makes rebuilding idempotent: run it again, get a fresh
    # index rather than duplicates.
    table = db.create_table(
        TABLE_NAME, data=rows, schema=_schema(), mode="overwrite"
    )

    # Build the BM25 full-text index on keyword_text (the snippet + MITRE's
    # real-world procedure examples). This is what makes keyword search fast and
    # real (not just substring matching), and lets it match tool/command names.
    table.create_fts_index("keyword_text", replace=True)

    return table.count_rows()


class VectorStore:
    """A thin handle over the LanceDB table with the two search modes."""

    def __init__(self, db_dir: Optional[Path] = None) -> None:
        db_dir = db_dir or DEFAULT_DB_DIR
        if not (db_dir / f"{TABLE_NAME}.lance").exists():
            raise FileNotFoundError(
                f"No index found at {db_dir}. "
                "Build it first: ./venv/bin/python scripts/build_index.py"
            )
        self.db = lancedb.connect(str(db_dir))
        self.table = self.db.open_table(TABLE_NAME)

    def count(self) -> int:
        """How many techniques are indexed."""
        return self.table.count_rows()

    def get_by_ids(self, attack_ids: list[str]) -> list[dict]:
        """Fetch stored records by exact ATT&CK ID (unknown IDs are skipped)."""
        if not attack_ids:
            return []
        # IDs only contain T, digits and dots, so quoting them is safe.
        id_list = ", ".join(f"'{aid}'" for aid in attack_ids)
        return (
            self.table.search()
            .where(f"attack_id IN ({id_list})")
            .limit(len(attack_ids))
            .to_list()
        )

    def semantic_search(self, query_vector: list[float], k: int = 5) -> list[dict]:
        """
        Vector search: find the k techniques whose meaning is closest to the
        query vector. Returns metadata dicts (with a `_distance` score;
        smaller = closer).
        """
        return (
            self.table.search(query_vector)
            .limit(k)
            .to_list()
        )

    def keyword_search(self, query_text: str, k: int = 5) -> list[dict]:
        """
        Keyword search: BM25 full-text match on the snippet text. Great for exact
        terms like "T1003" or "LSASS". (Used more in the next checkpoint; here it
        shows the store really does both modes.)
        """
        return (
            self.table.search(query_text, query_type="fts")
            .limit(k)
            .to_list()
        )


def open_store(db_dir: Optional[Path] = None) -> VectorStore:
    """Convenience opener so callers don't import the class directly."""
    return VectorStore(db_dir)
