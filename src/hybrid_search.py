"""
hybrid_search.py — the RETRIEVE step: cast a wide net for candidate techniques.

Hybrid search runs TWO searches and merges them:
  - SEMANTIC (vector) search   : matches by meaning ("stole passwords" -> credential
                                 dumping) even when no words overlap.
  - KEYWORD (BM25) search      : matches exact terms ("LSASS", "T1003", "schtasks")
                                 that meaning-based search can miss.

Each covers the other's blind spot. We merge their two ranked lists into one using
Reciprocal Rank Fusion (RRF) — the standard, simple, robust fusion method.

RRF in one sentence: a result's combined score is the sum, over each list it
appears in, of 1 / (rrf_k + its_rank_in_that_list). Being near the top of EITHER
list helps; being near the top of BOTH helps a lot. RRF only needs the RANKS, so
we don't have to reconcile vector distances against BM25 scores (which aren't on
the same scale) — that's exactly why it's the go-to method.

This module is the RETRIEVE half of the retrieval core. It does NOT rerank
(that's reranker.py) — it just returns a wide pool of ~10 candidates for the
reranker to sharpen.
"""

import re

from src.embedder import Embedder
from src.vector_store import VectorStore

# rrf_k dampens how much the very top ranks dominate. 60 is the conventional
# default from the original RRF paper and works well without tuning.
DEFAULT_RRF_K = 60


def normalize_query(text: str) -> str:
    """
    Turn a raw log line into clean tokens for searching.

    Raw logs are full of syntax noise — `Key=Value` pairs, quotes, colons,
    backslash paths — that both the full-text (BM25) parser and the embedding
    model choke on: the FTS parser treats quotes/colons/parens as operators, and
    the noise dilutes the meaningful words. We keep letters, digits, dots and
    hyphens (so IDs like "T1003.001" and words like "non-interactive" survive)
    and turn everything else into spaces.

    This is deliberately LIGHT — it only strips punctuation, it does not try to
    rewrite the log into prose. (That richer "log -> plain-language behaviour"
    step is Phase B / a later checkpoint, and benefits from the LLM.)

    We apply the SAME normalization to the query for both the keyword search and
    the semantic search / reranker, so every stage sees the same clean text.
    """
    # File paths -> just the file name: "C:\Windows\System32\curl.exe" -> "curl.exe".
    # Folder names like "Windows System32 Users public" appear in almost every
    # Windows log and in any ATT&CK description that quotes a path, so they made
    # unrelated techniques match on path words. The file NAME is the real signal.
    # (Drive letter required, so registry keys like HKLM\...\CurrentVersion\Run,
    # which ARE meaningful, are left intact.)
    text = re.sub(r"\b[A-Za-z]:(?:\\[\w .$-]+)*\\([\w.-]+)", r"\1", text)
    cleaned = re.sub(r"[^A-Za-z0-9.\- ]+", " ", text)
    # Collapse repeated whitespace into single spaces.
    return re.sub(r"\s+", " ", cleaned).strip()


def reciprocal_rank_fusion(
    ranked_lists: list[list[str]], rrf_k: int = DEFAULT_RRF_K
) -> dict[str, float]:
    """
    Fuse several ranked lists of IDs into one {attack_id: rrf_score} mapping.

    `ranked_lists` is a list of lists; each inner list is attack_ids in rank
    order (best first). Returns a dict of the combined RRF score per id.
    """
    scores: dict[str, float] = {}
    for ranked in ranked_lists:
        for rank, attack_id in enumerate(ranked):  # rank 0 = best
            scores[attack_id] = scores.get(attack_id, 0.0) + 1.0 / (rrf_k + rank)
    return scores


class HybridSearcher:
    """Runs semantic + keyword search and fuses them with RRF."""

    def __init__(self, store: VectorStore, embedder: Embedder) -> None:
        self.store = store
        self.embedder = embedder

    def search(
        self, query: str, pool: int = 20, top_k: int = 10, rrf_k: int = DEFAULT_RRF_K
    ) -> list[dict]:
        """Return the top_k fused candidate techniques for a single `query`."""
        return self.search_many([query], pool=pool, top_k=top_k, rrf_k=rrf_k)

    def search_many(
        self, queries: list[str], pool: int = 20, top_k: int = 10, rrf_k: int = DEFAULT_RRF_K
    ) -> list[dict]:
        """
        Return the top_k fused candidates across one OR MORE phrasings of the input.

        Every query gets both a semantic and a keyword search, and ALL of those
        ranked lists are fused together with RRF. We use this to search with the
        original log (exact tokens like "lsass.exe") AND its plain-language
        description (ATT&CK-style vocabulary) at the same time: a technique that
        ranks well for either phrasing — or both — rises to the top.

        `pool` is how many results to pull from EACH individual search before
        fusing. Each returned dict is the technique's stored record (attack_id,
        name, tactics, mitigations, text) plus an added "rrf_score".
        """
        ranked_lists: list[list[str]] = []
        # Remember the full record for every technique any search surfaced,
        # keyed by its ATT&CK ID, so we can return rich results after fusing.
        records_by_id: dict[str, dict] = {}

        for query in queries:
            # Normalize so keyword AND semantic search see the same clean text.
            clean_query = normalize_query(query)
            if not clean_query:
                continue

            # --- 1. Semantic search: embed the query, get nearest techniques. ---
            query_vector = self.embedder.embed_one(clean_query)
            semantic_hits = self.store.semantic_search(query_vector, k=pool)

            # --- 2. Keyword search: BM25 over the cleaned query text. ---
            keyword_hits = self.store.keyword_search(clean_query, k=pool)

            for hit in semantic_hits + keyword_hits:
                records_by_id.setdefault(hit["attack_id"], hit)
            ranked_lists.append([h["attack_id"] for h in semantic_hits])
            ranked_lists.append([h["attack_id"] for h in keyword_hits])

        # --- 3. Fuse all the rankings with RRF (ranks only). ---
        fused = reciprocal_rank_fusion(ranked_lists, rrf_k=rrf_k)

        # --- 4. Sort by fused score (highest first) and take the top_k. ---
        ranked_ids = sorted(fused, key=lambda aid: fused[aid], reverse=True)[:top_k]

        results = []
        for attack_id in ranked_ids:
            record = dict(records_by_id[attack_id])  # copy so we don't mutate cache
            record["rrf_score"] = fused[attack_id]
            results.append(record)
        return results
