"""
retrieval.py — the retrieval CORE: glue hybrid search + reranking into one call.

This is the full Phase B retrieval step (no LLM):

    log line  ->  hybrid search (wide ~10)  ->  rerank (sharp top 3)  ->  results

It's a thin orchestrator: the real work lives in hybrid_search.py and
reranker.py. Keeping this separate means the entry-point script (and, later, the
LLM generator and the API) can get "the top techniques for this log" from ONE
place without knowing the internals.

Models are loaded once when the pipeline is created, then reused across queries —
loading the embedder, store, and reranker each takes a moment, so we don't want
to redo it per log line.
"""

from typing import Optional

from src.embedder import Embedder
from src.vector_store import open_store, VectorStore
from src.hybrid_search import HybridSearcher, normalize_query
from src.reranker import Reranker


class RetrievalPipeline:
    """Retrieve + rerank techniques for an input log line."""

    def __init__(self, store: Optional[VectorStore] = None) -> None:
        # Load the three components once and hold onto them.
        self.embedder = Embedder()
        self.store = store or open_store()
        self.searcher = HybridSearcher(self.store, self.embedder)
        self.reranker = Reranker()

    def retrieve(
        self, log_line: str, pool: int = 20, candidates: int = 10, top_k: int = 3
    ) -> list[dict]:
        """
        Return the top_k techniques for `log_line`, best first.

        Steps:
          1. Hybrid search -> `candidates` (~10) fused candidates.
          2. Rerank those -> `top_k` (default 3) sharpest matches.

        Each result dict carries: attack_id, name, tactics, mitigations, text,
        rrf_score (from retrieval), and rerank_score (from reranking).
        """
        # Normalize the raw log once; use it for both retrieval and reranking so
        # every stage reads the same clean tokens (see hybrid_search.normalize_query).
        query = normalize_query(log_line)

        # 1. RETRIEVE: wide net of candidates via hybrid search.
        found = self.searcher.search(query, pool=pool, top_k=candidates)

        # 2. RERANK: sharpen to the best top_k.
        return self.reranker.rerank(query, found, top_k=top_k)
