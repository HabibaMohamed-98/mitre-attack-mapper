"""
retrieval.py — the retrieval CORE: glue rewrite + hybrid search + reranking.

    log line
      -> (optional) rewrite into a plain-language behaviour description  [LLM]
      -> hybrid search with the log AND the description (wide, ~10)      [local]
      -> rerank (sharp top N)                                            [local]

It's a thin orchestrator: the real work lives in query_rewriter.py,
hybrid_search.py and reranker.py. Keeping this separate means the pipeline, the
eval, and (later) the API get "the top techniques for this log" from ONE place.

The rewrite step is optional: without an LLM (no API key, or `--no-llm` in the
eval) retrieval still works — purely locally, just with lower recall on raw logs.

Models are loaded once when the pipeline is created, then reused across queries.
"""

from typing import Optional

from src.embedder import Embedder
from src.vector_store import open_store, VectorStore
from src.hybrid_search import HybridSearcher, normalize_query
from src.reranker import Reranker
from src.query_rewriter import QueryRewriter


def _keep_parents_visible(ranked: list[dict], top_k: int, max_extra: int = 2) -> list[dict]:
    """
    Take the top_k reranked candidates, and if any shown sub-technique's PARENT is
    in the candidate pool but ranked below the cut, show the parent too.

    Why: the reranker tends to score long, specific sub-technique descriptions
    above their shorter parent, so all the visible slots can go to variants
    (T1055.001, T1055.002, ...) and the parent T1055 never reaches the LLM. Then
    the LLM can't follow grounding rule 6 ("choose the parent when the evidence
    fits several sub-techniques equally"). At most `max_extra` parents are added,
    to keep the prompt small.
    """
    top = list(ranked[:top_k])
    shown = {c["attack_id"] for c in top}
    below_cut = {c["attack_id"]: c for c in ranked[top_k:]}
    added = 0
    for candidate in list(top):
        parent = candidate["attack_id"].split(".", 1)[0]
        if parent != candidate["attack_id"] and parent not in shown and parent in below_cut:
            top.append(below_cut[parent])
            shown.add(parent)
            added += 1
            if added == max_extra:
                break
    return top


class RetrievalPipeline:
    """Retrieve + rerank techniques for an input log line."""

    def __init__(
        self,
        store: Optional[VectorStore] = None,
        rewriter: Optional[QueryRewriter] = None,
    ) -> None:
        # Load the local components once and hold onto them.
        self.embedder = Embedder()
        self.store = store or open_store()
        self.searcher = HybridSearcher(self.store, self.embedder)
        self.reranker = Reranker()
        # None = no rewrite step (pure local retrieval).
        self.rewriter = rewriter

    def retrieve_detailed(
        self, log_line: str, pool: int = 20, candidates: int = 10, top_k: int = 3
    ) -> dict:
        """
        Run retrieval and return every intermediate result (the eval uses these to
        score each stage separately):

          {"description": str | None,   # the plain-language rewrite, if any
           "pool": [...],               # ~10 fused hybrid-search candidates
           "top": [...]}                # the top_k after reranking, best first
        """
        # 1. REWRITE (optional): describe the behaviour in ATT&CK-like language.
        description = self.rewriter.rewrite(log_line) if self.rewriter else None

        # 2. RETRIEVE: search with the original log AND the description, fused.
        queries = [log_line] + ([description] if description else [])
        found = self.searcher.search_many(queries, pool=pool, top_k=candidates)

        # 3. RERANK: the cross-encoder was trained on natural-language questions,
        # so when we have a plain-language description we rerank against it (it
        # struggled on raw log syntax). Otherwise, the normalized log.
        rerank_query = description or normalize_query(log_line)
        ranked = self.reranker.rerank(rerank_query, found, top_k=len(found))
        top = _keep_parents_visible(ranked, top_k)

        return {"description": description, "pool": found, "top": top}

    def retrieve(
        self, log_line: str, pool: int = 20, candidates: int = 10, top_k: int = 3
    ) -> list[dict]:
        """
        Return the top_k techniques for `log_line`, best first.

        Each result dict carries: attack_id, name, tactics, mitigations, text,
        rrf_score (from retrieval), and rerank_score (from reranking).
        """
        return self.retrieve_detailed(
            log_line, pool=pool, candidates=candidates, top_k=top_k
        )["top"]
