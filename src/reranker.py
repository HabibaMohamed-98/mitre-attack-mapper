"""
reranker.py — the RERANK step: carefully re-sort the candidates, keep the best.

Hybrid search is fast but rough: it scores the query and each technique
SEPARATELY, then compares. A cross-encoder reranker is slower but sharper: it
reads the query and ONE candidate TOGETHER, in the same pass, and outputs a
single relevance score. That joint reading catches nuances retrieval misses.

Because it's slower, we only run it on the ~10 candidates hybrid search already
narrowed to — not all 697 techniques. Retrieve wide and cheap, then rerank narrow
and sharp. Standard RAG pattern.

Model choice (one line): cross-encoder/ms-marco-MiniLM-L-6-v2 — a small,
CPU-friendly sentence-transformers cross-encoder, the standard lightweight
reranker, fine on this no-GPU Intel Mac.

This module ONLY reranks a given candidate list (retrieval lives in
hybrid_search.py), so it can be tested on its own.
"""

from sentence_transformers import CrossEncoder

# One place to change the reranker model for the whole project.
RERANKER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"


class Reranker:
    """A thin wrapper around a cross-encoder reranking model."""

    def __init__(self, model_name: str = RERANKER_MODEL) -> None:
        # Downloads the model on first use (~80 MB), then caches it.
        self.model = CrossEncoder(model_name)

    def rerank(self, query: str, candidates: list[dict], top_k: int = 3) -> list[dict]:
        """
        Score each candidate against the query and return the top_k, best first.

        `candidates` are records from hybrid search (each has a "text" snippet).
        We pair the query with each candidate's snippet, let the cross-encoder
        score all pairs, attach the score as "rerank_score", and sort.

        A higher score means more relevant (scores are unbounded logits, so they
        can be negative — only the ORDER matters).
        """
        if not candidates:
            return []

        # Build (query, candidate_text) pairs — this is what the model scores.
        pairs = [(query, c["text"]) for c in candidates]
        scores = self.model.predict(pairs)

        # Attach each score to its candidate (copy so we don't mutate the input).
        scored = []
        for candidate, score in zip(candidates, scores):
            enriched = dict(candidate)
            enriched["rerank_score"] = float(score)
            scored.append(enriched)

        # Sort by score, highest first, and keep the top_k.
        scored.sort(key=lambda c: c["rerank_score"], reverse=True)
        return scored[:top_k]
