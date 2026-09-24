"""
pipeline.py — the whole system in one call: log line in, grounded answer out.

This ties the three stages together:

    log line
       │
       ▼  QueryRewriter: plain-language behaviour description (LLM, no IDs)
       ▼  RetrievalPipeline (Checkpoint 2): hybrid search + rerank
    top techniques (+ their real mitigations)
       │
       ▼  build_prompt (Checkpoint 3): log + candidates + GROUNDING RULE
    a grounded prompt
       │
       ▼  LLMClient (Checkpoint 3): hosted, OpenAI-compatible model
    final answer: technique ID(s) + evidence + suggested mitigation

The retrieval core and the LLM are loaded once and reused. The LLM is only
contacted here, at the end — everything before it is local and free.
"""

from typing import Optional

from src.retrieval import RetrievalPipeline
from src.prompt import build_prompt
from src.llm import LLMClient
from src.query_rewriter import QueryRewriter

# How many reranked candidates the LLM chooses from. The eval showed the LLM picks
# the right technique whenever it's shown it, and the small reranker often places
# the right one 4th-5th rather than top 3. Showing 5 converts more of those into
# correct answers; the grounding rule still stops it from picking a poor match.
DEFAULT_TOP_K = 5


class MappingPipeline:
    """End-to-end: map a log line to grounded ATT&CK technique(s) + mitigation."""

    def __init__(self, top_k: int = DEFAULT_TOP_K) -> None:
        # LLM client — reads provider config from env/.env. Constructing it first
        # means a missing API key fails fast, before we load the local models.
        self.llm = LLMClient()
        # Retrieval core (rewriter + embedder + index + reranker). The rewriter
        # shares the same LLM client.
        self.retriever = RetrievalPipeline(rewriter=QueryRewriter(self.llm))
        self.top_k = top_k

    def run(self, log_line: str, return_candidates: bool = False):
        """
        Map one log line to a grounded answer.

        Steps:
          1. RETRIEVE the top techniques (with their mitigations) for the log.
          2. BUILD the grounded prompt from the log + those candidates.
          3. GENERATE the final answer with the LLM.

        Returns the answer string, or (answer, candidates) if return_candidates.
        """
        # 1. Retrieve grounded candidates (real IDs + real mitigations).
        candidates = self.retriever.retrieve(log_line, top_k=self.top_k)

        # 2. Build the grounded prompt (system rules + log + candidates).
        system_prompt, user_prompt = build_prompt(log_line, candidates)

        # 3. Ask the hosted LLM to write the grounded mapping.
        answer = self.llm.chat(system_prompt, user_prompt)

        if return_candidates:
            return answer, candidates
        return answer
