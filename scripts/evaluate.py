"""
evaluate.py — measure how good the system is, RETRIEVAL vs GENERATION separately.

Runs every labelled log in sample_logs.json through the pipeline and scores it
against the known-correct technique. This is 100% LOCAL (plus the hosted LLM
calls) — it is NOT a deploy. Eval = "is the answer right?"; deploy = "can others
reach it?". They're different; you do NOT deploy to evaluate.

Two halves, reported separately (so a wrong answer tells you which half to fix):

  RETRIEVAL  — did the search find the right technique at all?
     * recall@10 : is the correct technique in the ~10 hybrid candidates?
                   (If not, the reranker and LLM never even had a chance.)
     * rerank@1 / rerank@3 : after reranking, is it #1 / in the top 3?

  GENERATION — given good candidates, did the LLM name the right one?
     * exact  : the LLM's answer names the exact expected ID
     * family : it names the right parent technique (right area, maybe wrong
                sub-technique) — a softer credit

Usage:
  ./venv/bin/python scripts/evaluate.py            # retrieval + generation (needs API key)
  ./venv/bin/python scripts/evaluate.py --no-llm   # retrieval only (no key needed)
"""

import json
import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=FutureWarning)
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.embedder import Embedder                         # noqa: E402
from src.vector_store import open_store                   # noqa: E402
from src.hybrid_search import HybridSearcher, normalize_query  # noqa: E402
from src.reranker import Reranker                          # noqa: E402
from src.prompt import build_prompt                        # noqa: E402
from src.evaluation import (                               # noqa: E402
    extract_predicted_ids,
    is_exact_hit,
    is_family_hit,
)

PROJECT_ROOT = Path(__file__).parent.parent
SAMPLES_FILE = PROJECT_ROOT / "sample_logs.json"

# How many candidates the hybrid stage returns before reranking. recall@10 is
# measured against this pool.
POOL_TOP_K = 10


def load_samples() -> list[dict]:
    """Load the labelled test logs."""
    return json.loads(SAMPLES_FILE.read_text())["samples"]


def main() -> None:
    use_llm = "--no-llm" not in sys.argv

    print("Loading models + index...")
    embedder = Embedder()
    searcher = HybridSearcher(open_store(), embedder)
    reranker = Reranker()

    # The LLM is only built if we're doing the generation half. This lets the
    # retrieval eval run with NO API key at all.
    llm = None
    if use_llm:
        from src.llm import LLMClient, LLMConfigError
        try:
            llm = LLMClient()
        except LLMConfigError as err:
            print(f"\n[note] No LLM key set ({err.__class__.__name__}); "
                  "running RETRIEVAL-ONLY. Use --no-llm to silence this.\n")
            use_llm = False

    samples = load_samples()

    # Counters. "Scored" = the labelled (non-benign) logs we can grade by ID.
    scored = 0
    recall_at_10 = rerank_at_1 = rerank_at_3 = 0
    gen_exact = gen_family = 0
    benign_result = None
    rows = []

    for smp in samples:
        expected = smp["expected_technique_id"]
        log = smp["log"]
        difficulty = smp.get("difficulty", "?")

        # --- RETRIEVAL: pool + rerank (local, no LLM) ---
        query = normalize_query(log)
        pool = searcher.search(query, pool=20, top_k=POOL_TOP_K)
        pool_ids = [c["attack_id"] for c in pool]
        reranked = reranker.rerank(query, pool, top_k=3)
        rerank_ids = [c["attack_id"] for c in reranked]

        # --- GENERATION: ask the LLM using those reranked candidates ---
        predicted_ids: list[str] = []
        if use_llm and llm is not None:
            system_prompt, user_prompt = build_prompt(log, reranked)
            answer = llm.chat(system_prompt, user_prompt)
            predicted_ids = extract_predicted_ids(answer)

        # The benign log has no correct technique — score it separately.
        if expected.startswith("none"):
            # "Correct" = the system did NOT confidently assert a technique.
            benign_result = ("no technique asserted" if not predicted_ids
                             else f"asserted {predicted_ids} (false positive)")
            rows.append((expected, difficulty, "-", "-", "benign", "-"))
            continue

        scored += 1
        r10 = expected in pool_ids
        r1 = rerank_ids[:1] == [expected]
        r3 = expected in rerank_ids
        recall_at_10 += r10
        rerank_at_1 += r1
        rerank_at_3 += r3

        gen_mark = ""
        if use_llm:
            if is_exact_hit(expected, predicted_ids):
                gen_exact += 1
                gen_family += 1
                gen_mark = "exact"
            elif is_family_hit(expected, predicted_ids):
                gen_family += 1
                gen_mark = "family"
            else:
                gen_mark = f"miss{predicted_ids or ''}"

        rows.append((
            expected, difficulty,
            "Y" if r10 else "·",
            "Y" if r1 else ("3" if r3 else "·"),
            gen_mark if use_llm else "(skipped)",
            rerank_ids[0],
        ))

    # ---- Per-log table ----
    print("\n" + "=" * 78)
    print(f"{'expected':11} {'difficulty':11} {'rec@10':7} {'rerank':7} {'generation':16} top1")
    print("-" * 78)
    for expected, diff, r10, rnk, gen, top1 in rows:
        print(f"{expected:11} {diff:11} {r10:^7} {rnk:^7} {gen:16} {top1}")
    print("=" * 78)

    # ---- Summary ----
    def pct(n: int) -> str:
        return f"{n}/{scored} ({n/scored:.0%})" if scored else "n/a"

    print("\nRETRIEVAL (can search even find it?):")
    print(f"  recall@10 : {pct(recall_at_10)}   <- correct technique is in the candidate pool")
    print(f"  rerank@1  : {pct(rerank_at_1)}   <- correct technique ranked #1 after rerank")
    print(f"  rerank@3  : {pct(rerank_at_3)}   <- correct technique in the top 3")

    if use_llm:
        print("\nGENERATION (given candidates, does the LLM pick right?):")
        print(f"  exact hit : {pct(gen_exact)}   <- answer names the exact technique ID")
        print(f"  family hit: {pct(gen_family)}   <- answer names the right parent technique")
    else:
        print("\nGENERATION: skipped (no LLM). Run without --no-llm to score it.")

    if benign_result is not None:
        print(f"\nBENIGN control log: {benign_result}")

    print("\nNote: sample_logs.json is SYNTHETIC (representative, not a published")
    print("benchmark) — use these numbers to compare changes, not as absolute truth.")


if __name__ == "__main__":
    main()
