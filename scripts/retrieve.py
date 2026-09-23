"""
retrieve.py — type in a log line, see the final top-3 ATT&CK techniques.

This is the runnable entry point for the retrieval core (Checkpoint 2). It proves
retrieval works end-to-end with NO LLM: a log goes in, hybrid search + reranking
run, and the 3 best-matching techniques come out with their scores.

Two ways to run it:

  # pass the log line as an argument
  ./venv/bin/python scripts/retrieve.py "schtasks /create /tn Updater /tr evil.exe /sc onlogon"

  # or run with no argument for an interactive prompt (type a log, Enter)
  ./venv/bin/python scripts/retrieve.py
"""

import sys
import warnings
from pathlib import Path

# Silence a cosmetic FutureWarning from the transformers tokenizer (a library
# deprecation notice, unrelated to our code) so the printed output stays clean.
warnings.filterwarnings("ignore", category=FutureWarning)

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.retrieval import RetrievalPipeline   # noqa: E402


def print_results(log_line: str, results: list[dict]) -> None:
    """Pretty-print the final top-3 techniques for one log line."""
    print(f'\nLog line:\n  "{log_line}"\n')
    print("Top 3 techniques (after hybrid search + reranking):")
    print("=" * 64)
    for rank, r in enumerate(results, start=1):
        tactics = ", ".join(r["tactics"]) or "Unknown"
        # rerank_score is the decisive score; rrf_score shows the retrieval stage.
        print(
            f"{rank}. {r['attack_id']}  {r['name']}   [{tactics}]"
            f"\n     rerank score: {r['rerank_score']:.3f}"
            f"   (retrieval RRF: {r['rrf_score']:.4f})"
        )
    print("=" * 64)


def main() -> None:
    # Get the log line from the command line, or prompt for one interactively.
    if len(sys.argv) > 1:
        log_line = " ".join(sys.argv[1:])
    else:
        log_line = input("Paste a log line and press Enter:\n> ").strip()
        if not log_line:
            print("No log line given — nothing to do.")
            return

    # Load the pipeline once (loads embedder + store + reranker), then query.
    print("\nLoading models + index (first time is slower)...")
    pipeline = RetrievalPipeline()
    results = pipeline.retrieve(log_line, top_k=3)

    print_results(log_line, results)


if __name__ == "__main__":
    main()
