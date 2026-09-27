"""
evaluate.py — measure how good the system is, RETRIEVAL vs GENERATION separately.

Runs every labelled log in sample_logs.json through the pipeline and scores it
against the known-correct technique. This is 100% LOCAL (plus the hosted LLM
calls) — it is NOT a deploy. Eval = "is the answer right?"; deploy = "can others
reach it?". They're different; you do NOT deploy to evaluate.

Two halves, reported separately (so a wrong answer tells you which half to fix):

  RETRIEVAL  — did the search find the right technique at all?
     * recall@10  : is the correct technique in the ~10 hybrid candidates?
                    (If not, the reranker and LLM never even had a chance.)
     * rerank@1/3 : after reranking, is it #1 / in the top 3?
     * shown@5    : is it among the 5 candidates the LLM actually chooses from?

  GENERATION — given those candidates, did the LLM name the right one?
     * primary: the LLM's FIRST (main) pick is exactly right — the strict score,
                and the one to watch: listing extra techniques can't inflate it
     * exact  : the exact expected ID appears anywhere in the answer
     * family : it names the right parent technique (right area, maybe wrong
                sub-technique) — a softer credit

Fair scoring for an evolving ATT&CK: if MITRE has REVOKED an expected ID and
replaced it (e.g. T1070.001 -> T1685.005 in the current release), the official
replacement also counts as correct. The mapping comes from MITRE's own
"revoked-by" data — see attack_data.revoked_replacements().

Usage:
  ./venv/bin/python scripts/evaluate.py                    # full: rewrite + retrieval + generation
  ./venv/bin/python scripts/evaluate.py --show-rewrites    # also print each log's rewrite
  ./venv/bin/python scripts/evaluate.py --no-llm           # retrieval only, local, no key

Held-out set (built by scripts/build_heldout_set.py — NOT used for tuning):
  ./venv/bin/python scripts/evaluate.py --samples data/heldout_atomic.json --no-llm
  ./venv/bin/python scripts/evaluate.py --samples data/heldout_atomic.json --limit 25
  (--limit N takes the first N samples; the builder shuffled them, so it's a random subset.
   --no-table prints only the summary, handy for large sets.)
"""

import json
import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=FutureWarning)
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.attack_data import revoked_replacements          # noqa: E402
from src.retrieval import RetrievalPipeline                # noqa: E402
from src.prompt import build_prompt                        # noqa: E402
from src.pipeline import DEFAULT_TOP_K                     # noqa: E402
from src.evaluation import (                               # noqa: E402
    extract_predicted_ids,
    family,
)

PROJECT_ROOT = Path(__file__).parent.parent
SAMPLES_FILE = PROJECT_ROOT / "sample_logs.json"
# Every LLM request/response is cached here (gitignored). Re-running the eval only
# pays for calls whose prompts changed, and a run stopped by a rate limit resumes
# for free. Delete this folder to force fresh answers.
LLM_CACHE_DIR = PROJECT_ROOT / "data" / "llm_cache"

# How many candidates the hybrid stage returns before reranking (recall@10).
POOL_TOP_K = 10


def _arg_value(flag: str) -> str | None:
    """Return the value after `flag` on the command line (e.g. --limit 25), if given."""
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        sys.exit(f"{flag} needs a value")
    return None


def load_samples() -> list[dict]:
    """Load the labelled test logs (default: sample_logs.json; or --samples PATH)."""
    path = Path(_arg_value("--samples") or SAMPLES_FILE)
    samples = json.loads(path.read_text())["samples"]
    limit = _arg_value("--limit")
    return samples[: int(limit)] if limit else samples


def accepted_ids(expected: str, replacements: dict[str, str]) -> set[str]:
    """
    The IDs that count as correct for `expected`: itself, plus MITRE's official
    replacement if it was revoked (following chains of revocations).
    """
    ids = {expected}
    current = expected
    while current in replacements and replacements[current] not in ids:
        current = replacements[current]
        ids.add(current)
    return ids


def main() -> None:
    from src.llm import LLMQuotaError
    try:
        run()
    except LLMQuotaError as err:
        print(f"\n[quota] {err}")
        print("Every LLM answer received so far is cached in data/llm_cache/, so "
              "re-running later resumes where this stopped at no extra cost.")
        sys.exit(1)


def run() -> None:
    use_llm = "--no-llm" not in sys.argv
    show_rewrites = "--show-rewrites" in sys.argv

    # The LLM powers two steps: the query REWRITE (retrieval) and the final ANSWER
    # (generation). Without a key, the eval falls back to local-only retrieval.
    llm = None
    if use_llm:
        from src.llm import LLMClient, LLMConfigError
        try:
            llm = LLMClient(cache_dir=LLM_CACHE_DIR)
        except LLMConfigError:
            print("\n[note] No LLM key set; running RETRIEVAL-ONLY (local, no rewrite).\n")
            use_llm = False

    print("Loading models + index...")
    rewriter = None
    if use_llm:
        from src.query_rewriter import QueryRewriter
        rewriter = QueryRewriter(llm)
    retriever = RetrievalPipeline(rewriter=rewriter)
    replacements = revoked_replacements()

    samples = load_samples()

    # Counters. "Scored" = the labelled (non-benign) logs we can grade by ID.
    scored = 0
    recall_at_10 = rerank_at_1 = rerank_at_3 = shown_at_k = 0
    gen_primary = gen_exact = gen_family = 0
    benign_result = None
    notes: list[str] = []
    rows = []

    for smp in samples:
        expected = smp["expected_technique_id"]
        log = smp["log"]
        difficulty = smp.get("difficulty", "?")

        # --- RETRIEVAL: (rewrite) + hybrid pool + rerank ---
        result = retriever.retrieve_detailed(
            log, pool=20, candidates=POOL_TOP_K, top_k=DEFAULT_TOP_K
        )
        pool_ids = [c["attack_id"] for c in result["pool"]]
        shown = result["top"]                       # what the LLM gets to choose from
        shown_ids = [c["attack_id"] for c in shown]

        if show_rewrites and result["description"]:
            print(f"\n[{smp['id']}] {expected}\n  log:     {log[:110]}\n"
                  f"  rewrite: {result['description']}")

        # --- GENERATION: the LLM picks from the shown candidates ---
        predicted_ids: list[str] = []
        if use_llm:
            system_prompt, user_prompt = build_prompt(log, shown)
            predicted_ids = extract_predicted_ids(llm.chat(system_prompt, user_prompt))

        # The benign log has no correct technique — score it separately.
        # "Correct" = the LLM did NOT assert an attack technique for normal activity.
        if expected.startswith("none"):
            if not use_llm:
                benign_result = "not scored (needs the LLM to answer)"
            elif predicted_ids:
                benign_result = f"FALSE POSITIVE — mapped to {predicted_ids}"
            else:
                benign_result = "correct — no technique asserted"
            rows.append((expected, difficulty, "-", "-", "benign", "-"))
            continue

        scored += 1
        ok = accepted_ids(expected, replacements)
        if len(ok) > 1:
            notes.append(f"{expected} was revoked by MITRE -> also accepting "
                         f"{', '.join(sorted(ok - {expected}))}")

        r10 = bool(ok & set(pool_ids))
        r1 = shown_ids[0] in ok if shown_ids else False
        r3 = bool(ok & set(shown_ids[:3]))
        rk = bool(ok & set(shown_ids))
        recall_at_10 += r10
        rerank_at_1 += r1
        rerank_at_3 += r3
        shown_at_k += rk

        gen_mark = "(skipped)"
        if use_llm:
            families = {family(i) for i in ok}
            primary_ok = bool(predicted_ids) and predicted_ids[0] in ok
            gen_primary += primary_ok
            if ok & set(predicted_ids):
                gen_exact += 1
                gen_family += 1
                gen_mark = "exact" if primary_ok else f"2nd-pick{predicted_ids}"
            elif any(family(p) in families for p in predicted_ids):
                gen_family += 1
                gen_mark = f"family{predicted_ids}"
            else:
                gen_mark = f"miss{predicted_ids or ''}"

        # rerank column: Y = #1, 3 = top 3, 5 = top 5 (shown to LLM), · = not shown
        rank_mark = "Y" if r1 else ("3" if r3 else (str(DEFAULT_TOP_K) if rk else "·"))
        rows.append((expected, difficulty, "Y" if r10 else "·", rank_mark,
                     gen_mark, shown_ids[0] if shown_ids else "-"))

    # ---- Per-log table ----
    print("\n" + "=" * 84)
    print(f"Test set: {_arg_value('--samples') or SAMPLES_FILE.name}  ({len(samples)} logs)")
    mode = "rewrite + hybrid + rerank" if use_llm else "hybrid + rerank (local, no rewrite)"
    print(f"Retrieval mode: {mode}")
    print(f"{'expected':13} {'difficulty':11} {'rec@10':7} {'rerank':7} {'generation':24} top1")
    print("-" * 84)
    if "--no-table" not in sys.argv:
        for expected, diff, r10, rnk, gen, top1 in rows:
            print(f"{expected:13} {diff:11} {r10:^7} {rnk:^7} {gen:24} {top1}")
    print("=" * 84)

    # ---- Summary ----
    def pct(n: int) -> str:
        return f"{n}/{scored} ({n/scored:.0%})" if scored else "n/a"

    print("\nRETRIEVAL (can search even find it?):")
    print(f"  recall@10 : {pct(recall_at_10)}   <- correct technique is in the candidate pool")
    print(f"  rerank@1  : {pct(rerank_at_1)}   <- ranked #1 after rerank")
    print(f"  rerank@3  : {pct(rerank_at_3)}   <- in the top 3")
    print(f"  shown@{DEFAULT_TOP_K}   : {pct(shown_at_k)}   <- among the candidates the LLM chooses from (top {DEFAULT_TOP_K} + up to 2 parents)")

    if use_llm:
        print("\nGENERATION (given candidates, does the LLM pick right?):")
        print(f"  primary   : {pct(gen_primary)}   <- the LLM's MAIN pick is exactly right (strict)")
        print(f"  exact hit : {pct(gen_exact)}   <- exact technique ID appears anywhere in the answer")
        print(f"  family hit: {pct(gen_family)}   <- answer names the right parent technique")
    else:
        print("\nGENERATION: skipped (no LLM). Run without --no-llm to score it.")

    if benign_result is not None:
        print(f"\nBENIGN control log: {benign_result}")

    for note in sorted(set(notes)):
        print(f"\nNote: {note}")

    if llm is not None:
        print(f"\nLLM usage this run: {llm.api_calls} API calls, {llm.tokens_used:,} tokens "
              f"({llm.cache_hits} answers reused from cache)")

    if _arg_value("--samples"):
        print("\nNote: held-out set — do NOT tune the pipeline on these results, or the")
        print("set becomes 'seen'. Small subsets (--limit) swing a lot: 1 log in 25 = 4%.")
    else:
        print("\nNote: sample_logs.json is SYNTHETIC and guided the design — use these")
        print("numbers to compare changes, not as absolute truth.")


if __name__ == "__main__":
    main()
