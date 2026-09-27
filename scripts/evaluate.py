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

Quota safety cap:
  --token-budget 120000   stop cleanly once this many LLM tokens were used this run
                          (e.g. 60% of Groq's 200k/day), reporting the logs completed.

Investigation report (read it like an analyst would):
  --report data/reports/run.md   write, for EVERY log: the log, what the system
                                 understood, the options shown to the LLM, the
                                 LLM's full answer (technique + evidence +
                                 mitigation), a plain-English verdict saying WHERE
                                 it went wrong if it did, and time + tokens.
"""

import json
import os
import sys
import time
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

    report: list[dict] = []   # per-log details for --report
    budget = int(_arg_value("--token-budget") or 0)
    stopped_early = False

    for smp in samples:
        # Quota safety cap: stop BEFORE starting a log once the budget is spent,
        # so we never use up the whole day's free quota.
        if budget and llm is not None and llm.tokens_used >= budget:
            stopped_early = True
            break

        expected = smp["expected_technique_id"]
        log = smp["log"]
        difficulty = smp.get("difficulty", "?")

        started = time.time()
        tokens_before = llm.tokens_used if llm is not None else 0

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
        answer = ""
        if use_llm:
            system_prompt, user_prompt = build_prompt(log, shown)
            answer = llm.chat(system_prompt, user_prompt)
            predicted_ids = extract_predicted_ids(answer)

        entry = {
            "id": smp["id"], "log": log, "expected": expected,
            "expected_name": smp.get("expected_technique_name", ""),
            "rewrite": result["description"],
            "shown": [f"{c['attack_id']} {c['name']}" for c in shown],
            "answer": answer, "seconds": time.time() - started,
            "tokens": (llm.tokens_used - tokens_before) if llm is not None else 0,
        }
        report.append(entry)

        # The benign log has no correct technique — score it separately.
        # "Correct" = the LLM did NOT assert an attack technique for normal activity.
        if expected.startswith("none"):
            if not use_llm:
                benign_result = "not scored (needs the LLM to answer)"
            elif predicted_ids:
                benign_result = f"FALSE POSITIVE — mapped to {predicted_ids}"
            else:
                benign_result = "correct — no technique asserted"
            entry["verdict"] = ("✅ Correctly left unmapped (ordinary activity)"
                                if use_llm and not predicted_ids else
                                f"❌ False alarm: mapped ordinary activity to {predicted_ids}"
                                if use_llm else "not scored (no LLM)")
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

            # Plain-English verdict: if wrong, WHICH stage lost the answer.
            if primary_ok:
                entry["verdict"] = "✅ Correct"
            elif ok & set(predicted_ids):
                entry["verdict"] = "🟡 Right technique named, but not as the main answer"
            elif any(family(p) in families for p in predicted_ids):
                entry["verdict"] = "🟡 Right technique family, but a different specific variant"
            elif rk:
                entry["verdict"] = "❌ The LLM was shown the right technique but chose something else"
            elif r10:
                entry["verdict"] = "❌ Search found it, but it was ranked too low to reach the LLM"
            else:
                entry["verdict"] = "❌ Search never found the right technique"

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

    if stopped_early:
        print(f"\n[budget] Stopped early: the {budget:,}-token budget was reached. "
              f"Scores above cover only the {scored} logs completed.")
    if llm is not None:
        print(f"\nLLM usage this run: {llm.api_calls} API calls, {llm.tokens_used:,} tokens "
              f"({llm.cache_hits} answers reused from cache)")

    if _arg_value("--report"):
        path = Path(_arg_value("--report"))
        write_report(path, report, llm, scored, gen_primary, recall_at_10, shown_at_k)
        print(f"\nInvestigation report written to {path}")

    if _arg_value("--samples"):
        print("\nNote: held-out set — do NOT tune the pipeline on these results, or the")
        print("set becomes 'seen'. Small subsets (--limit) swing a lot: 1 log in 25 = 4%.")
    else:
        print("\nNote: sample_logs.json is SYNTHETIC and guided the design — use these")
        print("numbers to compare changes, not as absolute truth.")


def write_report(path: Path, report: list[dict], llm, scored: int,
                 correct: int, found: int, shown: int) -> None:
    """Write the per-log investigation report as Markdown (readable in any editor)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    total_time = sum(e["seconds"] for e in report)
    lines = [
        "# Investigation report",
        "",
        f"Model: `{llm.model if llm else 'none (search only)'}` · Logs: {len(report)} · "
        f"Test set: `{_arg_value('--samples') or SAMPLES_FILE.name}`",
        "",
        "| | Result |", "|---|---|",
        f"| Search found the right technique | {found} / {scored} |",
        f"| The right technique reached the LLM | {shown} / {scored} |",
        f"| The LLM's main answer was right | {correct} / {scored} |",
        f"| Average time per log | {total_time / max(len(report), 1):.1f} s |",
        f"| Tokens used | {llm.tokens_used if llm else 0:,} |",
        "",
    ]
    for n, e in enumerate(report, start=1):
        lines += [
            "---", "",
            f"## Log {n} of {len(report)} — {e.get('verdict', '')}", "",
            f"**Log:** `{e['log']}`", "",
            f"**Correct answer:** {e['expected']} {e['expected_name']}", "",
        ]
        if e["rewrite"]:
            lines += [f"**What the system understood:** {e['rewrite']}", ""]
        lines += [f"**Options given to the LLM ({len(e['shown'])}):** " + "; ".join(e["shown"]), ""]
        if e["answer"]:
            lines += ["**The LLM's answer:**", "", "```", e["answer"], "```", ""]
        lines += [f"*Time: {e['seconds']:.1f} s · Tokens: {e['tokens']:,}*", ""]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    main()
