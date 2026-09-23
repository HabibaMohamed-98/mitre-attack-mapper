"""
analyze_log.py — the whole system from the command line.

Give it a log line; it retrieves the best ATT&CK techniques, then asks the hosted
LLM to write a GROUNDED answer: technique ID(s), the evidence quoted from the log,
and a suggested mitigation drawn from ATT&CK's own data.

Setup (one time):
  1. Get a free Groq API key: https://console.groq.com/keys  (no credit card)
  2. cp .env.example .env
  3. Put your key in .env as  LLM_API_KEY=gsk_...

Run:
  ./venv/bin/python scripts/analyze_log.py "Sysmon EventID 10 ProcessAccess ... lsass.exe"
  # or with no argument for an interactive prompt:
  ./venv/bin/python scripts/analyze_log.py
"""

import os
import sys
import warnings
from pathlib import Path

# Quiet two cosmetic notices in this user-facing script:
#  - the transformers tokenizer FutureWarning
#  - the "tokenizers: process just got forked" parallelism warning (set BEFORE
#    any tokenizer import, which is why it's up here at the very top).
warnings.filterwarnings("ignore", category=FutureWarning)
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

sys.path.insert(0, str(Path(__file__).parent.parent))

from openai import AuthenticationError, APIConnectionError, APIStatusError  # noqa: E402
from src.pipeline import MappingPipeline       # noqa: E402
from src.llm import LLMConfigError             # noqa: E402


def main() -> None:
    # Get the log line from the command line, or prompt for one.
    if len(sys.argv) > 1:
        log_line = " ".join(sys.argv[1:])
    else:
        log_line = input("Paste a log line and press Enter:\n> ").strip()
        if not log_line:
            print("No log line given — nothing to do.")
            return

    # Build the pipeline. If the API key is missing, give a clear message and stop
    # (retrieval alone still works via scripts/retrieve.py, with no key needed).
    try:
        print("\nLoading models + index, then contacting the LLM...")
        pipeline = MappingPipeline(top_k=3)
    except LLMConfigError as err:
        print(f"\n[config] {err}")
        return

    # The retrieval part is local; the LLM call can fail on bad key / network.
    # Turn those into clear guidance instead of a raw stack trace.
    try:
        answer, candidates = pipeline.run(log_line, return_candidates=True)
    except AuthenticationError:
        print(
            "\n[auth] The LLM rejected the API key (401 Invalid API Key).\n"
            "       Check LLM_API_KEY in your .env: it should be your real Groq\n"
            "       key starting with 'gsk_', with no quotes or spaces.\n"
            "       Get/verify a key at https://console.groq.com/keys"
        )
        return
    except APIConnectionError:
        print("\n[network] Could not reach the LLM provider. Check your internet connection.")
        return
    except APIStatusError as err:
        # e.g. model not found, rate limit — surface the provider's message.
        print(f"\n[api] The LLM provider returned an error: {err.status_code} {err.message}")
        return

    # Show what retrieval fed the model (transparency: these are the ONLY IDs the
    # model was allowed to use), then the grounded answer.
    print("\n" + "=" * 66)
    print("Retrieved candidates given to the LLM (grounding set):")
    for c in candidates:
        print(f"   {c['attack_id']}  {c['name']}")
    print("=" * 66)
    print(f'\nLog line:\n  "{log_line}"\n')
    print("GROUNDED ANSWER")
    print("-" * 66)
    print(answer)
    print("-" * 66)


if __name__ == "__main__":
    main()
