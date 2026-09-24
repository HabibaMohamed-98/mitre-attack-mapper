"""
llm.py — a thin, SWAPPABLE wrapper around a hosted, OpenAI-compatible LLM.

Why a wrapper: the rest of the system should not care WHICH LLM we use. It just
asks "here's a system + user message, give me the reply." Swapping providers —
Groq -> Google Gemini / OpenRouter / Mistral, or a self-hosted model later — must
be a config change, never a code change.

How that's achieved: every provider below speaks the SAME "OpenAI-compatible"
API, so we use the standard `openai` Python client and only change three things,
all read from environment variables (never hardcoded):

    LLM_BASE_URL   the provider's endpoint   (Groq: https://api.groq.com/openai/v1)
    LLM_API_KEY    your secret key           (kept in .env, which is gitignored)
    LLM_MODEL      the model id              (Groq default: llama-3.3-70b-versatile)

Hardware note: this project runs on a 2019 Intel MacBook Pro with no usable GPU,
so the LLM is HOSTED — it runs on the provider's servers and the laptop only makes
a network call. Nothing about the model runs locally.

Default provider = Groq: genuinely free, no credit card, OpenAI-compatible, fast.
Default model = llama-3.3-70b-versatile (a current Groq production model, verified
against console.groq.com/docs/models on 2026-09-23). To switch providers, change
only the env vars — for example, point LLM_BASE_URL at OpenRouter/Gemini/Mistral
and set their key + a model id they host.
"""

import os
import re
import time

from dotenv import load_dotenv
from openai import OpenAI, RateLimitError

# Load variables from a local .env file (if present) into the environment, so
# `os.environ` picks up LLM_BASE_URL / LLM_API_KEY / LLM_MODEL. Safe to call even
# when there's no .env (it just does nothing then).
load_dotenv()

# Sensible defaults for Groq. Only the API KEY has no default — it's a secret and
# must be supplied by the user. Base URL and model can be overridden via env.
#
# Model note: openai/gpt-oss-20b is a current Groq model available on the FREE /
# developer tier (verified against a live free key on 2026-09-23). The larger
# Llama models (e.g. llama-3.3-70b-versatile) exist but sit on a higher Groq tier
# and 404 for free keys — so we default to one that free accounts can actually
# use. Swap via LLM_MODEL: openai/gpt-oss-120b (stronger) or qwen/qwen3.8-27b.
DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "openai/gpt-oss-20b"


class LLMConfigError(RuntimeError):
    """Raised when required LLM configuration (the API key) is missing."""


class LLMClient:
    """A minimal chat wrapper over any OpenAI-compatible provider."""

    def __init__(self) -> None:
        # Read config from the environment (populated from .env above).
        self.base_url = os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL)
        self.model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)
        api_key = os.environ.get("LLM_API_KEY")

        # The key is the one thing we can't default. Fail early with a clear,
        # actionable message rather than a confusing error deep in the API call.
        if not api_key:
            raise LLMConfigError(
                "LLM_API_KEY is not set. Copy .env.example to .env and add your "
                "free Groq key (get one at https://console.groq.com/keys)."
            )

        # The standard OpenAI client, simply pointed at the chosen provider.
        # Because the provider is OpenAI-compatible, this is all it takes.
        self.client = OpenAI(base_url=self.base_url, api_key=api_key)

    def chat(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> str:
        """
        Send one system + user message and return the model's text reply.

        temperature=0.0 keeps the answer focused and repeatable — we want the
        model to stick to the grounded facts we give it, not get creative.

        Free tiers have per-minute limits (Groq free: 8,000 tokens/minute). When
        we hit one, the provider answers "429 — try again in N seconds". Instead
        of crashing, we wait that long and retry (a few times at most).
        """
        max_attempts = 6
        for attempt in range(1, max_attempts + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    temperature=temperature,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                )
                # One choice, its message, its text content.
                return (response.choices[0].message.content or "").strip()
            except RateLimitError as err:
                if attempt == max_attempts:
                    raise
                time.sleep(_retry_delay(err, attempt))
        raise RuntimeError("unreachable")


def _retry_delay(err: RateLimitError, attempt: int) -> float:
    """
    How long to wait after a rate-limit error. Groq's message says e.g.
    "Please try again in 2.04s" — use that (plus a small cushion) when present,
    otherwise back off exponentially: 2s, 4s, 8s, ...
    """
    match = re.search(r"try again in ([\d.]+)s", str(err))
    if match:
        return float(match.group(1)) + 0.5
    return float(2 ** attempt)
