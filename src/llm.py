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

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Optional

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

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        """
        `cache_dir` (optional): if given, every request/response pair is saved
        there and identical requests are answered from disk instead of the API.
        The eval uses this so that (a) re-running it only pays for calls that
        changed, (b) a run interrupted by a rate limit resumes for free, and (c)
        results are exactly repeatable. Normal use (analyze_log.py) leaves it off.
        """
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

        self.cache_dir = cache_dir
        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)

        # Running totals, so callers can see how much quota a run used.
        self.tokens_used = 0      # tokens actually billed by the provider
        self.api_calls = 0
        self.cache_hits = 0

    def chat(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> str:
        """
        Send one system + user message and return the model's text reply.

        temperature=0.0 keeps the answer focused and repeatable — we want the
        model to stick to the grounded facts we give it, not get creative.

        Free tiers have per-minute limits (Groq free: 8,000 tokens/minute). When
        we hit one, the provider answers "429 — try again in N seconds". Short
        waits we sit out and retry; a long wait means the DAILY limit is used up,
        so we stop right away with a clear message instead of retrying pointlessly.
        """
        cache_file = self._cache_path(system_prompt, user_prompt, temperature)
        if cache_file is not None and cache_file.exists():
            self.cache_hits += 1
            return json.loads(cache_file.read_text())["reply"]

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
                break
            except RateLimitError as err:
                delay = _retry_delay(err, attempt)
                if attempt == max_attempts or delay > MAX_RATE_LIMIT_WAIT:
                    raise LLMQuotaError(
                        f"Rate limit reached for {self.model} (the provider asks to "
                        f"wait ~{delay:.0f}s). On Groq's free tier this usually "
                        "means the per-day token quota is used up; it frees up "
                        "gradually over a rolling 24 hours."
                    ) from err
                time.sleep(delay)

        # One choice, its message, its text content.
        reply = (response.choices[0].message.content or "").strip()
        self.api_calls += 1
        if response.usage is not None:
            self.tokens_used += response.usage.total_tokens

        if cache_file is not None:
            cache_file.write_text(json.dumps({"model": self.model, "reply": reply}))
        return reply

    def _cache_path(self, system_prompt: str, user_prompt: str, temperature: float):
        """A file name unique to this exact request (provider, model, prompts)."""
        if self.cache_dir is None:
            return None
        key = json.dumps([self.base_url, self.model, temperature, system_prompt, user_prompt])
        return self.cache_dir / (hashlib.sha256(key.encode()).hexdigest() + ".json")


# Waits longer than this aren't a per-minute hiccup — they mean the daily quota is
# exhausted, so there's no point sitting and retrying.
MAX_RATE_LIMIT_WAIT = 60.0


class LLMQuotaError(RuntimeError):
    """Raised when the provider's rate limit won't clear within a short wait."""


def _retry_delay(err: RateLimitError, attempt: int) -> float:
    """
    How long to wait after a rate-limit error. Groq's message says e.g.
    "Please try again in 2.04s" or "... in 6m56.02s" — use that (plus a small
    cushion) when present, otherwise back off exponentially: 2s, 4s, 8s, ...
    """
    match = re.search(r"try again in (?:(\d+)h)?(?:(\d+)m)?([\d.]+)s", str(err))
    if match:
        hours, minutes, seconds = match.groups()
        return int(hours or 0) * 3600 + int(minutes or 0) * 60 + float(seconds) + 0.5
    return float(2 ** attempt)
