"""
api.py — a small web service around the pipeline (Checkpoint 4, local only).

Two routes:
  GET  /          the web page (web/index.html): paste a log, see the answer
  POST /analyze   {"log": "..."}  ->  the grounded answer as JSON
  GET  /health    quick "is it up, and which model?" check

This file adds NO mapping logic of its own. It just calls MappingPipeline (the
same one scripts/analyze_log.py uses) and turns its output into JSON. If you
change how mapping works, you change src/pipeline.py and friends — not this.

Run locally:
  ./venv/bin/uvicorn src.api:app --host 127.0.0.1 --port 7860
then open http://127.0.0.1:7860
"""

import os
import time
from pathlib import Path

# Must be set before any tokenizer loads (avoids a noisy warning under uvicorn).
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from openai import APIConnectionError, APIStatusError, AuthenticationError
from pydantic import BaseModel, Field

from src.answer_parser import parse_answer
from src.llm import LLMConfigError, LLMQuotaError
from src.pipeline import MappingPipeline

WEB_PAGE = Path(__file__).parent.parent / "web" / "index.html"

# Keep requests log-line sized: protects the free LLM quota and keeps prompts small.
MAX_LOG_CHARS = 4000

app = FastAPI(title="MITRE ATT&CK Mapper", version="0.1")

# The pipeline loads three local models + the index (~10 s), so we build it ONCE,
# on the first request, and reuse it. None until then.
_pipeline: MappingPipeline | None = None


def get_pipeline() -> MappingPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = MappingPipeline()
    return _pipeline


class AnalyzeRequest(BaseModel):
    log: str = Field(..., description="One security log line or short incident description")


@app.get("/")
def index() -> FileResponse:
    """Serve the single web page."""
    return FileResponse(WEB_PAGE)


@app.get("/health")
def health() -> dict:
    """Is the service up, and which LLM is configured? (Does not call the LLM.)"""
    return {"status": "ok", "model": os.environ.get("LLM_MODEL", "default"),
            "pipeline_loaded": _pipeline is not None}


# A plain `def` (not `async def`): the pipeline is slow, blocking work, and FastAPI
# runs plain functions in a worker thread so the server stays responsive.
@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    """Map one log line to ATT&CK technique(s) + evidence + mitigation."""
    log = request.log.strip()
    if not log:
        raise HTTPException(400, "Please paste a log line.")
    if len(log) > MAX_LOG_CHARS:
        raise HTTPException(400, f"Log is too long (max {MAX_LOG_CHARS} characters).")

    started = time.time()
    # Turn the known failure modes into clear messages instead of a stack trace.
    try:
        result = get_pipeline().run_detailed(log)
    except LLMConfigError as err:
        raise HTTPException(503, f"LLM not configured: {err}")
    except AuthenticationError:
        raise HTTPException(503, "The LLM provider rejected the API key. Check LLM_API_KEY in .env.")
    except LLMQuotaError as err:
        raise HTTPException(429, str(err))
    except APIConnectionError:
        raise HTTPException(503, "Could not reach the LLM provider. Check the internet connection.")
    except APIStatusError as err:
        raise HTTPException(502, f"The LLM provider returned an error: {err.status_code}")

    candidates = result["candidates"]
    techniques = parse_answer(result["answer"], candidates)
    return {
        "log": log,
        "techniques": techniques,                  # [] means "no technique fits"
        "understood_as": result["description"],    # the plain-language rewrite
        "candidates": [                            # the real ATT&CK options it chose from
            {"technique_id": c["attack_id"], "name": c["name"], "tactics": c["tactics"]}
            for c in candidates
        ],
        "raw_answer": result["answer"],            # the LLM's full text, nothing hidden
        "seconds": round(time.time() - started, 1),
    }
