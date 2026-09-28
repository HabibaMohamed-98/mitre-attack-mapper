# MITRE ATT&CK Mapper (RAG project)

A from-scratch **RAG** (Retrieval-Augmented Generation) system that maps security
logs to **MITRE ATT&CK** techniques and suggests a grounded response.

> A log comes in → find the matching ATT&CK technique → write it up (with a suggested mitigation).

This is a clean-room learning + portfolio project built on open, public data only.
The full plan, decisions, and checkpoint status live in [`CLAUDE.md`](CLAUDE.md).

**Status:** Checkpoint 3 complete — the full pipeline works end-to-end: a log line
goes in, and a grounded answer comes out (technique ID(s) + evidence + suggested
mitigation), written by a free hosted LLM. Checkpoint 4 (API + UI + deploy) is
optional/last.

## Project layout

```
mitre-attack-mapper/
├── CLAUDE.md            # The project brief: plan, decisions, checkpoint status
├── README.md           # This file
├── requirements.txt    # Python dependencies (pinned; grows each checkpoint)
├── sample_logs.json    # Labelled test logs, used for eval in a later checkpoint
├── src/                # Reusable library code (imported by scripts)
│   ├── attack_data.py  # Extract techniques (id, name, desc, tactics, mitigations)
│   ├── snippets.py     # Turn a technique into one searchable text snippet
│   ├── embedder.py     # Local embedding model (all-MiniLM-L6-v2)
│   ├── vector_store.py # LanceDB hybrid store: vector + keyword search
│   ├── hybrid_search.py# Checkpoint 2: semantic + keyword search fused with RRF
│   ├── reranker.py     # Checkpoint 2: local cross-encoder reranker
│   ├── retrieval.py    # Checkpoint 2: log -> hybrid search -> rerank -> top 3
│   ├── llm.py          # Checkpoint 3: swappable OpenAI-compatible LLM wrapper
│   ├── prompt.py       # Checkpoint 3: builds the grounded prompt (grounding rule)
│   └── pipeline.py     # Checkpoint 3: retrieve -> prompt -> LLM -> answer
├── scripts/            # Runnable helper scripts you invoke by hand
│   ├── load_attack_data.py  # Checkpoint 1a: download + print ATT&CK techniques
│   ├── build_index.py       # Checkpoint 1: build the searchable index
│   ├── search.py            # Checkpoint 1: manual similarity search
│   ├── retrieve.py          # Checkpoint 2: log in -> top-3 techniques out
│   └── analyze_log.py       # Checkpoint 3: log in -> full grounded answer out
├── .env.example        # Template for LLM config (copy to .env, add your key)
└── data/               # Downloaded STIX + built index (git-ignored; rebuildable)
```

- **`scripts/`** = things you *run* directly to do a job.
- **`src/`** = shared building blocks that scripts (and later the API) import.
  Extraction (`attack_data.py`) is kept separate from indexing (`vector_store.py`)
  so each is testable on its own.
- **`data/`** = the downloaded ATT&CK STIX file and the built LanceDB index. Both
  are large and rebuildable, so they're git-ignored.

## How it works (Phase A — the searchable library)

```
extract techniques  ->  build one text snippet each  ->  embed locally  ->  index
(attack_data.py)        (snippets.py)                    (embedder.py)      (vector_store.py)
```

- **Embedding model:** `all-MiniLM-L6-v2` — small (~80 MB), fast, CPU-friendly
  sentence-transformers model; a strong general-purpose default that runs well on
  this no-GPU Intel Mac. Produces 384-dim vectors.
- **Store:** `LanceDB` — a mainstream, embedded (no server/Docker) open-source
  store that does BOTH vector (semantic) search AND full-text keyword search
  (BM25) in one table — exactly what hybrid search needs next checkpoint.

## Setup

Requires Python 3 (developed on 3.11). From the project root:

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Run

**1. (Checkpoint 1a) Download + preview the ATT&CK data:**

```bash
./venv/bin/python scripts/load_attack_data.py
```

First run downloads the Enterprise STIX 2.1 data into `data/` (~35 MB, one time)
and prints a few real techniques. Later runs reuse the file.

**2. (Checkpoint 1) Build the searchable index:**

```bash
./venv/bin/python scripts/build_index.py
```

Extracts all techniques, builds a snippet each, embeds them locally (first run
downloads the ~80 MB model), and writes the LanceDB index. Prints how many were
indexed (697). Re-running overwrites cleanly.

**3. (Checkpoint 1) Try a manual search:**

```bash
./venv/bin/python scripts/search.py "someone dumped LSASS memory to steal passwords"
```

Embeds your query and returns the closest techniques by meaning (plus the top
keyword hit). No LLM involved — this is pure retrieval.

**4. (Checkpoint 2) Map a log line to its top-3 techniques:**

```bash
./venv/bin/python scripts/retrieve.py "Sysmon EventID 4698 a scheduled task was created to run a program at logon"
```

Runs the full retrieval core: normalize the log → **hybrid search** (semantic +
keyword, fused with Reciprocal Rank Fusion) → **rerank** with a local
cross-encoder → the 3 best techniques with scores. Still no LLM. Run with no
argument for an interactive prompt.

### How the retrieval core works

```
log line ─▶ normalize ─▶ hybrid search (top ~10) ─▶ rerank ─▶ top 3
                          ├─ semantic (meaning)      cross-encoder
                          └─ keyword (BM25)          (reads log+technique together)
                          fused with RRF
```

- **Reranker:** `cross-encoder/ms-marco-MiniLM-L-6-v2` — small, CPU-friendly.
- **Query rewrite (full pipeline only):** raw logs and ATT&CK use different words
  ("Logon Type: 10" vs "Remote Desktop Protocol"). In `analyze_log.py` and the
  full eval, the LLM first rewrites the log into a plain-language behaviour
  description (no technique IDs allowed), and search runs on the log AND the
  description together. The LLM then chooses from the top 5 candidates.
  `retrieve.py` stays fully local and skips this step.

**5. (Checkpoint 3) Full pipeline — grounded answer from the hosted LLM:**

One-time setup (get a **free** Groq key — no credit card):

```bash
cp .env.example .env
# then edit .env and paste your key:  LLM_API_KEY=gsk_...
```

Get the key at <https://console.groq.com/keys>. Then run:

```bash
./venv/bin/python scripts/analyze_log.py "Sysmon EventID 10 ProcessAccess SourceImage=mimi.exe TargetImage=lsass.exe"
```

It retrieves the top techniques, then asks the LLM to write a **grounded** answer:
technique ID(s), the exact evidence quoted from the log, and a suggested
mitigation — using ONLY the retrieved real ATT&CK data (it never invents codes).

### The LLM is swappable (no lock-in)

The LLM lives behind a thin wrapper ([src/llm.py](src/llm.py)) that speaks the
standard OpenAI-compatible API. Switching providers is an **env-var change only**
(no code change) — set `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` in `.env`:

| Provider | `LLM_BASE_URL` | Example model |
|---|---|---|
| **Groq** (default) | `https://api.groq.com/openai/v1` | `openai/gpt-oss-20b` (free tier) |
| OpenRouter | `https://openrouter.ai/api/v1` | a `:free` model |
| Mistral | `https://api.mistral.ai/v1` | `mistral-small-latest` |
| Gemini | `https://generativelanguage.googleapis.com/v1beta/openai/` | `gemini-3.5-flash` (free tier: ~20 requests/day) |

The model runs on the **provider's servers**, so no GPU is needed on this laptop.

**6. Evaluate against the labelled logs (local):**

```bash
./venv/bin/python scripts/evaluate.py            # retrieval + generation
./venv/bin/python scripts/evaluate.py --no-llm   # retrieval only, no API key
```

Runs every log in `sample_logs.json` and reports **retrieval** (is the right
technique in the candidates / top 3 / #1?) and **generation** (does the LLM's
answer name it?) separately, so a wrong answer points to the half to fix. The
data is synthetic — use the numbers to compare changes, not as a benchmark.

**7. Use it in a browser (local web app):**

```bash
./venv/bin/uvicorn src.api:app --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>, paste a log line, and click **Analyze**
(or press Cmd/Ctrl+Enter). The first request takes longer because it loads the
models. Stop the server with Ctrl+C.

- `src/api.py` — FastAPI app. It adds no mapping logic: it calls the same
  `MappingPipeline` as `analyze_log.py`. Routes: `GET /` (the page),
  `POST /analyze` with `{"log": "..."}` (returns JSON), `GET /health`.
- `src/answer_parser.py` — turns the LLM's text answer into structured
  `techniques` (ID, name, evidence, mitigation) and re-checks the grounding rule:
  any ID not among the retrieved options is flagged `grounded: false`.
- `web/index.html` — the single page. Everything from the log and the LLM is
  shown as plain text (never as HTML).

It uses the same Groq quota as everything else (about 5k tokens per log).
