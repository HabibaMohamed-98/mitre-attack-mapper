# CLAUDE.md — MITRE ATT&CK Mapper (RAG project)

> This file orients any AI assistant (and any human) working on this repo.
> It captures the plan, the decisions already made, and the current status.
> Read it before making changes.

---

## What this project is

A from-scratch **RAG (Retrieval-Augmented Generation) system** that maps
security logs to **MITRE ATT&CK techniques** and suggests a response approach.

**The whole project in one line:**
> A log comes in → find the matching ATT&CK technique → write it up (with a suggested mitigation).

This is a clean-room learning + portfolio project. It does **not** depend on any
company systems, any specific SIEM, or any private data. Everything uses open,
public data.

**Built by:** a junior AI engineer doing RAG for the first time. Explanations
should be clear and beginner-friendly. Prefer simple, well-commented code over
clever code. Introduce one concept at a time.

**Hardware:** development is on a **2019 Intel MacBook Pro — no usable GPU**. So:
the LLM must be a FREE hosted API (runs on provider servers, no local GPU). The
only models that run locally are the small, CPU-friendly embedding model and
reranker — those are fine on this machine.

---

## Project requirements (what "done" and "good" mean here)

**Functional (what it must do):**
- Accept a security log line (or short incident description) as input.
- Map it to the correct MITRE ATT&CK technique ID(s), grounded in real ATT&CK data.
- Return: technique ID(s) + the evidence for each + a suggested mitigation
  (mitigations come from ATT&CK's own data, so they're grounded too).

**Non-functional (the constraints / qualities):**
- **Open + self-contained:** only open, public data and tools. No company systems,
  no specific SIEM, no private data, no hard dependency on any paid service.
- **Rooted, not guessing:** every component is a real, mainstream, documented tool.
- **Beginner-buildable:** built in small, independently-testable pieces; the user
  is never overwhelmed or building on an unproven piece.
- **Swappable LLM:** the LLM is behind a thin interface so it can be replaced
  (incl. a self-hosted open model) without touching the rest of the system.
- **Grounded + honest:** answers use only retrieved real IDs and always cite
  evidence; the system never invents technique codes.
- **Production-minded, not production-first:** choices should be reasonable for a
  real environment, but v1 optimizes for learning + a working local system.
- **Deploy is optional:** a fully working, evaluated LOCAL system is the real goal;
  deploying (for sharing) is a stretch goal, kept as simple as possible.

---

## Core concepts (shared vocabulary)

- **RAG** = instead of the LLM answering from memory, we first *retrieve* the
  relevant reference text, then let the LLM answer *using* that text. Open-book
  exam, not closed-book. Reduces hallucination and lets us cite sources.
- **MITRE ATT&CK** = a free, public catalog of attacker techniques, each with an
  ID (e.g. `T1003`), a name (e.g. "OS Credential Dumping"), and a description.
- **"Mapping"** = tagging an incoming log with the correct ATT&CK technique ID(s).
- **Retrieve** = grab a wide pile of maybe-relevant techniques (fast, rough).
- **Rerank** = carefully sort that pile and keep the best few (slower, sharper).
- **Hybrid search** = run BOTH keyword search (exact terms like `T1003`, `LSASS`)
  AND semantic/vector search (meaning, so "stole passwords" matches "credential
  dumping"), then merge. Each covers the other's blind spot.
- **Embedding** = turning text into a list of numbers that captures its meaning,
  so similar meanings sit close together. Powers semantic search.
- **Grounding rule** = the LLM must label using ONLY the retrieved technique IDs,
  and cite the evidence. This is what stops it inventing fake technique codes.

---

## Two different models do two different jobs (important!)

A RAG system uses TWO separate kinds of AI model. They are NOT interchangeable:

1. **Embedding model** — turns text into number-lists so we can SEARCH BY MEANING.
   It does the *retrieving*. It does NOT read or write answers. Small, cheap,
   runs locally. Used to index all techniques (setup) and to search (per log).
2. **LLM** (the big GPT/Claude/Llama kind) — READS the log + retrieved techniques
   and WRITES the final grounded answer. It does the *reasoning/writing*.

> Embedding model = does the searching. LLM = does the explaining. Need both.

This is why the checkpoints split the way they do:
- Checkpoints 1–2 = the SEARCH half (embedding model + reranker). Works and is
  testable with NO LLM at all.
- Checkpoint 3 = adds the LLM on top.

## Open-source LLM / production path

Self-hosting an open LLM is a legitimate production choice, but it needs a GPU —
and this project is built on a **2019 Intel MacBook Pro with no usable GPU**. So
we use a **FREE, hosted, OpenAI-compatible LLM API**, where the model runs on the
provider's servers and the laptop just makes a network call.

**Default: Groq** (free, no credit card, fast, OpenAI-compatible, hosts open
models). Free alternatives, all OpenAI-compatible and swappable: Google Gemini,
OpenRouter, Mistral.

The local pieces (embedding model + reranker) are small and CPU-friendly — they
run fine on this laptop (indexing all techniques takes a couple of minutes). Only
the big LLM is hosted.

Path:
- Checkpoint 3: use the free hosted endpoint via the OpenAI-compatible client.
- Later/optional: self-host an open model (vLLM/Ollama, also OpenAI-compatible) by
  changing only the base URL — but that needs better hardware, so it stays optional.
The OpenAI-compatible wrapper is what makes any of these a one-line change.

## Architecture (kept deliberately simple)

Two phases, standard for all RAG:

### Phase A — Setup (run once, offline): build the searchable library
1. Download MITRE ATT&CK STIX data.
2. Extract each technique: ID, name, description, tactic, linked mitigations.
3. Build one clean text snippet per technique.
4. Embed each snippet (locally) and load into a store that supports hybrid search.

### Phase B — Runtime (per log): answer
1. Take a log line → turn it into a plain-language behavior description.
2. **Retrieve** candidate techniques via **hybrid search**.
3. **Rerank** to the best few.
4. **Generate**: give the LLM the log + top techniques + their mitigations, with
   the grounding rule → output technique ID(s) + evidence + suggested mitigation.

---

## Tech decisions (already made — don't re-litigate without reason)

- **Language:** Python. (Python is installed; user has used it a bit.)
- **ATT&CK data:** official MITRE STIX 2.1 data. Use the Enterprise domain file
  `enterprise-attack.json`. Load it with MITRE's official Python tooling
  (`mitreattack-python`) rather than hand-parsing raw JSON.
- **Embeddings:** local / open-source (`sentence-transformers` family). Free, no
  API key, runs on a normal machine.
- **Reranker:** local / open-source cross-encoder (`sentence-transformers`). Free.
- **LLM (final answer writer):** a **FREE, hosted, OpenAI-compatible** LLM API.
  Hosted = the model runs on the provider's servers, so NO GPU is needed locally
  (important: this is built on a 2019 Intel MacBook Pro with no usable GPU).
  **Default: Groq** — genuinely free, no credit card, OpenAI-compatible endpoint
  (`https://api.groq.com/openai/v1`), fast, generous limits (~30 req/min,
  ~14,400/day), hosts open-weight models (Llama etc.). Drop-in free alternatives
  (also OpenAI-compatible): Google Gemini, OpenRouter (`:free` models), Mistral.
  Use the standard OpenAI client library, just pointed at the chosen endpoint.
  Config via env vars: base URL, API key, model name. Model IDs change — confirm
  a current one in the provider's docs rather than hardcoding from memory.
  Because it's OpenAI-compatible, swapping providers — or LATER self-hosting an
  open model (vLLM/Ollama, also OpenAI-compatible) — is a base-URL change only.
  (Self-hosting on this laptop would be slow/CPU-only, so it stays optional.)
- **Vector + keyword store:** a store that does BOTH so hybrid search is easy.
  (Specific choice TBD when we reach that checkpoint.)
- **API layer:** FastAPI (later checkpoint).
- **Deploy:** Docker container → simple host (later checkpoint).

---

## Build order — FOUR CHECKPOINTS (each works before moving on)

Build ONE checkpoint at a time. Verify it works. Then move on. Never build on
an unproven piece. When something breaks, it's in the piece just added.

- [x] **Checkpoint 1 — The library.** Download ATT&CK STIX → extract techniques →
      build clean snippets → embed → load into a hybrid-search store.
      *Done when:* a manual search returns relevant techniques. ✅ 2026-09-23
- [x] **Checkpoint 2 — Retrieval core.** Log in → hybrid search → rerank → clean
      top 3. *Done when:* pasting a sample log reliably surfaces the right
      technique. (Testable with NO LLM — proves retrieval before generation.)
      ✅ 2026-09-23
- [x] **Checkpoint 3 — Generation.** Log + top techniques + mitigations → LLM
      (hosted, wrapped) with grounding rule → mapping + evidence + mitigation.
      *Done when:* a log in gives a complete grounded answer out (command line).
      ✅ 2026-09-23
- [ ] **Checkpoint 4 — API + UI + deploy.** FastAPI wrapper + minimal web page +
      Docker → deployed to a URL. *Done when:* it's live and shareable.
      **OPTIONAL / STRETCH GOAL — save for last.** See "Deploy vs. eval" below.

### Deploy vs. eval (DIFFERENT things — don't confuse them)
- **Eval = checking answer QUALITY** (log in → answer out → is it right?).
  Runs ENTIRELY LOCALLY, from the terminal. No server, no URL, no cloud.
  You do NOT deploy to evaluate.
- **Deploy = making it reachable by OTHERS at a URL.** About access, not quality.
  Adds nothing to understanding whether it works. Optional, last, portfolio-only.
- **How to eval locally (simple):** feed in a log, read the answer, check it.
  Grown-up version: a small list of example logs with KNOWN correct techniques,
  run them all, count how many are right. Still 100% local.
- Guidance: get local end-to-end working + evaluated FIRST. Deploy only if/when
  the user wants a shareable version, using the simplest path.

### Phase two (after the four checkpoints, on a system we fully understand)
- Agentic upgrade: let the LLM control its own retrieve→check→re-search loop.
- Evaluation tooling: measure RETRIEVAL quality and GENERATION quality
  SEPARATELY (so we know which half to fix when an answer is wrong).

---

## Open data sources (no company dependencies)

- **Retrieval knowledge base:** MITRE ATT&CK STIX 2.1 data (public, MITRE GitHub).
- **Sample logs to map (input) — PROVIDED:** `sample_logs.json` in the repo is a
  labelled test set (18 synthetic-but-representative log lines, each with the
  correct ATT&CK ID). Use it for the eval in Prompt 5 / Checkpoint 5. It is
  clearly marked synthetic — good for functional testing, not a published benchmark.
- **Real raw datasets (for later / more volume):**
  - EVTX-ATTACK-SAMPLES: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
  - OTRF Security-Datasets (Mordor): https://github.com/OTRF/Security-Datasets
  - Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
  - Splunk Attack Data: https://github.com/splunk/attack_data

---

## Principles

- Rooted, not guessing: every component is a real, mainstream, documented tool.
- One small verifiable piece at a time. Keep the user oriented, not overwhelmed.
- Retrieval is proven before generation is added.
- The LLM stays swappable (no lock-in; clear path to fully-local later).
- Grounding rule always on: real IDs only, always cite evidence.

## Current status
- Planning complete.
- [x] **Checkpoint 1a — Load ATT&CK data.** Project scaffolding (src/, scripts/,
      data/, requirements.txt, README, .gitignore) + `scripts/load_attack_data.py`,
      which downloads the Enterprise STIX 2.1 file and prints techniques
      (ID — name — description) via `mitreattack-python`. Verified: 697 active
      techniques load and print. Done 2026-09-23.
- [x] **Checkpoint 1 (Phase A complete) — The searchable library.** Modular
      pipeline in src/ (attack_data → snippets → embedder → vector_store) plus
      scripts/build_index.py (repeatable) and scripts/search.py (manual query).
      Embeddings: all-MiniLM-L6-v2 (local, CPU). Store: LanceDB (embedded;
      vector + BM25 keyword in one, ready for hybrid). Verified: 697 techniques
      indexed; manual search for an LSASS-dumping log returns T1003.001 #1 with
      grounded mitigations. Done 2026-09-23.
- [x] **Checkpoint 2 — Retrieval core.** src/ modules: hybrid_search.py
      (semantic + BM25 keyword search fused with Reciprocal Rank Fusion → ~10
      candidates), reranker.py (local cross-encoder ms-marco-MiniLM-L-6-v2, small
      + CPU-only → top 3), retrieval.py (orchestrates), plus a light
      normalize_query() that strips log punctuation. Entry point:
      scripts/retrieve.py. Verified: LSASS/mimikatz→T1003.001, /etc/shadow→
      T1003.008, rundll32→T1218.011 all return correct #1. Reranker lifts top-1
      from 3/17 to 6/17 vs fusion alone. Done 2026-09-23.
      Honest note: strong on behaviour descriptions; partial on raw noisy SIEM
      logs (~top-3 40% on the hardest labelled logs). Closing that gap is the
      Phase B "log → plain-language behaviour" step (later, uses the LLM).
      Kept small CPU-only models per spec (a heavier reranker was too slow here).
- [x] **Checkpoint 3 — Generation.** src/ modules: llm.py (thin, swappable
      OpenAI-compatible wrapper; reads LLM_BASE_URL / LLM_API_KEY / LLM_MODEL from
      .env; provider = Groq), prompt.py (builds the grounded prompt + grounding
      rule: use ONLY retrieved IDs, cite log evidence, mitigation from provided
      ones), pipeline.py (retrieve → prompt → LLM). Entry point:
      scripts/analyze_log.py. Config: .env (gitignored) + .env.example template.
      Model: openai/gpt-oss-20b (Groq free tier — the big Llama models 404 on
      free keys). Verified end-to-end on 4 logs: T1003.001, T1490, T1053.005,
      T1136.001 — each returned technique + quoted evidence + real M-code
      mitigation. Done 2026-09-23.
- Full local pipeline (Phase A + B) now works end-to-end with no LLM lock-in.
- [x] **Local eval (Phase two, first piece).** src/evaluation.py (pure scoring:
      extract predicted IDs, exact vs family match) + scripts/evaluate.py (runs
      all 18 sample_logs.json entries; reports RETRIEVAL and GENERATION
      separately; `--no-llm` = retrieval only). Baseline 2026-09-24:
      retrieval recall@10 8/17, rerank@1 6/17, rerank@3 7/17; generation exact
      7/17, family 8/17; benign control → no technique asserted (correct).
      Finding: the LLM picks correctly every time the right technique is in the
      top 3 — the bottleneck is RETRIEVAL recall on noisy raw logs, not generation.
- Next (not started): improve retrieval recall (e.g. enrich snippets with ATT&CK
  procedure examples, or a log → behaviour normalization step), re-run eval to
  compare. Checkpoint 4 (API + UI + deploy) remains OPTIONAL / stretch.
