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
      Progress: API + web page done and working LOCALLY (2026-09-28).
      Not yet: Docker, deploy.

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
      Run: `./venv/bin/python scripts/evaluate.py` (add `--no-llm` for retrieval
      only). Answer parsing counts only the ID right after "Technique:", so an
      explicit "Technique: None" stays a no-match (re-verified 2026-09-24, same
      scores).
- [x] **Accuracy improvements (2026-09-24).** Guided by the eval, each change
      general (not keyed to specific test logs):
      1. Index text cleanup (snippets.clean_description): strip citations,
         markdown links, <code> tags; file paths -> file name. Rebuilt index.
      2. Query cleanup (normalize_query): file paths -> file name (drive letter
         required, so registry keys stay intact). Stopped path-heavy techniques
         (e.g. T1546.008) matching every Windows log.
      3. Phase B step 1 — src/query_rewriter.py: the LLM rewrites the log into a
         plain-language behaviour description (NO technique IDs; any that slip
         through are stripped). Retrieval searches with the log AND the
         description (search_many, fused with RRF); rerank uses the description.
      4. The LLM now chooses from the top 5 reranked candidates (was 3).
      5. Eval credits MITRE's official replacement for revoked IDs
         (attack_data.revoked_replacements; T1070.001 -> T1685.005).
      6. Robustness: llm.chat retries on 429 rate limits; prompt trims each
         candidate description to ~600 chars (Groq free tier = 8,000 tokens/min).
      Result (full eval): recall@10 8→13/17, shown@5 →13/17, generation exact
      7→13/17, family 8→14/17, benign still correctly unmapped. Local-only
      (--no-llm) recall@10 11/17. Cost: 2 LLM calls per log (rewrite + answer).
      Remaining misses: T1059.003 (LLM picked T1033 discovery — defensible),
      T1048 and T1112 (not retrieved), T1055 (sub-technique T1055.002 chosen).
      Caveat: 17 synthetic logs, and they guided these changes — validate on
      new labelled data (e.g. Atomic Red Team) before trusting the numbers.
- [~] **Second accuracy round (2026-09-24) — full-LLM eval NOT yet scored**
      (Groq free daily quota, 200k tokens/day for gpt-oss-20b, ran out mid-run).
      General fixes for the remaining misses:
      1. Parent techniques: search adds the parent of any retrieved sub-technique
         (HybridSearcher._add_missing_parents), and the LLM is shown the parent of
         any shown sub-technique (retrieval._keep_parents_visible, up to 2 extra).
      2. Rewrite prompt covers MECHANISM / OPERATION / PURPOSE, ≤80 words.
      3. Grounding rules 6–7: sub-technique only with sub-technique-specific
         evidence, else the parent; primary technique listed first.
      4. Eval: strict "primary" score (the LLM's first pick must be right).
      5. Quota tooling: eval caches LLM answers in data/llm_cache/ (gitignored;
         reruns and interrupted runs are free), reports tokens used; LLMQuotaError
         stops immediately on a daily-limit 429 instead of retrying.
      Verified so far (local, no LLM): shown-to-LLM 9 → 11/17.
      Honesty note: these fixes were chosen by studying the same 17 logs, so
      scores on them are optimistic — the real test is fresh, unseen labelled logs.
- [x] **Held-out eval (2026-09-27) — the honest numbers.** Pipeline frozen at
      commit 0a5386f (src/ untouched). scripts/build_heldout_set.py builds
      data/heldout_atomic.json from Atomic Red Team (atomics/Indexes/index.yaml,
      sha256 08f8bd07…, seed 42): one random command-line test per technique,
      turned into a process-creation line, technique IDs + Atomic folder names
      scrubbed (0 leaks). 341 samples. Eval: `--samples`, `--limit`, `--no-table`.
      Results (unseen data):
        search only, all 341: recall@10 49%, shown to LLM 31%, rerank@1 13%.
        full system, random 25: recall@10 17/25, shown 10/25, primary exact
        6/25 (24%), right family 9/25 (36%). 50 calls, ~88k Groq tokens.
      Compare: 13/17 (76%) on sample_logs.json, which guided the design —
      that number was optimistic. On unseen data the weakest link is the
      RERANKER (right technique found for 68% but shown to the LLM for 40%),
      then the LLM (picked correctly 6 of the 10 times it was shown).
      Caveats: 25 is a small sample (±~15%); inputs are bare command lines
      across 341 techniques incl. obscure ones — harder than typical SIEM logs.
      RULE: don't tune on this set. Any change must be judged on a NEW draw
      (different seed), and this seed-42 set then counts as seen.
- [x] **Improvement round on a DEV set (2026-09-27), no LLM quota used.**
      Builder now takes `--seed/--out/--exclude` and skips Atomic tests used by
      other sets (91 techniques have only one test, so a new seed alone would
      repeat them). Sets (zero overlap between any two):
        data/heldout_atomic.json  seed 42, 341 — used, now "seen"
        data/dev_atomic.json      seed 7,  250 — for trying changes
        data/test_atomic.json     seed 99, 193 — LOCKED, run once at the end
      Two fixes, measured search-only on the dev set:
        1. LLM sees top 10 candidates (pipeline.DEFAULT_TOP_K 5 -> 10).
        2. Keyword index includes MITRE's real-world procedure examples
           (attack_data._extract_examples -> snippets.build_keyword_text ->
           vector_store "keyword_text" column; FTS index moved to it, capped at
           2,500 chars/technique). Embedding, reranker and LLM prompt still use
           the plain snippet ("text").
      Dev results: right technique found 46% -> 52%; reaches the LLM 28% ->
      40% (fix 1) -> 45% (both). sample_logs local: shown 11 -> 13/17.
      Cost: answer prompts are larger (10 candidates).
- [x] **Test-set result (2026-09-27), system at commit 23be006.** The locked
      test set was split (first half of the builder-shuffled file):
        data/test_now_atomic.json  97 logs — evaluated now (now "seen")
        data/reserve_atomic.json   96 logs — RESERVED, never run/opened; keep
                                   for a final pre-production check
      Search only (no LLM), all 97: found 62%, reaches the LLM 54%.
      Same random 30, no LLM vs full system:
        found:            17/30 (57%)  ->  23/30 (77%)   (LLM rewrite helps search)
        reaches the LLM:  17/30 (57%)  ->  22/30 (73%)
        LLM main pick exactly right:        7/30 (23%)
        right ID anywhere in the answer:   11/30 (37%)
      Finding: the bottleneck MOVED. Search now delivers the answer 73% of the
      time, but the LLM picks it as its main answer only 7 of those 22 times.
      End-to-end exact is still ~1 in 4 (seed-42 run was 6/25 = 24%).
      Cost: 60 calls, ~137k tokens for 30 logs (~4.5k/log with 10 candidates).
- [~] **Why the LLM misses (diagnosed 2026-09-27, replayed from cache, 0 API
      calls).** Of the 15 test_now logs where the right answer was shown but not
      picked: 10 = the LLM named the SHELL (T1059.x PowerShell / cmd / Unix
      shell / Cloud API) instead of what the command does; 4 = debatable labels
      (LLM arguably right, e.g. rc.d script -> RC Scripts); 1 = no answer.
      Root cause: round-2 changes told the rewrite to lead with the MECHANISM
      (interpreter) and the LLM to pick the "core action the log records" —
      added to catch one sample log (cmd.exe), it backfired on unseen data.
      Fix (NOT yet measured):
        - Rewrite prompt leads with ACTION (what the command does) + TOOL; the
          shell is mentioned only if how it was used is itself suspicious.
        - Grounding rule 7 reworded; new rule 8: T1059.x is primary only when
          the interpreter use itself is suspicious (encoded/hidden/Office-
          launched) or nothing else fits.
        - Builder bug fixed: "C:\tools" became "C: ools" (\t read as a tab);
          existing sets repaired IN PLACE by Atomic test ID (same tests,
          reserve not opened; old seed-42 set has 4 unmatched, it's retired).
      Test plan (needs Groq quota): old prompts (commit 23be006, via a git
      worktree) vs new prompts on the SAME first 20 dev_atomic.json logs,
      ~180k tokens total. Judge on dev, not test_now (test_now was studied).
- [x] **End-to-end run after the shell fix (2026-09-27).** gpt-oss-120b (set per
      run via LLM_MODEL env var; .env still says gpt-oss-20b), first 20 of
      dev_atomic.json (now "seen"), commit 281063a. New eval options:
      `--token-budget N` (stops cleanly before a log once N tokens are used) and
      `--report PATH` (per-log Markdown: log, rewrite, options shown, the LLM's
      full answer, plain-English verdict of WHERE it failed, time, tokens).
      Report: data/reports/dev20_gpt-oss-120b.md (gitignored).
      Result: found 12/20, reaches LLM 10/20, LLM main pick right 5/20 (25%).
      Verdicts: 5 correct, 8 search never found it, 2 ranked too low, 4 LLM
      chose another shown option (+1 right ID but not first). Shell-as-answer
      dropped to 1 of 5 LLM misses (was 10 of 15). ~85k tokens; avg 28 s/log
      (mostly 8k tokens/min rate-limit waits; a single log is ~8–10 s).
      Progress so far: search-only on the same dev logs clearly improved
      (reaches LLM 28% -> 45%), but end-to-end on unseen logs is flat at ~24%
      (24% / 23% / 25% on DIFFERENT logs and models — not directly comparable).
- [x] **Checkpoint 4, part 1 — local web app (2026-09-28).** Runs locally only;
      NOT deployed.
        - src/api.py (FastAPI): GET / (the page), POST /analyze {"log": ...} ->
          JSON {techniques, understood_as, candidates, raw_answer, seconds},
          GET /health. Adds no mapping logic — calls MappingPipeline, built once
          on the first request. Clear errors: empty/oversized log (400, max 4,000
          chars), missing key/auth/network (503), quota (429).
        - src/pipeline.py: new run_detailed() (also returns the rewrite);
          run() now wraps it, so analyze_log.py is unchanged.
        - src/answer_parser.py: LLM text -> {technique_id, technique_name,
          evidence, mitigation_id, mitigation}; re-checks grounding (ID not among
          the shown options -> grounded: false; M-ID not listed for that
          technique -> mitigation_grounded: false). Tolerates **bold**/backticks.
        - web/index.html: single page (paste log, Analyze or Cmd/Ctrl+Enter),
          renders technique/evidence/mitigation, what it understood, the options
          and the raw answer; all text inserted as textContent (no HTML
          injection); light/dark.
        - requirements: fastapi 0.141.1, uvicorn 0.54.0. .claude/ gitignored
          (launch.json has machine-specific paths).
      Run: `./venv/bin/uvicorn src.api:app --host 127.0.0.1 --port 8000`, open
      http://127.0.0.1:8000. Verified: vssadmin example -> T1490 + evidence +
      M1053 in 11 s; error paths return clear messages; no server errors.
      scripts/analyze_log.py re-checked after the refactor: scheduled-task log
      -> T1053.005 + evidence + M1047.
- Next: fair before/after — old code (23be006) on the SAME 20 dev logs with
  gpt-oss-120b (~85k tokens; the "after" answers are cached). Then Checkpoint 4
  part 2 (Docker + deploy), OPTIONAL — only when the user asks.
