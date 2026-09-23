# MITRE ATT&CK Mapper (RAG project)

A from-scratch **RAG** (Retrieval-Augmented Generation) system that maps security
logs to **MITRE ATT&CK** techniques and suggests a grounded response.

> A log comes in → find the matching ATT&CK technique → write it up (with a suggested mitigation).

This is a clean-room learning + portfolio project built on open, public data only.
The full plan, decisions, and checkpoint status live in [`CLAUDE.md`](CLAUDE.md).

**Status:** Checkpoint 2 complete — the retrieval core works (log in → hybrid
search → rerank → top 3), with NO LLM yet. The LLM (grounded answer writer) comes
in Checkpoint 3.

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
│   └── retrieval.py    # Checkpoint 2: log -> hybrid search -> rerank -> top 3
├── scripts/            # Runnable helper scripts you invoke by hand
│   ├── load_attack_data.py  # Checkpoint 1a: download + print ATT&CK techniques
│   ├── build_index.py       # Checkpoint 1: build the searchable index
│   ├── search.py            # Checkpoint 1: manual similarity search
│   └── retrieve.py          # Checkpoint 2: log in -> top-3 techniques out
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
- **Note on inputs:** cleaner *behaviour descriptions* ("mimikatz read lsass
  memory") retrieve more accurately than raw, noisy SIEM logs. Turning a raw log
  into a plain-language behaviour description is a later step (Phase B / the LLM),
  which lifts accuracy on raw logs further.
