# MITRE ATT&CK Mapper (RAG project)

A from-scratch **RAG** (Retrieval-Augmented Generation) system that maps security
logs to **MITRE ATT&CK** techniques and suggests a grounded response.

> A log comes in → find the matching ATT&CK technique → write it up (with a suggested mitigation).

This is a clean-room learning + portfolio project built on open, public data only.
The full plan, decisions, and checkpoint status live in [`CLAUDE.md`](CLAUDE.md).

**Status:** Checkpoint 1 complete — the searchable library is built (extract →
snippet → embed → hybrid-search index). Retrieval logic, reranker, and the LLM
come in later checkpoints.

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
│   └── vector_store.py # LanceDB hybrid store: vector + keyword search
├── scripts/            # Runnable helper scripts you invoke by hand
│   ├── load_attack_data.py  # Checkpoint 1a: download + print ATT&CK techniques
│   ├── build_index.py       # Checkpoint 1: build the searchable index
│   └── search.py            # Checkpoint 1: manual similarity search
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
