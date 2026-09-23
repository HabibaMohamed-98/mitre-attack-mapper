# MITRE ATT&CK Mapper (RAG project)

A from-scratch **RAG** (Retrieval-Augmented Generation) system that maps security
logs to **MITRE ATT&CK** techniques and suggests a grounded response.

> A log comes in → find the matching ATT&CK technique → write it up (with a suggested mitigation).

This is a clean-room learning + portfolio project built on open, public data only.
The full plan, decisions, and checkpoint status live in [`CLAUDE.md`](CLAUDE.md).

**Status:** Checkpoint 1a — loading the ATT&CK data. (Search, embeddings, and the
LLM come in later checkpoints.)

## Project layout

```
mitre-attack-mapper/
├── CLAUDE.md            # The project brief: plan, decisions, checkpoint status
├── README.md           # This file
├── requirements.txt    # Python dependencies (grows each checkpoint)
├── sample_logs.json    # Labelled test logs, used for eval in a later checkpoint
├── src/                # Reusable library code (populated in later checkpoints)
├── scripts/            # Runnable helper scripts you invoke by hand
│   └── load_attack_data.py   # Checkpoint 1a: download + print ATT&CK techniques
└── data/               # Downloaded data (git-ignored; re-downloadable)
```

- **`scripts/`** = things you *run* directly to do a job (download data, later:
  build the index, run a query).
- **`src/`** = shared building blocks that scripts and, later, the API will import.
- **`data/`** = the downloaded ATT&CK STIX file. It's large (~35 MB) and always
  re-downloadable, so it's git-ignored.

## Setup

Requires Python 3 (developed on 3.11). From the project root:

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Run (Checkpoint 1a)

```bash
./venv/bin/python scripts/load_attack_data.py
```

On first run it downloads the MITRE ATT&CK Enterprise STIX 2.1 data into `data/`
(one time, ~35 MB), then prints a handful of real techniques — each with its
ATT&CK ID (e.g. `T1003`), name, and the start of its description. Later runs reuse
the downloaded file.
