"""
src/ — the reusable building blocks of the MITRE ATT&CK Mapper.

Scripts in scripts/ import from here. Each module does ONE job so it can be
tested on its own:

  attack_data.py  — read ATT&CK STIX and extract clean technique records
  snippets.py     — turn a technique record into one searchable text snippet
  embedder.py     — load the local embedding model and turn text into vectors
  vector_store.py — build / open the hybrid-search index and search it
"""
