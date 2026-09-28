# Dockerfile — package the web app (src/api.py + web/index.html) into one container.
#
# What goes INTO the image (all public, no secrets):
#   - the code and Python libraries (CPU-only PyTorch)
#   - the MITRE ATT&CK data and the built search index
#   - the two small local models (embedding + reranker), pre-downloaded
# What does NOT: the LLM API key. It's passed in at RUN time as an environment
# variable (LLM_API_KEY) — a host "secret" on Hugging Face, or `--env-file .env`
# locally. .dockerignore also keeps .env out of the build entirely.

# Base image pinned to an exact version (digest), so builds are reproducible and
# never re-download or re-tag the shared "python:3.11-slim" image.
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e

LABEL project="mitre-attack-mapper" \
      description="MITRE ATT&CK log mapper (RAG demo)"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Be patient with slow or flaky networks: longer timeouts, automatic retries.
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10 \
    # Where the embedding/reranker models are stored inside the image.
    HF_HOME=/app/.cache/huggingface \
    TOKENIZERS_PARALLELISM=false \
    # Hugging Face Spaces expects port 7860; other hosts can override PORT.
    PORT=7860

# Run as a normal user (id 1000 — what Hugging Face Spaces uses), not root.
RUN useradd --create-home --uid 1000 app
WORKDIR /app
RUN chown app:app /app

# 1) Libraries first (cached between builds unless requirements.txt changes).
#    PyTorch comes from its CPU-only index: the default wheel bundles GPU (CUDA)
#    libraries we don't need, which would make the image ~2 GB bigger.
#    Two separate steps, so if the second one fails, Docker keeps the finished
#    PyTorch step and doesn't download it again.
#    Each step retries up to 5 times: pip can't resume a stalled download, so on
#    a slow connection a big file (PyTorch is ~190 MB) may need another attempt.
RUN for attempt in 1 2 3 4 5; do \
      pip install --index-url https://download.pytorch.org/whl/cpu torch==2.2.2 && break; \
      echo "PyTorch download failed (attempt $attempt), retrying..."; sleep 10; \
    done && python -c "import torch"
COPY requirements.txt .
RUN for attempt in 1 2 3 4 5; do \
      pip install -r requirements.txt && break; \
      echo "Library download failed (attempt $attempt), retrying..."; sleep 10; \
    done && python -c "import fastapi, sentence_transformers, lancedb, openai"

# The import check above runs as root and creates the model-cache folder; give it
# to the normal user so the model downloads below can write there.
RUN mkdir -p "$HF_HOME" && chown -R app:app /app/.cache

# 2) The code.
COPY --chown=app:app . .
USER app

# 3) Build the searchable library INTO the image, so the app starts fast and
#    needs no downloads at runtime:
#    - download the ATT&CK data (~40 MB) and build the index (this also
#      downloads the embedding model, all-MiniLM-L6-v2, ~90 MB)
#    - pre-download the reranker (ms-marco-MiniLM-L-6-v2, ~90 MB)
RUN python scripts/load_attack_data.py \
 && python scripts/build_index.py \
 && python -c "from sentence_transformers import CrossEncoder; from src.reranker import RERANKER_MODEL; CrossEncoder(RERANKER_MODEL)"

EXPOSE 7860
CMD ["sh", "-c", "uvicorn src.api:app --host 0.0.0.0 --port ${PORT}"]
