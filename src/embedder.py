"""
embedder.py — load the local embedding model and turn text into vectors.

An "embedding" is a list of numbers that captures a piece of text's meaning, so
texts with similar meaning end up close together. This is what powers SEMANTIC
search (finding "credential dumping" from the query "stole passwords").

Model choice (one line, as the brief asks):
  all-MiniLM-L6-v2 — a small (~80 MB), fast, CPU-friendly sentence-transformers
  model that runs comfortably on this 2019 Intel MacBook (no GPU) while giving
  solid general-purpose semantic quality — the standard "good default" baseline.

It outputs 384-dimensional vectors. We normalize them (scale to length 1) so that
similarity can be computed as a simple dot product / cosine — the store expects
this for clean semantic ranking.

We wrap the model in a tiny class so the rest of the code doesn't care which
model we picked: swap the name here and everything downstream still works.
"""

from sentence_transformers import SentenceTransformer

# The Hugging Face model id. Kept as a module constant so there's ONE place to
# change the embedding model for the whole project.
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# The dimensionality this model outputs. The store needs to know the vector
# width up front, so we expose it here rather than hardcoding 384 elsewhere.
EMBEDDING_DIM = 384


class Embedder:
    """A thin wrapper around a sentence-transformers model."""

    def __init__(self, model_name: str = MODEL_NAME) -> None:
        # Loading downloads the model on first use (~80 MB) then caches it, so
        # later runs are offline and fast.
        self.model = SentenceTransformer(model_name)

    def embed(self, texts: list[str], show_progress: bool = False) -> list[list[float]]:
        """
        Turn a list of texts into a list of vectors (one per text).

        normalize_embeddings=True gives unit-length vectors for cosine similarity.
        We return plain Python lists (not numpy) because that's what the store
        wants to write.
        """
        vectors = self.model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=show_progress,
        )
        return vectors.tolist()

    def embed_one(self, text: str) -> list[float]:
        """Convenience helper for a single query string."""
        return self.embed([text])[0]


# Quick manual check: `./venv/bin/python -m src.embedder`
if __name__ == "__main__":
    emb = Embedder()
    vecs = emb.embed(["OS credential dumping from LSASS memory"])
    print(f"Model: {MODEL_NAME}")
    print(f"Vector length: {len(vecs[0])} (expected {EMBEDDING_DIM})")
