from __future__ import annotations

import os
from functools import lru_cache

import numpy as np
from sklearn.linear_model import LogisticRegression


DEFAULT_MODEL_NAME = os.getenv("DISTILBERT_MODEL_NAME", "distilbert-base-uncased")


def transformer_available() -> bool:
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401

        return True
    except Exception:
        return False


@lru_cache(maxsize=1)
def _load_embedder(model_name: str = DEFAULT_MODEL_NAME):
    """
    Loads a lightweight transformer encoder for embeddings.
    Cached to avoid repeated loads.
    """
    import torch
    from transformers import AutoModel, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
    model = AutoModel.from_pretrained(model_name)
    model.eval()
    device = torch.device("cpu")
    model.to(device)
    return tokenizer, model, device


def _mean_pool(last_hidden_state, attention_mask):
    import torch

    mask = attention_mask.unsqueeze(-1).type_as(last_hidden_state)
    summed = torch.sum(last_hidden_state * mask, dim=1)
    counts = torch.clamp(mask.sum(dim=1), min=1e-9)
    return summed / counts


def embed_texts(texts: list[str], model_name: str = DEFAULT_MODEL_NAME, max_length: int = 192) -> np.ndarray:
    """
    Produces dense embeddings for texts using mean pooling over token embeddings.
    Returns ndarray shape (n, hidden).
    """
    import torch

    tokenizer, model, device = _load_embedder(model_name)
    batches = []

    with torch.no_grad():
        for i in range(0, len(texts), 16):
            batch = texts[i : i + 16]
            enc = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            enc = {k: v.to(device) for k, v in enc.items()}
            out = model(**enc)
            pooled = _mean_pool(out.last_hidden_state, enc["attention_mask"])
            batches.append(pooled.cpu().numpy())

    return np.vstack(batches) if batches else np.zeros((0, 768), dtype=np.float32)


def train_embedding_classifier(texts: list[str], labels: list[int], model_name: str = DEFAULT_MODEL_NAME) -> dict:
    X = embed_texts(texts, model_name=model_name)
    y = np.asarray(labels, dtype=int)

    clf = LogisticRegression(
        max_iter=1200,
        n_jobs=1,
        solver="liblinear",
        random_state=42,
    )
    clf.fit(X, y)

    return {"model_name": model_name, "clf": clf}


def predict_proba(text: str, transformer_artifacts: dict) -> float:
    model_name = transformer_artifacts["model_name"]
    clf = transformer_artifacts["clf"]
    X = embed_texts([text], model_name=model_name)
    return float(clf.predict_proba(X)[0, 1])

