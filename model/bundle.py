from __future__ import annotations

import os
from dataclasses import dataclass

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from model.training_data import build_synthetic_training_corpus
from model.features import url_numeric_features


@dataclass
class ModelArtifacts:
    url_rf: RandomForestClassifier
    text_tfidf_lr: Pipeline
    transformer_text_lr: dict | None
    nlp_backend: str
    url_feature_names: list[str]


def _artifact_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "artifacts")


def _artifact_path(name: str) -> str:
    return os.path.join(_artifact_dir(), name)


def load_or_train() -> ModelArtifacts:
    os.makedirs(_artifact_dir(), exist_ok=True)
    path = _artifact_path("bundle.joblib")
    if os.path.exists(path):
        return joblib.load(path)

    corpus = build_synthetic_training_corpus()

    # URL RF model (numeric features)
    X_url = []
    y_url = []
    for u, label in corpus["url_samples"]:
        feats, names = url_numeric_features(u)
        X_url.append(feats)
        y_url.append(label)
    X_url = np.asarray(X_url, dtype=float)
    y_url = np.asarray(y_url, dtype=int)

    url_rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    url_rf.fit(X_url, y_url)

    # Lightweight NLP model (TF-IDF + Logistic Regression)
    text_tfidf_lr = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=1,
                    max_features=25000,
                    lowercase=True,
                    strip_accents="unicode",
                ),
            ),
            (
                "lr",
                LogisticRegression(
                    max_iter=1000,
                    n_jobs=1,
                    solver="liblinear",
                    random_state=42,
                ),
            ),
        ]
    )
    text_tfidf_lr.fit(corpus["text_samples_x"], corpus["text_samples_y"])

    # Optional transformer NLP (DistilBERT embeddings + logistic regression)
    transformer_text_lr = None
    nlp_backend = "tfidf"
    if os.getenv("ENABLE_DISTILBERT", "0") == "1":
        try:
            from model.transformer_nlp import transformer_available, train_embedding_classifier

            if transformer_available():
                transformer_text_lr = train_embedding_classifier(
                    corpus["text_samples_x"], corpus["text_samples_y"]
                )
                nlp_backend = "distilbert"
        except Exception:
            # If transformer training fails, keep TF-IDF model as baseline.
            transformer_text_lr = None
            nlp_backend = "tfidf"

    artifacts = ModelArtifacts(
        url_rf=url_rf,
        text_tfidf_lr=text_tfidf_lr,
        transformer_text_lr=transformer_text_lr,
        nlp_backend=nlp_backend,
        url_feature_names=names,
    )
    joblib.dump(artifacts, path)
    return artifacts

