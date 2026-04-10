from __future__ import annotations

import numpy as np

from model.bundle import load_or_train


def explain_numeric_url_features(ml: dict, top_k: int = 5) -> list[dict]:
    """
    Heuristic explanation for the RF numeric URL model using global importances.
    """
    art = load_or_train()
    feats = ml.get("numeric_features") or {}
    if not feats:
        return []

    importances = getattr(art.url_rf, "feature_importances_", None)
    if importances is None:
        return []

    names = art.url_feature_names
    scores = []
    for i, name in enumerate(names):
        imp = float(importances[i])
        val = float(feats.get(name, 0.0))
        # scale value for human ranking
        scores.append((name, imp * (abs(val) + 1.0), imp, val))

    scores.sort(key=lambda x: x[1], reverse=True)
    out = []
    for name, _, imp, val in scores[:top_k]:
        out.append(
            {
                "kind": "xai",
                "title": f"URL feature: {name}",
                "detail": f"Value={val:.2f}, importance≈{imp:.3f}",
            }
        )
    return out


def explain_tfidf_terms(text: str, top_k: int = 6) -> list[dict]:
    """
    Extracts top positive TF-IDF terms contributing to phishing classification.
    Works for both URLs and email text.
    """
    art = load_or_train()
    # If transformer backend is enabled, TF-IDF token explanations may not reflect the NLP model.
    if getattr(art, "transformer_text_lr", None):
        return []
    pipe = art.text_tfidf_lr
    vec = pipe.named_steps["tfidf"]
    lr = pipe.named_steps["lr"]

    X = vec.transform([text])
    if X.nnz == 0:
        return []

    coefs = lr.coef_[0]
    # Contribution ~ tfidf_value * coef
    idx = X.nonzero()[1]
    vals = X.data
    contrib = vals * coefs[idx]

    # only keep positive contributors
    pos = [(int(i), float(c)) for i, c in zip(idx, contrib) if c > 0]
    if not pos:
        return []

    pos.sort(key=lambda x: x[1], reverse=True)
    feature_names = np.asarray(vec.get_feature_names_out())

    out = []
    for i, c in pos[:top_k]:
        term = str(feature_names[i])
        out.append(
            {
                "kind": "xai",
                "title": "Suspicious term",
                "detail": f"'{term}' (signal {c:.3f})",
            }
        )
    return out

