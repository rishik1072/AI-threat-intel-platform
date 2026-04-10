from __future__ import annotations

import numpy as np

from model.bundle import load_or_train
from model.features import url_numeric_features
from model.transformer_nlp import predict_proba as transformer_predict_proba


def _clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


def _prob_to_threat_score(p: float) -> int:
    return int(round(_clamp(p, 0.0, 1.0) * 100))


def predict_proba_url(url_or_domain: str) -> dict:
    art = load_or_train()

    feats, names = url_numeric_features(url_or_domain)
    X = np.asarray([feats], dtype=float)

    rf_p = float(art.url_rf.predict_proba(X)[0, 1])
    if art.transformer_text_lr:
        nlp_p = float(transformer_predict_proba(url_or_domain, art.transformer_text_lr))
        nlp_backend = "distilbert"
    else:
        nlp_p = float(art.text_tfidf_lr.predict_proba([url_or_domain])[0, 1])
        nlp_backend = "tfidf"

    # Weighted ensemble: RF strong on structural URL features; NLP strong on tokens.
    p = 0.6 * rf_p + 0.4 * nlp_p

    return {
        "p_phishing": p,
        "components": {"rf": rf_p, "nlp": nlp_p, "nlp_backend": nlp_backend},
        "numeric_features": dict(zip(names, feats)),
    }


def predict_proba_email(email_text: str) -> dict:
    art = load_or_train()
    if art.transformer_text_lr:
        nlp_p = float(transformer_predict_proba(email_text, art.transformer_text_lr))
        nlp_backend = "distilbert"
    else:
        nlp_p = float(art.text_tfidf_lr.predict_proba([email_text])[0, 1])
        nlp_backend = "tfidf"
    return {"p_phishing": nlp_p, "components": {"nlp": nlp_p, "nlp_backend": nlp_backend}}


def to_platform_scores(p_phishing: float) -> tuple[str, float, int]:
    threat = _prob_to_threat_score(p_phishing)
    prediction = "phishing" if threat >= 55 else "safe"
    # Confidence: distance from boundary
    conf = _clamp(0.55 + abs(threat - 55) / 55.0 * 0.4, 0.55, 0.97)
    return prediction, float(conf), int(threat)

