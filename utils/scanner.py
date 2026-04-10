from __future__ import annotations

import re
from urllib.parse import urlparse

from model.ensemble import predict_proba_email, predict_proba_url, to_platform_scores
from model.explain import explain_numeric_url_features, explain_tfidf_terms
from utils.threat_intel import lookup_threat_intel
from utils.url_analysis import analyze_url_or_domain
from utils.email_analysis import analyze_email_text


_SUSPICIOUS_TERMS = [
    "urgent",
    "immediately",
    "verify",
    "suspended",
    "limited time",
    "action required",
    "password",
    "login",
    "update your account",
    "confirm",
    "security alert",
    "invoice",
    "gift card",
    "wire transfer",
    "bank",
    "crypto",
]


def _clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


def _risk_level_from_score(threat_score: int) -> str:
    if threat_score >= 70:
        return "high"
    if threat_score >= 40:
        return "medium"
    return "low"


def _prediction_from_score(threat_score: int) -> str:
    return "phishing" if threat_score >= 55 else "safe"


def _confidence_from_score(threat_score: int) -> float:
    # Confidence increases as you move away from the decision boundary (~55)
    dist = abs(threat_score - 55) / 55.0
    return _clamp(0.55 + dist * 0.4, 0.55, 0.95)


def _extract_domain(raw_input: str, input_type: str) -> str | None:
    if input_type == "domain":
        return raw_input.strip().lower()
    if input_type == "url":
        try:
            p = urlparse(raw_input.strip())
            return (p.hostname or "").lower() or None
        except Exception:
            return None
    return None


def _highlight_suspicious_words(text: str) -> list[dict]:
    highlights: list[dict] = []
    t = text
    lower = t.lower()

    for term in _SUSPICIOUS_TERMS:
        for m in re.finditer(re.escape(term), lower):
            highlights.append(
                {
                    "term": term,
                    "start": m.start(),
                    "end": m.end(),
                    "snippet": t[max(0, m.start() - 24) : min(len(t), m.end() + 24)],
                }
            )

    highlights.sort(key=lambda x: x["start"])
    return highlights[:30]


def scan_input(raw_input: str, input_type: str, heavy: bool = False) -> dict:
    """
    Returns the platform's unified scan schema.

    Combines:
    - heuristics (URL/email analysis rules)
    - threat intelligence (mock reputation)
    - ML ensemble (RandomForest + TF-IDF logistic regression)
    """
    reasons: list[dict] = []
    meta: dict = {"heavy_requested": heavy}

    url_findings = None
    email_findings = None

    baseline_score = 5
    rule_delta = 0
    heuristic_score = baseline_score
    ml = None
    intel = {"status": "unknown", "summary": "No intel lookup performed."}

    if input_type in {"url", "domain"}:
        url_findings = analyze_url_or_domain(raw_input, input_type=input_type)
        rule_delta += int(url_findings["score_delta"])
        heuristic_score += int(url_findings["score_delta"])
        reasons.extend(url_findings["reasons"])

        domain = url_findings.get("domain")
        intel = {"status": "unknown", "summary": "No intel lookup performed."}
        if input_type == "url":
            # Prefer URL reputation (GSB/VT) when available
            intel = lookup_threat_intel(raw_input, kind="url")
            # Also include domain reputation if domain extracted
            if domain:
                domain_intel = lookup_threat_intel(domain, kind="domain")
                intel = {"status": intel.get("status"), "summary": intel.get("summary"), "source": intel.get("source"), "score_delta": intel.get("score_delta", 0), "url": intel, "domain": domain_intel}
        else:
            if domain:
                intel = lookup_threat_intel(domain, kind="domain")
            else:
                intel = {"status": "unknown", "summary": "No domain extracted."}

        ml = predict_proba_url(raw_input)
    elif input_type == "email":
        email_findings = analyze_email_text(raw_input)
        rule_delta += int(email_findings["score_delta"])
        heuristic_score += int(email_findings["score_delta"])
        reasons.extend(email_findings["reasons"])
        intel = {"status": "n/a", "summary": "Threat intel not applicable to raw email text."}
        ml = predict_proba_email(raw_input)
    else:
        intel = {"status": "unknown", "summary": "Unrecognized input type."}
        reasons.append(
            {"kind": "input", "title": "Unknown input type", "detail": "Could not confidently classify the input."}
        )
        rule_delta += 10
        heuristic_score += 10

    highlights = []
    if input_type == "email":
        highlights = _highlight_suspicious_words(raw_input)

    intel_boost = int((intel or {}).get("score_delta") or 0)
    if intel.get("status") == "known_malicious":
        reasons.append({"kind": "intel", "title": "Known malicious (threat intel)", "detail": intel.get("summary", "")})
    elif intel.get("status") == "suspicious":
        reasons.append({"kind": "intel", "title": "Suspicious reputation (threat intel)", "detail": intel.get("summary", "")})
    elif intel.get("status") == "clean":
        reasons.append({"kind": "intel", "title": "No reputation detections", "detail": intel.get("summary", "")})

    heuristic_score = int(_clamp(heuristic_score + intel_boost, 0, 100))
    score_breakdown = {
        "base": int(baseline_score),
        "rules": int(rule_delta),
        "intel": int(intel_boost),
        "heuristic_total": int(heuristic_score),
        "ml": None,
        "blend": None,
        "final": None,
    }

    if ml:
        ml_pred, ml_conf, ml_threat = to_platform_scores(ml["p_phishing"])
        blended = int(round(0.72 * ml_threat + 0.28 * heuristic_score))
        threat_score = int(_clamp(blended, 0, 100))
        score_breakdown["ml"] = int(ml_threat)
        score_breakdown["blend"] = {
            "ml_weight": 0.72,
            "heuristic_weight": 0.28,
        }
        score_breakdown["final"] = int(threat_score)
        prediction = _prediction_from_score(threat_score)
        confidence = float(_clamp((ml_conf + _confidence_from_score(threat_score)) / 2.0, 0.55, 0.97))

        reasons.insert(
            0,
            {
                "kind": "ai",
                "title": "Ensemble AI signal",
                "detail": f"AI phishing probability ≈ {ml['p_phishing']:.2f} (RF {ml['components'].get('rf', 0):.2f}, NLP {ml['components'].get('nlp', 0):.2f}, backend {ml['components'].get('nlp_backend','nlp')}).",
            },
        )

        # Explainability (lightweight)
        reasons.extend(explain_tfidf_terms(raw_input, top_k=6))
        if input_type in {"url", "domain"}:
            reasons.extend(explain_numeric_url_features(ml, top_k=5))
    else:
        threat_score = int(_clamp(heuristic_score, 0, 100))
        score_breakdown["final"] = int(threat_score)
        prediction = _prediction_from_score(threat_score)
        confidence = float(_confidence_from_score(threat_score))

    return {
        "prediction": prediction,
        "confidence": confidence,
        "risk_level": _risk_level_from_score(threat_score),
        "threat_score": threat_score,
        "score_breakdown": score_breakdown,
        "reasons": reasons[:25],
        "highlights": highlights,
        "threat_intel": intel,
        "meta": {
            **meta,
            "url_findings": url_findings,
            "email_findings": email_findings,
            "ml": ml,
            "heuristic_score": heuristic_score,
            "score_breakdown": score_breakdown,
        },
    }

