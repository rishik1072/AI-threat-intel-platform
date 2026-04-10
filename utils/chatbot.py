from __future__ import annotations

from typing import Any


MAX_USER_MESSAGE_CHARS = 800


def _risk_advice(risk_level: str) -> list[str]:
    if risk_level == "high":
        return [
            "Do not click links or download attachments from this message/site.",
            "If you already interacted with it, change your password and enable MFA immediately.",
            "Report it to your security team and consider blocking the domain/URL.",
        ]
    if risk_level == "medium":
        return [
            "Treat this as suspicious: verify the sender/site via an independent channel.",
            "Avoid entering credentials unless you confirm the domain is legitimate.",
        ]
    return [
        "No strong phishing indicators detected, but stay cautious with unexpected requests.",
        "Verify the destination domain before entering credentials.",
    ]


def _top_reason_lines(reasons: list[dict], limit: int = 5) -> list[str]:
    out = []
    for r in (reasons or [])[:limit]:
        title = (r or {}).get("title") or "Reason"
        detail = (r or {}).get("detail") or ""
        if detail:
            out.append(f"- {title}: {detail}")
        else:
            out.append(f"- {title}")
    return out


def _intel_lines(threat_intel: dict) -> list[str]:
    if not threat_intel:
        return []
    status = threat_intel.get("status") or "unknown"
    summary = threat_intel.get("summary") or ""
    lines = [f"- Threat intel status: {status}"]
    if summary:
        lines.append(f"- Threat intel summary: {summary}")

    # Show provider breakdown when present (flat or nested)
    providers = threat_intel.get("providers")
    if not providers and isinstance(threat_intel.get("url"), dict):
        providers = (threat_intel.get("url") or {}).get("providers")
    if not providers and isinstance(threat_intel.get("domain"), dict):
        providers = (threat_intel.get("domain") or {}).get("providers")

    if isinstance(providers, list) and providers:
        for p in providers[:4]:
            lines.append(
                f"- {p.get('provider', 'provider')}: {p.get('status', 'unknown')} ({p.get('summary', '')})"
            )
    return lines


def _ai_lines(meta: dict) -> list[str]:
    ml = (meta or {}).get("ml") or {}
    if not ml:
        return []
    p = ml.get("p_phishing")
    comps = ml.get("components") or {}
    rf = comps.get("rf")
    nlp = comps.get("nlp")
    parts = []
    if isinstance(p, (int, float)):
        parts.append(f"AI phishing probability ≈ {p:.2f}")
    if isinstance(rf, (int, float)):
        parts.append(f"RF {rf:.2f}")
    if isinstance(nlp, (int, float)):
        parts.append(f"NLP {nlp:.2f}")
    if not parts:
        return []
    return [f"- Ensemble AI: {', '.join(parts)}"]


def explain_scan_naturally(scan_result: dict, user_message: str | None = None) -> dict[str, Any]:
    """
    Deterministic analyst-style assistant response built from model output + reasons.
    (No external LLM required.)
    """
    user_message = (user_message or "").strip()
    if len(user_message) > MAX_USER_MESSAGE_CHARS:
        user_message = user_message[:MAX_USER_MESSAGE_CHARS]

    prediction = (scan_result or {}).get("prediction") or "unknown"
    risk_level = (scan_result or {}).get("risk_level") or "unknown"
    confidence = float((scan_result or {}).get("confidence") or 0.0)
    threat_score = int((scan_result or {}).get("threat_score") or 0)
    reasons = (scan_result or {}).get("reasons") or []
    highlights = (scan_result or {}).get("highlights") or []
    threat_intel = (scan_result or {}).get("threat_intel") or {}
    meta = (scan_result or {}).get("meta") or {}

    # Core narrative
    lines = []
    lines.append(
        f"Verdict: {prediction.upper()} (risk: {risk_level.upper()}, threat score: {threat_score}/100, confidence: {round(confidence*100)}%)."
    )

    if user_message:
        lines.append("")
        lines.append(f"You asked: “{user_message}”")

    # Why
    lines.append("")
    lines.append("Why the system thinks this is risky:")
    lines.extend(_top_reason_lines(reasons, limit=6) or ["- No strong rule-based reasons were triggered."])

    # AI signal
    ai_lines = _ai_lines(meta)
    if ai_lines:
        lines.append("")
        lines.append("AI model signal:")
        lines.extend(ai_lines)

    # Threat intel
    intel = _intel_lines(threat_intel)
    if intel:
        lines.append("")
        lines.append("Threat intelligence:")
        lines.extend(intel)

    # Highlights (email)
    if isinstance(highlights, list) and highlights:
        terms = []
        for h in highlights[:8]:
            t = (h or {}).get("term")
            if t and t not in terms:
                terms.append(t)
        if terms:
            lines.append("")
            lines.append("Suspicious language detected (highlights): " + ", ".join(terms) + ".")

    # What to do next
    lines.append("")
    lines.append("Recommended next steps:")
    for tip in _risk_advice(risk_level):
        lines.append(f"- {tip}")

    return {
        "ok": True,
        "reply": "\n".join(lines).strip(),
    }

