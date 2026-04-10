from __future__ import annotations

import re


_URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\basap\b",
    r"\baction required\b",
    r"\byour account (?:will be|has been) (?:suspended|limited|locked)\b",
    r"\bwithin (?:24|48|72) hours\b",
]

_SOCIAL_ENGINEERING = [
    r"\bdear (?:customer|user|member)\b",
    r"\bkindly\b",
    r"\bsecurity alert\b",
    r"\bwe noticed unusual\b",
    r"\bconfirm (?:your|the) (?:identity|account)\b",
]

_CREDENTIAL_HARVEST = [
    r"\blog ?in\b",
    r"\bsign ?in\b",
    r"\bpassword\b",
    r"\bone-time\b|\botp\b|\b2fa\b",
    r"\bverify\b.*\baccount\b",
    r"\bupdate\b.*\bpayment\b",
]


def analyze_email_text(text: str) -> dict:
    t = (text or "").strip()
    tl = t.lower()

    reasons: list[dict] = []
    score_delta = 0

    urgency_hits = sum(1 for p in _URGENCY_PATTERNS if re.search(p, tl))
    if urgency_hits:
        reasons.append(
            {
                "kind": "email",
                "title": "Urgency / pressure tactics",
                "detail": f"Detected {urgency_hits} urgency indicator(s).",
            }
        )
        score_delta += min(18, 6 * urgency_hits)

    se_hits = sum(1 for p in _SOCIAL_ENGINEERING if re.search(p, tl))
    if se_hits:
        reasons.append(
            {
                "kind": "email",
                "title": "Social engineering patterns",
                "detail": f"Detected {se_hits} social engineering indicator(s).",
            }
        )
        score_delta += min(16, 5 * se_hits)

    cred_hits = sum(1 for p in _CREDENTIAL_HARVEST if re.search(p, tl))
    if cred_hits:
        reasons.append(
            {
                "kind": "email",
                "title": "Credential harvesting intent",
                "detail": f"Detected {cred_hits} credential-harvesting keyword group(s).",
            }
        )
        score_delta += min(22, 7 * cred_hits)

    if "http://" in tl:
        reasons.append(
            {
                "kind": "email",
                "title": "Insecure link (http://)",
                "detail": "Contains plaintext HTTP links (often abused in phishing).",
            }
        )
        score_delta += 8

    if len(t) < 40:
        reasons.append(
            {
                "kind": "email",
                "title": "Very short message",
                "detail": "Short messages with calls-to-action are common in phishing.",
            }
        )
        score_delta += 6

    return {"score_delta": score_delta, "reasons": reasons}

