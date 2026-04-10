import re

MAX_INPUT_CHARS = 8000

_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _looks_like_url(s: str) -> bool:
    s = s.strip().lower()
    return s.startswith(("http://", "https://")) or (
        "." in s and ("/" in s or "?" in s) and not _RE_EMAIL.match(s)
    )


def _looks_like_domain(s: str) -> bool:
    s = s.strip().lower()
    if " " in s or "/" in s or "@" in s:
        return False
    if s.startswith(("http://", "https://")):
        return False
    return "." in s and len(s) <= 253


def _looks_like_email_text(s: str) -> bool:
    # Heuristic: multi-word or contains typical email headers/phrases
    s_l = s.lower()
    return (
        "\n" in s
        or len(s.split()) >= 10
        or any(h in s_l for h in ["subject:", "from:", "to:", "dear ", "kindly", "regards"])
    )


def normalize_and_classify_input(raw: str, input_type_hint: str = "auto") -> dict:
    if not raw:
        return {"ok": False, "error": "Missing input."}
    if len(raw) > MAX_INPUT_CHARS:
        return {"ok": False, "error": f"Input too large (max {MAX_INPUT_CHARS} chars)."}

    normalized = raw.strip()
    hint = (input_type_hint or "auto").lower()

    if hint not in {"auto", "url", "email", "domain"}:
        return {"ok": False, "error": "Invalid input_type. Use auto, url, email, or domain."}

    if hint == "url":
        return {"ok": True, "input_type": "url", "normalized_input": normalized}
    if hint == "domain":
        return {"ok": True, "input_type": "domain", "normalized_input": normalized}
    if hint == "email":
        return {"ok": True, "input_type": "email", "normalized_input": normalized}

    # auto
    if _looks_like_url(normalized):
        return {"ok": True, "input_type": "url", "normalized_input": normalized}
    if _looks_like_domain(normalized):
        return {"ok": True, "input_type": "domain", "normalized_input": normalized}
    if _looks_like_email_text(normalized) or _RE_EMAIL.match(normalized):
        return {"ok": True, "input_type": "email", "normalized_input": normalized}

    return {"ok": True, "input_type": "unknown", "normalized_input": normalized}

