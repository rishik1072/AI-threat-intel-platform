from __future__ import annotations

import hashlib
import time

from utils.threat_intel_providers import gsb_url_lookup, vt_domain_lookup, vt_url_lookup


_CACHE: dict[str, tuple[float, dict]] = {}
_TTL_SECONDS = 60


def _hash_to_int(s: str) -> int:
    h = hashlib.sha256(s.encode("utf-8", errors="ignore")).digest()
    return int.from_bytes(h[:4], "big")


def lookup_threat_intel(target: str, kind: str = "domain") -> dict:
    """
    Threat intelligence lookup with caching.

    - kind='url': uses Google Safe Browsing (if configured) and VirusTotal (if configured)
    - kind='domain': uses VirusTotal domain reputation (if configured)
    - If no API keys are present, falls back to deterministic mock scoring.
    """
    kind = (kind or "domain").strip().lower()
    now = time.time()
    cache_key = f"{kind}:{target}".lower()
    cached = _CACHE.get(cache_key)
    if cached and now - cached[0] < _TTL_SECONDS:
        return cached[1]

    providers = []
    score_delta = 0

    # Real providers first (when configured)
    if kind == "url":
        providers.append(gsb_url_lookup(target))
        providers.append(vt_url_lookup(target))
    else:
        providers.append(vt_domain_lookup(target))

    any_real = any(p.status not in {"unavailable"} for p in providers)
    if any_real:
        for p in providers:
            score_delta += int(p.score_delta)

        statuses = {p.status for p in providers}
        if "malicious" in statuses:
            status = "known_malicious"
            summary = "Reputation providers indicate malicious."
        elif "suspicious" in statuses:
            status = "suspicious"
            summary = "Reputation providers indicate suspicious."
        elif "clean" in statuses and len(statuses) == 1:
            status = "clean"
            summary = "Reputation providers show no detections."
        else:
            status = "unknown"
            summary = "No strong reputation signal."

        res = {
            "status": status,
            "summary": summary,
            "source": "providers",
            "score_delta": max(-10, min(35, score_delta)),
            "providers": [
                {
                    "provider": p.provider,
                    "status": p.status,
                    "summary": p.summary,
                    "score_delta": p.score_delta,
                    "details": p.details,
                }
                for p in providers
            ],
        }
        _CACHE[cache_key] = (now, res)
        return res

    # Fallback deterministic mock when nothing configured
    x = _hash_to_int(target.lower())
    if x % 23 == 0:
        res = {
            "status": "known_malicious",
            "summary": "Known malicious indicator (mock reputation hit).",
            "source": "mock",
            "score_delta": 22,
        }
    elif x % 11 == 0:
        res = {
            "status": "suspicious",
            "summary": "Suspicious/low reputation (mock).",
            "source": "mock",
            "score_delta": 12,
        }
    else:
        res = {
            "status": "unknown",
            "summary": "New/unknown (mock).",
            "source": "mock",
            "score_delta": 0,
        }

    _CACHE[cache_key] = (now, res)
    return res

