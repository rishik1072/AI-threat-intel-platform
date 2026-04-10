from __future__ import annotations

import base64
import os
from dataclasses import dataclass

import requests


DEFAULT_TIMEOUT_S = 1.2


@dataclass
class ProviderResult:
    provider: str
    status: str  # malicious|suspicious|clean|unknown|unavailable|error
    summary: str
    score_delta: int
    details: dict


def _vt_headers() -> dict | None:
    key = os.getenv("VT_API_KEY", "").strip()
    if not key:
        return None
    return {"x-apikey": key}


def vt_url_lookup(url: str) -> ProviderResult:
    headers = _vt_headers()
    if not headers:
        return ProviderResult("virustotal", "unavailable", "VirusTotal not configured (VT_API_KEY missing).", 0, {})

    try:
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=DEFAULT_TIMEOUT_S,
        )
        if r.status_code == 404:
            return ProviderResult("virustotal", "unknown", "URL not found in VirusTotal.", 0, {"http_status": 404})
        r.raise_for_status()
        data = r.json() or {}
        stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)

        if malicious > 0:
            return ProviderResult(
                "virustotal",
                "malicious",
                f"VirusTotal flagged as malicious ({malicious} engines).",
                28,
                {"last_analysis_stats": stats},
            )
        if suspicious > 0:
            return ProviderResult(
                "virustotal",
                "suspicious",
                f"VirusTotal flagged as suspicious ({suspicious} engines).",
                16,
                {"last_analysis_stats": stats},
            )
        return ProviderResult("virustotal", "clean", "VirusTotal shows no detections.", -4, {"last_analysis_stats": stats})
    except requests.RequestException as e:
        return ProviderResult("virustotal", "error", f"VirusTotal lookup failed: {e}", 0, {})


def vt_domain_lookup(domain: str) -> ProviderResult:
    headers = _vt_headers()
    if not headers:
        return ProviderResult("virustotal", "unavailable", "VirusTotal not configured (VT_API_KEY missing).", 0, {})

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers,
            timeout=DEFAULT_TIMEOUT_S,
        )
        if r.status_code == 404:
            return ProviderResult("virustotal", "unknown", "Domain not found in VirusTotal.", 0, {"http_status": 404})
        r.raise_for_status()
        data = r.json() or {}
        stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)

        if malicious > 0:
            return ProviderResult(
                "virustotal",
                "malicious",
                f"VirusTotal flagged domain as malicious ({malicious} engines).",
                24,
                {"last_analysis_stats": stats},
            )
        if suspicious > 0:
            return ProviderResult(
                "virustotal",
                "suspicious",
                f"VirusTotal flagged domain as suspicious ({suspicious} engines).",
                14,
                {"last_analysis_stats": stats},
            )
        return ProviderResult("virustotal", "clean", "VirusTotal shows no detections.", -3, {"last_analysis_stats": stats})
    except requests.RequestException as e:
        return ProviderResult("virustotal", "error", f"VirusTotal lookup failed: {e}", 0, {})


def gsb_url_lookup(url: str) -> ProviderResult:
    key = os.getenv("GSB_API_KEY", "").strip()
    if not key:
        return ProviderResult("google_safe_browsing", "unavailable", "Google Safe Browsing not configured (GSB_API_KEY missing).", 0, {})

    body = {
        "client": {"clientId": "ai-threat-intel-platform", "clientVersion": "2026.1"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body,
            timeout=DEFAULT_TIMEOUT_S,
        )
        r.raise_for_status()
        data = r.json() or {}
        matches = data.get("matches") or []
        if matches:
            threat_types = sorted({m.get("threatType") for m in matches if m.get("threatType")})
            return ProviderResult(
                "google_safe_browsing",
                "malicious",
                f"Google Safe Browsing match: {', '.join(threat_types) if threat_types else 'threat match'}.",
                30,
                {"matches": matches},
            )
        return ProviderResult("google_safe_browsing", "clean", "No Google Safe Browsing matches.", -3, {"matches": []})
    except requests.RequestException as e:
        return ProviderResult("google_safe_browsing", "error", f"Safe Browsing lookup failed: {e}", 0, {})

