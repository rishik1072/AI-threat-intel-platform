from __future__ import annotations

import re
from urllib.parse import urlparse

import idna
import tldextract
from rapidfuzz.distance import Levenshtein


_POPULAR_BRANDS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "netflix",
    "github",
    "dropbox",
    "linkedin",
    "whatsapp",
    "telegram",
    "coinbase",
    "binance",
]

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)


def _is_ip_host(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def _looks_like_homograph(host: str) -> bool:
    # Fast checks:
    # - punycode / IDN usage
    # - mixed scripts (approx via non-ascii)
    if "xn--" in host:
        return True
    return any(ord(c) > 127 for c in host)


def _typosquat_candidate(sld: str) -> tuple[str, int] | None:
    best = None
    for brand in _POPULAR_BRANDS:
        d = Levenshtein.distance(sld, brand)
        if d <= 2:
            if best is None or d < best[1]:
                best = (brand, d)
    return best


def analyze_url_or_domain(raw_input: str, input_type: str = "url") -> dict:
    reasons: list[dict] = []
    score_delta = 0

    domain = None
    url = None

    if input_type == "url":
        url = raw_input.strip()
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            reasons.append({"kind": "url", "title": "Invalid URL", "detail": "No hostname found."})
            return {"domain": None, "score_delta": 20, "reasons": reasons}
    else:
        host = raw_input.strip().lower()

    domain = host

    # Normalize IDN (for display / analysis)
    try:
        ascii_host = idna.encode(host).decode("ascii")
    except Exception:
        ascii_host = host
        reasons.append({"kind": "domain", "title": "IDN decode issue", "detail": "Domain could not be normalized cleanly."})
        score_delta += 6

    if _is_ip_host(host):
        reasons.append({"kind": "url", "title": "IP-based host", "detail": "Uses an IP address instead of a domain."})
        score_delta += 18

    if input_type == "url" and "@" in raw_input:
        reasons.append({"kind": "url", "title": "Userinfo '@' in URL", "detail": "Phishing URLs sometimes abuse '@' to confuse users."})
        score_delta += 12

    if len(host) > 45:
        reasons.append({"kind": "domain", "title": "Long domain", "detail": f"Unusually long hostname length ({len(host)})."})
        score_delta += 8

    if _looks_like_homograph(host):
        reasons.append({"kind": "url", "title": "Possible homograph/IDN", "detail": f"Hostname looks like IDN/punycode ({ascii_host})."})
        score_delta += 14

    ext = _EXTRACT(host)
    sld = (ext.domain or "").lower()
    subdomain = (ext.subdomain or "").lower()

    if subdomain:
        depth = len([p for p in subdomain.split(".") if p])
        if depth >= 3:
            reasons.append({"kind": "url", "title": "Deep subdomain nesting", "detail": f"Suspicious subdomain depth ({depth})."})
            score_delta += 10
        if any(x in subdomain for x in ["login", "secure", "account", "verify", "update"]):
            reasons.append({"kind": "url", "title": "Suspicious subdomain keywords", "detail": "Subdomain contains authentication/security bait keywords."})
            score_delta += 10

    if sld:
        typo = _typosquat_candidate(sld)
        if typo:
            brand, dist = typo
            reasons.append({"kind": "domain", "title": "Possible typosquatting", "detail": f"Domain '{sld}' is close to brand '{brand}' (edit distance {dist})."})
            score_delta += 16

    if input_type == "url":
        # URL-specific patterns
        if url and len(url) > 110:
            reasons.append({"kind": "url", "title": "Long URL", "detail": f"Unusually long URL length ({len(url)})."})
            score_delta += 6
        if url and re.search(r"(?:\b|_)(?:confirm|verify|update|signin|login|password)(?:\b|_)", url.lower()):
            reasons.append({"kind": "url", "title": "Credential bait in path", "detail": "URL path/query contains login/verify keywords."})
            score_delta += 10

    return {"domain": domain, "score_delta": score_delta, "reasons": reasons}

