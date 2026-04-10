from __future__ import annotations

import math
import re
from urllib.parse import urlparse

import tldextract


_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def url_numeric_features(raw: str) -> tuple[list[float], list[str]]:
    """
    Numeric features for URL/domain strings usable by classical ML.
    Returns (feature_values, feature_names).
    """
    s = (raw or "").strip()
    sl = s.lower()

    # Parse URL best-effort
    host = ""
    path = ""
    query = ""
    scheme = ""
    if sl.startswith(("http://", "https://")):
        p = urlparse(s)
        host = (p.hostname or "").lower()
        path = p.path or ""
        query = p.query or ""
        scheme = (p.scheme or "").lower()
    else:
        host = sl

    ext = _EXTRACT(host)
    sub = ext.subdomain or ""
    sld = ext.domain or ""
    tld = ext.suffix or ""

    digits = sum(ch.isdigit() for ch in s)
    letters = sum(ch.isalpha() for ch in s)
    special = len(s) - digits - letters

    num_dots_host = host.count(".")
    sub_depth = len([p for p in sub.split(".") if p])

    has_at = 1.0 if "@" in s else 0.0
    has_ip = 1.0 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or "") else 0.0
    https = 1.0 if scheme == "https" else 0.0
    http = 1.0 if scheme == "http" else 0.0

    bait_kw = 1.0 if re.search(r"(?:\b|_)(login|signin|verify|update|password|account)(?:\b|_)", sl) else 0.0

    names = [
        "len",
        "digits",
        "letters",
        "special",
        "entropy",
        "num_dots_host",
        "sub_depth",
        "has_at",
        "has_ip",
        "https",
        "http",
        "bait_kw",
        "len_host",
        "len_path",
        "len_query",
        "len_sld",
        "len_tld",
    ]

    feats = [
        float(len(s)),
        float(digits),
        float(letters),
        float(special),
        float(_shannon_entropy(s)),
        float(num_dots_host),
        float(sub_depth),
        float(has_at),
        float(has_ip),
        float(https),
        float(http),
        float(bait_kw),
        float(len(host)),
        float(len(path)),
        float(len(query)),
        float(len(sld)),
        float(len(tld)),
    ]
    return feats, names

