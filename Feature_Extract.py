from urllib.parse import urlparse, parse_qs
import re
import ipaddress
from collections import Counter
import math
import numpy as np

SHORTENING_SERVICES = {'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co'}

# keep login-ish terms; we handle false positives using contextual features below
SUSPICIOUS_WORDS = {'login', 'signin', 'verify', 'account', 'update', 'password', 'billing', 'invoice'}

BRAND_NAMES = {'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram'}

SUSPICIOUS_EXTENSIONS = {'.exe', '.zip', '.rar', '.js', '.php', '.scr', '.bat'}

# Domains you generally trust as "owned by the real org"
# (NOT an auto-allow; it's a feature used by ML / policy.)
TRUSTED_DOMAINS = {
    "github.com",
    "github.io",          # GitHub Pages base domain
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "microsoft.com",
    "google.com",
}

# Trusted platforms that commonly host user-controlled content (higher abuse risk)
TRUSTED_HOSTING_PATTERNS = [
    r"(^|\.)github\.io$",
    r"(^|\.)sites\.google\.com$",
    r"(^|\.)docs\.google\.com$",
    r"(^|\.)forms\.google\.com$",
    r"(^|\.)storage\.googleapis\.com$",
    r"(^|\.)vercel\.app$",
    r"(^|\.)netlify\.app$",
    r"(^|\.)pages\.dev$",
]

# OAuth/SSO patterns to reduce auth false positives (scales beyond hardcoded providers)
AUTH_FLOW_TERMS = {
    "oauth", "authorize", "token", "auth", "sso", "session",
    "redirect_uri", "response_type", "client_id", "scope", "state",
    "code_challenge", "code_verifier", "nonce", "saml", "openid", "oidc",
    "continue", "returnurl", "callback"
}

# Optional: your own deployed site(s) (small list of what YOU own)
OWNED_SITES = {
    "eli-69.github.io",
}

def is_trusted_domain(url: str) -> int:
    """
    1 if hostname equals a trusted domain or is a subdomain of it.
    Avoids substring tricks like google.com.evil.ru.
    """
    try:
        host = urlparse(url).hostname
        if not host:
            return 0
        host = host.lower()
        for domain in TRUSTED_DOMAINS:
            if host == domain or host.endswith("." + domain):
                return 1
        return 0
    except Exception:
        return 0

# ---- URL normalization ----
def normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    return u

def hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()

def is_valid_url(url: str) -> int:
    try:
        p = urlparse(url)
        return int(p.scheme in ("http", "https", "ftp") and bool(p.hostname))
    except Exception:
        return 0

def is_https(url: str) -> int:
    try:
        return 1 if urlparse(url).scheme.lower() == "https" else 0
    except Exception:
        return 0

def has_at_symbol(url: str) -> int:
    return 1 if '@' in url else 0

def at_count(url: str) -> int:
    return url.count("@")

def has_userinfo(url: str) -> int:
    p = urlparse(url)
    return 1 if (p.username is not None or p.password is not None) else 0

def has_ip_address(url: str) -> int:
    h = hostname(url)
    if not h:
        return 0
    try:
        ipaddress.ip_address(h)
        return 1
    except ValueError:
        return 0

def subdomain_label_count(url: str) -> int:
    h = hostname(url)
    if not h:
        return 0
    labels = h.split(".")
    # naive; PSL-aware would be better, but OK for now
    return max(0, len(labels) - 2)

def has_many_subdomains(url: str) -> int:
    return 1 if subdomain_label_count(url) >= 2 else 0

def has_prefix_suffix_sld(url: str) -> int:
    h = hostname(url)
    parts = h.split(".")
    if len(parts) < 2:
        return 0
    sld = parts[-2]
    return 1 if ('-' in sld or '_' in sld) else 0

def hyphen_in_host(url: str) -> int:
    return 1 if "-" in hostname(url) else 0

def has_shortening_service(url: str) -> int:
    return 1 if hostname(url) in SHORTENING_SERVICES else 0

def url_length(url: str) -> int:
    return len(url)

def hostname_length(url: str) -> int:
    return len(hostname(url))

def path_length(url: str) -> int:
    return len(urlparse(url).path or "")

def query_length(url: str) -> int:
    return len(urlparse(url).query or "")

def hyphen_count(url: str) -> int:
    return hostname(url).count('-')

def dot_count(url: str) -> int:
    return hostname(url).count('.')

def special_char_count(url: str) -> int:
    special_chars = ['@', '?', '&', '=', '-', '_', '.', '#']
    return sum(url.count(c) for c in special_chars)

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def sep_count(url: str) -> int:
    return url.count('/') + url.count('=') + url.count('&')

def suspicious_words_in_path_query(url: str) -> int:
    p = urlparse(url)
    s = ((p.path or "") + "?" + (p.query or "")).lower()
    return sum(s.count(w) for w in SUSPICIOUS_WORDS)

def suspicious_words_in_host(url: str) -> int:
    h = hostname(url)
    return sum(h.count(w) for w in SUSPICIOUS_WORDS)

def brand_in_url(url: str) -> int:
    low = url.lower()
    return 1 if any(b in low for b in BRAND_NAMES) else 0

def brand_in_host(url: str) -> int:
    h = hostname(url)
    return 1 if any(b in h for b in BRAND_NAMES) else 0

def suspicious_extension(url: str) -> int:
    low = url.lower()
    return 1 if any(low.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) else 0

def path_segment_count(url: str) -> int:
    path = urlparse(url).path or ""
    segments = [s for s in path.split('/') if s]
    return len(segments)

def percent_encoding_count(url: str) -> int:
    return url.count('%')

def pct_encoding_ratio(url: str) -> float:
    return percent_encoding_count(url) / max(1, len(url))

def query_to_url_ratio(url: str) -> float:
    return query_length(url) / max(1, url_length(url))

def path_to_url_ratio(url: str) -> float:
    return path_length(url) / max(1, url_length(url))

def has_punycode(url: str) -> int:
    return 1 if "xn--" in hostname(url) else 0

def double_slash_in_path(url: str) -> int:
    p = urlparse(url)
    return 1 if "//" in (p.path or "") else 0

def digit_ratio_in_host(url: str) -> float:
    h = hostname(url)
    if not h:
        return 0.0
    digits = sum(ch.isdigit() for ch in h)
    return digits / max(1, len(h))

def longest_digit_run(url: str) -> int:
    h = hostname(url)
    runs = re.findall(r"\d+", h)
    return max((len(r) for r in runs), default=0)

def num_query_params(url: str) -> int:
    return len(parse_qs(urlparse(url).query))

def avg_param_key_len(url: str) -> float:
    qs = parse_qs(urlparse(url).query)
    keys = list(qs.keys())
    if not keys:
        return 0.0
    return float(np.mean([len(k) for k in keys]))

def max_param_key_len(url: str) -> int:
    qs = parse_qs(urlparse(url).query)
    keys = list(qs.keys())
    if not keys:
        return 0
    return int(max(len(k) for k in keys))

# ---- Context features to reduce false positives ----
def trusted_but_hosting(url: str) -> int:
    h = hostname(url)
    for pat in TRUSTED_HOSTING_PATTERNS:
        if re.search(pat, h):
            return 1
    return 0

def google_search_related(url: str) -> int:
    """
    1 for Google search results and Google redirect endpoints used when clicking search results.
    Use this in your backend to bypass scanning entirely if you want 'never flag google searches'.
    """
    p = urlparse(url)
    h = (p.hostname or "").lower()
    if not (h == "www.google.com" or h.endswith(".google.com")):
        return 0
    path = (p.path or "").lower()
    if path == "/search" or path.startswith("/search"):
        return 1
    if path in {"/url", "/imgres"}:
        return 1
    return 0

def auth_like_flow(url: str) -> int:
    p = urlparse(url)
    blob = ((p.path or "") + "?" + (p.query or "")).lower()

    for t in AUTH_FLOW_TERMS:
        if t in blob:
            return 1

    qs = parse_qs(p.query)
    for k in qs.keys():
        if k.lower() in AUTH_FLOW_TERMS:
            return 1

    return 0

def is_owned_site(url: str) -> int:
    return 1 if hostname(url) in OWNED_SITES else 0

def owned_site_path_ok(url: str) -> int:
    """
    Optional safety: only mark benign if path is within expected scope.
    Adjust prefix to your project path if needed.
    """
    if not is_owned_site(url):
        return 0
    path = (urlparse(url).path or "/").lower()
    # allow site root and your project paths
    return 1 if (path == "/" or path.startswith("/risklens.github.io")) else 0

def extract_features(url: str) -> dict:
    url = normalize_url(url)
    p = urlparse(url)

    feats = {
        "valid_url": is_valid_url(url),
        "is_https": is_https(url),

        "has_at_symbol": has_at_symbol(url),
        "at_count": at_count(url),
        "userinfo": has_userinfo(url),

        "has_ip": has_ip_address(url),

        "subdomain_labels": subdomain_label_count(url),
        "many_subdomains": has_many_subdomains(url),

        "prefix_suffix_sld": has_prefix_suffix_sld(url),
        "hyphen_in_host": hyphen_in_host(url),

        "shortener": has_shortening_service(url),

        "url_len": url_length(url),
        "host_len": hostname_length(url),
        "path_len": path_length(url),
        "query_len": query_length(url),

        "hyphen_count": hyphen_count(url),
        "dot_count": dot_count(url),
        "special_char_count": special_char_count(url),

        "entropy_url": shannon_entropy(url.lower()),
        "entropy_host": shannon_entropy(hostname(url)),

        "sep_count": sep_count(url),

        "susp_words_path_query": suspicious_words_in_path_query(url),
        "susp_words_host": suspicious_words_in_host(url),

        "brand_in_url": brand_in_url(url),
        "brand_in_host": brand_in_host(url),

        "suspicious_ext": suspicious_extension(url),
        "path_segments": path_segment_count(url),

        "pct_encoding": percent_encoding_count(url),
        "pct_encoding_ratio": pct_encoding_ratio(url),

        "num_query_params": num_query_params(url),
        "avg_param_key_len": avg_param_key_len(url),
        "max_param_key_len": max_param_key_len(url),

        "query_to_url_ratio": query_to_url_ratio(url),
        "path_to_url_ratio": path_to_url_ratio(url),

        "punycode": has_punycode(url),
        "double_slash_path": double_slash_in_path(url),

        "digit_ratio": digit_ratio_in_host(url),
        "longest_digit_run": longest_digit_run(url),

        "port": int(p.port or 0),

        # Context / special-case signals
        "trusted_domain": is_trusted_domain(url),
        "trusted_hosting": trusted_but_hosting(url),
        "google_search_related": google_search_related(url),
        "auth_like_flow": auth_like_flow(url),

        # Optional: your own deployment
        "owned_site": is_owned_site(url),
        "owned_site_path_ok": owned_site_path_ok(url),
    }
    return feats