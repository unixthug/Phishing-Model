import json
import math
import os
from urllib.parse import urlparse, parse_qs
import re
import ipaddress
from pathlib import Path
import tldextract

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "account", "update",
    "password", "billing", "invoice", "secure"
}

TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "github.com"
}

SHORTENING_SERVICES = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co"
}

SUSPICIOUS_TLDS = {
    ".ru", ".tk", ".ml", ".ga", ".cf"
}

AUTH_FLOW_TERMS = {
    "oauth", "authorize", "token", "auth", "sso", "session",
    "redirect_uri", "response_type", "client_id", "scope",
    "state", "code_challenge", "code_verifier", "nonce",
    "openid", "oidc", "callback", "returnurl", "continue"
}

REDIRECT_HINTS = {
    "redirect", "redirect_uri", "redirect_url", "return", "returnto",
    "returnurl", "next", "target", "dest", "destination", "continue",
    "url", "redir", "r", "u", "goto"
}

SUSPICIOUS_FILE_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".js", ".apk", ".exe", ".scr", ".zip",
    ".rar", ".7z", ".iso", ".img", ".jar", ".bat", ".cmd", ".ps1", ".hta"
}

BRAND_NAMES = {
    "google", "facebook", "amazon", "apple", "microsoft",
    "paypal", "netflix", "instagram", "docusign", "dropbox",
    "bankofamerica", "chase", "outlook", "office365"
}
BASE_DIR = Path(__file__).resolve().parent
DOMAIN_COUNT_PATH = BASE_DIR / "domain_counts.json"
DOMAIN_COUNTS = {}
_DOMAIN_COUNTS_MTIME = None
DEFAULT_URL_SCHEME = os.getenv("DEFAULT_URL_SCHEME", "https").strip().lower()
if DEFAULT_URL_SCHEME not in {"http", "https"}:
    DEFAULT_URL_SCHEME = "https"

# Load once at import — file doesn't change at runtime
try:
    with open(DOMAIN_COUNT_PATH, "r", encoding="utf-8") as f:
        DOMAIN_COUNTS = json.load(f)
except Exception:
    DOMAIN_COUNTS = {}

def load_domain_counts(force: bool = False) -> dict:
    global DOMAIN_COUNTS, _DOMAIN_COUNTS_MTIME

    try:
        current_mtime = DOMAIN_COUNT_PATH.stat().st_mtime
    except OSError:
        DOMAIN_COUNTS = {}
        _DOMAIN_COUNTS_MTIME = None
        return DOMAIN_COUNTS

    if force or _DOMAIN_COUNTS_MTIME != current_mtime:
        try:
            with open(DOMAIN_COUNT_PATH, "r", encoding="utf-8") as f:
                DOMAIN_COUNTS = json.load(f)
            _DOMAIN_COUNTS_MTIME = current_mtime
        except Exception:
            DOMAIN_COUNTS = {}
            _DOMAIN_COUNTS_MTIME = None

    return DOMAIN_COUNTS

#makes url normalization and parsing easier, also handles missing scheme cases
def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"{DEFAULT_URL_SCHEME}://" + url
    return url

def get_hostname(parsed) -> str:
    return parsed.hostname.lower() if parsed.hostname else ""

def has_suspicious_subdomain(hostname: str) -> int:
    parts = hostname.split(".")
    if len(parts) < 3:
        return 0

    root = ".".join(parts[-2:])
    subdomains = parts[:-2]

    for sub in subdomains:
        for brand in ["paypal", "google", "amazon", "facebook", "chase"]:
            if brand in sub and brand not in root:
                return 1
    return 0

def get_domain_frequency(root_domain: str) -> float:
    if not root_domain:
        return 0.0

    domain_counts = load_domain_counts()
    return math.log1p(domain_counts.get(root_domain, 1))


def safe_has_port(parsed) -> int:
    try:
        return 1 if parsed.port is not None else 0
    except ValueError:
        return 0

def is_trusted_domain(hostname: str) -> int:
    return 1 if any(
        hostname == domain or hostname.endswith("." + domain) for domain in TRUSTED_DOMAINS
    ) else 0

def has_ip_address(hostname: str) -> int:
    if not hostname:
        return 0
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0

#helper function to clean main extractor
def is_shortener(hostname: str) -> int:
    return 1 if hostname in SHORTENING_SERVICES else 0

def has_suspicious_tld(hostname: str) -> int:
    return 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0


def has_auth_flow_terms(parsed) -> int:
    blob = ((parsed.path or "") + "?" + (parsed.query or "")).lower()

    if any(term in blob for term in AUTH_FLOW_TERMS):
        return 1

    query_keys = parse_qs(parsed.query).keys()
    if any(key.lower() in AUTH_FLOW_TERMS for key in query_keys):
        return 1 
        
    return 0


def get_subdomains(hostname: str) -> list[str]:
    parts = hostname.split(".")
    if len(parts) <= 2:
        return []
    return parts[:-2]


def count_brand_mentions(text: str) -> int:
    lowered = (text or "").lower()
    return sum(lowered.count(brand) for brand in BRAND_NAMES)


def has_redirect_param(parsed) -> int:
    try:
        query = parse_qs(parsed.query)
    except Exception:
        return 0
    return 1 if any(key.lower() in REDIRECT_HINTS for key in query.keys()) else 0


def count_redirect_params(parsed) -> int:
    try:
        query = parse_qs(parsed.query)
    except Exception:
        return 0
    return sum(1 for key in query.keys() if key.lower() in REDIRECT_HINTS)


def has_embedded_http(text: str) -> int:
    lowered = (text or "").lower()
    return 1 if "http://" in lowered or "https://" in lowered else 0


def get_path_extension(parsed) -> str:
    path = (parsed.path or "").lower()
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1]


def has_suspicious_file_extension(parsed) -> int:
    return 1 if get_path_extension(parsed) in SUSPICIOUS_FILE_EXTENSIONS else 0


def hostname_digit_ratio(hostname: str) -> float:
    return sum(ch.isdigit() for ch in hostname) / max(1, len(hostname))


def hostname_alpha_ratio(hostname: str) -> float:
    return sum(ch.isalpha() for ch in hostname) / max(1, len(hostname))


def longest_hostname_token(hostname: str) -> int:
    tokens = [token for token in re.split(r"[^a-zA-Z0-9]+", hostname) if token]
    if not tokens:
        return 0
    return max(len(token) for token in tokens)


def count_path_tokens(parsed) -> int:
    blob = (parsed.path or "") + "&" + (parsed.query or "")
    return len([token for token in re.split(r"[^a-zA-Z0-9]+", blob) if token])


def count_host_brand_mismatch(hostname: str, root_domain: str) -> int:
    if not hostname:
        return 0

    subdomains = ".".join(get_subdomains(hostname))
    if not subdomains:
        return 0

    return sum(
        1 for brand in BRAND_NAMES
        if brand in subdomains and brand not in root_domain
    )

# main extractor function
def extract_features(url:str) -> dict:
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = get_hostname(parsed)
    url_lower = url.lower()
    ext = tldextract.extract(hostname)
    root_domain = ext.top_domain_under_public_suffix or hostname
    features = {}
    # -------------------------
    # Basic URL features
    # -------------------------
    features["valid_url"] = 1 if parsed.scheme in ["http", "https", "ftp"] and hostname else 0
    features["is_https"] = 1 if parsed.scheme == "https" else 0
    features["url_length"] = len(url)
    features["num_dots"] = hostname.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_at_symbols"] = url.count("@")
    features["num_slashes"] = url.count("/")
    features["num_question_marks"] = url.count("?")
    features["num_equals"] = url.count("=")
    features["num_ampersands"] = url.count("&")
    features["has_percent_encoding"] = 1 if "%" in url else 0

    # -------------------------
    # More complex features can be added here, such as:
    # -------------------------
    features["has_userinfo"] = 1 if (parsed.username is not None or parsed.password is not None) else 0
    features["special_char_count"] = sum(url.count(c) for c in ["@", "?", "&", "=", "-", "_", "#"])
    features["path_segment_count"] = len([seg for seg in parsed.path.split("/") if seg])
    features["percent_encoding_count"] = url.count("%")
    features["query_to_url_ratio"] = len(parsed.query) / max(1, len(url))
    features["path_to_url_ratio"] = len(parsed.path) / max(1, len(url))
    features["has_embedded_http"] = has_embedded_http(url)
    # -------------------------
    # Hostname/domain features
    # -------------------------
    features["hostname_length"] = len(hostname)
    parts = hostname.split(".") if hostname else []
    features["num_subdomains"] = max(0, len(parts) - 2)
    features["has_www"] = 1 if hostname.startswith("www.") else 0
    features["num_digits_in_host"] = sum(c.isdigit() for c in hostname)
    features["hostname_digit_ratio"] = hostname_digit_ratio(hostname)
    features["hostname_alpha_ratio"] = hostname_alpha_ratio(hostname)
    features["hostname_has_hyphen"] = 1 if "-" in hostname else 0
    features["longest_hostname_token"] = longest_hostname_token(hostname)
    features["has_ip_address"] = has_ip_address(hostname)
    features["is_trusted_domain"] = is_trusted_domain(hostname)
    features["is_shortener"] = is_shortener(hostname)
    features["suspicious_tld"] = has_suspicious_tld(hostname)
    features["has_punycode"] = 1 if "xn--" in hostname else 0
    features["domain_freq"] = get_domain_frequency(root_domain)
    features["suspicious_subdomain"] = has_suspicious_subdomain(hostname)
    features["brand_mismatch_count"] = count_host_brand_mismatch(hostname, root_domain)
    # -------------------------
    # Path/query features
    # -------------------------
    features["path_length"] = len(parsed.path)
    features["query_length"] = len(parsed.query)
    features["has_double_slash_in_path"] = 1 if "//" in parsed.path else 0
    features["num_query_params"] = len(parse_qs(parsed.query))
    features["has_port"] = safe_has_port(parsed)
    features["has_redirect_param"] = has_redirect_param(parsed)
    features["redirect_param_count"] = count_redirect_params(parsed)
    features["path_token_count"] = count_path_tokens(parsed)
    features["has_suspicious_file_extension"] = has_suspicious_file_extension(parsed)
    features["shortener_with_path"] = 1 if (
    features["is_shortener"] == 1 and features["path_length"] > 0
    ) else 0
    # -------------------------
    # Suspicious word features
    # -------------------------
    features["has_suspicious_words"] = 1 if any(
        word in url_lower for word in SUSPICIOUS_WORDS
    ) else 0

    features["suspicious_words_in_host"] = sum(
        hostname.count(word) for word in SUSPICIOUS_WORDS
    )

    path_query = ((parsed.path or "") + "?" + (parsed.query or "")).lower()
    features["suspicious_words_in_path_query"] = sum(
        path_query.count(word) for word in SUSPICIOUS_WORDS
    )

    features["brand_in_url"] = 1 if any(b in url_lower for b in BRAND_NAMES) else 0
    features["brand_in_host"] = 1 if any(b in hostname for b in BRAND_NAMES) else 0
    features["brand_count_url"] = count_brand_mentions(url_lower)
    features["brand_count_host"] = count_brand_mentions(hostname)
    # -------------------------
    # Auth / false-positive reduction
    # -------------------------
    features["auth_like_flow"] = has_auth_flow_terms(parsed)
    features["long_url"] = 1 if len(url) > 75 else 0

    return features