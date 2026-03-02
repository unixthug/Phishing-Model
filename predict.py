# predict.py
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import joblib
import pandas as pd
import requests

from Feature_Extract import extract_features

# -------------------------
# Config (env overridable)
# -------------------------
MODELS_DIR = Path(os.getenv("MODELS_DIR", "models"))
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Direct-download URLs (set these in Render/Docker env)
MODEL_PKL_URL = os.getenv("MODEL_PKL_URL", "").strip()
FEATURE_COLS_URL = os.getenv("FEATURE_COLS_URL", "").strip()

# Local filenames (in /models)
LOCAL_MODEL = MODELS_DIR / os.getenv("LOCAL_MODEL_NAME", "phishing_model.pkl")
LOCAL_COLS_PKL = MODELS_DIR / os.getenv("LOCAL_COLS_PKL_NAME", "feature_columns.pkl")

# Thresholding
DEFAULT_THRESHOLD = float(os.getenv("PHISH_THRESHOLD", "0.80"))

# ✅ Policy toggles (env)
# Comma-separated list of hostnames you own and never want flagged
# Example: "eli-69.github.io,example.com"
OWNED_HOSTS = {
    h.strip().lower()
    for h in os.getenv("OWNED_HOSTS", "eli-69.github.io").split(",")
    if h.strip()
}

# Discord invite handling: "phishing" or "suspicious"
DISCORD_INVITE_VERDICT = os.getenv("DISCORD_INVITE_VERDICT", "suspicious").strip().lower()
if DISCORD_INVITE_VERDICT not in {"phishing", "suspicious"}:
    DISCORD_INVITE_VERDICT = "suspicious"

# Internal caches
_lock = threading.Lock()
_cached_model: Any = None
_cached_cols: List[str] | None = None


# -------------------------
# URL policy helpers
# -------------------------
def _ensure_scheme(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    # If user passes "www.google.com/..." or similar, urlparse treats it as path.
    if "://" not in u:
        u = "http://" + u
    return u


def _host_path(url: str) -> Tuple[str, str]:
    u = _ensure_scheme(url)
    p = urlparse(u)
    host = (p.hostname or "").lower()
    path = (p.path or "").lower()
    return host, path


def is_google_search_related(url: str) -> bool:
    """
    Exclude Google Search results pages and Google redirect endpoints used when clicking search results.
    Covers:
      - www.google.com, google.com, *.google.com
      - country domains like www.google.ca, www.google.co.uk, etc.
    """
    host, path = _host_path(url)
    if not host:
        return False

    # normalize trailing dot (rare but can happen)
    host = host.rstrip(".")

    # Host match:
    #  - google.com / www.google.com / *.google.com
    #  - www.google.<ccTLD> (e.g., www.google.ca, www.google.co.uk)
    is_google_host = (
        host == "google.com"
        or host == "www.google.com"
        or host.endswith(".google.com")
        or host.startswith("www.google.")   # country domains
    )
    if not is_google_host:
        return False

    # Path match:
    return (
        path == "/search"
        or path.startswith("/search")
        or path == "/url"
        or path == "/imgres"
    )

def is_discord_invite(url: str) -> bool:
    """
    Flag only Discord invites:
      - https://discord.gg/<code>
      - https://discord.com/invite/<code>
    """
    host, path = _host_path(url)
    if not host:
        return False

    # discord.gg/<code>
    if host == "discord.gg" and path.strip("/") != "":
        return True

    # discord.com/invite/<code>
    if (host == "discord.com" or host.endswith(".discord.com")) and path.startswith("/invite/"):
        return True

    return False


def is_owned_host(url: str) -> bool:
    """
    Never flag hostnames you own (small allowlist).
    """
    host, _ = _host_path(url)
    return bool(host) and host in OWNED_HOSTS


# -------------------------
# Artifact download/load
# -------------------------
def _download(url: str, dest: Path) -> None:
    """Download a file to dest (atomic write)."""
    if not url:
        raise RuntimeError(
            f"Missing download URL for {dest.name}. Set MODEL_PKL_URL / FEATURE_COLS_URL env var(s)."
        )

    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
    tmp.replace(dest)


def _ensure_artifacts_present() -> None:
    """Ensure model + feature columns exist locally."""
    if not LOCAL_MODEL.exists():
        _download(MODEL_PKL_URL, LOCAL_MODEL)

    if not LOCAL_COLS_PKL.exists():
        _download(FEATURE_COLS_URL, LOCAL_COLS_PKL)


def load_train_cols() -> List[str]:
    """Required by server.py. Loads and caches the training column order."""
    global _cached_cols
    with _lock:
        if _cached_cols is not None:
            return _cached_cols

        _ensure_artifacts_present()

        cols: Any = None
        if LOCAL_COLS_PKL.exists():
            cols = joblib.load(LOCAL_COLS_PKL)

        if not isinstance(cols, list) or not cols or not all(isinstance(c, str) for c in cols):
            raise ValueError("Feature columns file is invalid (expected a non-empty list[str]).")

        _cached_cols = cols
        return cols


def load_bundle(_model_choice: str) -> Tuple[Dict[str, Any], str]:
    """
    Required by server.py.
    We ignore model_choice and load the single hosted model.
    Returns a bundle dict + model_path string.
    """
    global _cached_model
    with _lock:
        if _cached_model is None:
            _ensure_artifacts_present()
            _cached_model = joblib.load(LOCAL_MODEL)

        bundle = {
            "model": _cached_model,
            "threshold": DEFAULT_THRESHOLD,
        }
        return bundle, str(LOCAL_MODEL)


def _make_X(url: str, train_cols: List[str]) -> pd.DataFrame:
    feats = extract_features(url)  # returns dict
    X = pd.DataFrame([feats]).reindex(columns=train_cols, fill_value=0)
    return X


def predict_with_bundle(
    url: str,
    bundle: Dict[str, Any],
    train_cols: List[str],
    suspicious_cutoff: float,
) -> Tuple[str, float, float]:
    """
    Required by server.py. Returns: (verdict, probability, threshold)

    Backend policy additions:
      - Never flag Google searches
      - Flag Discord invites only
      - Never flag owned hostnames (e.g., your GitHub Pages site)
    """
    # ✅ 1) Never flag Google searches (period)
    if is_google_search_related(url):
        return "legitimate", 0.0, float(bundle.get("threshold", DEFAULT_THRESHOLD))

    # ✅ 2) Never flag your own site(s)
    if is_owned_host(url):
        return "legitimate", 0.0, float(bundle.get("threshold", DEFAULT_THRESHOLD))

    # ✅ 3) Flag Discord invites only (no model needed)
    if is_discord_invite(url):
        threshold = float(bundle.get("threshold", DEFAULT_THRESHOLD))
        # Return a high probability so it is always treated as flagged by UI
        prob = 0.99
        verdict = DISCORD_INVITE_VERDICT  # "suspicious" by default
        return verdict, prob, threshold

    # ---- Normal ML pipeline below ----
    model = bundle["model"]
    threshold = float(bundle.get("threshold", DEFAULT_THRESHOLD))

    X = _make_X(url, train_cols)

    if hasattr(model, "predict_proba"):
        prob = float(model.predict_proba(X)[0][1])
    else:
        prob = float(model.predict(X)[0])

    if prob >= threshold:
        verdict = "phishing"
    elif prob >= suspicious_cutoff:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    return verdict, prob, threshold

