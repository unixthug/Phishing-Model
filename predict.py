# predict.py
import os
import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import pandas as pd
import requests

from Feature_Extract import extract_features  # :contentReference[oaicite:1]{index=1}

# -------------------------
# Config (env overridable)
# -------------------------
MODELS_DIR = Path(os.getenv("MODELS_DIR", "models"))
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Hugging Face direct-download "resolve" URLs (set these in Render/Docker env)
MODEL_PKL_URL = os.getenv("MODEL_PKL_URL", "").strip()
FEATURE_COLS_URL = os.getenv("FEATURE_COLS_URL", "").strip()

# Local filenames (in /models)
LOCAL_MODEL = MODELS_DIR / os.getenv("LOCAL_MODEL_NAME", "phishing_model.pkl")
LOCAL_COLS_PKL = MODELS_DIR / os.getenv("LOCAL_COLS_PKL_NAME", "feature_columns.pkl")

# Thresholding
DEFAULT_THRESHOLD = float(os.getenv("PHISH_THRESHOLD", "0.80"))

# Internal caches
_lock = threading.Lock()
_cached_model: Any = None
_cached_cols: List[str] | None = None


def _download(url: str, dest: Path) -> None:
    """Download a file to dest (atomic write)."""
    if not url:
        raise RuntimeError(f"Missing download URL for {dest.name}. Set env var(s).")

    headers = {}

    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with requests.get(url, headers=headers, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
    tmp.replace(dest)


def _ensure_artifacts_present() -> None:
    """
    Ensure model + feature columns exist locally.
    We accept either feature_columns.pkl or feature_columns.json.
    """
    # Model
    if not LOCAL_MODEL.exists():
        _download(MODEL_PKL_URL, LOCAL_MODEL)

    # Columns: prefer pkl;
    if not LOCAL_COLS_PKL.exists()
        _download(FEATURE_COLS_URL, LOCAL_COLS_PKL)


def load_train_cols() -> List[str]:
    """
    Required by server.py.
    Loads and caches the training column order.
    """
    global _cached_cols
    with _lock:
        if _cached_cols is not None:
            return _cached_cols

        _ensure_artifacts_present()

        if LOCAL_COLS_PKL.exists():
            cols = joblib.load(LOCAL_COLS_PKL)

        if not isinstance(cols, list) or not cols or not all(isinstance(c, str) for c in cols):
            raise ValueError("Feature columns file is invalid (expected a non-empty list[str]).")

        _cached_cols = cols
        return cols


def load_bundle(_model_choice: str) -> Tuple[Dict[str, Any], str]:
    """
    Required by server.py.
    We ignore model_choice and load the single HF-hosted model.
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
    feats = extract_features(url)  # returns dict with 40 feature keys :contentReference[oaicite:2]{index=2}
    X = pd.DataFrame([feats]).reindex(columns=train_cols, fill_value=0)
    return X


def predict_with_bundle(
    url: str,
    bundle: Dict[str, Any],
    train_cols: List[str],
    suspicious_cutoff: float,
) -> Tuple[str, float, float]:
    """
    Required by server.py.
    Returns: (verdict, probability, threshold)
    """
    model = bundle["model"]
    threshold = float(bundle.get("threshold", DEFAULT_THRESHOLD))

    X = _make_X(url, train_cols)

    # LightGBM sklearn API supports predict_proba; if not, fall back to predict
    if hasattr(model, "predict_proba"):
        prob = float(model.predict_proba(X)[0][1])
    else:
        # Some models output score directly
        prob = float(model.predict(X)[0])

    if prob >= threshold:
        verdict = "phishing"
    elif prob >= suspicious_cutoff:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    return verdict, prob, threshold