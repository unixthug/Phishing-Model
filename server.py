import os
from typing import Any, Dict, List

import joblib
import pandas as pd
from flask import Flask, jsonify, request
from flask_cors import CORS

from Feature_Extract import extract_features

app = Flask(__name__)
CORS(app)

MODEL_PATH = os.environ.get("MODEL_PATH", "/app/models/phishing_model.pkl")
FEATURE_COLS_PATH = os.environ.get("FEATURE_COLS_PATH", "/app/models/feature_columns.pkl")

# Thresholds (server-side, not user-configurable)
PHISH_THRESHOLD = float(os.environ.get("PHISH_THRESHOLD", "0.80"))
SUSPICIOUS_CUTOFF = float(os.environ.get("SUSPICIOUS_CUTOFF", "0.50"))

_model: Any = None
_train_cols: List[str] | None = None


def get_model() -> Any:
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def get_train_cols() -> List[str]:
    global _train_cols
    if _train_cols is None:
        cols = joblib.load(FEATURE_COLS_PATH)
        if not isinstance(cols, list) or not cols or not all(isinstance(c, str) for c in cols):
            raise ValueError("feature_columns.pkl is invalid (expected non-empty list[str])")
        _train_cols = cols
    return _train_cols


def convert_to_risk(probability):
    """Convert phishing probability (0-1) into a 0-100 risk score."""
    return round(float(probability) * 100, 2)


def explain_from_features(feats: Dict[str, Any]) -> List[str]:
    """Lightweight explanations derived from the real feature extractor."""
    reasons: List[str] = []

    try:
        if float(feats.get("url_len", 0)) > 75:
            reasons.append("Unusually long URL")
        if int(feats.get("has_at_symbol", 0)) == 1 or int(feats.get("userinfo", 0)) == 1:
            reasons.append("Contains @ symbol or userinfo")
        if int(feats.get("many_subdomains", 0)) == 1 or int(feats.get("subdomain_labels", 0)) >= 2:
            reasons.append("Excessive subdomains")
        if int(feats.get("is_https", 0)) == 0:
            reasons.append("Not using HTTPS")
        if int(feats.get("has_ip", 0)) == 1:
            reasons.append("Uses IP address instead of domain")
        if int(feats.get("shortener", 0)) == 1:
            reasons.append("URL shortener detected")
        if int(feats.get("punycode", 0)) == 1:
            reasons.append("Punycode domain (possible homograph attack)")
        if int(feats.get("suspicious_ext", 0)) == 1:
            reasons.append("Suspicious file extension in URL")
        if int(feats.get("pct_encoding", 0)) >= 3:
            reasons.append("Heavy percent-encoding in URL")
        if int(feats.get("brand_in_url", 0)) == 1 and int(feats.get("brand_in_host", 0)) == 0:
            reasons.append("Brand name in URL path but not in hostname")
        if int(feats.get("prefix_suffix_sld", 0)) == 1:
            reasons.append("Hyphen/underscore in second-level domain")
        if float(feats.get("digit_ratio", 0)) > 0.3:
            reasons.append("High ratio of digits in hostname")
    except Exception:
        pass

    return reasons


@app.route("/score", methods=["POST"])
def score():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Missing URL"}), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "Empty URL"}), 400

    try:
        feats = extract_features(url)
        X = pd.DataFrame([feats]).reindex(columns=get_train_cols(), fill_value=0)

        model = get_model()
        if hasattr(model, "predict_proba"):
            prob = float(model.predict_proba(X)[0][1])
        else:
            prob = float(model.predict(X)[0])

        score_val = convert_to_risk(prob)

        if prob >= PHISH_THRESHOLD:
            verdict = "phishing"
        elif prob >= SUSPICIOUS_CUTOFF:
            verdict = "suspicious"
        else:
            verdict = "legitimate"

        why_flagged = explain_from_features(feats)

        return jsonify(
            {
                "url": url,
                "verdict": verdict,
                "prob_phishing": round(prob, 4),
                "score": score_val,
                "threshold": PHISH_THRESHOLD,
                "why_flagged": why_flagged,
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def home():
    return jsonify({"status": "RiskLens API running", "version": "0.4.0"})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
