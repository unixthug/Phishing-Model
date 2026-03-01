import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# Load trained model
MODEL_PATH = os.environ.get(
    "MODEL_PATH",
    "/app/models/phishing_model.pkl"
)
model = joblib.load(MODEL_PATH)


# -----------------------------
# Feature Extraction for simple "no no's" to explain risk scoring
# -----------------------------
def extract_features(url):
    parsed = urlparse(url)

    return [
        len(url),                         # URL length
        url.count("."),                   # Dot count
        int("https" not in parsed.scheme),# HTTP (1) vs HTTPS (0)
        int("@" in url),                  # @ symbol present
        int("-" in parsed.netloc),        # Dash in domain
        int(bool(re.search(r"\d", parsed.netloc))),  # Digits in domain
    ]


# -----------------------------
# Risk Score Conversion
# -----------------------------
def convert_to_risk(probability):
    """
    Convert phishing probability (0-1)
    into a 0-100 risk score for extension.
    """
    return round(probability * 100)


# -----------------------------
# Score Endpoint (NO API KEY)
# -----------------------------
@app.route("/score", methods=["POST"])
def score():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Missing URL"}), 400

    url = data["url"]

    try:
        features = extract_features(url)
        probability = model.predict_proba([features])[0][1]
        risk_score = convert_to_risk(probability)

        # Simple explanation logic (kept lightweight)
        reasons = []

        if len(url) > 75:
            reasons.append("Unusually long URL")

        if "@" in url:
            reasons.append("Contains @ symbol")

        if url.count(".") > 4:
            reasons.append("Excessive subdomains")

        if "https" not in url:
            reasons.append("Not using HTTPS")

        return jsonify({
            "score": risk_score,
            "probability": round(probability, 4),
            "reasons": reasons
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# Health Check
# -----------------------------
@app.route("/")
def home():
    return jsonify({"status": "RiskLens API running"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)