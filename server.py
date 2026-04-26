import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from predict import predict_url

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)

def convert_to_risk(probability: float) -> float:
    return round(float(probability) * 100, 2)


@app.route("/score", methods=["POST"])
@limiter.limit("60 per minute")
def score():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing URL"}), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "Empty URL"}), 400

    result = predict_url(url)

    if not result.get("success"):
        return jsonify({"error": result.get("error", "Prediction failed")}), 500

    prob = result["prediction_score"]
    return jsonify({
        "url": result["url"],
        "verdict": result["classification"],
        "prob_phishing": round(prob, 4) if prob is not None else None,
        "score": convert_to_risk(prob) if prob is not None else None,
        "threshold": result["phishing_threshold"],
        "suspicious_threshold": result["suspicious_threshold"],
        "why_flagged": result["signals"] if result["classification"] in {"suspicious", "phishing"} else [],
        "ai_feedback": result["ai_feedback"],
        "decision_source": result["decision_source"],
        "certificate_check": result["certificate_check"],
    })


@app.route("/")
def home():
    return jsonify({"status": "RiskLens API running", "version": "0.5.0"})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
