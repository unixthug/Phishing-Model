# RiskLens API + Extension

## Real-Time ML-Powered Phishing Detection

RiskLens is a machine learning–driven browser security system designed to detect phishing and malicious websites in real time.

It consists of two components:

- A Firefox extension that monitors navigation events and displays a live risk score.
- A hosted API that loads a trained phishing detection model and evaluates URLs dynamically.

Instead of relying purely on static blocklists, RiskLens evaluates URL structure and behavioral patterns using a trained LightGBM model to generate a predictive phishing probability.

---

## How It Works

When a user visits a website:

1. The extension detects a completed navigation event.
2. The URL is sent to the `/score` endpoint.
3. The backend:
   - Extracts URL-based features
   - Loads the trained model
   - Computes phishing probability
4. The API returns:
   - `verdict`
   - `prob_phishing`
   - `score`
   - `threshold`
5. The extension:
   - Converts probability to a 0–100 score
   - Updates the toolbar icon
   - Displays the animated score in the popup
   - Optionally blocks high-risk pages

---

## Architecture

### Extension (Client)

- Detects main-frame navigation
- Sends POST requests to backend
- Caches scores by hostname
- Applies configurable danger threshold
- Handles optional redirect to warning page
- Displays animated risk score UI

### Backend API (Server)

- Loads LightGBM model (`.pkl`)
- Loads feature column mapping
- Extracts structured features from URL
- Returns structured scoring response
- Designed for deployment via Docker on Render

---

## Core Features

- Real-time phishing probability scoring
- 0–100 animated risk scale
- Safe / Suspicious / Danger labeling
- Configurable block threshold
- Host-based caching to reduce API load
- Temporary allowlist bypass
- Secure API key authentication
- Server-hosted model artifacts

---

## Why This Approach

Traditional browser protections rely heavily on known malicious domain lists. RiskLens introduces predictive analysis that can:

- Evaluate newly registered domains
- Flag suspicious structural patterns
- Provide transparency through numerical scoring
- Adapt through retraining of the ML model

This makes RiskLens a practical hybrid between static filtering and intelligent threat detection.

---

## Deployment

The backend is containerized using Docker and deployed on Render.

Model artifacts are downloaded at runtime using environment variables:

- `MODEL_PKL_URL`
- `FEATURE_COLS_URL`

The API exposes:

POST /score  
Content-Type: application/json  

Example request:

{
  "url": "https://example.com"
}

Example response:

{
  "url": "https://example.com",
  "verdict": "legitimate",
  "prob_phishing": 0.03,
  "score": 3.0,
  "threshold": 0.8
}

---

## Project Status

Active development.
