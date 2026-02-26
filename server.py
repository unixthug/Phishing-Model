import os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from predict import load_train_cols, load_bundle, predict_with_bundle

app = FastAPI()

API_KEY = os.getenv("RISKLENS_API_KEY", "")

train_cols = load_train_cols()
rf_bundle, _ = load_bundle("rf")

class UrlInput(BaseModel):
    url: str

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/score")
def score(data: UrlInput, x_api_key: str | None = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    verdict, prob, threshold = predict_with_bundle(
        data.url, rf_bundle, train_cols, suspicious_cutoff=0.20
    )

    return {
        "url": data.url,
        "verdict": verdict,
        "prob_phishing": prob,     # 0..1
        "score": prob * 100.0,     # 0..100
        "threshold": threshold
    }