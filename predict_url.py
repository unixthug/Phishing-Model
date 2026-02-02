import json #for API and frontend
import joblib #used to help effeciency off loading the model
import pandas as pd # helps format matching for ze model uh huhuhuh
from functools import lru_cache # this is for the optimazation when we implement sql
from Feature_Extraction_Engine import extract_features 

MODEL_PATH = "phishing_detector_model.pkl"          # model file location
FEATURES_PATH = "models/feature_columns.json"       # for the front end

#loads model once to speed up stuff
_model = joblib.load(MODEL_PATH)

with open(FEATURES_PATH, "r") as f:
    FEATURE_COLUMNS = json.load(f)

#we can adjust this for the false positives
T_LOW = 0.20     # <= this is Safe
T_HIGH = 0.32    # >= this is Phishing
# between will be marked as Sus

#actual prediction stuff
@lru_cache(maxsize=1024)
def classify_new_url(url: str):
    # Extract features
    feats = extract_features(url)
    df = pd.DataFrame([feats])

    # Enforce training-time feature order
    df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)

    # Gets probabilities
    probs = _model.predict_proba(df)[0]
    p_safe = float(probs[0])
    p_phish = float(probs[1])

    #labels for front end
    if p_phish >= T_HIGH:
        label = "Phishing"
    elif p_phish <= T_LOW:
        label = "Safe"
    else:
        label = "Suspicious"

  #risk scores
    low = max(0.0, (0.5 - p_phish) / 0.5)
    high = max(0.0, (p_phish - 0.5) / 0.5)
    medium = 1.0 - (low + high)

    low, medium, high = map(lambda x: round(x, 3), (low, medium, high))

    return {
        "label": label,
        "p_safe": round(p_safe, 3),
        "p_phishing": round(p_phish, 3),
        "thresholds": {
            "safe_max": T_LOW,
            "phishing_min": T_HIGH
        },
        "risk_scores": {
            "low": low,
            "medium": medium,
            "high": high
        }
    }

#example 
if __name__ == "__main__":
    url = input("Enter URL: ").strip()
    result = classify_new_url(url)
    print(json.dumps(result, indent=2))
