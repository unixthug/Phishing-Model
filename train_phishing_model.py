import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib

# -----------------------------------------
# 1. Load dataset
# -----------------------------------------
df = pd.read_csv("phishing_features_dataset.csv")

# Remove columns that are not pure features
X = df.drop(["label", "url"], axis=1)
y = df["label"]

# -----------------------------------------
# 2. Identify feature types
# -----------------------------------------

categorical = ["registrar", "ssl_issuer"]  # strings
numerical = [col for col in X.columns if col not in categorical]

# -----------------------------------------
# 3. Preprocessing pipeline
# -----------------------------------------
preprocess = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
        ("num", "passthrough", numerical)
    ]
)

# -----------------------------------------
# 4. Model pipeline
# -----------------------------------------
model = Pipeline(
    steps=[
        ("preprocess", preprocess),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            random_state=42
        ))
    ]
)

# -----------------------------------------
# 5. Train-test split
# -----------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------------------
# 6. Train model
# -----------------------------------------
model.fit(X_train, y_train)

# -----------------------------------------
# 7. Evaluate
# -----------------------------------------
accuracy = model.score(X_test, y_test)
print(f"🔥 Model Accuracy: {accuracy:.2f}")

# -----------------------------------------
# 8. Save the model
# -----------------------------------------
joblib.dump(model, "phishing_detector_model.pkl")
print("Model saved as phishing_detector_model.pkl")
