import pandas as pd
from Feature_Extraction_Engine import extract_features   # import YOUR Increment 2 code

# 1. Load the input CSV (URLs + labels)
df = pd.read_csv("phishing_dataset_urls.csv")

all_feature_rows = []

for index, row in df.iterrows():
    url = row["url"]
    label = row["label"]

    print(f"Extracting features for: {url}")

    try:
        features = extract_features(url)
        features["label"] = label
        features["url"] = url
        all_feature_rows.append(features)

    except Exception as e:
        print(f"Error extracting {url}: {e}")

# 2. Convert all feature rows into a DataFrame
feature_df = pd.DataFrame(all_feature_rows)

# 3. Save dataset
feature_df.to_csv("phishing_features_dataset.csv", index=False)

print("🎉 Feature extraction complete!")
print("➡ Output saved as: phishing_features_dataset.csv")
