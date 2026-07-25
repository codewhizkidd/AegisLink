"""
Trains a GradientBoostingClassifier on phishing_v2.csv (built by
build_dataset.py from live URLs) and compares it against the existing
pickled model on the same held-out test split.
"""
import pickle
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics

warnings.filterwarnings("ignore")

data = pd.read_csv("phishing_v2.csv")
X = data.drop(["url", "class"], axis=1)
y = data["class"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

gbc = GradientBoostingClassifier(max_depth=4, learning_rate=0.7, random_state=42)
gbc.fit(X_train, y_train)

y_train_pred = gbc.predict(X_train)
y_test_pred = gbc.predict(X_test)

print("=== New model (trained on phishing_v2.csv) ===")
print(f"Train accuracy: {metrics.accuracy_score(y_train, y_train_pred):.3f}")
print(f"Test accuracy:  {metrics.accuracy_score(y_test, y_test_pred):.3f}")
print(metrics.classification_report(y_test, y_test_pred))

with open("pickle/new_model_v2.pkl", "wb") as f:
    pickle.dump(gbc, f)

print("Saved to pickle/new_model_v2.pkl")

# Sanity check against known cases
print("\n=== Spot checks ===")
try:
    from feature import FeatureExtraction

    for url, expected in [
        ("https://github.com/", "safe"),
        ("https://google.com/", "safe"),
    ]:
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        pred = gbc.predict(x)[0]
        proba = gbc.predict_proba(x)[0]
        label = "safe" if pred == 1 else "phishing"
        print(f"{url} -> {label} ({proba[1]*100:.1f}% safe), expected {expected}")
except Exception as e:
    print(f"Spot check skipped: {e}")
