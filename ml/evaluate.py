import os

import joblib
import pandas as pd


MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "model",
    "sentinelx_model.pkl"
)

DATASET_PATH = os.path.join(
    os.path.dirname(__file__),
    "dataset",
    "sentinelx_dataset.csv"
)

FEATURES = [
    "packets_per_min",
    "connections_per_min",
    "unique_ports",
    "failed_connections",
    "login_failures",
    "new_device"
]


model = joblib.load(MODEL_PATH)

data = pd.read_csv(DATASET_PATH)

X = data[FEATURES]

predictions = model.predict(X)

data["prediction"] = predictions

data["result"] = data["prediction"].map({
    1: "NORMAL",
    -1: "ANOMALY"
})

print("\nSentinelX ML Evaluation")
print("=" * 40)

print(data[FEATURES + ["prediction", "result"]].to_string(index=False))

print("\nPrediction Summary")
print("=" * 40)

print(data["result"].value_counts())

print("\n-1 = Anomaly")
print(" 1 = Normal")