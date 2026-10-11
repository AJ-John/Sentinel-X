import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix


# =========================================================
# SENTINELX ML TRAINING
# =========================================================

BASE_DIR = os.path.dirname(__file__)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "sentinelx_dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "model"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "sentinelx_model.pkl"
)

EVALUATION_PATH = os.path.join(
    MODEL_DIR,
    "evaluation.csv"
)


FEATURES = [
    "packets_per_min",
    "connections_per_min",
    "unique_ports",
    "failed_connections",
    "login_failures",
    "new_device"
]


# =========================================================
# CONFIGURATION
# =========================================================

RANDOM_STATE = 42

REAL_NORMAL_SAMPLES = 200
SYNTHETIC_NORMAL_SAMPLES = 3000


# =========================================================
# HEADER
# =========================================================

print()
print("=" * 70)
print("             SENTINELX ML ENGINE")
print("        ISOLATION FOREST TRAINING SYSTEM")
print("=" * 70)


# =========================================================
# LOAD ORIGINAL DATASET
# =========================================================

if not os.path.exists(DATASET_PATH):

    raise FileNotFoundError(
        f"Dataset not found:\n{DATASET_PATH}"
    )


data = pd.read_csv(
    DATASET_PATH
)


print()
print(
    f"Original dataset      : {len(data)} samples"
)


# =========================================================
# VALIDATE DATASET
# =========================================================

missing_features = [
    feature
    for feature in FEATURES
    if feature not in data.columns
]

if missing_features:

    raise ValueError(
        f"Missing features: {missing_features}"
    )


# =========================================================
# CLEAN DATA
# =========================================================

data = data.copy()

data["new_device"] = (
    pd.to_numeric(
        data["new_device"],
        errors="coerce"
    )
    .fillna(0)
    .astype(int)
)

for feature in FEATURES:

    data[feature] = pd.to_numeric(
        data[feature],
        errors="coerce"
    )


data = data.dropna(
    subset=FEATURES
)


# =========================================================
# IDENTIFY ORIGINAL NORMAL DATA
# =========================================================

normal_mask = (
    (data["packets_per_min"] <= 500)
    &
    (data["connections_per_min"] <= 130)
    &
    (data["unique_ports"] <= 130)
    &
    (data["failed_connections"] <= 8)
    &
    (data["login_failures"] <= 5)
    &
    (data["new_device"] == 0)
)


original_normal = data[
    normal_mask
].copy()


original_anomalies = data[
    ~normal_mask
].copy()


print()
print("=" * 70)
print("ORIGINAL DATA DISTRIBUTION")
print("=" * 70)

print(
    f"Normal samples        : {len(original_normal)}"
)

print(
    f"Attack/anomaly samples: {len(original_anomalies)}"
)


# =========================================================
# GENERATE REALISTIC NORMAL NETWORK BEHAVIOR
# =========================================================
#
# This is important.
#
# A real laptop does not always have:
#
#   5 ports
#   10 connections
#
# Browsers, Windows services, Discord, Steam, antivirus,
# cloud applications, updates and background services can
# produce much larger normal values.
#
# We therefore create multiple normal operating patterns.
# =========================================================

rng = np.random.default_rng(
    RANDOM_STATE
)


normal_samples = []


# ---------------------------------------------------------
# PROFILE 1
# Light desktop activity
# ---------------------------------------------------------

for _ in range(700):

    connections = rng.normal(
        35,
        12
    )

    ports = rng.normal(
        25,
        10
    )

    packets = rng.normal(
        120,
        50
    )

    normal_samples.append([
        packets,
        connections,
        ports,
        rng.integers(0, 3),
        rng.integers(0, 2),
        0
    ])


# ---------------------------------------------------------
# PROFILE 2
# Normal browser / development activity
# ---------------------------------------------------------

for _ in range(900):

    connections = rng.normal(
        75,
        18
    )

    ports = rng.normal(
        55,
        15
    )

    packets = rng.normal(
        300,
        100
    )

    normal_samples.append([
        packets,
        connections,
        ports,
        rng.integers(0, 5),
        rng.integers(0, 3),
        0
    ])


# ---------------------------------------------------------
# PROFILE 3
# Heavy laptop activity
# ---------------------------------------------------------

for _ in range(900):

    connections = rng.normal(
        95,
        18
    )

    ports = rng.normal(
        80,
        15
    )

    packets = rng.normal(
        400,
        100
    )

    normal_samples.append([
        packets,
        connections,
        ports,
        rng.integers(0, 6),
        rng.integers(0, 4),
        0
    ])


# ---------------------------------------------------------
# PROFILE 4
# High but still normal activity
# ---------------------------------------------------------

for _ in range(500):

    connections = rng.normal(
        110,
        12
    )

    ports = rng.normal(
        95,
        12
    )

    packets = rng.normal(
        450,
        80
    )

    normal_samples.append([
        packets,
        connections,
        ports,
        rng.integers(0, 7),
        rng.integers(0, 4),
        0
    ])


# =========================================================
# CONVERT SYNTHETIC NORMAL DATA
# =========================================================

synthetic_normal = pd.DataFrame(
    normal_samples,
    columns=FEATURES
)


# =========================================================
# CLEAN SYNTHETIC VALUES
# =========================================================

for feature in [
    "packets_per_min",
    "connections_per_min",
    "unique_ports",
    "failed_connections",
    "login_failures"
]:

    synthetic_normal[feature] = (
        synthetic_normal[feature]
        .clip(lower=0)
        .round()
        .astype(int)
    )


synthetic_normal["new_device"] = 0


# =========================================================
# ADD ORIGINAL NORMAL DATA
# =========================================================

real_normal_features = original_normal[
    FEATURES
].copy()


training_normal = pd.concat(
    [
        real_normal_features,
        synthetic_normal
    ],
    ignore_index=True
)


# =========================================================
# REMOVE DUPLICATES
# =========================================================

training_normal = (
    training_normal
    .drop_duplicates()
    .reset_index(drop=True)
)


# =========================================================
# TRAINING INFORMATION
# =========================================================

print()
print("=" * 70)
print("FINAL NORMAL TRAINING DATA")
print("=" * 70)

print(
    f"Original normal       : "
    f"{len(real_normal_features)}"
)

print(
    f"Synthetic normal      : "
    f"{len(synthetic_normal)}"
)

print(
    f"Final training samples: "
    f"{len(training_normal)}"
)


# =========================================================
# DISPLAY NORMAL RANGES
# =========================================================

print()
print("=" * 70)
print("LEARNED NORMAL RANGES")
print("=" * 70)

for feature in FEATURES:

    print(
        f"{feature:22s}: "
        f"{training_normal[feature].min():.0f}"
        f" - "
        f"{training_normal[feature].max():.0f}"
    )


# =========================================================
# TRAIN ISOLATION FOREST
# =========================================================

X_train = training_normal[
    FEATURES
].astype(float)


print()
print("=" * 70)
print("TRAINING ISOLATION FOREST")
print("=" * 70)

print(
    "Algorithm             : Isolation Forest"
)

print(
    "Trees                 : 500"
)

print(
    "Contamination         : 3%"
)

print(
    "Training mode         : NORMAL ONLY"
)

print(
    "Features              : 6"
)


model = IsolationForest(

    n_estimators=500,

    max_samples="auto",

    contamination=0.03,

    max_features=1.0,

    bootstrap=False,

    random_state=RANDOM_STATE,

    n_jobs=-1
)


model.fit(
    X_train
)


# =========================================================
# EVALUATE ORIGINAL DATASET
# =========================================================

print()
print("=" * 70)
print("MODEL EVALUATION")
print("=" * 70)


X_eval = data[
    FEATURES
].astype(float)


predictions = model.predict(
    X_eval
)


evaluation = data.copy()


evaluation[
    "ml_prediction"
] = predictions


evaluation[
    "ml_anomaly"
] = (
    predictions == -1
)


evaluation[
    "actual_anomaly"
] = (
    ~normal_mask
).astype(int)


evaluation[
    "predicted_anomaly"
] = (
    evaluation[
        "ml_anomaly"
    ].astype(int)
)


# =========================================================
# CLASSIFICATION REPORT
# =========================================================

print()

print(
    classification_report(
        evaluation["actual_anomaly"],
        evaluation["predicted_anomaly"],
        target_names=[
            "NORMAL",
            "ANOMALY"
        ],
        zero_division=0
    )
)


# =========================================================
# CONFUSION MATRIX
# =========================================================

matrix = confusion_matrix(

    evaluation[
        "actual_anomaly"
    ],

    evaluation[
        "predicted_anomaly"
    ]
)


print(
    "Confusion Matrix"
)

print(
    "-" * 70
)

print(
    matrix
)


# =========================================================
# CREATE MODEL DIRECTORY
# =========================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


# =========================================================
# SAVE MODEL
# =========================================================

joblib.dump(
    model,
    MODEL_PATH
)


# =========================================================
# SAVE EVALUATION
# =========================================================

evaluation.to_csv(
    EVALUATION_PATH,
    index=False
)


# =========================================================
# FINAL MESSAGE
# =========================================================

print()
print("=" * 70)
print("                 TRAINING COMPLETE")
print("=" * 70)

print()

print(
    "Isolation Forest trained successfully."
)

print(
    f"Normal training samples: "
    f"{len(training_normal)}"
)

print(
    "Features: 6"
)

print()

print(
    "Model saved to:"
)

print(
    MODEL_PATH
)

print()

print(
    "Evaluation saved to:"
)

print(
    EVALUATION_PATH
)

print()

print(
    "SentinelX ML engine is ready."
)

print(
    "=" * 70
)

print()