import os
import joblib
import pandas as pd


# =========================================================
# MODEL PATH
# =========================================================

MODEL_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "ml",
        "model",
        "sentinelx_model.pkl"
    )
)


# =========================================================
# FEATURES
# =========================================================

FEATURES = [
    "packets_per_min",
    "connections_per_min",
    "unique_ports",
    "failed_connections",
    "login_failures",
    "new_device"
]


# =========================================================
# LOAD MODEL
# =========================================================

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"SentinelX ML model not found:\n"
        f"{MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)


# =========================================================
# ML ANOMALY DETECTION
# =========================================================

def detect_anomaly(event: dict):

    agent_status = event.get(
        "agent_status",
        "UNKNOWN"
    )


    # =====================================================
    # BASELINE LEARNING
    # =====================================================

    if agent_status == "BASELINE_LEARNING":

        return {
            "ml_anomaly": False,
            "ml_prediction": 1,
            "ml_status": "BASELINE",
            "ml_reason": (
                "Local security agent is "
                "still learning baseline behavior."
            )
        }


    # =====================================================
    # NORMAL LOCAL ACTIVITY
    # =====================================================

    if agent_status == "NORMAL":

        return {
            "ml_anomaly": False,
            "ml_prediction": 1,
            "ml_status": "NORMAL",
            "ml_reason": (
                "Activity is within the "
                "local endpoint baseline."
            )
        }


    # =====================================================
    # SUSPICIOUS / HIGH ACTIVITY
    # =====================================================

    data = pd.DataFrame([
        {
            feature: event.get(
                feature,
                0
            )
            for feature in FEATURES
        }
    ])


    prediction = model.predict(
        data[FEATURES]
    )[0]

    prediction = int(prediction)

    is_anomaly = prediction == -1


    # =====================================================
    # LOCAL AGENT + ML CONFIRMATION
    # =====================================================

    if agent_status in [
        "SUSPICIOUS",
        "HIGH_ACTIVITY"
    ]:

        if is_anomaly:

            status = "ANOMALY"

            reason = (
                "Local baseline deviation "
                "confirmed by Isolation Forest."
            )

        else:

            status = "NORMAL"

            reason = (
                "Local baseline deviation detected, "
                "but Isolation Forest did not classify "
                "the event as anomalous."
            )


    # =====================================================
    # UNKNOWN STATUS
    # =====================================================

    else:

        status = (
            "ANOMALY"
            if is_anomaly
            else
            "NORMAL"
        )

        reason = (
            "Isolation Forest classification."
        )


    # =====================================================
    # RETURN RESULT
    # =====================================================

    return {

        "ml_anomaly":
            is_anomaly,

        "ml_prediction":
            prediction,

        "ml_status":
            status,

        "ml_reason":
            reason

    }