import joblib
import os

MODEL_PATH = "ai_model.pkl"

model = None

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)


def predict_attack_risk(threat_score, username="", password="", log_type="web"):
    if model is None:
        return "UNKNOWN"

    features = [
        threat_score,
        len(username),
        len(password),
        1 if log_type == "ssh_command" else 0
    ]

    prediction = model.predict([features])[0]

    if prediction == 2:
        return "HIGH"
    elif prediction == 1:
        return "MEDIUM"
    else:
        return "LOW"