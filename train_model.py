import json
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

LOG_FILE = "logs/honeypot_logs.json"


def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return json.load(f)


def extract_features(log):
    return [
        log.get("threat_score", 0),
        len(log.get("username", "")),
        len(log.get("password", "")),
        1 if log.get("type") == "ssh_command" else 0
    ]


def label_data(log):
    score = log.get("threat_score", 0)
    if score >= 6:
        return 2
    elif score >= 3:
        return 1
    else:
        return 0


logs = load_logs()

if len(logs) < 5:
    print("Not enough data to train model.")
    exit()

X = []
y = []

for log in logs:
    X.append(extract_features(log))
    y.append(label_data(log))

X = np.array(X)
y = np.array(y)

model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, "ai_model.pkl")

print("Model trained and saved as ai_model.pkl")