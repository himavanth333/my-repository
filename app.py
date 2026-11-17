from flask import Flask, request, render_template, jsonify, session, redirect, url_for
import json
import os
import time
from datetime import datetime
from collections import defaultdict
import hashlib
import threading
import subprocess

from ai_model import predict_attack_risk

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

LOG_FILE = "logs/honeypot_logs.json"
FAKE_FILESYSTEM = {
    "/": ["bin", "etc", "home", "var", "usr"],
    "/home": ["admin"],
    "/home/admin": [".bashrc", ".ssh", "notes.txt"],
    "/etc": ["passwd", "shadow", "hosts"],
    "/var": ["log"],
    "/var/log": ["auth.log", "syslog"]
}

FAKE_FILE_CONTENT = {
    "/etc/passwd":
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin:x:1000:1000::/home/admin:/bin/bash",

    "/etc/shadow":
        "root:$6$randomhash:19000:0:99999:7:::\n"
        "admin:$6$anotherhash:19000:0:99999:7:::",

    "/var/log/auth.log":
        "Feb 18 sshd[1024]: Failed password for root from 192.168.1.50\n"
}
# ---------------- ADMIN CONFIG ----------------
REAL_ADMIN_USERNAME = "admin"
REAL_ADMIN_PASSWORD = "admin$123"

FAILED_ADMIN_ATTEMPTS = {}
ADMIN_ATTEMPT_LIMIT = 3

SUSPICIOUS_KEYWORDS = ["admin", "root", "select", "drop", "union", "1=1", "--"]


# ---------------- THREAT SCORING ----------------
def calculate_threat_score(username, password):
    score = 0

    if username and username.lower() in ["admin", "root", "administrator"]:
        score += 3

    for keyword in SUSPICIOUS_KEYWORDS:
        if (username and keyword in username.lower()) or \
           (password and keyword in password.lower()):
            score += 2

    if password and len(password) < 4:
        score += 1

    return score


# ---------------- LOG UTILITIES ----------------
def get_logs():
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except:
        return []


def log_event(data):
    if not os.path.exists("logs"):
        os.makedirs("logs")

    logs = get_logs()
    previous_hash = logs[-1]["current_hash"] if logs else "0"

    block = {
        "timestamp": data.get("timestamp"),
        "ip": data.get("ip"),
        "type": data.get("type"),
        "username": data.get("username"),
        "password": data.get("password"),
        "user_agent": data.get("user_agent"),
        "threat_score": data.get("threat_score"),
        "ai_risk": data.get("ai_risk"),
        "previous_hash": previous_hash
    }

    block_string = json.dumps(block, sort_keys=True)
    current_hash = hashlib.sha256(block_string.encode()).hexdigest()
    block["current_hash"] = current_hash

    logs.append(block)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)


def verify_chain():
    logs = get_logs()

    for i in range(1, len(logs)):
        current = logs[i]
        previous = logs[i - 1]

        block_copy = current.copy()
        stored_hash = block_copy.pop("current_hash", None)

        recalculated_hash = hashlib.sha256(
            json.dumps(block_copy, sort_keys=True).encode()
        ).hexdigest()

        if stored_hash != recalculated_hash:
            return False

        if current["previous_hash"] != previous.get("current_hash"):
            return False

    return True


def calculate_ip_totals(logs):
    ip_totals = defaultdict(int)
    for log in logs:
        ip = log.get("ip")
        score = log.get("threat_score", 0)
        if ip:
            ip_totals[ip] += score
    return ip_totals


# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    # REAL ADMIN
    if username == REAL_ADMIN_USERNAME and password == REAL_ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return redirect(url_for("admin_dashboard"))

    # FAKE ADMIN TRAP
    if username == "admin":
        FAILED_ADMIN_ATTEMPTS[ip] = FAILED_ADMIN_ATTEMPTS.get(ip, 0) + 1
        if FAILED_ADMIN_ATTEMPTS[ip] >= ADMIN_ATTEMPT_LIMIT:
            session["fake_admin"] = True
            return redirect(url_for("fake_admin_dashboard"))

    threat_score = calculate_threat_score(username, password)
    ai_risk = predict_attack_risk(threat_score, username, password, "web")

    log_event({
        "timestamp": str(datetime.now()),
        "ip": ip,
        "type": "web_login_attempt",
        "username": username,
        "password": password,
        "user_agent": user_agent,
        "threat_score": threat_score,
        "ai_risk": ai_risk
    })

    return "Authentication Failed."


@app.route("/admin")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("home"))

    logs = get_logs()
    logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)

    ip_totals = calculate_ip_totals(logs)
    chain_valid = verify_chain()

    return render_template(
        "admin.html",
        logs=logs,
        ip_totals=ip_totals,
        chain_valid=chain_valid
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------- FAKE ADMIN ----------------

@app.route("/fake-admin")
def fake_admin_dashboard():
    if not session.get("fake_admin"):
        return redirect(url_for("home"))

    # Log fake admin access
    log_event({
        "timestamp": str(datetime.now()),
        "ip": request.remote_addr,
        "type": "fake_admin_access",
        "username": "admin",
        "password": "unknown",
        "user_agent": request.headers.get("User-Agent"),
        "threat_score": 8,
        "ai_risk": "HIGH"
    })

    return render_template("fake_admin.html")


# ---------------- API ----------------

@app.route("/api/logs")
def api_logs():
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 403

    logs = get_logs()
    logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify(logs)


# ---------------- SIMULATION ----------------

@app.route("/simulate")
def simulate_attack():
    from random import randint, choice

    fake_ips = ["192.168.1." + str(randint(2, 254)) for _ in range(5)]
    risks = ["LOW", "MEDIUM", "HIGH"]

    for ip in fake_ips:
        threat = randint(1, 8)
        log_event({
            "timestamp": str(datetime.now()),
            "ip": ip,
            "type": "simulated_attack",
            "username": "admin",
            "password": "1234",
            "threat_score": threat,
            "ai_risk": choice(risks)
        })

    return "Simulation Triggered"


# ---------------- LINUX SANDBOX EXECUTION ----------------
# ---------------- LINUX SANDBOX EXECUTION ----------------

@app.route("/linux_exec", methods=["POST"])
def linux_exec():

    if not session.get("fake_admin"):
        return jsonify({"output": "Access Denied"})

    data = request.get_json()
    command = data.get("command", "").strip()

    # Isolated fake terminal state
    if "fake_cwd" not in session:
        session["fake_cwd"] = "/home/admin"

    cwd = session["fake_cwd"]
    parts = command.split()
    output = ""

    if command == "pwd":
        output = cwd

    elif command == "ls":
        output = "  ".join(FAKE_FILESYSTEM.get(cwd, []))

    elif parts and parts[0] == "cd":
        if len(parts) < 2:
            output = ""
        else:
            target = parts[1]

            if target == "..":
                if cwd != "/":
                    cwd = "/".join(cwd.rstrip("/").split("/")[:-1])
                    if cwd == "":
                        cwd = "/"

            elif target.startswith("/"):
                if target in FAKE_FILESYSTEM:
                    cwd = target
                else:
                    output = f"bash: cd: {target}: No such file or directory"

            else:
                new_path = cwd.rstrip("/") + "/" + target
                if new_path in FAKE_FILESYSTEM:
                    cwd = new_path
                else:
                    output = f"bash: cd: {target}: No such file or directory"

            session["fake_cwd"] = cwd

    elif parts and parts[0] == "cat":
        if len(parts) > 1:
            file_path = parts[1]
            if not file_path.startswith("/"):
                file_path = cwd.rstrip("/") + "/" + file_path

            output = FAKE_FILE_CONTENT.get(file_path, "No such file")
        else:
            output = "cat: missing operand"

    elif command == "whoami":
        output = "root"

    elif command == "uname -a":
        output = "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"

    elif command.startswith("sudo"):
        output = "[sudo] password for root:"

    elif command == "exit":
        output = "logout"

    else:
        output = "command not found"

    # Log it
    log_event({
        "timestamp": str(datetime.now()),
        "ip": request.remote_addr,
        "type": "fake_terminal_command",
        "username": "admin",
        "password": "unknown",
        "user_agent": request.headers.get("User-Agent"),
        "threat_score": 5,
        "ai_risk": "HIGH"
    })

    return jsonify({
        "output": output,
        "cwd": session.get("fake_cwd", "/home/admin")
    })
# ---------------- REAL LINUX EXECUTION ----------------
@app.route("/real_linux_exec", methods=["POST"])
def real_linux_exec():

    if not session.get("admin_logged_in"):
        return jsonify({"output": "Access Denied"})

    data = request.get_json()
    command = data.get("command", "").strip()

    try:
        result = subprocess.getoutput(f'bash -c "{command}"')
    except Exception as e:
        result = str(e)

    return jsonify({"output": result})
# ---------------- AUTO RETRAIN ----------------

def auto_retrain():
    while True:
        time.sleep(300)
        subprocess.run(["python", "train_model.py"])


threading.Thread(target=auto_retrain, daemon=True).start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)