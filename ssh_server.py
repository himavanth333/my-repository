import socket
import threading
import json
import os
import hashlib
import subprocess
from datetime import datetime
from ai_model import predict_attack_risk

HOST = "127.0.0.1"  # safer on Windows
PORT = 50022       # high safe port
LOG_FILE = "logs/honeypot_logs.json"

SUSPICIOUS_COMMANDS = ["wget", "curl", "nc", "nmap", "chmod", "sudo"]

SAFE_COMMANDS = ["ls", "pwd", "whoami", "id", "echo", "cat"]


def calculate_command_score(command):
    score = 0
    for word in SUSPICIOUS_COMMANDS:
        if word in command:
            score += 2
    if command == "whoami":
        score += 1
    return score


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

    previous_hash = logs[-1]["current_hash"] if logs and "current_hash" in logs[-1] else "0"
    data["previous_hash"] = previous_hash

    log_string = json.dumps(data, sort_keys=True)
    data["current_hash"] = hashlib.sha256(log_string.encode()).hexdigest()

    logs.append(data)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)


def recv_data(conn):
    data = b""
    while not data.endswith(b"\n"):
        try:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
        except:
            break
    return data.decode(errors="ignore").strip()


def handle_client(conn, addr):
    ip = addr[0]

    try:
        conn.sendall(b"Ubuntu 22.04 LTS\r\n")
        conn.sendall(b"login: ")

        username = recv_data(conn)
        conn.sendall(b"Password: ")
        password = recv_data(conn)

        threat_score = 1

        ai_risk = predict_attack_risk(
            threat_score,
            username,
            password,
            "ssh_login"
        )

        log_event({
            "timestamp": str(datetime.now()),
            "ip": ip,
            "type": "ssh_login_attempt",
            "username": username,
            "password": password,
            "threat_score": threat_score,
            "ai_risk": ai_risk
        })

        conn.sendall(b"\r\nLogin incorrect\r\n")

        while True:
            conn.sendall(b"$ ")
            command = recv_data(conn)

            if not command:
                break

            if command.lower() == "exit":
                conn.sendall(b"logout\r\n")
                break

            threat_score = calculate_command_score(command)

            ai_risk = predict_attack_risk(
                threat_score,
                username,
                command,
                "ssh_command"
            )

            log_event({
                "timestamp": str(datetime.now()),
                "ip": ip,
                "type": "ssh_command",
                "command": command,
                "threat_score": threat_score,
                "ai_risk": ai_risk
            })

            # -------- LINUX COMMAND EXECUTION --------
            try:
                base_cmd = command.split()[0]

                if base_cmd in SAFE_COMMANDS:
                    result = subprocess.getoutput(command)
                    conn.sendall(result.encode() + b"\r\n")
                else:
                    conn.sendall(b"command not found\r\n")

            except Exception:
                conn.sendall(b"error executing command\r\n")

    except:
        pass
    finally:
        conn.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] SSH Honeypot running on port {PORT}")

    try:
        while True:
            conn, addr = server.accept()
            print(f"[+] Connection from {addr}")

            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            ).start()

    except KeyboardInterrupt:
        print("\n[!] Shutting down honeypot...")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()