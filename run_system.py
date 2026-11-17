import subprocess
import threading

def run_flask():
    subprocess.run(["python", "app.py"])

def run_ssh():
    subprocess.run(["python", "ssh_server.py"])

threading.Thread(target=run_flask).start()
threading.Thread(target=run_ssh).start()