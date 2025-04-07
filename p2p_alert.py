import socket
import threading
import json
from datetime import datetime

BROADCAST_PORT = 5005
BROADCAST_IP = '<broadcast>'
ALERTS_LOG_FILE = "alerts_log.json"

def send_alert(alert_data):
    message = json.dumps(alert_data).encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(message, (BROADCAST_IP, BROADCAST_PORT))
        print(f"[UDP] Alert sent: {alert_data}")

def receive_alerts():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', BROADCAST_PORT))
        print("[UDP] Listening for incoming alerts...")

        while True:
            data, addr = s.recvfrom(4096)
            alert = json.loads(data.decode('utf-8'))
            alert["received_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_alert(alert)
            print(f"[UDP] Received alert from {addr}: {alert}")

def log_alert(alert):
    with open(ALERTS_LOG_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def start_receiver():
    threading.Thread(target=receive_alerts, daemon=True).start()

if __name__ == "__main__":
    start_receiver()
    # To test sending:
    # send_alert({"source": "agent1", "threat": "DDoS", "timestamp": datetime.now().isoformat()})
