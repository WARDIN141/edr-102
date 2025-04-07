import json
import time
import psutil
import joblib
import pandas as pd
import os
import socket
import subprocess
from datetime import datetime
from p2p_alert import send_alert  # Importing send_alert for P2P broadcasting

MODEL_FILENAME = "trained_model.pkl"
LOG_FILENAME = "agent_log.json"

def collect_metrics():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    net = psutil.net_io_counters()
    
    return {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "CPU_Usage": cpu,
        "Memory_Usage": memory,
        "Disk_Usage": disk,
        "Bytes_Sent": net.bytes_sent,
        "Bytes_Recv": net.bytes_recv
    }

def get_ai_threat_prediction(data_row_dict):
    clf, label_encoder = joblib.load(MODEL_FILENAME)
    input_df = pd.DataFrame([data_row_dict])
    input_df = input_df[[col for col in clf.feature_names_in_ if col in input_df.columns]]
    input_df = input_df.reindex(columns=clf.feature_names_in_, fill_value=0)
    prediction = clf.predict(input_df)[0]
    prediction_label = label_encoder.inverse_transform([prediction])[0]
    return prediction_label

def auto_remediate(prediction):
    print(f"[!] Auto-Remediation Triggered for Threat: {prediction}")
    if any(key in prediction for key in ["DDoS", "DoS", "Bot"]):
        disable_network()
    elif any(key in prediction for key in ["Infiltration", "Heartbleed"]):
        kill_high_usage_processes()
    elif any(key in prediction for key in ["Web Attack", "Patator", "PortScan"]):
        simulate_blocking_ip()

def disable_network():
    print("[!] Disabling network interface temporarily...")
    if os.name == "nt":
        os.system("ipconfig /release")
    else:
        os.system("sudo ifconfig eth0 down")
    time.sleep(5)
    print("[+] Re-enabling network interface...")
    if os.name == "nt":
        os.system("ipconfig /renew")
    else:
        os.system("sudo ifconfig eth0 up")

def kill_high_usage_processes(threshold=50):
    print("[!] Checking for high CPU/Memory usage processes...")
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            if proc.info['cpu_percent'] > threshold or proc.info['memory_percent'] > threshold:
                print(f"[!] Killing Process: {proc.info['name']} (PID: {proc.info['pid']})")
                psutil.Process(proc.info['pid']).kill()
        except Exception as e:
            print(f"[!] Error terminating process: {e}")

def simulate_blocking_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"[!] Simulating blocking of IP: {local_ip}")
    # In real case, use firewall or routing table

def log_entry(data, prediction):
    entry = {
        "timestamp": data["Timestamp"],
        "metrics": {
            "cpu": data["CPU_Usage"],
            "memory": data["Memory_Usage"],
            "disk": data["Disk_Usage"],
            "bytes_sent": data["Bytes_Sent"],
            "bytes_recv": data["Bytes_Recv"]
        },
        "ai_prediction": prediction
    }

    with open(LOG_FILENAME, "a") as log_file:
        log_file.write(json.dumps(entry) + "\n")

    print(f"[+] Logged: {entry}")

def broadcast_alert(prediction):
    alert_data = {
        "source": socket.gethostname(),
        "threat": prediction,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    send_alert(alert_data)

def main():
    print("[*] Agent started. Monitoring, remediating, and broadcasting alerts...")
    while True:
        metrics = collect_metrics()
        prediction = get_ai_threat_prediction(metrics)
        auto_remediate(prediction)
        broadcast_alert(prediction)
        log_entry(metrics, prediction)
        time.sleep(10)  # adjustable

if __name__ == "__main__":
    main()
