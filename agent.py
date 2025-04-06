import psutil
import platform
import time
import json
import socket
import os
import csv
from datetime import datetime
from collections import defaultdict

class SystemMonitor:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.os_type = platform.system()
        self.known_processes = ["chrome", "firefox", "explorer.exe", "bash", "python"]
        self.system_processes = self._get_system_process_list()
        self.log_file = os.path.abspath(os.path.join("logs", "system_monitor.log"))
        self.report_file = os.path.abspath(os.path.join("reports", "system_report.csv"))
        self.setup_directories()

    def _get_system_process_list(self):
        return {
            "Windows": [
                "svchost.exe", "System", "smss.exe", "csrss.exe",
                "wininit.exe", "services.exe", "lsass.exe"
            ],
            "Linux": ["systemd", "kthreadd", "ksoftirqd", "rcu_sched", "cron"],
            "Darwin": ["launchd", "kernel_task", "mDNSResponder"]
        }.get(self.os_type, [])

    def setup_directories(self):
        os.makedirs("logs", exist_ok=True)
        os.makedirs("reports", exist_ok=True)

    def collect_metrics(self):
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system": {
                "host": self.hostname,
                "os": self.os_type,
                "uptime": int(time.time() - psutil.boot_time())
            },
            "resources": {
                "cpu": psutil.cpu_percent(interval=1),
                "memory": psutil.virtual_memory().percent,
                "process_count": len(psutil.pids())
            },
            "network": self._get_network_stats(),
            "processes": self._get_process_stats()
        }

    def _get_network_stats(self):
        connections = [
            {
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status
            }
            for conn in psutil.net_connections(kind='inet')
            if conn.status == 'ESTABLISHED'
        ]
        return {"total_connections": len(connections), "connections": connections[:5]}

    def _get_process_stats(self):
        processes = []
        suspicious = []

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']):
            try:
                name = proc.info['name']
                if name and name.lower() in [p.lower() for p in self.system_processes]:
                    continue

                processes.append({
                    "pid": proc.info['pid'],
                    "name": name,
                    "user": proc.info['username'],
                    "cpu": proc.info['cpu_percent']
                })

                if name and name.lower() not in [p.lower() for p in self.known_processes]:
                    suspicious.append(name)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            "total_processes": len(processes),
            "suspicious_processes": suspicious,
            "top_processes": sorted(processes, key=lambda x: x['cpu'], reverse=True)[:5]
        }

    def detect_anomalies(self, metrics):
        alerts = defaultdict(list)
        if metrics['resources']['cpu'] > 90:
            alerts['resource_alerts'].append("High CPU usage")
        if metrics['resources']['memory'] > 90:
            alerts['resource_alerts'].append("High memory usage")
        if metrics['processes']['suspicious_processes']:
            alerts['security_alerts'].append(
                f"Unknown processes: {', '.join(metrics['processes']['suspicious_processes'])}"
            )
        return dict(alerts)

    def log_data(self, metrics, alerts):
        with open(self.log_file, 'a') as f:
            json.dump({
                "timestamp": metrics['timestamp'],
                "metrics": metrics,
                "alerts": alerts if alerts else None
            }, f)
            f.write('\n')

    def generate_report(self):
        try:
            with open(self.log_file, 'r') as f:
                logs = [json.loads(line) for line in f]

            with open(self.report_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=[
                    'timestamp', 'host', 'os', 'uptime',
                    'cpu_percent', 'memory_percent', 'process_count',
                    'network_connections', 'alerts', 'top_processes'
                ])
                writer.writeheader()

                for entry in logs:
                    writer.writerow({
                        'timestamp': entry['timestamp'],
                        'host': entry['metrics']['system']['host'],
                        'os': entry['metrics']['system']['os'],
                        'uptime': entry['metrics']['system']['uptime'],
                        'cpu_percent': entry['metrics']['resources']['cpu'],
                        'memory_percent': entry['metrics']['resources']['memory'],
                        'process_count': entry['metrics']['resources']['process_count'],
                        'network_connections': entry['metrics']['network']['total_connections'],
                        'alerts': ' | '.join(
                            f"{k}: {', '.join(v)}"
                            for k, v in entry.get('alerts', {}).items()
                        ) if entry.get('alerts') else 'None',
                        'top_processes': ', '.join(
                            f"{p['name']}({p['cpu']}%)"
                            for p in entry['metrics']['processes']['top_processes']
                        )
                    })

            print(f"\n[+] Report generated at: {self.report_file}")

        except Exception as e:
            print(f"\n[!] Failed to generate report: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    monitor = SystemMonitor()
    print(f"[*] Monitoring {monitor.hostname} ({monitor.os_type})\nPress Ctrl+C to stop and generate report.\n")

    try:
        while True:
            metrics = monitor.collect_metrics()
            alerts = monitor.detect_anomalies(metrics)
            monitor.log_data(metrics, alerts)
            time.sleep(5)
    except KeyboardInterrupt:
        monitor.generate_report()
        print("\n[!] Monitoring stopped. Final report generated.")