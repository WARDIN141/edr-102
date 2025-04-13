import streamlit as st
import pandas as pd
import numpy as np
import threading
import json
import os
import time
from datetime import datetime
from agent import run_agent, collect_metrics, get_ai_threat_prediction, log_entry
from p2p_alert import start_receiver

AGENT_LOG = "agent_log.json"
ALERTS_LOG = "alerts_log.json"

st.set_page_config(page_title="Cybersec AI Dashboard", layout="wide")
st.title("💀 CYBERSEC AI DASHBOARD")

# Start background services
if "agent_thread_started" not in st.session_state:
    threading.Thread(target=run_agent, daemon=True).start()
    start_receiver()
    st.session_state.agent_thread_started = True

col1, col2 = st.columns(2)

# --- Left Column ---
with col1:
    st.header("📊 Live System Metrics")
    if os.path.exists(AGENT_LOG):
        with open(AGENT_LOG) as f:
            entries = [json.loads(line) for line in f.readlines()][-1:]
            if entries:
                latest = entries[0]
                st.metric("CPU Usage", f"{latest['metrics']['cpu']}%")
                st.metric("Memory Usage", f"{latest['metrics']['memory']}%")
                st.metric("Disk Usage", f"{latest['metrics']['disk']}%")
                st.metric("Bytes Sent", f"{latest['metrics']['bytes_sent']}")
                st.metric("Bytes Recv", f"{latest['metrics']['bytes_recv']}")
            else:
                st.info("Waiting for agent to generate logs...")
    else:
        st.info("No metrics available yet.")

    st.subheader("📉 Historical CPU & Memory")
    if os.path.exists(AGENT_LOG):
        with open(AGENT_LOG) as f:
            entries = [json.loads(line) for line in f.readlines()]
            if entries:
                timestamps = [e['timestamp'] for e in entries]
                cpu_vals = [e['metrics']['cpu'] for e in entries]
                mem_vals = [e['metrics']['memory'] for e in entries]

                st.line_chart(pd.DataFrame({'CPU': cpu_vals, 'Memory': mem_vals}, index=timestamps))
    else:
        st.info("No data to plot.")

# --- Right Column ---
with col2:
    st.header("⚠️ Threat Predictions")
    if os.path.exists(AGENT_LOG):
        with open(AGENT_LOG) as f:
            entries = [json.loads(line) for line in f.readlines()][-5:]
            for entry in entries:
                st.code(f"[{entry['timestamp']}] → Threat: {entry['ai_prediction']}", language="bash")
    else:
        st.info("Threat predictions will show up soon...")

    st.header("📁 Upload Log File")
    uploaded_file = st.file_uploader("Upload system log (JSON lines)", type=["json", "log"])
    if uploaded_file:
        lines = uploaded_file.readlines()
        parsed = [json.loads(line) for line in lines if line]
        st.write("Parsed Logs:", parsed[:3])
        st.success("Simulated Threat Analysis: No anomaly detected.")

# --- Real-time Logs ---
st.header("📟 Real-time Alerts & Logs")

placeholder = st.empty()

def refresh_logs():
    with placeholder.container():
        st.subheader("🔔 Received Alerts")
        if os.path.exists(ALERTS_LOG):
            with open(ALERTS_LOG) as f:
                alerts = f.readlines()[-5:]
                for alert in alerts:
                    try:
                        a = json.loads(alert)
                        st.code(f"[{a['timestamp']}] {a['source']} → {a['threat']}", language="bash")
                    except:
                        continue
        else:
            st.info("No alerts received yet.")

        st.subheader("📜 Agent Logs")
        if os.path.exists(AGENT_LOG):
            with open(AGENT_LOG) as f:
                logs = f.readlines()[-5:]
                for log in logs:
                    try:
                        l = json.loads(log)
                        st.code(f"[{l['timestamp']}] CPU: {l['metrics']['cpu']}% | MEM: {l['metrics']['memory']}% | Threat: {l['ai_prediction']}", language="bash")
                    except:
                        continue
        else:
            st.info("Agent logs will appear here.")

refresh_logs()
time.sleep(10)
st.rerun()