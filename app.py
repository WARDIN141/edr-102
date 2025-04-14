import streamlit as st
import pandas as pd
import json
import os
import threading
from datetime import datetime
from agent import main as run_agent, collect_metrics, get_ai_threat_prediction, log_entry
from p2p_alert import start_receiver

# Constants
AGENT_LOG = "agent_log.json"
ALERTS_LOG = "alerts_log.json"
MODEL_FILENAME = "trained_model.pkl"

# Custom CSS for modern aesthetic
st.markdown("""
    <style>
    .main {
        background: linear-gradient(to right, #1e1e2f, #2a2a3d);
        color: #ffffff;
        font-family: 'Arial', sans-serif;
    }
    .sidebar .sidebar-content {
        background: #1a1a27;
        color: #ffffff;
    }
    .stButton>button {
        background-color: #4ecca3;
        color: white;
        border-radius: 5px;
    }
    .stSelectbox, .stTextInput {
        background-color: #2e2e42;
        color: #ffffff;
        border-radius: 5px;
    }
    .metric-box {
        background-color: #2e2e42;
        padding: 10px;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.3);
    }
    </style>
""", unsafe_allow_html=True)

# Cache log loading
@st.cache_data
def load_logs(file_path):
    try:
        if os.path.exists(file_path):
            with open(file_path) as f:
                return [json.loads(line) for line in f.readlines() if line.strip()]
        return []
    except Exception as e:
        st.error(f"Error loading logs: {e}")
        return []

# Function to get latest metrics
def get_latest_metrics():
    logs = load_logs(AGENT_LOG)
    return logs[-1]['metrics'] if logs else None

# Function to get historical data
def get_historical_data():
    logs = load_logs(AGENT_LOG)
    if logs:
        df = pd.DataFrame([log['metrics'] for log in logs])
        df['timestamp'] = [log['timestamp'] for log in logs]
        df.set_index('timestamp', inplace=True)
        return df
    return pd.DataFrame()

# Function to get threat predictions with type and severity
def get_threat_predictions():
    logs = load_logs(AGENT_LOG)
    if logs:
        df = pd.DataFrame([{
            'timestamp': log['timestamp'],
            'threat': log['ai_prediction'],
            'type': log['ai_prediction'].split()[0] if ' ' in log['ai_prediction'] else log['ai_prediction'],
            'severity': (
                "critical" if any(k in log['ai_prediction'].lower() for k in ["ddos", "infiltration", "heartbleed"]) else
                "moderate" if any(k in log['ai_prediction'].lower() for k in ["web attack", "patator", "portscan"]) else
                "low"
            )
        } for log in logs])
        return df
    return pd.DataFrame()

# Function to get alerts
def get_alerts():
    alerts = load_logs(ALERTS_LOG)
    return pd.DataFrame(alerts) if alerts else pd.DataFrame()

# Sidebar: Agent Controls and Theme Toggle
st.sidebar.header("🛠️ Agent Controls")
pause_agent = st.sidebar.button("Pause Agent")
restart_agent = st.sidebar.button("Restart Agent")
if pause_agent:
    st.sidebar.info("Agent paused (placeholder).")
if restart_agent:
    st.sidebar.info("Agent restarted (placeholder).")

st.sidebar.subheader("🔧 Configuration")
config = {"mode": "default", "interval": "10s"}  # Placeholder config
st.sidebar.json(config)

st.sidebar.subheader("🎨 Theme")
theme = st.sidebar.radio("Select Theme", ["Dark", "Light"])
if theme == "Light":
    st.markdown("<style>.main {background: #ffffff; color: #000000;}</style>", unsafe_allow_html=True)

st.sidebar.subheader("🔄 Refresh Interval")
refresh_interval = st.sidebar.slider("Seconds", 5, 60, 10) * 1000

# Start background services
if "agent_thread_started" not in st.session_state:
    if os.path.exists(MODEL_FILENAME):
        threading.Thread(target=run_agent, daemon=True).start()
        threading.Thread(target=start_receiver, daemon=True).start()
        st.session_state.agent_thread_started = True
    else:
        st.error(f"Model file '{MODEL_FILENAME}' not found. Please train the model using model.py.")

# Main Content
st.title("💀 CYBERSEC AI DASHBOARD")
st.markdown("A modern cybersecurity monitoring tool powered by AI.")

# Live System Metrics
st.header("📊 Live System Metrics")
metrics = get_latest_metrics()
if metrics:
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown('<div class="metric-box">', unsafe_allow_html=True)
        st.metric("CPU Usage", f"{metrics['cpu']}%")
        st.markdown('</div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="metric-box">', unsafe_allow_html=True)
        st.metric("Memory Usage", f"{metrics['memory']}%")
        st.markdown('</div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-box">', unsafe_allow_html=True)
        st.metric("Disk Usage", f"{metrics['disk']}%")
        st.markdown('</div>', unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="metric-box">', unsafe_allow_html=True)
        st.metric("Bytes Sent", f"{metrics['bytes_sent']}")
        st.markdown('</div>', unsafe_allow_html=True)
    with col5:
        st.markdown('<div class="metric-box">', unsafe_allow_html=True)
        st.metric("Bytes Recv", f"{metrics['bytes_recv']}")
        st.markdown('</div>', unsafe_allow_html=True)
else:
    st.info("Waiting for agent to generate logs...")

# Historical Charts
st.header("📉 Historical CPU & Memory")
historical_data = get_historical_data()
if not historical_data.empty:
    st.line_chart(historical_data[['cpu', 'memory']], height=300)
else:
    st.info("No historical data available.")

# Threat Predictions with Filters
st.header("⚠️ Threat Predictions")
threat_df = get_threat_predictions()
if not threat_df.empty:
    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.selectbox("Filter by Severity", ["All", "Critical", "Moderate", "Low"])
    with col2:
        threat_types = ["All"] + list(threat_df['type'].unique())
        type_filter = st.selectbox("Filter by Type", threat_types)
    
    # Apply filters
    filtered_df = threat_df
    if severity_filter != "All":
        filtered_df = filtered_df[filtered_df['severity'] == severity_filter.lower()]
    if type_filter != "All":
        filtered_df = filtered_df[filtered_df['type'] == type_filter]
    
    # Search bar
    search_term = st.text_input("Search Threats", "")
    if search_term:
        filtered_df = filtered_df[filtered_df['threat'].str.contains(search_term, case=False, na=False)]
    
    # Color-coding
    def color_severity(val):
        color = 'red' if val == 'critical' else 'yellow' if val == 'moderate' else 'green'
        return f'background-color: {color}'
    
    st.dataframe(filtered_df.style.applymap(color_severity, subset=['severity']), height=200)
    
    # Check for new critical threats
    if not filtered_df[filtered_df['severity'] == 'critical'].empty:
        st.warning("🚨 New critical threat detected!")
else:
    st.info("No threat predictions available.")

# Real-time Alerts & Logs
st.header("📟 Real-time Alerts & Logs")
alerts_df = get_alerts()
if not alerts_df.empty:
    st.subheader("🔔 Received Alerts")
    st.dataframe(alerts_df.tail(5))
    csv = alerts_df.to_csv(index=False)
    st.download_button("Download Alerts as CSV", csv, "alerts.csv", "text/csv")
else:
    st.info("No alerts received yet.")

logs_df = pd.DataFrame(load_logs(AGENT_LOG))
if not logs_df.empty:
    st.subheader("📜 Agent Logs")
    st.dataframe(logs_df.tail(5))
    logs_json = logs_df.to_json(orient="records")
    st.download_button("Download Logs as JSON", logs_json, "logs.json", "application/json")
else:
    st.info("No logs available.")

# Upload Log File
st.header("📁 Upload Log File")
uploaded_file = st.file_uploader("Upload system log (JSON lines)", type=["json", "log"])
if uploaded_file:
    try:
        lines = uploaded_file.readlines()
        parsed = [json.loads(line.decode('utf-8')) for line in lines if line.strip()]
        st.write("Parsed Logs (First 3):", parsed[:3])
        if parsed:
            threat = get_ai_threat_prediction(parsed[0]['metrics'])
            st.success(f"Threat Analysis: {threat}")
        else:
            st.success("Simulated Threat Analysis: No anomaly detected.")
    except json.JSONDecodeError:
        st.error("Invalid JSON format in uploaded file.")
    except Exception as e:
        st.error(f"Error processing file: {e}")

# Auto-refresh
from streamlit_autorefresh import st_autorefresh
st_autorefresh(interval=refresh_interval, key="logrefresh")

# Footer
st.markdown("---")
st.markdown(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
