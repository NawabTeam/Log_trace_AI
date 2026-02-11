import streamlit as st
import pandas as pd
import numpy as np
import psutil
import time
import plotly.express as px
from sklearn.ensemble import IsolationForest

st.set_page_config(layout="wide", page_title="LogTrace AI SOC")

# ---------- Helper ----------
def find_timestamp_column(df):
    candidates = ["modified", "modified_time", "mtime", "last_modified", "timestamp"]
    for c in candidates:
        if c in df.columns:
            return c
    return None

# ---------- Sidebar ----------
st.sidebar.title("🛡️ LogTrace AI")
mft_file = st.sidebar.file_uploader("Upload MFT CSV")
usn_file = st.sidebar.file_uploader("Upload USN CSV")
sec_file = st.sidebar.file_uploader("Upload Security CSV")

tabs = st.tabs([
    "📊 Overview",
    "🧠 Threat Detection",
    "📡 Live Monitor",
    "📈 Visual Analytics",
    "🧾 Evidence"
])

# ---------- Load Logs ----------
if mft_file and usn_file and sec_file:
    mft = pd.read_csv(mft_file)
    usn = pd.read_csv(usn_file)
    sec = pd.read_csv(sec_file)

    for df in [mft, usn, sec]:
        ts = find_timestamp_column(df)
        if not ts:
            st.error("Timestamp column missing")
            st.stop()
        df["timestamp"] = pd.to_datetime(df[ts], errors="coerce")

# ---------- Overview ----------
with tabs[0]:
    st.metric("Total MFT Records", len(mft))
    st.metric("USN Events", len(usn))
    st.metric("Security Logs", len(sec))

# ---------- Threat Detection ----------
with tabs[1]:
    st.subheader("🚨 AI-based Anomaly Detection")

    features = usn[["timestamp"]].dropna()
    features["epoch"] = features["timestamp"].astype(np.int64) // 10**9

    model = IsolationForest(contamination=0.03)
    usn["anomaly"] = model.fit_predict(features[["epoch"]])

    threats = usn[usn["anomaly"] == -1]
    st.dataframe(threats.head(50))

# ---------- Live Monitor ----------
with tabs[2]:
    col1, col2, col3 = st.columns(3)

    col1.metric("CPU Usage", f"{psutil.cpu_percent()}%")
    col2.metric("Memory Usage", f"{psutil.virtual_memory().percent}%")
    col3.metric("System Uptime", f"{int(time.time() - psutil.boot_time())//60} mins")

# ---------- Visual Analytics ----------
with tabs[3]:
    cpu = [psutil.cpu_percent(interval=1) for _ in range(10)]
    fig = px.line(cpu, title="CPU Usage Trend")
    st.plotly_chart(fig, use_container_width=True)

# ---------- Evidence ----------
with tabs[4]:
    st.download_button(
        "Download Detected Threats",
        threats.to_csv(index=False),
        "evidence.csv",
        "text/csv"
    )
