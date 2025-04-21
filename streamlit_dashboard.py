import os
import time
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import random
import plotly.express as px
import plotly.graph_objects as go
from packet_sniffer import simulate_traffic

# Load CSS styles
def load_css():
    with open("styles.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# Sample data generation functions
def generate_event_logs():
    events = []
    for i in range(50):
        events.append({
            "Timestamp": datetime.now() - timedelta(minutes=random.randint(1, 1440)),
            "Event Type": random.choice(["Login", "Logout", "File Access", "System Change", "Security Alert"]),
            "Source IP": f"192.168.1.{random.randint(1, 50)}",
            "User": random.choice(["admin", "user1", "user2", "service_account"]),
            "Status": random.choice(["Success", "Failed", "Warning"])
        })
    return pd.DataFrame(events)

def generate_reports():
    reports = []
    for i in range(10):
        reports.append({
            "Report Name": f"Security Report {i+1}",
            "Generated On": datetime.now() - timedelta(days=random.randint(1, 30)),
            "Type": random.choice(["Daily", "Weekly", "Monthly"]),
            "Status": random.choice(["Complete", "Pending", "Failed"])
        })
    return pd.DataFrame(reports)

def generate_alerts():
    alerts = []
    for i in range(15):
        severity = random.choice(["Critical", "High", "Medium", "Low"])
        description = random.choice([
            "Unauthorized file access",
            "Multiple failed login attempts",
            "Suspicious network activity",
            "Policy violation detected",
            "System configuration change"
        ])
        alerts.append({
            "Alert ID": f"ALERT-{random.randint(1000, 9999)}",
            "Timestamp": datetime.now() - timedelta(minutes=random.randint(1, 720)),
            "Severity": severity,
            "Description": description,
            "Status": random.choice(["New", "In Progress", "Resolved"])
        })
    return pd.DataFrame(alerts)

# ---- PAGE SECTIONS ----
def show_dashboard():
    st.markdown("<h1 class='header'>Dashboard Overview</h1>", unsafe_allow_html=True)

    # Status cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("**System Status**")
        st.success("\u2714\ufe0f Operational")
    with col2:
        st.markdown("**Active Users**")
        st.info("24")
    with col3:
        st.markdown("**Threat Level**")
        threat_level = "Medium"
        if threat_level == "High":
            st.markdown("<div style='color:white;background-color:red;padding:5px;border-radius:5px;'>\ud83d\udea8 High</div>", unsafe_allow_html=True)
        elif threat_level == "Medium":
            st.markdown("<div style='color:white;background-color:blue;padding:5px;border-radius:5px;'>\u26a0\ufe0f Medium</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div style='color:white;background-color:green;padding:5px;border-radius:5px;'>\u2705 Low</div>", unsafe_allow_html=True)
    with col4:
        st.markdown("**Last Scan**")
        last_scan = st.session_state.get("last_scan")
        scan_display = last_scan.strftime('%Y-%m-%d %I:%M %p') if last_scan else "Not yet scanned"
        st.info(scan_display)

    # Dynamic slice performance
    performance = random.randint(30, 80)  # Random performance between 30% and 80%
    st.markdown("### System Performance")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=performance,
        title={'text': "Slice Performance"},
        gauge={'axis': {'range': [0, 100]},
               'bar': {'color': "orange"}}
    ))
    st.plotly_chart(fig)

    st.markdown("---")
    st.markdown("### Recent Activity")
    activity_log = generate_event_logs().sort_values("Timestamp", ascending=False).head(5)
    st.dataframe(activity_log)

    st.markdown("### Security Alerts Summary")
    alerts_summary = generate_alerts().groupby("Severity").size().reset_index(name="Count")
    fig_bar = px.bar(alerts_summary, x="Severity", y="Count", color="Severity", title="Alerts by Severity",
                     color_discrete_map={"Critical": "darkred", "High": "orangered", "Medium": "gold", "Low": "lightgreen"})
    st.plotly_chart(fig_bar)

def show_event_logs():
    st.markdown("<h1 class='header'>Event Logs</h1>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        event_type = st.multiselect("Event Type", options=["All"] + list(generate_event_logs()["Event Type"].unique()))
    with col2:
        date_range = st.date_input("Date Range", [])
    with col3:
        status_filter = st.multiselect("Status", options=["All"] + list(generate_event_logs()["Status"].unique()))

    event_logs = generate_event_logs()
    if "All" not in event_type and event_type:
        event_logs = event_logs[event_logs["Event Type"].isin(event_type)]
    if "All" not in status_filter and status_filter:
        event_logs = event_logs[event_logs["Status"].isin(status_filter)]

    st.dataframe(event_logs.sort_values("Timestamp", ascending=False))

    st.download_button(
        label="Export Logs",
        data=event_logs.to_csv(index=False),
        file_name="event_logs_export.csv",
        mime="text/csv"
    )

def show_reports():
    st.markdown("<h1 class='header'>Reports</h1>", unsafe_allow_html=True)

    with st.expander("Generate New Report"):
        report_type = st.selectbox("Report Type", ["Daily Summary", "Security Audit", "User Activity"])
        time_range = st.selectbox("Time Range", ["Last 24 Hours", "Last 7 Days", "Last 30 Days"])
        if st.button("Generate Report"):
            with st.spinner("Generating report..."):
                time.sleep(2)
                st.success("Report generated successfully!")

    reports = generate_reports()
    st.dataframe(reports.sort_values("Generated On", ascending=False))

    selected_report = st.selectbox("Select Report to View", reports["Report Name"])
    if st.button("View Selected Report"):
        st.info(f"Displaying report: {selected_report}")
        st.write("This would show the detailed report content in a real implementation")

def show_alerts():
    st.markdown("<h1 class='header'>Security Alerts</h1>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.multiselect("Severity Level", options=["All"] + list(generate_alerts()["Severity"].unique()))
    with col2:
        status_filter = st.multiselect("Alert Status", options=["All"] + list(generate_alerts()["Status"].unique()))

    alerts = generate_alerts()
    if "All" not in severity_filter and severity_filter:
        alerts = alerts[alerts["Severity"].isin(severity_filter)]
    if "All" not in status_filter and status_filter:
        alerts = alerts[alerts["Status"].isin(status_filter)]

    color_map = {
        "Critical": "darkred",
        "High": "orangered",
        "Medium": "gold",
        "Low": "lightgreen"
    }

    for _, alert in alerts.sort_values("Timestamp", ascending=False).iterrows():
        border_color = color_map.get(alert['Severity'], "gray")
        alert_time = alert["Timestamp"].strftime("%I:%M %p")

        st.markdown(f"""
        <div class="log-entry" style="border-left: 6px solid {border_color}; padding: 10px; margin: 5px 0;">
            <strong>{alert['Severity']} Alert:</strong> {alert['Description']}<br>
            <small><strong>Time:</strong> {alert_time} | <strong>ID:</strong> {alert['Alert ID']} | <strong>Status:</strong> {alert['Status']}</small>
        </div>
        """, unsafe_allow_html=True)

    if st.button("Acknowledge All Alerts"):
        st.success("All alerts acknowledged")

# ---- USER AUTH ----
def login():
    st.markdown("<h1 class='header'>INTRUSION DETECTION SYSTEM  - Login</h1>", unsafe_allow_html=True)

    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit_button = st.form_submit_button("Login")

        if submit_button:
            if username == "admin" and password == "admin@12":
                st.session_state.logged_in = True
                st.session_state.current_page = "Dashboard"
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Invalid credentials. Please try again.")

# ---- MAIN APP ----
def main_app():
    with st.sidebar:
        st.markdown("### Navigation")
        page = st.radio("", ["Dashboard", "Event Logs", "Reports", "Alerts"])
        st.session_state.current_page = page

        st.markdown("---")
        if st.button("Run Security Scan"):
            with st.spinner("Scanning..."):
                simulate_traffic()
                st.session_state.last_scan = datetime.now()
                st.success("Scan completed!")

        st.markdown("---")
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.rerun()

    if st.session_state.current_page == "Dashboard":
        show_dashboard()
    elif st.session_state.current_page == "Event Logs":
        show_event_logs()
    elif st.session_state.current_page == "Reports":
        show_reports()
    elif st.session_state.current_page == "Alerts":
        show_alerts()

# ---- SETUP PAGE ----
def setup():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Dashboard"
    if not st.session_state.logged_in:
        login()
    else:
        main_app()

setup()
