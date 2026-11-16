
import streamlit as st
import pandas as pd
import plotly.express as px
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.threat_detection import AegisThreatDetector
from modules.risk_scoring import AegisRiskScorer
from modules.intelligent_response import AegisIntelligentResponse

from database.db_manager import (
    initialize_db,
    save_event,
    get_events,
    get_stats
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="AEGIS-AI Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AEGIS-AI")
st.subheader("AI-Powered Cloud Security Threat Detection System")

st.markdown(
    "Monitor security events, detect suspicious activities, "
    "evaluate risk and receive intelligent response recommendations."
)

st.divider()


# --------------------------------------------------
# INITIALIZE SYSTEM
# --------------------------------------------------

@st.cache_resource
def load_security_engines():
    return (
        AegisThreatDetector(),
        AegisRiskScorer(),
        AegisIntelligentResponse()
    )


initialize_db()

try:
    detector, risk_scorer, response_engine = load_security_engines()
except Exception as error:
    st.error(f"Unable to load AI models: {error}")
    st.info("Please verify that the trained model files exist inside the models folder.")
    st.stop()


# --------------------------------------------------
# FEATURE ENGINEERING
# --------------------------------------------------

def prepare_event(event):
    prepared = event.copy()

    login_attempts = max(float(prepared["login_attempts"]), 1)

    prepared["night_access"] = int(
        float(prepared["access_hour"]) < 6
        or float(prepared["access_hour"]) >= 22
    )

    prepared["failed_login_ratio"] = (
        float(prepared["failed_logins"]) / login_attempts
    )

    prepared["high_data_transfer"] = int(
        float(prepared["data_transfer_mb"]) > 500
    )

    prepared["high_device_risk"] = int(
        float(prepared["device_risk"]) > 75
    )

    return prepared


# --------------------------------------------------
# SIDEBAR NAVIGATION
# --------------------------------------------------

st.sidebar.title("🛡️ AEGIS-AI")
st.sidebar.caption("Security Monitoring Platform")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Analyze Security Event",
        "Event History",
        "Model Insights"
    ]
)

st.sidebar.divider()
st.sidebar.success("AI Security Engines Loaded")
st.sidebar.caption("Local demonstration environment")


# --------------------------------------------------
# PAGE 1: OVERVIEW
# --------------------------------------------------

if page == "Overview":

    st.header("Security Overview")

    stats = get_stats()

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Events",
        stats["total_events"]
    )

    col2.metric(
        "Detected Threats",
        stats["detected_threats"]
    )

    col3.metric(
        "Normal Events",
        stats["normal_events"]
    )

    st.divider()

    st.subheader("Threat Severity Distribution")

    severity_data = stats.get("severity_breakdown", {})

    if severity_data:
        severity_df = pd.DataFrame(
            list(severity_data.items()),
            columns=["Severity", "Count"]
        )

        fig = px.pie(
            severity_df,
            names="Severity",
            values="Count",
            hole=0.45,
            title="Security Risk Distribution"
        )

        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("No analyzed security events available yet.")

    st.subheader("Recent Security Events")

    recent_events = get_events(10)

    if recent_events:
        recent_df = pd.DataFrame([
            {
                "ID": item["id"],
                "Time": item["created_at"],
                "Severity": item["severity"],
                "Risk Score": item["risk_score"],
                "Threat": "Yes" if item["is_threat"] else "No"
            }
            for item in recent_events
        ])

        st.dataframe(
            recent_df,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("Analyze your first security event to see dashboard data.")


# --------------------------------------------------
# PAGE 2: ANALYZE SECURITY EVENT
# --------------------------------------------------

elif page == "Analyze Security Event":

    st.header("AI Security Event Analysis")

    st.write(
        "Enter the security event details below. "
        "The AI engines will analyze the event and generate a risk assessment."
    )

    with st.form("security_event_form"):

        st.subheader("Login Activity")

        c1, c2, c3 = st.columns(3)

        login_attempts = c1.number_input(
            "Login Attempts",
            min_value=0,
            max_value=1000,
            value=5
        )

        failed_logins = c2.number_input(
            "Failed Logins",
            min_value=0,
            max_value=1000,
            value=1
        )

        access_hour = c3.slider(
            "Access Hour",
            min_value=0,
            max_value=23,
            value=14
        )

        st.subheader("Network and Access Details")

        c4, c5, c6 = st.columns(3)

        data_transfer_mb = c4.number_input(
            "Data Transfer (MB)",
            min_value=0.0,
            value=100.0
        )

        ip_reputation = c5.slider(
            "IP Reputation",
            min_value=0,
            max_value=100,
            value=80
        )

        privilege_level = c6.selectbox(
            "Privilege Level",
            [0, 1, 2, 3, 4, 5],
            index=1
        )

        st.subheader("Device and Session Details")

        c7, c8, c9, c10 = st.columns(4)

        unusual_location = c7.selectbox(
            "Unusual Location",
            [0, 1],
            format_func=lambda x: "Yes" if x == 1 else "No"
        )

        access_denied = c8.number_input(
            "Access Denied",
            min_value=0,
            max_value=1000,
            value=0
        )

        session_duration = c9.number_input(
            "Session Duration",
            min_value=0,
            value=30
        )

        device_risk = c10.slider(
            "Device Risk",
            min_value=0,
            max_value=100,
            value=20
        )

        submitted = st.form_submit_button(
            "🔍 Analyze Security Event",
            use_container_width=True
        )

    if submitted:

        if failed_logins > login_attempts:
            st.error("Failed logins cannot exceed total login attempts.")

        else:

            event = {
                "login_attempts": login_attempts,
                "failed_logins": failed_logins,
                "access_hour": access_hour,
                "data_transfer_mb": data_transfer_mb,
                "ip_reputation": ip_reputation,
                "privilege_level": privilege_level,
                "unusual_location": unusual_location,
                "access_denied": access_denied,
                "session_duration": session_duration,
                "device_risk": device_risk
            }

            try:
                with st.spinner("AI engines analyzing security event..."):

                    prepared_event = prepare_event(event)

                    detection = detector.detect_threat(prepared_event)

                    risk = risk_scorer.calculate_risk(
                        prepared_event,
                        detection
                    )

                    response = response_engine.generate_response(
                        prepared_event,
                        detection,
                        risk
                    )

                    record_id = save_event(
                        prepared_event,
                        detection,
                        risk,
                        response
                    )

                st.success(
                    f"Analysis completed! Record ID: {record_id}"
                )

                st.divider()

                st.subheader("Threat Detection Result")

                is_threat = detection.get("is_threat", False)

                if is_threat:
                    st.error("⚠️ Suspicious Security Activity Detected")
                else:
                    st.success("✅ No Threat Detected")

                risk_score = risk.get(
                    "risk_score",
                    risk.get("score", 0)
                )

                severity = risk.get("severity", "Unknown")

                c1, c2, c3 = st.columns(3)

                c1.metric(
                    "Risk Score",
                    f"{float(risk_score):.1f}/100"
                )

                c2.metric(
                    "Severity",
                    severity
                )

                c3.metric(
                    "Threat Status",
                    "Threat" if is_threat else "Normal"
                )

                st.progress(
                    max(0, min(float(risk_score) / 100, 1))
                )

                st.subheader("Detection Details")
                st.json(detection)

                st.subheader("Risk Explanation")
                st.json(risk)

                st.subheader("Intelligent Response Recommendations")
                st.json(response)

                st.info(
                    "Recommendations are advisory only. "
                    "No account, IP address or device is automatically blocked."
                )

            except Exception as error:
                st.error(f"Analysis failed: {error}")


# --------------------------------------------------
# PAGE 3: EVENT HISTORY
# --------------------------------------------------

elif page == "Event History":

    st.header("Security Event History")

    limit = st.selectbox(
        "Number of recent records",
        [10, 25, 50, 100, 250, 500],
        index=2
    )

    events = get_events(limit)

    if events:

        history_df = pd.DataFrame([
            {
                "ID": item["id"],
                "Timestamp": item["created_at"],
                "Severity": item["severity"],
                "Risk Score": item["risk_score"],
                "Threat Detected": (
                    "Yes" if item["is_threat"] else "No"
                )
            }
            for item in events
        ])

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        selected_id = st.selectbox(
            "Select Event ID to inspect",
            [item["id"] for item in events]
        )

        selected_event = next(
            item for item in events
            if item["id"] == selected_id
        )

        st.subheader(f"Event Details — ID {selected_id}")

        st.write("Original Event")
        st.json(selected_event["event_data"])

        st.write("Detection Result")
        st.json(selected_event["detection_data"])

        st.write("Risk Assessment")
        st.json(selected_event["risk_data"])

        st.write("Response Recommendations")
        st.json(selected_event["response_data"])

    else:
        st.info("No event history available yet.")


# --------------------------------------------------
# PAGE 4: MODEL INSIGHTS
# --------------------------------------------------

elif page == "Model Insights":

    st.header("Machine Learning Model Insights")

    metrics_path = PROJECT_ROOT / "reports" / "model_metrics.csv"
    importance_path = PROJECT_ROOT / "reports" / "feature_importance.csv"

    if metrics_path.exists():

        st.subheader("Model Performance")

        metrics_df = pd.read_csv(metrics_path)

        st.dataframe(
            metrics_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.warning("Model metrics report not found.")

    if importance_path.exists():

        st.subheader("Feature Importance")

        importance_df = pd.read_csv(importance_path)

        if len(importance_df.columns) >= 2:

            feature_col = importance_df.columns[0]

            importance_col = importance_df.columns[1]

            importance_df[importance_col] = pd.to_numeric(
                importance_df[importance_col],
                errors="coerce"
            )

            importance_df = importance_df.dropna(
                subset=[importance_col]
            )

            importance_df = importance_df.sort_values(
                importance_col,
                ascending=False
            )

            fig = px.bar(
                importance_df.head(15),
                x=importance_col,
                y=feature_col,
                orientation="h",
                title="Top 15 Important Features"
            )

            fig.update_layout(
                yaxis={"categoryorder": "total ascending"}
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:
            st.warning("Feature importance file has an unexpected format.")

    else:
        st.warning("Feature importance report not found.")


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "AEGIS-AI | AI-Powered Cloud Security Threat Detection "
    "| Academic Demonstration Project"
)
