import json
import logging
import os
import sys
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv
from streamlit.errors import StreamlitSecretNotFoundError

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flows.incident_flow import run_incident_investigation
from schemas.incident_models import RawAlertInput

LOGGER = logging.getLogger(__name__)

ATTACK_SAMPLE = {
    "alert_id": "ALT-2026-0042",
    "source": "SIEM / Linux Auth & EDR",
    "timestamp": "2026-11-19T02:15:10Z",
    "summary": "Anomalous SSH login followed by remote shell script execution on prod-app-01",
    "source_ip": "185.220.101.45",
    "target_user": "deploy_bot",
    "target_host": "prod-app-01",
}

FALSE_POSITIVE_SAMPLE = {
    "alert_id": "ALT-2026-0099",
    "source": "Internal Cron Monitor",
    "timestamp": "2026-11-19T09:00:05Z",
    "summary": "Scheduled internal healthcheck HTTP request triggered rate threshold on staging-db-01",
    "source_ip": "10.0.4.18",
    "target_user": "healthcheck",
    "target_host": "staging-db-01",
}

st.set_page_config(
    page_title="Autonomous SOC Incident Investigator",
    layout="wide",
)

load_dotenv(PROJECT_ROOT / ".env", override=False)
try:
    for setting in ("GROQ_API_KEY", "GROQ_BASE_URL", "MODEL"):
        if not os.getenv(setting) and setting in st.secrets:
            os.environ[setting] = str(st.secrets[setting])
except StreamlitSecretNotFoundError:
    pass

st.title("Autonomous Incident Investigator")
st.caption("Multi-agent SOC alert triage, log forensics, threat intelligence, and response planning.")
st.warning(
    "Use sanitized or synthetic alerts in this demo. Submitted alert data is sent to the configured LLM provider."
)

sample_name = st.selectbox("Load a sample alert", ["Attack sample", "False positive sample"])
sample_key = "attack" if sample_name == "Attack sample" else "false_positive"
sample = ATTACK_SAMPLE if sample_key == "attack" else FALSE_POSITIVE_SAMPLE

with st.form(f"alert_form_{sample_key}"):
    left, right = st.columns(2)
    with left:
        alert_id = st.text_input(
            "Alert ID", value=sample["alert_id"], key=f"alert_id_{sample_key}"
        )
        timestamp = st.text_input(
            "Timestamp (UTC)", value=sample["timestamp"], key=f"timestamp_{sample_key}"
        )
        source = st.text_input(
            "Telemetry source", value=sample["source"], key=f"source_{sample_key}"
        )
    with right:
        source_ip = st.text_input(
            "Source IP", value=sample["source_ip"], key=f"source_ip_{sample_key}"
        )
        target_user = st.text_input(
            "Target user", value=sample["target_user"], key=f"target_user_{sample_key}"
        )
        target_host = st.text_input(
            "Target host / asset", value=sample["target_host"], key=f"target_host_{sample_key}"
        )
    summary = st.text_area(
        "Alert summary", value=sample["summary"], key=f"summary_{sample_key}"
    )
    submitted = st.form_submit_button("Run multi-agent investigation", type="primary")

if submitted:
    if not all((alert_id.strip(), timestamp.strip(), source.strip(), summary.strip())):
        st.error("Alert ID, timestamp, telemetry source, and summary are required.")
    elif not os.getenv("GROQ_API_KEY", "").strip():
        st.error("Configure GROQ_API_KEY in Streamlit secrets or your local .env file before investigating.")
    else:
        alert = RawAlertInput(
            alert_id=alert_id.strip(),
            source=source.strip(),
            timestamp=timestamp.strip(),
            summary=summary.strip(),
            source_ip=source_ip.strip() or None,
            target_user=target_user.strip() or None,
            target_host=target_host.strip() or None,
        )
        st.session_state.pop("incident_report", None)
        try:
            with st.spinner("Agents are investigating the alert..."):
                st.session_state["incident_report"] = run_incident_investigation(alert)
        except Exception as exc:
            LOGGER.exception("Incident investigation failed")
            st.error(f"Investigation failed ({type(exc).__name__}). Check the app logs for details.")

report = st.session_state.get("incident_report")
if report:
    st.divider()
    st.header(f"Investigation report: {report['alert_id']}")

    triage = report["triage"]
    classification = "False positive" if triage["is_false_positive"] else "Threat"
    status_column, classification_column, severity_column, confidence_column = st.columns(4)
    status_column.metric("Status", report["status"].replace("_", " ").title())
    classification_column.metric("Classification", classification)
    severity_column.metric("Severity", triage["severity"])
    confidence_column.metric("Confidence", f"{triage['confidence']:.0%}")
    st.write(triage["reasoning"])

    if report.get("logs"):
        with st.expander("Log forensics", expanded=True):
            st.write(report["logs"]["key_observations"])
            st.markdown("**Timeline**")
            for event in report["logs"]["timeline"]:
                st.write(f"- {event}")
            if report["logs"]["extracted_iocs"]:
                st.markdown("**Extracted indicators**")
                st.write(", ".join(report["logs"]["extracted_iocs"]))

    if report.get("threat_intel"):
        with st.expander("Threat intelligence", expanded=True):
            st.write(f"**Category:** {report['threat_intel']['threat_category']}")
            st.write(f"**Blast radius:** {report['threat_intel']['blast_radius']}")
            st.write(report["threat_intel"]["intel_notes"])
            if report["threat_intel"]["mitre_techniques"]:
                st.write(
                    "**MITRE ATT&CK techniques:** "
                    + ", ".join(report["threat_intel"]["mitre_techniques"])
                )

    if report.get("response_plan"):
        response_plan = report["response_plan"]
        with st.expander("Recommended response plan", expanded=True):
            st.write(f"**Priority:** {response_plan['priority_level']}")
            st.write(response_plan["executive_summary"])
            for action in response_plan["immediate_actions"]:
                st.write(f"- {action}")
            if response_plan["requires_human_approval"]:
                st.warning("High-impact actions require approval from a qualified SOC analyst.")

    st.download_button(
        "Download report as JSON",
        data=json.dumps(report, indent=2),
        file_name=f"{report['alert_id']}-report.json",
        mime="application/json",
    )
