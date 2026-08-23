# Where the user dashboard is displayed
import json
from pathlib import Path
from collections import Counter
import plotly.express as px

import streamlit as st


ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILE = ROOT / "results" / "results.json"


st.set_page_config(
    page_title="Security Analysis",
    page_icon="🔐",
    layout="wide"
)


st.title("🔐 Security Analysis Dashboard")

st.caption(
    "Prototype security analysis for SAST, Secret Scanning, and SCA"
)


if not RESULTS_FILE.exists():

    st.warning(
        "No scan results found. "
        "Run the security scanner first."
    )

    st.stop()


with open(RESULTS_FILE) as file:
    data = json.load(file)


# Overall result

if data["status"] == "PASS":
    st.success("✅ All security checks passed")
else:
    st.error("❌ Security checks failed")


# Summary

summary = data["summary"]

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Passed", summary["passed"])

with col2:
    st.metric("Warnings", summary["warnings"])

with col3:
    st.metric("Failed", summary["failed"])


st.divider()

# Historical Trends
st.header("Historical Trends")
history_dir = ROOT / "results" / "history"
if history_dir.exists():
    history_files = list(history_dir.glob("scan_*.json"))
    if history_files:
        history_data = {"Date": [], "Failed": [], "Warnings": [], "Passed": []}
        for hf in sorted(history_files):
            try:
                with open(hf) as f:
                    hdata = json.load(f)
                    history_data["Date"].append(hdata.get("timestamp", hf.stem.split("scan_")[1]))
                    history_data["Failed"].append(hdata["summary"]["failed"])
                    history_data["Warnings"].append(hdata["summary"]["warnings"])
                    history_data["Passed"].append(hdata["summary"]["passed"])
            except Exception:
                continue
                
        if history_data["Date"]:
            fig_trend = px.line(
                history_data, 
                x="Date", 
                y=["Failed", "Warnings", "Passed"], 
                title="Scan Results Over Time",
                markers=True
            )
            st.plotly_chart(fig_trend, use_container_width=True)

st.divider()

# Sidebar Filters
st.sidebar.header("Filters")
all_findings = data.get("findings", [])

if all_findings:
    scanners = sorted(list(set(f["scanner"] for f in all_findings)))
    severities = sorted(list(set(f["severity"] for f in all_findings)))
    
    selected_scanners = st.sidebar.multiselect("Scanners", scanners, default=scanners)
    selected_severities = st.sidebar.multiselect("Severities", severities, default=severities)
    
    filtered_findings = [
        f for f in all_findings 
        if f["scanner"] in selected_scanners and f["severity"] in selected_severities
    ]
else:
    filtered_findings = []


# Charts
if filtered_findings:
    st.header("Visualizations")
    
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        sev_counts = Counter(f['severity'] for f in filtered_findings)
        fig_pie = px.pie(
            names=list(sev_counts.keys()), 
            values=list(sev_counts.values()), 
            title="Findings by Severity"
        )
        st.plotly_chart(fig_pie, use_container_width=True)
        
    with chart_col2:
        scan_counts = Counter(f['scanner'] for f in filtered_findings)
        fig_bar = px.bar(
            x=list(scan_counts.keys()), 
            y=list(scan_counts.values()), 
            title="Findings by Scanner", 
            labels={'x': 'Scanner', 'y': 'Count'}
        )
        st.plotly_chart(fig_bar, use_container_width=True)

st.divider()

# Findings

st.header("Security Findings")


if not filtered_findings:
    st.success("🎉 No security findings detected matching the current filters.")


for finding in filtered_findings:

    if finding["status"] == "FAIL":
        icon = "🔴"
    elif finding["status"] == "WARN":
        icon = "🟠"
    else:
        icon = "🟢"

    title = (
        f"{icon} "
        f"{finding['category']} "
        f"— "
        f"{finding['severity']}"
    )

    with st.expander(title):

        st.write(f"**Scanner:** {finding['scanner']}")
        st.write(f"**Type:** {finding['type']}")
        st.write(f"**File:** `{finding['file']}`")

        if finding.get("line"):
            st.write(f"**Line/Version:** {finding['line']}")

        st.write(
            f"**File:** "
            f"`{finding['file']}`"
        )

        st.write(
            f"**Problem:** "
            f"{finding.get('description', finding.get('message', 'No problem description available.'))}"
        )

        if finding["line"]:
            st.write(
                f"**Line:** "
                f"{finding['line']}"
            )

        st.write(
            f"**Description:** "
            f"{finding.get('technical_message', finding.get('message', 'No technical description available.'))}"
        )

        st.write(
            f"**Status:** "
            f"{finding['status']}"
        )
