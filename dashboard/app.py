# Where the user dashboard is displayed
import json
from pathlib import Path

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
    "Prototype security analysis for SAST and secret scanning"
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

    st.success(
        "✅ All security checks passed"
    )

else:

    st.error(
        "❌ Security checks failed"
    )


# Summary

summary = data["summary"]

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Passed",
        summary["passed"]
    )

with col2:
    st.metric(
        "Warnings",
        summary["warnings"]
    )

with col3:
    st.metric(
        "Failed",
        summary["failed"]
    )


st.divider()


# Findings

st.header("Security Findings")


if not data["findings"]:

    st.success(
        "🎉 No security findings detected."
    )


for finding in data["findings"]:

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

        st.write(
            f"**Scanner:** "
            f"{finding['scanner']}"
        )

        st.write(
            f"**Type:** "
            f"{finding['type']}"
        )

        st.write(
            f"**File:** "
            f"`{finding['file']}`"
        )

        if finding["line"]:
            st.write(
                f"**Line:** "
                f"{finding['line']}"
            )

        st.write(
            f"**Description:** "
            f"{finding['message']}"
        )

        st.write(
            f"**Status:** "
            f"{finding['status']}"
        )