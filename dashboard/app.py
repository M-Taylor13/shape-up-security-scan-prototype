# Where the user dashboard is displayed
import json
from pathlib import Path
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

import streamlit as st


ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILE = ROOT / "results" / "results.json"

SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 1, "HIGH": 2, "WARNING": 3, "WARN": 4, "INFO": 5, "PASS": 6}
SEVERITY_COLORS = {
    "CRITICAL": "#ff4b4b",
    "ERROR":    "#ff4b4b",
    "HIGH":     "#ff7c43",
    "WARNING":  "#ffa600",
    "WARN":     "#ffa600",
    "INFO":     "#4b9eff",
    "PASS":     "#21c55d",
}
# Streamlit markdown colours used to show a status as coloured text
STATUS_COLOR = {"FAIL": "red", "WARN": "orange", "PASS": "green"}
TYPE_LABELS = {"SAST": "SAST", "SECRET": "Secret", "SCA": "SCA"}

# What each severity means and what it does to the scan result (see scanner/criteria.py)
SEVERITY_INFO = {
    "CRITICAL": ("FAIL", "Can be exploited easily with serious impact, such as a leaked credential or remote code execution. Fix immediately."),
    "HIGH":     ("FAIL", "A serious flaw that is likely to be exploitable. Fix before release."),
    "ERROR":    ("FAIL", "Semgrep's highest level, treated the same as high. Fix before release."),
    "MEDIUM":   ("WARN", "A real weakness that needs specific conditions to exploit. Plan a fix."),
    "WARNING":  ("WARN", "Semgrep's middle level, treated the same as medium. Plan a fix."),
    "LOW":      ("PASS", "Minor risk or a hardening suggestion. Fix when convenient."),
    "INFO":     ("PASS", "Informational only. No action required."),
}

# What each scanner does, shown in the sidebar and on every finding card
SCANNER_INFO = {
    "Semgrep": {
        "kind": "SAST (static code analysis)",
        "summary": "Reads the source code for risky patterns without running it.",
        "detail": "Finds problems such as SQL injection, cross-site scripting and command injection. Works across many languages, including Python and JavaScript.",
    },
    "Bandit": {
        "kind": "SAST for Python",
        "summary": "Checks Python code for common security mistakes.",
        "detail": "Finds problems such as weak hashing, unsafe deserialisation, shell commands built from input and hardcoded passwords. Only scans Python files.",
    },
    "Gitleaks": {
        "kind": "Secret scanning",
        "summary": "Looks for credentials that were committed by accident.",
        "detail": "Finds passwords, API keys and tokens in any file. Every match is treated as critical.",
    },
    "OSV-Scanner": {
        "kind": "SCA (dependency analysis)",
        "summary": "Checks third-party packages against a public database of known vulnerabilities.",
        "detail": "Reads dependency files for npm, Python, Go, Java, Rust, .NET and more, and reports which version to upgrade to.",
    },
}


st.set_page_config(
    page_title="Security Analysis Dashboard",
    layout="wide"
)

# ── Custom CSS ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        color: #fff;
        margin-right: 4px;
    }
    .badge-CRITICAL { background: #ff4b4b; }
    .badge-ERROR    { background: #ff4b4b; }
    .badge-HIGH     { background: #ff7c43; }
    .badge-WARNING  { background: #ffa600; color: #1a1a1a; }
    .badge-WARN     { background: #ffa600; color: #1a1a1a; }
    .badge-INFO     { background: #4b9eff; }
    .badge-PASS     { background: #21c55d; }

    .finding-card {
        border-left: 4px solid #444;
        padding: 12px 16px;
        margin-bottom: 10px;
        border-radius: 4px;
        background: rgba(255,255,255,0.03);
    }
    .finding-card-CRITICAL, .finding-card-ERROR { border-left-color: #ff4b4b; }
    .finding-card-HIGH     { border-left-color: #ff7c43; }
    .finding-card-WARNING, .finding-card-WARN  { border-left-color: #ffa600; }
    .finding-card-INFO     { border-left-color: #4b9eff; }
    .finding-card-PASS     { border-left-color: #21c55d; }

    .finding-location {
        font-family: monospace;
        font-size: 0.82rem;
        color: #9ca3af;
    }

    [data-testid="stMetricLabel"] { font-size: 0.85rem !important; }
</style>
""", unsafe_allow_html=True)


# ── Header ───────────────────────────────────────────────────────────────────
st.title("Security Analysis Dashboard")
st.caption("Automated SAST · Secret Detection · Software Composition Analysis")


# ── Load data ────────────────────────────────────────────────────────────────
if not RESULTS_FILE.exists():
    st.warning(
        "No scan results found. "
        "Run `python scanner/scan.py` then `python scanner/process_results.py` first."
    )
    st.stop()

with open(RESULTS_FILE) as f:
    data = json.load(f)

all_findings = data.get("findings", [])
summary = data["summary"]


# ── Sidebar filters ──────────────────────────────────────────────────────────
st.sidebar.header("Filters")

with st.sidebar.expander("About the Scanners"):
    for scanner_name, info in SCANNER_INFO.items():
        st.markdown(f"**{scanner_name}**  \n*{info['kind']}*  \n{info['summary']} {info['detail']}")

with st.sidebar.expander("About the Severities"):
    st.markdown(
        "Each finding has a severity, which decides whether it fails the scan. "
        "Dependency findings are rated by CVSS score: 9.0+ critical, 7.0+ high, 4.0+ medium, otherwise low."
    )
    for severity_name, (action, meaning) in SEVERITY_INFO.items():
        st.markdown(
            f"**{severity_name}** → :{STATUS_COLOR.get(action, 'gray')}[{action}]  \n{meaning}"
        )

if all_findings:
    scanners   = sorted(set(f["scanner"]  for f in all_findings))
    severities = sorted(set(f["severity"] for f in all_findings), key=lambda s: SEVERITY_ORDER.get(s, 99))
    types      = sorted(set(f["type"]     for f in all_findings))

    selected_scanners   = st.sidebar.multiselect("Scanners",   scanners,   default=scanners)
    selected_severities = st.sidebar.multiselect("Severities", severities, default=severities)
    selected_types      = st.sidebar.multiselect("Types",      types,      default=types)
    search_query        = st.sidebar.text_input("Search findings", placeholder="e.g. sql, flask, xss…")

    filtered_findings = [
        f for f in all_findings
        if f["scanner"]  in selected_scanners
        and f["severity"] in selected_severities
        and f["type"]    in selected_types
        and (not search_query or search_query.lower() in json.dumps(f).lower())
    ]
else:
    filtered_findings = []


# ── Overall status banner ────────────────────────────────────────────────────
if data["status"] == "PASS":
    st.success("All security checks passed")
else:
    st.error("One or more security checks failed")


# ── KPI row ──────────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Failed",   summary["failed"])
with col2:
    st.metric("Warnings", summary["warnings"])
with col3:
    st.metric("Passed",   summary["passed"])
with col4:
    total = summary["failed"] + summary["warnings"] + summary["passed"]
    pct   = round((summary["passed"] / total * 100) if total else 0, 1)
    st.metric("Pass Rate", f"{pct}%")


st.divider()


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_overview, tab_vulns, tab_remediation, tab_trends = st.tabs([
    "Overview",
    "Vulnerabilities",
    "Remediation",
    "Trends",
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
with tab_overview:
    if not filtered_findings:
        st.success("No findings match the current filters.")
    else:
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            sev_counts = Counter(f["severity"] for f in filtered_findings)
            ordered_keys = sorted(sev_counts.keys(), key=lambda s: SEVERITY_ORDER.get(s, 99))
            fig_pie = px.pie(
                names=ordered_keys,
                values=[sev_counts[k] for k in ordered_keys],
                title="Findings by Severity",
                color=ordered_keys,
                color_discrete_map=SEVERITY_COLORS,
                hole=0.4,
            )
            fig_pie.update_traces(textinfo="label+percent")
            st.plotly_chart(fig_pie, use_container_width=True)

        with chart_col2:
            scan_counts = Counter(f["scanner"] for f in filtered_findings)
            fig_bar = px.bar(
                x=list(scan_counts.keys()),
                y=list(scan_counts.values()),
                title="Findings by Scanner",
                labels={"x": "Scanner", "y": "Count"},
                color=list(scan_counts.keys()),
                text_auto=True,
            )
            fig_bar.update_layout(showlegend=False)
            st.plotly_chart(fig_bar, use_container_width=True)

        # Severity × Scanner heatmap
        st.subheader("Severity × Scanner Breakdown")
        rows = []
        for f in filtered_findings:
            rows.append({"Scanner": f["scanner"], "Severity": f["severity"]})
        if rows:
            df = pd.DataFrame(rows)
            pivot = df.groupby(["Scanner", "Severity"]).size().unstack(fill_value=0)
            fig_heat = go.Figure(data=go.Heatmap(
                z=pivot.values.tolist(),
                x=pivot.columns.tolist(),
                y=pivot.index.tolist(),
                colorscale="Reds",
                text=pivot.values.tolist(),
                texttemplate="%{text}",
                showscale=True,
            ))
            fig_heat.update_layout(
                title="Finding Count",
                xaxis_title="Severity",
                yaxis_title="Scanner",
                height=300
            )
            st.plotly_chart(fig_heat, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — VULNERABILITIES LIST
# ══════════════════════════════════════════════════════════════════════════════
with tab_vulns:
    if not filtered_findings:
        st.success("No findings match the current filters.")
    else:
        # Sort: FAIL first, then WARN, then by severity
        sorted_findings = sorted(
            filtered_findings,
            key=lambda f: (
                0 if f["status"] == "FAIL" else 1 if f["status"] == "WARN" else 2,
                SEVERITY_ORDER.get(f["severity"], 99),
            )
        )

        st.caption(f"Showing **{len(sorted_findings)}** finding(s)")

        group_by = st.radio(
            "Group by",
            ["None", "Type", "Scanner", "Severity"],
            horizontal=True,
            key="vuln_group"
        )

        def render_finding_card(finding):
            sev = finding["severity"]
            status = finding["status"]
            status_label = f":{STATUS_COLOR.get(status, 'gray')}[{status}]"
            type_label = TYPE_LABELS.get(finding["type"], finding["type"])
            short_cat = finding.get("title") or finding["category"].split(".")[-1].replace("-", " ").title()

            loc_parts = [f"`{finding['file']}`"]
            if finding.get("line"):
                loc_parts.append(f"line **{finding['line']}**")
            location_str = "  ·  ".join(loc_parts)

            with st.expander(f"{status_label}  {short_cat}  —  {finding['scanner']}  [{sev}]", expanded=False):
                st.markdown(f"**Location:** {location_str}")

                c1, c2, c3 = st.columns([1, 1, 2])
                with c1:
                    st.markdown(
                        f'<span class="badge badge-{sev}">{sev}</span>',
                        unsafe_allow_html=True
                    )
                with c2:
                    st.markdown(f"`{type_label}`")
                with c3:
                    st.markdown(f"**Status:** {status_label}")

                st.divider()
                st.markdown(finding["message"])
                st.caption(f"Rule ID: `{finding['category']}`")
                severity_info = SEVERITY_INFO.get(sev)
                if severity_info:
                    st.caption(f"{sev} severity: {severity_info[1]}")
                scanner_info = SCANNER_INFO.get(finding["scanner"])
                if scanner_info:
                    st.caption(
                        f"Found by {finding['scanner']} ({scanner_info['kind']}): {scanner_info['summary']}"
                    )

        if group_by == "None":
            for f in sorted_findings:
                render_finding_card(f)
        else:
            group_key = {"Type": "type", "Scanner": "scanner", "Severity": "severity"}[group_by]
            groups: dict = {}
            for f in sorted_findings:
                key = f[group_key]
                groups.setdefault(key, []).append(f)

            if group_by == "Severity":
                groups = dict(sorted(groups.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 99)))

            for group_name, group_findings in groups.items():
                count = len(group_findings)
                st.subheader(f"{group_name}  ({count} finding{'s' if count != 1 else ''})")
                for f in group_findings:
                    render_finding_card(f)
                st.divider()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — REMEDIATION GUIDANCE
# ══════════════════════════════════════════════════════════════════════════════
with tab_remediation:
    st.header("Remediation Guidance")
    st.caption("Prioritised list of actions to fix or mitigate identified findings.")

    if not filtered_findings:
        st.success("No findings — nothing to remediate!")
    else:
        fail_findings = [f for f in filtered_findings if f["status"] == "FAIL"]
        warn_findings = [f for f in filtered_findings if f["status"] == "WARN"]

        def render_remediation_card(f, priority_label):
            short_cat = f.get("title") or f["category"].split(".")[-1].replace("-", " ").title()
            with st.expander(f"{priority_label}  {short_cat}  ·  `{f['file']}`"):
                st.markdown(
                    f"**Severity:** `{f['severity']}`  |  "
                    f"**Scanner:** `{f['scanner']}`  |  "
                    f"**Type:** `{f['type']}`"
                )
                if f.get("line"):
                    st.markdown(f"**Location:** `{f['file']}` line **{f['line']}**")
                st.divider()
                st.markdown(f["message"])

        if fail_findings:
            st.subheader("High Priority — Must Fix")
            for f in sorted(fail_findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
                render_remediation_card(f, ":red[FAIL]")

        if warn_findings:
            st.subheader("Lower Priority — Should Fix")
            for f in sorted(warn_findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
                render_remediation_card(f, ":orange[WARN]")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — TRENDS
# ══════════════════════════════════════════════════════════════════════════════
with tab_trends:
    st.header("Historical Trends")
    history_dir = ROOT / "results" / "history"

    if not history_dir.exists():
        st.info("No historical data found yet. Run more scans to see trends here.")
    else:
        history_files = sorted(history_dir.glob("scan_*.json"))
        if not history_files:
            st.info("No historical scan files found.")
        else:
            history_rows = []
            for hf in history_files:
                try:
                    with open(hf) as hfile:
                        hdata = json.load(hfile)
                    history_rows.append({
                        "Timestamp": hdata.get("timestamp", hf.stem),
                        "Failed":    hdata["summary"]["failed"],
                        "Warnings":  hdata["summary"]["warnings"],
                        "Passed":    hdata["summary"]["passed"],
                        "Total":     hdata["summary"]["failed"] + hdata["summary"]["warnings"] + hdata["summary"]["passed"],
                    })
                except Exception:
                    continue

            if history_rows:
                df_hist = pd.DataFrame(history_rows)
                df_hist["Timestamp"] = pd.to_datetime(df_hist["Timestamp"], errors="coerce")
                df_hist = df_hist.sort_values("Timestamp")
                df_hist["Pass Rate %"] = (
                    df_hist["Passed"] / df_hist["Total"].replace(0, 1) * 100
                ).round(1)

                fig_trend = px.line(
                    df_hist,
                    x="Timestamp",
                    y=["Failed", "Warnings", "Passed"],
                    title="Scan Results Over Time",
                    markers=True,
                    color_discrete_map={
                        "Failed":   "#ff4b4b",
                        "Warnings": "#ffa600",
                        "Passed":   "#21c55d"
                    },
                )
                fig_trend.update_layout(yaxis_title="Count", legend_title="Status")
                st.plotly_chart(fig_trend, use_container_width=True)

                fig_rate = px.area(
                    df_hist,
                    x="Timestamp",
                    y="Pass Rate %",
                    title="Pass Rate Over Time",
                    color_discrete_sequence=["#21c55d"],
                )
                fig_rate.update_layout(yaxis_range=[0, 100])
                st.plotly_chart(fig_rate, use_container_width=True)

                st.subheader("Scan History Table")
                st.dataframe(
                    df_hist[["Timestamp", "Failed", "Warnings", "Passed", "Pass Rate %"]]
                    .sort_values("Timestamp", ascending=False),
                    use_container_width=True,
                    hide_index=True,
                )