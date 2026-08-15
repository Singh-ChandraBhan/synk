"""Streamlit dashboard. Importing this module performs no remediation."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import streamlit as st

from snyk_nuget_agent.graph import RemediationService


def _theme() -> None:
    st.markdown("""<style>
    :root{color-scheme:dark}.stApp{background:#0c1017;color:#f8fafc}.block-container{max-width:1080px;padding:1.5rem 2rem 4rem}
    [data-testid="stHeader"]{background:transparent}[data-testid="stSidebar"]{background:#252832;border-right:1px solid #303541}
    [data-testid="stSidebar"] .block-container{padding:2rem 1.2rem}[data-testid="stSidebar"] *{color:#f8fafc}
    [data-testid="stSidebar"] input,[data-testid="stSidebar"] [data-baseweb="select"]>div{background:#11151d!important}
    h1,h2,h3{color:#fff!important}p,label,[data-testid="stCaptionContainer"]{color:#aab2c0}.app-title{font-size:30px;font-weight:850;color:#fff}
    .app-subtitle{color:#8d96a6;font-size:12px;margin:4px 0 15px}.demo-banner{border:1px solid #f5c542;background:#fff1b8;color:#5b4300;border-radius:6px;padding:10px 13px;font-size:12px;margin-bottom:18px}
    .section-title{color:#fff;font-size:19px;font-weight:800;margin:22px 0 12px}.context-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px}
    .context-label{color:#7d8797;font-size:10px;margin-bottom:4px}.context-value{color:#c8ced8;background:#282b35;border-radius:5px;padding:8px 10px;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .status-card{border-radius:10px;min-height:96px;padding:14px 15px;color:#111827;border-left:4px solid var(--accent);box-shadow:0 4px 12px rgba(0,0,0,.2)}
    .status-icon{font-size:19px;margin-bottom:8px}.status-label{font-size:9px;font-weight:800;letter-spacing:.12em;color:#4b5563}.status-value{margin-top:8px;font-size:14px;font-weight:850;color:#111827}
    .metric-card{background:#111827;border:1px solid #344154;border-radius:8px;padding:12px 14px}.metric-label{color:#a8b2c2;font-size:10px;font-weight:700}.metric-value{color:#fff;font-size:24px;margin-top:6px}
    [data-testid="stDataFrame"]{border:1px solid #303744;border-radius:8px;overflow:hidden}[data-testid="stDataFrame"] *{font-size:11px}div[data-testid="stForm"]{background:transparent;border:0;padding:0}
    div.stButton>button,div.stDownloadButton>button,a[data-testid="stLinkButton"]{border:1px solid #596273!important;border-radius:6px!important;background:#10151d!important;color:#f8fafc!important;font-size:11px!important;font-weight:700!important;min-height:37px}
    div.stButton>button[kind="primary"],div[data-testid="stFormSubmitButton"] button{background:#ff4f5e!important;border-color:#ff4f5e!important;color:white!important}
    div.stButton>button:hover{border-color:#ff6b77!important;box-shadow:0 0 0 1px #ff6b77}[data-testid="stTextInput"] input,[data-testid="stTextArea"] textarea,[data-testid="stSelectbox"] [data-baseweb="select"]>div{background:#282b35;color:#fff;border-color:#343946}
    [data-testid="stAlert"]{border-radius:6px;font-size:12px}details{background:#10141c!important;border:1px solid #343b48!important;border-radius:6px!important}.sidebar-title{font-size:14px;font-weight:800;margin-bottom:12px}.sidebar-note{color:#aab2c0;font-size:10px;line-height:1.55;margin-top:20px}
    </style>""", unsafe_allow_html=True)


def _title(text: str) -> None:
    st.markdown(f'<div class="section-title">{text}</div>', unsafe_allow_html=True)


def _status_cards(state: dict[str, Any] | None) -> None:
    approval = (state or {}).get("approval") or {}
    validated = bool((state or {}).get("validation", {}).get("success"))
    scanned = bool(state)
    cards = [
        ("&#128269;", "SCAN STATUS", "Completed" if scanned else "Ready", "#d9f8e5", "#10b981"),
        ("&#128295;", "REMEDIATION STATUS", "Validated" if validated else "Ready" if scanned else "Not started", "#dceaff", "#2563eb"),
        ("&#9989;", "APPROVAL STATUS", "Approved" if approval.get("approved") else "Rejected" if approval else "Pending", "#fff4c9", "#f59e0b"),
        ("&#128279;", "PULL REQUEST", "Ready" if validated else "Not created", "#e8edf3", "#64748b"),
    ]
    for column, (icon, label, value, background, accent) in zip(st.columns(4), cards):
        column.markdown(f'<div class="status-card" style="background:{background};--accent:{accent}"><div class="status-icon">{icon}</div><div class="status-label">{label}</div><div class="status-value">{value}</div></div>', unsafe_allow_html=True)


def _metrics(findings: list[dict[str, Any]]) -> None:
    values = [("Total Vulnerabilities", len(findings))]
    values.extend((severity.title(), sum(1 for item in findings if item["severity"] == severity)) for severity in ("critical", "high", "medium", "low"))
    for column, (label, value) in zip(st.columns(5), values):
        column.markdown(f'<div class="metric-card"><div class="metric-label">{label}</div><div class="metric-value">{value}</div></div>', unsafe_allow_html=True)


def render() -> None:
    st.set_page_config(page_title="Snyk NuGet Remediation Agent", page_icon="🛡️", layout="wide")
    _theme()
    st.sidebar.markdown('<div class="sidebar-title">Repository Target</div>', unsafe_allow_html=True)
    demo = st.sidebar.toggle("Demo mode", value=True)
    repository = st.sidebar.text_input("Repository", value="https://github.com/acme/orders-api")
    branch = st.sidebar.text_input("Branch", value="main")
    solution = st.sidebar.text_input("Solution selector", value="src/Orders.Api.sln" if demo else "")
    token = st.sidebar.text_input("Snyk token (optional)", type="password")
    st.sidebar.slider("Compatible-version retries", 1, 5, 2)
    st.sidebar.markdown('<div class="sidebar-note">Real mode scans internally. No report upload or manual path is required.<br><br>Secrets are never displayed or written to evidence.</div>', unsafe_allow_html=True)

    st.markdown('<div class="app-title">Snyk NuGet Remediation Agent</div>', unsafe_allow_html=True)
    st.markdown('<div class="app-subtitle">LangGraph vulnerability discovery, safe upgrades, build validation, retry, and rollback.</div>', unsafe_allow_html=True)
    with st.expander("What this application does"):
        st.write("Scans .NET solutions with Snyk, proposes stable NuGet upgrades, enforces human approval, validates the complete solution, and rolls back unsafe changes.")
    if demo:
        st.markdown('<div class="demo-banner"><b>Demo mode:</b> All vulnerabilities and remediation results below are synthetic data. No project files are changed.</div>', unsafe_allow_html=True)

    _title("Repository & Workflow Status")
    st.markdown(f'<div class="context-grid"><div><div class="context-label">Repository</div><div class="context-value">{repository or "Local repository"}</div></div><div><div class="context-label">Branch</div><div class="context-value">{branch}</div></div><div><div class="context-label">Solution</div><div class="context-value">{solution or "Not selected"}</div></div></div>', unsafe_allow_html=True)
    state = st.session_state.get("agent_state")
    _status_cards(state)
    st.write("")
    if st.button("Scan Project", type="primary", width="stretch"):
        try:
            if token:
                os.environ["SNYK_TOKEN"] = token
            st.session_state.agent_state = RemediationService().start(solution or "Synthetic.sln", demo=demo)
            st.rerun()
        except Exception as exc:
            st.error(str(exc))
    state = st.session_state.get("agent_state")
    if not state:
        st.info("Scan the project to load findings and prepare a remediation plan.")
        return

    _title("Human Approval Gate")
    if not state.get("approval"):
        with st.form("approval"):
            left, right = st.columns([2, 1])
            approver = left.text_input("Approver", value="Security Reviewer")
            comment = left.text_area("Decision comment", value="Reviewed Snyk findings and proposed stable NuGet upgrades.")
            decision = right.radio("Decision", ["Approve", "Reject"])
            if st.form_submit_button("Approve Remediation" if decision == "Approve" else "Reject Remediation", width="stretch"):
                try:
                    st.session_state.agent_state = RemediationService().decide(state, decision == "Approve", approver, comment)
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
    else:
        approval = state["approval"]
        st.success(f"Decision recorded: {'Approved' if approval['approved'] else 'Rejected'} by {approval['approver']} · {approval['timestamp_utc']}")

    findings = state.get("findings", [])
    _metrics(findings)
    _title("Vulnerability Inventory")
    inventory = [{"Package": item["package"], "Current Version": item["installed_version"], "Severity": item["severity"].title(), "CVE": ", ".join(item["cves"]) or "Not supplied", "Vulnerability ID": item["snyk_id"], "Fixed Version": ", ".join(item["fixed_versions"]), "Dependency": "Transitive" if item["transitive"] else "Direct/unknown"} for item in findings]
    st.dataframe(inventory, width="stretch", hide_index=True, selection_mode="single-row", on_select="rerun")
    st.caption("Select one row in the inventory, then use the details button below.")
    action1, action2, action3 = st.columns(3)
    show_details = action1.button("View Snyk Details & Remediation", width="stretch")
    run_fix = action2.button("Fix Snyk NuGet Vulnerabilities & Build Project", disabled=not (state.get("approval") or {}).get("approved"), width="stretch")
    run_tests = action3.button("Build & Run All MSTest Cases", width="stretch")
    if show_details:
        with st.expander("Finding details and safe-version recommendations", expanded=True):
            st.dataframe(state.get("changes", []), width="stretch", hide_index=True)
            st.json(findings)
    if run_fix:
        try:
            st.session_state.agent_state = RemediationService().apply(state)
            st.rerun()
        except Exception as exc:
            st.error(str(exc))
    if run_tests:
        try:
            st.session_state.agent_state = RemediationService().build_test(state)
            st.rerun()
        except Exception as exc:
            st.error(str(exc))

    state = st.session_state.get("agent_state")
    if state.get("validation"):
        _title("Build & MSTest Results")
        validation = state["validation"]
        columns = st.columns(4)
        columns[0].metric("Build", "Passed" if validation.get("build") else "Failed")
        totals = validation.get("totals", {})
        columns[1].metric("Total tests", totals.get("total", 0)); columns[2].metric("Passed", totals.get("passed", 0)); columns[3].metric("Failed", totals.get("failed", 0))
        st.dataframe(validation.get("tests", []), width="stretch", hide_index=True)
    result = Path(state["output_dir"]) / "result.json"
    if result.exists():
        st.download_button("Download JSON Evidence", result.read_bytes(), "result.json", "application/json")


if __name__ == "__main__":
    render()
