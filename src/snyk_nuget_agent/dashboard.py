"""Streamlit dashboard. Importing this module performs no remediation."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import streamlit as st

from snyk_nuget_agent.graph import RemediationService


def _cards(state: dict[str, Any] | None) -> None:
    if not state:
        cards = [
            ("🔍", "Scan", "Ready", "ready"),
            ("🛠️", "Remediation", "Not started", "idle"),
            ("👤", "Approval", "Pending", "pending"),
            ("🔀", "Pull request", "Not created", "idle"),
        ]
    else:
        approval = state.get("approval") or {}
        approved = bool(approval.get("approved"))
        rejected = bool(approval) and not approved
        validation_ok = bool(state.get("validation", {}).get("success"))
        status = str(state.get("status", "Not started")).replace("_", " ").title()
        cards = [
            ("✅", "Scan", "Complete", "success"),
            ("🛡️", "Remediation", status, "success" if validation_ok else "active"),
            ("✓" if approved else "✕" if rejected else "👤", "Approval", "Approved" if approved else "Rejected" if rejected else "Pending", "success" if approved else "danger" if rejected else "pending"),
            ("🔀", "Pull request", "Demo PR ready" if state.get("demo") and validation_ok else "Description ready" if validation_ok else "Not created", "success" if validation_ok else "idle"),
        ]

    palette = {
        "ready": ("#2563eb", "#eff6ff", "#bfdbfe"),
        "active": ("#7c3aed", "#f5f3ff", "#ddd6fe"),
        "success": ("#059669", "#ecfdf5", "#a7f3d0"),
        "pending": ("#d97706", "#fffbeb", "#fde68a"),
        "danger": ("#dc2626", "#fef2f2", "#fecaca"),
        "idle": ("#64748b", "#f8fafc", "#e2e8f0"),
    }
    columns = st.columns(4, gap="medium")
    for column, (icon, label, value, tone) in zip(columns, cards):
        accent, background, border = palette[tone]
        column.markdown(
            f"""
            <div style="background:{background}; border:1px solid {border}; border-radius:16px;
                        padding:18px; min-height:116px; box-shadow:0 4px 14px rgba(15,23,42,.06);">
              <div style="display:flex; align-items:center; gap:12px; margin-bottom:14px;">
                <div style="width:42px; height:42px; border-radius:12px; background:white;
                            display:flex; align-items:center; justify-content:center; font-size:22px;
                            box-shadow:0 2px 8px rgba(15,23,42,.08); color:{accent};">{icon}</div>
                <div style="font-size:13px; font-weight:700; letter-spacing:.04em;
                            text-transform:uppercase; color:#475569;">{label}</div>
              </div>
              <span style="display:inline-block; color:{accent}; background:white; border:1px solid {border};
                           border-radius:999px; padding:5px 11px; font-size:14px; font-weight:700;">{value}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render() -> None:
    st.set_page_config(page_title="Snyk NuGet Remediation Agent", layout="wide")
    st.title("Snyk NuGet Remediation Agent")
    demo = st.sidebar.toggle("Demo mode (synthetic, never modifies files)", value=True)
    repository = st.sidebar.text_input("Repository URL", placeholder="https://github.com/org/repo")
    branch = st.sidebar.text_input("Branch", value="main")
    solution = st.sidebar.text_input("Solution path", value="Synthetic.sln" if demo else "")
    token = st.sidebar.text_input("Optional Snyk token", type="password")
    st.sidebar.caption("Tokens are held only for this process and are never displayed or written.")
    state = st.session_state.get("agent_state")
    _cards(state)
    if demo:
        st.warning("Synthetic demo mode is active. No repository or project files will be modified.")
    if st.button("Scan Project", type="primary"):
        try:
            if token: os.environ["SNYK_TOKEN"] = token
            state = RemediationService().start(solution, demo=demo)
            st.session_state.agent_state = state
            st.success("Synthetic scan complete" if demo else "Scan complete")
        except Exception as exc:
            st.error(str(exc))
    state = st.session_state.get("agent_state")
    if not state:
        st.info(f"Repository: {repository or 'local'} · Branch: {branch} · Workflow: ready")
        return
    findings = state.get("findings", [])
    st.subheader("Severity metrics")
    counts = {severity: sum(1 for f in findings if f["severity"] == severity) for severity in ("critical", "high", "medium", "low")}
    for column, severity in zip(st.columns(4), counts): column.metric(severity.title(), counts[severity])
    st.subheader("Vulnerability inventory")
    st.dataframe(findings, use_container_width=True)
    selected = st.selectbox("Detailed finding", range(len(findings)), format_func=lambda i: f"{findings[i]['package']} · {findings[i]['snyk_id']}") if findings else None
    if findings and selected is not None: st.json(findings[selected])
    st.subheader("Safe-version recommendation and remediation plan")
    st.dataframe(state.get("changes", []), use_container_width=True)
    if not state.get("approval"):
        with st.form("approval"):
            approver = st.text_input("Approver name")
            comment = st.text_area("Decision comment")
            approve = st.radio("Decision", ["Approve", "Reject"], horizontal=True)
            if st.form_submit_button("Record decision"):
                try:
                    state = RemediationService().decide(state, approve == "Approve", approver, comment)
                    st.session_state.agent_state = state
                    st.rerun()
                except ValueError as exc: st.error(str(exc))
    col1, col2 = st.columns(2)
    if col1.button("Fix and build", disabled=not state.get("approval", {}).get("approved")):
        try:
            st.session_state.agent_state = RemediationService().apply(state)
            st.rerun()
        except Exception as exc: st.error(str(exc))
    if col2.button("Build and test independently"):
        try:
            st.session_state.agent_state = RemediationService().build_test(state)
            st.rerun()
        except Exception as exc: st.error(str(exc))
    if state.get("validation"):
        st.subheader("Validation results")
        st.json(state["validation"])
        st.subheader("Per-test-project report")
        st.dataframe(state["validation"].get("tests", []), use_container_width=True)
    output = Path(state["output_dir"])
    result = output / "result.json"
    if result.exists(): st.download_button("Download JSON evidence", result.read_bytes(), "result.json", "application/json")
    for title, name in (("Executive Markdown report", "remediation-report.md"), ("Pull-request description", "pull-request.md")):
        file = output / name
        if file.exists():
            st.subheader(title); st.markdown(file.read_text(encoding="utf-8"))
    if demo and state.get("validation", {}).get("success"):
        st.link_button("Open synthetic pull request", "https://example.invalid/pull/42")


if __name__ == "__main__":
    render()
