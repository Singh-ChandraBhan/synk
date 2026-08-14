"""Streamlit dashboard. Importing this module performs no remediation."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import streamlit as st

from snyk_nuget_agent.graph import RemediationService


def _theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at 85% 0%, rgba(59,130,246,.12), transparent 28rem),
                radial-gradient(circle at 5% 35%, rgba(139,92,246,.08), transparent 24rem),
                #f8fafc;
        }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0f172a 0%, #172554 58%, #312e81 100%);
            border-right: 1px solid rgba(255,255,255,.08);
        }
        [data-testid="stSidebar"] * { color: #f8fafc; }
        [data-testid="stSidebar"] input {
            color: #0f172a !important;
            background: rgba(255,255,255,.96) !important;
        }
        [data-testid="stSidebar"] [data-baseweb="toggle"] div { color: inherit; }
        .block-container { max-width: 1440px; padding-top: 1.7rem; padding-bottom: 4rem; }
        .hero {
            position: relative; overflow: hidden; border-radius: 24px; padding: 30px 34px;
            margin-bottom: 24px; color: white;
            background: linear-gradient(120deg, #0f172a 0%, #1e3a8a 58%, #6d28d9 100%);
            box-shadow: 0 18px 46px rgba(30,58,138,.2);
        }
        .hero:after {
            content: ""; position: absolute; width: 260px; height: 260px; right: -50px; top: -115px;
            border-radius: 50%; border: 44px solid rgba(255,255,255,.08);
        }
        .hero-kicker { font-size: 12px; font-weight: 800; letter-spacing: .16em; color: #93c5fd; }
        .hero-title { font-size: clamp(27px, 4vw, 42px); line-height: 1.08; font-weight: 800; margin: 8px 0; }
        .hero-copy { max-width: 760px; color: #dbeafe; font-size: 15px; margin: 0; }
        .hero-badge {
            display: inline-flex; align-items: center; gap: 7px; margin-top: 17px; padding: 7px 12px;
            border-radius: 999px; font-size: 12px; font-weight: 700;
            background: rgba(255,255,255,.1); border: 1px solid rgba(255,255,255,.2);
        }
        .section-label {
            margin: 28px 0 12px; color: #0f172a; font-size: 18px; font-weight: 800;
            display: flex; align-items: center; gap: 9px;
        }
        .section-label:after { content: ""; height: 1px; flex: 1; background: linear-gradient(90deg,#cbd5e1,transparent); }
        div.stButton > button, div.stDownloadButton > button, a[data-testid="stLinkButton"] {
            min-height: 44px; border-radius: 12px !important; font-weight: 750 !important;
            border: 1px solid #cbd5e1 !important; box-shadow: 0 4px 12px rgba(15,23,42,.06);
            transition: transform .15s ease, box-shadow .15s ease;
        }
        div.stButton > button:hover, div.stDownloadButton > button:hover {
            transform: translateY(-1px); box-shadow: 0 7px 18px rgba(37,99,235,.15);
        }
        [data-testid="stDataFrame"], [data-testid="stJson"] {
            border-radius: 14px; overflow: hidden; border: 1px solid #e2e8f0;
            box-shadow: 0 5px 18px rgba(15,23,42,.05);
        }
        [data-testid="stMetric"] {
            background: rgba(255,255,255,.88); border: 1px solid #e2e8f0;
            border-radius: 15px; padding: 14px 16px; box-shadow: 0 5px 16px rgba(15,23,42,.05);
        }
        div[data-testid="stForm"] {
            background: rgba(255,255,255,.82); border: 1px solid #dbeafe;
            border-radius: 18px; padding: 18px; box-shadow: 0 6px 20px rgba(37,99,235,.06);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _section(icon: str, title: str) -> None:
    st.markdown(f'<div class="section-label"><span>{icon}</span>{title}</div>', unsafe_allow_html=True)


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
    _theme()
    demo = st.sidebar.toggle("Demo mode (synthetic, never modifies files)", value=True)
    st.sidebar.markdown("### 🛡️ Scan configuration")
    repository = st.sidebar.text_input("Repository URL", placeholder="https://github.com/org/repo")
    branch = st.sidebar.text_input("Branch", value="main")
    solution = st.sidebar.text_input("Solution path", value="Synthetic.sln" if demo else "")
    token = st.sidebar.text_input("Optional Snyk token", type="password")
    st.sidebar.caption("Tokens are held only for this process and are never displayed or written.")
    st.sidebar.markdown("---")
    st.sidebar.caption("🔒 Approval-gated · Backup protected · Rollback ready")
    state = st.session_state.get("agent_state")
    mode_label = "Synthetic demo mode" if demo else "Live repository mode"
    st.markdown(
        f"""
        <div class="hero">
          <div class="hero-kicker">SECURE DEPENDENCY AUTOMATION</div>
          <div class="hero-title">Snyk NuGet Remediation Agent</div>
          <p class="hero-copy">Discover vulnerable .NET packages, approve safe upgrades, and validate every remediation with a complete build and MSTest run.</p>
          <div class="hero-badge">● {mode_label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    _section("⚡", "Workflow status")
    _cards(state)
    if demo:
        st.warning("Synthetic demo mode is active. No repository or project files will be modified.")
    st.write("")
    if st.button("🔍  Scan project", type="primary", use_container_width=True):
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
    _section("📊", "Security posture")
    counts = {severity: sum(1 for f in findings if f["severity"] == severity) for severity in ("critical", "high", "medium", "low")}
    for column, severity in zip(st.columns(4), counts): column.metric(severity.title(), counts[severity])
    _section("🧬", "Vulnerability inventory")
    st.dataframe(findings, use_container_width=True)
    selected = st.selectbox("Detailed finding", range(len(findings)), format_func=lambda i: f"{findings[i]['package']} · {findings[i]['snyk_id']}") if findings else None
    if findings and selected is not None: st.json(findings[selected])
    _section("🛠️", "Safe-version recommendations")
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
    _section("🚀", "Remediate and validate")
    col1, col2 = st.columns(2)
    if col1.button("🛡️  Fix, build and test", disabled=not (state.get("approval") or {}).get("approved"), use_container_width=True):
        try:
            st.session_state.agent_state = RemediationService().apply(state)
            st.rerun()
        except Exception as exc: st.error(str(exc))
    if col2.button("🧪  Build and test independently", use_container_width=True):
        try:
            st.session_state.agent_state = RemediationService().build_test(state)
            st.rerun()
        except Exception as exc: st.error(str(exc))
    if state.get("validation"):
        _section("✅", "Validation results")
        st.json(state["validation"])
        st.markdown("#### Test project results")
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
