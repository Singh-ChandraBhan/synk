"""LangGraph orchestration and a reusable high-level service."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from langgraph.graph import END, StateGraph

from .state import AgentState, Approval, Change, Finding
from .tools import (backup_and_apply, create_plan, demo_findings, demo_validation,
                    make_output_dir, rollback, scan_solution, validate, validate_solution,
                    write_approval, write_reports)


def _findings(state: AgentState) -> list[Finding]:
    return [Finding(**item) for item in state.get("findings", [])]


def _changes(state: AgentState) -> list[Change]:
    return [Change(**item) for item in state.get("changes", [])]


def load_scan_node(state: AgentState) -> dict[str, Any]:
    output = Path(state["output_dir"])
    if state.get("demo"):
        findings = demo_findings()
    else:
        solution = validate_solution(state["solution"])
        findings = scan_solution(solution, output)
    return {"findings": [asdict(f) for f in findings], "status": "scanned"}


def resolve_candidates_node(state: AgentState) -> dict[str, Any]:
    if state.get("demo"):
        changes = [Change(f.package, f.installed_version, f.fixed_versions, f.fixed_versions[0], None, f.project, "synthetic", False, f.transitive, f.parent_package, reason="Synthetic safe upgrade") for f in _findings(state)]
    else:
        changes = create_plan(validate_solution(state["solution"]), _findings(state))
    return {"changes": [asdict(c) for c in changes], "status": "planned"}


def prepare_plan_node(state: AgentState) -> dict[str, Any]:
    return {"status": "awaiting_approval"}


def wait_approval_node(state: AgentState) -> dict[str, Any]:
    approval = state.get("approval")
    if approval is None:
        return {"status": "awaiting_approval"}
    return {"status": "approved" if approval.get("approved") else "rejected"}


def apply_node(state: AgentState) -> dict[str, Any]:
    if state.get("demo") or state.get("dry_run"):
        changes = _changes(state)
        for change in changes:
            change.status = "remediated" if state.get("demo") else "dry_run"
        return {"status": "simulated" if state.get("demo") else "dry_run", "backups": {}, "changes": [asdict(c) for c in changes]}
    changes = _changes(state)
    backups = backup_and_apply(changes, Path(state["output_dir"]))
    return {"changes": [asdict(c) for c in changes], "backups": backups, "status": "applied"}


def validation_node(state: AgentState) -> dict[str, Any]:
    output = Path(state["output_dir"])
    validation = demo_validation(output) if state.get("demo") else validate(validate_solution(state["solution"]), output)
    return {"validation": validation, "status": "validated" if validation["success"] else "validation_failed"}


def retry_node(state: AgentState) -> dict[str, Any]:
    # Candidate iteration is performed by RemediationService.apply with rollback
    # between attempts; this node makes retry state explicit for graph inspection.
    return {"candidate_index": state.get("candidate_index", 0) + 1, "status": "retrying"}


def rollback_node(state: AgentState) -> dict[str, Any]:
    rollback(state.get("backups", {}))
    return {"status": "rolled_back"}


def evidence_node(state: AgentState) -> dict[str, Any]:
    write_reports(dict(state), Path(state["output_dir"]))
    return {"status": state.get("status", "complete")}


def _after_approval(state: AgentState) -> str:
    approval = state.get("approval")
    return "apply" if approval and approval.get("approved") else "evidence"


def _after_validation(state: AgentState) -> str:
    return "evidence" if state.get("validation", {}).get("success") else "rollback"


def build_graph():
    graph = StateGraph(AgentState)
    for name, node in (("load_scan", load_scan_node), ("resolve_candidates", resolve_candidates_node),
                       ("prepare_plan", prepare_plan_node), ("wait_approval", wait_approval_node),
                       ("apply", apply_node), ("validate", validation_node), ("retry", retry_node),
                       ("rollback", rollback_node), ("evidence", evidence_node)):
        graph.add_node(name, node)
    graph.set_entry_point("load_scan")
    graph.add_edge("load_scan", "resolve_candidates")
    graph.add_edge("resolve_candidates", "prepare_plan")
    graph.add_edge("prepare_plan", "wait_approval")
    graph.add_conditional_edges("wait_approval", _after_approval, {"apply": "apply", "evidence": "evidence"})
    graph.add_edge("apply", "validate")
    graph.add_conditional_edges("validate", _after_validation, {"evidence": "evidence", "rollback": "rollback"})
    graph.add_edge("rollback", "evidence")
    graph.add_edge("evidence", END)
    return graph.compile()


graph = build_graph()


class RemediationService:
    """Stateful facade shared by CLI and Streamlit; UI code has no edit logic."""

    def start(self, solution: str, *, demo: bool = False, dry_run: bool = False, output_base: Path = Path("artifacts")) -> AgentState:
        if not demo:
            validate_solution(solution)
        output = make_output_dir(output_base)
        state: AgentState = {"solution": str(Path(solution).resolve()), "demo": demo, "dry_run": dry_run, "output_dir": str(output), "errors": [], "status": "initialized"}
        state.update(load_scan_node(state))
        state.update(resolve_candidates_node(state))
        state.update(prepare_plan_node(state))
        write_reports(dict(state), output)
        return state

    def decide(self, state: AgentState, approved: bool, approver: str, comment: str) -> AgentState:
        approval = write_approval(Path(state["output_dir"]), approved, approver, comment)
        state["approval"] = asdict(approval)
        state.update(wait_approval_node(state))
        if not approved:
            write_reports(dict(state), Path(state["output_dir"]))
        return state

    def apply(self, state: AgentState) -> AgentState:
        approval = state.get("approval")
        if not approval or not approval.get("approved"):
            raise PermissionError("Explicit recorded approval is required before remediation")
        state.update(apply_node(state))
        state.update(validation_node(state))
        if not state["validation"]["success"] and state.get("backups"):
            # Retry each next compatible candidate as a coordinated set.
            original = _changes(state)
            backups = state["backups"]
            rollback(backups)
            max_candidates = max((len(c.candidates) for c in original), default=1)
            for index in range(1, max_candidates):
                trial = _changes(state)
                for change in trial:
                    if index < len(change.candidates):
                        change.selected_version = change.candidates[index]
                state["changes"] = [asdict(c) for c in trial]
                state["candidate_index"] = index
                state.update(apply_node(state))
                state.update(validation_node(state))
                if state["validation"]["success"]:
                    break
                rollback(backups)
            if not state["validation"]["success"]:
                state["status"] = "rolled_back"
        write_reports(dict(state), Path(state["output_dir"]))
        return state

    def build_test(self, state: AgentState) -> AgentState:
        state.update(validation_node(state))
        write_reports(dict(state), Path(state["output_dir"]))
        return state
