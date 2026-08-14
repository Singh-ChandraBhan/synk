"""Typed workflow state and serializable domain models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypedDict


@dataclass(frozen=True)
class Finding:
    package: str
    installed_version: str
    fixed_versions: list[str]
    severity: str
    cves: list[str]
    snyk_id: str
    project: str
    description: str = ""
    transitive: bool = False
    parent_package: str | None = None


@dataclass
class Change:
    package: str
    current_version: str
    candidates: list[str]
    selected_version: str | None
    file: str | None
    project: str
    source: str = "PackageReference"
    major_upgrade: bool = False
    transitive: bool = False
    parent_package: str | None = None
    status: str = "proposed"
    reason: str = ""


@dataclass
class Approval:
    approved: bool
    approver: str
    comment: str
    timestamp_utc: str


@dataclass
class TestResult:
    project: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    trx_file: str | None = None
    success: bool = False


class AgentState(TypedDict, total=False):
    solution: str
    demo: bool
    dry_run: bool
    output_dir: str
    findings: list[dict[str, Any]]
    changes: list[dict[str, Any]]
    approval: dict[str, Any] | None
    validation: dict[str, Any]
    backups: dict[str, str]
    errors: list[str]
    status: str
    candidate_index: int


@dataclass
class RunResult:
    solution: str
    demo: bool
    status: str = "initialized"
    findings: list[Finding] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    approval: Approval | None = None
    validation: dict[str, Any] = field(default_factory=dict)
    output_dir: Path | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["output_dir"] = str(self.output_dir) if self.output_dir else None
        return value

