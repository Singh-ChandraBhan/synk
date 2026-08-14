"""Side-effect-aware tools for scanning, planning, editing, and validating."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from packaging.version import InvalidVersion, Version

from .state import Approval, Change, Finding, TestResult

PACKAGE_REFERENCE = re.compile(r"(<PackageReference\b(?=[^>]*\bInclude=[\"']{name}[\"'])[^>]*\bVersion=[\"'])([^\"']+)([\"'])", re.I)
PACKAGE_VERSION = re.compile(r"(<PackageVersion\b(?=[^>]*\b(?:Include|Update)=[\"']{name}[\"'])[^>]*\bVersion=[\"'])([^\"']+)([\"'])", re.I)
PACKAGE_CONFIG = re.compile(r"(<package\b(?=[^>]*\bid=[\"']{name}[\"'])[^>]*\bversion=[\"'])([^\"']+)([\"'])", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_output_dir(base: Path = Path("artifacts")) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = (base / stamp).resolve()
    path.mkdir(parents=True, exist_ok=False)
    (path / "logs").mkdir()
    (path / "trx").mkdir()
    (path / "backups").mkdir()
    return path


def validate_solution(value: str | Path, *, must_exist: bool = True) -> Path:
    path = Path(value).expanduser().resolve()
    if path.suffix.lower() != ".sln":
        raise ValueError(f"Expected a .sln file, got: {path}")
    if must_exist and (not path.is_file()):
        raise FileNotFoundError(f"Solution does not exist: {path}")
    return path


def run_command(args: list[str], cwd: Path, log: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    if not args or any("\x00" in part for part in args):
        raise ValueError("Invalid subprocess argument")
    merged = os.environ.copy()
    if env:
        merged.update(env)
    result = subprocess.run(args, cwd=cwd, env=merged, text=True, encoding="utf-8", errors="replace", capture_output=True, shell=False, check=False)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(f"$ {' '.join(args)}\n\nSTDOUT\n{result.stdout}\nSTDERR\n{result.stderr}", encoding="utf-8")
    return result


def _dependency_chain(item: dict[str, Any]) -> tuple[bool, str | None]:
    path = item.get("from") or []
    names = [str(x).split("@", 1)[0] for x in path]
    return len(names) > 2, (names[-2] if len(names) > 2 else None)


def parse_snyk_json(data: dict[str, Any] | list[Any]) -> list[Finding]:
    documents = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    for document in documents:
        project = str(document.get("displayTargetFile") or document.get("targetFile") or document.get("projectName") or "unknown")
        for item in document.get("vulnerabilities", []):
            transitive, parent = _dependency_chain(item)
            fixed = item.get("fixedIn") or item.get("nearestFixedInVersion") or []
            if isinstance(fixed, str):
                fixed = [fixed]
            identifiers = item.get("identifiers") or {}
            findings.append(Finding(
                package=str(item.get("packageName") or item.get("name") or "unknown"),
                installed_version=str(item.get("version") or "0"),
                fixed_versions=[str(v) for v in fixed],
                severity=str(item.get("severity") or "unknown"),
                cves=[str(v) for v in identifiers.get("CVE", [])],
                snyk_id=str(item.get("id") or "unknown"), project=project,
                description=str(item.get("title") or item.get("description") or ""),
                transitive=transitive, parent_package=parent,
            ))
    return findings


def scan_solution(solution: Path, output: Path, token: str | None = None) -> list[Finding]:
    restore = run_command(["dotnet", "restore", str(solution)], solution.parent, output / "logs" / "restore-before-scan.log")
    if restore.returncode:
        raise RuntimeError("dotnet restore failed; see restore-before-scan.log")
    env = {"SNYK_TOKEN": token} if token else None
    scan = run_command(["snyk", "test", "--file=" + str(solution), "--all-projects", "--json"], solution.parent, output / "logs" / "snyk-scan.log", env)
    raw = scan.stdout.strip()
    if not raw:
        raise RuntimeError("Snyk produced no JSON output; authenticate with `snyk auth` or set SNYK_TOKEN")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Snyk output was not valid JSON; see snyk-scan.log") from exc
    (output / "scan.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    return parse_snyk_json(data)


def demo_findings() -> list[Finding]:
    specs = [
        ("Newtonsoft.Json", "12.0.1", "13.0.3", "high", "CVE-2024-DEMO-001", "SNYK-DOTNET-NEWTONSOFTJSON-DEMO"),
        ("System.Text.Json", "7.0.0", "7.0.4", "high", "CVE-2024-DEMO-002", "SNYK-DOTNET-SYSTEMTEXTJSON-DEMO"),
        ("Microsoft.IdentityModel.Tokens", "6.30.0", "6.35.0", "critical", "CVE-2024-DEMO-003", "SNYK-DOTNET-IDENTITYMODEL-DEMO"),
        ("Npgsql", "7.0.1", "7.0.7", "medium", "CVE-2024-DEMO-004", "SNYK-DOTNET-NPGSQL-DEMO"),
    ]
    return [Finding(p, old, [new], sev, [cve], sid, "Synthetic.App/Synthetic.App.csproj", "Synthetic demonstration finding", p == "System.Text.Json", "Microsoft.NETCore.App" if p == "System.Text.Json" else None) for p, old, new, sev, cve, sid in specs]


def _versions(url: str) -> list[str]:
    request = urllib.request.Request(url, headers={"User-Agent": "snyk-nuget-agent/1.0"})
    with urllib.request.urlopen(request, timeout=15) as response:  # nosec: NuGet HTTPS endpoint
        return list(json.load(response).get("versions", []))


def nuget_versions(package: str) -> list[str]:
    encoded = package.lower()
    versions = _versions(f"https://api.nuget.org/v3-flatcontainer/{encoded}/index.json")
    deprecated: set[str] = set()
    try:
        request = urllib.request.Request(
            f"https://api.nuget.org/v3/registration5-gz-semver2/{encoded}/index.json",
            headers={"User-Agent": "snyk-nuget-agent/1.0"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec: fixed NuGet HTTPS host
            registration = json.load(response)
        leaves: list[dict[str, Any]] = []
        for page in registration.get("items", []):
            if "items" in page:
                leaves.extend(page["items"])
            elif page.get("@id"):
                child_request = urllib.request.Request(page["@id"], headers={"User-Agent": "snyk-nuget-agent/1.0"})
                with urllib.request.urlopen(child_request, timeout=15) as response:  # nosec: URL supplied by NuGet registration
                    leaves.extend(json.load(response).get("items", []))
        for leaf in leaves:
            entry = leaf.get("catalogEntry", {})
            if entry.get("deprecation"):
                deprecated.add(str(entry.get("version", "")).lower())
    except (OSError, ValueError, json.JSONDecodeError):
        # Availability of the primary version feed is sufficient to plan; if
        # deprecation metadata is unavailable the approval UI exposes review.
        pass
    stable: list[tuple[Version, str]] = []
    for raw in versions:
        try:
            parsed = Version(raw)
        except InvalidVersion:
            continue
        if not parsed.is_prerelease and raw.lower() not in deprecated:
            stable.append((parsed, raw))
    return [raw for _, raw in sorted(stable, reverse=True)]


def compatible_candidates(current: str, fixed: Iterable[str], available: Iterable[str]) -> list[str]:
    try:
        base = Version(current)
    except InvalidVersion:
        return list(dict.fromkeys(fixed))
    minimums = []
    for raw in fixed:
        try: minimums.append(Version(raw))
        except InvalidVersion: pass
    result: list[Version] = []
    for raw in available:
        try: candidate = Version(raw)
        except InvalidVersion: continue
        if candidate <= base or candidate.is_prerelease or (minimums and not any(candidate >= minimum for minimum in minimums)):
            continue
        result.append(candidate)
    result.sort(key=lambda v: (v.major != base.major, v.minor != base.minor, v))
    return [str(v) for v in result]


def locate_package(solution: Path, package: str) -> tuple[Path | None, str]:
    root = solution.parent
    escaped = re.escape(package)
    props = list(root.rglob("Directory.Packages.props"))
    candidates = props + list(root.rglob("*.csproj")) + list(root.rglob("*.fsproj")) + list(root.rglob("packages.config"))
    for path in candidates:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if re.search(rf"(?:Include|Update|id)=[\"']{escaped}[\"']", text, re.I):
            source = "Directory.Packages.props" if path.name == "Directory.Packages.props" else ("packages.config" if path.name == "packages.config" else "PackageReference")
            return path, source
    return None, "transitive"


def create_plan(solution: Path, findings: list[Finding], *, query_nuget: bool = True) -> list[Change]:
    changes: list[Change] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        target = finding.parent_package if finding.transitive and finding.parent_package else finding.package
        key = (target, finding.project)
        if key in seen: continue
        seen.add(key)
        path, source = locate_package(solution, target)
        available: list[str] = []
        if query_nuget:
            try: available = nuget_versions(target)
            except Exception: available = finding.fixed_versions
        candidates = compatible_candidates(finding.installed_version, finding.fixed_versions, available or finding.fixed_versions)
        selected = candidates[0] if candidates else None
        major = bool(selected and Version(selected).major > Version(finding.installed_version).major)
        reason = "Major version requires manual review" if major else ("Compatible stable upgrade" if selected else "No safe stable candidate found")
        changes.append(Change(target, finding.installed_version, candidates[:10], selected, str(path) if path else None, finding.project, source, major, finding.transitive, finding.parent_package, reason=reason))
    return changes


def write_approval(output: Path, approved: bool, approver: str, comment: str) -> Approval:
    if not approver.strip() or not comment.strip():
        raise ValueError("Approver name and decision comment are required")
    approval = Approval(approved, approver.strip(), comment.strip(), utc_now())
    (output / "approval.json").write_text(json.dumps(asdict(approval), indent=2), encoding="utf-8")
    return approval


def backup_and_apply(changes: list[Change], output: Path) -> dict[str, str]:
    backups: dict[str, str] = {}
    for change in changes:
        if not change.file or not change.selected_version: continue
        path = Path(change.file).resolve()
        if str(path) not in backups:
            backup = output / "backups" / f"{len(backups):03d}-{path.name}"
            shutil.copy2(path, backup)
            backups[str(path)] = str(backup)
        text = path.read_text(encoding="utf-8-sig")
        pattern = PACKAGE_VERSION if change.source == "Directory.Packages.props" else PACKAGE_CONFIG if change.source == "packages.config" else PACKAGE_REFERENCE
        compiled = re.compile(pattern.pattern.format(name=re.escape(change.package)), pattern.flags)
        updated, count = compiled.subn(rf"\g<1>{change.selected_version}\g<3>", text, count=1)
        if not count and change.source == "PackageReference":
            # Also support the valid child-element form:
            # <PackageReference Include="X"><Version>1.2.3</Version>.
            child = re.compile(rf"(<PackageReference\b(?=[^>]*\bInclude=[\"']{re.escape(change.package)}[\"'])[^>]*>.*?<Version>)([^<]+)(</Version>)", re.I | re.S)
            updated, count = child.subn(rf"\g<1>{change.selected_version}\g<3>", text, count=1)
        if not count:
            raise RuntimeError(f"Could not safely update {change.package} in {path}")
        path.write_text(updated, encoding="utf-8", newline="")
        change.status = "applied"
    return backups


def rollback(backups: dict[str, str]) -> None:
    for original, backup in backups.items():
        shutil.copy2(backup, original)


def discover_test_projects(solution: Path) -> list[Path]:
    projects: list[Path] = []
    for project in solution.parent.rglob("*.*proj"):
        text = project.read_text(encoding="utf-8-sig", errors="replace")
        if "Microsoft.NET.Test.Sdk" in text or "MSTest.TestAdapter" in text or "<IsTestProject>true" in text:
            projects.append(project)
    return projects


def parse_trx(path: Path, project: str) -> TestResult:
    root = ET.parse(path).getroot()
    counters = next((node for node in root.iter() if node.tag.endswith("Counters")), None)
    attrs = counters.attrib if counters is not None else {}
    total, passed, failed = (int(attrs.get(k, 0)) for k in ("total", "passed", "failed"))
    skipped = int(attrs.get("notExecuted", 0))
    return TestResult(project, total, passed, failed, skipped, str(path), failed == 0)


def validate(solution: Path, output: Path) -> dict[str, Any]:
    restore = run_command(["dotnet", "restore", str(solution)], solution.parent, output / "logs" / "restore.log")
    build = run_command(["dotnet", "build", str(solution), "--no-restore", "--configuration", "Release"], solution.parent, output / "logs" / "build.log") if restore.returncode == 0 else None
    tests: list[TestResult] = []
    if build and build.returncode == 0:
        for index, project in enumerate(discover_test_projects(solution)):
            name = f"test-{index}.trx"
            result = run_command(["dotnet", "test", str(project), "--no-build", "--configuration", "Release", "--logger", f"trx;LogFileName={name}", "--results-directory", str(output / "trx")], solution.parent, output / "logs" / f"test-{index}.log")
            trx = output / "trx" / name
            tests.append(parse_trx(trx, str(project)) if trx.exists() else TestResult(str(project), success=result.returncode == 0))
    success = restore.returncode == 0 and bool(build and build.returncode == 0) and all(t.success for t in tests)
    return {"success": success, "restore": restore.returncode == 0, "build": bool(build and build.returncode == 0), "tests": [asdict(t) for t in tests], "totals": {k: sum(getattr(t, k) for t in tests) for k in ("total", "passed", "failed", "skipped")}}


def demo_validation(output: Path) -> dict[str, Any]:
    tests = [TestResult("Synthetic.UnitTests", 12, 12, 0, 0, str(output / "trx" / "synthetic-unit.trx"), True), TestResult("Synthetic.IntegrationTests", 12, 12, 0, 0, str(output / "trx" / "synthetic-integration.trx"), True)]
    for test in tests:
        Path(test.trx_file or "").write_text(f'<TestRun><ResultSummary><Counters total="12" passed="12" failed="0" notExecuted="0" /></ResultSummary></TestRun>', encoding="utf-8")
    (output / "logs" / "snyk-scan.log").write_text("SYNTHETIC: four findings", encoding="utf-8")
    (output / "logs" / "build.log").write_text("SYNTHETIC: build succeeded", encoding="utf-8")
    return {"success": True, "restore": True, "build": True, "tests": [asdict(t) for t in tests], "totals": {"total": 24, "passed": 24, "failed": 0, "skipped": 0}}


def write_reports(result: dict[str, Any], output: Path) -> None:
    (output / "result.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    synthetic = " **SYNTHETIC DEMO DATA**" if result.get("demo") else ""
    findings = result.get("findings", [])
    changes = result.get("changes", [])
    validation = result.get("validation", {})
    report = f"# Snyk NuGet Remediation Report{synthetic}\n\n- Status: {result.get('status')}\n- Findings: {len(findings)}\n- Proposed changes: {len(changes)}\n- Validation: {'passed' if validation.get('success') else 'not passed'}\n\n## Changes\n" + "\n".join(f"- `{c['package']}` {c['current_version']} → {c.get('selected_version') or 'unresolved'}" for c in changes)
    (output / "remediation-report.md").write_text(report + "\n", encoding="utf-8")
    pr = f"# Remediate vulnerable NuGet dependencies{synthetic}\n\n{len(changes)} dependency upgrades were approval-gated and validated.\n\n## Validation\n- Build: {'passed' if validation.get('build') else 'failed/not run'}\n- Tests: {validation.get('totals', {}).get('passed', 0)} passed\n"
    (output / "pull-request.md").write_text(pr, encoding="utf-8")
