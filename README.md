# Snyk NuGet Remediation Agent

Production-oriented, approval-gated remediation for vulnerable NuGet dependencies. It restores and scans a solution with Snyk, finds version declarations, proposes stable non-downgrade upgrades, records human approval, edits with backups, validates the entire solution, retries compatible candidates, and rolls back unsafe changes.

> Demo mode is synthetic and never changes project files. The application does not create a real pull request; it generates a ready-to-use PR description (and a clearly fake link in demo mode).

## Architecture

`tools.py` owns deterministic scanning, NuGet lookup, XML-safe targeted edits, subprocesses, TRX parsing, backups, and evidence. `graph.py` exposes typed LangGraph nodes and `RemediationService`, the shared orchestration API. `cli.py` and `dashboard.py` are thin interfaces. No destructive action runs merely by importing the dashboard.

Workflow: restore/scan → resolve candidates → prepare plan → wait for approval → backup/apply → restore/build/test → retry → rollback on exhaustion → evidence.

The candidate order prefers stable patches, then compatible minors, then majors. Major upgrades are flagged for manual review. Transitive findings target their nearest parent when Snyk reports a usable dependency chain. NuGet's flat-container and registration APIs supply versions and deprecation metadata; prerelease and deprecated versions are excluded. If registration metadata is temporarily unavailable, the plan remains subject to the mandatory human review.

## Requirements

- Python 3.10+
- .NET SDK compatible with the target solution
- Snyk CLI on `PATH` (`npm install -g snyk`)
- A Snyk token or an existing `snyk auth` session
- Windows PowerShell is supported; commands use argument arrays and never `shell=True`

OpenAI variables are optional. LangChain OpenAI is packaged for future policy-assisted recommendations; remediation decisions are deterministic in version 1.0.

## Installation and environment

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
Copy-Item .env.example .env
```

Set `SNYK_TOKEN` in the process environment or `.env`. Never pass it on the command line. `.env`, logs, generated evidence, caches, local tools, `bin`, `obj`, and virtual environments are ignored.

## Demo mode

Demo mode needs no real solution, Snyk, .NET, or credentials:

```powershell
snyk-nuget-agent plan Synthetic.sln --demo
snyk-nuget-agent apply Synthetic.sln --demo --approve --approver "Demo User" --comment "Approved synthetic demonstration"
snyk-nuget-dashboard
```

It creates four labeled synthetic findings (Newtonsoft.Json, System.Text.Json, Microsoft.IdentityModel.Tokens, Npgsql), simulates four remediations, a successful build, and 24 passing MSTest tests in two projects.

## Real scanning and approval workflow

```powershell
snyk auth
snyk-nuget-agent scan C:\src\App\App.sln
snyk-nuget-agent plan C:\src\App\App.sln --dry-run
snyk-nuget-agent apply C:\src\App\App.sln --approve --approver "Ada Lovelace" --comment "Reviewed ticket SEC-123"
```

`scan` and `plan` create findings and a plan but do not edit. `apply` starts a fresh scan and requires all three approval arguments. Without `--approve`, the decision is recorded as rejected. For an independent validation run:

```powershell
snyk-nuget-agent build-test C:\src\App\App.sln --output C:\temp\validation
```

The service validates the `.sln` path, makes timestamped evidence, backs up every touched file, applies only after approval, restores/builds the complete solution, discovers test projects, runs each with TRX output, and restores originals if all compatible candidate sets fail.

## Dashboard

```powershell
snyk-nuget-dashboard
# equivalent: python -m streamlit run src/snyk_nuget_agent/dashboard.py
```

The sidebar accepts repository/branch context, local solution path, and an optional masked token. Repository cloning and pushing are intentionally outside this security boundary: clone/checkout first, select the local `.sln`, and use the generated `pull-request.md` in your normal reviewed Git workflow.

## Evidence

Each run creates `artifacts/<UTC timestamp>/` with `result.json`, `approval.json` after a decision, `remediation-report.md`, `pull-request.md`, scan/build/test logs, TRX files, and backup copies. Credentials are neither logged nor serialized. Backup names are indexed to avoid collisions.

## GitHub Actions

Add `SNYK_TOKEN` as a repository Actions secret, then run **Snyk NuGet Remediation** manually with the solution path. The workflow is deliberately plan-only and uploads evidence. Applying an approved plan should occur in a protected environment or reviewed local branch; CI does not invent approval.

## Security considerations

- Secrets are read from environment variables and are never printed.
- Subprocesses use fixed executable names and argument arrays, not a shell.
- Only existing `.sln` files are accepted in real mode.
- No project changes occur before a named, commented approval record.
- Every touched file is copied before edits and restored after failed validation.
- Generated reports may contain dependency and filesystem metadata; handle them as internal security evidence.

## Troubleshooting

- **`dotnet`/`snyk` not found:** install it and restart the terminal so `PATH` refreshes.
- **Snyk produced no JSON:** run `snyk auth`, set `SNYK_TOKEN`, and inspect `logs/snyk-scan.log`.
- **Restore failed:** reproduce with `dotnet restore <solution>` and check authenticated NuGet feeds.
- **Package not located:** central versions may use MSBuild properties or custom imports. The agent refuses an unsafe edit; update that package manually.
- **No tests discovered:** ensure the project references `Microsoft.NET.Test.Sdk`, `MSTest.TestAdapter`, or sets `IsTestProject`.
- **Major upgrade flagged:** review release notes and compatibility before approving.
