# Demonstration walkthrough

## Before the session

From the repository root, create and activate a Python 3.10+ virtual environment, run `python -m pip install -e .`, then start `snyk-nuget-dashboard`. No Snyk token or .NET SDK is needed for the demonstration. Leave **Demo mode** enabled.

## 1. Establish the problem (1 minute)

Explain that NuGet security fixes often cross several project files and that an upgrade is not complete until the whole solution builds and tests. Point out the four workflow cards. Emphasize that demo data is visibly labeled synthetic and no file modifications can occur.

## 2. Scan (1 minute)

Optionally enter a sample repository URL and branch; leave `Synthetic.sln` selected. Click **Scan Project**. Show severity cards and the inventory containing Newtonsoft.Json, System.Text.Json, Microsoft.IdentityModel.Tokens, and Npgsql. Open an individual finding to show CVE, Snyk ID, affected project, description, and transitive metadata.

## 3. Review recommendations (2 minutes)

Show the remediation plan: installed version, ordered candidates, selected safe version, source, and reason. Explain that a real run queries NuGet, excludes prereleases, never downgrades, prefers patch/minor upgrades, and flags majors. Explain that transitive findings are remediated through an appropriate parent when Snyk provides the chain.

## 4. Human gate (1 minute)

Enter approver `Demo Security Reviewer` and comment `Reviewed synthetic findings for presentation`. Choose **Approve**, then record the decision. Show that the UTC-stamped `approval.json` now exists. Mention that blank identity/comment is rejected and project edits are unreachable without approval.

## 5. Fix and validate (2 minutes)

Click **Fix and build**. The demo simulates four remediations, restore/build success, and 24 passing MSTest tests split evenly across two projects. Show the totals and per-project table. Clarify that real mode backs up each file, applies changes, builds the full solution, parses TRX, retries later compatible versions, and rolls back if none validate.

Use **Build and test independently** to demonstrate that validation is also available without another remediation action.

## 6. Evidence and handoff (2 minutes)

Download `result.json`. Scroll through the executive Markdown report and generated pull-request description. Click the clearly synthetic PR link. In the timestamped artifacts directory show scan/build logs, two TRX files, reports, decision evidence, and the backup directory.

## 7. CLI close (1 minute)

Run:

```powershell
snyk-nuget-agent apply Synthetic.sln --demo --approve --approver "Demo Security Reviewer" --comment "CLI demonstration"
```

Point out that the same service layer powers both interfaces. Close by showing the GitHub Actions workflow, which intentionally scans/plans and uploads evidence but never fabricates approval or applies changes.
