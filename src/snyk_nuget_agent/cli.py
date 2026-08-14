"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from dotenv import load_dotenv

from .graph import RemediationService
from .tools import validate, validate_solution


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="snyk-nuget-agent", description="Approval-gated NuGet vulnerability remediation")
    sub = root.add_subparsers(dest="command", required=True)
    for name in ("scan", "plan"):
        cmd = sub.add_parser(name)
        cmd.add_argument("solution")
        cmd.add_argument("--demo", action="store_true")
        cmd.add_argument("--dry-run", action="store_true")
        cmd.add_argument("--output-base", type=Path, default=Path("artifacts"))
    apply = sub.add_parser("apply")
    apply.add_argument("solution")
    apply.add_argument("--approver", required=True)
    apply.add_argument("--comment", required=True)
    apply.add_argument("--approve", action="store_true", help="Explicitly approve changes")
    apply.add_argument("--demo", action="store_true")
    apply.add_argument("--dry-run", action="store_true")
    apply.add_argument("--output-base", type=Path, default=Path("artifacts"))
    build = sub.add_parser("build-test")
    build.add_argument("solution")
    build.add_argument("--output", type=Path, required=True)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    load_dotenv()
    args = parser().parse_args(argv)
    try:
        if args.command == "build-test":
            solution = validate_solution(args.solution)
            args.output.mkdir(parents=True, exist_ok=True)
            for directory in ("logs", "trx", "backups"):
                (args.output / directory).mkdir(exist_ok=True)
            result = validate(solution, args.output)
            print(json.dumps(result, indent=2))
            return 0 if result["success"] else 1
        service = RemediationService()
        state = service.start(args.solution, demo=args.demo, dry_run=args.dry_run, output_base=args.output_base)
        if args.command == "apply":
            state = service.decide(state, args.approve, args.approver, args.comment)
            if args.approve:
                state = service.apply(state)
        print(json.dumps(state, indent=2, default=str))
        return 0 if state.get("status") not in {"validation_failed", "rolled_back"} else 1
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print(f"Error: {exc}", file=os.sys.stderr)
        return 2

