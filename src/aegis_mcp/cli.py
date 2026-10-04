"""Small CLI for operators and reproducible checks; the MCP server is the product."""

import argparse
import json
import shutil
import sys
from pathlib import Path

from .engine import Engine
from .server import guide_markdown


def main():
    parser = argparse.ArgumentParser(description="Aegis: ten-step confidentiality audit preparation")
    parser.add_argument("--targets", help="Operator-owned target configuration file")
    parser.add_argument("--workspace", help="Private local evidence directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("guide", help="Print the English ten-step guide")
    commands.add_parser("targets", help="List registered target IDs")
    commands.add_parser("doctor", help="Check local setup without connecting to targets")
    audit = commands.add_parser("audit", help="Collect read-only evidence")
    audit.add_argument("target_id")
    plan = commands.add_parser("plan", help="Create a reviewable remediation plan")
    plan.add_argument("target_id")
    plan.add_argument("--audit", required=True)
    for command in ["apply", "rollback"]:
        mutation = commands.add_parser(command, help="Execute a locally enabled target change")
        mutation.add_argument("--plan", required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("before")
    compare.add_argument("after")
    report = commands.add_parser("report", help="Render the existing professional report template")
    report.add_argument("--audit", required=True)
    report.add_argument("--before")
    report.add_argument("--narrative", help="Optional JSON matching ReportNarrative")
    options = parser.parse_args()
    engine = Engine(options.workspace, options.targets)
    try:
        if options.command == "guide":
            print(guide_markdown())
            return
        if options.command == "targets":
            result = engine.targets()
        elif options.command == "doctor":
            result = {
                "python": sys.version.split()[0],
                "targets": engine.targets(),
                "ssh_available": bool(shutil.which("ssh")),
                "docker_cli_available": bool(shutil.which("docker")),
                "target_changes_enabled": engine.allow_apply,
                "http": "Loopback only; stdio recommended",
                "setup": "Register targets in targets.yaml; no lab or target daemon is provisioned.",
            }
        elif options.command == "audit":
            result = engine.audit(options.target_id)
            result = {k: v for k, v in result.items() if k not in {"observations", "target_config_hash"}}
        elif options.command == "plan":
            result = engine.plan(options.target_id, options.audit)
        elif options.command == "apply":
            result = engine.apply(options.plan)
        elif options.command == "rollback":
            result = engine.rollback(options.plan)
        elif options.command == "compare":
            result = engine.compare(options.before, options.after)
        else:
            narrative = json.loads(Path(options.narrative).read_text()) if options.narrative else None
            result = engine.render_report(options.audit, options.before, narrative)
        print(json.dumps(result, indent=2))
    except (ValueError, PermissionError, RuntimeError, OSError) as failure:
        print(f"Aegis: {failure}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
