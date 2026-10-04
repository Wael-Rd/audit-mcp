"""Render the reusable template with clearly marked synthetic evidence. No targets are contacted."""

import json
from pathlib import Path

from aegis_mcp.checks import assess
from aegis_mcp.reporting import render_html, report_context
from aegis_mcp.server import guide_markdown
from aegis_mcp.targets import Target
from aegis_mcp.workspace import canonical, digest


def main():
    root = Path(__file__).resolve().parents[1]
    observed = json.loads((root / "examples/synthetic-observation.json").read_text())
    target = Target(transport="local", owner="Illustrative system owner", classification="confidential")
    checks, reviews = assess(target, observed)
    counts = {
        status: sum(c["status"] == status for c in checks)
        for status in ["pass", "fail", "unknown", "not_applicable"]
    }
    audit = {
        "audit_id": digest(canonical(observed)),
        "at": "2026-10-05T00:00:00+00:00",
        "target_id": "synthetic-preview",
        "transport": "local",
        "owner": target.owner,
        "classification": target.classification,
        "facts": observed["facts"],
        "checks": checks,
        "reviews": reviews,
        "summary": {**counts, "total": len(checks), "human_reviews": 10},
    }
    context = report_context(audit)
    context["illustrative"] = True
    assets = root / "docs/assets"
    assets.mkdir(parents=True, exist_ok=True)
    preview = "\n".join(line.rstrip() for line in render_html(context).splitlines()) + "\n"
    (assets / "report-preview.html").write_text(preview)
    (root / "docs/ten-step-guide.md").write_text(guide_markdown())
    print("Generated synthetic template preview and English ten-step guide. No system audited.")


if __name__ == "__main__":
    main()
