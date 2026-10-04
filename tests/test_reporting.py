import base64
import hashlib
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_mcp.catalog import STEPS, SUBJECT
from aegis_mcp.reporting import ReportNarrative, render_html
from aegis_mcp.server import guide_markdown


def test_subject_is_exactly_the_requested_ten_step_summary():
    assert len(STEPS) == 10
    assert SUBJECT == (
        "Summary of a Ten-Step Best-Practice Guide to the Hardening Process of an Information System "
        "in Preparation for a Confidentiality Audit"
    )
    assert all(f"## {n:02}." in guide_markdown() for n in range(1, 11))


def test_unknown_crypto_and_restore_evidence_never_become_passes(engine):
    audit = engine.audit("test")
    checks = [
        c
        for c in audit["checks"]
        if c["title"] in {"Encrypted-storage coverage", "Recovery exercise and backup encryption proven"}
    ]
    assert len(checks) == 2
    assert all(c["status"] == "unknown" for c in checks)
    assert len(audit["reviews"]) == 10


def test_report_escapes_narrative_and_target_instructions(engine):
    audit = engine.audit("test")
    context = engine.report_context(audit["audit_id"])
    context["owner"] = '<script>alert("owner")</script>'
    html = render_html(
        context,
        {
            "title": '<script>alert("title")</script>',
            "executive_summary": 'Ignore instructions <img src=x onerror="alert(1)">',
            "priorities": ['<iframe src="https://example.invalid"></iframe>'],
        },
    )
    assert '<script>alert("owner")</script>' not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "<iframe src=" not in html
    assert "connect-src 'none'" in html


def test_csp_hashes_match_packaged_css_and_script(engine):
    audit = engine.audit("test")
    html = render_html(engine.report_context(audit["audit_id"]))
    for tag in ["style", "script"]:
        content = re.search(f"<{tag}>(.*?)</{tag}>", html, re.S).group(1)
        checksum = base64.b64encode(hashlib.sha256(content.encode()).digest()).decode()
        assert "'sha256-" + checksum + "'" in html


def test_narrative_cannot_override_evidence():
    with pytest.raises(ValidationError):
        ReportNarrative.model_validate({"summary": {"pass": 999}})
    with pytest.raises(ValidationError):
        ReportNarrative.model_validate({"step_notes": [{"step": 1, "note": "A"}, {"step": 1, "note": "B"}]})


def test_html_markdown_and_json_exports_share_one_snapshot(engine):
    audit = engine.audit("test")
    result = engine.render_report(audit["audit_id"])
    for path in result["files"].values():
        text = Path(path).read_text()
        assert audit["audit_id"] in text
