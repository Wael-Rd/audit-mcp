<p align="center"><img src="docs/assets/aegis-banner.svg" alt="Aegis MCP — evidence before assurance" width="100%"></p>

# Aegis MCP

**An English, ISO-aligned confidentiality audit assistant for your existing Linux systems.**

Connect an MCP-compatible AI client, register your VPS, WSL instance or Docker container, and work through ten hardening steps. Aegis gathers bounded system evidence, builds reviewable remediation plans, verifies supported changes, and supplies a ready-made professional report template. There is no bundled lab, agent daemon or required AI API key.

> **Project subject:** Summary of a Ten-Step Best-Practice Guide to the Hardening Process of an Information System in Preparation for a Confidentiality Audit.

The embedded guide and report both follow that subject: **ten best-practice steps for an information system preparing for a confidentiality audit**. ISO/IEC 27001:2022 and ISO/IEC 27002:2022 provide suggested control mappings. They do not turn individual technical checks into certification claims.

[Report design](docs/assets/report-preview.html) · [AI connections](docs/connecting-ai.md) · [Ten-step guide](docs/ten-step-guide.md) · [Architecture](docs/architecture.md) · [Hardening boundaries](docs/hardening.md)

![Professional report template preview](docs/assets/report-preview.png)

The preview uses **synthetic evidence** to demonstrate the template. It is not an audit of a real system.

## Start in three minutes

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/) and a Linux execution environment. Run the server in WSL when using a Windows machine. SSH targets and existing containers need Python 3.9+ inside the target; missing tools are recorded as missing evidence.

```bash
uv sync --frozen
cp targets.example.yaml targets.yaml
# Edit targets.yaml: keep only targets you own and intend to assess.
uv run aegis doctor
uv run aegis-mcp
```

`aegis-mcp` waits for an AI client over stdio. It does not print a dashboard. Register the launch command in your MCP client using [the connection examples](docs/connecting-ai.md).

You can verify setup before connecting an AI:

```bash
uv run aegis guide
uv run aegis targets
uv run aegis audit wsl
# Save the returned audit_id and use it in the following commands.
uv run aegis plan wsl --audit <audit_id>
uv run aegis report --audit <audit_id>
```

The report command fills the existing template with deterministic summary prose. A connected AI can supply a richer narrative through `get_report_context` and `render_report`.

## Connect your AI

For clients using the common `mcpServers` configuration shape:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/audit_mcp", "run", "--frozen", "aegis-mcp"],
      "env": {
        "AEGIS_TARGETS": "/absolute/path/to/audit_mcp/targets.yaml",
        "AEGIS_WORKSPACE": "/absolute/path/to/audit_mcp/.runtime",
        "AEGIS_ALLOW_APPLY": "0"
      }
    }
  }
}
```

Use absolute paths and make `uv` available to the client process. Client configuration shapes differ; see [connection examples](docs/connecting-ai.md). Aegis works with **MCP-compatible AI hosts**. A model without an MCP host needs an adapter. Your chosen host handles model credentials and inference; Aegis does not call a paid model itself.

For OpenCode, use [examples/opencode.json](examples/opencode.json): OpenCode expects an `mcp` mapping rather than `mcpServers`. The [OpenCode setup instructions](docs/connecting-ai.md#opencode) explain how to merge it and verify `aegis connected`.

Suggested first request:

> Use Aegis to summarize the ten-step hardening best-practice guide, audit my registered `wsl` target for confidentiality readiness, and produce a professional English report using the embedded template. Keep missing evidence and human review items visible. Do not apply target changes.

## The ten steps

| Step | Best-practice domain | Confidentiality purpose | Suggested ISO controls |
| --- | --- | --- | --- |
| 01 | Scope, inventory and classify | Know which assets and data need protection | A.5.9, A.5.12, A.5.13 |
| 02 | Maintain a patched baseline | Reduce exposure from vulnerable software | A.8.8, A.8.9 |
| 03 | Constrain identities and access | Permit access only to approved identities | A.5.15, A.5.16, A.5.18, A.8.2, A.8.5 |
| 04 | Separate network trust zones | Restrict unintended paths to sensitive services | A.8.20–A.8.22 |
| 05 | Protect cryptography and keys | Protect confidential data in transit and storage | A.8.24, A.5.17 |
| 06 | Reduce system attack surface | Reduce information leaks and excess privilege | A.8.9, A.8.19, A.8.27 |
| 07 | Minimize data exposure | Reduce permissive files and data disclosure | A.8.3, A.8.11, A.8.12, A.5.34 |
| 08 | Observe and investigate access | Produce usable access and incident evidence | A.8.15–A.8.17 |
| 09 | Secure backups and prove recovery | Protect copies and demonstrate recovery | A.8.13, A.5.30 |
| 10 | Validate and build the audit dossier | Preserve evidence, review gaps and verify changes | A.5.35, A.5.36, A.8.32 |

All ten domains are always present. Technical checks remain `pass`, `fail`, `unknown` or `not_applicable`; organizational and application controls remain independent review items.

## What the MCP exposes

| Tool | Result |
| --- | --- |
| `get_hardening_guide` | Exact English subject, ten steps and ISO links |
| `list_targets` | Locally registered IDs and capabilities |
| `audit_target` | Read-only target observations and a SHA-256 audit ID |
| `create_hardening_plan` | Sealed plan, exact diffs, prerequisites and manual work |
| `apply_hardening_plan` | Supported changes, target backup and after evidence |
| `rollback_hardening_plan` | Restore managed settings and collect new evidence |
| `compare_audits` | Status transitions between snapshots |
| `get_report_context` | Compact ten-step evidence, writing brief and narrative schema |
| `render_report` | Offline HTML, Markdown and JSON files |

Four resources supply the guide, report director, reusable report structure and standards mappings. Two prompts guide the assessment and professional report workflow.

## Professional report, with little model effort

The design is built in: editorial cover, mint accents, clear typography, ten-step evidence sections, ISO control chips, status filters, search, a before/after comparison and a print-to-PDF layout. It requires no external fonts, analytics or network requests.

The AI receives compact facts and a strict narrative schema. It drafts the title, executive summary, priorities and optional step notes once. The server generates all tables and styling. Narrative cannot override collected counts or statuses. HTML is escaped and protected by a restrictive content-security policy.

Reports and system evidence stay in `.runtime/`, which is ignored by Git. Evidence may include operational hostnames, usernames and configured paths: review a report before sharing it externally.

## Supported hardening

Audit collection is read-only on the target. Target changes require **both** `AEGIS_ALLOW_APPLY=1` in the server environment and `allow_apply: true` for the target. The operator still controls conversational authorization through the AI host.

The current automatic catalogue is deliberately explicit:

- Linux kernel information-disclosure and link-protection settings: `dmesg_restrict`, `kptr_restrict`, `protected_hardlinks`, `protected_symlinks`.
- A managed login-shell `umask 027` drop-in. Existing processes and service policies are unaffected.
- Key-only SSH and disabled direct root SSH login, after independent key access and configuration prerequisites are verified locally.

Patching, firewall changes, application IAM, volume encryption, MFA, logging custody, backup encryption and restore exercises are guided work requiring environment-specific review. Docker targets are audit-only; WSL kernel controls are inherited from its host. Aegis does not provision, restart or rebuild containers.

[Read the exact prerequisites and rollback behavior](docs/hardening.md) before enabling target writes.

## Development and verification

```bash
uv sync --frozen
uv run ruff check src tests scripts
uv run pytest -q
uv run python scripts/check_repository.py
uv run pip-audit --skip-editable
uv build
```

Tests cover the real MCP protocol using synthetic target evidence, target/option injection, evidence tampering, local permission gates, stale plans, rollback, inherited-control handling, report escaping and content-security hashes. Adapter and operational test boundaries are documented in [validation](docs/validation.md).

## Repository layout

```text
src/aegis_mcp/      MCP server, bounded collector, adapters, evidence and reporting
  assets/prompts/  Ten-step workflow and one-pass report director
  assets/templates/ Professional offline HTML/CSS/JS template
docs/              Setup, guide, architecture, hardening and template preview
examples/          MCP host configuration examples
tests/             Protocol, security and report regression tests
scripts/           Publication checks and synthetic template preview
targets.example.yaml Operator target configuration template
uv.lock            Locked dependencies
```

ISO mapping references: [ISO/IEC 27001:2022](https://www.iso.org/standard/27001), [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html). This repository contains original guidance and control identifiers, not copied ISO standard text. See [SECURITY.md](SECURITY.md) and [MIT license](LICENSE).
