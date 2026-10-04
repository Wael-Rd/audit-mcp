# Validation record

Validated locally on 2026-10-05 with Python 3.13 and the locked MCP SDK 2.3.0. This record distinguishes real protocol/collector checks from synthetic target evidence.

| Check | Evidence boundary | Result |
| --- | --- | --- |
| Regression suite | 31 tests; simulated target observations and isolated temporary configuration paths | Passed |
| Ruff | Server, collector, adapters, reports, tests and scripts | Passed |
| Dependency audit | Installed locked environment; editable project skipped by pip-audit | No known dependency vulnerabilities reported |
| MCP in-process protocol | Tools, resources, prompts and report workflow over the real SDK, synthetic target facts | Passed |
| MCP stdio | Real child-process server; guide/tool discovery | Passed |
| Streamable HTTP | Real loopback server; guide tool, invalid Host and Origin requests | Passed; invalid Host 421, invalid Origin 403 |
| Read-only local collector | Real local Linux metadata; no target configuration mutation | 23 checks recorded, including unknown and inherited-control states |
| Browser template | Chromium; synthetic evidence only | Ten sections, filters, evidence search, mobile width and print-to-PDF passed; no script/CSP errors |
| Package build | Wheel and source archive; required collector/template/prompt resources checked | Passed |
| Publication scan | Git-visible source, examples and synthetic preview; ignored runtime artifacts excluded | No matching credential material or private runtime artifacts |

No VPS or live Docker target was used. SSH option handling was tested with a mocked transport; a remote SSH connection and live target mutation remain unexecuted. Hardening failure/rollback and successful after-evidence handling were tested in isolation, not by changing the developer's system. No hosted AI provider was called.

The design preview is clearly labeled synthetic and does not establish operational findings. The local collector smoke check demonstrates that collection runs; it is not a full confidentiality audit of the development environment.

Reproduce the automated checks:

```bash
uv sync --frozen
uv run ruff check src tests scripts
uv run pytest -q
uv run pip-audit --skip-editable
uv run python scripts/check_repository.py
uv build
```

The scan checks high-confidence credential patterns; it cannot prove the absence of every secret. New target adapters or remediation actions need operational testing against an authorized disposable target before relying on them in production.
