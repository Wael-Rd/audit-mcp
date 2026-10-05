# Connect Aegis to an AI host

Aegis is a real MCP server exposing tools, resources and prompts. An MCP-compatible host connects the model to those capabilities. The host owns the model connection; Aegis does not need an OpenAI, Anthropic or other provider API key.

## Local stdio

Recommended launch command:

```bash
uv --directory /absolute/path/to/audit_mcp run --frozen aegis-mcp
```

Clients may use different configuration wrappers. Examples are provided in `examples/`: a common `mcpServers` shape, a VS Code `servers` shape, and a generic loopback HTTP endpoint. Replace all paths; keep credentials outside the repository. Use the same Linux environment for local WSL collection and the server.

## OpenCode

OpenCode uses an `mcp` mapping with `type: "local"`, a command array and an `environment` object. [examples/opencode.json](../examples/opencode.json) supplies that configuration. Run `uv sync --frozen`, replace its absolute paths, and merge the `aegis` entry into your OpenCode configuration. Preserve your existing providers and other MCP entries. The direct virtual-environment Python command avoids dependency resolution during startup.

Merge the entry into your global `~/.config/opencode/opencode.jsonc` or existing `opencode.json` to use Aegis across projects. Reopen an existing OpenCode session to load the change, then check:

```bash
opencode mcp list
```

Look for `aegis connected`. Aegis tools use the `aegis_` prefix, such as `aegis_get_hardening_guide` and `aegis_audit_target`. Ask:

> Use Aegis to audit registered target `wsl` against the ten-step confidentiality hardening guide, then generate a professional English report using the embedded template. Keep target changes disabled and show missing evidence.

Target registrations stay in the ignored `targets.yaml`. Register only your own systems. The local WSL entry can start with no sensitive/backup paths and `classification: unclassified` until the operator supplies its real scope and classification.

OpenCode setup reference: [official MCP server configuration](https://opencode.ai/docs/en/mcp-servers/).

`targets.yaml` registers your own systems. The model can request only a target ID; it cannot introduce a hostname, container ID or shell command. Keep only entries you intend to assess. `sudo: true` uses noninteractive `sudo -n`; configure permissions locally rather than putting a password into MCP.

## Loopback Streamable HTTP

```bash
uv run aegis-mcp --transport streamable-http --port 8765
```

Endpoint: `http://127.0.0.1:8765/mcp`. The listener is fixed to loopback and validates Host and Origin headers to reduce DNS-rebinding risk. It is intended for trusted clients on the same machine. It does not implement a public OAuth deployment; do not expose it through an internet tunnel or reverse proxy. Use stdio for the simplest local setup. If a hosted AI cannot reach your local endpoint, use a local MCP host or design an authenticated deployment separately.

## Assessment workflow

Ask the host to use the `confidentiality_audit` prompt or use this request:

> Assess registered target `vps` against the ten-step confidentiality hardening guide. Show the evidence and supported remediation plan. Keep target changes disabled. Then use get_report_context and render_report to produce a professional English report with the built-in template.

For report generation, the AI should read the compact context once, fill `ReportNarrative`, and call `render_report`. It does not need to read, recreate or rewrite the HTML template. Files are returned as absolute local paths.

Host support for MCP prompts, resources, structured results and local file access varies. Tools remain the primary path. No particular hosted model or paid provider was exercised during project validation.

Protocol reference: [official Python SDK](https://github.com/modelcontextprotocol/python-sdk), [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
