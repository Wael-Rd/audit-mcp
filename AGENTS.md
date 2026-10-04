# Project conventions

- Preserve the exact English subject in `catalog.SUBJECT` and exactly ten guide steps.
- This repository is an MCP server for existing infrastructure. Do not build or provision a lab.
- Keep target addresses, container names and metadata paths operator-configured. MCP arguments use registered IDs.
- Keep evidence, AI commentary and human review separate. Never treat an unknown or inherited control as a pass.
- Run `uv run ruff check src tests scripts` and `uv run pytest -q` after functional changes.
- Check report rendering after template changes. Narrative is escaped; only packaged CSS and JS may use Jinja `safe`.
- Runtime data, keys and target registrations are private and ignored by Git.
