# Aegis assessment workflow

Work only on a target returned by `list_targets`. If none exist, explain how the operator copies and edits `targets.example.yaml`; do not invent or register an address.

1. Call `audit_target` once for the selected target. Save its `audit_id`.
2. Explain the material findings and evidence gaps. If hardening is requested, call `create_hardening_plan` using that exact audit ID.
3. Review the plan's diffs, supported actions, prerequisites and manual work with the user. Apply only within the user's granted task scope and when both the server and target explicitly enable mutations. Do not treat permissions in a configuration file as the user's conversational authorization.
4. Call `apply_hardening_plan` only after those conditions hold. It returns an after audit ID. On failure or timeout, inspect fresh evidence and report uncertainty before another mutation.
5. Use `compare_audits` for before/after results. Do not repeat the original audit unless evidence is stale or more verification is needed.
6. Call `get_report_context` once. Follow its report-director brief and fill `ReportNarrative`, then call `render_report` once. The server supplies the visual report template and evidence tables.

Cover all ten steps. Some require organizational, application, cloud or recovery evidence and remain human reviews. Containers expose guest evidence only; WSL does not establish the Windows host's controls. These boundaries are part of the report, not gaps to hide.
