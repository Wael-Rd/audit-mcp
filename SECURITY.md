# Security policy

Aegis is a confidentiality audit preparation tool for systems the operator owns or is authorized to assess. It exposes a fixed collector and remediation catalogue, not a general remote shell. Target addresses and metadata paths are registered locally, outside model arguments.

Default target collection is read-only. Mutations require both server and target opt-ins, root target access and a sealed plan. SSH changes require an independent verified key-login assertion and configuration prerequisites. Supported actions have configuration backups and validation; incomplete rollback is reported explicitly.

Use stdio with a trusted local AI host. HTTP is a trusted-local-client loopback option, not a public authenticated service. Protect your local account, Docker socket, SSH identities, target registry and private evidence directory. Docker socket access itself is highly privileged.

Reports contain operational metadata and should be reviewed before sharing. Do not commit `.runtime/`, target registrations, environment files, provider credentials, SSH keys or target evidence. The repository includes only configuration examples and a clearly marked synthetic design preview.

Local snapshot hashes and event chains do not establish independent evidence custody against an administrator. Narrative safety does not guarantee narrative factual accuracy. An ISO mapping is not a compliance finding or certification claim.

Report suspected defects privately to the repository owner. Include the affected version, minimal reproduction, expected/actual behavior and sanitized evidence. Never include live keys, confidential records or working access tokens in an issue.
