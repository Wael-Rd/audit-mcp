"""Original audit guidance; ISO identifiers are suggested mappings, not normative text."""

SUBJECT = (
    "Summary of a Ten-Step Best-Practice Guide to the Hardening Process of an Information System "
    "in Preparation for a Confidentiality Audit"
)

STEPS = [
    {
        "id": 1,
        "title": "Scope, inventory and classify",
        "tag": "SCOPE",
        "controls": ["A.5.9", "A.5.12", "A.5.13"],
        "clauses": ["4.3", "6.1.2"],
        "risk": "Unknown assets and unclassified information escape protection.",
        "action": "Identify the target OS, environment, owner, sensitive paths and confidentiality boundary.",
        "review": "Approve the ISMS scope, inventory, classification and asset ownership.",
    },
    {
        "id": 2,
        "title": "Maintain a patched baseline",
        "tag": "BASELINE",
        "controls": ["A.8.8", "A.8.9"],
        "clauses": ["6.1.3"],
        "risk": "Unpatched packages and configuration drift preserve known weaknesses.",
        "action": "Inspect package metadata and automatic update settings; propose a tested maintenance window.",
        "review": "Refresh package metadata, scan vulnerabilities, approve patch SLAs and test rollback.",
    },
    {
        "id": 3,
        "title": "Constrain identities and access",
        "tag": "IDENTITY",
        "controls": ["A.5.15", "A.5.16", "A.5.18", "A.8.2", "A.8.5"],
        "clauses": ["6.1.3"],
        "risk": "Shared privileged accounts and weak authentication expose confidential data.",
        "action": "Review UID-zero accounts and effective SSH policy; optionally deploy validated key-only SSH settings.",
        "review": "Verify an independent key-authenticated login before changing SSH; review MFA and account lifecycle.",
    },
    {
        "id": 4,
        "title": "Separate network trust zones",
        "tag": "NETWORK",
        "controls": ["A.8.20", "A.8.21", "A.8.22"],
        "clauses": ["6.1.3"],
        "risk": "Unnecessary listeners and permissive network boundaries permit unwanted access.",
        "action": "Inventory listening sockets and locally visible firewall policy without sending network probes.",
        "review": "Review cloud security groups, Docker host policies, management access and egress filtering.",
    },
    {
        "id": 5,
        "title": "Protect cryptography and keys",
        "tag": "ENCRYPTION",
        "controls": ["A.8.24", "A.5.17"],
        "clauses": ["6.1.3"],
        "risk": "Cleartext transport, storage or exposed keys reveal sensitive information.",
        "action": "Inspect effective SSH cipher policy and available storage-encryption indicators.",
        "review": "Verify application TLS, certificate lifecycle, encryption of all confidential volumes and independent key custody.",
    },
    {
        "id": 6,
        "title": "Reduce system attack surface",
        "tag": "SYSTEM",
        "controls": ["A.8.9", "A.8.19", "A.8.27"],
        "clauses": ["6.1.3"],
        "risk": "Kernel information leaks and avoidable privileges increase compromise impact.",
        "action": "Inspect a bounded kernel baseline; apply supported information-disclosure and link-protection settings.",
        "review": "Review service privilege, container capabilities, host kernel and hypervisor configuration.",
    },
    {
        "id": 7,
        "title": "Minimize data exposure",
        "tag": "DATA",
        "controls": ["A.8.3", "A.8.11", "A.8.12", "A.5.34"],
        "clauses": ["6.1.3"],
        "risk": "Broad file permissions and permissive defaults disclose confidential records.",
        "action": "Inspect metadata of configured sensitive paths and shadow-file permissions; install a restrictive login-shell umask.",
        "review": "Test application authorization, retention, masking, export controls and DLP independently.",
    },
    {
        "id": 8,
        "title": "Observe and investigate access",
        "tag": "MONITORING",
        "controls": ["A.8.15", "A.8.16", "A.8.17"],
        "clauses": ["9.1"],
        "risk": "Missing logs, alerts or synchronized clocks prevent reliable investigation.",
        "action": "Observe local logging services and time-synchronization status; preserve a local workflow evidence chain.",
        "review": "Validate remote log custody, confidentiality of logs, alert coverage and incident escalation.",
    },
    {
        "id": 9,
        "title": "Secure backups and prove recovery",
        "tag": "RECOVERY",
        "controls": ["A.8.13", "A.5.30"],
        "clauses": ["8.1"],
        "risk": "A stolen backup reveals data; an untested copy may not restore.",
        "action": "Inspect the metadata of explicitly configured backup paths and document recovery evidence gaps.",
        "review": "Verify backup encryption, separate keys, offsite custody, RPO/RTO and a real restore exercise.",
    },
    {
        "id": 10,
        "title": "Validate and build the audit dossier",
        "tag": "EVIDENCE",
        "controls": ["A.5.35", "A.5.36", "A.8.32"],
        "clauses": ["7.5", "9.2", "10.2"],
        "risk": "Presentation quality can obscure missing evidence and residual risk.",
        "action": "Compare immutable audit snapshots, verify changes and create a traceable English HTML/Markdown dossier.",
        "review": "Independently approve applicability, risk treatment, evidence sufficiency and corrective actions. Technical checks are not certification.",
    },
]

SOURCES = [
    {"title": "ISO/IEC 27001:2022 — ISMS requirements", "url": "https://www.iso.org/standard/27001"},
    {"title": "ISO/IEC 27002:2022 — control guidance", "url": "https://www.iso.org/standard/75652.html"},
    {"title": "Official MCP Python SDK", "url": "https://github.com/modelcontextprotocol/python-sdk"},
    {
        "title": "MCP transport specification",
        "url": "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports",
    },
]
