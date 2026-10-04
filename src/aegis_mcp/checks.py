"""Assess observed facts without turning missing or inherited evidence into passes."""

from .agent import FILES, SYSCTLS
from .catalog import STEPS


def assess(target, observed):
    rows = []

    def add(step, title, condition, source, detail, remediation=None, severity="medium", na=False):
        status = (
            "not_applicable" if na else "unknown" if condition is None else "pass" if condition else "fail"
        )
        rows.append(
            {
                "id": f"C{len(rows) + 1:02}",
                "step": step,
                "title": title,
                "status": status,
                "severity": severity if status == "fail" else "info",
                "source": source,
                "observation": detail,
                "remediation": remediation,
                "controls": STEPS[step - 1]["controls"],
                "evidence_kind": "target_observation",
            }
        )

    facts = observed["facts"]
    container = facts["container"] or target.transport == "docker"
    host_owned = container or facts["wsl"]
    add(
        1,
        "Operating system identified",
        facts["os"] != "unknown",
        "/etc/os-release",
        f"{facts['os']}; {facts['architecture']}; kernel {facts['kernel']}",
    )
    add(
        1,
        "Owner and classification recorded",
        target.owner != "Unassigned" and target.classification != "unclassified",
        "Operator target configuration",
        f"Owner: {target.owner}; classification: {target.classification}. Operator statements need scope approval.",
    )
    patches = observed["patches"]
    fresh = patches["metadata_age_hours"] is not None and patches["metadata_age_hours"] <= 24
    add(
        2,
        "No pending packages in fresh metadata",
        patches["pending"] == 0 if patches["available"] and fresh else None,
        "APT cached package metadata",
        f"Pending: {patches['pending']}; metadata age hours: {patches['metadata_age_hours']}. No package refresh or vulnerability scan was performed.",
    )
    add(
        2,
        "Automatic security updates configured",
        patches["automatic_configured"] if facts["os_id"] in {"ubuntu", "debian"} else None,
        "APT periodic configuration",
        "Configuration indicator only; validate the update service and maintenance policy.",
        na=container,
    )
    add(
        3,
        "Single expected UID-zero account",
        observed["uid_zero"] == ["root"],
        "System account database",
        "UID-zero accounts: " + ", ".join(observed["uid_zero"]),
        severity="high",
    )
    ssh = observed["ssh"]
    effective = ssh["effective"]
    add(
        3,
        "Direct SSH root login disabled",
        effective.get("permitrootlogin") == "no" if ssh["available"] else None,
        "sshd -T",
        "Observed PermitRootLogin: " + effective.get("permitrootlogin", "unavailable"),
        "ssh",
        "high",
        na=container and not ssh["available"],
    )
    key_only = (
        effective.get("passwordauthentication") == "no"
        and effective.get("kbdinteractiveauthentication") == "no"
        and effective.get("pubkeyauthentication") == "yes"
    )
    add(
        3,
        "Key-only SSH policy",
        key_only if ssh["available"] else None,
        "sshd -T",
        "Requires PasswordAuthentication=no, KbdInteractiveAuthentication=no, PubkeyAuthentication=yes. Match blocks need independent validation.",
        "ssh",
        "high",
        na=container and not ssh["available"],
    )
    net = observed["network"]
    wildcard = [row for row in net["listeners"] if row["address"].startswith(("0.0.0.0:", "[::]:", "*:"))]
    add(
        4,
        "No wildcard listeners",
        not wildcard if net["available"] else None,
        "ss -H -lntu",
        f"Wildcard listeners: {len(wildcard)}. This conservative finding requires an intentional-service review; a public listener is not itself an exploit.",
    )
    firewall = net["firewall"]
    add(
        4,
        "Default-drop firewall indicator",
        firewall["default_drop_indicated"] if firewall["available"] else None,
        "nft list ruleset",
        "An observed drop policy is only an indicator; traffic coverage, cloud firewalls and Docker rules require review.",
        na=host_owned,
    )
    ciphers = effective.get("ciphers")
    weak = ("cbc", "3des", "arcfour")
    add(
        5,
        "Legacy SSH ciphers absent",
        not any(term in ciphers for term in weak) if ciphers else None,
        "sshd -T",
        "Effective SSH cipher list checked for legacy CBC/3DES/RC4 indicators.",
        na=container and not ssh["available"],
    )
    add(
        5,
        "Encrypted-storage coverage",
        None,
        "Storage indicators + human review",
        f"LUKS device indicator: {observed['storage']['luks_indicator']}. This does not prove encryption of the root volume or all confidential paths.",
    )
    for key, expected in SYSCTLS.items():
        actual = observed["sysctl"].get(key)
        add(
            6,
            key,
            actual == expected if actual is not None else None,
            "/proc/sys/" + key.replace(".", "/"),
            f"Observed {actual}; baseline {expected}. Host-owned settings are excluded for containers and WSL.",
            "sysctl",
            na=host_owned,
        )
    shadow = observed["shadow"]
    add(
        7,
        "Shadow file not world accessible",
        int(shadow["mode"], 8) & 0o007 == 0 if shadow["status"] == "observed" else None,
        "/etc/shadow metadata",
        "Checks mode bits only; never reads password hashes.",
        severity="high",
    )
    paths = observed["sensitive_paths"]
    available = paths and all(p["status"] == "observed" for p in paths)
    add(
        7,
        "Configured confidential paths restrict other users",
        all(int(p["mode"], 8) & 0o007 == 0 for p in paths) if available else None,
        "Configured path metadata",
        f"{len(paths)} configured path(s). ACLs, parent permissions and recursive descendants require separate review.",
        severity="high",
    )
    umask = observed["managed_files"]["umask"]
    configured_umask = int(umask["content"].split()[-1], 8) if umask["content"] else None
    add(
        7,
        "Managed login-shell umask configured",
        configured_umask & 0o027 == 0o027 if configured_umask is not None else False,
        FILES["umask"],
        "Aegis drop-in sets umask 027 or stricter for new login shells. It does not prove the umask of existing processes.",
        "umask",
    )
    add(
        8,
        "Local logging service active",
        any(state == "active" for state in observed["services"].values()) if facts["systemd"] else None,
        "systemctl is-active",
        str(observed["services"]),
        na=not facts["systemd"],
    )
    add(
        8,
        "System clock synchronization reported",
        observed["ntp"] == "yes" if observed["ntp"] is not None else None,
        "timedatectl NTPSynchronized",
        "Inherited time and external synchronization require review in containers and WSL.",
        na=host_owned,
    )
    backups = observed["backup_paths"]
    backup_ready = backups and all(p["status"] == "observed" for p in backups)
    add(
        9,
        "Configured backup paths restrict other users",
        all(int(p["mode"], 8) & 0o007 == 0 for p in backups) if backup_ready else None,
        "Configured backup path metadata",
        f"{len(backups)} configured backup path(s). Existence and permissions do not prove encryption or a successful restore.",
        severity="high",
    )
    add(
        9,
        "Recovery exercise and backup encryption proven",
        None,
        "Human review",
        "Provide independently verified restore evidence, backup encryption details, RPO/RTO and key custody.",
    )
    add(
        10,
        "Target evidence collected",
        True,
        "Bounded collector",
        "Timestamped snapshot collected; integrity is checked when it is loaded from the evidence store.",
    )
    reviews = [
        {
            "id": f"M{s['id']:02}",
            "step": s["id"],
            "status": "review",
            "observation": s["review"],
            "evidence_kind": "human_review_required",
        }
        for s in STEPS
    ]
    return rows, reviews
