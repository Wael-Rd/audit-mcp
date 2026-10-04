# Target collection and hardening boundaries

The guide covers ten domains. Automation covers only fixed changes whose effects can be validated without knowing your application architecture. A report always retains the remaining review work.

## Collector

The target needs Python 3.9+ and Linux. Aegis sends an embedded standard-library script through `python3 -c`; it does not install a target service. The local adapter uses the server's interpreter, SSH uses strict known-host checking and batch mode, and Docker uses `docker exec` on an existing registered container.

Collection reads OS metadata, selected effective SSH settings, listening socket addresses, a firewall indicator, cached APT status, selected kernel values, logging-service state and metadata for operator-configured data/backup paths. Password hashes, keys, tokens and confidential file contents are not read. Missing commands, permissions or evidence remain unknown. Some host-owned controls are not applicable inside WSL or containers.

The collector never runs `apt update`, upgrades packages, probes external services or modifies the target during an audit. APT status without recent metadata is unknown. A firewall drop indicator does not prove complete filtering. A LUKS indicator does not prove protection of every data volume. Backup path metadata does not prove encryption or recovery.

## Reviewable changes

`create_hardening_plan` links an audit snapshot to a registered target and supplies exact diffs. Plans are HMAC sealed with a private workspace key. Target registration changes, modified plans and stale effective settings are rejected before a change. The plan includes manual work for all ten domains.

To enable mutations, set `AEGIS_ALLOW_APPLY=1` for the server and `allow_apply: true` for the target **before collecting the audit and creating the plan**. The target collector must run as root; local/SSH `sudo: true` uses `sudo -n`. Do not run the MCP host itself as root or provide unrestricted shell tools to a model just to use Aegis.

## Automatic actions

| Action | Files and activation | Preconditions / limits |
| --- | --- | --- |
| Kernel baseline | `/etc/sysctl.d/99-aegis.conf`; activate four exact sysctl values | Linux host, all keys available; excluded for WSL/container targets |
| Login-shell umask | `/etc/profile.d/99-aegis-umask.sh`; `umask 027` | New login shells only; no recursive chmod or application/service policy changes |
| SSH policy | `/etc/ssh/sshd_config.d/00-aegis.conf`; validate `sshd -t`, check effective policy, reload SSH | Non-root SSH management identity, systemd, working independent key-authenticated admin session, unconditional drop-in Include, effective policy available, no main-file Match block |

The operator must set `ssh_key_access_verified: true` only after verifying a separate working key login. This flag is an operator assertion; Aegis cannot prove another session exists. Included SSH configurations can contain additional conditional rules, so assess them independently. Never use a root SSH management identity to disable root SSH access. SSH changes and reloads can affect later logins; have console access and a recovery method.

Aegis refuses to overwrite files at these paths unless their contents match the bounded syntax of its managed configuration. It rejects symlinks in mutation paths and preserves a stricter umask detected in the login configuration. Container targets remain audit-only because guest writes are ephemeral and kernel/network protection belongs partly to the host.

## Backup, failure and rollback

Before applying, the collector stores previous managed file contents, modes and kernel values under `/var/lib/aegis-mcp/<plan_id>/manifest.json`. This is a **configuration rollback snapshot**, not an application data backup.

Failed activation triggers an attempt to restore the prior state. If restoration fails, the tool explicitly reports incomplete rollback. A disconnected or timed-out SSH session leaves the result uncertain: reconnect, collect fresh evidence and inspect target state before retrying.

`rollback_hardening_plan` requires a successful local change record and refuses to overwrite managed files modified since the apply. It restores saved files and kernel values, then validates/reloads SSH when applicable. It does not restore arbitrary data, packages or cloud settings.

## Recommended operator sequence

1. Register the target and confirm access.
2. Collect evidence and inspect the findings.
3. Review the plan, prerequisites and exact changes.
4. Apply within the user's authorized task scope.
5. Compare the after snapshot and preserve recovery records.
6. Generate the report and assign the remaining manual work.
