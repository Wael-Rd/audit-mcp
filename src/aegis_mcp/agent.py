"""Bounded Linux collector/remediator. Sent over stdin; never installed as a daemon.

Invoked ephemerally through the registered adapter; no daemon is installed.
This file uses only the standard library so targets need only Python 3.9+.
"""

import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MARKER = "# Managed by Aegis MCP\n"
SYSCTLS = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
}
FILES = {
    "sysctl": "/etc/sysctl.d/99-aegis.conf",
    "umask": "/etc/profile.d/99-aegis-umask.sh",
    "ssh": "/etc/ssh/sshd_config.d/00-aegis.conf",
}
CONTENTS = {
    "sysctl": MARKER + "".join(k + " = " + v + "\n" for k, v in SYSCTLS.items()),
    "umask": MARKER + "umask 027\n",
    "ssh": MARKER
    + "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n",
}


def managed_content(action, content):
    """Never return arbitrary text from a file that merely claims our marker."""
    if not content or not content.startswith(MARKER):
        return None
    lines = [line.strip() for line in content[len(MARKER) :].splitlines() if line.strip()]
    if action == "umask":
        valid = len(lines) == 1 and re.fullmatch(r"umask [0-7]{3}", lines[0])
    elif action == "sysctl":
        valid = all(
            re.fullmatch(
                r"(?:kernel\.dmesg_restrict|kernel\.kptr_restrict|fs\.protected_hardlinks|fs\.protected_symlinks)\s*=\s*[012]",
                line,
            )
            for line in lines
        )
    else:
        valid = all(
            re.fullmatch(
                r"(?:PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|PubkeyAuthentication) (?:yes|no|prohibit-password)",
                line,
            )
            for line in lines
        )
    return content if valid else None


def command(argv):
    executable = shutil.which(argv[0])
    if executable is None and argv[0] == "sshd" and Path("/usr/sbin/sshd").is_file():
        executable = "/usr/sbin/sshd"
    if executable is None:
        return {"ok": False, "reason": "command_unavailable"}
    try:
        result = subprocess.run(  # noqa: S603 - argv comes from the fixed collector/remediation catalogue
            [executable, *argv[1:]], capture_output=True, text=True, timeout=12, check=False
        )
        return {"ok": result.returncode == 0, "code": result.returncode, "output": result.stdout[:65536]}
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "reason": "command_failed_or_timed_out"}


def text(path, limit=8192):
    try:
        with open(path, encoding="utf-8", errors="replace") as stream:
            return stream.read(limit)
    except OSError:
        return None


def metadata(path):
    try:
        p = Path(path)
        if p.is_symlink():
            return {"path": path, "status": "symlink_requires_review"}
        entry = p.stat()
        return {
            "path": path,
            "status": "observed",
            "mode": oct(stat.S_IMODE(entry.st_mode)),
            "uid": entry.st_uid,
            "gid": entry.st_gid,
            "modified": entry.st_mtime,
            "directory": p.is_dir(),
        }
    except OSError:
        return {"path": path, "status": "unavailable"}


def collect(settings):
    release = text("/etc/os-release") or ""
    os_release = dict(line.split("=", 1) for line in release.splitlines() if "=" in line)
    systemd = Path("/run/systemd/system").is_dir()
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    wsl = "microsoft" in platform.release().lower()
    ssh_result = command(["sshd", "-T"])
    ssh_values = {}
    if ssh_result.get("ok"):
        for line in ssh_result["output"].splitlines():
            key, _, value = line.partition(" ")
            if key in {
                "permitrootlogin",
                "passwordauthentication",
                "kbdinteractiveauthentication",
                "pubkeyauthentication",
                "ciphers",
            }:
                ssh_values[key] = value
    ssh_config = text("/etc/ssh/sshd_config") or ""
    includes_dropins = any(
        re.match(r"^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$", line, re.I)
        for line in ssh_config.splitlines()
    )
    listeners_result = command(["ss", "-H", "-lntu"])
    listeners = []
    if listeners_result.get("ok"):
        for line in listeners_result["output"].splitlines()[:200]:
            columns = line.split()
            if len(columns) >= 5:
                listeners.append({"protocol": columns[0], "address": columns[4]})
    firewall = command(["nft", "list", "ruleset"])
    firewall_info = {
        "available": firewall.get("ok", False),
        "default_drop_indicated": bool(re.search(r"policy\s+drop", firewall.get("output", ""))),
    }
    update_file = Path("/var/lib/apt/periodic/update-success-stamp")
    age = (time.time() - update_file.stat().st_mtime) / 3600 if update_file.exists() else None
    updates = command(["apt", "list", "--upgradable"]) if shutil.which("apt") else {"ok": False}
    update_count = (
        sum("[upgradable from:" in line for line in updates.get("output", "").splitlines())
        if updates.get("ok")
        else None
    )
    periodic = "\n".join(
        text(p) or "" for p in ["/etc/apt/apt.conf.d/20auto-upgrades", "/etc/apt/apt.conf.d/10periodic"]
    )
    automatic = bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', periodic))
    service_states = {}
    for service in ["systemd-journald", "auditd", "rsyslog"]:
        if systemd:
            output = command(["systemctl", "is-active", service])
            service_states[service] = output.get("output", "").strip() or "unknown"
        else:
            service_states[service] = "not_applicable"
    ntp = command(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]) if systemd else {"ok": False}
    values = {key: text("/proc/sys/" + key.replace(".", "/"), 64) for key in SYSCTLS}
    values = {key: value.strip() if value is not None else None for key, value in values.items()}
    managed = {}
    for action, path in FILES.items():
        try:
            safe_path(path)
            content = managed_content(action, text(path))
        except ValueError:
            content = None
        managed[action] = {
            "path": path,
            "content": content,
            "exists": Path(path).exists() or Path(path).is_symlink(),
            "managed": content is not None,
        }
    umask_defaults = []
    for path in ["/etc/login.defs", "/etc/profile"]:
        content = text(path) or ""
        for match in re.finditer(r"^\s*(?:UMASK|umask)\s+0?([0-7]{3})\b", content, re.M):
            umask_defaults.append(match.group(1))
    mounts = text("/proc/mounts", 65536) or ""
    root_source = next(
        (line.split()[0] for line in mounts.splitlines() if len(line.split()) > 1 and line.split()[1] == "/"),
        None,
    )
    # This indicator cannot establish encryption of every confidential volume.
    luks = any((text(p, 256) or "").startswith("CRYPT-LUKS") for p in Path("/sys/block").glob("dm-*/dm/uuid"))
    return {
        "collected_at": time.time(),
        "facts": {
            "os": os_release.get("PRETTY_NAME", "unknown").strip('"'),
            "os_id": os_release.get("ID", "unknown").strip('"'),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "uid": os.geteuid(),
            "systemd": systemd,
            "container": container,
            "wsl": wsl,
            "root_source": root_source,
        },
        "uid_zero": [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == 0],
        "ssh": {
            "available": ssh_result.get("ok", False),
            "effective": ssh_values,
            "dropin_included": includes_dropins,
            "match_rules": bool(re.search(r"^\s*Match\s", ssh_config, re.M)),
        },
        "network": {
            "available": listeners_result.get("ok", False),
            "listeners": listeners,
            "firewall": firewall_info,
        },
        "patches": {
            "available": updates.get("ok", False),
            "metadata_age_hours": age,
            "pending": update_count,
            "automatic_configured": automatic,
        },
        "sysctl": values,
        "managed_files": managed,
        "umask_defaults": umask_defaults,
        "services": service_states,
        "ntp": ntp.get("output", "").strip() if ntp.get("ok") else None,
        "storage": {"luks_indicator": luks},
        "shadow": metadata("/etc/shadow"),
        "sensitive_paths": [metadata(p) for p in settings.get("sensitive_paths", [])],
        "backup_paths": [metadata(p) for p in settings.get("backup_paths", [])],
    }


def fingerprint(observation):
    # Volatile timestamps, sockets and package-cache age do not invalidate an
    # otherwise identical, reviewed plan. Effective SSH/sysctl settings do.
    selected = {k: observation[k] for k in ["sysctl", "managed_files", "ssh"]}
    selected["umask_defaults"] = observation.get("umask_defaults", [])
    return hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()


def safe_path(path):
    path = Path(path)
    for item in [path, *path.parents]:
        if item.is_symlink():
            raise ValueError("Refusing a symlink in a managed configuration path")
    return path


def atomic_write(path, content, mode=0o644):
    path = safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".aegis-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def activate(actions, old_values=None):
    if "sysctl" in actions:
        for key, value in (old_values or SYSCTLS).items():
            if value is not None and not command(["sysctl", "-w", key + "=" + value]).get("ok"):
                raise RuntimeError("Unable to activate kernel baseline")
    if "ssh" in actions:
        if not command(["sshd", "-t"]).get("ok"):
            raise RuntimeError("SSH configuration validation failed")
        if not command(["systemctl", "reload", "ssh"]).get("ok"):
            if not command(["systemctl", "reload", "sshd"]).get("ok"):
                raise RuntimeError("Unable to reload SSH service")


def restore(manifest):
    for action, previous in manifest["files"].items():
        path = safe_path(FILES[action])
        if previous["content"] is None:
            path.unlink(missing_ok=True)
        else:
            atomic_write(path, previous["content"], previous["mode"])
    activate(list(manifest["files"]), manifest["sysctl"])


def apply(settings, request):
    if os.geteuid() != 0:
        raise PermissionError(
            "Hardening requires a root collector; configure local noninteractive sudo access"
        )
    before = collect(settings)
    if before["facts"]["container"]:
        raise ValueError("Container targets are audit-only; remediate the image and host separately")
    if fingerprint(before) != request["fingerprint"]:
        raise ValueError("Target configuration changed; create a fresh plan")
    actions = request["actions"]
    if not actions or any(a not in FILES for a in actions) or len(set(actions)) != len(actions):
        raise ValueError("Unknown or empty remediation action set")
    if "sysctl" in actions and (before["facts"]["wsl"] or any(v is None for v in before["sysctl"].values())):
        raise ValueError("Kernel baseline is unavailable or owned by the WSL host")
    if "umask" in actions and any(int(v, 8) & ~0o027 for v in before.get("umask_defaults", [])):
        raise ValueError("An existing stricter umask must be preserved; review it locally")
    if "ssh" in actions and (
        settings.get("ssh_user") == "root"
        or not settings.get("ssh_key_access_verified")
        or not before["ssh"]["dropin_included"]
        or before["ssh"]["match_rules"]
        or not before["facts"]["systemd"]
    ):
        raise ValueError("SSH prerequisites not satisfied")
    if not re.fullmatch(r"[a-f0-9]{64}", request["plan_id"]):
        raise ValueError("Invalid plan identifier")
    manifest = {"files": {}, "sysctl": before["sysctl"], "plan_id": request["plan_id"]}
    for action in actions:
        path = safe_path(FILES[action])
        content = text(path) if path.exists() else None
        if content is not None and managed_content(action, content) is None:
            raise ValueError("Existing configuration file is not managed by Aegis")
        if path.exists() and path.stat().st_size > 8192:
            raise ValueError("Managed configuration exceeds size limit")
        manifest["files"][action] = {
            "content": content,
            "mode": stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644,
        }
    backup = safe_path("/var/lib/aegis-mcp/" + request["plan_id"])
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(backup.parent, 0o700)
    atomic_write(backup / "manifest.json", json.dumps(manifest), 0o600)
    try:
        for action in actions:
            atomic_write(FILES[action], CONTENTS[action])
        activate(actions)
        after = collect(settings)
        if any(after["managed_files"][action]["content"] != CONTENTS[action] for action in actions):
            raise RuntimeError("Managed configuration did not match the reviewed plan")
        if "sysctl" in actions and after["sysctl"] != SYSCTLS:
            raise RuntimeError("Kernel settings did not take effect")
        if "ssh" in actions and any(
            after["ssh"]["effective"].get(k) != v
            for k, v in {
                "permitrootlogin": "no",
                "passwordauthentication": "no",
                "kbdinteractiveauthentication": "no",
                "pubkeyauthentication": "yes",
            }.items()
        ):
            raise RuntimeError("Effective SSH policy did not match the plan")
        return {
            "status": "applied",
            "backup_id": request["plan_id"],
            "observations": after,
            "activation_note": "Umask applies to new login shells; application services need their own policy.",
        }
    except Exception as error:
        try:
            restore(manifest)
        except Exception:
            raise RuntimeError(
                "Apply failed and rollback was incomplete; inspect the target locally"
            ) from error
        raise RuntimeError("Apply failed; previous managed configuration was restored") from error


def rollback(settings, request):
    if os.geteuid() != 0 or not re.fullmatch(r"[a-f0-9]{64}", request["plan_id"]):
        raise PermissionError("Root and a valid backup identifier are required")
    if collect(settings)["facts"]["container"]:
        raise ValueError("Container targets are audit-only")
    path = safe_path("/var/lib/aegis-mcp/" + request["plan_id"] + "/manifest.json")
    manifest = json.loads(path.read_text())
    if manifest.get("plan_id") != request["plan_id"] or any(a not in FILES for a in manifest["files"]):
        raise ValueError("Invalid backup manifest")
    # Do not erase changes made by an administrator after Aegis applied a plan.
    for action in manifest["files"]:
        if text(FILES[action]) != CONTENTS[action]:
            raise ValueError("Configuration drift detected; automatic rollback refused")
    restore(manifest)
    return {"status": "rolled_back", "observations": collect(settings)}


def main():
    if platform.system() != "Linux":
        raise ValueError("Collector supports Linux; run local Windows targets through WSL")
    request = json.loads(sys.argv[1])
    settings = request.get("settings", {})
    operation = request["operation"]
    if operation == "collect":
        result = collect(settings)
    elif operation == "apply":
        result = apply(settings, request)
    elif operation == "rollback":
        result = rollback(settings, request)
    else:
        raise ValueError("Unknown operation")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        print(json.dumps({"error": str(failure)}))
        sys.exit(1)
