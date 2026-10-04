import copy
import json

import pytest
import yaml

from aegis_mcp.engine import Engine


@pytest.fixture
def observed():
    return {
        "collected_at": 1791000000,
        "facts": {
            "os": "Ubuntu 24.04 LTS",
            "os_id": "ubuntu",
            "kernel": "6.8.0-example",
            "architecture": "x86_64",
            "hostname": "illustrative-system",
            "uid": 0,
            "systemd": True,
            "container": False,
            "wsl": False,
            "root_source": "/dev/vda1",
        },
        "uid_zero": ["root"],
        "ssh": {
            "available": True,
            "effective": {
                "permitrootlogin": "yes",
                "passwordauthentication": "yes",
                "kbdinteractiveauthentication": "no",
                "pubkeyauthentication": "yes",
                "ciphers": "aes256-gcm@openssh.com",
            },
            "dropin_included": True,
            "match_rules": False,
        },
        "network": {
            "available": True,
            "listeners": [{"protocol": "tcp", "address": "0.0.0.0:22"}],
            "firewall": {"available": True, "default_drop_indicated": True},
        },
        "patches": {"available": True, "metadata_age_hours": 1.2, "pending": 0, "automatic_configured": True},
        "sysctl": {
            "kernel.dmesg_restrict": "0",
            "kernel.kptr_restrict": "0",
            "fs.protected_hardlinks": "1",
            "fs.protected_symlinks": "1",
        },
        "managed_files": {
            "sysctl": {
                "path": "/etc/sysctl.d/99-aegis.conf",
                "content": None,
                "exists": False,
                "managed": False,
            },
            "umask": {
                "path": "/etc/profile.d/99-aegis-umask.sh",
                "content": None,
                "exists": False,
                "managed": False,
            },
            "ssh": {
                "path": "/etc/ssh/sshd_config.d/00-aegis.conf",
                "content": None,
                "exists": False,
                "managed": False,
            },
        },
        "services": {"systemd-journald": "active", "auditd": "inactive", "rsyslog": "inactive"},
        "ntp": "yes",
        "storage": {"luks_indicator": False},
        "shadow": {"path": "/etc/shadow", "status": "observed", "mode": "0o640"},
        "sensitive_paths": [{"path": "/srv/private", "status": "observed", "mode": "0o700"}],
        "backup_paths": [{"path": "/srv/backups", "status": "observed", "mode": "0o700"}],
    }


@pytest.fixture
def engine(tmp_path, monkeypatch, observed):
    configuration = tmp_path / "targets.yaml"
    configuration.write_text(
        yaml.safe_dump(
            {
                "targets": {
                    "test": {
                        "transport": "local",
                        "owner": "Example owner",
                        "classification": "confidential",
                        "allow_apply": False,
                    }
                }
            }
        )
    )
    result = Engine(tmp_path / "evidence", configuration, allow_apply=False)
    monkeypatch.setattr("aegis_mcp.engine.execute", lambda *args, **kwargs: copy.deepcopy(observed))
    return result


def change_configuration(engine, **fields):
    path = engine.targets_file
    content = yaml.safe_load(path.read_text())
    content["targets"]["test"].update(fields)
    path.write_text(yaml.safe_dump(content))


def tamper(path, transform):
    value = json.loads(path.read_text())
    transform(value)
    path.write_text(json.dumps(value))
