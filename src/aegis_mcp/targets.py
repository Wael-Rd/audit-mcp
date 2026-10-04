"""Targets are registered by the operator, never chosen by model-supplied addresses."""

import json
import os
import re
import shlex
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    transport: Literal["local", "ssh", "docker"]
    description: str = Field(default="Registered Linux target", max_length=200)
    owner: str = Field(default="Unassigned", max_length=100)
    classification: Literal["public", "internal", "confidential", "restricted", "unclassified"] = (
        "unclassified"
    )
    allow_apply: bool = False
    sudo: bool = False
    host: str | None = None
    user: str | None = None
    port: int = Field(default=22, ge=1, le=65535)
    identity_file: str | None = None
    known_hosts_file: str = "~/.ssh/known_hosts"
    container: str | None = None
    ssh_key_access_verified: bool = False
    sensitive_paths: list[str] = Field(default_factory=list, max_length=20)
    backup_paths: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_target(self):
        if self.transport == "ssh":
            if not self.host or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}", self.host):
                raise ValueError("SSH host must be a plain hostname or IP address")
            if not self.user or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]{0,31}", self.user):
                raise ValueError("Invalid SSH username")
        if self.transport == "docker" and (
            not self.container or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", self.container)
        ):
            raise ValueError("Invalid registered container name")
        for path in [*self.sensitive_paths, *self.backup_paths]:
            if not path.startswith("/") or len(path) > 1024 or any(c in path for c in "\n\r\x00"):
                raise ValueError("Configured metadata paths must be absolute Linux paths")
        return self

    def collector_settings(self):
        return {
            "sensitive_paths": self.sensitive_paths,
            "backup_paths": self.backup_paths,
            "ssh_key_access_verified": self.ssh_key_access_verified,
            "ssh_user": self.user if self.transport == "ssh" else None,
        }


def load_targets(path=None) -> dict[str, Target]:
    config = Path(path or os.environ.get("AEGIS_TARGETS", "targets.yaml")).expanduser()
    if not config.exists():
        return {}
    if config.stat().st_size > 65536:
        raise ValueError("Target configuration exceeds size limit")
    document = yaml.safe_load(config.read_text())
    if (
        not isinstance(document, dict)
        or set(document) != {"targets"}
        or not isinstance(document["targets"], dict)
    ):
        raise ValueError("Expected a targets mapping in the configuration")
    if len(document["targets"]) > 50:
        raise ValueError("At most 50 targets can be registered")
    result = {}
    for name, values in document["targets"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name):
            raise ValueError("Invalid target identifier")
        result[name] = Target.model_validate(values)
    return result


def execute(target: Target, operation: str, **parameters):
    if operation not in {"collect", "apply", "rollback"}:
        raise ValueError("Unsupported collector operation")
    source = files("aegis_mcp").joinpath("agent.py").read_text()
    request = json.dumps({**parameters, "operation": operation, "settings": target.collector_settings()})
    python = ["python3", "-c", source, request]
    if target.sudo:
        python = ["sudo", "-n", "--", *python]
    if target.transport == "local":
        argv = python if target.sudo else [sys.executable, "-c", source, request]
    elif target.transport == "ssh":
        argv = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "UserKnownHostsFile=" + str(Path(target.known_hosts_file).expanduser().absolute()),
            "-p",
            str(target.port),
        ]
        if target.identity_file:
            argv += [
                "-i",
                str(Path(target.identity_file).expanduser().absolute()),
                "-o",
                "IdentitiesOnly=yes",
            ]
        argv += ["--", f"{target.user}@{target.host}", shlex.join(python)]
    else:
        argv = ["docker", "exec", target.container, *python]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603
    except FileNotFoundError as error:
        raise RuntimeError(f"{target.transport} transport executable is unavailable") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Collector timed out; inspect the target before retrying a change") from error
    if len(result.stdout) > 1048576:
        raise ValueError("Collector output exceeds the evidence limit")
    try:
        observed = json.loads(result.stdout)
    except ValueError as error:
        raise RuntimeError(
            "Collector returned no valid evidence. Check connectivity, Python 3 and permissions."
        ) from error
    if result.returncode != 0 or "error" in observed:
        raise RuntimeError(observed.get("error", "Collector failed; check target access locally"))
    return observed
