import copy
import json
import shlex
import subprocess

import pytest
from conftest import change_configuration, tamper
from pydantic import ValidationError

from aegis_mcp import agent
from aegis_mcp.targets import Target, execute
from aegis_mcp.workspace import Workspace


@pytest.mark.parametrize(
    "host", ["-oProxyCommand=touch /tmp/x", "example.com;id", "$(id)", "example.com\nother"]
)
def test_ssh_host_cannot_inject_options_or_commands(host):
    with pytest.raises(ValidationError):
        Target(transport="ssh", host=host, user="auditor")


@pytest.mark.parametrize("name", ["--privileged", "x;id", "$(id)"])
def test_container_name_cannot_inject_options(name):
    with pytest.raises(ValidationError):
        Target(transport="docker", container=name)


def test_unknown_targets_and_evidence_traversal_rejected(engine):
    with pytest.raises(ValueError, match="Unknown target"):
        engine.audit("arbitrary-host")
    with pytest.raises(ValueError, match="identifier"):
        engine.read_audit("../../etc/shadow")


def test_workspace_symlinks_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = tmp_path / "evidence"
    workspace.mkdir()
    (workspace / "reports").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        Workspace(workspace)


def test_snapshot_tampering_rejected(engine):
    audit = engine.audit("test")
    tamper(
        engine.ws.path("audits/" + audit["audit_id"] + ".json"), lambda v: v["summary"].update({"fail": 0})
    )
    with pytest.raises(ValueError, match="integrity"):
        engine.read_audit(audit["audit_id"])


def test_plan_tampering_rejected(engine):
    audit = engine.audit("test")
    plan = engine.plan("test", audit["audit_id"])
    tamper(
        engine.ws.path("plans/" + plan["plan_id"] + ".json"),
        lambda v: v["plan"].update({"actions": ["arbitrary"]}),
    )
    with pytest.raises(ValueError, match="integrity"):
        engine.apply(plan["plan_id"])


def test_both_local_optins_required(engine):
    audit = engine.audit("test")
    plan = engine.plan("test", audit["audit_id"])
    engine.allow_apply = True
    with pytest.raises(PermissionError, match="allow_apply"):
        engine.apply(plan["plan_id"])


def test_changed_target_registration_invalidates_plan(engine):
    change_configuration(engine, allow_apply=True)
    engine.allow_apply = True
    audit = engine.audit("test")
    plan = engine.plan("test", audit["audit_id"])
    change_configuration(engine, owner="Another owner")
    with pytest.raises(ValueError, match="registration changed"):
        engine.apply(plan["plan_id"])


def test_ssh_not_proposed_without_independent_key_access(engine):
    audit = engine.audit("test")
    plan = engine.plan("test", audit["audit_id"])
    assert "ssh" not in plan["actions"]
    assert any("independent key" in message for message in plan["prerequisites"])


def test_root_ssh_manager_cannot_disable_its_own_access(engine):
    change_configuration(
        engine, transport="ssh", host="example.invalid", user="root", ssh_key_access_verified=True
    )
    audit = engine.audit("test")
    plan = engine.plan("test", audit["audit_id"])
    assert "ssh" not in plan["actions"]


def test_host_owned_kernel_controls_excluded_for_wsl(engine, observed, monkeypatch):
    observed["facts"]["wsl"] = True
    monkeypatch.setattr("aegis_mcp.engine.execute", lambda *args, **kwargs: copy.deepcopy(observed))
    audit = engine.audit("test")
    assert all(c["status"] == "not_applicable" for c in audit["checks"] if c["step"] == 6)
    assert "sysctl" not in engine.plan("test", audit["audit_id"])["actions"]


def test_docker_target_has_no_remediation_actions(engine):
    change_configuration(engine, transport="docker", container="existing-app", allow_apply=True)
    engine.allow_apply = True
    audit = engine.audit("test")
    plan = engine.plan("test", audit["audit_id"])
    assert plan["actions"] == []
    with pytest.raises(PermissionError, match="audit-only"):
        engine.apply(plan["plan_id"])


def test_stale_target_evidence_rejected_before_writes(observed, monkeypatch):
    monkeypatch.setattr(agent.os, "geteuid", lambda: 0)
    monkeypatch.setattr(agent, "collect", lambda _: copy.deepcopy(observed))
    with pytest.raises(ValueError, match="changed"):
        agent.apply({}, {"fingerprint": "0" * 64, "actions": ["umask"], "plan_id": "1" * 64})


def test_failed_activation_restores_managed_file(tmp_path, observed, monkeypatch):
    monkeypatch.setattr(agent.os, "geteuid", lambda: 0)
    monkeypatch.setattr(agent, "collect", lambda _: copy.deepcopy(observed))
    original = agent.MARKER + "umask 077\n"
    destination = tmp_path / "etc/profile.d/99-aegis-umask.sh"
    destination.parent.mkdir(parents=True)
    destination.write_text(original)
    observed["managed_files"]["umask"].update({"content": original, "exists": True, "managed": True})
    monkeypatch.setattr(agent, "FILES", {**agent.FILES, "umask": str(destination)})
    real_safe = agent.safe_path

    def private_path(path):
        if str(path).startswith("/var/lib/aegis-mcp"):
            path = tmp_path / str(path).lstrip("/")
        return real_safe(path)

    monkeypatch.setattr(agent, "safe_path", private_path)
    calls = []

    def fail_once(*args):
        calls.append(args)
        if len(calls) == 1:
            raise RuntimeError("Simulated activation failure")

    monkeypatch.setattr(agent, "activate", fail_once)
    with pytest.raises(RuntimeError, match="was restored"):
        agent.apply(
            {}, {"fingerprint": agent.fingerprint(observed), "actions": ["umask"], "plan_id": "1" * 64}
        )
    assert destination.read_text() == original
    assert len(calls) == 2


def test_ssh_uses_strict_host_keys_and_quoted_fixed_python(monkeypatch):
    captured = {}

    def run(argv, **kwargs):
        captured.update({"argv": argv, "kwargs": kwargs})
        return subprocess.CompletedProcess(argv, 0, json.dumps({"facts": {}}), "")

    monkeypatch.setattr("aegis_mcp.targets.subprocess.run", run)
    target = Target(transport="ssh", host="vps.example.invalid", user="auditor")
    execute(target, "collect")
    assert "StrictHostKeyChecking=yes" in captured["argv"]
    assert "BatchMode=yes" in captured["argv"]
    assert not captured["kwargs"].get("shell", False)
    remote = shlex.split(captured["argv"][-1])
    assert remote[:2] == ["python3", "-c"]
    assert json.loads(remote[-1])["operation"] == "collect"


def test_event_chain_detects_modified_detail(engine):
    engine.audit("test")
    path = engine.ws.path("evidence/events.jsonl")
    row = json.loads(path.read_text().splitlines()[0])
    row["detail"]["target_id"] = "modified"
    path.write_text(json.dumps(row) + "\n")
    assert not engine.ws.verify_events()


def test_managed_marker_cannot_launder_secret_text_into_evidence():
    content = agent.MARKER + "API_TOKEN=synthetic-sensitive-value\n"
    assert agent.managed_content("umask", content) is None
    assert agent.managed_content("sysctl", content) is None
    assert agent.managed_content("ssh", content) is None


def test_stricter_existing_umask_is_preserved(engine, observed, monkeypatch):
    observed["umask_defaults"] = ["077"]
    monkeypatch.setattr("aegis_mcp.engine.execute", lambda *args, **kwargs: copy.deepcopy(observed))
    audit = engine.audit("test")
    plan = engine.plan("test", audit["audit_id"])
    assert "umask" not in plan["actions"]
    assert any("stricter" in p for p in plan["prerequisites"])


def test_apply_records_verified_after_evidence_and_rejects_replay(engine, observed, monkeypatch):
    change_configuration(engine, allow_apply=True)
    engine.allow_apply = True
    before = engine.audit("test")
    plan = engine.plan("test", before["audit_id"])
    after = copy.deepcopy(observed)
    after["sysctl"] = agent.SYSCTLS.copy()
    after["managed_files"]["umask"].update(
        {"content": agent.CONTENTS["umask"], "exists": True, "managed": True}
    )
    monkeypatch.setattr(
        "aegis_mcp.engine.execute", lambda *args, **kwargs: {"status": "applied", "observations": after}
    )
    change = engine.apply(plan["plan_id"])
    comparison = engine.compare(before["audit_id"], change["after_audit_id"])
    assert change["status"] == "applied"
    assert comparison["after"]["fail"] < comparison["before"]["fail"]
    assert any(c["before"] == "fail" and c["after"] == "pass" for c in comparison["changes"])
    with pytest.raises(ValueError, match="already been used"):
        engine.apply(plan["plan_id"])
