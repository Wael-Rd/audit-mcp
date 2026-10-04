"""Audit snapshots, sealed plans and a fixed remediation catalogue."""

import difflib
import hashlib
import hmac
import os
import re
from pathlib import Path

from .agent import CONTENTS, FILES, fingerprint
from .catalog import STEPS, SUBJECT
from .checks import assess
from .targets import execute, load_targets
from .workspace import Workspace, canonical, digest, now


class Engine:
    def __init__(self, workspace=None, targets_file=None, allow_apply=None):
        self.ws = Workspace(Path(workspace or os.environ.get("AEGIS_WORKSPACE", ".runtime")))
        self.targets_file = targets_file
        self.allow_apply = (
            allow_apply if allow_apply is not None else os.environ.get("AEGIS_ALLOW_APPLY") == "1"
        )

    def targets(self):
        return [
            {
                "id": name,
                "transport": target.transport,
                "description": target.description,
                "classification": target.classification,
                "allow_apply": target.allow_apply and self.allow_apply,
                "capabilities": "audit-only"
                if target.transport == "docker"
                else "audit + bounded remediation",
            }
            for name, target in load_targets(self.targets_file).items()
        ]

    def target(self, name):
        targets = load_targets(self.targets_file)
        if name not in targets:
            raise ValueError("Unknown target ID; register it in the local targets.yaml first")
        return targets[name]

    def _save_audit(self, target_id, target, observed):
        checks, reviews = assess(target, observed)
        counts = {
            status: sum(c["status"] == status for c in checks)
            for status in ["pass", "fail", "unknown", "not_applicable"]
        }
        result = {
            "subject": SUBJECT,
            "at": now(),
            "target_id": target_id,
            "transport": target.transport,
            "owner": target.owner,
            "classification": target.classification,
            "facts": observed["facts"],
            "observations": observed,
            "checks": checks,
            "reviews": reviews,
            "summary": {**counts, "total": len(checks), "human_reviews": len(reviews)},
            "target_config_hash": digest(canonical(target.model_dump())),
            "interpretation": "Technical snapshot, not an ISO compliance score. Unknowns and reviews remain unresolved.",
        }
        audit_id = digest(canonical(result))
        result["audit_id"] = audit_id
        self.ws.write_json("audits/" + audit_id + ".json", result)
        self.ws.event("audit", {"target_id": target_id, "audit_id": audit_id, "summary": counts})
        return result

    def audit(self, target_id):
        target = self.target(target_id)
        observed = execute(target, "collect")
        with self.ws.lock():
            return self._save_audit(target_id, target, observed)

    def _id(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{64}", identifier):
            raise ValueError("Expected a 64-character evidence identifier")
        return identifier

    def read_audit(self, audit_id):
        self.ws.guard()
        result = self.ws.json("audits/" + self._id(audit_id) + ".json")
        content = {key: value for key, value in result.items() if key != "audit_id"}
        if digest(canonical(content)) != audit_id or result.get("audit_id") != audit_id:
            raise ValueError("Audit evidence integrity failed")
        return result

    def _key(self):
        path = self.ws.path(".plan.key")
        if not path.exists():
            self.ws.write(".plan.key", os.urandom(32))
        if path.stat().st_mode & 0o077 or path.stat().st_size != 32:
            raise ValueError("Plan signing key must be private and 32 bytes")
        return path.read_bytes()

    def plan(self, target_id, audit_id):
        target = self.target(target_id)
        audit = self.read_audit(audit_id)
        if audit["target_id"] != target_id or audit["target_config_hash"] != digest(
            canonical(target.model_dump())
        ):
            raise ValueError("Audit does not match the current registered target configuration")
        observed = audit["observations"]
        actions = sorted(
            {c["remediation"] for c in audit["checks"] if c["status"] == "fail" and c["remediation"]}
        )
        prerequisites = []
        if observed["facts"]["container"] or target.transport == "docker":
            actions = []
            prerequisites.append(
                "Container is audit-only. Rebuild its image and harden the host independently."
            )
        if "sysctl" in actions and (
            observed["facts"]["wsl"] or any(v is None for v in observed["sysctl"].values())
        ):
            actions.remove("sysctl")
            prerequisites.append("Kernel settings are inherited or unavailable; assess the owning host.")
        if "umask" in actions and any(int(v, 8) & ~0o027 for v in observed.get("umask_defaults", [])):
            actions.remove("umask")
            prerequisites.append(
                "An existing stricter login umask must be preserved; assess the login configuration locally."
            )
        if "ssh" in actions and (
            target.transport == "ssh"
            and target.user == "root"
            or not target.ssh_key_access_verified
            or not observed["ssh"]["dropin_included"]
            or observed["ssh"]["match_rules"]
            or not observed["facts"]["systemd"]
            or not observed["ssh"]["available"]
        ):
            actions.remove("ssh")
            prerequisites.append(
                "SSH remediation requires a non-root SSH management identity, verified independent key access, effective sshd policy, systemd, an unconditional drop-in Include and no Match block."
            )
        for action in actions.copy():
            entry = observed["managed_files"][action]
            if entry["exists"] and not entry["managed"]:
                actions.remove(action)
                prerequisites.append(
                    f"{FILES[action]} already exists and is not Aegis-managed; review it locally."
                )
        changes = [
            {
                "action": action,
                "path": FILES[action],
                "content": CONTENTS[action],
                "diff": "".join(
                    difflib.unified_diff(
                        (observed["managed_files"][action]["content"] or "").splitlines(True),
                        CONTENTS[action].splitlines(True),
                        fromfile=FILES[action] + " (before)",
                        tofile=FILES[action] + " (proposed)",
                    )
                ),
            }
            for action in actions
        ]
        plan = {
            "target_id": target_id,
            "audit_id": audit_id,
            "at": now(),
            "actions": actions,
            "changes": changes,
            "fingerprint": fingerprint(observed),
            "target_config_hash": audit["target_config_hash"],
            "prerequisites": prerequisites,
            "manual_work": [s for s in STEPS],
            "activation": "Sysctl is activated immediately; SSH is validated and reloaded; umask affects new login shells.",
            "rollback": "Previous managed files and kernel values are backed up under /var/lib/aegis-mcp/<plan_id>.",
        }
        plan_id = digest(canonical(plan))
        plan["plan_id"] = plan_id
        with self.ws.lock():
            seal = hmac.new(self._key(), canonical(plan), hashlib.sha256).hexdigest()
            self.ws.write_json("plans/" + plan_id + ".json", {"plan": plan, "seal": seal})
            self.ws.event("plan", {"target_id": target_id, "plan_id": plan_id, "actions": actions})
        return plan

    def read_plan(self, plan_id):
        self.ws.guard()
        entry = self.ws.json("plans/" + self._id(plan_id) + ".json")
        calculated = hmac.new(self._key(), canonical(entry["plan"]), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated, entry["seal"]) or entry["plan"]["plan_id"] != plan_id:
            raise ValueError("Plan integrity failed")
        return entry["plan"]

    def _mutation(self, plan_id, operation):
        plan = self.read_plan(plan_id)
        target = self.target(plan["target_id"])
        if not self.allow_apply or not target.allow_apply:
            raise PermissionError(
                "Target mutation requires AEGIS_ALLOW_APPLY=1 and allow_apply: true for this registered target"
            )
        if target.transport == "docker":
            raise PermissionError("Docker targets are audit-only")
        if plan["target_config_hash"] != digest(canonical(target.model_dump())):
            raise ValueError("Target registration changed; collect a fresh audit and plan")
        with self.ws.lock():
            if not self.ws.verify_events():
                raise ValueError("Workflow ledger integrity failed")
            record_path = "changes/" + plan_id + ".json"
            existing = self.ws.json(record_path) if self.ws.path(record_path).exists() else None
            if operation == "apply" and existing:
                raise ValueError(
                    "This plan has already been used; collect fresh evidence before another change"
                )
            if operation == "rollback" and (not existing or existing.get("status") != "applied"):
                raise ValueError("No successfully applied change to roll back")
            self.ws.event(operation + "_requested", {"target_id": plan["target_id"], "plan_id": plan_id})
            result = execute(
                target, operation, plan_id=plan_id, fingerprint=plan["fingerprint"], actions=plan["actions"]
            )
            self.ws.write_json(record_path, {"status": result["status"], "at": now(), "plan_id": plan_id})
            after = self._save_audit(plan["target_id"], target, result["observations"])
            self.ws.event(operation + "_completed", {"plan_id": plan_id, "audit_id": after["audit_id"]})
            return {
                "status": result["status"],
                "plan_id": plan_id,
                "after_audit_id": after["audit_id"],
                "summary": after["summary"],
            }

    def apply(self, plan_id):
        return self._mutation(plan_id, "apply")

    def rollback(self, plan_id):
        return self._mutation(plan_id, "rollback")

    def compare(self, before_id, after_id):
        before, after = self.read_audit(before_id), self.read_audit(after_id)
        if (
            before["target_id"] != after["target_id"]
            or before["target_config_hash"] != after["target_config_hash"]
        ):
            raise ValueError("Compare snapshots of the same target registration")
        previous = {c["id"]: c for c in before["checks"]}
        return {
            "target_id": after["target_id"],
            "before": before["summary"],
            "after": after["summary"],
            "changes": [
                {
                    "id": c["id"],
                    "title": c["title"],
                    "before": previous[c["id"]]["status"],
                    "after": c["status"],
                }
                for c in after["checks"]
                if previous[c["id"]]["status"] != c["status"]
            ],
        }

    def report_context(self, audit_id, before_id=None):
        from .reporting import report_context

        audit = self.read_audit(audit_id)
        comparison = self.compare(before_id, audit_id) if before_id else None
        return report_context(audit, comparison)

    def render_report(self, audit_id, before_id=None, narrative=None):
        from .reporting import export_report

        context = self.report_context(audit_id, before_id)
        with self.ws.lock():
            files = export_report(self.ws, context, narrative)
            self.ws.event("report", {"audit_id": audit_id, "files": list(files)})
            return {"status": "exported", "files": files}
