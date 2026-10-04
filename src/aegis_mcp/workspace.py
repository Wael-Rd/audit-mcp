"""Private managed workspace, atomic writes and local integrity evidence."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from filelock import FileLock


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Workspace:
    def __init__(self, root: Path):
        self.root = root.expanduser().absolute()
        if self.root == Path(self.root.anchor) or self.root == Path.home():
            raise ValueError("Use a dedicated evidence directory")
        self.guard()

    def guard(self):
        for path in [*self.root.parents, self.root]:
            if path.is_symlink():
                raise ValueError("Workspace symlinks are not allowed")
        if self.root.exists():
            if not self.root.is_dir():
                raise ValueError("Workspace must be a directory")
            # Evidence is kept in a dedicated private workspace.
            for path in self.root.rglob("*"):
                if path.is_symlink():
                    raise ValueError("Workspace symlinks are not allowed")

    def lock(self):
        self.guard()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        return FileLock(str(self.root / ".lock"), timeout=30)

    def path(self, relative: str) -> Path:
        path = self.root / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("Path must stay inside the evidence workspace")
        for parent in [path, *path.parents]:
            if parent.is_symlink():
                raise ValueError("Workspace symlinks are not allowed")
            if parent == self.root:
                break
        return path

    def write(self, relative: str, content: bytes, mode=0o600):
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_name(path.name + ".tmp")
        if temporary.exists():
            raise ValueError("Unexpected temporary file; inspect the workspace")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def json(self, relative: str):
        return json.loads(self.path(relative).read_text())

    def write_json(self, relative: str, value):
        self.write(relative, json.dumps(value, indent=2).encode())

    def hashes(self, names):
        return {name: digest(self.path(name).read_bytes()) for name in sorted(names)}

    def event(self, action: str, detail: dict):
        if not self.verify_events():
            raise ValueError("Event ledger integrity failed; inspect before continuing")
        path = self.path("evidence/events.jsonl")
        previous = "0" * 64
        lines = path.read_text().splitlines() if path.exists() else []
        if lines:
            previous = json.loads(lines[-1])["hash"]
        event = {"at": now(), "action": action, "detail": detail, "previous": previous}
        event["hash"] = digest(canonical(event))
        self.write("evidence/events.jsonl", ("\n".join([*lines, json.dumps(event)]) + "\n").encode())

    def verify_events(self):
        path = self.path("evidence/events.jsonl")
        previous = "0" * 64
        try:
            for line in path.read_text().splitlines() if path.exists() else []:
                event = json.loads(line)
                claimed = event.pop("hash")
                if event["previous"] != previous or digest(canonical(event)) != claimed:
                    return False
                previous = claimed
            return True
        except (ValueError, KeyError, TypeError):
            return False
