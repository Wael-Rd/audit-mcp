"""Check publishable files for accidental credentials or runtime artifacts."""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{25,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
]
PRIVATE = {"targets.yaml", "targets.yml", ".env"}


def main():
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S603,S607
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        print("Initialize the local Git repository before the publication check.", file=sys.stderr)
        return 1
    findings = []
    names = set(name for name in result.stdout.decode().split("\0") if name)
    for name in sorted(names):
        path = ROOT / name
        if (
            name.split("/")[0] in {".runtime", ".venv"}
            or path.name in PRIVATE
            or path.suffix in {".key", ".pem"}
        ):
            findings.append(name + ": private runtime/configuration artifact")
            continue
        if not path.is_file() or path.is_symlink():
            continue
        try:
            content = path.read_text()
        except UnicodeDecodeError:
            continue
        if any(pattern.search(content) for pattern in PATTERNS):
            findings.append(name + ": possible credential material (value redacted)")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"Checked {len(names)} publishable files: no matching credentials or private runtime artifacts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
