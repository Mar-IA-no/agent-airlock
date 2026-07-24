"""Two-commit approved-sources protocol, without self-reference.

Problem: a versioned manifest cannot contain the hash of the very commit that
contains it (bootstrap). Solution:

- **Commit A** freezes the code and assets that assemble what you send.
- **Commit B** adds ONLY the manifest, which references A and pins the sha256
  of every dependency as of A.
- The verifier identifies B **structurally**: HEAD must be a commit whose only
  diff against A is the manifest itself, with a clean worktree. Any later
  commit invalidates the pair — evolution requires a new A/B.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(repo: Path, approved: dict, approved_relpath: str) -> str:
    """Verify the trust root; returns HEAD (== commit B) on success."""
    head = _git(repo, "rev-parse", "HEAD")
    if _git(repo, "status", "--porcelain"):
        raise RuntimeError("dirty worktree: export requires a clean tree")
    commit_a = approved["commit_a"]
    changed = [line for line in _git(repo, "diff", "--name-only",
                                      commit_a, head).splitlines() if line]
    if changed != [approved_relpath]:
        raise RuntimeError(
            f"HEAD is not a valid commit B: diff against A must be exactly "
            f"[{approved_relpath}], got {changed}; evolution requires a new A/B pair")
    for entry in approved["files"]:
        path = repo / entry["path"]
        if not path.is_file():
            raise RuntimeError(f"approved source missing: {entry['path']}")
        if _sha256_file(path) != entry["sha256"]:
            raise RuntimeError(f"blob differs from commit A: {entry['path']}")
    return head


def build_manifest(repo: Path, files: list[str], extra: dict | None = None) -> dict:
    """Build the approved-sources dict for the CURRENT HEAD (to be commit A)."""
    manifest = {
        "approved_version": "agent-airlock-trustroot-v0.1",
        "commit_a": _git(repo, "rev-parse", "HEAD"),
        "files": [{"path": f, "sha256": _sha256_file(repo / f)} for f in files],
    }
    if extra:
        manifest.update(extra)
    return manifest
