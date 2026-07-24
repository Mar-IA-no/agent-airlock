"""Structural isolation for agent CLIs (bwrap), with an acceptance probe.

The guarantee this module provides is *structural*, not promissory: inside the
jail, the paths you did not mount **do not exist**. That is a stronger claim
than any sandbox flag of the agent itself — and it is testable from inside.

Threat model (be honest about it):

- The jail protects **your filesystem from the agent**. It does NOT protect
  the agent's own credential (the CLI needs it to authenticate) and it does
  NOT close the network (the agent needs its API). Payload hygiene
  (``airlock.scan``) is therefore inseparable from the jail: if you put a
  secret in the prompt, the network is an exfiltration channel.
- Fail-closed: if ``bwrap`` is unavailable, refuse to run. No fallback.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


class JailUnavailable(RuntimeError):
    """bwrap is missing — isolation is fail-closed, there is no fallback."""


@dataclass
class JailSpec:
    """What exists inside the jail. Everything else does not."""
    jail_home: Path                 # HOME inside: only what the CLI needs (auth, config)
    workdir: Path                   # empty cwd for the agent
    results_dir: Path | None = None # optional writable results mount
    network: bool = True            # agents usually need their API
    extra_ro_binds: list[tuple[str, str]] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    HOME_MOUNT = "/jailhome"
    WORK_MOUNT = "/work"
    RESULTS_MOUNT = "/results"


def allowlisted_env(spec: JailSpec) -> dict[str, str]:
    """Environment built from scratch — nothing inherited from the parent."""
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": spec.HOME_MOUNT,
        "TMPDIR": "/tmp",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONNOUSERSITE": "1",
    }
    env.update(spec.env)
    return env


def bwrap_command(spec: JailSpec, argv: list[str]) -> list[str]:
    if shutil.which("bwrap") is None:
        raise JailUnavailable(
            "bwrap not available: isolation is fail-closed, no fallback exists")
    command = [
        "bwrap", "--die-with-parent",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/bin", "/bin",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--bind", str(spec.jail_home), spec.HOME_MOUNT,
        "--ro-bind", str(spec.workdir), spec.WORK_MOUNT,
    ]
    if spec.results_dir is not None:
        command += ["--bind", str(spec.results_dir), spec.RESULTS_MOUNT]
    if spec.network:
        for path in ("/etc/resolv.conf", "/etc/hosts", "/etc/ssl"):
            if Path(path).exists():
                command += ["--ro-bind", path, path]
        # mount/pid/ipc/uts unshared; network intentionally kept.
        command += ["--unshare-pid", "--unshare-ipc", "--unshare-uts"]
    else:
        command += ["--unshare-all"]
    for source, target in spec.extra_ro_binds:
        command += ["--ro-bind", source, target]
    command += ["--chdir", spec.WORK_MOUNT, *argv]
    return command


def run_in_jail(spec: JailSpec, argv: list[str],
                timeout: float | None = None) -> subprocess.CompletedProcess:
    command = bwrap_command(spec, argv)
    return subprocess.run(command, env=allowlisted_env(spec),
                          capture_output=True, text=True, timeout=timeout)


PROBE_SCRIPT = r'''
import json, os, sys
paths = sys.argv[1:]
report = {"paths": [], "canary_env_visible": "AIRLOCK_CANARY" in os.environ}
for raw in paths:
    entry = {"path": raw}
    try:
        os.stat(raw); entry["stat"] = "ACCESSIBLE"
    except OSError:
        entry["stat"] = "denied"
    try:
        open(raw, "r").close(); entry["open"] = "ACCESSIBLE"
    except OSError:
        entry["open"] = "denied"
    report["paths"].append(entry)
report["isolated"] = (not report["canary_env_visible"]) and all(
    e["stat"] == "denied" and e["open"] == "denied" for e in report["paths"])
print(json.dumps(report))
'''


def probe(spec: JailSpec, forbidden_paths: list[str]) -> dict:
    """Acceptance test FROM INSIDE the jail: every forbidden path must not
    exist; the parent's canary env var must not be visible.

    Callers should set AIRLOCK_CANARY in their own environment before calling;
    ``allowlisted_env`` guarantees it is not forwarded.
    """
    os.environ.setdefault("AIRLOCK_CANARY", "secret-that-must-not-pass")
    completed = run_in_jail(
        spec, ["python3", "-c", PROBE_SCRIPT, *forbidden_paths])
    if completed.returncode != 0:
        raise RuntimeError(f"probe failed to run: {completed.stderr[-500:]}")
    import json
    return json.loads(completed.stdout.strip().splitlines()[-1])
