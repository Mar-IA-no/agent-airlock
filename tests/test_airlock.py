"""Tests for the five airlock components (offline; jail tests need bwrap)."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from airlock import blindpack, jail, scan, transport, trustroot  # noqa: E402


# --- jail -------------------------------------------------------------------

needs_bwrap = pytest.mark.skipif(shutil.which("bwrap") is None,
                                 reason="bwrap unavailable (fail-closed)")


@needs_bwrap
def test_probe_forbidden_paths_do_not_exist(tmp_path):
    home = tmp_path / "home"; home.mkdir()
    work = tmp_path / "work"; work.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("must not be readable", encoding="utf-8")
    spec = jail.JailSpec(jail_home=home, workdir=work, network=False)
    report = jail.probe(spec, [str(secret), "/root", str(Path.cwd())])
    assert report["isolated"] is True
    assert report["canary_env_visible"] is False


@needs_bwrap
def test_jail_mounts_only_whitelisted(tmp_path):
    home = tmp_path / "home"; home.mkdir()
    work = tmp_path / "work"; work.mkdir()
    (work / "visible.txt").write_text("ok", encoding="utf-8")
    spec = jail.JailSpec(jail_home=home, workdir=work, network=False)
    completed = jail.run_in_jail(spec, ["python3", "-c",
                                         "import os; print(sorted(os.listdir('.')))"])
    assert completed.returncode == 0
    assert "visible.txt" in completed.stdout


def test_jail_fail_closed_without_bwrap(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    spec = jail.JailSpec(jail_home=tmp_path, workdir=tmp_path)
    with pytest.raises(jail.JailUnavailable):
        jail.bwrap_command(spec, ["true"])


# --- transport --------------------------------------------------------------

def _request_builder(case_id):
    return {"case_id": case_id, "prompt": f"hello {case_id}",
            "model": "test-model", "effort": "high"}


def test_transport_roundtrip(tmp_path):
    out = tmp_path / "run"
    summary = transport.export_requests(["C1", "C2"], _request_builder,
                                        None, out, run_scope="full")
    assert summary["exported"] == ["C1", "C2"]
    responses = tmp_path / "responses"; responses.mkdir()
    for cid in ("C1", "C2"):
        req = json.loads((out / "requests" / f"{cid}.json").read_text())
        (responses / f"{cid}.json").write_text(json.dumps({
            "case_id": cid, "request_sha256": req["request_sha256"],
            "response": "answer"}), encoding="utf-8")
    result = transport.import_responses(out / "requests", responses,
                                        out / "RUN_MANIFEST.json",
                                        out / "outputs.json",
                                        metadata={"arm_id": "demo"})
    assert result == {"imported": 2, "correlation": "operator_attestation"}


def test_transport_rejects_uncorrelated_and_missing(tmp_path):
    out = tmp_path / "run"
    transport.export_requests(["C1"], _request_builder, None, out)
    responses = tmp_path / "responses"; responses.mkdir()
    (responses / "C1.json").write_text(json.dumps({
        "case_id": "C1", "request_sha256": "0" * 64, "response": "x"}),
        encoding="utf-8")
    with pytest.raises(RuntimeError, match="correlate"):
        transport.import_responses(out / "requests", responses,
                                   out / "RUN_MANIFEST.json", out / "o.json")
    (responses / "C1.json").unlink()
    with pytest.raises(RuntimeError, match="missing"):
        transport.import_responses(out / "requests", responses,
                                   out / "RUN_MANIFEST.json", out / "o.json")


def test_pre_send_check_aborts_export(tmp_path):
    with pytest.raises(RuntimeError, match="pre-send"):
        transport.export_requests(["C1"], _request_builder,
                                  lambda cid, req: ["leak!"], tmp_path / "run")


def test_hash_covers_full_config():
    base = _request_builder("C1")
    assert transport.request_sha256(base) != transport.request_sha256(
        dict(base, effort="low"))


# --- trustroot --------------------------------------------------------------

def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def _make_pair(tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t"); _git(repo, "config", "user.name", "t")
    (repo / "asset.txt").write_text("frozen", encoding="utf-8")
    _git(repo, "add", "-A"); _git(repo, "commit", "-qm", "A")
    approved = trustroot.build_manifest(repo, ["asset.txt"])
    (repo / "approved.json").write_text(json.dumps(approved), encoding="utf-8")
    _git(repo, "add", "-A"); _git(repo, "commit", "-qm", "B")
    return repo, approved


def test_trustroot_accepts_valid_pair(tmp_path):
    repo, approved = _make_pair(tmp_path)
    head = trustroot.verify(repo, approved, "approved.json")
    assert len(head) == 40


def test_trustroot_rejects_commit_c(tmp_path):
    repo, approved = _make_pair(tmp_path)
    (repo / "later.txt").write_text("C", encoding="utf-8")
    _git(repo, "add", "-A"); _git(repo, "commit", "-qm", "C")
    with pytest.raises(RuntimeError, match="new A/B pair"):
        trustroot.verify(repo, approved, "approved.json")


def test_trustroot_rejects_dirty_tree(tmp_path):
    repo, approved = _make_pair(tmp_path)
    (repo / "asset.txt").write_text("tampered", encoding="utf-8")
    with pytest.raises(RuntimeError, match="dirty"):
        trustroot.verify(repo, approved, "approved.json")


# --- scan -------------------------------------------------------------------

def test_scan_authorized_values_are_excluded():
    deny = scan.build_denyset(
        prose_fields=["This sentence is definitely long enough to match."],
        distinctive_values=[{"k": "authorized-projection-value"}],
        authorized_values=[{"k": "authorized-projection-value"}])
    assert not any("authorized" in d for d in deny)
    assert scan.scan("clean prompt", deny) == []


def test_scan_catches_normalized_prose():
    deny = scan.build_denyset(["The hidden rubric prose, quite long indeed."], [])
    assert scan.scan("...THE HIDDEN   rubric prose  quite long indeed!!!...", deny)


def test_scan_ignores_atomic_tokens():
    assert scan.distinctive("INT02") is None
    assert scan.distinctive("speak") is None


# --- blindpack --------------------------------------------------------------

def _outputs(tmp_path, arm_id, text):
    path = tmp_path / f"{arm_id}.json"
    path.write_text(json.dumps({"arm_id": arm_id, "rows": [
        {"case_id": "C1", "response": f"{text} one"},
        {"case_id": "C2", "response": f"{text} two"}]}), encoding="utf-8")
    return path


def test_blindpack_structural_blinding(tmp_path):
    prereg = tmp_path / "prereg.json"
    prereg.write_text(json.dumps({"arm_ids": ["x", "y"], "case_ids": ["C1", "C2"],
                                   "missing_comparator_policy": "abort"}),
                      encoding="utf-8")
    out = tmp_path / "pack"
    summary = blindpack.build(prereg, {"x": _outputs(tmp_path, "x", "left"),
                                        "y": _outputs(tmp_path, "y", "right")},
                              out, instructions="Score 0-3.")
    assert summary["cases"] == 2
    for path in (out / "blind").glob("*.json"):
        if path.name == "DELIVERABLE_MANIFEST.json":
            assert "BLIND_KEY" not in path.read_text(encoding="utf-8")
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert set(doc) <= blindpack.ALLOWED_BLIND_KEYS
    key = json.loads((out / "sealed/BLIND_KEY.json").read_text())
    assert set(key["assignments"]) == {"C1", "C2"}


def test_blindpack_aborts_on_missing_comparator(tmp_path):
    prereg = tmp_path / "prereg.json"
    prereg.write_text(json.dumps({"arm_ids": ["x", "y"], "case_ids": ["C1"],
                                   "missing_comparator_policy": "abort"}),
                      encoding="utf-8")
    with pytest.raises(RuntimeError, match="missing comparators"):
        blindpack.build(prereg, {"x": _outputs(tmp_path, "x", "l")},
                        tmp_path / "pack", instructions="i")


def test_blindpack_rejects_extra_arm(tmp_path):
    prereg = tmp_path / "prereg.json"
    prereg.write_text(json.dumps({"arm_ids": ["x"], "case_ids": ["C1"],
                                   "missing_comparator_policy": "abort"}),
                      encoding="utf-8")
    with pytest.raises(RuntimeError, match="non-preregistered"):
        blindpack.build(prereg, {"x": _outputs(tmp_path, "x", "l"),
                                  "sneaky": _outputs(tmp_path, "sneaky", "s")},
                        tmp_path / "pack", instructions="i")


def test_blindpack_case_context_included(tmp_path):
    prereg = tmp_path / "prereg.json"
    prereg.write_text(json.dumps({"arm_ids": ["x"], "case_ids": ["C1", "C2"],
                                   "missing_comparator_policy": "abort"}),
                      encoding="utf-8")
    out = tmp_path / "pack"
    blindpack.build(prereg, {"x": _outputs(tmp_path, "x", "l")}, out,
                    instructions="i",
                    case_context=lambda cid: {"context": [f"turn for {cid}"],
                                               "rubric": {"why": "because"}})
    doc = json.loads((out / "blind/C1.json").read_text(encoding="utf-8"))
    assert doc["context"] == ["turn for C1"] and doc["rubric"]["why"] == "because"
    assert set(doc) <= blindpack.ALLOWED_BLIND_KEYS


# --- lessons learned in production use (2026-07) -----------------------------

def test_structured_leak_is_caught_in_both_key_orders():
    """A denyset built only from sorted-keys JSON misses a leak serialized in
    insertion order — and prompt builders usually emit insertion order."""
    from airlock.scan import build_denyset, scan
    secret = {"b": 2, "a": 1}
    denyset = build_denyset([], [secret])
    sorted_form = json.dumps(secret, ensure_ascii=False, separators=(",", ":"),
                             sort_keys=True)
    insertion_form = json.dumps(secret, ensure_ascii=False, separators=(",", ":"))
    assert sorted_form != insertion_form
    assert scan(f"x {sorted_form} y", denyset)
    assert scan(f"x {insertion_form} y", denyset)


def test_authorized_value_is_cleared_in_both_key_orders():
    from airlock.scan import build_denyset, scan
    value = {"b": 2, "a": 1}
    denyset = build_denyset([], [value], authorized_values=[value])
    both = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + " " +
            json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                       sort_keys=True))
    assert scan(both, denyset) == []


def test_pinned_input_aborts_on_substitution_and_absence(tmp_path):
    from airlock.transport import verify_pinned_input
    target = tmp_path / "predictions.json"
    target.write_text('{"a": 1}', encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    assert verify_pinned_input(target, digest) == digest
    target.write_text('{"a": 2}', encoding="utf-8")  # substituted after pinning
    with pytest.raises(RuntimeError, match="pinned digest"):
        verify_pinned_input(target, digest)
    with pytest.raises(RuntimeError, match="missing"):
        verify_pinned_input(tmp_path / "gone.json", digest)


def test_opaque_token_is_not_recoverable_from_public_material():
    """Hashing a label with a published salt is not opacity: the label space
    is small and enumerable. The HMAC key must be secret."""
    from airlock.transport import opaque_source_token
    key = b"k" * 32
    public_salt = "deadbeef" * 8          # e.g. the published document digest
    token = opaque_source_token("patient_01", key)
    for guess_label in ("patient_01", "patient_1", "`patient_01`"):
        for guess in (
            hashlib.sha256(f"{public_salt}|{guess_label}".encode()).hexdigest()[:20],
            hashlib.sha256(guess_label.encode()).hexdigest()[:20],
        ):
            assert guess != token
    assert opaque_source_token("patient_01", key) == token       # stable
    assert opaque_source_token("patient_02", key) != token       # distinguishes
    with pytest.raises(ValueError):
        opaque_source_token("patient_01", b"short")


def test_payload_travels_on_stdin_not_argv():
    """A prompt passed as an argument is readable in /proc/<pid>/cmdline."""
    from airlock.jail import JailSpec, bwrap_command
    spec = JailSpec(jail_home=Path("/tmp"), workdir=Path("/tmp"))
    command = bwrap_command(spec, ["some-agent", "exec", "-"])
    assert "some-agent" in command
    assert not any("SECRET-PAYLOAD" in part for part in command)
