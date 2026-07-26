"""Export → invoke → import with canonical requests and strict correlation.

The invocation of an agent CLI cannot be called from inside your pipeline the
way an HTTP endpoint can — it is a separate, possibly manual, step. This
module makes that step auditable:

- The **effective request** is one canonical dict containing the prompt AND
  the full invocation config (model, effort, sandbox, cwd policy, session
  policy). Its sha256 is computed exclusively over that representation, so a
  response cannot be correlated with a materially different invocation.
- The **import** rejects uncorrelated, missing and duplicated responses
  against an explicit expected set (``run_scope``).
- Honesty: unless the transport returns an objective receipt, correlation is
  **operator attestation**, not proof of invocation identity. The output says
  which one it is.
"""
from __future__ import annotations

import hashlib
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Callable

TRANSPORT_VERSION = "agent-airlock-transport-v0.1"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True)


def request_sha256(effective_request: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(effective_request).encode("utf-8")).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def export_requests(
    case_ids: list[str],
    build_request: Callable[[str], dict[str, Any]],
    pre_send_check: Callable[[str, dict[str, Any]], list[str]] | None,
    output: Path,
    run_scope: str = "full",
) -> dict:
    """Build one canonical request per case; abort on any pre-send finding."""
    requests_dir = output / "requests"
    for case_id in case_ids:
        effective = build_request(case_id)
        if pre_send_check is not None:
            findings = pre_send_check(case_id, effective)
            if findings:
                raise RuntimeError(
                    f"pre-send check flagged {case_id}: {findings[:3]} — export aborted")
        _write_json(requests_dir / f"{case_id}.json", {
            "case_id": case_id,
            "request_sha256": request_sha256(effective),
            "effective_request": effective,
        })
    _write_json(output / "RUN_MANIFEST.json", {
        "transport_version": TRANSPORT_VERSION,
        "run_scope": run_scope,
        "expected_case_ids": list(case_ids),
    })
    return {"exported": list(case_ids), "run_scope": run_scope}


def import_responses(
    requests_dir: Path,
    responses_dir: Path,
    run_manifest_path: Path,
    output: Path,
    metadata: dict[str, Any] | None = None,
) -> dict:
    run_manifest = _read_json(run_manifest_path)
    expected = list(run_manifest["expected_case_ids"])
    requests = {p.stem: _read_json(p) for p in requests_dir.glob("*.json")}
    responses: dict[str, dict] = {}
    for path in sorted(responses_dir.glob("*.json")):
        row = _read_json(path)
        cid = row["case_id"]
        if cid in responses:
            raise RuntimeError(f"duplicated response for {cid}")
        responses[cid] = row
    missing = [c for c in expected if c not in responses]
    extra = [c for c in responses if c not in expected]
    if missing:
        raise RuntimeError(f"missing responses from the expected set: {missing}")
    if extra:
        raise RuntimeError(f"responses outside the expected set: {extra}")
    rows = []
    receipts = True
    for cid in expected:
        request = requests.get(cid)
        if request is None:
            raise RuntimeError(f"request missing for {cid}")
        response = responses[cid]
        if response.get("request_sha256") != request["request_sha256"]:
            raise RuntimeError(
                f"{cid}: response request_sha256 does not correlate with the request")
        receipts = receipts and bool(response.get("receipt"))
        rows.append({
            "case_id": cid,
            "response": (response.get("response") or "").strip(),
            "request_sha256": request["request_sha256"],
            "session_id": response.get("session_id"),
            "usage": response.get("usage"),  # provider-reported or None; never estimated
            "wall_seconds": response.get("wall_seconds"),
        })
    document = {
        "transport_version": TRANSPORT_VERSION,
        "run_scope": run_manifest["run_scope"],
        "correlation": "verified_receipt" if receipts else "operator_attestation",
        "rows": rows,
    }
    if metadata:
        document.update(metadata)
    _write_json(output, document)
    return {"imported": len(rows), "correlation": document["correlation"]}


def verify_pinned_input(path: Path, expected_sha256: str,
                        description: str = "pinned input") -> str:
    """Fail-closed check for an input that a preregistration pinned by hash.

    Field note (earned the hard way): recording the hash of an input in a
    manifest makes a run *auditable after the fact*, but it does not stop a
    substitution from happening. If a preregistration pins the material an
    experiment consumes — a predictions file, a frozen corpus, a comparator's
    outputs — the producer must **compare and abort before emitting anything**.
    "Detectable" and "prevented" are different guarantees; choose prevented.

    Raises if the file is missing or its digest differs. Returns the digest.
    """
    if not path.is_file():
        raise RuntimeError(
            f"{description} missing: {path} — a pinned input is mandatory; "
            "nothing is emitted without it")
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise RuntimeError(
            f"{description} does not match the pinned digest: expected "
            f"{expected_sha256[:12]}…, got {actual[:12]}… — aborted")
    return actual


def opaque_source_token(label: str, key: bytes, length: int = 20) -> str:
    """Stable, non-reversible token for a private source label.

    Field note: hashing a label with a *public* salt (the digest of the source
    document, say) is not opacity. Source labels usually live in a small,
    guessable universe (``patient_01``, ``session_03_b``…), so anyone holding
    the published salt recovers them by enumeration. Use an HMAC keyed with a
    secret that never enters the repository; then equality between records is
    still verifiable by whoever holds the key, and by nobody else.

    ``key`` must be at least 16 bytes; the caller is responsible for storing
    it outside the repo (mode 0600) and for failing closed when it is absent.
    """
    if len(key) < 16:
        raise ValueError("HMAC key too short (<16 bytes)")
    return hmac.new(key, label.encode("utf-8"), hashlib.sha256).hexdigest()[:length]
