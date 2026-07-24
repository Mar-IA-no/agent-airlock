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
import json
from pathlib import Path
from typing import Any, Callable

TRANSPORT_VERSION = "agent-airlock-transport-v0.1"


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
