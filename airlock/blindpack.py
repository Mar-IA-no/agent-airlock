"""Pre-registered, structurally blinded human-review packs.

Two safeguards that a naive "shuffle and hide the names" pack lacks:

- **Pre-registration in two artifacts**: composition (arms, universe, policy
  for missing comparators) is fixed BEFORE any output exists, in
  ``PACK_PREREGISTRATION.json`` (no hashes — outputs do not exist yet). After
  generation, ``PACK_INPUTS_RESOLVED.json`` is produced mechanically and
  proves conformity. Choosing comparators after seeing outputs is
  retrospective selection — forbidden by construction.
- **Blinding by access separation**: two physically separate trees. ``blind/``
  is the deliverable (randomized options, structural key allowlist — content
  is NOT word-scanned, since legitimate responses may contain any word);
  ``sealed/`` holds the key. The deliverable manifest never mentions the key.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

BUILDER_VERSION = "agent-airlock-blindpack-v0.1"
ALLOWED_BLIND_KEYS = {"case_id", "instructions", "options",
                       "context", "state", "injected_decision", "rubric"}


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(prereg_path: Path, outputs_paths: dict[str, Path], output: Path,
          instructions: str, case_context=None) -> dict:
    """``case_context(case_id) -> dict`` optionally supplies the material the
    reviewer needs to judge (conversation, injected decision, rubric...).
    Without it the pack has options only — usually NOT evaluable; provide it."""
    prereg = _read_json(prereg_path)
    expected_arms = set(prereg["arm_ids"])
    actual_arms = set(outputs_paths)
    if actual_arms != expected_arms:  # exact equality: no missing, no extras
        missing = sorted(expected_arms - actual_arms)
        extra = sorted(actual_arms - expected_arms)
        if extra:
            raise RuntimeError(f"non-preregistered arms present: {extra}")
        if missing and prereg.get("missing_comparator_policy", "abort") == "abort":
            raise RuntimeError(
                f"missing comparators {missing} and preregistered policy is abort")
    universe = list(prereg["case_ids"])
    outputs_by_arm = {}
    for arm_id, path in outputs_paths.items():
        document = _read_json(path)
        rows = {r["case_id"]: r for r in document["rows"]}
        if not set(universe) <= set(rows):
            raise RuntimeError(f"{arm_id}: does not cover the preregistered universe")
        document["_sha256"] = _sha256_file(path)
        document["_rows"] = rows
        outputs_by_arm[arm_id] = document

    blind_dir = output / "blind"
    sealed_dir = output / "sealed"
    salt = secrets.token_hex(16)
    key = {"salt": salt, "assignments": {}}
    for cid in universe:
        options = {arm_id: doc["_rows"][cid].get("response", "")
                   for arm_id, doc in outputs_by_arm.items()}
        ordered = sorted(options.items(), key=lambda kv: hashlib.sha256(
            f"{salt}:{cid}:{kv[0]}".encode()).hexdigest())
        labels = [chr(ord("A") + i) for i in range(len(ordered))]
        key["assignments"][cid] = {label: arm_id
                                    for label, (arm_id, _) in zip(labels, ordered)}
        blind_case = {
            "case_id": cid,
            "instructions": instructions,
            "options": {label: text for label, (_a, text) in zip(labels, ordered)},
        }
        if case_context is not None:
            context = dict(case_context(cid))
            assert not (set(context) & set(blind_case)), "context clashes with core keys"
            blind_case.update(context)
        _write_json(blind_dir / f"{cid}.json", blind_case)
    _write_json(sealed_dir / "BLIND_KEY.json", key)
    _write_json(sealed_dir / "PACK_INPUTS_RESOLVED.json", {
        "builder_version": BUILDER_VERSION,
        "preregistration_sha256": _sha256_file(prereg_path),
        "resolved": {arm_id: {"outputs_sha256": doc["_sha256"]}
                      for arm_id, doc in outputs_by_arm.items()},
        "conforms": True,
    })
    _write_json(blind_dir / "DELIVERABLE_MANIFEST.json", {
        "builder_version": BUILDER_VERSION,
        "files": sorted(p.name for p in blind_dir.glob("*.json")
                         if p.name != "DELIVERABLE_MANIFEST.json"),
        "note": "This manifest covers only the review files in this directory. "
                 "No correction key exists in the deliverable package.",
    })
    return {"cases": len(universe), "arms": sorted(outputs_by_arm)}
