"""Payload hygiene: allowlist construction first, deny-scan as defense in depth.

Doctrine (earned through three adversarial audit loops):

1. The PRIMARY guarantee is **allowlist construction**: assemble what you send
   only from sources whose hashes you verified. You do not "prove a negative";
   you build from material that by origin has nothing to leak.
2. The deny-scan is **defense in depth**, arm-aware and fail-closed. It must
   never include values that are legitimate inputs for the arm being scanned
   (or you get false positives), and it must never rely on atomic tokens
   shared with legitimate content (``INT02``-style labels, single common
   words). Structured fields are matched by *distinctive serialization*;
   prose is matched normalized (casing/whitespace/punctuation).
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

MIN_PROSE = 12          # minimum prose fragment length to count as a leak
MIN_DISTINCTIVE = 7     # minimum length for a structured value to be distinctive


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def prose_snippets(text: str | None, min_length: int = MIN_PROSE) -> list[str]:
    if not text:
        return []
    snippets = []
    for chunk in re.split(r"[.\n]", text):
        chunk = chunk.strip()
        if len(chunk) >= min_length:
            snippets.append(chunk)
    return snippets


def distinctive(value: Any, min_length: int = MIN_DISTINCTIVE) -> str | None:
    """Serialize a structured value if it is distinctive enough to scan for."""
    if value is None:
        return None
    if isinstance(value, str):
        return value if len(value) >= min_length else None
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                            sort_keys=True)
    return serialized if len(serialized) >= min_length else None


def build_denyset(
    prose_fields: list[str | None],
    distinctive_values: list[Any],
    authorized_values: list[Any] = (),
) -> list[str]:
    """Compose a denyset. ``authorized_values`` are removed even if present in
    the other lists (they are legitimate inputs of this arm)."""
    authorized = {distinctive(v) for v in authorized_values if v is not None}
    deny: list[str] = []
    for text in prose_fields:
        deny.extend(prose_snippets(text))
    for value in distinctive_values:
        serialized = distinctive(value)
        if serialized and serialized not in authorized:
            deny.append(serialized)
    return [d for d in deny if d]


def scan(sent_text: str, denyset: list[str]) -> list[str]:
    normalized_text = normalize(sent_text)
    findings = []
    for needle in denyset:
        if needle in sent_text:
            findings.append(needle)
        elif len(needle) >= MIN_PROSE and normalize(needle) in normalized_text:
            findings.append(needle)
    return findings
