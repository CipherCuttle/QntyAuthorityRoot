"""The canonical JSON and SHA-256 rules shared with QntySpot V0."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .errors import CanonicalFormError


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise CanonicalFormError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_float(text: str) -> Any:
    raise CanonicalFormError(
        f"JSON number {text!r} would be parsed as binary float; "
        "economic values must be canonical decimal strings"
    )


def _reject_constant(text: str) -> Any:
    raise CanonicalFormError(f"JSON constant {text!r} is not admissible")


def strict_json_loads(raw: str | bytes) -> Any:
    """Parse JSON while refusing duplicate keys, floats, and constants."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalFormError(f"JSON is not valid UTF-8: {exc}") from exc
    if not isinstance(raw, str):
        raise CanonicalFormError(f"expected str or bytes, got {type(raw).__name__}")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalFormError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalFormError(f"malformed JSON: {exc}") from exc


def canonical_json_str(obj: Any) -> str:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_json_bytes(obj: Any) -> bytes:
    return canonical_json_str(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_object(obj: Any) -> str:
    return sha256_hex(canonical_json_bytes(obj))
