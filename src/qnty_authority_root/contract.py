"""The exact QntySpot V0 authority receipt consumer contract.

This module intentionally contains only public contract material and Ed25519
verification. It has no private-key, network, transaction, or service code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from .canon import canonical_json_bytes, digest_object, sha256_hex, strict_json_loads
from .errors import AuthorityRootError, CanonicalFormError

AUTHORITY_ROOT_CONTRACT_VERSION = "QNTY_SPOT_EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0"
AUTHORITY_ROOT_SCHEMA = "qntyspot.authority_root.v0"
TRUST_CONFIG_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".trust_config"
GRANT_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".grant"
GRANT_ID_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".grant_id"
RECEIPT_ID_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".receipt_id"
ED25519_SIGNATURE_ALGORITHM = "Ed25519"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_PORTABLE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[0-9]+)*$")
_RESERVED_EXACT_SCOPE_TOKENS = frozenset({"*", "any", "latest"})
_AUTHORITY_POLICY_SCHEMA = "qntyspot.program_b.v0.authority_policy"
MAX_UINT256 = 2**256 - 1


def _portable(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _PORTABLE_RE.fullmatch(value) or len(value) > 64:
        raise AuthorityRootError(f"{field_name}: non-portable identity")
    return value


def _digest(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
        raise AuthorityRootError(f"{field_name}: expected lowercase SHA-256 hex")
    return value


def _commit(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _COMMIT_RE.fullmatch(value):
        raise AuthorityRootError(f"{field_name}: expected lowercase 40-character commit")
    return value


def _label(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or value.strip() != value:
        raise AuthorityRootError(f"{field_name}: must be a short non-empty label")
    return value


def _address(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise AuthorityRootError(f"{field_name}: expected lowercase EVM address")
    if int(value, 16) == 0:
        raise AuthorityRootError(f"{field_name}: the zero address is not admissible")
    return value


def _positive_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise AuthorityRootError(f"{field_name}: expected positive integer")
    return value


def _non_negative_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise AuthorityRootError(f"{field_name}: expected non-negative integer")
    return value


def _atomic(value: Any, *, field_name: str, positive: bool) -> int:
    if type(value) is not int or (value <= 0 if positive else value < 0):
        expectation = "positive" if positive else "non-negative"
        raise AuthorityRootError(f"{field_name}: expected {expectation} integer")
    if value > MAX_UINT256:
        raise AuthorityRootError(f"{field_name}: exceeds uint256")
    return value


def _canonical_atomic(value: Any, *, field_name: str, positive: bool) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise AuthorityRootError(f"{field_name}: non-canonical atomic amount")
    amount = int(value)
    return _atomic(amount, field_name=field_name, positive=positive)


def _assert_exact_scope(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise AuthorityRootError(f"{field_name}: exact scope must be a string")
    if value.strip().casefold() in _RESERVED_EXACT_SCOPE_TOKENS:
        raise AuthorityRootError(f"{field_name}: wildcard and alias scopes are forbidden")
    return value


class AuthorityLevel(IntEnum):
    SHADOW = 0
    RECONCILE_ONLY = 1
    SUBMIT_EXACT_SIGNED_BYTES = 2
    HUMAN_SIGNED_EXECUTION = 3
    AUTONOMOUS_BOUNDED_SIGNER = 4


@dataclass(frozen=True, slots=True)
class AuthorityPolicyRefV0:
    """An exact authority scope consumed by canonical QntySpot."""

    authority_root_id: str
    granted_level: AuthorityLevel
    permitted_repository_commit: str
    permitted_implementation_digest: str
    permitted_network_id: str
    permitted_taker_address: str
    permitted_venue_id: str
    max_reservation_atomic: int
    max_cumulative_atomic: int
    not_before_epoch_s: int
    not_after_epoch_s: int
    schema: str = _AUTHORITY_POLICY_SCHEMA

    def __post_init__(self) -> None:
        _portable(self.authority_root_id, field_name="authority_root_id")
        if not isinstance(self.granted_level, AuthorityLevel):
            raise AuthorityRootError(f"unknown granted_level {self.granted_level!r}")
        _commit(self.permitted_repository_commit, field_name="permitted_repository_commit")
        _assert_exact_scope(self.permitted_repository_commit, field_name="permitted_repository_commit")
        _digest(self.permitted_implementation_digest, field_name="permitted_implementation_digest")
        _assert_exact_scope(self.permitted_implementation_digest, field_name="permitted_implementation_digest")
        _label(self.permitted_network_id, field_name="permitted_network_id")
        _assert_exact_scope(self.permitted_network_id, field_name="permitted_network_id")
        _address(self.permitted_taker_address, field_name="permitted_taker_address")
        _assert_exact_scope(self.permitted_taker_address, field_name="permitted_taker_address")
        _portable(self.permitted_venue_id, field_name="permitted_venue_id")
        _assert_exact_scope(self.permitted_venue_id, field_name="permitted_venue_id")
        _atomic(self.max_reservation_atomic, field_name="max_reservation_atomic", positive=True)
        _atomic(self.max_cumulative_atomic, field_name="max_cumulative_atomic", positive=True)
        if self.max_reservation_atomic > self.max_cumulative_atomic:
            raise AuthorityRootError("max_reservation must not exceed max_cumulative")
        _non_negative_int(self.not_before_epoch_s, field_name="not_before_epoch_s")
        _positive_int(self.not_after_epoch_s, field_name="not_after_epoch_s")
        if self.not_after_epoch_s <= self.not_before_epoch_s:
            raise AuthorityRootError("an authority grant must expire after it begins")
        if self.schema != _AUTHORITY_POLICY_SCHEMA:
            raise AuthorityRootError("unknown authority policy schema")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "authority_root_id": self.authority_root_id,
            "granted_level": int(self.granted_level),
            "max_cumulative_atomic": str(self.max_cumulative_atomic),
            "max_reservation_atomic": str(self.max_reservation_atomic),
            "not_after_epoch_s": self.not_after_epoch_s,
            "not_before_epoch_s": self.not_before_epoch_s,
            "permitted_implementation_digest": self.permitted_implementation_digest,
            "permitted_network_id": self.permitted_network_id,
            "permitted_repository_commit": self.permitted_repository_commit,
            "permitted_taker_address": self.permitted_taker_address,
            "permitted_venue_id": self.permitted_venue_id,
            "schema": self.schema,
        }

    @property
    def authority_policy_digest(self) -> str:
        return digest_object(self.canonical_object())

    def assert_valid_at(self, now_epoch_s: int) -> None:
        _non_negative_int(now_epoch_s, field_name="now_epoch_s")
        if not self.not_before_epoch_s <= now_epoch_s < self.not_after_epoch_s:
            raise AuthorityRootError(f"authority grant is not valid at {now_epoch_s}")


@dataclass(frozen=True, slots=True)
class TrustedAuthorityRootV0:
    """Public trust configuration plus separately supplied public anchor bytes."""

    root_id: str
    signature_algorithm: str
    public_key_fingerprint: str
    minimum_authority_epoch: int
    trust_config_version: int
    trust_config_digest: str
    anchor_bytes: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _portable(self.root_id, field_name="root_id")
        if self.signature_algorithm != ED25519_SIGNATURE_ALGORITHM:
            raise AuthorityRootError("signature_algorithm must be Ed25519")
        _digest(self.public_key_fingerprint, field_name="public_key_fingerprint")
        if type(self.anchor_bytes) is not bytes or len(self.anchor_bytes) != 32:
            raise AuthorityRootError("anchor_bytes must be exactly 32 public-key bytes")
        if sha256_hex(self.anchor_bytes) != self.public_key_fingerprint:
            raise AuthorityRootError("public-key fingerprint does not match anchor bytes")
        _positive_int(self.minimum_authority_epoch, field_name="minimum_authority_epoch")
        _positive_int(self.trust_config_version, field_name="trust_config_version")
        _digest(self.trust_config_digest, field_name="trust_config_digest")
        if sha256_hex(canonical_json_bytes(self.canonical_object())) != self.trust_config_digest:
            raise AuthorityRootError("trust_config_digest does not bind root configuration")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "minimum_authority_epoch": self.minimum_authority_epoch,
            "public_key_fingerprint": self.public_key_fingerprint,
            "root_id": self.root_id,
            "schema": TRUST_CONFIG_SCHEMA,
            "signature_algorithm": self.signature_algorithm,
            "trust_config_version": self.trust_config_version,
        }

    @property
    def serialized_config(self) -> bytes:
        return canonical_json_bytes(self.canonical_object())


@dataclass(frozen=True, slots=True)
class AuthorityGrantReceiptV0:
    """The exact 12-field serialized QntySpot authority receipt."""

    root_id: str
    public_key_fingerprint: str
    signature_algorithm: str
    authority_epoch: int
    serial: int
    issued_at_epoch_s: int
    authority_policy: AuthorityPolicyRefV0
    signature: bytes
    schema: str = GRANT_SCHEMA

    def __post_init__(self) -> None:
        _portable(self.root_id, field_name="root_id")
        _digest(self.public_key_fingerprint, field_name="public_key_fingerprint")
        if self.signature_algorithm != ED25519_SIGNATURE_ALGORITHM:
            raise AuthorityRootError("signature_algorithm must be Ed25519")
        _positive_int(self.authority_epoch, field_name="authority_epoch")
        _positive_int(self.serial, field_name="serial")
        _non_negative_int(self.issued_at_epoch_s, field_name="issued_at_epoch_s")
        if not isinstance(self.authority_policy, AuthorityPolicyRefV0):
            raise AuthorityRootError("authority_policy must be AuthorityPolicyRefV0")
        if self.authority_policy.authority_root_id != self.root_id:
            raise AuthorityRootError("receipt root_id disagrees with authority policy")
        for field_name, value in (
            ("permitted_repository_commit", self.authority_policy.permitted_repository_commit),
            ("permitted_implementation_digest", self.authority_policy.permitted_implementation_digest),
            ("permitted_network_id", self.authority_policy.permitted_network_id),
            ("permitted_taker_address", self.authority_policy.permitted_taker_address),
            ("permitted_venue_id", self.authority_policy.permitted_venue_id),
        ):
            _assert_exact_scope(value, field_name=field_name)
        if type(self.signature) is not bytes or len(self.signature) != 64:
            raise AuthorityRootError("signature must be exactly 64 Ed25519 bytes")
        if self.schema != GRANT_SCHEMA:
            raise AuthorityRootError("unknown authority grant schema")

    @property
    def authority_policy_digest(self) -> str:
        return self.authority_policy.authority_policy_digest

    @property
    def grant_id(self) -> str:
        return digest_object(
            {
                "authority_epoch": self.authority_epoch,
                "authority_policy_digest": self.authority_policy_digest,
                "root_id": self.root_id,
                "schema": GRANT_ID_SCHEMA,
                "serial": self.serial,
            }
        )

    def signed_body_object(self) -> dict[str, Any]:
        return {
            "authority_epoch": self.authority_epoch,
            "authority_policy": self.authority_policy.canonical_object(),
            "authority_policy_digest": self.authority_policy_digest,
            "grant_id": self.grant_id,
            "issued_at_epoch_s": self.issued_at_epoch_s,
            "public_key_fingerprint": self.public_key_fingerprint,
            "root_id": self.root_id,
            "schema": self.schema,
            "serial": self.serial,
            "signature_algorithm": self.signature_algorithm,
        }

    @property
    def signed_body_bytes(self) -> bytes:
        return canonical_json_bytes(self.signed_body_object())

    @property
    def signed_body_digest(self) -> str:
        return sha256_hex(self.signed_body_bytes)

    @property
    def receipt_id(self) -> str:
        return digest_object(
            {
                "grant_id": self.grant_id,
                "public_key_fingerprint": self.public_key_fingerprint,
                "root_id": self.root_id,
                "schema": RECEIPT_ID_SCHEMA,
                "signature_algorithm": self.signature_algorithm,
                "signature_digest": sha256_hex(self.signature),
                "signed_body_digest": self.signed_body_digest,
            }
        )

    def to_object(self) -> dict[str, Any]:
        document = self.signed_body_object()
        document.update({"receipt_id": self.receipt_id, "signature": self.signature.hex()})
        return document

    @property
    def serialized(self) -> bytes:
        return canonical_json_bytes(self.to_object())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AuthorityGrantReceiptV0":
        if type(raw) is not bytes:
            raise AuthorityRootError("authority receipt must be explicit bytes")
        try:
            document = strict_json_loads(raw)
            if type(document) is not dict:
                raise AuthorityRootError("authority receipt must be a JSON object")
            expected_fields = {
                "authority_epoch", "authority_policy", "authority_policy_digest", "grant_id",
                "issued_at_epoch_s", "public_key_fingerprint", "receipt_id", "root_id",
                "schema", "serial", "signature", "signature_algorithm",
            }
            if set(document) != expected_fields:
                raise AuthorityRootError("authority receipt has unknown or missing fields")
            if canonical_json_bytes(document) != raw:
                raise AuthorityRootError("authority receipt is not canonical JSON")
            policy = _authority_policy_from_object(document["authority_policy"])
            signature_text = document["signature"]
            if not isinstance(signature_text, str) or not re.fullmatch(r"[0-9a-f]{128}", signature_text):
                raise AuthorityRootError("signature: expected lowercase 64-byte hex")
            receipt = cls(
                root_id=document["root_id"],
                public_key_fingerprint=document["public_key_fingerprint"],
                signature_algorithm=document["signature_algorithm"],
                authority_epoch=document["authority_epoch"],
                serial=document["serial"],
                issued_at_epoch_s=document["issued_at_epoch_s"],
                authority_policy=policy,
                signature=bytes.fromhex(signature_text),
                schema=document["schema"],
            )
            if document["authority_policy_digest"] != receipt.authority_policy_digest:
                raise AuthorityRootError("authority policy digest mismatch")
            if document["grant_id"] != receipt.grant_id:
                raise AuthorityRootError("grant identity mismatch")
            if document["receipt_id"] != receipt.receipt_id:
                raise AuthorityRootError("receipt identity mismatch")
            return receipt
        except (AuthorityRootError, CanonicalFormError, TypeError, ValueError) as exc:
            if isinstance(exc, AuthorityRootError):
                raise
            raise AuthorityRootError(f"malformed authority receipt: {exc}") from exc


def _authority_policy_from_object(document: Any) -> AuthorityPolicyRefV0:
    if type(document) is not dict:
        raise AuthorityRootError("authority_policy must be a JSON object")
    expected_fields = {
        "authority_root_id", "granted_level", "max_cumulative_atomic", "max_reservation_atomic",
        "not_after_epoch_s", "not_before_epoch_s", "permitted_implementation_digest",
        "permitted_network_id", "permitted_repository_commit", "permitted_taker_address",
        "permitted_venue_id", "schema",
    }
    if set(document) != expected_fields:
        raise AuthorityRootError("authority policy has unknown or missing fields")
    if type(document["granted_level"]) is not int:
        raise AuthorityRootError("granted_level must be an integer")
    try:
        return AuthorityPolicyRefV0(
            authority_root_id=document["authority_root_id"],
            granted_level=AuthorityLevel(document["granted_level"]),
            permitted_repository_commit=document["permitted_repository_commit"],
            permitted_implementation_digest=document["permitted_implementation_digest"],
            permitted_network_id=document["permitted_network_id"],
            permitted_taker_address=document["permitted_taker_address"],
            permitted_venue_id=document["permitted_venue_id"],
            max_reservation_atomic=_canonical_atomic(
                document["max_reservation_atomic"], field_name="max_reservation_atomic", positive=True
            ),
            max_cumulative_atomic=_canonical_atomic(
                document["max_cumulative_atomic"], field_name="max_cumulative_atomic", positive=True
            ),
            not_before_epoch_s=document["not_before_epoch_s"],
            not_after_epoch_s=document["not_after_epoch_s"],
            schema=document["schema"],
        )
    except (AuthorityRootError, TypeError, ValueError) as exc:
        if isinstance(exc, AuthorityRootError):
            raise
        raise AuthorityRootError(f"malformed authority policy: {exc}") from exc


def verify_receipt_signature(receipt: AuthorityGrantReceiptV0 | bytes, public_key_bytes: bytes) -> None:
    """Verify an authority receipt with explicitly supplied public bytes."""
    if isinstance(receipt, bytes):
        receipt = AuthorityGrantReceiptV0.from_bytes(receipt)
    if not isinstance(receipt, AuthorityGrantReceiptV0):
        raise AuthorityRootError("receipt is not an authority grant")
    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise AuthorityRootError("public key must be exactly 32 bytes")
    if receipt.public_key_fingerprint != sha256_hex(public_key_bytes):
        raise AuthorityRootError("authority receipt fingerprint does not identify the supplied key")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            receipt.signature, receipt.signed_body_bytes
        )
    except ImportError as exc:
        raise AuthorityRootError("Ed25519 verifier is unavailable") from exc
    except (InvalidSignature, ValueError) as exc:
        raise AuthorityRootError("authority receipt signature is invalid") from exc
