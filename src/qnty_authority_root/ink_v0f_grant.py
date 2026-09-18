"""One-shot Ink V0F short-lived authority receipt issuance.

All temporal and signing inputs are explicit. This module performs no network
activity, discovers no credentials, and creates no external execution effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contract import AuthorityGrantReceiptV0, AuthorityPolicyRefV0
from .errors import IssuancePolicyError
from .ink_v0f_binding import INK_V0F_GRANT_PREPARATION
from .issuer import AuthorityIssuer, Ed25519Signer
from .policy import AuthorityIssuancePolicyV0, AuthorityIssuanceRequestV0

INK_V0F_ISSUANCE_BUNDLE_SCHEMA = "qnty.authority_root.ink_v0f_issuance_bundle.v0"


def _epoch(value: Any, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise IssuancePolicyError(f"{field}: expected non-negative integer epoch seconds")
    return value


def _positive(value: Any, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise IssuancePolicyError(f"{field}: expected positive integer")
    return value


def ink_v0f_issuer_policy() -> AuthorityIssuancePolicyV0:
    prep = INK_V0F_GRANT_PREPARATION
    return AuthorityIssuancePolicyV0(
        root_id=prep.authority_root_id,
        repository_identity=prep.repository_identity,
        maximum_issuable_level=prep.maximum_issuable_level,
        allowed_network_ids=(prep.permitted_network_id,),
        allowed_taker_addresses=(prep.permitted_taker_address,),
        allowed_venue_ids=(prep.permitted_venue_id,),
        max_reservation_atomic=prep.max_reservation_atomic,
        max_cumulative_atomic=prep.max_cumulative_atomic,
        max_grant_duration_s=prep.max_grant_duration_s,
    )


def build_ink_v0f_request(
    *,
    issued_at_epoch_s: int,
    duration_s: int = 900,
) -> AuthorityIssuanceRequestV0:
    issued_at = _epoch(issued_at_epoch_s, field="issued_at_epoch_s")
    duration = _positive(duration_s, field="duration_s")
    prep = INK_V0F_GRANT_PREPARATION
    if duration > prep.max_grant_duration_s:
        raise IssuancePolicyError("duration_s exceeds the frozen Ink V0F grant ceiling")

    authority = AuthorityPolicyRefV0(
        authority_root_id=prep.authority_root_id,
        granted_level=prep.maximum_issuable_level,
        permitted_repository_commit=prep.permitted_repository_commit,
        permitted_implementation_digest=prep.permitted_implementation_digest,
        permitted_network_id=prep.permitted_network_id,
        permitted_taker_address=prep.permitted_taker_address,
        permitted_venue_id=prep.permitted_venue_id,
        max_reservation_atomic=prep.max_reservation_atomic,
        max_cumulative_atomic=prep.max_cumulative_atomic,
        not_before_epoch_s=issued_at,
        not_after_epoch_s=issued_at + duration,
    )
    return AuthorityIssuanceRequestV0(
        repository_identity=prep.repository_identity,
        authority_policy=authority,
        issued_at_epoch_s=issued_at,
    )


def ink_v0f_request_id(*, issued_at_epoch_s: int, duration_s: int) -> str:
    issued_at = _epoch(issued_at_epoch_s, field="issued_at_epoch_s")
    duration = _positive(duration_s, field="duration_s")
    if duration > INK_V0F_GRANT_PREPARATION.max_grant_duration_s:
        raise IssuancePolicyError("duration_s exceeds the frozen Ink V0F grant ceiling")
    return f"ink-v0f-{issued_at}-{duration}"


@dataclass(frozen=True, slots=True)
class InkV0FIssuanceBundleV0:
    request_id: str
    receipt_bytes: bytes
    trust_config_bytes: bytes
    trust_config_digest: str
    public_anchor_bytes: bytes
    schema: str = INK_V0F_ISSUANCE_BUNDLE_SCHEMA

    def __post_init__(self) -> None:
        if type(self.request_id) is not str or not self.request_id:
            raise IssuancePolicyError("request_id must be non-empty text")
        if type(self.receipt_bytes) is not bytes or not self.receipt_bytes:
            raise IssuancePolicyError("receipt_bytes must be explicit bytes")
        if type(self.trust_config_bytes) is not bytes or not self.trust_config_bytes:
            raise IssuancePolicyError("trust_config_bytes must be explicit bytes")
        if (
            type(self.trust_config_digest) is not str
            or len(self.trust_config_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in self.trust_config_digest)
        ):
            raise IssuancePolicyError("trust_config_digest must be lowercase SHA-256 hex")
        if type(self.public_anchor_bytes) is not bytes or len(self.public_anchor_bytes) != 32:
            raise IssuancePolicyError("public_anchor_bytes must be exactly 32 bytes")
        if self.schema != INK_V0F_ISSUANCE_BUNDLE_SCHEMA:
            raise IssuancePolicyError("unknown Ink V0F issuance bundle schema")

    @property
    def receipt(self) -> AuthorityGrantReceiptV0:
        return AuthorityGrantReceiptV0.from_bytes(self.receipt_bytes)


def issue_ink_v0f_grant(
    *,
    db_path: str | Path,
    signer: Ed25519Signer,
    authority_epoch: int,
    minimum_authority_epoch: int,
    trust_config_version: int,
    issued_at_epoch_s: int,
    duration_s: int = 900,
) -> InkV0FIssuanceBundleV0:
    """Issue one exact, short-lived Ink V0F receipt through the durable issuer."""

    issued_at = _epoch(issued_at_epoch_s, field="issued_at_epoch_s")
    duration = _positive(duration_s, field="duration_s")
    request = build_ink_v0f_request(
        issued_at_epoch_s=issued_at,
        duration_s=duration,
    )
    request_id = ink_v0f_request_id(
        issued_at_epoch_s=issued_at,
        duration_s=duration,
    )
    issuer = AuthorityIssuer(
        db_path=db_path,
        issuer_policy=ink_v0f_issuer_policy(),
        authority_epoch=authority_epoch,
        minimum_authority_epoch=minimum_authority_epoch,
        trust_config_version=trust_config_version,
        signer=signer,
    )
    receipt_bytes = issuer.issue(request_id=request_id, request=request)
    return InkV0FIssuanceBundleV0(
        request_id=request_id,
        receipt_bytes=receipt_bytes,
        trust_config_bytes=issuer.trust_config_bytes,
        trust_config_digest=issuer.trust_config_digest,
        public_anchor_bytes=issuer.public_anchor_bytes,
    )
