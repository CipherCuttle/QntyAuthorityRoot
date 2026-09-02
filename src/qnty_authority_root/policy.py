"""Mechanical V0 issuer restrictions and request shape."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .canon import digest_object
from .contract import AuthorityLevel, AuthorityPolicyRefV0, MAX_UINT256
from .errors import IssuancePolicyError

CANONICAL_REPOSITORY_IDENTITY = "CipherCuttle/QntySpot"
ALLOWED_NETWORK_ID = "evm:46630"
FORBIDDEN_MAINNET_NETWORK_ID = "evm:4663"
MAX_GRANT_DURATION_S = 3600
_REPOSITORY_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_REQUEST_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_PORTABLE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[0-9]+)*$")
_RESERVED = frozenset({"*", "any", "latest"})


def _validate_repository_identity(value: Any, *, field: str) -> str:
    parts = value.split("/") if type(value) is str else []
    if len(parts) != 2 or not all(_REPOSITORY_PART_RE.fullmatch(part or "") for part in parts):
        raise IssuancePolicyError(f"{field}: expected explicit owner/name")
    if value.strip() != value:
        raise IssuancePolicyError(f"{field}: surrounding whitespace is forbidden")
    return value


def _exact_scope(value: Any, *, field: str) -> str:
    if type(value) is not str or not value:
        raise IssuancePolicyError(f"{field}: exact scope must be non-empty text")
    if value.strip().casefold() in _RESERVED:
        raise IssuancePolicyError(f"{field}: wildcard and alias scopes are forbidden")
    return value


def _positive(value: Any, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise IssuancePolicyError(f"{field}: expected positive integer")
    return value


@dataclass(frozen=True, slots=True)
class AuthorityIssuancePolicyV0:
    """Narrow issuer configuration; no permissive defaults are provided."""

    root_id: str
    repository_identity: str
    maximum_issuable_level: AuthorityLevel
    allowed_network_ids: tuple[str, ...]
    allowed_taker_addresses: tuple[str, ...]
    allowed_venue_ids: tuple[str, ...]
    max_reservation_atomic: int
    max_cumulative_atomic: int
    max_grant_duration_s: int
    schema: str = "qntyspot.authority_root.v0.issuance_policy"

    def __post_init__(self) -> None:
        if type(self.root_id) is not str or not _PORTABLE_RE.fullmatch(self.root_id) or len(self.root_id) > 64:
            raise IssuancePolicyError("root_id: non-portable identity")
        if self.repository_identity != CANONICAL_REPOSITORY_IDENTITY:
            raise IssuancePolicyError("repository_identity must be CipherCuttle/QntySpot")
        _validate_repository_identity(self.repository_identity, field="repository_identity")
        if type(self.maximum_issuable_level) is not AuthorityLevel:
            raise IssuancePolicyError("maximum_issuable_level is not an AuthorityLevel")
        if self.maximum_issuable_level > AuthorityLevel.HUMAN_SIGNED_EXECUTION:
            raise IssuancePolicyError("maximum issuer authority exceeds HUMAN_SIGNED_EXECUTION")
        if type(self.allowed_network_ids) is not tuple or self.allowed_network_ids != (ALLOWED_NETWORK_ID,):
            raise IssuancePolicyError("allowed_network_ids must be exactly (evm:46630,)")
        for field_name, values in (
            ("allowed_network_ids", self.allowed_network_ids),
            ("allowed_taker_addresses", self.allowed_taker_addresses),
            ("allowed_venue_ids", self.allowed_venue_ids),
        ):
            if type(values) is not tuple or not values:
                raise IssuancePolicyError(f"{field_name} must be a non-empty tuple")
            for value in values:
                _exact_scope(value, field=field_name)
        _positive(self.max_reservation_atomic, field="max_reservation_atomic")
        _positive(self.max_cumulative_atomic, field="max_cumulative_atomic")
        if self.max_reservation_atomic > MAX_UINT256 or self.max_cumulative_atomic > MAX_UINT256:
            raise IssuancePolicyError("capital ceiling exceeds uint256")
        if self.max_reservation_atomic > self.max_cumulative_atomic:
            raise IssuancePolicyError("issuance per-action ceiling exceeds cumulative ceiling")
        _positive(self.max_grant_duration_s, field="max_grant_duration_s")
        if self.max_grant_duration_s > MAX_GRANT_DURATION_S:
            raise IssuancePolicyError("grant duration ceiling exceeds 3600 seconds")
        if type(self.schema) is not str or self.schema != "qntyspot.authority_root.v0.issuance_policy":
            raise IssuancePolicyError("unknown issuance policy schema")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "allowed_network_ids": sorted(self.allowed_network_ids),
            "allowed_taker_addresses": sorted(self.allowed_taker_addresses),
            "allowed_venue_ids": sorted(self.allowed_venue_ids),
            "max_cumulative_atomic": str(self.max_cumulative_atomic),
            "max_grant_duration_s": self.max_grant_duration_s,
            "max_reservation_atomic": str(self.max_reservation_atomic),
            "maximum_issuable_level": int(self.maximum_issuable_level),
            "repository_identity": self.repository_identity,
            "root_id": self.root_id,
            "schema": self.schema,
        }

    @property
    def policy_digest(self) -> str:
        return digest_object(self.canonical_object())


@dataclass(frozen=True, slots=True)
class AuthorityIssuanceRequestV0:
    """Caller-supplied content whose digest is bound to a request id."""

    repository_identity: str
    authority_policy: AuthorityPolicyRefV0
    issued_at_epoch_s: int

    def __post_init__(self) -> None:
        _validate_repository_identity(self.repository_identity, field="repository_identity")
        if type(self.authority_policy) is not AuthorityPolicyRefV0:
            raise IssuancePolicyError("authority_policy must be AuthorityPolicyRefV0")
        if type(self.issued_at_epoch_s) is not int or self.issued_at_epoch_s < 0:
            raise IssuancePolicyError("issued_at_epoch_s must be a non-negative integer")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "authority_policy": self.authority_policy.canonical_object(),
            "issued_at_epoch_s": self.issued_at_epoch_s,
            "repository_identity": self.repository_identity,
            "schema": "qntyspot.authority_root.v0.issuance_request",
        }

    @property
    def request_digest(self) -> str:
        return digest_object(self.canonical_object())


def assert_issuance_request_admissible(
    policy: AuthorityIssuancePolicyV0,
    request: AuthorityIssuanceRequestV0,
) -> None:
    """Reject every request outside the V0 issuer boundary."""
    if type(policy) is not AuthorityIssuancePolicyV0:
        raise IssuancePolicyError("issuer policy is not AuthorityIssuancePolicyV0")
    if type(request) is not AuthorityIssuanceRequestV0:
        raise IssuancePolicyError("issuance request is not AuthorityIssuanceRequestV0")
    if type(request.authority_policy) is not AuthorityPolicyRefV0:
        raise IssuancePolicyError("authority_policy is not AuthorityPolicyRefV0")
    if request.repository_identity != policy.repository_identity:
        raise IssuancePolicyError("issuance request targets a different repository")
    authority = request.authority_policy
    if authority.authority_root_id != policy.root_id:
        raise IssuancePolicyError("issuance request targets a different root")
    if authority.granted_level > policy.maximum_issuable_level:
        raise IssuancePolicyError("issuance level exceeds issuer policy")
    if authority.granted_level > AuthorityLevel.HUMAN_SIGNED_EXECUTION:
        raise IssuancePolicyError("AUTONOMOUS_BOUNDED_SIGNER is not issuable")
    if authority.permitted_network_id == FORBIDDEN_MAINNET_NETWORK_ID:
        raise IssuancePolicyError("evm:4663 mainnet is forbidden")
    if authority.permitted_network_id != ALLOWED_NETWORK_ID:
        raise IssuancePolicyError("issuance network is not Robinhood testnet evm:46630")
    if authority.permitted_network_id not in policy.allowed_network_ids:
        raise IssuancePolicyError("issuance network is not allowed")
    if authority.permitted_taker_address not in policy.allowed_taker_addresses:
        raise IssuancePolicyError("issuance taker is not allowed")
    if authority.permitted_venue_id not in policy.allowed_venue_ids:
        raise IssuancePolicyError("issuance venue is not allowed")
    if authority.max_reservation_atomic > policy.max_reservation_atomic:
        raise IssuancePolicyError("issuance reservation ceiling exceeds issuer policy")
    if authority.max_cumulative_atomic > policy.max_cumulative_atomic:
        raise IssuancePolicyError("issuance cumulative ceiling exceeds issuer policy")
    duration = authority.not_after_epoch_s - authority.not_before_epoch_s
    if duration <= 0:
        raise IssuancePolicyError("grant duration must be positive")
    if duration > MAX_GRANT_DURATION_S or duration > policy.max_grant_duration_s:
        raise IssuancePolicyError("issuance duration exceeds issuer policy")
    if not authority.not_before_epoch_s <= request.issued_at_epoch_s < authority.not_after_epoch_s:
        raise IssuancePolicyError("issued-at time must be inside grant interval")


def validate_request_id(request_id: Any) -> str:
    if type(request_id) is not str or not _REQUEST_ID_RE.fullmatch(request_id) or len(request_id) > 64:
        raise IssuancePolicyError("request_id must be a portable lowercase stable identifier")
    if request_id.casefold() in _RESERVED:
        raise IssuancePolicyError("request_id cannot be a wildcard or alias")
    return request_id


def snapshot_issuance_policy(policy: AuthorityIssuancePolicyV0) -> AuthorityIssuancePolicyV0:
    """Copy an exact issuer policy into concrete, validated built-in values."""
    if type(policy) is not AuthorityIssuancePolicyV0:
        raise IssuancePolicyError("issuer_policy is not AuthorityIssuancePolicyV0")
    return AuthorityIssuancePolicyV0(
        root_id=policy.root_id,
        repository_identity=policy.repository_identity,
        maximum_issuable_level=policy.maximum_issuable_level,
        allowed_network_ids=policy.allowed_network_ids,
        allowed_taker_addresses=policy.allowed_taker_addresses,
        allowed_venue_ids=policy.allowed_venue_ids,
        max_reservation_atomic=policy.max_reservation_atomic,
        max_cumulative_atomic=policy.max_cumulative_atomic,
        max_grant_duration_s=policy.max_grant_duration_s,
        schema=policy.schema,
    )


def snapshot_issuance_request(request: AuthorityIssuanceRequestV0) -> AuthorityIssuanceRequestV0:
    """Copy an exact request into concrete, validated built-in values."""
    if type(request) is not AuthorityIssuanceRequestV0:
        raise IssuancePolicyError("issuance request is not AuthorityIssuanceRequestV0")
    authority = request.authority_policy
    if type(authority) is not AuthorityPolicyRefV0:
        raise IssuancePolicyError("authority_policy is not AuthorityPolicyRefV0")
    return AuthorityIssuanceRequestV0(
        repository_identity=request.repository_identity,
        authority_policy=AuthorityPolicyRefV0(
            authority_root_id=authority.authority_root_id,
            granted_level=authority.granted_level,
            permitted_repository_commit=authority.permitted_repository_commit,
            permitted_implementation_digest=authority.permitted_implementation_digest,
            permitted_network_id=authority.permitted_network_id,
            permitted_taker_address=authority.permitted_taker_address,
            permitted_venue_id=authority.permitted_venue_id,
            max_reservation_atomic=authority.max_reservation_atomic,
            max_cumulative_atomic=authority.max_cumulative_atomic,
            not_before_epoch_s=authority.not_before_epoch_s,
            not_after_epoch_s=authority.not_after_epoch_s,
            schema=authority.schema,
        ),
        issued_at_epoch_s=request.issued_at_epoch_s,
    )
