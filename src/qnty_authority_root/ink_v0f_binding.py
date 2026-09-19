"""Exact Ink V0F taker + implementation binding for first dust-live grant prep.

This module is offline governance only. It does not sign, submit, broadcast,
read secrets, or move capital.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canon import canonical_json_bytes, digest_object
from .contract import AuthorityLevel, AuthorityPolicyRefV0
from .errors import IssuancePolicyError
from .risk import (
    INK_V0F_DUST_RISK_POLICY,
    INK_V0F_DUST_RISK_POLICY_DIGEST,
    INK_V0F_NETWORK_ID,
    INK_V0F_VENUE_ID,
)

INK_V0F_HISTORICAL_GRANT_PREPARATION_SCHEMA = (
    "qnty.authority_root.ink_v0f_grant_preparation.v0"
)
INK_V0F_HISTORICAL_QNTYSPOT_COMMIT = "7b10a1a74607a9d2bf35438b89f02755b689d4ec"
INK_V0F_HISTORICAL_QNTYSPOT_IMPLEMENTATION_DIGEST = (
    "0df376585a874e773d65b5dda0010a3d2eca28c541da474c6ca1cc60b3e929ec"
)
INK_V0F_HISTORICAL_GRANT_PREPARATION_DIGEST = (
    "de565373e0e7630f72cc4e86e6ce8104aff618b76720b6c2c0f72ea8a16867a8"
)

INK_V0F_LEVEL3_V0_GRANT_PREPARATION_SCHEMA = (
    "qnty.authority_root.ink_v0f_level3_grant_preparation.v0"
)
INK_V0F_LEVEL3_V0_QNTYSPOT_COMMIT = "79d66648b80173f71c2e5a3b307984d525edf479"
INK_V0F_LEVEL3_V0_QNTYSPOT_IMPLEMENTATION_DIGEST = (
    "ac408e3c0ccfdac8106b3c5aef44904e07504112aacc49a2097affdd3e025aea"
)
INK_V0F_LEVEL3_V0_GRANT_PREPARATION_DIGEST = (
    "b0655a0a5e83dd55264a3fc10a5c0be75ae31782b2ab84ee2ebbe54d09f13233"
)

INK_V0F_GRANT_PREPARATION_SCHEMA = (
    "qnty.authority_root.ink_v0f_level3_grant_preparation.v1"
)
INK_V0F_AUTHORITY_ROOT_ID = "qnty-authority-root-v0"
INK_V0F_REPOSITORY_IDENTITY = "CipherCuttle/QntySpot"
INK_V0F_QNTYSPOT_COMMIT = "af5edb2eaf9e6ab55a8295da4a9cb5f2e7d549b6"
INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST = (
    "f0f3dfb14ddc5be1b2b500fdd4bf134f37dc63c56116e8be39a5496b95db707a"
)
INK_V0F_TAKER_ADDRESS = "0x3e604be3293d930069d0805e85379e0ca5fa01cb"
INK_V0F_GRANT_PREPARATION_DIGEST = (
    "00ab5e8721d4ccd59d2ada0f7574a6b3368f930341cb72d9b8d3c00da865ab3d"
)


@dataclass(frozen=True, slots=True)
class InkV0FGrantPreparationV1:
    authority_root_id: str = INK_V0F_AUTHORITY_ROOT_ID
    repository_identity: str = INK_V0F_REPOSITORY_IDENTITY
    permitted_repository_commit: str = INK_V0F_QNTYSPOT_COMMIT
    permitted_implementation_digest: str = INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST
    permitted_network_id: str = INK_V0F_NETWORK_ID
    permitted_taker_address: str = INK_V0F_TAKER_ADDRESS
    permitted_venue_id: str = INK_V0F_VENUE_ID
    maximum_issuable_level: AuthorityLevel = AuthorityLevel.HUMAN_SIGNED_EXECUTION
    max_reservation_atomic: int = INK_V0F_DUST_RISK_POLICY.max_entry_atomic
    max_cumulative_atomic: int = INK_V0F_DUST_RISK_POLICY.max_cumulative_entry_atomic
    max_grant_duration_s: int = INK_V0F_DUST_RISK_POLICY.max_grant_duration_s
    risk_policy_digest: str = INK_V0F_DUST_RISK_POLICY_DIGEST
    schema: str = INK_V0F_GRANT_PREPARATION_SCHEMA

    def __post_init__(self) -> None:
        expected = (
            ("authority_root_id", self.authority_root_id, INK_V0F_AUTHORITY_ROOT_ID),
            ("repository_identity", self.repository_identity, INK_V0F_REPOSITORY_IDENTITY),
            (
                "permitted_repository_commit",
                self.permitted_repository_commit,
                INK_V0F_QNTYSPOT_COMMIT,
            ),
            (
                "permitted_implementation_digest",
                self.permitted_implementation_digest,
                INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
            ),
            ("permitted_network_id", self.permitted_network_id, INK_V0F_NETWORK_ID),
            ("permitted_taker_address", self.permitted_taker_address, INK_V0F_TAKER_ADDRESS),
            ("permitted_venue_id", self.permitted_venue_id, INK_V0F_VENUE_ID),
            (
                "maximum_issuable_level",
                self.maximum_issuable_level,
                AuthorityLevel.HUMAN_SIGNED_EXECUTION,
            ),
            (
                "max_reservation_atomic",
                self.max_reservation_atomic,
                INK_V0F_DUST_RISK_POLICY.max_entry_atomic,
            ),
            (
                "max_cumulative_atomic",
                self.max_cumulative_atomic,
                INK_V0F_DUST_RISK_POLICY.max_cumulative_entry_atomic,
            ),
            (
                "max_grant_duration_s",
                self.max_grant_duration_s,
                INK_V0F_DUST_RISK_POLICY.max_grant_duration_s,
            ),
            (
                "risk_policy_digest",
                self.risk_policy_digest,
                INK_V0F_DUST_RISK_POLICY_DIGEST,
            ),
            ("schema", self.schema, INK_V0F_GRANT_PREPARATION_SCHEMA),
        )
        for field, actual, frozen in expected:
            if type(actual) is not type(frozen) or actual != frozen:
                raise IssuancePolicyError(
                    f"{field}: Ink V0F grant preparation is frozen"
                )

    def canonical_object(self) -> dict[str, Any]:
        return {
            "authority_root_id": self.authority_root_id,
            "max_cumulative_atomic": str(self.max_cumulative_atomic),
            "max_grant_duration_s": self.max_grant_duration_s,
            "max_reservation_atomic": str(self.max_reservation_atomic),
            "maximum_issuable_level": int(self.maximum_issuable_level),
            "permitted_implementation_digest": self.permitted_implementation_digest,
            "permitted_network_id": self.permitted_network_id,
            "permitted_repository_commit": self.permitted_repository_commit,
            "permitted_taker_address": self.permitted_taker_address,
            "permitted_venue_id": self.permitted_venue_id,
            "repository_identity": self.repository_identity,
            "risk_policy_digest": self.risk_policy_digest,
            "schema": self.schema,
        }

    @property
    def serialized(self) -> bytes:
        return canonical_json_bytes(self.canonical_object())

    @property
    def preparation_digest(self) -> str:
        return digest_object(self.canonical_object())


# Backward-compatible import alias for callers that imported the original
# class name. The current frozen defaults/schema are V1.
InkV0FGrantPreparationV0 = InkV0FGrantPreparationV1

INK_V0F_GRANT_PREPARATION = InkV0FGrantPreparationV1()
if INK_V0F_GRANT_PREPARATION.preparation_digest != INK_V0F_GRANT_PREPARATION_DIGEST:
    raise RuntimeError("Ink V0F grant preparation digest invariant failed")


def assert_ink_v0f_exact_authority_binding(authority: AuthorityPolicyRefV0) -> None:
    """Reject any Ink V0F receipt scope that differs from the reviewed tuple."""

    if type(authority) is not AuthorityPolicyRefV0:
        raise IssuancePolicyError("Ink V0F authority must be AuthorityPolicyRefV0")

    prep = INK_V0F_GRANT_PREPARATION
    exact = (
        ("authority_root_id", authority.authority_root_id, prep.authority_root_id),
        ("granted_level", authority.granted_level, prep.maximum_issuable_level),
        (
            "permitted_repository_commit",
            authority.permitted_repository_commit,
            prep.permitted_repository_commit,
        ),
        (
            "permitted_implementation_digest",
            authority.permitted_implementation_digest,
            prep.permitted_implementation_digest,
        ),
        ("permitted_network_id", authority.permitted_network_id, prep.permitted_network_id),
        (
            "permitted_taker_address",
            authority.permitted_taker_address,
            prep.permitted_taker_address,
        ),
        ("permitted_venue_id", authority.permitted_venue_id, prep.permitted_venue_id),
        ("max_reservation_atomic", authority.max_reservation_atomic, prep.max_reservation_atomic),
        ("max_cumulative_atomic", authority.max_cumulative_atomic, prep.max_cumulative_atomic),
    )
    for field, actual, expected in exact:
        if actual != expected:
            raise IssuancePolicyError(
                f"Ink V0F {field} differs from the reviewed grant preparation"
            )

    duration = authority.not_after_epoch_s - authority.not_before_epoch_s
    if duration <= 0 or duration > prep.max_grant_duration_s:
        raise IssuancePolicyError(
            "Ink V0F grant duration differs from the reviewed duration ceiling"
        )
