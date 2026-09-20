from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from qnty_authority_root import (
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    IssuancePolicyError,
    assert_issuance_request_admissible,
)
from qnty_authority_root.ink_v0f_binding import (
    INK_V0F_GRANT_PREPARATION,
    INK_V0F_GRANT_PREPARATION_DIGEST,
    INK_V0F_HISTORICAL_GRANT_PREPARATION_DIGEST,
    INK_V0F_HISTORICAL_QNTYSPOT_COMMIT,
    INK_V0F_HISTORICAL_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_LEVEL3_V0_GRANT_PREPARATION_DIGEST,
    INK_V0F_LEVEL3_V0_QNTYSPOT_COMMIT,
    INK_V0F_LEVEL3_V0_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_LEVEL3_V1_GRANT_PREPARATION_DIGEST,
    INK_V0F_LEVEL3_V1_QNTYSPOT_COMMIT,
    INK_V0F_LEVEL3_V1_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_LEVEL3_V2_GRANT_PREPARATION_DIGEST,
    INK_V0F_LEVEL3_V2_QNTYSPOT_COMMIT,
    INK_V0F_LEVEL3_V2_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_LEVEL3_V3_GRANT_PREPARATION_DIGEST,
    INK_V0F_LEVEL3_V3_QNTYSPOT_COMMIT,
    INK_V0F_LEVEL3_V3_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_LEVEL3_V4_GRANT_PREPARATION_DIGEST,
    INK_V0F_LEVEL3_V4_QNTYSPOT_COMMIT,
    INK_V0F_LEVEL3_V4_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_QNTYSPOT_COMMIT,
    INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_TAKER_ADDRESS,
    InkV0FGrantPreparationV5,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "INK_V0F_LEVEL3_GRANT_PREPARATION_V5.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
PREVIOUS_LEVEL3_V4_ARTIFACT = ROOT / "artifacts" / "INK_V0F_LEVEL3_GRANT_PREPARATION_V4.json"
PREVIOUS_LEVEL3_V4_SIDECAR = PREVIOUS_LEVEL3_V4_ARTIFACT.with_suffix(".sha256")
PREVIOUS_LEVEL3_V3_ARTIFACT = ROOT / "artifacts" / "INK_V0F_LEVEL3_GRANT_PREPARATION_V3.json"
PREVIOUS_LEVEL3_V3_SIDECAR = PREVIOUS_LEVEL3_V3_ARTIFACT.with_suffix(".sha256")
PREVIOUS_LEVEL3_V2_ARTIFACT = ROOT / "artifacts" / "INK_V0F_LEVEL3_GRANT_PREPARATION_V2.json"
PREVIOUS_LEVEL3_V2_SIDECAR = PREVIOUS_LEVEL3_V2_ARTIFACT.with_suffix(".sha256")
PREVIOUS_LEVEL3_V1_ARTIFACT = ROOT / "artifacts" / "INK_V0F_LEVEL3_GRANT_PREPARATION_V1.json"
PREVIOUS_LEVEL3_V1_SIDECAR = PREVIOUS_LEVEL3_V1_ARTIFACT.with_suffix(".sha256")
PREVIOUS_LEVEL3_ARTIFACT = ROOT / "artifacts" / "INK_V0F_LEVEL3_GRANT_PREPARATION_V0.json"
PREVIOUS_LEVEL3_SIDECAR = PREVIOUS_LEVEL3_ARTIFACT.with_suffix(".sha256")
HISTORICAL_ARTIFACT = ROOT / "artifacts" / "INK_V0F_GRANT_PREPARATION_V0.json"
HISTORICAL_SIDECAR = HISTORICAL_ARTIFACT.with_suffix(".sha256")


def issuer_policy() -> AuthorityIssuancePolicyV0:
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


def request() -> AuthorityIssuanceRequestV0:
    prep = INK_V0F_GRANT_PREPARATION
    return AuthorityIssuanceRequestV0(
        repository_identity=prep.repository_identity,
        authority_policy=AuthorityPolicyRefV0(
            authority_root_id=prep.authority_root_id,
            granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
            permitted_repository_commit=prep.permitted_repository_commit,
            permitted_implementation_digest=prep.permitted_implementation_digest,
            permitted_network_id=prep.permitted_network_id,
            permitted_taker_address=prep.permitted_taker_address,
            permitted_venue_id=prep.permitted_venue_id,
            max_reservation_atomic=prep.max_reservation_atomic,
            max_cumulative_atomic=prep.max_cumulative_atomic,
            not_before_epoch_s=1_700_000_000,
            not_after_epoch_s=1_700_000_900,
        ),
        issued_at_epoch_s=1_700_000_001,
    )


def test_exact_user_taker_and_qntyspot_identity_are_frozen() -> None:
    prep = INK_V0F_GRANT_PREPARATION
    assert INK_V0F_TAKER_ADDRESS == "0x3e604be3293d930069d0805e85379e0ca5fa01cb"
    assert INK_V0F_QNTYSPOT_COMMIT == "b25fa90a7fc0aa3304f17907b354cbab40c11ce3"
    assert INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST == (
        "3412d290f5ff0a3b1ae1915f071a503fccd9c5e386e7d4ef0335c9079c4c0e21"
    )
    assert prep.maximum_issuable_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert prep.max_reservation_atomic == 1_000_000_000_000_000
    assert prep.max_cumulative_atomic == 1_000_000_000_000_000
    assert prep.max_grant_duration_s == 900


def test_preparation_artifact_is_exact_and_digest_bound() -> None:
    raw = ARTIFACT.read_bytes()
    assert raw == INK_V0F_GRANT_PREPARATION.serialized
    assert INK_V0F_GRANT_PREPARATION.preparation_digest == INK_V0F_GRANT_PREPARATION_DIGEST
    assert SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_GRANT_PREPARATION_DIGEST}  {ARTIFACT.name}\n"
    )


def test_previous_level3_v4_preparation_artifact_remains_immutable() -> None:
    raw = PREVIOUS_LEVEL3_V4_ARTIFACT.read_bytes()
    assert INK_V0F_LEVEL3_V4_QNTYSPOT_COMMIT.encode() in raw
    assert INK_V0F_LEVEL3_V4_QNTYSPOT_IMPLEMENTATION_DIGEST.encode() in raw
    from qnty_authority_root import sha256_hex

    assert sha256_hex(raw) == INK_V0F_LEVEL3_V4_GRANT_PREPARATION_DIGEST
    assert PREVIOUS_LEVEL3_V4_SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_LEVEL3_V4_GRANT_PREPARATION_DIGEST}  "
        f"{PREVIOUS_LEVEL3_V4_ARTIFACT.name}\n"
    )


def test_previous_level3_v3_preparation_artifact_remains_immutable() -> None:
    raw = PREVIOUS_LEVEL3_V3_ARTIFACT.read_bytes()
    assert INK_V0F_LEVEL3_V3_QNTYSPOT_COMMIT.encode() in raw
    assert INK_V0F_LEVEL3_V3_QNTYSPOT_IMPLEMENTATION_DIGEST.encode() in raw
    from qnty_authority_root import sha256_hex

    assert sha256_hex(raw) == INK_V0F_LEVEL3_V3_GRANT_PREPARATION_DIGEST
    assert PREVIOUS_LEVEL3_V3_SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_LEVEL3_V3_GRANT_PREPARATION_DIGEST}  "
        f"{PREVIOUS_LEVEL3_V3_ARTIFACT.name}\n"
    )


def test_previous_level3_v2_preparation_artifact_remains_immutable() -> None:
    raw = PREVIOUS_LEVEL3_V2_ARTIFACT.read_bytes()
    assert INK_V0F_LEVEL3_V2_QNTYSPOT_COMMIT.encode() in raw
    assert INK_V0F_LEVEL3_V2_QNTYSPOT_IMPLEMENTATION_DIGEST.encode() in raw
    from qnty_authority_root import sha256_hex

    assert sha256_hex(raw) == INK_V0F_LEVEL3_V2_GRANT_PREPARATION_DIGEST
    assert PREVIOUS_LEVEL3_V2_SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_LEVEL3_V2_GRANT_PREPARATION_DIGEST}  "
        f"{PREVIOUS_LEVEL3_V2_ARTIFACT.name}\n"
    )


def test_previous_level3_v1_preparation_artifact_remains_immutable() -> None:
    raw = PREVIOUS_LEVEL3_V1_ARTIFACT.read_bytes()
    assert INK_V0F_LEVEL3_V1_QNTYSPOT_COMMIT.encode() in raw
    assert INK_V0F_LEVEL3_V1_QNTYSPOT_IMPLEMENTATION_DIGEST.encode() in raw
    from qnty_authority_root import sha256_hex

    assert sha256_hex(raw) == INK_V0F_LEVEL3_V1_GRANT_PREPARATION_DIGEST
    assert PREVIOUS_LEVEL3_V1_SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_LEVEL3_V1_GRANT_PREPARATION_DIGEST}  "
        f"{PREVIOUS_LEVEL3_V1_ARTIFACT.name}\n"
    )


def test_previous_level3_preparation_artifact_remains_immutable() -> None:
    raw = PREVIOUS_LEVEL3_ARTIFACT.read_bytes()
    assert INK_V0F_LEVEL3_V0_QNTYSPOT_COMMIT.encode() in raw
    assert INK_V0F_LEVEL3_V0_QNTYSPOT_IMPLEMENTATION_DIGEST.encode() in raw
    from qnty_authority_root import sha256_hex

    assert sha256_hex(raw) == INK_V0F_LEVEL3_V0_GRANT_PREPARATION_DIGEST
    assert PREVIOUS_LEVEL3_SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_LEVEL3_V0_GRANT_PREPARATION_DIGEST}  "
        f"{PREVIOUS_LEVEL3_ARTIFACT.name}\n"
    )


def test_historical_preparation_artifact_remains_immutable() -> None:
    raw = HISTORICAL_ARTIFACT.read_bytes()
    assert INK_V0F_HISTORICAL_QNTYSPOT_COMMIT.encode() in raw
    assert INK_V0F_HISTORICAL_QNTYSPOT_IMPLEMENTATION_DIGEST.encode() in raw
    from qnty_authority_root import sha256_hex

    assert sha256_hex(raw) == INK_V0F_HISTORICAL_GRANT_PREPARATION_DIGEST
    assert HISTORICAL_SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_HISTORICAL_GRANT_PREPARATION_DIGEST}  {HISTORICAL_ARTIFACT.name}\n"
    )


@pytest.mark.parametrize(
    ("commit", "digest"),
    (
        (
            INK_V0F_HISTORICAL_QNTYSPOT_COMMIT,
            INK_V0F_HISTORICAL_QNTYSPOT_IMPLEMENTATION_DIGEST,
        ),
        (
            INK_V0F_LEVEL3_V0_QNTYSPOT_COMMIT,
            INK_V0F_LEVEL3_V0_QNTYSPOT_IMPLEMENTATION_DIGEST,
        ),
        (
            INK_V0F_LEVEL3_V1_QNTYSPOT_COMMIT,
            INK_V0F_LEVEL3_V1_QNTYSPOT_IMPLEMENTATION_DIGEST,
        ),
        (
            INK_V0F_LEVEL3_V2_QNTYSPOT_COMMIT,
            INK_V0F_LEVEL3_V2_QNTYSPOT_IMPLEMENTATION_DIGEST,
        ),
        (
            INK_V0F_LEVEL3_V3_QNTYSPOT_COMMIT,
            INK_V0F_LEVEL3_V3_QNTYSPOT_IMPLEMENTATION_DIGEST,
        ),
        (
            INK_V0F_LEVEL3_V4_QNTYSPOT_COMMIT,
            INK_V0F_LEVEL3_V4_QNTYSPOT_IMPLEMENTATION_DIGEST,
        ),
    ),
)
def test_prior_qntyspot_identities_are_no_longer_issuable(
    commit: str,
    digest: str,
) -> None:
    req = request()
    stale = replace(
        req.authority_policy,
        permitted_repository_commit=commit,
        permitted_implementation_digest=digest,
    )
    with pytest.raises(IssuancePolicyError, match="reviewed grant preparation"):
        assert_issuance_request_admissible(
            issuer_policy(),
            replace(req, authority_policy=stale),
        )


def test_exact_prepared_request_is_admissible() -> None:
    assert_issuance_request_admissible(issuer_policy(), request())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("permitted_taker_address", "0x00000000000000000000000000000000000000aa", "taker"),
        ("permitted_repository_commit", "0" * 40, "repository_commit"),
        ("permitted_implementation_digest", "0" * 64, "implementation_digest"),
        ("permitted_venue_id", "other-venue", "venue"),
    ),
)
def test_different_live_identity_fails_closed(field: str, value, message: str) -> None:
    req = request()
    changed = replace(req.authority_policy, **{field: value})
    with pytest.raises(IssuancePolicyError, match=message):
        assert_issuance_request_admissible(
            issuer_policy(),
            replace(req, authority_policy=changed),
        )


def test_different_taker_cannot_be_put_in_ink_issuer_policy() -> None:
    prep = INK_V0F_GRANT_PREPARATION
    with pytest.raises(IssuancePolicyError, match="reviewed taker"):
        AuthorityIssuancePolicyV0(
            root_id=prep.authority_root_id,
            repository_identity=prep.repository_identity,
            maximum_issuable_level=prep.maximum_issuable_level,
            allowed_network_ids=(prep.permitted_network_id,),
            allowed_taker_addresses=("0x00000000000000000000000000000000000000aa",),
            allowed_venue_ids=(prep.permitted_venue_id,),
            max_reservation_atomic=prep.max_reservation_atomic,
            max_cumulative_atomic=prep.max_cumulative_atomic,
            max_grant_duration_s=prep.max_grant_duration_s,
        )


def test_preparation_object_cannot_be_reconstructed_differently() -> None:
    with pytest.raises(IssuancePolicyError, match="frozen"):
        InkV0FGrantPreparationV5(
            permitted_taker_address="0x00000000000000000000000000000000000000aa"
        )
