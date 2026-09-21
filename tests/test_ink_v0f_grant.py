from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qnty_authority_root import (
    AuthorityLevel,
    IssuanceConflictError,
    IssuancePolicyError,
)
from qnty_authority_root.ink_v0f_binding import (
    INK_V0F_GRANT_PREPARATION,
    INK_V0F_GRANT_PREPARATION_DIGEST,
    INK_V0F_LEVEL3_V8_GRANT_PREPARATION_DIGEST,
    INK_V0F_LEVEL3_V8_GRANT_PREPARATION_SCHEMA,
    INK_V0F_LEVEL3_V8_QNTYSPOT_COMMIT,
    INK_V0F_LEVEL3_V8_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_QNTYSPOT_COMMIT,
    INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_TAKER_ADDRESS,
    InkV0FGrantPreparationV9,
)
from qnty_authority_root.ink_v0f_grant import (
    build_ink_v0f_request,
    ink_v0f_issuer_policy,
    ink_v0f_request_id,
    issue_ink_v0f_grant,
)


class EphemeralTestSigner:
    def __init__(self) -> None:
        seed = hashlib.sha256(b"ink-v0f-short-lived-grant-tests").digest()
        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def test_v9_binding_advances_only_qntyspot_identity_and_preserves_v8_history() -> None:
    assert INK_V0F_LEVEL3_V8_GRANT_PREPARATION_SCHEMA.endswith(".v8")
    assert INK_V0F_LEVEL3_V8_QNTYSPOT_COMMIT == (
        "05c11fee96fdcbf392e4a90b78f8e0207a96ac58"
    )
    assert INK_V0F_LEVEL3_V8_QNTYSPOT_IMPLEMENTATION_DIGEST == (
        "eccb92637e9f496b65efd8baeabf35c9d4828474d3ee95da69b93b81af968990"
    )
    assert INK_V0F_LEVEL3_V8_GRANT_PREPARATION_DIGEST == (
        "18903624f8f78b55859cdada4a2b8255f22673f428a019172abe2c8bd9706459"
    )

    assert INK_V0F_QNTYSPOT_COMMIT == "91ec941d7e89fc44da0e4501b52f47fc65962020"
    assert INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST == (
        "dbcbab558ad591d195fcee06951389d1eb566fed40d9b211b8e5578f61b14f81"
    )
    assert INK_V0F_GRANT_PREPARATION.schema.endswith(".v9")
    assert INK_V0F_GRANT_PREPARATION_DIGEST == (
        "8437e963680952795073a90773845cfbd7ba3b053c5268e2310d16996cd06b15"
    )
    assert INK_V0F_GRANT_PREPARATION.preparation_digest == (
        INK_V0F_GRANT_PREPARATION_DIGEST
    )

def test_request_builder_uses_only_the_frozen_first_grant_tuple() -> None:
    request = build_ink_v0f_request(issued_at_epoch_s=1_800_000_000, duration_s=900)
    authority = request.authority_policy
    assert authority.granted_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert authority.permitted_repository_commit == INK_V0F_QNTYSPOT_COMMIT
    assert authority.permitted_implementation_digest == INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST
    assert authority.permitted_taker_address == INK_V0F_TAKER_ADDRESS
    assert authority.max_reservation_atomic == 1_000_000_000_000_000
    assert authority.max_cumulative_atomic == 1_000_000_000_000_000
    assert authority.not_before_epoch_s == 1_800_000_000
    assert authority.not_after_epoch_s == 1_800_000_900
    assert request.issued_at_epoch_s == 1_800_000_000


@pytest.mark.parametrize("duration", (0, 901))
def test_request_builder_rejects_invalid_grant_duration(duration: int) -> None:
    with pytest.raises(IssuancePolicyError):
        build_ink_v0f_request(
            issued_at_epoch_s=1_800_000_000,
            duration_s=duration,
        )


def test_request_identity_is_explicit_and_deterministic() -> None:
    assert ink_v0f_request_id(
        issued_at_epoch_s=1_800_000_000,
        duration_s=900,
    ) == "ink-v0f-1800000000-900"


def test_issuer_policy_is_exactly_the_frozen_profile() -> None:
    policy = ink_v0f_issuer_policy()
    assert policy.allowed_taker_addresses == (INK_V0F_TAKER_ADDRESS,)
    assert policy.maximum_issuable_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert policy.max_reservation_atomic == 1_000_000_000_000_000
    assert policy.max_cumulative_atomic == 1_000_000_000_000_000
    assert policy.max_grant_duration_s == 900


def test_one_shot_issue_is_signed_durable_and_idempotent(tmp_path) -> None:
    signer = EphemeralTestSigner()
    kwargs = dict(
        db_path=tmp_path / "ink-v0f.sqlite3",
        signer=signer,
        authority_epoch=10,
        minimum_authority_epoch=10,
        trust_config_version=3,
        issued_at_epoch_s=1_800_000_000,
        duration_s=900,
    )
    first = issue_ink_v0f_grant(**kwargs)
    second = issue_ink_v0f_grant(**kwargs)
    assert first == second
    receipt = first.receipt
    assert receipt.authority_policy.granted_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert receipt.authority_policy.permitted_taker_address == INK_V0F_TAKER_ADDRESS
    assert first.public_anchor_bytes == signer.public_key_bytes
    assert len(first.trust_config_digest) == 64
    assert first.request_id == "ink-v0f-1800000000-900"


def test_overlapping_ink_grants_fail_closed_atomically(tmp_path) -> None:
    signer = EphemeralTestSigner()
    base = dict(
        db_path=tmp_path / "overlap.sqlite3",
        signer=signer,
        authority_epoch=10,
        minimum_authority_epoch=10,
        trust_config_version=3,
        duration_s=900,
    )
    first = issue_ink_v0f_grant(
        **base,
        issued_at_epoch_s=1_800_000_000,
    )
    assert first.receipt.authority_policy.not_after_epoch_s == 1_800_000_900
    with pytest.raises(IssuanceConflictError, match="overlapping Ink V0F"):
        issue_ink_v0f_grant(
            **base,
            issued_at_epoch_s=1_800_000_100,
        )

    second = issue_ink_v0f_grant(
        **base,
        issued_at_epoch_s=1_800_000_900,
    )
    assert second.receipt.serial == 2


def test_concurrent_overlapping_ink_grants_allow_exactly_one_commit(tmp_path) -> None:
    signer = EphemeralTestSigner()
    db_path = tmp_path / "concurrent-overlap.sqlite3"

    def issue(start: int):
        try:
            bundle = issue_ink_v0f_grant(
                db_path=db_path,
                signer=signer,
                authority_epoch=10,
                minimum_authority_epoch=10,
                trust_config_version=3,
                issued_at_epoch_s=start,
                duration_s=900,
            )
            return ("ok", bundle.receipt.serial)
        except IssuanceConflictError as exc:
            return ("conflict", str(exc))

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(issue, (1_800_000_000, 1_800_000_100)))

    assert sorted(result[0] for result in outcomes) == ["conflict", "ok"]
    assert [result[1] for result in outcomes if result[0] == "ok"] == [1]
