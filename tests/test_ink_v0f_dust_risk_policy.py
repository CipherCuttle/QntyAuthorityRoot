from __future__ import annotations

from dataclasses import replace
from fractions import Fraction

import pytest

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    AuthorityIssuer,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    IssuancePolicyError,
)
from qnty_authority_root.risk import (
    INK_V0F_BANKED_PROFIT_RATIO,
    INK_V0F_DUST_RISK_POLICY,
    INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC,
    INK_V0F_MAX_ENTRY_ATOMIC,
    INK_V0F_NETWORK_ID,
    INK_V0F_PROFIT_RECYCLE_RATIO,
    INK_V0F_VENUE_ID,
    QNTYSPOT_V0F_IMPLEMENTATION_DIGEST,
    QNTYSPOT_V0F_REPOSITORY_COMMIT,
    assert_ink_v0f_authority_policy_admissible,
)


def _issuer_policy(taker: str) -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id="qnty-authority-root-v0",
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        allowed_network_ids=(INK_V0F_NETWORK_ID,),
        allowed_taker_addresses=(taker,),
        allowed_venue_ids=(INK_V0F_VENUE_ID,),
        max_reservation_atomic=INK_V0F_MAX_ENTRY_ATOMIC,
        max_cumulative_atomic=INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC,
        max_grant_duration_s=INK_V0F_DUST_RISK_POLICY.max_grant_duration_s,
    )


def _request(taker: str) -> AuthorityIssuanceRequestV0:
    return AuthorityIssuanceRequestV0(
        repository_identity="CipherCuttle/QntySpot",
        authority_policy=AuthorityPolicyRefV0(
            authority_root_id="qnty-authority-root-v0",
            granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
            permitted_repository_commit=QNTYSPOT_V0F_REPOSITORY_COMMIT,
            permitted_implementation_digest=QNTYSPOT_V0F_IMPLEMENTATION_DIGEST,
            permitted_network_id=INK_V0F_NETWORK_ID,
            permitted_taker_address=taker,
            permitted_venue_id=INK_V0F_VENUE_ID,
            max_reservation_atomic=INK_V0F_MAX_ENTRY_ATOMIC,
            max_cumulative_atomic=INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC,
            not_before_epoch_s=1_700_000_000,
            not_after_epoch_s=1_700_000_900,
        ),
        issued_at_epoch_s=1_700_000_100,
    )


def test_frozen_ink_dust_policy_is_single_position_non_compounding() -> None:
    policy = INK_V0F_DUST_RISK_POLICY
    assert policy.network_id == "evm:57073"
    assert policy.venue_id == "inkyswap-v2-ink-mainnet"
    assert policy.max_entry_atomic == 1_000_000_000_000_000
    assert policy.max_cumulative_entry_atomic == 1_000_000_000_000_000
    assert policy.max_open_positions_global == 1
    assert policy.max_open_positions_per_network == 1
    assert policy.max_open_positions_per_instrument == 1
    assert policy.max_in_flight_entries == 1
    assert policy.max_price_impact_bps == 100
    assert policy.max_slippage_bps == 50
    assert INK_V0F_PROFIT_RECYCLE_RATIO == Fraction(0, 1)
    assert INK_V0F_BANKED_PROFIT_RATIO == Fraction(1, 1)
    assert len(policy.policy_digest) == 64


def test_exact_ink_dust_request_is_issuable_offline(signer, tmp_path) -> None:
    taker = "0x00000000000000000000000000000000000000aa"
    issuer = AuthorityIssuer(
        db_path=tmp_path / "ink-v0f.sqlite3",
        issuer_policy=_issuer_policy(taker),
        authority_epoch=9,
        minimum_authority_epoch=9,
        trust_config_version=2,
        signer=signer,
    )
    raw = issuer.issue(request_id="ink-v0f-dust", request=_request(taker))
    receipt = AuthorityGrantReceiptV0.from_bytes(raw)
    assert receipt.authority_policy.permitted_network_id == INK_V0F_NETWORK_ID
    assert receipt.authority_policy.permitted_venue_id == INK_V0F_VENUE_ID
    assert receipt.authority_policy.max_reservation_atomic == INK_V0F_MAX_ENTRY_ATOMIC
    assert receipt.authority_policy.max_cumulative_atomic == INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("permitted_repository_commit", "0" * 40, "unreviewed QntySpot commit"),
        ("permitted_implementation_digest", "0" * 64, "implementation digest"),
        ("permitted_venue_id", "other-venue", "venue"),
        ("max_reservation_atomic", INK_V0F_MAX_ENTRY_ATOMIC + 1, "entry cap"),
        (
            "max_cumulative_atomic",
            INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC + 1,
            "cumulative capital",
        ),
    ),
)
def test_ink_dust_scope_widening_fails_closed(field: str, value, message: str) -> None:
    taker = "0x00000000000000000000000000000000000000aa"
    request = _request(taker)
    widened = replace(request.authority_policy, **{field: value})
    with pytest.raises(IssuancePolicyError, match=message):
        assert_ink_v0f_authority_policy_admissible(
            widened,
            repository_identity=request.repository_identity,
        )


def test_ink_dust_autonomous_signer_and_long_grant_fail_closed() -> None:
    taker = "0x00000000000000000000000000000000000000aa"
    request = _request(taker)
    with pytest.raises(IssuancePolicyError, match="autonomous"):
        assert_ink_v0f_authority_policy_admissible(
            replace(
                request.authority_policy,
                granted_level=AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER,
            ),
            repository_identity=request.repository_identity,
        )
    with pytest.raises(IssuancePolicyError, match="duration"):
        assert_ink_v0f_authority_policy_admissible(
            replace(request.authority_policy, not_after_epoch_s=1_700_001_000),
            repository_identity=request.repository_identity,
        )


def test_ink_issuer_policy_itself_cannot_be_wider_than_risk_envelope() -> None:
    taker = "0x00000000000000000000000000000000000000aa"
    with pytest.raises(IssuancePolicyError, match="reservation|dust"):
        replace(_issuer_policy(taker), max_reservation_atomic=INK_V0F_MAX_ENTRY_ATOMIC + 1)
    with pytest.raises(IssuancePolicyError, match="one taker"):
        replace(_issuer_policy(taker), allowed_taker_addresses=(taker, "0x00000000000000000000000000000000000000bb"))
