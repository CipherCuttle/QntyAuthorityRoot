from __future__ import annotations

from dataclasses import replace

import pytest

from qnty_authority_root import AuthorityLevel, AuthorityPolicyRefV0, IssuancePolicyError
from qnty_authority_root.policy import assert_issuance_request_admissible


def test_mainnet_is_rejected(issuer, request_factory) -> None:
    request = request_factory(network="evm:4663")
    with pytest.raises(IssuancePolicyError, match="4663|mainnet"):
        issuer.issue(request_id="reject-mainnet", request=request)


def test_only_robinhood_testnet_is_allowed(issuer, request_factory) -> None:
    with pytest.raises(IssuancePolicyError, match="network"):
        issuer.issue(request_id="reject-other-network", request=request_factory(network="evm:1"))


def test_autonomous_signer_is_rejected(issuer, request_factory) -> None:
    request = request_factory(level=AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER)
    with pytest.raises(IssuancePolicyError, match="AUTONOMOUS|authority|level"):
        issuer.issue(request_id="reject-autonomous", request=request)


def test_duration_over_3600_is_rejected(issuer, request_factory) -> None:
    request = request_factory(not_before_epoch_s=100, not_after_epoch_s=100 + 3601, issued_at_epoch_s=100)
    with pytest.raises(IssuancePolicyError, match="duration"):
        issuer.issue(request_id="reject-long-grant", request=request)


@pytest.mark.parametrize("not_before,not_after", [(100, 100), (101, 100)])
def test_zero_or_negative_duration_is_rejected(request_factory, not_before, not_after) -> None:
    with pytest.raises(Exception, match="expire|duration"):
        request_factory(
            not_before_epoch_s=not_before,
            not_after_epoch_s=not_after,
            issued_at_epoch_s=not_before,
        )


@pytest.mark.parametrize("field,value", [("venue", "latest"), ("venue", " any "), ("taker", "ANY")])
def test_wildcard_and_alias_scopes_are_rejected(request_factory, field, value) -> None:
    with pytest.raises(Exception, match="wildcard|alias|canonical|portable|address"):
        request_factory(**{field: value})


def test_wrong_root_repository_taker_and_venue_are_rejected(issuer, request_factory) -> None:
    cases = (
        ("wrong-root", {"root_id": "other-authority-root"}, "root"),
        ("wrong-repository", {"repository_identity": "CipherCuttle/Other"}, "repository"),
        ("wrong-taker", {"taker": "0x00000000000000000000000000000000000000bb"}, "taker"),
        ("wrong-venue", {"venue": "other-venue"}, "venue"),
    )
    for request_id, changes, message in cases:
        with pytest.raises(IssuancePolicyError, match=message):
            issuer.issue(request_id=request_id, request=request_factory(**changes))


def test_capital_ceiling_violations_are_rejected(issuer, request_factory) -> None:
    with pytest.raises(IssuancePolicyError, match="reservation"):
        issuer.issue(
            request_id="reject-per-action-cap",
            request=request_factory(max_reservation_atomic=1_000_001, max_cumulative_atomic=2_000_000),
        )
    with pytest.raises(IssuancePolicyError, match="cumulative"):
        issuer.issue(
            request_id="reject-cumulative-cap",
            request=request_factory(max_reservation_atomic=1_000_000, max_cumulative_atomic=4_000_001),
        )


def test_malformed_commit_and_repository_identity_are_rejected(request_factory) -> None:
    with pytest.raises(Exception, match="commit"):
        request_factory(commit="not-a-commit")
    with pytest.raises(IssuancePolicyError, match="owner/name"):
        request_factory(repository_identity="not-a-repository")


def test_policy_scope_aliases_are_rejected_at_construction(issuer_policy) -> None:
    with pytest.raises(IssuancePolicyError, match="wildcard|alias"):
        replace(issuer_policy, allowed_venue_ids=("*",))


def test_request_policy_digest_is_exact_and_not_repaired(request_factory) -> None:
    request = request_factory()
    assert request.authority_policy.authority_policy_digest
    assert request.request_digest
    with pytest.raises(Exception):
        AuthorityPolicyRefV0(
            authority_root_id=request.authority_policy.authority_root_id,
            granted_level=request.authority_policy.granted_level,
            permitted_repository_commit="A" * 40,
            permitted_implementation_digest=request.authority_policy.permitted_implementation_digest,
            permitted_network_id=request.authority_policy.permitted_network_id,
            permitted_taker_address=request.authority_policy.permitted_taker_address,
            permitted_venue_id=request.authority_policy.permitted_venue_id,
            max_reservation_atomic=1,
            max_cumulative_atomic=1,
            not_before_epoch_s=1,
            not_after_epoch_s=2,
        )
