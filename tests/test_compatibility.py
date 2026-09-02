from __future__ import annotations

import importlib
from dataclasses import replace

import pytest

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    AuthorityLevel,
    AuthorityIssuer,
    verify_receipt_signature,
)
from qnty_authority_root.canon import canonical_json_bytes, strict_json_loads
from qnty_authority_root.errors import CanonicalFormError

from conftest import NOW, TestOnlySigner as _TestOnlySigner


def test_canonical_json_is_deterministic_and_strict() -> None:
    assert canonical_json_bytes({"z": 1, "a": "x"}) == b'{"a":"x","z":1}'
    with pytest.raises(CanonicalFormError):
        strict_json_loads('{"a": 1.0}')
    with pytest.raises(CanonicalFormError, match="duplicate"):
        strict_json_loads('{"a": 1, "a": 2}')


def test_receipt_is_exactly_canonical_and_signature_verifies(issuer, request_factory) -> None:
    raw = issuer.issue(request_id="canonical-receipt", request=request_factory())
    receipt = AuthorityGrantReceiptV0.from_bytes(raw)

    assert receipt.serialized == raw
    assert set(receipt.to_object()) == {
        "authority_epoch",
        "authority_policy",
        "authority_policy_digest",
        "grant_id",
        "issued_at_epoch_s",
        "public_key_fingerprint",
        "receipt_id",
        "root_id",
        "schema",
        "serial",
        "signature",
        "signature_algorithm",
    }
    verify_receipt_signature(raw, issuer.public_anchor_bytes)


def test_signature_verification_binds_fingerprint_to_supplied_public_key(
    issuer, request_factory
) -> None:
    request = request_factory()
    raw = issuer.issue(request_id="fingerprint-binding", request=request)
    receipt = AuthorityGrantReceiptV0.from_bytes(raw)
    changed = replace(receipt, public_key_fingerprint="00" * 32)
    changed = replace(changed, signature=_TestOnlySigner().sign(changed.signed_body_bytes))
    with pytest.raises(Exception, match="fingerprint"):
        verify_receipt_signature(changed, issuer.public_anchor_bytes)


def test_trust_configuration_is_public_and_digest_pinned(issuer) -> None:
    root = issuer.trusted_root
    assert root.serialized_config == issuer.trust_config_bytes
    assert root.trust_config_digest == issuer.trust_config_digest
    assert root.anchor_bytes == issuer.public_anchor_bytes
    assert "private" not in root.serialized_config.decode()
    assert "seed" not in root.serialized_config.decode()


def test_exact_qntyspot_consumer_accepts_and_verifies_output(
    canonical_qntyspot, issuer, request_factory
) -> None:
    canonical_authority = importlib.import_module("qntyspot.authority_root")
    canonical_execution = importlib.import_module("qntyspot.execution_contract")

    raw = issuer.issue(request_id="canonical-consumer", request=request_factory())
    own_receipt = AuthorityGrantReceiptV0.from_bytes(raw)
    parsed = canonical_authority.AuthorityGrantReceiptV0.from_bytes(raw)
    assert parsed.serialized == raw
    assert parsed.authority_policy_digest == own_receipt.authority_policy_digest
    assert parsed.grant_id == own_receipt.grant_id
    assert parsed.receipt_id == own_receipt.receipt_id
    assert parsed.signed_body_bytes == own_receipt.signed_body_bytes

    trusted_root = canonical_authority.load_trusted_authority_root(
        issuer.trust_config_bytes,
        expected_config_digest=issuer.trust_config_digest,
        anchor_bytes=issuer.public_anchor_bytes,
    )
    session = canonical_execution.ExecutionSessionV0(
        repository_commit=parsed.authority_policy.permitted_repository_commit,
        implementation_digest=parsed.authority_policy.permitted_implementation_digest,
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id="22" * 32,
        authority_policy_digest=parsed.authority_policy_digest,
        taker_address=parsed.authority_policy.permitted_taker_address,
        network_id=parsed.authority_policy.permitted_network_id,
        venue_id=parsed.authority_policy.permitted_venue_id,
        venue_adapter_version="v0",
        started_at_epoch_s=NOW - 60,
        session_ordinal=0,
    )
    verified = canonical_authority.verify_authority_grant(
        receipt=raw,
        trusted_root=trusted_root,
        session=session,
        now_epoch_s=NOW,
    )
    assert verified.receipt_id == parsed.receipt_id
    assert verified.signed_body_digest == parsed.signed_body_digest
    assert (
        canonical_authority.effective_authority_level(
            source_phase_ceiling=canonical_execution.AuthorityLevel.SHADOW,
            verified_grant=verified,
            now_epoch_s=NOW,
        )
        is canonical_execution.AuthorityLevel.SHADOW
    )
    assert canonical_execution.Capability.PRODUCE_SIGNATURE not in canonical_authority.effective_capabilities(
        source_phase_ceiling=canonical_execution.AuthorityLevel.SHADOW,
        verified_grant=verified,
        now_epoch_s=NOW,
    )


def test_higher_grant_remains_shadow_at_current_qntyspot_ceiling(
    canonical_qntyspot, issuer, request_factory
) -> None:
    canonical_authority = importlib.import_module("qntyspot.authority_root")
    canonical_execution = importlib.import_module("qntyspot.execution_contract")
    high_request = request_factory(level=AuthorityLevel.HUMAN_SIGNED_EXECUTION)
    raw = issuer.issue(request_id="shadow-ceiling", request=high_request)
    receipt = canonical_authority.AuthorityGrantReceiptV0.from_bytes(raw)
    trusted_root = canonical_authority.load_trusted_authority_root(
        issuer.trust_config_bytes,
        expected_config_digest=issuer.trust_config_digest,
        anchor_bytes=issuer.public_anchor_bytes,
    )
    session = canonical_execution.ExecutionSessionV0(
        repository_commit=receipt.authority_policy.permitted_repository_commit,
        implementation_digest=receipt.authority_policy.permitted_implementation_digest,
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id="33" * 32,
        authority_policy_digest=receipt.authority_policy_digest,
        taker_address=receipt.authority_policy.permitted_taker_address,
        network_id=receipt.authority_policy.permitted_network_id,
        venue_id=receipt.authority_policy.permitted_venue_id,
        venue_adapter_version="v0",
        started_at_epoch_s=NOW - 60,
    )
    verified = canonical_authority.verify_authority_grant(
        receipt=receipt, trusted_root=trusted_root, session=session, now_epoch_s=NOW
    )
    assert canonical_authority.effective_authority_level(
        source_phase_ceiling=canonical_execution.PHASE_GRANTED_AUTHORITY_LEVEL,
        verified_grant=verified,
        now_epoch_s=NOW,
    ) is canonical_execution.AuthorityLevel.SHADOW
