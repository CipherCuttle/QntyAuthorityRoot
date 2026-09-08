from __future__ import annotations

import hashlib
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qnty_authority_root import (
    ALLOWED_NETWORK_ID,
    AuthorityGrantReceiptV0,
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    AuthorityIssuer,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    assert_issuance_request_admissible,
)
from qnty_authority_root.canon import canonical_json_bytes, sha256_hex, strict_json_loads
from qnty_authority_root.errors import AuthorityRootError, IssuanceConflictError, IssuancePolicyError
from qnty_authority_root.policy import validate_request_id


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_SCHEMA_REPAIR_SUCCESSOR_GOVERNANCE_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
PREDECESSOR_ARTIFACT = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_DEDICATED_SIGNER_GRANT_GOVERNANCE_V0.json"
PREDECESSOR_ARTIFACT_DIGEST = "244ab9959f734d628b3b2e19dc75d189cce9fba01d506441408ed8574cdc2a1d"
PARENT = "5116a2af8fccd7278bba44c618cff3fedeaa27f1"
ROOT_ID = "qnty-authority-root-v0"
OLD_REQUEST_ID = "qnty-submit-exact-signed-bytes-dedicated-signer-qualification-grant-v0"
PREDECESSOR_REQUEST_ID = "qnty-l2-dedicated-signer-qualification-v0"
SUCCESSOR_REQUEST_ID = "qnty-l2-dedicated-signer-qualification-v0r1"
TAKER = "0x70680880335932a6ce4da357c32ed1a6fd5dc51f"
VENUE = "robinhood-chain-testnet-external-transaction"
OLD_COMMIT = "cf90df0b682d3ea850032ece342e362d56998d17"
REPAIRED_COMMIT = "e01c5da205eedaa67c301ff30425f9d17f2fbc54"
OLD_IMPLEMENTATION = "b74ccdd99b5a5de4f11310014cf29100a60d07d8e350a43cd1f2dc2b678936f7"
REPAIRED_IMPLEMENTATION = "d289031abf773114bc9dc8c57528367531961051c66f1b6efd28c9ee4addcb2a"
POLICY_DIGEST = "3b6847ab54d37e6e7101f8882105dae870ba049b8b0f8616d785fa476ee2fd83"
REPAIR_ARTIFACT_DIGEST = "1d1365615ac96bfd8b93c70aac88e78a29095509de6be8690bd2a1a66d355296"
SIGNED_BYTES_SHA256 = "f97f2c68d98a902fc6df96398cd7cc73cbeccb7a81f24d5a4d262585c9d590d6"
SIGNED_TX_HASH = "0xe560616f3f5708d19cd803667c8c596db84dae01d4acf9daaa44ddb85cf790f7"
TRUST_CONFIG_DIGEST = "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"


class _TestOnlySigner:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"schema-repair-successor-test").digest())

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def _document() -> dict[str, object]:
    raw = ARTIFACT.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == f"{sha256_hex(raw)}  {ARTIFACT.name}\n"
    return document


def _policy() -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES,
        allowed_network_ids=(ALLOWED_NETWORK_ID,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE,),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=900,
    )


def _request(*, commit: str = REPAIRED_COMMIT, implementation: str = REPAIRED_IMPLEMENTATION) -> AuthorityIssuanceRequestV0:
    return AuthorityIssuanceRequestV0(
        repository_identity="CipherCuttle/QntySpot",
        authority_policy=AuthorityPolicyRefV0(
            authority_root_id=ROOT_ID,
            granted_level=AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES,
            permitted_repository_commit=commit,
            permitted_implementation_digest=implementation,
            permitted_network_id=ALLOWED_NETWORK_ID,
            permitted_taker_address=TAKER,
            permitted_venue_id=VENUE,
            max_reservation_atomic=1,
            max_cumulative_atomic=1,
            not_before_epoch_s=1000,
            not_after_epoch_s=1900,
        ),
        issued_at_epoch_s=1000,
    )


def _successor_gate(request_id: str, request: AuthorityIssuanceRequestV0) -> None:
    if request_id != SUCCESSOR_REQUEST_ID:
        raise IssuancePolicyError("only one exact successor request is governed")
    if request != _request():
        raise IssuancePolicyError("successor scope is not the repaired exact scope")
    assert_issuance_request_admissible(_policy(), request)


def test_artifact_is_canonical_and_binds_only_the_repaired_successor() -> None:
    document = _document()
    assert document["schema"] == "qnty.authority_root.submit_exact_signed_bytes_schema_repair_successor_governance.v0"
    assert document["canonical_parent"] == PARENT
    assert document["predecessor"] == {
        "authority_epoch": 4,
        "blockchain_transaction": "NO",
        "grant_duration_seconds": 900,
        "issued_at_epoch_s": 1788877927,
        "not_after_epoch_s": 1788878827,
        "reissuable": "NO",
        "request_id": PREDECESSOR_REQUEST_ID,
        "request_id_reusable": "NO",
        "serial": 1,
        "status": "EXPIRED_UNUSED_BLOCKED_BY_QNTYSPOT_SCHEMA_COMPATIBILITY",
    }
    assert document["successor"]["authority_epoch"] == 4
    assert document["successor"]["expected_serial"] == 2
    assert document["successor"]["request_id"] == SUCCESSOR_REQUEST_ID
    assert document["successor"]["request_id_length"] == 43
    assert document["successor"]["count_authorized"] == 1
    assert document["successor"]["scope"] == {
        "implementation_digest": REPAIRED_IMPLEMENTATION,
        "network_id": ALLOWED_NETWORK_ID,
        "repository_commit": REPAIRED_COMMIT,
        "taker_address": TAKER,
        "venue_id": VENUE,
    }
    assert document["qntyspot"]["previous_commit"] == OLD_COMMIT
    assert document["qntyspot"]["previous_implementation_digest"] == OLD_IMPLEMENTATION
    assert document["qntyspot"]["repaired_commit"] == REPAIRED_COMMIT
    assert document["qntyspot"]["repaired_implementation_digest"] == REPAIRED_IMPLEMENTATION
    assert document["qntyspot"]["repair_artifact_digest"] == REPAIR_ARTIFACT_DIGEST
    assert document["issuer_policy_digest"] == POLICY_DIGEST
    assert document["production_schema_v4_migration_before_issuance"] == "REQUIRED"
    assert document["production_grant_issued"] == "NO"
    assert document["production_qntyspot_ledger_modified"] == "NO"
    assert document["blockchain_transaction"] == "NO"
    assert document["authority_boundary"]["level_3_authorized"] == "NO"
    assert b"/home/" not in ARTIFACT.read_bytes()
    assert b"-----BEGIN" not in ARTIFACT.read_bytes()


def test_predecessor_artifact_and_policy_are_not_mutated() -> None:
    raw = PREDECESSOR_ARTIFACT.read_bytes()
    assert sha256_hex(raw) == PREDECESSOR_ARTIFACT_DIGEST
    parent_raw = subprocess.run(
        ["git", "show", f"{PARENT}:artifacts/SUBMIT_EXACT_SIGNED_BYTES_DEDICATED_SIGNER_GRANT_GOVERNANCE_V0.json"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    assert raw == parent_raw


def test_request_ids_have_exact_canonical_status() -> None:
    assert len(OLD_REQUEST_ID) == 70
    with pytest.raises(IssuancePolicyError):
        validate_request_id(OLD_REQUEST_ID)
    assert len(SUCCESSOR_REQUEST_ID) == 43
    assert validate_request_id(SUCCESSOR_REQUEST_ID) == SUCCESSOR_REQUEST_ID
    assert SUCCESSOR_REQUEST_ID.count("-") == 5


def test_successor_scope_is_exact_level_2_and_hostile_variants_fail() -> None:
    request = _request()
    _successor_gate(SUCCESSOR_REQUEST_ID, request)
    assert request.authority_policy.granted_level is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert request.authority_policy.max_reservation_atomic == 1
    assert request.authority_policy.max_cumulative_atomic == 1
    assert request.authority_policy.not_after_epoch_s - request.authority_policy.not_before_epoch_s == 900

    variants = (
        {"permitted_repository_commit": OLD_COMMIT},
        {"permitted_implementation_digest": OLD_IMPLEMENTATION},
        {"permitted_network_id": "evm:4663"},
        {"permitted_network_id": "*"},
        {"permitted_taker_address": "0x1324d87e24e1657f6fe6805de814bb6873052106"},
        {"permitted_venue_id": "*"},
        {"max_reservation_atomic": 2, "max_cumulative_atomic": 2},
        {"granted_level": AuthorityLevel.HUMAN_SIGNED_EXECUTION},
    )
    for changes in variants:
        with pytest.raises(AuthorityRootError):
            _successor_gate(
                SUCCESSOR_REQUEST_ID,
                replace(request, authority_policy=replace(request.authority_policy, **changes)),
            )
    with pytest.raises(IssuancePolicyError):
        _successor_gate(PREDECESSOR_REQUEST_ID, request)


def test_successor_is_serial_two_after_one_historical_predecessor(tmp_path: Path) -> None:
    issuer = AuthorityIssuer(
        db_path=tmp_path / "temporary-epoch-4.sqlite3",
        issuer_policy=_policy(),
        authority_epoch=4,
        minimum_authority_epoch=1,
        trust_config_version=1,
        signer=_TestOnlySigner(),
    )
    issuer.issue(request_id="historical-predecessor", request=_request())
    receipt_bytes = issuer.issue(request_id=SUCCESSOR_REQUEST_ID, request=_request())
    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
    assert receipt.authority_epoch == 4
    assert receipt.serial == 2
    assert [row[1] for row in issuer.list_committed()] == [1, 2]
    with pytest.raises(IssuanceConflictError):
        issuer.issue(request_id=SUCCESSOR_REQUEST_ID, request=replace(_request(), issued_at_epoch_s=1001))
    assert len(issuer.list_committed()) == 2


def test_predecessor_cannot_be_reissued_and_production_effects_are_forbidden(tmp_path: Path) -> None:
    issuer = AuthorityIssuer(
        db_path=tmp_path / "temporary-empty-ledger.sqlite3",
        issuer_policy=_policy(),
        authority_epoch=4,
        minimum_authority_epoch=1,
        trust_config_version=1,
        signer=_TestOnlySigner(),
    )
    with pytest.raises(IssuancePolicyError):
        issuer.issue(request_id=OLD_REQUEST_ID, request=_request())
    assert issuer.list_committed() == ()
    document = _document()
    assert document["new_authority_epoch"] == "NO"
    assert document["new_ledger"] == "NO"
    assert document["epoch_5_required"] == "NO"
    assert document["successor_count_authorized"] == 1


def test_staged_transaction_identity_and_boundaries_are_unchanged() -> None:
    document = _document()
    staged = document["staged_transaction"]
    assert staged == {
        "calldata_length": 36,
        "calldata_sha256": "b5fc21f6bc329ddf071208dd8075a63a2ec4974eef3b05cb7510835498f23baf",
        "chain_id": 46630,
        "from": TAKER,
        "gas_limit": 100000,
        "gas_price": 20000000,
        "nonce": 0,
        "signed_bytes_sha256": SIGNED_BYTES_SHA256,
        "signed_tx_hash": SIGNED_TX_HASH,
        "staged_transaction_changed": "NO",
        "to": "0x33e4191705c386532ba27cbf171db86919200b94",
        "value": 0,
    }
    assert document["authority_boundary"] == {
        "effective_authority": "MIN(SOURCE_PHASE_CEILING,VERIFIED_EXTERNAL_GRANT_LEVEL)",
        "level_3_authorized": "NO",
        "permitted_level": "SUBMIT_EXACT_SIGNED_BYTES",
        "private_key_access": "NO",
    }
