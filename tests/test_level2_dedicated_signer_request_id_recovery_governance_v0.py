from __future__ import annotations

import hashlib
import sqlite3
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
from qnty_authority_root.errors import IssuancePolicyError
from qnty_authority_root.policy import validate_request_id


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/LEVEL2_DEDICATED_SIGNER_REQUEST_ID_RECOVERY_GOVERNANCE_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
PREDECESSOR = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_DEDICATED_SIGNER_GRANT_GOVERNANCE_V0.json"
PREDECESSOR_DIGEST = "244ab9959f734d628b3b2e19dc75d189cce9fba01d506441408ed8574cdc2a1d"
PRODUCTION_LEDGER = Path(
    "/home/swirky/.local/share/qnty-authority-root/production/v0/state/epoch-4/"
    "authority-root-issuance-v0-epoch-4.sqlite3"
)

OLD_REQUEST_ID = "qnty-submit-exact-signed-bytes-dedicated-signer-qualification-grant-v0"
NEW_REQUEST_ID = "qnty-l2-dedicated-signer-qualification-v0"
ROOT_ID = "qnty-authority-root-v0"
TAKER = "0x70680880335932a6ce4da357c32ed1a6fd5dc51f"
VENUE = "robinhood-chain-testnet-external-transaction"
COMMIT = "cf90df0b682d3ea850032ece342e362d56998d17"
IMPLEMENTATION = "b74ccdd99b5a5de4f11310014cf29100a60d07d8e350a43cd1f2dc2b678936f7"
POLICY_DIGEST = "3b6847ab54d37e6e7101f8882105dae870ba049b8b0f8616d785fa476ee2fd83"


class _TestSigner:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"recovery-test").digest())

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def policy() -> AuthorityIssuancePolicyV0:
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


def request() -> AuthorityIssuanceRequestV0:
    authority = AuthorityPolicyRefV0(
        authority_root_id=ROOT_ID,
        granted_level=AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES,
        permitted_repository_commit=COMMIT,
        permitted_implementation_digest=IMPLEMENTATION,
        permitted_network_id=ALLOWED_NETWORK_ID,
        permitted_taker_address=TAKER,
        permitted_venue_id=VENUE,
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        not_before_epoch_s=1000,
        not_after_epoch_s=1900,
    )
    return AuthorityIssuanceRequestV0(
        repository_identity="CipherCuttle/QntySpot",
        authority_policy=authority,
        issued_at_epoch_s=1000,
    )


def test_artifact_is_canonical_and_freezes_exact_successor() -> None:
    raw = ARTIFACT.read_bytes()
    document = strict_json_loads(raw)
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == f"{sha256_hex(raw)}  {ARTIFACT.name}\n"
    assert document["old_request_id_length"] == 70
    assert document["new_request_id_length"] == 41
    assert document["new_request_id"] == NEW_REQUEST_ID
    assert document["exact_successor_count"] == 1
    assert document["epoch_4_ledger_status"] == "INITIALIZED_EMPTY_AFTER_FAILED_UNREPRESENTABLE_REQUEST_ID"
    assert document["epoch_4_ledger_reuse_authorized"] == "YES"
    assert document["epoch_4_next_serial"] == 1
    assert document["epoch_5_required"] == "NO"
    assert document["issuer_policy_changed"] == "NO"
    assert document["issuer_policy_digest"] == POLICY_DIGEST
    assert document["staged_transaction_changed"] == "NO"
    assert document["production_grant_issued"] == "NO"
    assert document["blockchain_transaction"] == "NO"
    assert document["qntyspot_reservation_created"] == "NO"
    assert document["level_3_authorized"] == "NO"


def test_old_id_is_exactly_70_and_canonical_validator_rejects_it() -> None:
    assert len(OLD_REQUEST_ID) == 70
    with pytest.raises(IssuancePolicyError):
        validate_request_id(OLD_REQUEST_ID)


def test_new_id_is_exactly_41_portable_and_accepted() -> None:
    assert len(NEW_REQUEST_ID) == 41
    assert validate_request_id(NEW_REQUEST_ID) == NEW_REQUEST_ID


def test_successor_scope_is_exact_level_2_and_hostile_variants_fail() -> None:
    issuer_policy = policy()
    successor = request()
    assert issuer_policy.policy_digest == POLICY_DIGEST
    assert successor.authority_policy.granted_level is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert successor.authority_policy.permitted_taker_address == TAKER
    assert successor.authority_policy.permitted_network_id == "evm:46630"
    assert successor.authority_policy.permitted_venue_id == VENUE
    assert successor.authority_policy.permitted_repository_commit == COMMIT
    assert successor.authority_policy.permitted_implementation_digest == IMPLEMENTATION
    assert successor.authority_policy.max_reservation_atomic == 1
    assert successor.authority_policy.max_cumulative_atomic == 1
    assert successor.authority_policy.not_after_epoch_s - successor.authority_policy.not_before_epoch_s == 900
    assert_issuance_request_admissible(issuer_policy, successor)

    with pytest.raises(IssuancePolicyError):
        assert_issuance_request_admissible(
            issuer_policy,
            replace(successor, authority_policy=replace(successor.authority_policy, permitted_network_id="evm:4663")),
        )
    with pytest.raises(IssuancePolicyError):
        assert_issuance_request_admissible(
            issuer_policy,
            replace(
                successor,
                authority_policy=replace(
                    successor.authority_policy,
                    granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
                ),
            ),
        )


def test_old_id_cannot_issue_and_successor_gets_serial_one_in_temp_ledger(tmp_path: Path) -> None:
    db = tmp_path / "epoch-4-equivalent.sqlite3"
    issuer = AuthorityIssuer(
        db_path=db,
        issuer_policy=policy(),
        authority_epoch=4,
        minimum_authority_epoch=1,
        trust_config_version=1,
        signer=_TestSigner(),
    )
    with pytest.raises(IssuancePolicyError):
        issuer.issue(request_id=OLD_REQUEST_ID, request=request())
    assert issuer.list_committed() == ()
    receipt_bytes = issuer.issue(request_id=NEW_REQUEST_ID, request=request())
    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
    assert receipt.authority_epoch == 4
    assert receipt.serial == 1
    assert issuer.list_committed() == ((NEW_REQUEST_ID, 1, receipt.receipt_id),)


def test_production_epoch4_is_read_only_empty_and_predecessor_artifact_unchanged() -> None:
    assert PRODUCTION_LEDGER.is_file()
    with sqlite3.connect(f"file:{PRODUCTION_LEDGER}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM issuances").fetchone()[0] == 0
    assert hashlib.sha256(PREDECESSOR.read_bytes()).hexdigest() == PREDECESSOR_DIGEST


def test_recovery_declares_no_new_production_or_qntyspot_effects() -> None:
    document = strict_json_loads(ARTIFACT.read_bytes())
    assert document["authorityroot_runtime_source_changed"] == "NO"
    assert document["change_boundary"]["qntyspot_changed"] == "NO"
    assert document["change_boundary"]["existing_epoch_4_ledger_mutated"] == "NO"
    assert document["staged_transaction_continuity"]["signed_tx_hash"] == (
        "0xe560616f3f5708d19cd803667c8c596db84dae01d4acf9daaa44ddb85cf790f7"
    )
