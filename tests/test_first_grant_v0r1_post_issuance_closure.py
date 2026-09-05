from __future__ import annotations

import importlib
import io
import os
import sqlite3
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

import pytest

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    canonical_json_bytes,
    sha256_hex,
    strict_json_loads,
    verify_receipt_signature,
)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/FIRST_GRANT_EXPIRED_INTENT_RECOVERY_ISSUANCE_V0R1_CLOSURE.json"
SIDECAR = ROOT / "artifacts/FIRST_GRANT_EXPIRED_INTENT_RECOVERY_ISSUANCE_V0R1_CLOSURE.sha256"
PRODUCTION_ROOT = Path(
    os.environ.get(
        "QNTY_AUTHORITY_ROOT_PRODUCTION",
        "/home/swirky/.local/share/qnty-authority-root/production/v0",
    )
)

AUTHORITY_ROOT_CANONICAL = "93c141371454702c5ffd327cc4ff87b44338f68a"
FROZEN_ISSUER_SOURCE = "3f9c31ea03d599b79009c459fc5242189fb2f77f"
QNTYSPOT_COMMIT = "6a23171e790e8ae95c9b7bf6c2b55fe6d06a66bf"
IMPLEMENTATION_DIGEST = "d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de"
PREREQUISITE_DIGEST = "ce277412228aeaa8b7a204b2e1265ac6c49727d96e3f05174f34e82cef845824"
FIRST_GRANT_DESIGN_DIGEST = "1d2b4c14c1d4f3f24f91240e82d14f315060f0b0a77cda3e80a76f11027a5cc8"
RECOVERY_DESIGN_DIGEST = "f1a032b96c431001410e96245fcd9ea4dc0e19846e13a8e95a62effb296692da"
ISSUER_POLICY_DIGEST = "680b0bc9076413e7d09f53d9259503ac33482a978c7546f8da2b0c4a21a2b7ed"
TRUST_CONFIG_DIGEST = "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
PUBLIC_KEY_FINGERPRINT = "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe"
ROOT_ID = "qnty-authority-root-v0"
REQUEST_ID = "qnty-first-production-shadow-grant-v0r1"
ORIGINAL_REQUEST_ID = "qnty-first-production-shadow-grant-v0"
REQUEST_INTENT_DIGEST = "83801f647b6b54cc71267b25a9cc1f0153ddeeab150919ddfdacd656ffc04850"
ORIGINAL_INTENT_DIGEST = "b37bbf8e64f3302635c8a26bee719f98fdeb0f336a45ffbf7d6a246e3763664a"
AUTHORITY_POLICY_DIGEST = "7308394a0598099ff5e146e14f5b916d2ce2e49a7c75630254d80fa98edfe69a"
ORIGINAL_AUTHORITY_POLICY_DIGEST = "223942bceec7536266094e54922f8fba2c62d08d90d085b09ba3420d4d33c8d2"
ISSUED_AT = 1788621087
NOT_AFTER = 1788621387
RECEIPT_ID = "e33c11d648113f03a00c7afacbfa34e6b95cc891be2a2166d6216d0b1a0c5871"
RECEIPT_SHA256 = "83a075f507f1944e129ffea73f145fa430f24293ce40268bca9f2c69819d4e09"
ANCHOR = bytes.fromhex(
    "b8254f9dc8aec38671a5c6b851e461a0d676a31e48805f6c4bd01ca035756cde"
)

AUTHORITY_POLICY: dict[str, Any] = {
    "authority_root_id": ROOT_ID,
    "granted_level": 0,
    "max_cumulative_atomic": "1",
    "max_reservation_atomic": "1",
    "not_after_epoch_s": NOT_AFTER,
    "not_before_epoch_s": ISSUED_AT,
    "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
    "permitted_network_id": "evm:46630",
    "permitted_repository_commit": QNTYSPOT_COMMIT,
    "permitted_taker_address": "0x1324d87e24e1657f6fe6805de814bb6873052106",
    "permitted_venue_id": "zero-x-swap-v2-robinhood-chain",
    "schema": "qntyspot.program_b.v0.authority_policy",
}

RECEIPT_OBJECT: dict[str, Any] = {
    "authority_epoch": 1,
    "authority_policy": AUTHORITY_POLICY,
    "authority_policy_digest": AUTHORITY_POLICY_DIGEST,
    "grant_id": "a5755d54847c3b6df2ec7496492b966653a83ff310bf1313f1da7ac01d536a7e",
    "issued_at_epoch_s": ISSUED_AT,
    "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
    "receipt_id": RECEIPT_ID,
    "root_id": ROOT_ID,
    "schema": "qntyspot.authority_root.v0.grant",
    "serial": 1,
    "signature": (
        "c42846842c197beb8370cafe88b38a06ce8f2b046bb7f93754753194d46f0c50"
        "237b63e10d7cfcdaeb967662b6426186d487576daf4dd0b5a1499166679b9a04"
    ),
    "signature_algorithm": "Ed25519",
}

TRUST_CONFIG_OBJECT: dict[str, Any] = {
    "minimum_authority_epoch": 1,
    "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
    "root_id": ROOT_ID,
    "schema": "qntyspot.authority_root.v0.trust_config",
    "signature_algorithm": "Ed25519",
    "trust_config_version": 1,
}

SUCCESSOR_INTENT_OBJECT: dict[str, Any] = {
    "authority_epoch": 1,
    "authority_policy": AUTHORITY_POLICY,
    "authority_policy_digest": AUTHORITY_POLICY_DIGEST,
    "canonical_declaration_digest": "f11b20d7b417571eb235010989c5479e2fd2c31a16d1e06df453ea870ebcba06",
    "first_grant_design_artifact_digest": FIRST_GRANT_DESIGN_DIGEST,
    "frozen_issuer_source_canonical": FROZEN_ISSUER_SOURCE,
    "granted_level": "SHADOW",
    "issued_at_epoch_s": ISSUED_AT,
    "issuer_policy_digest": ISSUER_POLICY_DIGEST,
    "max_cumulative_atomic": "1",
    "max_reservation_atomic": "1",
    "not_after_epoch_s": NOT_AFTER,
    "not_before_epoch_s": ISSUED_AT,
    "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
    "permitted_network_id": "evm:46630",
    "permitted_repository_commit": QNTYSPOT_COMMIT,
    "permitted_taker_address": "0x1324d87e24e1657f6fe6805de814bb6873052106",
    "permitted_venue_id": "zero-x-swap-v2-robinhood-chain",
    "prerequisite_artifact_digest": PREREQUISITE_DIGEST,
    "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
    "qnty_authority_root_canonical": AUTHORITY_ROOT_CANONICAL,
    "recovery_design_artifact_digest": RECOVERY_DESIGN_DIGEST,
    "request_id": REQUEST_ID,
    "root_id": ROOT_ID,
    "schema": "qnty.authority_root.first_grant_request_intent.v0r1",
    "supersedes_authority_policy_digest": ORIGINAL_AUTHORITY_POLICY_DIGEST,
    "supersedes_request_id": ORIGINAL_REQUEST_ID,
    "supersedes_request_intent_digest": ORIGINAL_INTENT_DIGEST,
    "supersedes_request_status": "TERMINAL_EXPIRED_UNCOMMITTED",
}

ORIGINAL_INTENT_OBJECT: dict[str, Any] = {
    "authority_epoch": 1,
    "authority_policy": {
        **AUTHORITY_POLICY,
        "not_after_epoch_s": 1788572385,
        "not_before_epoch_s": 1788572085,
    },
    "authority_policy_digest": ORIGINAL_AUTHORITY_POLICY_DIGEST,
    "design_artifact_digest": FIRST_GRANT_DESIGN_DIGEST,
    "granted_level": "SHADOW",
    "issued_at_epoch_s": 1788572085,
    "issuer_policy_digest": ISSUER_POLICY_DIGEST,
    "max_cumulative_atomic": "1",
    "max_reservation_atomic": "1",
    "not_after_epoch_s": 1788572385,
    "not_before_epoch_s": 1788572085,
    "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
    "permitted_network_id": "evm:46630",
    "permitted_repository_commit": QNTYSPOT_COMMIT,
    "permitted_taker_address": "0x1324d87e24e1657f6fe6805de814bb6873052106",
    "permitted_venue_id": "zero-x-swap-v2-robinhood-chain",
    "prerequisite_artifact_digest": PREREQUISITE_DIGEST,
    "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
    "qnty_authority_root_canonical": FROZEN_ISSUER_SOURCE,
    "request_id": ORIGINAL_REQUEST_ID,
    "root_id": ROOT_ID,
    "schema": "qnty.authority_root.first_grant_request_intent.v0",
}

EXPECTED_ZERO_EFFECT_COUNTERS = {
    "ACCOUNT_SIGNING_MATERIAL_ACCESSED": "NO",
    "APPROVALS": 0,
    "AUTHORITY_RECEIPT_SIGNATURES": 1,
    "BLOCKCHAIN_SIGNATURES": 0,
    "BROADCASTS": 0,
    "CAPITAL_DEPLOYED": 0,
    "CHAINLINK_CALLS": 0,
    "RESERVATIONS": 0,
    "ROBINHOOD_CALLS": 0,
    "RPC_CALLS": 0,
    "TRANSACTION_SERIALIZATIONS": 0,
    "TRANSACTION_SUBMISSIONS": 0,
    "ZEROX_CALLS": 0,
}


def _load_artifact() -> tuple[bytes, dict[str, Any]]:
    raw = ARTIFACT.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    return raw, document


def _qntyspot_repository() -> Path | None:
    for candidate in (
        ROOT.parent / "QntySpot",
        ROOT.parent.parent / "repos/QntySpot",
    ):
        if (candidate / ".git").exists():
            return candidate
    return None


@pytest.fixture(scope="module")
def canonical_qntyspot(tmp_path_factory: pytest.TempPathFactory):
    repository = _qntyspot_repository()
    if repository is None:
        pytest.skip("canonical QntySpot repository is not provisioned")
    checkout = tmp_path_factory.mktemp("canonical-qntyspot")
    archive = subprocess.run(
        ["git", "-C", str(repository), "archive", QNTYSPOT_COMMIT],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(checkout)
    sys.path.insert(0, str(checkout))
    for name in list(sys.modules):
        if name == "qntyspot" or name.startswith("qntyspot."):
            del sys.modules[name]
    try:
        yield importlib.import_module("qntyspot")
    finally:
        sys.path.remove(str(checkout))
        for name in list(sys.modules):
            if name == "qntyspot" or name.startswith("qntyspot."):
                del sys.modules[name]


def test_closure_artifact_is_canonical_and_sidecar_bound() -> None:
    raw, document = _load_artifact()
    assert canonical_json_bytes(document) == raw
    assert sha256_hex(raw) == SIDECAR.read_text(encoding="ascii").split()[0]
    assert SIDECAR.read_text(encoding="ascii") == (
        f"{sha256_hex(raw)}  {ARTIFACT.name}\n"
    )
    assert b"/home/" not in raw
    assert b"BEGIN " not in raw
    assert document["status"] == "CLOSED_PASS"
    assert document["closure_status"] == "CLOSED_PASS"


def test_closure_binds_exact_public_intent_receipt_and_inputs() -> None:
    _, document = _load_artifact()
    assert document["authority_root_canonical_sha"] == AUTHORITY_ROOT_CANONICAL
    assert document["frozen_issuer_source_sha"] == FROZEN_ISSUER_SOURCE
    assert document["qntyspot_canonical_sha"] == QNTYSPOT_COMMIT
    assert document["qntyspot_implementation_digest"] == IMPLEMENTATION_DIGEST
    assert document["prerequisite_digest"] == PREREQUISITE_DIGEST
    assert document["first_grant_design_digest"] == FIRST_GRANT_DESIGN_DIGEST
    assert document["recovery_design_digest"] == RECOVERY_DESIGN_DIGEST
    assert document["issuer_policy_digest"] == ISSUER_POLICY_DIGEST
    assert document["trust_config_digest"] == TRUST_CONFIG_DIGEST
    assert document["public_key_fingerprint"] == PUBLIC_KEY_FINGERPRINT
    assert document["authority_policy"] == AUTHORITY_POLICY
    assert document["successor_intent_digest"] == REQUEST_INTENT_DIGEST
    assert sha256_hex(canonical_json_bytes(SUCCESSOR_INTENT_OBJECT)) == REQUEST_INTENT_DIGEST
    assert sha256_hex(canonical_json_bytes(ORIGINAL_INTENT_OBJECT)) == ORIGINAL_INTENT_DIGEST
    assert document["request_id"] == REQUEST_ID
    assert document["successor_request_id"] == REQUEST_ID
    assert document["original_request_id"] == ORIGINAL_REQUEST_ID
    assert document["original_status"] == "TERMINAL_EXPIRED_UNCOMMITTED"
    assert document["original_ledger_rows"] == 0
    assert document["original_receipt"] == "NONE"
    assert document["original_reissuable"] == "NO"


def test_public_receipt_signature_is_valid_without_private_material() -> None:
    receipt_bytes = canonical_json_bytes(RECEIPT_OBJECT)
    assert sha256_hex(receipt_bytes) == RECEIPT_SHA256
    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
    verify_receipt_signature(receipt, ANCHOR)
    assert receipt.receipt_id == RECEIPT_ID
    assert receipt.serial == 1
    assert receipt.authority_policy_digest == AUTHORITY_POLICY_DIGEST


def test_historical_qntyspot_replay_passes_and_current_expiry_fails(
    canonical_qntyspot,
) -> None:
    qs_authority_root = importlib.import_module("qntyspot.authority_root")
    qs_execution_contract = importlib.import_module("qntyspot.execution_contract")
    receipt_bytes = canonical_json_bytes(RECEIPT_OBJECT)
    root = qs_authority_root.load_trusted_authority_root(
        canonical_json_bytes(TRUST_CONFIG_OBJECT),
        expected_config_digest=TRUST_CONFIG_DIGEST,
        anchor_bytes=ANCHOR,
    )
    receipt = qs_authority_root.AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
    session = qs_execution_contract.ExecutionSessionV0(
        repository_commit=QNTYSPOT_COMMIT,
        implementation_digest=IMPLEMENTATION_DIGEST,
        runtime_identity="authority-receipt-proof-v0",
        db_schema_version=0,
        policy_id="00" * 32,
        authority_policy_digest=receipt.authority_policy_digest,
        taker_address="0x1324d87e24e1657f6fe6805de814bb6873052106",
        network_id="evm:46630",
        venue_id="zero-x-swap-v2-robinhood-chain",
        venue_adapter_version="authority-receipt-proof-v0",
        started_at_epoch_s=ISSUED_AT,
        session_ordinal=0,
    )
    verified = qs_authority_root.verify_authority_grant(
        receipt=receipt,
        trusted_root=root,
        session=session,
        now_epoch_s=ISSUED_AT,
    )
    assert verified.authority_policy.granted_level is qs_execution_contract.AuthorityLevel.SHADOW
    assert qs_execution_contract.PHASE_GRANTED_AUTHORITY_LEVEL is qs_execution_contract.AuthorityLevel.SHADOW
    assert qs_authority_root.effective_authority_level(
        source_phase_ceiling=qs_execution_contract.PHASE_GRANTED_AUTHORITY_LEVEL,
        verified_grant=verified,
        now_epoch_s=ISSUED_AT,
    ) is qs_execution_contract.AuthorityLevel.SHADOW

    current_now = int(time.time())
    assert current_now > NOT_AFTER
    with pytest.raises(qs_authority_root.AuthorityVerificationError, match="not valid"):
        qs_authority_root.verify_authority_grant(
            receipt=receipt,
            trusted_root=root,
            session=session,
            now_epoch_s=current_now,
        )

    _, document = _load_artifact()
    assert document["historical_verification_replay_epoch_s"] == ISSUED_AT
    assert document["historical_in_window_qntyspot_verification"] == "PASS"
    assert document["current_receipt_status"] == "EXPIRED"
    assert document["current_verification_failure"] == "EXPECTED_EXPIRY"
    assert document["current_verification_observed_at_epoch_s"] > NOT_AFTER


def test_provisioned_public_state_has_one_immutable_successor_row() -> None:
    database = PRODUCTION_ROOT / "state/authority-root-issuance-v0.sqlite3"
    if not database.exists():
        pytest.skip("provisioned production ledger is not available")
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        rows = connection.execute(
            "SELECT request_id, authority_epoch, serial, receipt_id, receipt_bytes "
            "FROM issuances ORDER BY serial"
        ).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert dict(row)["request_id"] == REQUEST_ID
        assert row["authority_epoch"] == 1
        assert row["serial"] == 1
        assert row["receipt_id"] == RECEIPT_ID
        assert bytes(row["receipt_bytes"]) == canonical_json_bytes(RECEIPT_OBJECT)
        assert connection.execute(
            "SELECT COUNT(*) FROM issuances WHERE request_id = ?", (ORIGINAL_REQUEST_ID,)
        ).fetchone()[0] == 0

    receipt_path = PRODUCTION_ROOT / "public/first-grant-shadow-receipt-v0r1.json"
    receipt_sidecar = PRODUCTION_ROOT / "public/first-grant-shadow-receipt-v0r1.sha256"
    successor_intent = PRODUCTION_ROOT / "state/first-grant-request-intent-v0r1.json"
    successor_sidecar = PRODUCTION_ROOT / "state/first-grant-request-intent-v0r1.sha256"
    original_intent = PRODUCTION_ROOT / "state/first-grant-request-intent-v0.json"
    original_sidecar = PRODUCTION_ROOT / "state/first-grant-request-intent-v0.sha256"
    assert receipt_path.read_bytes() == canonical_json_bytes(RECEIPT_OBJECT)
    assert receipt_sidecar.read_text(encoding="ascii") == f"{RECEIPT_SHA256}  {receipt_path.name}\n"
    assert successor_intent.read_bytes() == canonical_json_bytes(SUCCESSOR_INTENT_OBJECT)
    assert successor_sidecar.read_text(encoding="ascii") == f"{REQUEST_INTENT_DIGEST}  {successor_intent.name}\n"
    assert original_intent.read_bytes() == canonical_json_bytes(ORIGINAL_INTENT_OBJECT)
    assert original_sidecar.read_text(encoding="ascii") == f"{ORIGINAL_INTENT_DIGEST}  {original_intent.name}\n"

    _, document = _load_artifact()
    assert document["total_issuance_rows"] == 1
    assert document["ledger_row_count"] == 1
    assert document["ledger_history_result"] == "EXACTLY_SUCCESSOR_V0R1_ONLY_NO_FOREIGN_HISTORY"
    assert document["production_ledger"]["only_row"]["serial"] == 1


def test_closure_has_zero_economic_effects_and_no_authority_escalation() -> None:
    _, document = _load_artifact()
    assert document["zero_effect_counters"] == EXPECTED_ZERO_EFFECT_COUNTERS
    assert document["authority_result"] == {
        "capital_authority": "NONE",
        "effective_authority_at_issuance": "SHADOW",
        "issued_external_grant_level": "SHADOW",
        "live_capital_authorized": "NO",
        "signing_authorized": "NO",
        "source_phase_ceiling_at_issuance": "SHADOW",
    }
    assert document["issued_external_grant_level"] == "SHADOW"
    assert document["source_phase_ceiling"] == "SHADOW"
    assert document["source_phase_ceiling_at_issuance"] == "SHADOW"
    assert document["effective_authority_at_issuance"] == "SHADOW"
    assert document["signing_authorized"] == "NO"
    assert document["capital_authority"] == "NONE"
    assert document["no_reissue_conclusion"] == "NO_REISSUE_NO_REFRESH_NO_NEW_SUCCESSOR"
    assert document["no_second_issuance"] == "YES"
    assert document["successor_v0r1_committed_once"] == "YES"
    assert document["successor_v0r1_reissuable"] == "NO"
    assert document["next_phase"] == "QNTY_SPOT_RECONCILE_ONLY_SOURCE_CEILING_DESIGN_V0"
    assert document["next_action"] == document["next_phase"]
