from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from qnty_authority_root import (
    ALLOWED_NETWORK_ID,
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    assert_issuance_request_admissible,
)
from qnty_authority_root.canon import canonical_json_bytes, digest_object, sha256_hex, strict_json_loads
from qnty_authority_root.errors import AuthorityRootError, IssuancePolicyError


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_DEDICATED_SIGNER_GRANT_GOVERNANCE_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
EPOCH_3_ARTIFACT = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_GRANT_GOVERNANCE_V0.json"
EPOCH_3_SIDECAR = EPOCH_3_ARTIFACT.with_suffix(".sha256")
EPOCH_2_LEDGER = Path(
    "/home/swirky/.local/share/qnty-authority-root/production/v0/state/epoch-2/"
    "authority-root-issuance-v0-epoch-2.sqlite3"
)
EPOCH_3_LEDGER = Path(
    "/home/swirky/.local/share/qnty-authority-root/production/v0/state/epoch-3/"
    "authority-root-issuance-v0-epoch-3.sqlite3"
)
EPOCH_4_LEDGER_RELATIVE = "state/epoch-4/authority-root-issuance-v0-epoch-4.sqlite3"
EPOCH_4_LEDGER = Path("/home/swirky/.local/share/qnty-authority-root/production/v0") / EPOCH_4_LEDGER_RELATIVE

ROOT_ID = "qnty-authority-root-v0"
PARENT = "6692b3c11a3a64ad27caebf0513df54180286c67"
QNTYSPOT_COMMIT = "cf90df0b682d3ea850032ece342e362d56998d17"
IMPLEMENTATION_DIGEST = "b74ccdd99b5a5de4f11310014cf29100a60d07d8e350a43cd1f2dc2b678936f7"
IMPLEMENTATION_SIDECAR_DIGEST = "3198414adcba2ec1ea0ff71dc3b76642a8d8ea32ba986d362f39200d5f8df8d2"
TAKER = "0x70680880335932a6ce4da357c32ed1a6fd5dc51f"
OLD_RABBY_TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
VENUE = "robinhood-chain-testnet-external-transaction"
REQUEST_ID = "qnty-submit-exact-signed-bytes-dedicated-signer-qualification-grant-v0"
POLICY_DIGEST = "3b6847ab54d37e6e7101f8882105dae870ba049b8b0f8616d785fa476ee2fd83"
EPOCH_3_ARTIFACT_DIGEST = "e98706a9462da2d6e33b75a8ce2174ec9a710e8316ce21486412c8c3b38aa948"
EPOCH_3_POLICY_DIGEST = "747f83b3c7081e40e0415b5fb8f1d0fabfdec06425d164d629cfd1649d2b67c6"
TRUST_CONFIG_DIGEST = "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
PUBLIC_KEY_FINGERPRINT = "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe"


class GovernanceRejection(ValueError):
    pass


def _document() -> dict[str, Any]:
    raw = ARTIFACT.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == f"{sha256_hex(raw)}  {ARTIFACT.name}\n"
    return document


def _policy(*, maximum: AuthorityLevel = AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES) -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=maximum,
        allowed_network_ids=(ALLOWED_NETWORK_ID,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE,),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=900,
    )


def _request(**changes: Any) -> AuthorityIssuanceRequestV0:
    request_repository = changes.pop("request_repository_identity", "CipherCuttle/QntySpot")
    issued_at = changes.pop("issued_at_epoch_s", 1000)
    values: dict[str, Any] = {
        "authority_root_id": ROOT_ID,
        "granted_level": AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES,
        "permitted_repository_commit": QNTYSPOT_COMMIT,
        "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
        "permitted_network_id": ALLOWED_NETWORK_ID,
        "permitted_taker_address": TAKER,
        "permitted_venue_id": VENUE,
        "max_reservation_atomic": 1,
        "max_cumulative_atomic": 1,
        "not_before_epoch_s": 1000,
        "not_after_epoch_s": 1900,
    }
    values.update(changes)
    return AuthorityIssuanceRequestV0(
        repository_identity=request_repository,
        authority_policy=AuthorityPolicyRefV0(**values),
        issued_at_epoch_s=issued_at,
    )


def _exact_governance_gate(
    request_id: str,
    request: AuthorityIssuanceRequestV0,
    *,
    authority_epoch: int = 4,
    ledger_relative_path: str = EPOCH_4_LEDGER_RELATIVE,
) -> None:
    if request_id != REQUEST_ID:
        raise GovernanceRejection("only the exact future request is governed")
    if authority_epoch != 4:
        raise GovernanceRejection("the successor authority epoch is exactly 4")
    if ledger_relative_path != EPOCH_4_LEDGER_RELATIVE:
        raise GovernanceRejection("the future production ledger path is isolated and exact")
    if request != _request():
        raise GovernanceRejection("request scope is not exact")
    assert_issuance_request_admissible(_policy(), request)


def test_artifact_is_canonical_and_freezes_epoch_4_governance() -> None:
    document = _document()
    assert document["AUTHORITY_EPOCH"] == 4
    assert document["AUTHORITY_ROOT_PARENT"] == PARENT
    assert document["EPOCH_3_STATUS"] == "RETIRED_UNUSED_BEFORE_ISSUANCE"
    assert document["EPOCH_3"]["ledger_present"] == "NO"
    assert document["EPOCH_3"]["grants_issued"] == 0
    assert document["EPOCH_4_PRODUCTION_LEDGER"]["created_now"] == "NO"
    assert document["QNTYSPOT_CANONICAL"] == QNTYSPOT_COMMIT
    assert document["QNTYSPOT_IMPLEMENTATION_DIGEST"] == IMPLEMENTATION_DIGEST
    assert document["issuer_policy"]["digest"] == POLICY_DIGEST
    assert document["issuer_policy"]["maximum_issuable_level"] == "SUBMIT_EXACT_SIGNED_BYTES"
    assert document["issuer_policy"]["level_3_authorized"] == "NO"
    assert document["PRESTAGE_SIGNED_BYTES_BEFORE_ISSUANCE"] == "REQUIRED"
    assert document["PRODUCTION_EFFECTS"] == {
        "authorityroot_production_signer_accessed": "NO",
        "blockchain_transaction": "NO",
        "epoch_3_grants_issued": 0,
        "epoch_3_ledger_created": "NO",
        "epoch_4_ledger_created": "NO",
        "funding": "NO",
        "grant_issued": "NO",
        "real_transaction_signed": "NO",
    }
    assert b"/home/" not in ARTIFACT.read_bytes()
    assert b"-----BEGIN" not in ARTIFACT.read_bytes()
    assert b'"signature"' not in ARTIFACT.read_bytes()


def test_epoch_3_artifact_and_policy_remain_unchanged() -> None:
    raw = EPOCH_3_ARTIFACT.read_bytes()
    assert sha256_hex(raw) == EPOCH_3_ARTIFACT_DIGEST
    assert EPOCH_3_SIDECAR.read_text(encoding="ascii") == f"{EPOCH_3_ARTIFACT_DIGEST}  {EPOCH_3_ARTIFACT.name}\n"
    old = strict_json_loads(raw)
    assert old["AUTHORITY_EPOCH"] == 3
    assert old["issuer_policy"]["digest"] == EPOCH_3_POLICY_DIGEST
    assert old["issuer_policy"]["canonical_object"]["allowed_taker_addresses"] == [OLD_RABBY_TAKER]
    assert _policy().allowed_taker_addresses != tuple(old["issuer_policy"]["canonical_object"]["allowed_taker_addresses"])


def test_production_preflight_is_read_only_and_epoch_3_is_absent() -> None:
    assert EPOCH_2_LEDGER.exists()
    assert not EPOCH_3_LEDGER.exists()
    assert not EPOCH_4_LEDGER.exists()
    with sqlite3.connect(f"file:{EPOCH_2_LEDGER}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        metadata = connection.execute("SELECT * FROM issuer_metadata").fetchone()
        assert metadata is not None
        assert metadata["authority_epoch"] == 2
        assert metadata["trust_config_version"] == 1
        assert metadata["trust_config_digest"] == TRUST_CONFIG_DIGEST
        assert connection.execute("SELECT COUNT(*) FROM issuances").fetchone()[0] >= 1


def test_epoch_4_ledger_is_deferred_and_synthetic_state_is_temporary(tmp_path: Path) -> None:
    assert not EPOCH_4_LEDGER.exists()
    synthetic = tmp_path / EPOCH_4_LEDGER_RELATIVE
    synthetic.parent.mkdir(parents=True)
    with sqlite3.connect(synthetic) as connection:
        connection.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker VALUES ('governance-only')")
    assert synthetic.exists()
    assert not EPOCH_4_LEDGER.exists()


def test_policy_digest_is_mechanical_and_exact() -> None:
    policy = _policy()
    expected = {
        "allowed_network_ids": ["evm:46630"],
        "allowed_taker_addresses": [TAKER],
        "allowed_venue_ids": [VENUE],
        "max_cumulative_atomic": "1",
        "max_grant_duration_s": 900,
        "max_reservation_atomic": "1",
        "maximum_issuable_level": 2,
        "repository_identity": "CipherCuttle/QntySpot",
        "root_id": ROOT_ID,
        "schema": "qntyspot.authority_root.v0.issuance_policy",
    }
    assert policy.canonical_object() == expected
    assert policy.policy_digest == POLICY_DIGEST
    assert digest_object(expected) == POLICY_DIGEST
    assert policy.maximum_issuable_level is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert policy.max_reservation_atomic == 1
    assert policy.max_cumulative_atomic == 1
    assert policy.max_grant_duration_s == 900


def test_exact_epoch_4_level_2_request_passes_without_issuance() -> None:
    request = _request()
    _exact_governance_gate(REQUEST_ID, request)
    assert request.authority_policy.granted_level is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert request.authority_policy.not_after_epoch_s - request.authority_policy.not_before_epoch_s == 900
    assert not EPOCH_4_LEDGER.exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"granted_level": AuthorityLevel.SHADOW},
        {"granted_level": AuthorityLevel.RECONCILE_ONLY},
        {"granted_level": AuthorityLevel.HUMAN_SIGNED_EXECUTION},
        {"granted_level": AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER},
        {"permitted_taker_address": OLD_RABBY_TAKER},
        {"permitted_taker_address": "0x1111111111111111111111111111111111111111"},
        {"permitted_taker_address": "0x0000000000000000000000000000000000000000"},
        {"permitted_network_id": "evm:4663"},
        {"permitted_network_id": "evm:1"},
        {"permitted_network_id": "*"},
        {"permitted_venue_id": "wrong-venue"},
        {"permitted_venue_id": "*"},
        {"permitted_repository_commit": "a" * 40},
        {"permitted_implementation_digest": "b" * 64},
        {"authority_root_id": "other-authority-root"},
        {"request_repository_identity": "CipherCuttle/Other"},
        {"max_reservation_atomic": 2, "max_cumulative_atomic": 2},
        {"max_cumulative_atomic": 2},
        {"max_reservation_atomic": 2, "max_cumulative_atomic": 1},
        {"max_reservation_atomic": 0},
        {"max_cumulative_atomic": 0},
        {"not_after_epoch_s": 1901},
        {"not_after_epoch_s": 1000},
        {"not_after_epoch_s": 999},
    ],
)
def test_exact_governance_rejects_hostile_scope_variants(changes: dict[str, Any]) -> None:
    with pytest.raises((AuthorityRootError, IssuancePolicyError, GovernanceRejection, ValueError)):
        _exact_governance_gate(REQUEST_ID, _request(**changes))


@pytest.mark.parametrize(
    "request_id,authority_epoch,ledger_relative_path",
    [
        ("qnty-submit-exact-signed-bytes-qualification-grant-v0", 4, EPOCH_4_LEDGER_RELATIVE),
        (REQUEST_ID, 3, EPOCH_4_LEDGER_RELATIVE),
        (REQUEST_ID, 2, EPOCH_4_LEDGER_RELATIVE),
        (REQUEST_ID, 4, "state/epoch-3/authority-root-issuance-v0-epoch-3.sqlite3"),
        (REQUEST_ID, 4, "state/epoch-2/authority-root-issuance-v0-epoch-2.sqlite3"),
    ],
)
def test_request_identity_epoch_and_isolated_epoch_4_path_are_mandatory(
    request_id: str, authority_epoch: int, ledger_relative_path: str
) -> None:
    with pytest.raises(GovernanceRejection):
        _exact_governance_gate(
            request_id,
            _request(),
            authority_epoch=authority_epoch,
            ledger_relative_path=ledger_relative_path,
        )


def test_trust_root_signer_and_level_boundaries_are_immutable() -> None:
    document = _document()
    assert document["ROOT_ID"] == ROOT_ID
    assert document["TRUST_CONTINUITY"] == {
        "minimum_authority_epoch": 1,
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
        "root_id": ROOT_ID,
        "signature_algorithm": "Ed25519",
        "trust_config_digest": TRUST_CONFIG_DIGEST,
        "trust_config_version": 1,
    }
    assert document["DEDICATED_EXTERNAL_SIGNER"] == {
        "address": TAKER,
        "autonomous_signing": "NO",
        "class": "DEDICATED_TESTNET_ONLY_HUMAN_UNLOCKED_OFFLINE_SIGNER",
        "private_key_access_by_authorityroot": "NO",
        "private_key_access_by_qntyspot": "NO",
        "production_capital_authority": "NONE",
        "signer_backend": "Foundry cast",
        "signer_network_proof": "HARD_NETWORK_ISOLATION",
    }
    assert min(AuthorityLevel.SHADOW, AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES) is AuthorityLevel.SHADOW
    assert document["issuer_policy"]["level_3_authorized"] == "NO"
    for denied in document["LEVEL_2_AUTHORITY_MEANING"]["denies"]:
        assert denied != "SUBMIT_EXACT_SIGNED_BYTES"

    mutated_root = dict(document["TRUST_CONTINUITY"], root_id="rotated-root")
    mutated_trust = dict(document["TRUST_CONTINUITY"], trust_config_version=2)
    assert mutated_root != document["TRUST_CONTINUITY"]
    assert mutated_trust != document["TRUST_CONTINUITY"]


def test_prestage_and_no_production_effects_are_mandatory() -> None:
    document = _document()
    assert document["PRESTAGE_SIGNED_BYTES_BEFORE_ISSUANCE"] == "REQUIRED"
    assert document["PRODUCTION_EFFECTS"]["grant_issued"] == "NO"
    assert document["PRODUCTION_EFFECTS"]["real_transaction_signed"] == "NO"
    assert document["PRODUCTION_EFFECTS"]["blockchain_transaction"] == "NO"
    assert document["PRODUCTION_EFFECTS"]["funding"] == "NO"
    assert document["synthetic_admissibility"]["temporary_or_synthetic_ledgers_only"] == "YES"
    assert document["EXACT_FUTURE_REQUEST"]["production_timestamps"] == "DEFERRED"


def test_future_qualification_is_unsigned_revert_scope_only() -> None:
    future = _document()["FUTURE_QUALIFICATION_TRANSACTION"]
    assert future == {
        "data": "0x2e1a7d4d" + "ff" * 32,
        "expected_outcome": "REVERTED",
        "from": TAKER,
        "to": "0x33e4191705c386532ba27cbf171db86919200b94",
        "value": 0,
    }
    assert "gas" not in future
    assert "nonce" not in future
    assert "signature" not in future
