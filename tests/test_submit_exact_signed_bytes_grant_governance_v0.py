from __future__ import annotations

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
from qnty_authority_root.canon import canonical_json_bytes, sha256_hex, strict_json_loads
from qnty_authority_root.errors import AuthorityRootError, IssuancePolicyError


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_GRANT_GOVERNANCE_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
EPOCH_2_LEDGER = Path(
    "/home/swirky/.local/share/qnty-authority-root/production/v0/state/epoch-2/"
    "authority-root-issuance-v0-epoch-2.sqlite3"
)
EPOCH_3_LEDGER = Path(
    "/home/swirky/.local/share/qnty-authority-root/production/v0/state/epoch-3/"
    "authority-root-issuance-v0-epoch-3.sqlite3"
)
ROOT_ID = "qnty-authority-root-v0"
QNTYSPOT_MAIN = "cf90df0b682d3ea850032ece342e362d56998d17"
IMPLEMENTATION_DIGEST = "b74ccdd99b5a5de4f11310014cf29100a60d07d8e350a43cd1f2dc2b678936f7"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
VENUE = "robinhood-chain-testnet-external-transaction"
REQUEST_ID = "qnty-submit-exact-signed-bytes-qualification-grant-v0"
ISSUER_POLICY_DIGEST = "747f83b3c7081e40e0415b5fb8f1d0fabfdec06425d164d629cfd1649d2b67c6"


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
    values: dict[str, Any] = {
        "authority_root_id": ROOT_ID,
        "granted_level": AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES,
        "permitted_repository_commit": QNTYSPOT_MAIN,
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
        repository_identity="CipherCuttle/QntySpot",
        authority_policy=AuthorityPolicyRefV0(**values),
        issued_at_epoch_s=1000,
    )


def _exact_governance_gate(
    request_id: str,
    request: AuthorityIssuanceRequestV0,
    *,
    authority_epoch: int = 3,
    ledger_relative_path: str = "state/epoch-3/authority-root-issuance-v0-epoch-3.sqlite3",
) -> None:
    if request_id != REQUEST_ID:
        raise GovernanceRejection("only the exact future request is governed")
    if authority_epoch != 3:
        raise GovernanceRejection("Level 2 requires isolated authority epoch 3")
    if ledger_relative_path != "state/epoch-3/authority-root-issuance-v0-epoch-3.sqlite3":
        raise GovernanceRejection("the governed epoch-3 ledger path is exact")
    if request.authority_policy != _request().authority_policy:
        raise GovernanceRejection("request scope is not exact")
    assert_issuance_request_admissible(_policy(), request)


def test_artifact_is_canonical_and_freezes_exact_governance() -> None:
    document = _document()
    assert document["AUTHORITY_EPOCH"] == 3
    assert document["QNTYSPOT_CANONICAL"] == QNTYSPOT_MAIN
    assert document["QNTYSPOT_IMPLEMENTATION_DIGEST"] == IMPLEMENTATION_DIGEST
    assert document["LEVEL_1_QUALIFICATION"] == "CLOSED"
    assert document["PRESTAGE_SIGNED_BYTES_BEFORE_ISSUANCE"] == "REQUIRED"
    assert document["issuer_policy"]["digest"] == ISSUER_POLICY_DIGEST
    assert document["issuer_policy"]["maximum_issuable_level"] == "SUBMIT_EXACT_SIGNED_BYTES"
    assert document["issuer_policy"]["level_3_authorized"] == "NO"
    assert document["exact_future_request"]["request_id"] == REQUEST_ID
    assert document["exact_future_request"]["granted_level_numeric"] == 2
    assert document["PRODUCTION_EFFECTS"] == {
        "epoch_3_ledger_created": "NO",
        "epoch_3_ledger_mutated": "NO",
        "grant_issued": "NO",
        "production_signer_accessed": "NO",
        "production_timestamps_captured": "NO",
    }


def test_epoch_2_ledger_is_read_only_intact_and_epoch_3_is_deferred() -> None:
    assert EPOCH_2_LEDGER.exists()
    assert not EPOCH_3_LEDGER.exists()
    with sqlite3.connect(f"file:{EPOCH_2_LEDGER}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        metadata = connection.execute("SELECT * FROM issuer_metadata").fetchone()
        assert metadata["authority_epoch"] == 2
        assert metadata["trust_config_version"] == 1
        assert metadata["trust_config_digest"] == "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
        rows = connection.execute(
            "SELECT authority_epoch, serial FROM issuances ORDER BY serial"
        ).fetchall()
        assert [(row["authority_epoch"], row["serial"]) for row in rows] == [(2, 1), (2, 2), (2, 3)]


def test_exact_epoch_3_level_2_request_passes_without_issuing() -> None:
    request = _request()
    _exact_governance_gate(REQUEST_ID, request)
    assert request.authority_policy.granted_level is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert request.authority_policy.not_after_epoch_s - request.authority_policy.not_before_epoch_s == 900
    assert not EPOCH_3_LEDGER.exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"granted_level": AuthorityLevel.SHADOW},
        {"granted_level": AuthorityLevel.RECONCILE_ONLY},
        {"granted_level": AuthorityLevel.HUMAN_SIGNED_EXECUTION},
        {"granted_level": AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER},
        {"permitted_network_id": "evm:4663"},
        {"permitted_network_id": "evm:1"},
        {"permitted_taker_address": "0x1111111111111111111111111111111111111111"},
        {"permitted_taker_address": "0x0000000000000000000000000000000000000000"},
        {"permitted_venue_id": "wrong-venue"},
        {"permitted_venue_id": "*"},
        {"max_reservation_atomic": 2},
        {"max_cumulative_atomic": 2},
        {"max_reservation_atomic": 2, "max_cumulative_atomic": 1},
        {"max_reservation_atomic": 0},
        {"max_cumulative_atomic": 0},
        {"not_after_epoch_s": 1901},
        {"not_after_epoch_s": 1000},
        {"not_after_epoch_s": 999},
        {"authority_root_id": "other-root"},
        {"permitted_repository_commit": "a" * 40},
        {"permitted_implementation_digest": "b" * 64},
    ],
)
def test_exact_governance_rejects_hostile_scope_variants(changes: dict[str, Any]) -> None:
    with pytest.raises((AuthorityRootError, IssuancePolicyError, GovernanceRejection)):
        _exact_governance_gate(REQUEST_ID, _request(**changes))


@pytest.mark.parametrize(
    "request_id,authority_epoch,ledger_relative_path",
    [
        ("qnty-submit-exact-signed-bytes-qualification-grant-v0r1", 3, "state/epoch-3/authority-root-issuance-v0-epoch-3.sqlite3"),
        (REQUEST_ID, 2, "state/epoch-3/authority-root-issuance-v0-epoch-3.sqlite3"),
        (REQUEST_ID, 3, "state/epoch-2/authority-root-issuance-v0-epoch-2.sqlite3"),
    ],
)
def test_exact_request_identity_epoch_and_isolated_path_are_mandatory(
    request_id: str, authority_epoch: int, ledger_relative_path: str
) -> None:
    with pytest.raises(GovernanceRejection):
        _exact_governance_gate(
            request_id,
            _request(),
            authority_epoch=authority_epoch,
            ledger_relative_path=ledger_relative_path,
        )


def test_synthetic_ledger_only_and_no_production_issuance(tmp_path: Path) -> None:
    synthetic = tmp_path / "state/epoch-3/authority-root-issuance-v0-epoch-3.sqlite3"
    synthetic.parent.mkdir(parents=True)
    with sqlite3.connect(synthetic) as connection:
        connection.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker VALUES ('governance-only')")
    assert synthetic.exists()
    assert not EPOCH_3_LEDGER.exists()
