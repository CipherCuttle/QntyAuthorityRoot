from __future__ import annotations

import sqlite3
import sys
import time
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
    canonical_json_bytes,
    sha256_hex,
    strict_json_loads,
)

QNTYSPOT_ROOT = Path("/home/swirky/DevHub/worktrees/QntySpot-reconcile-v0r1")
if str(QNTYSPOT_ROOT) not in sys.path:
    sys.path.insert(0, str(QNTYSPOT_ROOT))
from qntyspot.states import IntentState, PRE_COMMITMENT_STATES, is_legal_transition  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/RECONCILE_ONLY_GRANT_V0R1_EXPIRED_NO_TX_RECOVERY_GOVERNANCE_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
AUTHORITY_LEDGER = Path(
    "/home/swirky/.local/share/qnty-authority-root/production/v0/state/epoch-2/"
    "authority-root-issuance-v0-epoch-2.sqlite3"
)
QNTYSPOT_LEDGER = Path(
    "/home/swirky/.local/share/qntyspot/production/v0/state/epoch-2/"
    "reconcile-only-qualification-v0r1.sqlite3"
)
QNTYSPOT_MAIN = "e71f3d698c449bbd7eb73bcd4547899b7f5f0594"
IMPLEMENTATION_DIGEST = "bdb1f4025ee7c16130ea422bd21febd69de4759654da1710f1e41d6935f6bc81"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
VENUE = "robinhood-chain-testnet-external-transaction"
ACTION = "2432028630086a782b96520aad9777ead039ac51ab8e1ca877f6ad9bb9c7d563"
V0R2_REQUEST_ID = "qnty-reconcile-only-qualification-grant-v0r2"


class GovernanceRejection(ValueError):
    pass


def _document() -> dict[str, Any]:
    raw = ARTIFACT.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    assert raw == canonical_json_bytes(document)
    digest = sha256_hex(raw)
    assert SIDECAR.read_text(encoding="ascii") == f"{digest}  {ARTIFACT.name}\n"
    return document


def _policy() -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id="qnty-authority-root-v0",
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
        allowed_network_ids=(ALLOWED_NETWORK_ID,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE,),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=900,
    )


def _request(**changes: Any) -> AuthorityIssuanceRequestV0:
    values: dict[str, Any] = {
        "authority_root_id": "qnty-authority-root-v0",
        "granted_level": AuthorityLevel.RECONCILE_ONLY,
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


def _exact_successor_gate(request_id: str, request: AuthorityIssuanceRequestV0) -> None:
    if request_id != V0R2_REQUEST_ID:
        raise GovernanceRejection("only the one governed V0R2 successor is authorized")
    if request.authority_policy != _request().authority_policy:
        raise GovernanceRejection("successor authority scope is not exact")
    assert_issuance_request_admissible(_policy(), request)


def test_artifact_is_canonical_and_freezes_exact_successor() -> None:
    document = _document()
    assert document["SERIAL_2_STATUS"] == "EXPIRED_UNUSED_FOR_QUALIFICATION"
    assert document["SERIAL_2_EXTERNAL_TX_COUNT"] == 0
    assert document["SERIAL_2_SETTLEMENT_COUNT"] == 0
    assert document["SERIAL_2_RESERVATION_FINAL_STATE"] == "RELEASED"
    assert document["SUCCESSOR_REQUEST_ID"] == V0R2_REQUEST_ID
    assert document["SUCCESSOR_EXPECTED_SERIAL"] == 3
    assert document["AUTHORITY_EPOCH"] == 2
    assert document["DURATION_SECONDS"] == 900
    assert document["AUTHORITY_INCREASE"] == "NO"
    assert document["NEW_LEDGER"] == "NO"
    assert document["PRESTAGE_EXTERNAL_TX_BEFORE_ISSUANCE"] == "REQUIRED"
    assert document["RABBY_FINAL_CONFIRMATION_BEFORE_CLOCK"] == "REQUIRED"
    assert document["canonical_inputs"] == {
        "authority_root_main": "60fdd052d3fd44c7f7ea739eaeb690f359bbecfb",
        "issuer_policy_digest": "8f0751348af21cecddd545178d7d62e9538698e212d1c1a057eed4720e8bde63",
        "predecessor_governance_artifact_digest": "f2645429aff2b860a239126dfb9aeb6fdb59d0d5e6412065d0acc7ce867945b4",
        "qntyspot_implementation_digest": IMPLEMENTATION_DIGEST,
        "qntyspot_main": QNTYSPOT_MAIN,
        "recovery_governance_digest": "03cabba8dd56b450b11efc865e67bd0697aacc2a3aa65a61127b9f345e2c027b",
        "trust_config_digest": "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6",
    }


def test_serial_2_is_expired_and_authority_ledger_has_no_serial_3() -> None:
    document = _document()
    serial = document["serial_2"]
    assert int(time.time()) > serial["not_after_epoch_s"]
    with sqlite3.connect(f"file:{AUTHORITY_LEDGER}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        rows = connection.execute(
            "SELECT request_id, authority_epoch, serial FROM issuances ORDER BY serial"
        ).fetchall()
        assert [(row["request_id"], row["authority_epoch"], row["serial"]) for row in rows] == [
            ("qnty-reconcile-only-qualification-grant-v0", 2, 1),
            ("qnty-reconcile-only-qualification-grant-v0r1", 2, 2),
        ]
        assert connection.execute(
            "SELECT COUNT(*) FROM issuances WHERE request_id = ?",
            (V0R2_REQUEST_ID,),
        ).fetchone()[0] == 0


def test_existing_precommitment_recovery_semantics_are_exact() -> None:
    assert IntentState.RESERVED in PRE_COMMITMENT_STATES
    assert is_legal_transition(IntentState.RESERVED, IntentState.CANCELLED)
    assert not is_legal_transition(IntentState.RESERVED, IntentState.FILLED)
    recovery_source = (QNTYSPOT_ROOT / "qntyspot/ledger/recovery.py").read_text()
    assert "RecoveryDisposition.ABANDON" in recovery_source
    assert "to_state=IntentState.CANCELLED" in recovery_source


def test_qntyspot_recovery_is_durable_and_has_no_external_activity() -> None:
    document = _document()
    recovery = document["qntyspot_recovery"]
    assert recovery["economic_action_id"] == ACTION
    assert recovery["initial_intent_state"] == "RESERVED"
    assert recovery["recovery_disposition"] == "ABANDON"
    assert recovery["terminal_intent_state"] == "CANCELLED"
    assert recovery["reservation_final_state"] == "RELEASED"
    assert recovery["recovery_second_call_actions"] == 0
    with sqlite3.connect(f"file:{QNTYSPOT_LEDGER}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        intent = connection.execute(
            "SELECT state, quote_exposure_atomic FROM intents WHERE economic_action_id = ?",
            (ACTION,),
        ).fetchone()
        reservation = connection.execute(
            "SELECT status, amount_atomic FROM budget_reservations WHERE economic_action_id = ?",
            (ACTION,),
        ).fetchone()
        assert dict(intent) == {"state": "CANCELLED", "quote_exposure_atomic": "1"}
        assert dict(reservation) == {"status": "RELEASED", "amount_atomic": "1"}
        assert connection.execute(
            "SELECT COUNT(*) FROM budget_reservations WHERE status <> 'RELEASED'"
        ).fetchone()[0] == 0
        for table, column in (
            ("external_transaction_refs", "economic_action_id"),
            ("signed_transactions", "external_action_id"),
            ("execution_envelopes", "economic_action_id"),
            ("chain_observations", "external_action_id"),
            ("reconciliations", "external_action_id"),
            ("fill_receipts", "economic_action_id"),
        ):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {column} = ?", (ACTION,)
            ).fetchone()[0] == 0


def test_successor_v0r2_is_exactly_one_level_1_request_and_not_issued() -> None:
    document = _document()
    policy = _policy()
    assert policy.policy_digest == document["ISSUER_POLICY_DIGEST"]
    request = _request()
    _exact_successor_gate(V0R2_REQUEST_ID, request)
    successor = document["successor_authority"]
    assert successor == {
        "authority_epoch": 2,
        "authority_root_id": "qnty-authority-root-v0",
        "duration_seconds": 900,
        "granted_level": "RECONCILE_ONLY",
        "max_cumulative_atomic": "1",
        "max_reservation_atomic": "1",
        "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
        "permitted_network_id": "evm:46630",
        "permitted_repository_commit": QNTYSPOT_MAIN,
        "permitted_taker_address": TAKER,
        "permitted_venue_id": VENUE,
        "successor_count": 1,
        "successor_expected_serial": 3,
        "successor_request_id": V0R2_REQUEST_ID,
    }
    assert document["hostile_review"]["critical"] == 0
    assert document["hostile_review"]["high"] == 0
    assert not Path(
        "/home/swirky/.local/share/qnty-authority-root/production/v0/public/"
        "reconcile-only-qualification-grant-v0r2.json"
    ).exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"granted_level": AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES},
        {"permitted_network_id": "evm:4663"},
        {"permitted_taker_address": "0x1111111111111111111111111111111111111111"},
        {"permitted_venue_id": "zero-x-swap-v2-robinhood-chain"},
        {"max_reservation_atomic": 2},
        {"max_cumulative_atomic": 2},
        {"not_after_epoch_s": 1901},
        {"permitted_repository_commit": "a" * 40},
        {"permitted_implementation_digest": "b" * 64},
    ],
)
def test_v0r2_hostile_scope_variants_fail_closed(changes: dict[str, Any]) -> None:
    with pytest.raises(Exception):
        _exact_successor_gate(V0R2_REQUEST_ID, _request(**changes))


@pytest.mark.parametrize("request_id", [
    "qnty-reconcile-only-qualification-grant-v0r1",
    "qnty-reconcile-only-qualification-grant-v0r3",
])
def test_only_v0r2_successor_request_id_is_authorized(request_id: str) -> None:
    with pytest.raises(GovernanceRejection):
        _exact_successor_gate(request_id, _request())
