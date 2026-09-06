from __future__ import annotations

import sqlite3
import subprocess
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
)
from qnty_authority_root.canon import canonical_json_bytes, sha256_hex, strict_json_loads
from qnty_authority_root.errors import AuthorityRootError, IssuancePolicyError


ROOT = Path(__file__).resolve().parents[1]
QNTYSPOT_REPO = ROOT.parent / "QntySpot"
ARTIFACT = ROOT / "artifacts/RECONCILE_ONLY_GRANT_EXPIRED_RECOVERY_GOVERNANCE_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
PRODUCTION_ROOT = Path("/home/swirky/.local/share/qnty-authority-root/production/v0")
LEDGER = PRODUCTION_ROOT / "state/epoch-2/authority-root-issuance-v0-epoch-2.sqlite3"
ORIGINAL_INTENT = PRODUCTION_ROOT / "state/epoch-2/reconcile-only-qualification-grant-v0-intent.json"
ORIGINAL_INTENT_SIDECAR = ORIGINAL_INTENT.with_suffix(".sha256")
ORIGINAL_RECEIPT = PRODUCTION_ROOT / "public/reconcile-only-qualification-grant-v0.json"
ORIGINAL_RECEIPT_SIDECAR = ORIGINAL_RECEIPT.with_suffix(".sha256")

AUTHORITY_ROOT_MAIN = "527481d0068b4acb987f35c31b409eab32534a8b"
QNTYSPOT_MAIN = "e71f3d698c449bbd7eb73bcd4547899b7f5f0594"
IMPLEMENTATION_DIGEST = "bdb1f4025ee7c16130ea422bd21febd69de4759654da1710f1e41d6935f6bc81"
GOVERNANCE_ARTIFACT_DIGEST = "f2645429aff2b860a239126dfb9aeb6fdb59d0d5e6412065d0acc7ce867945b4"
ISSUER_POLICY_DIGEST = "8f0751348af21cecddd545178d7d62e9538698e212d1c1a057eed4720e8bde63"
TRUST_CONFIG_DIGEST = "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
ROOT_ID = "qnty-authority-root-v0"
NETWORK = ALLOWED_NETWORK_ID
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
VENUE = "robinhood-chain-testnet-external-transaction"
OLD_VENUE = "zero-x-swap-v2-robinhood-chain"
ORIGINAL_REQUEST_ID = "qnty-reconcile-only-qualification-grant-v0"
SUCCESSOR_REQUEST_ID = "qnty-reconcile-only-qualification-grant-v0r1"
ORIGINAL_RECEIPT_ID = "96663e7f54747985f063d24b2dea249eb421e27a4d618a42f5517281035a5c2f"
ORIGINAL_RECEIPT_SHA256 = "6a053d0d157d8745a2b6d431b21fbb4f00b979643cf4e6d937ab4e95120a87e7"
ORIGINAL_INTENT_SHA256 = "ae19ec621f2a953c7416417483bb9ca5c7e120f131d3150015c127c8e58ebd72"
ORIGINAL_REQUEST_BYTES_SHA256 = "94442b40ff1e9046771d7724ce6c143bde79ebb2f360b1728e99bea52b27d6d2"
ISSUED_AT = 1788718194
NOT_AFTER = 1788719094


class GovernanceRejection(ValueError):
    pass


def _load_artifact() -> tuple[bytes, dict[str, Any]]:
    raw = ARTIFACT.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    return raw, document


def _successor_policy() -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
        allowed_network_ids=(NETWORK,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE,),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=900,
    )


def _successor_scope(
    *,
    level: AuthorityLevel = AuthorityLevel.RECONCILE_ONLY,
    commit: str = QNTYSPOT_MAIN,
    implementation_digest: str = IMPLEMENTATION_DIGEST,
    network: str = NETWORK,
    taker: str = TAKER,
    venue: str = VENUE,
    max_reservation_atomic: int = 1,
    max_cumulative_atomic: int = 1,
    not_before_epoch_s: int = 1000,
    not_after_epoch_s: int = 1900,
) -> AuthorityPolicyRefV0:
    return AuthorityPolicyRefV0(
        authority_root_id=ROOT_ID,
        granted_level=level,
        permitted_repository_commit=commit,
        permitted_implementation_digest=implementation_digest,
        permitted_network_id=network,
        permitted_taker_address=taker,
        permitted_venue_id=venue,
        max_reservation_atomic=max_reservation_atomic,
        max_cumulative_atomic=max_cumulative_atomic,
        not_before_epoch_s=not_before_epoch_s,
        not_after_epoch_s=not_after_epoch_s,
    )


def _successor_request(
    *,
    request_id: str = SUCCESSOR_REQUEST_ID,
    **changes: Any,
) -> AuthorityIssuanceRequestV0:
    return AuthorityIssuanceRequestV0(
        repository_identity="CipherCuttle/QntySpot",
        authority_policy=_successor_scope(**changes),
        issued_at_epoch_s=1000,
    )


def _exact_successor_gate(
    request_id: str,
    request: AuthorityIssuanceRequestV0,
    *,
    authority_epoch: int = 2,
    ledger_path: Path = LEDGER,
) -> None:
    if request_id != SUCCESSOR_REQUEST_ID:
        raise GovernanceRejection("only the one governed successor request is authorized")
    if request_id == ORIGINAL_REQUEST_ID:
        raise GovernanceRejection("the expired original request id cannot be reused")
    if authority_epoch != 2:
        raise GovernanceRejection("successor must remain in governed authority epoch 2")
    if ledger_path != LEDGER:
        raise GovernanceRejection("only the existing governed epoch-2 ledger is authorized")
    if request.authority_policy != _successor_scope():
        raise GovernanceRejection("successor authority scope is not the exact governed scope")
    assert_issuance_request_admissible(_successor_policy(), request)


def _git_revision(repo: Path, revision: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", revision],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def test_artifact_is_canonical_and_pins_exact_inputs() -> None:
    raw, document = _load_artifact()
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == f"{sha256_hex(raw)}  {ARTIFACT.name}\n"
    assert document["canonical_inputs"] == {
        "authority_root_main": AUTHORITY_ROOT_MAIN,
        "issuer_policy_digest": ISSUER_POLICY_DIGEST,
        "predecessor_governance_artifact_digest": GOVERNANCE_ARTIFACT_DIGEST,
        "qntyspot_implementation_digest": IMPLEMENTATION_DIGEST,
        "qntyspot_main": QNTYSPOT_MAIN,
        "trust_config_digest": TRUST_CONFIG_DIGEST,
    }
    assert _git_revision(ROOT, AUTHORITY_ROOT_MAIN) == AUTHORITY_ROOT_MAIN
    assert _git_revision(QNTYSPOT_REPO, QNTYSPOT_MAIN) == QNTYSPOT_MAIN
    assert document["SUCCESSOR_REQUEST_ID"] == SUCCESSOR_REQUEST_ID
    assert document["SUCCESSOR_EXPECTED_SERIAL"] == 2


def test_original_production_receipt_and_intent_are_expired_terminal_history() -> None:
    receipt_raw = ORIGINAL_RECEIPT.read_bytes()
    receipt = strict_json_loads(receipt_raw)
    assert isinstance(receipt, dict)
    assert receipt_raw == canonical_json_bytes(receipt)
    assert sha256_hex(receipt_raw) == ORIGINAL_RECEIPT_SHA256
    assert ORIGINAL_RECEIPT_SIDECAR.read_text(encoding="ascii") == (
        f"{ORIGINAL_RECEIPT_SHA256}  {ORIGINAL_RECEIPT.name}\n"
    )
    assert receipt["authority_epoch"] == 2
    assert receipt["serial"] == 1
    assert receipt["receipt_id"] == ORIGINAL_RECEIPT_ID
    assert receipt["authority_policy"]["granted_level"] == 1
    assert receipt["issued_at_epoch_s"] == ISSUED_AT
    assert receipt["authority_policy"]["not_before_epoch_s"] == ISSUED_AT
    assert receipt["authority_policy"]["not_after_epoch_s"] == NOT_AFTER
    assert int(time.time()) > NOT_AFTER

    intent_raw = ORIGINAL_INTENT.read_bytes()
    intent = strict_json_loads(intent_raw)
    assert isinstance(intent, dict)
    assert intent_raw == canonical_json_bytes(intent)
    assert sha256_hex(intent_raw) == ORIGINAL_INTENT_SHA256
    assert ORIGINAL_INTENT_SIDECAR.read_text(encoding="ascii") == (
        f"{ORIGINAL_INTENT_SHA256}  {ORIGINAL_INTENT.name}\n"
    )
    assert intent["request_id"] == ORIGINAL_REQUEST_ID
    assert intent["authority_root_canonical"] == AUTHORITY_ROOT_MAIN
    assert intent["governance_artifact_digest"] == GOVERNANCE_ARTIFACT_DIGEST
    assert intent["issued_at_epoch_s"] == ISSUED_AT
    assert intent["not_after_epoch_s"] == NOT_AFTER
    assert intent["receipt_path"].endswith("public/reconcile-only-qualification-grant-v0.json")
    assert intent["ledger_relative_path"] == "state/epoch-2/authority-root-issuance-v0-epoch-2.sqlite3"

    document = _load_artifact()[1]
    assert document["ORIGINAL_RECEIPT_STATUS"] == "EXPIRED_UNUSED_FOR_QUALIFICATION"
    assert document["expired_original_freeze"] == {
        "original_receipt_mutable": "NO",
        "original_receipt_reissuable": "NO",
        "original_request_id_reusable": "NO",
        "original_timestamp_refresh_allowed": "NO",
        "root_cause": "QUALIFICATION_NOT_COMPLETED_WITHIN_VALID_GRANT_WINDOW",
    }


def test_epoch_2_ledger_is_read_only_one_row_and_next_serial_is_two() -> None:
    with sqlite3.connect(f"file:{LEDGER}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        metadata = connection.execute("SELECT * FROM issuer_metadata").fetchone()
        assert metadata is not None
        assert metadata["authority_epoch"] == 2
        assert metadata["minimum_authority_epoch"] == 1
        assert metadata["trust_config_version"] == 1
        assert metadata["trust_config_digest"] == TRUST_CONFIG_DIGEST
        rows = connection.execute(
            "SELECT request_id, request_digest, authority_epoch, serial, receipt_id, receipt_bytes "
            "FROM issuances ORDER BY serial"
        ).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row["request_id"] == ORIGINAL_REQUEST_ID
        assert row["request_digest"] == ORIGINAL_REQUEST_BYTES_SHA256
        assert row["authority_epoch"] == 2
        assert row["serial"] == 1
        assert row["receipt_id"] == ORIGINAL_RECEIPT_ID
        assert bytes(row["receipt_bytes"]) == ORIGINAL_RECEIPT.read_bytes()
        assert connection.execute(
            "SELECT COUNT(*) FROM issuances WHERE request_id = ?", (SUCCESSOR_REQUEST_ID,)
        ).fetchone()[0] == 0
        assert connection.execute("SELECT COALESCE(MAX(serial), 0) + 1 FROM issuances").fetchone()[0] == 2


def test_successor_scope_is_identical_and_admissible_without_issuing_a_receipt() -> None:
    policy = _successor_policy()
    request = _successor_request()
    assert policy.policy_digest == ISSUER_POLICY_DIGEST
    assert request.authority_policy == _successor_scope()
    assert request.authority_policy.granted_level is AuthorityLevel.RECONCILE_ONLY
    assert request.authority_policy.permitted_repository_commit == QNTYSPOT_MAIN
    assert request.authority_policy.permitted_implementation_digest == IMPLEMENTATION_DIGEST
    assert request.authority_policy.permitted_network_id == NETWORK
    assert request.authority_policy.permitted_taker_address == TAKER
    assert request.authority_policy.permitted_venue_id == VENUE
    assert request.authority_policy.max_reservation_atomic == 1
    assert request.authority_policy.max_cumulative_atomic == 1
    assert request.authority_policy.not_after_epoch_s - request.authority_policy.not_before_epoch_s == 900
    _exact_successor_gate(SUCCESSOR_REQUEST_ID, request)
    assert ORIGINAL_RECEIPT.exists()
    assert not (
        PRODUCTION_ROOT / "public/reconcile-only-qualification-grant-v0r1.json"
    ).exists()


@pytest.mark.parametrize(
    "name,changes",
    [
        ("level-2", {"level": AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES}),
        ("level-3", {"level": AuthorityLevel.HUMAN_SIGNED_EXECUTION}),
        ("level-4", {"level": AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER}),
        ("mainnet", {"network": "evm:4663"}),
        ("wrong-network", {"network": "evm:1"}),
        ("wrong-taker", {"taker": "0x1111111111111111111111111111111111111111"}),
        ("zero-taker", {"taker": "0x0000000000000000000000000000000000000000"}),
        ("old-venue", {"venue": OLD_VENUE}),
        ("another-venue", {"venue": "another-venue"}),
        ("wildcard-venue", {"venue": "*"}),
        ("reservation-2", {"max_reservation_atomic": 2}),
        ("cumulative-2", {"max_cumulative_atomic": 2}),
        ("duration-901", {"not_after_epoch_s": 1901}),
        ("duration-3600", {"not_after_epoch_s": 4600}),
    ],
)
def test_successor_authority_boundaries_fail_closed(name: str, changes: dict[str, Any]) -> None:
    del name
    try:
        candidate = _successor_request(**changes)
        assert_issuance_request_admissible(_successor_policy(), candidate)
    except (AuthorityRootError, IssuancePolicyError):
        return
    raise AssertionError(f"hostile successor request was admitted: {changes}")


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", "a" * 40),
        ("implementation_digest", "b" * 64),
    ],
)
def test_source_substitutions_pass_generic_shape_but_fail_exact_governance(
    field: str, value: str
) -> None:
    candidate = _successor_request(**{field: value})
    assert_issuance_request_admissible(_successor_policy(), candidate)
    with pytest.raises(GovernanceRejection, match="exact governed scope"):
        _exact_successor_gate(SUCCESSOR_REQUEST_ID, candidate)


@pytest.mark.parametrize(
    "label,kwargs",
    [
        ("original-request-id", {"request_id": ORIGINAL_REQUEST_ID}),
        ("second-successor", {"request_id": "qnty-reconcile-only-qualification-grant-v0r2"}),
    ],
)
def test_only_one_distinct_successor_request_is_authorized(label: str, kwargs: dict[str, Any]) -> None:
    del label
    with pytest.raises(GovernanceRejection):
        _exact_successor_gate(kwargs["request_id"], _successor_request())


def test_same_epoch_and_existing_ledger_are_mandatory() -> None:
    request = _successor_request()
    with pytest.raises(GovernanceRejection, match="epoch 2"):
        _exact_successor_gate(SUCCESSOR_REQUEST_ID, request, authority_epoch=3)
    with pytest.raises(GovernanceRejection, match="existing governed epoch-2 ledger"):
        _exact_successor_gate(
            SUCCESSOR_REQUEST_ID,
            request,
            ledger_path=ROOT / "alternate-ledger.sqlite3",
        )
    document = _load_artifact()[1]
    assert document["AUTHORITY_EPOCH"] == 2
    assert document["NEW_AUTHORITY_EPOCH"] == "NO"
    assert document["NEW_LEDGER"] == "NO"
    assert document["same_governed_ledger"]["expected_successor_serial"] == 2


def test_checkpoint_and_just_in_time_workflow_are_frozen() -> None:
    document = _load_artifact()[1]
    workflow = document["operational_episode"]["workflow"]
    assert workflow.index("PERFORM_HOSTILE_REVIEW") < workflow.index(
        "ISSUE_SUCCESSOR_LEVEL_1_RECEIPT_ONLY_AFTER_PREFLIGHT"
    )
    assert workflow.index("IMMEDIATELY_CREATE_DURABLE_QUOTE_RESERVATION") < workflow.index(
        "IMMEDIATELY_ENTER_HUMAN_EXTERNAL_TRANSACTION_CHECKPOINT"
    )
    checkpoint = document["human_external_transaction_checkpoint"]
    assert checkpoint["required"] == "YES"
    assert checkpoint["checkpoint_after"] == "ISSUANCE_AND_DURABLE_RESERVATION"
    assert checkpoint["required_output_fields"] == [
        "EXTERNAL_TX_REQUIRED_NOW",
        "SECONDS_REMAINING",
        "NETWORK = Robinhood Chain testnet / evm:46630",
        "EXPECTED_TAKER = 0x1324d87e24e1657f6fe6805de814bb6873052106",
        "REQUIRED_OUTCOME = REVERTED",
        "TRANSACTION_COUNT_ALLOWED = 1",
        "QNTYSPOT_CONSTRUCTS_TRANSACTION = NO",
        "QNTYSPOT_SIGNS_TRANSACTION = NO",
        "QNTYSPOT_SUBMITS_TRANSACTION = NO",
        "USER_MUST_RETURN = PUBLIC_TRANSACTION_HASH_ONLY",
    ]
    assert document["operational_episode"]["provider_observation_count"] == 2
    assert document["operational_episode"]["finality_minimum_blocks"] == 32
    assert document["operational_episode"]["terminal_intent_state"] == "REJECTED"
    assert document["operational_episode"]["reservation_terminal_state"] == "RELEASED"
    assert document["operational_episode"]["fill_receipt_created"] == "NO"


def test_no_future_successor_production_files_exist_yet() -> None:
    document = _load_artifact()[1]
    paths = document["production_paths_deferred"]
    assert paths["created_now"] == []
    for relative in (
        paths["future_intent"],
        paths["future_intent_sidecar"],
        paths["future_receipt"],
        paths["future_receipt_sidecar"],
    ):
        assert not (PRODUCTION_ROOT / relative).exists()


def test_single_hostile_review_has_no_critical_or_high_findings() -> None:
    review = _load_artifact()[1]["hostile_review"]
    assert review["review_count"] == 1
    assert review["review_stage"] == "AFTER_CANDIDATE_FREEZE"
    assert review["critical"] == 0
    assert review["high"] == 0
    assert review["targeted_rereview"] == "NOT_REQUIRED"
    assert all(value == "PASS" for value in review["attack_results"].values())


def test_recovery_does_not_read_private_keys_or_create_a_receipt() -> None:
    assert not (PRODUCTION_ROOT / "public/reconcile-only-qualification-grant-v0r1.json").exists()
    assert _load_artifact()[1]["synthetic_recovery_tests"]["no_successor_receipt_issued"] == "YES"
