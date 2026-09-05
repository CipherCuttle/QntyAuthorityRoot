from __future__ import annotations

from pathlib import Path

from qnty_authority_root import canonical_json_bytes, sha256_hex, strict_json_loads


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "artifacts/FIRST_GRANT_EXPIRED_INTENT_RECOVERY_DESIGN_V0R1.json"
SIDECAR = ROOT / "artifacts/FIRST_GRANT_EXPIRED_INTENT_RECOVERY_DESIGN_V0R1.sha256"

ORIGINAL_REQUEST_ID = "qnty-first-production-shadow-grant-v0"
SUCCESSOR_REQUEST_ID = "qnty-first-production-shadow-grant-v0r1"
ORIGINAL_INTENT_DIGEST = "b37bbf8e64f3302635c8a26bee719f98fdeb0f336a45ffbf7d6a246e3763664a"
ORIGINAL_AUTHORITY_POLICY_DIGEST = "223942bceec7536266094e54922f8fba2c62d08d90d085b09ba3420d4d33c8d2"
QNTYSPOT_COMMIT = "6a23171e790e8ae95c9b7bf6c2b55fe6d06a66bf"
IMPLEMENTATION_DIGEST = "d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de"
NETWORK = "evm:46630"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
VENUE = "zero-x-swap-v2-robinhood-chain"


def _design() -> tuple[bytes, dict[str, object]]:
    raw = DESIGN.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    return raw, document


def test_artifact_and_sidecar_bind_exact_canonical_bytes() -> None:
    raw, document = _design()
    assert canonical_json_bytes(document) == raw
    fields = SIDECAR.read_text(encoding="utf-8").split()
    assert fields == [sha256_hex(raw), DESIGN.name]


def test_original_episode_is_terminal_and_immutable() -> None:
    _, document = _design()
    episode = document["original_production_episode"]
    assert episode == {
        "authority_policy_digest": ORIGINAL_AUTHORITY_POLICY_DIGEST,
        "issued_at_epoch_s": 1788572085,
        "issuance_rows": 0,
        "latest_confirmed_actual_now": 1788572971,
        "not_after_epoch_s": 1788572385,
        "not_before_epoch_s": 1788572085,
        "receipt": "NONE",
        "request_id": ORIGINAL_REQUEST_ID,
        "request_intent_digest": ORIGINAL_INTENT_DIGEST,
        "request_reissuable": "NO",
        "request_status": "TERMINAL_EXPIRED_UNCOMMITTED",
        "root_receipt_signatures": 0,
    }


def test_successor_is_the_only_separately_governed_logical_request() -> None:
    _, document = _design()
    successor = document["successor_request_contract"]
    assert successor["authorized_successor_request_id"] == SUCCESSOR_REQUEST_ID
    assert successor["original_request_id"] == ORIGINAL_REQUEST_ID
    assert successor["supersession_is_not_reissuance"] == "YES"
    assert successor["authority_policy_digest"].endswith(
        "never copy 223942bceec7536266094e54922f8fba2c62d08d90d085b09ba3420d4d33c8d2"
    )
    assert document["successor_scope"]["request_id"] == SUCCESSOR_REQUEST_ID
    assert SUCCESSOR_REQUEST_ID != ORIGINAL_REQUEST_ID


def test_successor_scope_cannot_raise_shadow_authority() -> None:
    _, document = _design()
    scope = document["successor_scope"]
    assert scope["granted_level"] == "SHADOW"
    assert scope["issuer_maximum_level"] == "SHADOW"
    assert scope["source_phase_ceiling"] == "SHADOW"
    assert scope["expected_effective_authority"] == "SHADOW"
    assert scope["signing_authorized"] == "NO"
    assert scope["capital_authority"] == "NONE"
    assert scope["permitted_repository_commit"] == QNTYSPOT_COMMIT
    assert scope["permitted_implementation_digest"] == IMPLEMENTATION_DIGEST
    assert scope["permitted_network_id"] == NETWORK
    assert scope["permitted_taker_address"] == TAKER
    assert scope["permitted_venue_id"] == VENUE
    assert scope["max_reservation_atomic"] == "1"
    assert scope["max_cumulative_atomic"] == "1"


def test_design_preserves_v0_state_and_forbids_all_effects() -> None:
    raw, document = _design()
    state = document["state_preservation_contract"]
    assert state["original_intent"] == "state/first-grant-request-intent-v0.json"
    assert state["original_intent_digest_must_remain"] == ORIGINAL_INTENT_DIGEST
    assert state["original_ledger_expected_rows"] == 0
    assert state["production_state_mutation_during_design"] == "FORBIDDEN"
    assert document["successor_state_layout"]["intent_relative"] != state["original_intent"]
    assert "/home/" not in raw.decode("utf-8")

    counters = document["design_phase_actual_counters"]
    assert counters["authority_root_private_key_accessed"] == "NO"
    assert counters["account_signing_material_accessed"] == "NO"
    assert counters["authority_receipt_signatures"] == 0
    assert counters["production_request_intents_created"] == 0
    assert counters["production_ledger_initialized"] == "NO"
    assert counters["production_receipts_created"] == 0
    assert counters["production_issuance_rows_created"] == 0
    assert counters["production_serials_allocated"] == 0
    assert counters["blockchain_signatures"] == 0
    assert counters["capital_deployed"] == 0
    assert counters["robinhood_calls"] == 0
    assert counters["zerox_calls"] == 0
    assert counters["rpc_calls"] == 0
    assert counters["chainlink_calls"] == 0


def test_artifact_carries_canonical_inputs_and_pending_next_action() -> None:
    _, document = _design()
    inputs = document["canonical_inputs"]
    assert inputs["current_qnty_authority_root_canonical"] == "a20cb61bfcad2bd7db25fe2279463e5ba3f583d4"
    assert inputs["frozen_issuer_source_canonical"] == "3f9c31ea03d599b79009c459fc5242189fb2f77f"
    assert inputs["qntyspot_canonical"] == QNTYSPOT_COMMIT
    assert document["schema"] == "qnty.authority_root.first_grant_expired_intent_recovery_design.v0r1"
    assert document["status"] == "DESIGN_ONLY_PENDING_CANONICALIZATION"
    assert document["next_action"] == (
        "QNTY_AUTHORITY_ROOT_FIRST_GRANT_EXPIRED_INTENT_RECOVERY_DESIGN_V0R1_CANONICALIZATION"
    )
