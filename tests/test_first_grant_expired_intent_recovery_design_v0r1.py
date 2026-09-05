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

POST_CLOCK_OPERATIONS = [
    "CAPTURE_SUCCESSOR_CLOCK_ONCE",
    "CONSTRUCT_EXACT_SUCCESSOR_AUTHORITY_POLICY",
    "COMPUTE_SUCCESSOR_AUTHORITY_POLICY_DIGEST",
    "CONSTRUCT_EXACT_SUCCESSOR_INTENT",
    "ATOMICALLY_PERSIST_SUCCESSOR_INTENT",
    "ATOMICALLY_PERSIST_SUCCESSOR_INTENT_SIDECAR",
    "LOAD_EXPLICIT_PROVISIONED_AUTHORITY_ROOT_PRIVATE_KEY",
    "VERIFY_DERIVED_PUBLIC_KEY_FINGERPRINT",
    "VERIFY_DERIVED_PUBLIC_KEY_EQUALS_PUBLIC_ANCHOR",
    "CONSTRUCT_CANONICAL_AUTHORITY_ISSUER",
    "GET_COMMITTED_ORIGINAL_REQUEST",
    "GET_COMMITTED_SUCCESSOR_REQUEST",
    "REQUIRE_NO_UNEXPECTED_COMMITMENT_OR_HISTORY",
    "CAPTURE_ACTUAL_NOW_FOR_LIVE_GATE",
    "REQUIRE_ACTUAL_NOW_LT_SUCCESSOR_NOT_AFTER",
    "ISSUE_SUCCESSOR_EXACTLY_ONCE",
]


def _design() -> tuple[bytes, dict[str, object]]:
    raw = DESIGN.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    return raw, document


def _timing_contract(document: dict[str, object]) -> dict[str, object]:
    timing = document["successor_issuance_timing_contract"]
    assert isinstance(timing, dict)
    return timing


def test_artifact_and_sidecar_bind_exact_canonical_bytes() -> None:
    raw, document = _design()
    assert canonical_json_bytes(document) == raw
    fields = SIDECAR.read_text(encoding="utf-8").split()
    assert fields == [sha256_hex(raw), DESIGN.name]


def test_timing_contract_freezes_complete_pre_clock_readiness_and_key_rule() -> None:
    _, document = _design()
    timing = _timing_contract(document)

    assert timing["pre_clock_readiness"] == {
        "all_artifact_hashing_repository_inspection_completed": "YES",
        "all_git_github_verification_required_for_ceremony_completed": "YES",
        "all_normal_test_suites_required_for_issuance_preflight_completed": "YES",
        "all_qntyspot_checkout_worktree_preparation_completed": "YES",
        "all_required_imports_and_local_runtime_setup_complete": "YES",
        "authority_root_canonical_verified": "YES",
        "frozen_issuer_source_verified": "YES",
        "issuer_policy_verified": "YES",
        "no_foreign_ledger_history": "YES",
        "no_original_committed_receipt": "YES",
        "no_successor_committed_receipt": "YES",
        "original_v0_intent_verified": "YES",
        "original_v0_sidecar_verified": "YES",
        "original_v0_terminal_expired_uncommitted": "YES",
        "prerequisite_artifact_verified": "YES",
        "production_ledger_exists": "YES",
        "production_ledger_row_count": 0,
        "production_ledger_schema_metadata_valid": "YES",
        "public_anchor_verified": "YES",
        "qntyspot_canonical_verified": "YES",
        "qntyspot_implementation_digest_verified": "YES",
        "qntyspot_verification_runtime_prepared": "YES",
        "recovery_design_canonical_verified": "YES",
        "successor_intent_absent_or_exact_recovery_state": "YES",
        "trust_config_verified": "YES",
    }
    assert timing["pre_clock_only_operations"] == [
        "ALL_EXPENSIVE_NONSECRET_PREPARATION",
        "ALL_REQUIRED_IMPORTS_AND_LOCAL_RUNTIME_SETUP",
        "ALL_NORMAL_TEST_SUITES_REQUIRED_FOR_ISSUANCE_PREFLIGHT",
        "ALL_GIT_GITHUB_VERIFICATION_REQUIRED_FOR_CEREMONY",
        "ALL_QNTYSPOT_CHECKOUT_WORKTREE_PREPARATION",
        "ALL_ARTIFACT_HASHING_REPOSITORY_INSPECTION",
    ]
    assert timing["pre_clock_private_key_rule"] == {
        "account_signing_material_accessed_pre_clock": "NO",
        "authority_root_private_key_accessed_pre_clock": "NO",
        "private_key_content_accessed_pre_clock": "NO",
        "provisioned_private_key_locator_resolution_pre_clock": "PERMITTED_WITHOUT_OPENING_CONTENT",
    }


def test_clock_capture_and_post_clock_sequence_are_exactly_ordered() -> None:
    _, document = _design()
    timing = _timing_contract(document)
    clock = timing["clock_capture"]
    assert clock == {
        "capture_exactly_once": "YES",
        "issued_at_epoch_s": "int(actual current Unix time)",
        "new_successor_id": "FORBIDDEN",
        "not_after_epoch_s": "issued_at_epoch_s + 300",
        "not_before_epoch_s": "issued_at_epoch_s",
        "recapture": "FORBIDDEN",
        "refresh": "FORBIDDEN",
        "successor_clock_capture_point": "AFTER_ALL_EXPENSIVE_NONSECRET_READINESS_IMMEDIATELY_BEFORE_DURABLE_SUCCESSOR_INTENT",
    }

    section = timing["post_clock_critical_section"]
    assert isinstance(section, list)
    assert [entry["sequence"] for entry in section] == list(range(1, 17))
    operations = [entry["operation"] for entry in section]
    assert operations == POST_CLOCK_OPERATIONS
    assert timing["post_clock_only_operations"] == "EXACTLY_POST_CLOCK_CRITICAL_SECTION_IN_SEQUENCE"

    assert operations.index("ATOMICALLY_PERSIST_SUCCESSOR_INTENT") < operations.index(
        "LOAD_EXPLICIT_PROVISIONED_AUTHORITY_ROOT_PRIVATE_KEY"
    )
    assert operations.index("ATOMICALLY_PERSIST_SUCCESSOR_INTENT_SIDECAR") < operations.index(
        "LOAD_EXPLICIT_PROVISIONED_AUTHORITY_ROOT_PRIVATE_KEY"
    )
    assert operations.index("VERIFY_DERIVED_PUBLIC_KEY_EQUALS_PUBLIC_ANCHOR") < operations.index(
        "CONSTRUCT_CANONICAL_AUTHORITY_ISSUER"
    )
    assert operations[-2:] == [
        "REQUIRE_ACTUAL_NOW_LT_SUCCESSOR_NOT_AFTER",
        "ISSUE_SUCCESSOR_EXACTLY_ONCE",
    ]


def test_post_clock_execution_forbids_interruption_and_expensive_work() -> None:
    _, document = _design()
    timing = _timing_contract(document)
    uninterrupted = timing["uninterrupted_execution"]
    assert uninterrupted["no_expensive_work_after_clock_capture"] == "YES"
    assert uninterrupted["no_operations_between_live_gate_and_issue"] == "YES"
    assert uninterrupted["single_local_process_invocation"] == "REQUIRED"

    for field in (
        "post_clock_agent_round_trip",
        "post_clock_artifact_discovery",
        "post_clock_deliberation",
        "post_clock_environment_discovery",
        "post_clock_git_commands",
        "post_clock_github_calls",
        "post_clock_key_discovery",
        "post_clock_manual_confirmation",
        "post_clock_network_calls",
        "post_clock_operator_interaction",
        "post_clock_provider_calls",
        "post_clock_qntyspot_checkout_setup",
        "post_clock_retry_loop",
        "post_clock_sleep",
        "post_clock_test_execution",
    ):
        assert uninterrupted[field] == "FORBIDDEN"


def test_successor_window_retry_ladder_and_telemetry_are_frozen() -> None:
    _, document = _design()
    timing = _timing_contract(document)
    assert timing["live_window"] == {
        "actual_now_capture_operation": "CAPTURE_ACTUAL_NOW_FOR_LIVE_GATE",
        "expired_successor_result": "terminal expired-uncommitted governed episode requiring new governance",
        "issue_precondition": "actual_now < successor_not_after_epoch_s",
        "on_false": ["STOP", "DO_NOT_ISSUE", "DO_NOT_REFRESH", "DO_NOT_CREATE_V0R2"],
        "no_artificial_smaller_timing_threshold": "REQUIRED_WINDOW_ONLY",
        "post_clock_pre_issue_elapsed_requirement": "POST_CLOCK_PRE_ISSUE_ELAPSED_S < 300",
        "window_seconds": 300,
    }
    assert timing["retry_and_issue_limit"]["automatic_successor_ladder"] == "FORBIDDEN"
    assert timing["retry_and_issue_limit"]["v0r2"] == "FORBIDDEN"
    assert timing["retry_and_issue_limit"]["successor_max_direct_issue_calls"] == 1
    assert document["successor_issuance_gate"]["original_v0_issue_api_may_be_called"] == "NO"
    assert timing["telemetry"]["private_key_load_started_after_intent_durable"] == "YES"
    assert (
        timing["telemetry"]["successor_intent_durable_epoch_s"]
        == "IF_MECHANICALLY_OBSERVABLE_WITHOUT_CHANGING_CANONICAL_INTENT"
    )
    assert timing["telemetry"]["required_final_reporting_fields"] == [
        "SUCCESSOR_CLOCK_CAPTURE_EPOCH_S",
        "SUCCESSOR_INTENT_DURABLE_EPOCH_S",
        "PRIVATE_KEY_LOAD_STARTED_AFTER_INTENT_DURABLE",
        "LIVE_GATE_EPOCH_S",
        "ISSUE_CALL_STARTED_EPOCH_S",
        "POST_CLOCK_PRE_ISSUE_ELAPSED_S",
    ]


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
