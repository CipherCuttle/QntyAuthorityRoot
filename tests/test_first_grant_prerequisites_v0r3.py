from __future__ import annotations

import hashlib
import importlib
import importlib.util
import io
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from qnty_authority_root import (
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    AuthorityRootError,
    IssuancePolicyError,
    assert_issuance_request_admissible,
    canonical_json_bytes,
    strict_json_loads,
)
from qnty_authority_root.policy import validate_request_id


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/FIRST_GRANT_PREREQUISITES_V0R3.json"
SIDECAR = ROOT / "artifacts/FIRST_GRANT_PREREQUISITES_V0R3.sha256"
QNTYSPOT_REPO = ROOT.parents[1] / "repos/QntySpot"

QNTYAUTHORITYROOT_PARENT = "1f53a26ecffd8efa844ad74cf77cc14c1f37e171"
QNTYSPOT_COMMIT = "6a23171e790e8ae95c9b7bf6c2b55fe6d06a66bf"
IMPLEMENTATION_DIGEST = "d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de"
DECLARATION_DIGEST = "f11b20d7b417571eb235010989c5479e2fd2c31a16d1e06df453ea870ebcba06"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
VENUE = "zero-x-swap-v2-robinhood-chain"
NETWORK = "evm:46630"
ROOT_ID = "qnty-authority-root-v0"
REPOSITORY = "CipherCuttle/QntySpot"
REQUEST_ID = "qnty-first-production-shadow-grant-v0"
ISSUER_POLICY_DIGEST = "680b0bc9076413e7d09f53d9259503ac33482a978c7546f8da2b0c4a21a2b7ed"
SYNTHETIC_POLICY_DIGEST = "1787b0ea9810361f992ee174c520b9b2e0c83b9bed8264c4c2a325ae18ed7cfe"
BLOCKED_V0R2_POLICY_DIGEST = "842c02de77239d67c00ef1f2c0055048c87741f3e37653731cf202329dfb8847"
BLOCKED_V0R2_ARTIFACT_DIGEST = "5c8747ec7fcdb597e21602692fb9c2697622002a76096f6a8b76efa81a1bf2fe"
OLD_IMPLEMENTATION_DIGEST = "2da5b936e8cb657d5204a161c27cc94862a18099db838a1c97e77deccb6b9f9d"
OLD_VENUE = "0x-swap-v2-robinhood-chain"


EXPECTED_ISSUER_POLICY = {
    "allowed_network_ids": [NETWORK],
    "allowed_taker_addresses": [TAKER],
    "allowed_venue_ids": [VENUE],
    "max_cumulative_atomic": "1",
    "max_grant_duration_s": 300,
    "max_reservation_atomic": "1",
    "maximum_issuable_level": 0,
    "repository_identity": REPOSITORY,
    "root_id": ROOT_ID,
    "schema": "qntyspot.authority_root.v0.issuance_policy",
}

EXPECTED_SYNTHETIC_POLICY = {
    "authority_root_id": ROOT_ID,
    "granted_level": 0,
    "max_cumulative_atomic": "1",
    "max_reservation_atomic": "1",
    "not_after_epoch_s": 1300,
    "not_before_epoch_s": 1000,
    "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
    "permitted_network_id": NETWORK,
    "permitted_repository_commit": QNTYSPOT_COMMIT,
    "permitted_taker_address": TAKER,
    "permitted_venue_id": VENUE,
    "schema": "qntyspot.program_b.v0.authority_policy",
}


def _issuer_policy() -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity=REPOSITORY,
        maximum_issuable_level=AuthorityLevel.SHADOW,
        allowed_network_ids=(NETWORK,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE,),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=300,
    )


def _authority_policy(**changes: Any) -> AuthorityPolicyRefV0:
    values: dict[str, Any] = {
        "authority_root_id": ROOT_ID,
        "granted_level": AuthorityLevel.SHADOW,
        "permitted_repository_commit": QNTYSPOT_COMMIT,
        "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
        "permitted_network_id": NETWORK,
        "permitted_taker_address": TAKER,
        "permitted_venue_id": VENUE,
        "max_reservation_atomic": 1,
        "max_cumulative_atomic": 1,
        "not_before_epoch_s": 1000,
        "not_after_epoch_s": 1300,
    }
    values.update(changes)
    return AuthorityPolicyRefV0(**values)


def _synthetic_request(**changes: Any) -> AuthorityIssuanceRequestV0:
    repository_identity = changes.pop("repository_identity", REPOSITORY)
    issued_at_epoch_s = changes.pop("issued_at_epoch_s", 1000)
    return AuthorityIssuanceRequestV0(
        repository_identity=repository_identity,
        authority_policy=_authority_policy(**changes),
        issued_at_epoch_s=issued_at_epoch_s,
    )


def _negative_failure_layer(**changes: Any) -> str:
    try:
        request = _synthetic_request(**changes)
    except (AuthorityRootError, IssuancePolicyError, TypeError, ValueError):
        return "AuthorityPolicyRefV0 construction"
    try:
        assert_issuance_request_admissible(_issuer_policy(), request)
    except (AuthorityRootError, IssuancePolicyError, TypeError, ValueError):
        return "assert_issuance_request_admissible"
    raise AssertionError("negative case unexpectedly passed")


def test_artifact_is_exact_canonical_json_and_contains_no_production_issuance() -> None:
    raw = ARTIFACT.read_bytes()
    artifact = strict_json_loads(raw)

    assert raw == canonical_json_bytes(artifact)
    assert artifact["schema"] == "qnty.authority_root.first_grant_prerequisites.v0r3"
    assert artifact["issuer_policy"] == EXPECTED_ISSUER_POLICY
    assert artifact["issuer_policy_digest"] == ISSUER_POLICY_DIGEST
    assert artifact["synthetic_validation"]["authority_policy"] == EXPECTED_SYNTHETIC_POLICY
    assert artifact["synthetic_validation"]["authority_policy_digest"] == SYNTHETIC_POLICY_DIGEST
    assert artifact["synthetic_validation"]["status"] == "NON_PRODUCTION"

    lowered = raw.lower()
    assert b"-----begin" not in lowered
    assert b"/home/swirky/.local/share/qnty-authority-root/production/v0" not in lowered
    assert b'"receipt_id"' not in raw
    assert b'"grant_id"' not in raw


def test_artifact_sidecar_covers_exact_bytes() -> None:
    digest = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    assert SIDECAR.read_text(encoding="ascii") == f"{digest}  {ARTIFACT.name}\n"


def test_exact_issuer_policy_object_and_digest() -> None:
    policy = _issuer_policy()
    assert policy.canonical_object() == EXPECTED_ISSUER_POLICY
    assert policy.policy_digest == ISSUER_POLICY_DIGEST
    assert policy.maximum_issuable_level is AuthorityLevel.SHADOW
    assert policy.allowed_network_ids == (NETWORK,)
    assert policy.allowed_taker_addresses == (TAKER,)
    assert policy.allowed_venue_ids == (VENUE,)
    assert policy.max_reservation_atomic == 1
    assert policy.max_cumulative_atomic == 1
    assert policy.max_grant_duration_s == 300


def test_exact_synthetic_policy_digest_and_admissible_request() -> None:
    policy = _authority_policy()
    request = AuthorityIssuanceRequestV0(
        repository_identity=REPOSITORY,
        authority_policy=policy,
        issued_at_epoch_s=1000,
    )

    assert policy.canonical_object() == EXPECTED_SYNTHETIC_POLICY
    assert policy.authority_policy_digest == SYNTHETIC_POLICY_DIGEST
    assert_issuance_request_admissible(_issuer_policy(), request)
    assert request.authority_policy.granted_level is AuthorityLevel.SHADOW
    assert request.authority_policy.not_before_epoch_s == 1000
    assert request.authority_policy.not_after_epoch_s == 1300


def test_required_negative_proofs_fail_closed_at_observed_layers() -> None:
    cases = (
        ("authority-reconcile-only", {"granted_level": AuthorityLevel.RECONCILE_ONLY}),
        ("authority-submit-exact-signed-bytes", {"granted_level": AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES}),
        ("authority-human-signed-execution", {"granted_level": AuthorityLevel.HUMAN_SIGNED_EXECUTION}),
        ("authority-autonomous-bounded-signer", {"granted_level": AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER}),
        ("network-mainnet-evm-4663", {"permitted_network_id": "evm:4663"}),
        ("network-other-explicit-evm-1", {"permitted_network_id": "evm:1"}),
        ("network-wildcard", {"permitted_network_id": "*"}),
        ("network-alias", {"permitted_network_id": "latest"}),
        ("taker-different-valid-nonzero-address", {"permitted_taker_address": "0x00000000000000000000000000000000000000bb"}),
        ("taker-zero-address", {"permitted_taker_address": "0x0000000000000000000000000000000000000000"}),
        ("venue-old-invalid-0x-swap-v2-robinhood-chain", {"permitted_venue_id": OLD_VENUE}),
        ("venue-zero-x-allowance-holder", {"permitted_venue_id": "zero-x-allowance-holder"}),
        ("venue-another-portable-venue", {"permitted_venue_id": "another-portable-venue"}),
        ("venue-wildcard", {"permitted_venue_id": "*"}),
        ("capital-reservation-2", {"max_reservation_atomic": 2, "max_cumulative_atomic": 2}),
        ("capital-cumulative-2", {"max_cumulative_atomic": 2}),
        ("capital-reservation-0", {"max_reservation_atomic": 0}),
        ("capital-cumulative-less-than-reservation", {"max_reservation_atomic": 2, "max_cumulative_atomic": 1}),
        ("duration-301-seconds", {"not_after_epoch_s": 1301}),
        ("duration-3600-seconds", {"not_after_epoch_s": 4600}),
        ("duration-zero", {"not_after_epoch_s": 1000}),
        ("duration-negative", {"not_after_epoch_s": 999}),
        ("root-different-root-id", {"authority_root_id": "other-authority-root"}),
        ("repository-different-owner-name", {"repository_identity": "CipherCuttle/Other"}),
    )
    observed = [
        {"case": name, "failure_layer": _negative_failure_layer(**changes)}
        for name, changes in cases
    ]
    artifact = strict_json_loads(ARTIFACT.read_bytes())
    assert observed == artifact["negative_proofs"]


def test_request_id_rules_are_truthful_and_exact() -> None:
    assert validate_request_id(REQUEST_ID) == REQUEST_ID
    for invalid in ("*", "latest", "ANY", "identifier with spaces", "Qnty-first-production-shadow-grant-v0"):
        with pytest.raises(IssuancePolicyError):
            validate_request_id(invalid)

    retry_suffix = f"{REQUEST_ID}-retry-1"
    retry_generically_valid = True
    try:
        assert validate_request_id(retry_suffix) == retry_suffix
    except IssuancePolicyError:
        retry_generically_valid = False

    artifact = strict_json_loads(ARTIFACT.read_bytes())
    assert artifact["request_id_rule"]["exact_request_id"] == REQUEST_ID
    assert artifact["request_id_rule"]["retry_request_id_policy"] == "reuse exact original request_id"
    assert retry_generically_valid is True
    assert artifact["request_id_rule"]["same_logical_first_grant_must_not_use_retry_suffix"] is True


def _canonical_qntyspot_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "canonical-qntyspot"
    archive = subprocess.run(
        ["git", "-C", str(QNTYSPOT_REPO), "archive", QNTYSPOT_COMMIT],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(checkout)
    return checkout


def _load_identity_builder(checkout: Path):
    path = checkout / "scripts/derive_deployment_identity.py"
    spec = importlib.util.spec_from_file_location("canonical_qntyspot_identity", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_identity


def test_exact_qntyspot_commit_identity_and_declaration(tmp_path: Path) -> None:
    commit = subprocess.run(
        ["git", "-C", str(QNTYSPOT_REPO), "rev-parse", f"{QNTYSPOT_COMMIT}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert commit == QNTYSPOT_COMMIT

    checkout = _canonical_qntyspot_checkout(tmp_path)
    identity = _load_identity_builder(checkout)(checkout, QNTYSPOT_COMMIT)
    assert identity["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert identity["implementation_digest"] == IMPLEMENTATION_DIGEST

    declaration = checkout / "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R1.json"
    declaration_raw = declaration.read_bytes()
    declaration_object = strict_json_loads(declaration_raw)
    assert hashlib.sha256(declaration_raw).hexdigest() == DECLARATION_DIGEST
    assert declaration_raw == canonical_json_bytes(declaration_object)
    assert declaration_object["schema"] == "qntyspot.robinhood_testnet_taker_declaration.v0r1"
    assert declaration_object["venue_id"] == VENUE
    assert declaration_object["network_id"] == NETWORK
    assert declaration_object["taker_address"] == TAKER


def test_exact_qntyspot_authority_contract_has_shadow_ceiling_and_no_root_import(tmp_path: Path) -> None:
    checkout = _canonical_qntyspot_checkout(tmp_path)
    sys.path.insert(0, str(checkout))
    try:
        execution = importlib.import_module("qntyspot.execution_contract")
        runtime_authority = importlib.import_module("qntyspot.authority_root")
        canonical_policy = execution.AuthorityPolicyRefV0(
            authority_root_id=ROOT_ID,
            granted_level=execution.AuthorityLevel.SHADOW,
            permitted_repository_commit=QNTYSPOT_COMMIT,
            permitted_implementation_digest=IMPLEMENTATION_DIGEST,
            permitted_network_id=NETWORK,
            permitted_taker_address=TAKER,
            permitted_venue_id=VENUE,
            max_reservation_atomic=1,
            max_cumulative_atomic=1,
            not_before_epoch_s=1000,
            not_after_epoch_s=1300,
        )
        assert canonical_policy.canonical_object() == EXPECTED_SYNTHETIC_POLICY
        assert execution.PHASE_GRANTED_AUTHORITY_LEVEL is execution.AuthorityLevel.SHADOW
        effective = min(execution.PHASE_GRANTED_AUTHORITY_LEVEL, canonical_policy.granted_level)
        assert effective is execution.AuthorityLevel.SHADOW
        capabilities = execution.granted_capabilities(execution.AuthorityLevel.SHADOW)
        for forbidden in (
            execution.Capability.RESERVE_CAPITAL,
            execution.Capability.AUTHORIZE_APPROVAL,
            execution.Capability.CONSTRUCT_ENVELOPE,
            execution.Capability.SUBMIT_EXACT_BYTES,
            execution.Capability.PRODUCE_SIGNATURE,
        ):
            assert forbidden not in capabilities
        assert runtime_authority.PHASE_GRANTED_AUTHORITY_LEVEL is execution.AuthorityLevel.SHADOW
    finally:
        for name in list(sys.modules):
            if name == "qntyspot" or name.startswith("qntyspot."):
                del sys.modules[name]
        sys.path.remove(str(checkout))

    runtime_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (checkout / "qntyspot").rglob("*.py")
    )
    assert "qnty_authority_root" not in runtime_source


def test_current_artifact_does_not_reuse_retired_or_blocked_values() -> None:
    raw = ARTIFACT.read_bytes().decode("utf-8")
    artifact = strict_json_loads(raw)
    current_values = {str(value) for value in artifact.values() if isinstance(value, (str, int, float, bool))}
    assert BLOCKED_V0R2_POLICY_DIGEST not in current_values
    assert BLOCKED_V0R2_ARTIFACT_DIGEST not in current_values
    assert OLD_IMPLEMENTATION_DIGEST not in raw
    assert artifact["qntyspot_binding"]["permitted_venue_id"] == VENUE
    assert artifact["qntyspot_binding"]["permitted_venue_id"] != OLD_VENUE
    assert artifact["qntyspot_binding"]["permitted_implementation_digest"] == IMPLEMENTATION_DIGEST


def test_authority_root_source_is_unchanged_from_clean_parent() -> None:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            QNTYAUTHORITYROOT_PARENT,
            "--",
            "src/qnty_authority_root",
        ],
        cwd=ROOT,
    )
    assert result.returncode == 0
