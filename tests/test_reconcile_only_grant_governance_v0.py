from __future__ import annotations

import hashlib
import importlib
import io
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

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
from qnty_authority_root.errors import AuthorityRootError, DatabaseError, IssuancePolicyError


ROOT = Path(__file__).resolve().parents[1]
QNTYSPOT_REPO = ROOT.parent / "QntySpot"
ARTIFACT = ROOT / "artifacts/RECONCILE_ONLY_GRANT_GOVERNANCE_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")

AUTHORITY_ROOT_MAIN = "618b05f1e780f7f20443f8c020bac0f676e66ff9"
QNTYSPOT_MAIN = "e71f3d698c449bbd7eb73bcd4547899b7f5f0594"
IMPLEMENTATION_DIGEST = "bdb1f4025ee7c16130ea422bd21febd69de4759654da1710f1e41d6935f6bc81"
V0R3_DIGEST = "d4364133e8f62393f3cc3d083ff19828c7b939e6818f22fa9406a064c0e24a33"
SELECTOR_REPAIR_DIGEST = "e345bf62aa3925687a58971d811ce9f67bf28b816cc85d04f991cafffbf99e0b"
INTENT_DESIGN_DIGEST = "36c2a6e29de02462d61a9b34da609d018a16621a602c39553fcf1a57839cbfd2"
HISTORICAL_ISSUER_POLICY_DIGEST = "680b0bc9076413e7d09f53d9259503ac33482a978c7546f8da2b0c4a21a2b7ed"
PROPOSED_ISSUER_POLICY_DIGEST = "8f0751348af21cecddd545178d7d62e9538698e212d1c1a057eed4720e8bde63"
ROOT_ID = "qnty-authority-root-v0"
NETWORK = ALLOWED_NETWORK_ID
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
OLD_VENUE = "zero-x-swap-v2-robinhood-chain"
NEW_VENUE = "robinhood-chain-testnet-external-transaction"
OLD_COMMIT = "6a23171e790e8ae95c9b7bf6c2b55fe6d06a66bf"
OLD_IMPLEMENTATION_DIGEST = "d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de"
REQUEST_ID = "qnty-reconcile-only-qualification-grant-v0"
HISTORICAL_REQUEST_ID = "qnty-first-production-shadow-grant-v0"


class SyntheticSigner:
    """Deterministic in-memory signer; it never reads a key or wallet file."""

    def __init__(self, label: str) -> None:
        seed = hashlib.sha256(label.encode("utf-8")).digest()
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.sign_calls = 0

    @property
    def public_key_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        self.sign_calls += 1
        return self._private.sign(message)


class GovernanceRejection(ValueError):
    pass


def _git_blob(commit: str, relative_path: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(QNTYSPOT_REPO), "show", f"{commit}:{relative_path}"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def _historical_issuer_policy() -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.SHADOW,
        allowed_network_ids=(NETWORK,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(OLD_VENUE,),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=300,
    )


def _proposed_issuer_policy() -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
        allowed_network_ids=(NETWORK,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(NEW_VENUE,),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=900,
    )


def _policy_ref(
    *,
    level: AuthorityLevel = AuthorityLevel.RECONCILE_ONLY,
    commit: str = QNTYSPOT_MAIN,
    implementation_digest: str = IMPLEMENTATION_DIGEST,
    network: str = NETWORK,
    taker: str = TAKER,
    venue: str = NEW_VENUE,
    root_id: str = ROOT_ID,
    max_reservation_atomic: int = 1,
    max_cumulative_atomic: int = 1,
    not_before_epoch_s: int = 1000,
    not_after_epoch_s: int = 1900,
) -> AuthorityPolicyRefV0:
    return AuthorityPolicyRefV0(
        authority_root_id=root_id,
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


def _request(
    *,
    repository_identity: str = "CipherCuttle/QntySpot",
    issued_at_epoch_s: int = 1000,
    **changes: Any,
) -> AuthorityIssuanceRequestV0:
    return AuthorityIssuanceRequestV0(
        repository_identity=repository_identity,
        authority_policy=_policy_ref(**changes),
        issued_at_epoch_s=issued_at_epoch_s,
    )


def _historical_request() -> AuthorityIssuanceRequestV0:
    return _request(
        level=AuthorityLevel.SHADOW,
        commit=OLD_COMMIT,
        implementation_digest=OLD_IMPLEMENTATION_DIGEST,
        venue=OLD_VENUE,
        not_after_epoch_s=1300,
    )


def _issuer(
    path: Path,
    policy: AuthorityIssuancePolicyV0,
    signer: SyntheticSigner,
    *,
    authority_epoch: int,
) -> AuthorityIssuer:
    return AuthorityIssuer(
        db_path=path,
        issuer_policy=policy,
        authority_epoch=authority_epoch,
        minimum_authority_epoch=1,
        trust_config_version=1,
        signer=signer,
    )


def _assert_exact_governed_request(request_id: str, request: AuthorityIssuanceRequestV0) -> None:
    if request_id != REQUEST_ID:
        raise GovernanceRejection("request id is not the exact governed identity")
    if request.repository_identity != "CipherCuttle/QntySpot":
        raise GovernanceRejection("repository identity is not exact")
    if request.authority_policy != _policy_ref():
        raise GovernanceRejection("authority policy is not the exact governed binding")
    assert_issuance_request_admissible(_proposed_issuer_policy(), request)


def _clear_qntyspot_modules() -> None:
    for name in list(sys.modules):
        if name == "qntyspot" or name.startswith("qntyspot."):
            del sys.modules[name]


@pytest.fixture
def canonical_qntyspot_e71(tmp_path: Path):
    checkout = tmp_path / "canonical-qntyspot-e71"
    checkout.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(QNTYSPOT_REPO), "archive", QNTYSPOT_MAIN],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(checkout)
    sys.path.insert(0, str(checkout))
    _clear_qntyspot_modules()
    try:
        yield importlib.import_module("qntyspot")
    finally:
        _clear_qntyspot_modules()
        sys.path.remove(str(checkout))
        shutil.rmtree(checkout, ignore_errors=True)


def test_governance_artifact_is_canonical_and_pins_exact_inputs() -> None:
    raw = ARTIFACT.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == f"{sha256_hex(raw)}  {ARTIFACT.name}\n"

    inputs = document["canonical_inputs"]
    assert inputs["authority_root_main"] == AUTHORITY_ROOT_MAIN
    assert inputs["qntyspot_main"] == QNTYSPOT_MAIN
    assert inputs["qntyspot_implementation_digest"] == IMPLEMENTATION_DIGEST
    assert inputs["qntyspot_v0r3_declaration_digest"] == V0R3_DIGEST
    assert inputs["qntyspot_selector_repair_artifact_digest"] == SELECTOR_REPAIR_DIGEST
    assert inputs["qntyspot_intent_design_artifact_digest"] == INTENT_DESIGN_DIGEST
    assert inputs["historical_issuer_policy_digest"] == HISTORICAL_ISSUER_POLICY_DIGEST

    declaration_raw = _git_blob(QNTYSPOT_MAIN, "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R3.json")
    declaration = strict_json_loads(declaration_raw)
    assert sha256_hex(declaration_raw) == V0R3_DIGEST
    assert declaration["implementation_digest"] == IMPLEMENTATION_DIGEST
    assert sha256_hex(
        _git_blob(QNTYSPOT_MAIN, "artifacts/RECONCILE_ONLY_REVERT_OBSERVATION_MINIMALITY_REPAIR_V0.json")
    ) == SELECTOR_REPAIR_DIGEST
    assert sha256_hex(
        _git_blob(QNTYSPOT_MAIN, "artifacts/RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0.json")
    ) == INTENT_DESIGN_DIGEST


def test_proposed_policy_digest_and_exact_future_request() -> None:
    document = strict_json_loads(ARTIFACT.read_bytes())
    policy = _proposed_issuer_policy()
    assert policy.policy_digest == PROPOSED_ISSUER_POLICY_DIGEST
    assert policy.policy_digest != HISTORICAL_ISSUER_POLICY_DIGEST
    assert document["issuer_policy"]["canonical_object"] == policy.canonical_object()
    assert document["issuer_policy"]["digest"] == policy.policy_digest

    request = _request()
    _assert_exact_governed_request(REQUEST_ID, request)
    future = document["future_request"]
    assert future["request_id"] == REQUEST_ID
    assert future["authority_policy"] == request.authority_policy.canonical_object()
    assert future["issued_at_epoch_s"] == 1000


def test_same_ledger_policy_swap_does_not_preserve_historical_replay(tmp_path: Path) -> None:
    signer = SyntheticSigner("same-ledger-policy-swap")
    path = tmp_path / "same-ledger.sqlite3"
    historical = _issuer(path, _historical_issuer_policy(), signer, authority_epoch=1)
    historical_bytes = historical.issue(
        request_id=HISTORICAL_REQUEST_ID,
        request=_historical_request(),
    )
    assert historical.get_committed(HISTORICAL_REQUEST_ID) == historical_bytes

    swapped = _issuer(path, _proposed_issuer_policy(), signer, authority_epoch=1)
    with pytest.raises(DatabaseError, match="no longer admissible"):
        swapped.get_committed(HISTORICAL_REQUEST_ID)
    with pytest.raises(DatabaseError, match="different authority configuration"):
        _issuer(path, _proposed_issuer_policy(), signer, authority_epoch=2)


def test_broadened_flat_policy_admits_old_venue_at_level_1() -> None:
    flat_policy = AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
        allowed_network_ids=(NETWORK,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(OLD_VENUE, NEW_VENUE),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=900,
    )
    old_venue_level_1 = _request(venue=OLD_VENUE)
    assert_issuance_request_admissible(flat_policy, old_venue_level_1)


def test_epoch_2_isolated_ledger_and_qntyspot_consumer_continuity(
    tmp_path: Path, canonical_qntyspot_e71: Any
) -> None:
    del canonical_qntyspot_e71
    signer = SyntheticSigner("epoch-2-isolated-ledger")
    historical_issuer = _issuer(
        tmp_path / "epoch-1.sqlite3",
        _historical_issuer_policy(),
        signer,
        authority_epoch=1,
    )
    epoch_2_issuer = _issuer(
        tmp_path / "epoch-2.sqlite3",
        _proposed_issuer_policy(),
        signer,
        authority_epoch=2,
    )
    historical_bytes = historical_issuer.issue(
        request_id=HISTORICAL_REQUEST_ID,
        request=_historical_request(),
    )
    epoch_2_bytes = epoch_2_issuer.issue(request_id=REQUEST_ID, request=_request())
    same_policy_epoch_1 = _issuer(
        tmp_path / "same-policy-epoch-1.sqlite3",
        _proposed_issuer_policy(),
        signer,
        authority_epoch=1,
    ).issue(request_id="epoch-identity-probe", request=_request())

    epoch_1_receipt = AuthorityGrantReceiptV0.from_bytes(historical_bytes)
    epoch_2_receipt = AuthorityGrantReceiptV0.from_bytes(epoch_2_bytes)
    same_policy_epoch_1_receipt = AuthorityGrantReceiptV0.from_bytes(same_policy_epoch_1)
    assert historical_issuer.get_committed(HISTORICAL_REQUEST_ID) == historical_bytes
    assert epoch_1_receipt.root_id == epoch_2_receipt.root_id == ROOT_ID
    assert epoch_1_receipt.authority_epoch == 1
    assert epoch_2_receipt.authority_epoch == 2
    assert epoch_1_receipt.serial == epoch_2_receipt.serial == 1
    assert same_policy_epoch_1_receipt.authority_policy_digest == epoch_2_receipt.authority_policy_digest
    assert same_policy_epoch_1_receipt.grant_id != epoch_2_receipt.grant_id
    assert historical_issuer.trust_config_digest == epoch_2_issuer.trust_config_digest
    assert historical_issuer.trusted_root.trust_config_version == epoch_2_issuer.trusted_root.trust_config_version == 1
    assert historical_issuer.trusted_root.minimum_authority_epoch == epoch_2_issuer.trusted_root.minimum_authority_epoch == 1
    assert historical_issuer.public_anchor_bytes == epoch_2_issuer.public_anchor_bytes

    authority = importlib.import_module("qntyspot.authority_root")
    execution = importlib.import_module("qntyspot.execution_contract")
    ledger_module = importlib.import_module("qntyspot.ledger")
    qntyspot_errors = importlib.import_module("qntyspot.errors")
    trusted_root = authority.load_trusted_authority_root(
        epoch_2_issuer.trust_config_bytes,
        expected_config_digest=epoch_2_issuer.trust_config_digest,
        anchor_bytes=epoch_2_issuer.public_anchor_bytes,
    )

    def verify(raw: bytes, policy_id: str):
        receipt = authority.AuthorityGrantReceiptV0.from_bytes(raw)
        session = execution.ExecutionSessionV0(
            repository_commit=receipt.authority_policy.permitted_repository_commit,
            implementation_digest=receipt.authority_policy.permitted_implementation_digest,
            runtime_identity="cpython-3.11",
            db_schema_version=1,
            policy_id=policy_id,
            authority_policy_digest=receipt.authority_policy_digest,
            taker_address=receipt.authority_policy.permitted_taker_address,
            network_id=receipt.authority_policy.permitted_network_id,
            venue_id=receipt.authority_policy.permitted_venue_id,
            venue_adapter_version="v0",
            started_at_epoch_s=receipt.issued_at_epoch_s,
            session_ordinal=0,
        )
        return authority.verify_authority_grant(
            receipt=raw,
            trusted_root=trusted_root,
            session=session,
            now_epoch_s=receipt.issued_at_epoch_s,
        )

    with ledger_module.open_ledger(str(tmp_path / "consumer-continuity.sqlite3")) as ledger:
        runtime = ledger_module.ExecutionRuntime(ledger)
        historical_verified = verify(historical_bytes, "11" * 32)
        epoch_2_verified = verify(epoch_2_bytes, "22" * 32)
        assert runtime.record_verified_authority(historical_verified, accepted_at_epoch_s=1000)
        assert runtime.record_verified_authority(epoch_2_verified, accepted_at_epoch_s=1001)
        with pytest.raises(qntyspot_errors.AuthorityVerificationError, match="rolls back"):
            runtime.record_verified_authority(historical_verified, accepted_at_epoch_s=1002)
        row = ledger.connection.execute("SELECT * FROM authority_root_state").fetchone()
        assert row["highest_accepted_epoch"] == 2
        assert row["minimum_authority_epoch"] == 1
        assert row["trust_config_digest"] == epoch_2_issuer.trust_config_digest


def _assert_rejected(changes: dict[str, Any]) -> None:
    try:
        candidate = _request(**changes)
        assert_issuance_request_admissible(_proposed_issuer_policy(), candidate)
    except (AuthorityRootError, IssuancePolicyError):
        return
    raise AssertionError(f"hostile request was admitted: {changes}")


@pytest.mark.parametrize(
    "name,changes",
    [
        ("SUBMIT_EXACT_SIGNED_BYTES", {"level": AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES}),
        ("HUMAN_SIGNED_EXECUTION", {"level": AuthorityLevel.HUMAN_SIGNED_EXECUTION}),
        ("AUTONOMOUS_BOUNDED_SIGNER", {"level": AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER}),
        ("mainnet", {"network": "evm:4663"}),
        ("another-network", {"network": "evm:1"}),
        ("wrong-taker", {"taker": "0x1111111111111111111111111111111111111111"}),
        ("zero-taker", {"taker": "0x0000000000000000000000000000000000000000"}),
        ("old-venue", {"venue": OLD_VENUE}),
        ("another-venue", {"venue": "another-venue"}),
        ("wildcard-venue", {"venue": "*"}),
        ("reservation-2", {"max_reservation_atomic": 2}),
        ("cumulative-2", {"max_cumulative_atomic": 2}),
        ("zero-reservation", {"max_reservation_atomic": 0}),
        ("cumulative-less-than-reservation", {"max_reservation_atomic": 2, "max_cumulative_atomic": 1}),
        ("duration-901", {"not_after_epoch_s": 1901}),
        ("duration-3600", {"not_after_epoch_s": 4600}),
        ("zero-duration", {"not_after_epoch_s": 1000}),
        ("negative-duration", {"not_after_epoch_s": 999}),
        ("different-root", {"root_id": "other-authority-root"}),
        ("different-repository", {"repository_identity": "Other/Repository"}),
    ],
)
def test_exact_level_1_boundaries_fail_closed(name: str, changes: dict[str, Any]) -> None:
    del name
    _assert_rejected(changes)


@pytest.mark.parametrize("field", ["commit", "implementation_digest"])
def test_commit_and_implementation_substitution_requires_exact_governance(field: str) -> None:
    substitution = {field: "a" * (40 if field == "commit" else 64)}
    substituted = _request(**substitution)
    assert_issuance_request_admissible(_proposed_issuer_policy(), substituted)
    with pytest.raises(GovernanceRejection, match="exact governed binding"):
        _assert_exact_governed_request(REQUEST_ID, substituted)
    with pytest.raises(GovernanceRejection, match="exact governed identity"):
        _assert_exact_governed_request("different-request-id", substituted)


def test_governance_boundary_declares_three_changes_and_zero_production_effects() -> None:
    document = strict_json_loads(ARTIFACT.read_bytes())
    assert document["change_boundary"]["allowed_changed_paths"] == [
        "artifacts/RECONCILE_ONLY_GRANT_GOVERNANCE_V0.json",
        "artifacts/RECONCILE_ONLY_GRANT_GOVERNANCE_V0.sha256",
        "tests/test_reconcile_only_grant_governance_v0.py",
    ]
    assert document["change_boundary"]["runtime_source_changed"] == "NO"
    assert document["change_boundary"]["qntyspot_changed"] == "NO"
    assert document["ledger_strategy"]["level_1_authority_epoch"] == 2
    assert document["ledger_strategy"]["level_1_ledger_strategy"] == "ISOLATED_EPOCH_LEDGER"
    assert document["ledger_strategy"]["production_path_governance_pinned"] == "YES"
    assert document["ledger_strategy"]["production_ledger_relative"] == (
        "state/epoch-2/authority-root-issuance-v0-epoch-2.sqlite3"
    )
    counters = document["production_effect_counters"]
    assert counters["PRODUCTION_PRIVATE_KEY_ACCESSED"] == "NO"
    assert counters["PRIVATE_KEY_CONTENT_ACCESSED"] == "NO"
    assert counters["PRODUCTION_LEDGER_CREATED"] == "NO"
    assert counters["PRODUCTION_LEDGER_MUTATED"] == "NO"
    assert counters["PRODUCTION_RECEIPTS_CREATED"] == 0
    assert counters["AUTHORITY_RECEIPT_SIGNATURES"] == 0
    assert counters["BLOCKCHAIN_SIGNATURES"] == 0
    assert counters["RPC_CALLS"] == 0
    assert counters["TESTNET_TRANSACTIONS"] == 0
    assert counters["CAPITAL_DEPLOYED"] == 0
