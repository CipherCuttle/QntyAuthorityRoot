from __future__ import annotations

import hashlib
import importlib
import io
import json
import sqlite3
import subprocess
import sys
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    AuthorityIssuer,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    IssuanceConflictError,
    canonical_json_bytes,
    sha256_hex,
    strict_json_loads,
)


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "artifacts/FIRST_GRANT_DESIGN_V0R1.json"
SIDECAR = ROOT / "artifacts/FIRST_GRANT_DESIGN_V0R1.sha256"
PREREQUISITES = ROOT / "artifacts/FIRST_GRANT_PREREQUISITES_V0R3.json"
PRODUCTION_ROOT = Path("/home/swirky/.local/share/qnty-authority-root/production/v0")

QNTYAUTHORITYROOT_PARENT = "3f9c31ea03d599b79009c459fc5242189fb2f77f"
PREREQUISITE_DIGEST = "ce277412228aeaa8b7a204b2e1265ac6c49727d96e3f05174f34e82cef845824"
QNTYSPOT_COMMIT = "6a23171e790e8ae95c9b7bf6c2b55fe6d06a66bf"
IMPLEMENTATION_DIGEST = "d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de"
DECLARATION_DIGEST = "f11b20d7b417571eb235010989c5479e2fd2c31a16d1e06df453ea870ebcba06"
ISSUER_POLICY_DIGEST = "680b0bc9076413e7d09f53d9259503ac33482a978c7546f8da2b0c4a21a2b7ed"
SYNTHETIC_POLICY_DIGEST = "1787b0ea9810361f992ee174c520b9b2e0c83b9bed8264c4c2a325ae18ed7cfe"
ROOT_ID = "qnty-authority-root-v0"
REPOSITORY = "CipherCuttle/QntySpot"
NETWORK = "evm:46630"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
VENUE = "zero-x-swap-v2-robinhood-chain"
REQUEST_ID = "qnty-first-production-shadow-grant-v0"
SYNTHETIC_NOW = 1100


class SyntheticSigner:
    """Deterministic test-only Ed25519 signer; never a production key loader."""

    def __init__(self, label: str = "first-grant-design-v0r1") -> None:
        seed = hashlib.sha256(label.encode("utf-8")).digest()
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.sign_calls = 0

    @property
    def public_key_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        self.sign_calls += 1
        return self._private.sign(message)


def _artifact() -> tuple[bytes, dict[str, Any]]:
    raw = DESIGN.read_bytes()
    document = strict_json_loads(raw)
    assert isinstance(document, dict)
    return raw, document


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


def _request(**changes: Any) -> AuthorityIssuanceRequestV0:
    issued_at = changes.pop("issued_at_epoch_s", 1000)
    return AuthorityIssuanceRequestV0(
        repository_identity=REPOSITORY,
        authority_policy=_authority_policy(**changes),
        issued_at_epoch_s=issued_at,
    )


def _canonical_qntyspot_checkout(tmp_path: Path) -> Path:
    candidates = (ROOT.parents[1] / "repos/QntySpot", ROOT.parent / "QntySpot")
    for candidate in candidates:
        result = subprocess.run(
            ["git", "-C", str(candidate), "rev-parse", f"{QNTYSPOT_COMMIT}^{{commit}}"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip() == QNTYSPOT_COMMIT:
            checkout = tmp_path / "canonical-qntyspot"
            archive = subprocess.run(
                ["git", "-C", str(candidate), "archive", QNTYSPOT_COMMIT],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
                tar.extractall(checkout)
            return checkout
    raise AssertionError("exact canonical QntySpot commit is not available")


def _load_canonical_qntyspot(tmp_path: Path):
    checkout = _canonical_qntyspot_checkout(tmp_path)
    sys.path.insert(0, str(checkout))
    for name in list(sys.modules):
        if name == "qntyspot" or name.startswith("qntyspot."):
            del sys.modules[name]
    return checkout, importlib.import_module("qntyspot")


def _unload_canonical_qntyspot(checkout: Path) -> None:
    sys.path.remove(str(checkout))
    for name in list(sys.modules):
        if name == "qntyspot" or name.startswith("qntyspot."):
            del sys.modules[name]


def test_design_artifact_is_canonical_and_sidecar_binds_exact_bytes() -> None:
    raw, document = _artifact()
    assert document["schema"] == "qnty.authority_root.first_grant_design.v0r1"
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == (
        f"{hashlib.sha256(raw).hexdigest()}  {DESIGN.name}\n"
    )


def test_design_consumes_exact_prerequisite_and_frozen_policy() -> None:
    _, document = _artifact()
    prerequisite_raw = PREREQUISITES.read_bytes()
    assert hashlib.sha256(prerequisite_raw).hexdigest() == PREREQUISITE_DIGEST
    assert document["canonical_inputs"]["canonical_prerequisite_artifact_digest"] == PREREQUISITE_DIGEST
    assert document["canonical_inputs"]["qnty_authority_root_canonical"] == QNTYAUTHORITYROOT_PARENT
    assert document["canonical_inputs"]["qntyspot_canonical"] == QNTYSPOT_COMMIT
    assert document["canonical_inputs"]["qntyspot_implementation_digest"] == IMPLEMENTATION_DIGEST
    assert document["canonical_inputs"]["canonical_declaration_digest"] == DECLARATION_DIGEST
    assert document["canonical_inputs"]["synthetic_prerequisite_authority_policy_digest"] == SYNTHETIC_POLICY_DIGEST
    assert document["issuer_policy"]["canonical_object"] == _issuer_policy().canonical_object()
    assert document["issuer_policy"]["digest"] == ISSUER_POLICY_DIGEST
    assert _issuer_policy().policy_digest == ISSUER_POLICY_DIGEST


def test_design_has_no_production_receipt_or_private_material() -> None:
    raw, document = _artifact()
    lowered = raw.lower()
    assert b"-----begin" not in lowered
    assert str(PRODUCTION_ROOT).encode() not in raw
    assert b'"receipt_id":"' not in raw
    assert b'"grant_id":"' not in raw
    assert b'"signature":"' not in raw
    assert document["grant_template"]["issued_at_epoch_s"] == "captured once during future issuance"
    assert document["grant_template"]["expected_serial"] == (
        "1, allocated by canonical issuer; not frozen as production data"
    )
    assert document["design_phase_actual_counters"]["PRIVATE_KEY_CONTENT_ACCESSED"] == "NO"
    assert document["design_phase_actual_counters"]["PRODUCTION_LEDGER_INITIALIZED"] == "NO"
    assert document["design_phase_actual_counters"]["PRODUCTION_RECEIPTS_CREATED"] == 0


def test_production_state_locators_are_relative_and_bounded() -> None:
    _, document = _artifact()
    layout = document["production_state_layout"]
    for key, value in layout.items():
        if key.endswith("relative"):
            assert value
            assert not value.startswith("/")
            assert ".." not in Path(value).parts
    assert layout["production_state_directory_relative"] == "state"
    assert layout["ledger_relative"] == "state/authority-root-issuance-v0.sqlite3"
    assert layout["first_grant_intent_relative"] == "state/first-grant-request-intent-v0.json"
    assert layout["first_grant_intent_sidecar_relative"] == "state/first-grant-request-intent-v0.sha256"
    assert layout["first_grant_receipt_relative"] == "public/first-grant-shadow-receipt-v0.json"
    assert layout["first_grant_receipt_sidecar_relative"] == "public/first-grant-shadow-receipt-v0.sha256"


def test_public_provisioning_reconciliation_is_root_only_and_state_is_absent() -> None:
    _, document = _artifact()
    reconciliation = document["production_public_provisioning_reconciliation"]
    assert [entry["relative_locator"] for entry in reconciliation["discovered_public_files"]] == [
        "public/authority-root-ed25519-v0.pub",
        "public/provisioning-v0.json",
        "public/trusted-authority-root-v0.json",
    ]
    observed = reconciliation["observed_root_identity"]
    assert observed["root_id"] == ROOT_ID
    assert observed["signature_algorithm"] == "Ed25519"
    assert observed["public_key_fingerprint"] == "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe"
    assert observed["trust_config_digest"] == "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
    assert reconciliation["prospective_production_state"] == "ABSENT"
    assert not (PRODUCTION_ROOT / "state").exists()


def test_intent_contract_is_deterministic_and_never_refreshes_window() -> None:
    _, document = _artifact()
    intent = {
        "authority_policy": _authority_policy().canonical_object(),
        "authority_policy_digest": SYNTHETIC_POLICY_DIGEST,
        "issued_at_epoch_s": 1000,
        "not_after_epoch_s": 1300,
        "not_before_epoch_s": 1000,
        "request_id": REQUEST_ID,
        "schema": "qnty.authority_root.first_grant_request_intent.v0",
    }
    exact_bytes = canonical_json_bytes(intent)
    assert exact_bytes == canonical_json_bytes(json.loads(exact_bytes))
    assert sha256_hex(exact_bytes) == sha256_hex(canonical_json_bytes(intent))
    refreshed = dict(intent, issued_at_epoch_s=1001, not_before_epoch_s=1001, not_after_epoch_s=1301)
    assert canonical_json_bytes(refreshed) != exact_bytes
    assert document["request_intent_contract"]["expiration_rule"].startswith("valid uncommitted intent")
    assert document["no_automatic_retry"]["retry_suffix"].startswith("FORBIDDEN")


def test_synthetic_issuer_is_exactly_once_and_append_only(tmp_path: Path) -> None:
    signer = SyntheticSigner()
    db_path = tmp_path / "synthetic-authority-root.sqlite3"
    issuer = AuthorityIssuer(
        db_path=db_path,
        issuer_policy=_issuer_policy(),
        authority_epoch=1,
        minimum_authority_epoch=1,
        trust_config_version=1,
        signer=signer,
    )
    request = _request()
    raw = issuer.issue(request_id=REQUEST_ID, request=request)
    assert signer.sign_calls == 1
    assert AuthorityGrantReceiptV0.from_bytes(raw).serial == 1
    assert issuer.list_committed() == ((REQUEST_ID, 1, AuthorityGrantReceiptV0.from_bytes(raw).receipt_id),)
    assert issuer.get_committed(REQUEST_ID) == raw

    same = issuer.issue(request_id=REQUEST_ID, request=request)
    assert same == raw
    assert signer.sign_calls == 1
    assert len(issuer.list_committed()) == 1

    with pytest.raises(IssuanceConflictError):
        issuer.issue(request_id=REQUEST_ID, request=_request(issued_at_epoch_s=1001))
    assert issuer.get_committed(REQUEST_ID) == raw

    with sqlite3.connect(db_path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="non-deletable"):
            connection.execute("DELETE FROM issuances WHERE request_id = ?", (REQUEST_ID,))


def test_ambiguous_synthetic_issue_failure_has_no_automatic_retry(tmp_path: Path) -> None:
    class AmbiguousSigner(SyntheticSigner):
        def sign(self, message: bytes) -> bytes:
            self.sign_calls += 1
            self._private.sign(message)
            raise RuntimeError("synthetic post-sign failure")

    signer = AmbiguousSigner()
    issuer = AuthorityIssuer(
        db_path=tmp_path / "ambiguous.sqlite3",
        issuer_policy=_issuer_policy(),
        authority_epoch=1,
        minimum_authority_epoch=1,
        trust_config_version=1,
        signer=signer,
    )
    with pytest.raises(RuntimeError, match="post-sign"):
        issuer.issue(request_id=REQUEST_ID, request=_request())
    assert signer.sign_calls == 1
    assert issuer.get_committed(REQUEST_ID) is None
    _, document = _artifact()
    assert document["signing_ambiguity_contract"]["truthful_categories"] == [
        "NONE",
        "KNOWN_ONE",
        "POSSIBLY_OCCURRED",
    ]
    assert document["no_automatic_retry"]["max_direct_issue_calls_per_operator_run"] == 1


def test_canonical_qntyspot_accepts_synthetic_shadow_receipt(tmp_path: Path) -> None:
    checkout, qntyspot = _load_canonical_qntyspot(tmp_path)
    try:
        signer = SyntheticSigner()
        issuer = AuthorityIssuer(
            db_path=tmp_path / "qntyspot-proof.sqlite3",
            issuer_policy=_issuer_policy(),
            authority_epoch=1,
            minimum_authority_epoch=1,
            trust_config_version=1,
            signer=signer,
        )
        raw = issuer.issue(request_id=REQUEST_ID, request=_request())
        receipt = qntyspot.authority_root.AuthorityGrantReceiptV0.from_bytes(raw)
        trusted_root = qntyspot.authority_root.load_trusted_authority_root(
            issuer.trust_config_bytes,
            expected_config_digest=issuer.trust_config_digest,
            anchor_bytes=issuer.public_anchor_bytes,
        )
        session = qntyspot.execution_contract.ExecutionSessionV0(
            repository_commit=QNTYSPOT_COMMIT,
            implementation_digest=IMPLEMENTATION_DIGEST,
            runtime_identity="authority-receipt-proof-v0",
            db_schema_version=0,
            policy_id=hashlib.sha256(b"first-grant-design-verification-only-policy-v0").hexdigest(),
            authority_policy_digest=receipt.authority_policy_digest,
            taker_address=TAKER,
            network_id=NETWORK,
            venue_id=VENUE,
            venue_adapter_version="authority-receipt-proof-v0",
            started_at_epoch_s=1050,
            session_ordinal=0,
        )
        verified = qntyspot.authority_root.verify_authority_grant(
            receipt=raw,
            trusted_root=trusted_root,
            session=session,
            now_epoch_s=SYNTHETIC_NOW,
        )
        assert verified.root_id == ROOT_ID
        assert verified.public_key_fingerprint == issuer.trusted_root.public_key_fingerprint
        assert verified.trust_config_digest == issuer.trust_config_digest
        assert verified.receipt_id == receipt.receipt_id
        assert verified.signed_body_digest == receipt.signed_body_digest
        assert qntyspot.authority_root.effective_authority_level(
            source_phase_ceiling=qntyspot.execution_contract.AuthorityLevel.SHADOW,
            verified_grant=verified,
            now_epoch_s=SYNTHETIC_NOW,
        ) is qntyspot.execution_contract.AuthorityLevel.SHADOW
        capabilities = qntyspot.authority_root.effective_capabilities(
            source_phase_ceiling=qntyspot.execution_contract.AuthorityLevel.SHADOW,
            verified_grant=verified,
            now_epoch_s=SYNTHETIC_NOW,
        )
        for forbidden in (
            "RESERVE_CAPITAL",
            "AUTHORIZE_APPROVAL",
            "CONSTRUCT_ENVELOPE",
            "SUBMIT_EXACT_BYTES",
            "PRODUCE_SIGNATURE",
        ):
            assert getattr(qntyspot.execution_contract.Capability, forbidden) not in capabilities
    finally:
        _unload_canonical_qntyspot(checkout)


@pytest.mark.parametrize(
    "variant",
    (
        "wrong_repository_commit",
        "wrong_implementation_digest",
        "wrong_network",
        "wrong_taker",
        "wrong_venue",
        "wrong_policy_digest",
        "expired",
        "not_yet_valid",
        "bad_signature",
    ),
)
def test_canonical_qntyspot_rejects_hostile_scope_or_time_variants(
    tmp_path: Path, variant: str
) -> None:
    checkout, qntyspot = _load_canonical_qntyspot(tmp_path)
    try:
        signer = SyntheticSigner()
        issuer = AuthorityIssuer(
            db_path=tmp_path / f"{variant}.sqlite3",
            issuer_policy=_issuer_policy(),
            authority_epoch=1,
            minimum_authority_epoch=1,
            trust_config_version=1,
            signer=signer,
        )
        raw = issuer.issue(request_id=REQUEST_ID, request=_request())
        parsed = qntyspot.authority_root.AuthorityGrantReceiptV0.from_bytes(raw)
        trusted_root = qntyspot.authority_root.load_trusted_authority_root(
            issuer.trust_config_bytes,
            expected_config_digest=issuer.trust_config_digest,
            anchor_bytes=issuer.public_anchor_bytes,
        )
        session = qntyspot.execution_contract.ExecutionSessionV0(
            repository_commit=QNTYSPOT_COMMIT,
            implementation_digest=IMPLEMENTATION_DIGEST,
            runtime_identity="authority-receipt-proof-v0",
            db_schema_version=0,
            policy_id="11" * 32,
            authority_policy_digest=parsed.authority_policy_digest,
            taker_address=TAKER,
            network_id=NETWORK,
            venue_id=VENUE,
            venue_adapter_version="authority-receipt-proof-v0",
            started_at_epoch_s=1050,
        )
        now = SYNTHETIC_NOW
        receipt: Any = raw
        if variant == "wrong_repository_commit":
            session = replace(session, repository_commit="b" * 40)
        elif variant == "wrong_implementation_digest":
            session = replace(session, implementation_digest="c" * 64)
        elif variant == "wrong_network":
            session = replace(session, network_id="evm:1")
        elif variant == "wrong_taker":
            session = replace(session, taker_address="0x00000000000000000000000000000000000000bb")
        elif variant == "wrong_venue":
            session = replace(session, venue_id="another-venue")
        elif variant == "wrong_policy_digest":
            session = replace(session, authority_policy_digest="d" * 64)
        elif variant == "expired":
            now = 1300
        elif variant == "not_yet_valid":
            now = 999
        elif variant == "bad_signature":
            receipt = replace(parsed, signature=bytes(64))
        with pytest.raises(qntyspot.errors.AuthorityVerificationError):
            qntyspot.authority_root.verify_authority_grant(
                receipt=receipt,
                trusted_root=trusted_root,
                session=session,
                now_epoch_s=now,
            )
    finally:
        _unload_canonical_qntyspot(checkout)


def test_wrong_public_trust_anchor_is_rejected(tmp_path: Path) -> None:
    checkout, qntyspot = _load_canonical_qntyspot(tmp_path)
    try:
        signer = SyntheticSigner()
        issuer = AuthorityIssuer(
            db_path=tmp_path / "wrong-anchor.sqlite3",
            issuer_policy=_issuer_policy(),
            authority_epoch=1,
            minimum_authority_epoch=1,
            trust_config_version=1,
            signer=signer,
        )
        with pytest.raises(qntyspot.errors.AuthorityVerificationError):
            qntyspot.authority_root.load_trusted_authority_root(
                issuer.trust_config_bytes,
                expected_config_digest=issuer.trust_config_digest,
                anchor_bytes=b"\x00" * 32,
            )
    finally:
        _unload_canonical_qntyspot(checkout)


def test_synthetic_tests_only_use_temporary_state_and_never_production_state() -> None:
    assert not (PRODUCTION_ROOT / "state").exists()
    assert not str(PRODUCTION_ROOT) in str(ROOT)
