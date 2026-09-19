from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    canonical_json_bytes,
    sha256_hex,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "issue_ink_v0f_epoch5_production_grant.py"
GOVERNANCE = ROOT / "artifacts" / "INK_V0F_LEVEL3_EPOCH5_GOVERNANCE_V0.json"
GOVERNANCE_SIDECAR = GOVERNANCE.with_suffix(".sha256")


def _module():
    spec = importlib.util.spec_from_file_location("ink_epoch5_issuer", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _key_material(tmp_path: Path):
    seed = hashlib.sha256(b"ink-v0f-epoch5-production-test").digest()
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fingerprint = sha256_hex(public)
    trust = {
        "minimum_authority_epoch": 1,
        "public_key_fingerprint": fingerprint,
        "root_id": "qnty-authority-root-v0",
        "schema": "qntyspot.authority_root.v0.trust_config",
        "signature_algorithm": "Ed25519",
        "trust_config_version": 1,
    }
    trust_bytes = canonical_json_bytes(trust)
    private_path = tmp_path / "authority-root.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    return private_path, public, fingerprint, trust_bytes, sha256_hex(trust_bytes)


def _production_root(tmp_path: Path, public: bytes, trust_bytes: bytes) -> Path:
    root = tmp_path / "production"
    (root / "public").mkdir(parents=True)
    (root / "state").mkdir()
    (root / "public" / "authority-root-ed25519-v0.pub").write_bytes(public)
    (root / "public" / "trusted-authority-root-v0.json").write_bytes(trust_bytes)
    return root


def test_epoch5_governance_artifact_is_exact_and_forbids_epoch4_reuse() -> None:
    raw = GOVERNANCE.read_bytes()
    doc = json.loads(raw)
    assert raw == canonical_json_bytes(doc)
    digest = sha256_hex(raw)
    assert digest == "74fb3c2d2e377bb08ce6ec813c96b36a5477181189ff62e3b94ad9b584498f02"
    assert GOVERNANCE_SIDECAR.read_text(encoding="ascii") == (
        f"{digest}  {GOVERNANCE.name}\n"
    )
    assert doc["epoch_4"]["level_3_authorized"] == "NO"
    assert doc["epoch_4"]["reuse_for_ink_level3"] == "FORBIDDEN"
    assert doc["epoch_5"]["authority_epoch"] == 5
    assert doc["epoch_5"]["ledger_relative_path"] == (
        "state/epoch-5/authority-root-issuance-v0-epoch-5.sqlite3"
    )
    assert doc["exact_grant_scope"]["permitted_repository_commit"] == (
        "af5edb2eaf9e6ab55a8295da4a9cb5f2e7d549b6"
    )
    assert doc["exact_grant_scope"]["permitted_implementation_digest"] == (
        "f0f3dfb14ddc5be1b2b500fdd4bf134f37dc63c56116e8be39a5496b95db707a"
    )
    assert doc["exact_grant_scope"]["granted_level_numeric"] == 3
    assert doc["exact_grant_scope"]["max_reservation_atomic"] == "1000000000000000"
    assert doc["exact_grant_scope"]["max_cumulative_atomic"] == "1000000000000000"
    assert doc["exact_grant_scope"]["grant_duration_seconds"] == 900


def test_epoch5_current_rebind_refuses_before_preflight_key_or_ledger(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _module()
    private_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _production_root(tmp_path, public, trust_bytes)
    monkeypatch.setattr(module, "EXPECTED_PUBLIC_KEY_FINGERPRINT", fingerprint)
    monkeypatch.setattr(module, "EXPECTED_TRUST_CONFIG_DIGEST", trust_digest)
    monkeypatch.setattr(
        module,
        "_run_read_only_preflight",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("superseded epoch-5 lane must refuse before preflight")
        ),
    )
    monkeypatch.setattr(
        module,
        "_load_private_key",
        lambda path: (_ for _ in ()).throw(
            AssertionError("superseded epoch-5 lane must refuse before key access")
        ),
    )

    assert module.CURRENT_QNTYSPOT_COMMIT != module.EXPECTED_QNTYSPOT_COMMIT
    assert module.CURRENT_IMPLEMENTATION_DIGEST != module.EXPECTED_IMPLEMENTATION_DIGEST
    with pytest.raises(RuntimeError, match="historical-only"):
        module.issue_once(
            production_root=root,
            private_key_path=private_path,
            issued_at_epoch_s=2_000_000_000,
        )

    assert not (root / "state/epoch-5").exists()


def test_epoch5_historical_receipt_validator_remains_exact() -> None:
    module = _module()
    issued_at = 2_000_000_000
    policy = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        permitted_repository_commit=module.EXPECTED_QNTYSPOT_COMMIT,
        permitted_implementation_digest=module.EXPECTED_IMPLEMENTATION_DIGEST,
        permitted_network_id=module.EXPECTED_NETWORK,
        permitted_taker_address=module.EXPECTED_TAKER,
        permitted_venue_id=module.EXPECTED_VENUE,
        max_reservation_atomic=module.EXPECTED_ATOMIC,
        max_cumulative_atomic=module.EXPECTED_ATOMIC,
        not_before_epoch_s=issued_at,
        not_after_epoch_s=issued_at + module.DURATION_S,
    )
    receipt = AuthorityGrantReceiptV0(
        root_id="qnty-authority-root-v0",
        public_key_fingerprint="11" * 32,
        signature_algorithm="Ed25519",
        authority_epoch=module.AUTHORITY_EPOCH,
        serial=1,
        issued_at_epoch_s=issued_at,
        authority_policy=policy,
        signature=b"\x00" * 64,
    )
    module._assert_exact_receipt(receipt, issued_at_epoch_s=issued_at)

    current_scope = AuthorityPolicyRefV0(
        authority_root_id=policy.authority_root_id,
        granted_level=policy.granted_level,
        permitted_repository_commit=module.CURRENT_QNTYSPOT_COMMIT,
        permitted_implementation_digest=module.CURRENT_IMPLEMENTATION_DIGEST,
        permitted_network_id=policy.permitted_network_id,
        permitted_taker_address=policy.permitted_taker_address,
        permitted_venue_id=policy.permitted_venue_id,
        max_reservation_atomic=policy.max_reservation_atomic,
        max_cumulative_atomic=policy.max_cumulative_atomic,
        not_before_epoch_s=policy.not_before_epoch_s,
        not_after_epoch_s=policy.not_after_epoch_s,
    )
    current_receipt = AuthorityGrantReceiptV0(
        root_id=receipt.root_id,
        public_key_fingerprint=receipt.public_key_fingerprint,
        signature_algorithm=receipt.signature_algorithm,
        authority_epoch=receipt.authority_epoch,
        serial=receipt.serial,
        issued_at_epoch_s=receipt.issued_at_epoch_s,
        authority_policy=current_scope,
        signature=receipt.signature,
    )
    with pytest.raises(RuntimeError, match="QntySpot commit mismatch"):
        module._assert_exact_receipt(current_receipt, issued_at_epoch_s=issued_at)
