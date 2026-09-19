from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qnty_authority_root import AuthorityGrantReceiptV0, canonical_json_bytes, sha256_hex

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
    assert doc["local_production_preflight"]["active_ink_grants"] == 0
    assert [row["authority_epoch"] for row in doc["local_production_preflight"]["compatible_ledgers"]] == [1, 2, 4]
    assert doc["exact_grant_scope"]["granted_level_numeric"] == 3
    assert doc["exact_grant_scope"]["max_reservation_atomic"] == "1000000000000000"
    assert doc["exact_grant_scope"]["max_cumulative_atomic"] == "1000000000000000"
    assert doc["exact_grant_scope"]["grant_duration_seconds"] == 900
    assert doc["production_effects"]["authority_receipt_issued"] == "NO"
    assert doc["production_effects"]["epoch_5_ledger_created"] == "NO"


def test_one_shot_epoch5_issuance_is_exact_and_idempotent(tmp_path: Path, monkeypatch) -> None:
    module = _module()
    private_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _production_root(tmp_path, public, trust_bytes)

    monkeypatch.setattr(module, "EXPECTED_PUBLIC_KEY_FINGERPRINT", fingerprint)
    monkeypatch.setattr(module, "EXPECTED_TRUST_CONFIG_DIGEST", trust_digest)
    calls = {"count": 0}

    def preflight(root, *, now_epoch_s, allow_active_request_id):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"active_ink_grants": []}
        return {
            "active_ink_grants": [
                {
                    "authority_epoch": 5,
                    "relative_path": "state/epoch-5/authority-root-issuance-v0-epoch-5.sqlite3",
                    "request_id": allow_active_request_id,
                }
            ]
        }

    monkeypatch.setattr(module, "_run_read_only_preflight", preflight)

    issued_at = 2_000_000_000
    first = module.issue_once(
        production_root=root,
        private_key_path=private_path,
        issued_at_epoch_s=issued_at,
    )
    second = module.issue_once(
        production_root=root,
        private_key_path=private_path,
        issued_at_epoch_s=issued_at,
    )

    assert first == second
    assert first["authority_epoch"] == 5
    assert first["request_id"] == f"ink-v0f-{issued_at}-900"
    assert first["not_after_epoch_s"] == issued_at + 900
    db = root / "state/epoch-5/authority-root-issuance-v0-epoch-5.sqlite3"
    assert db.is_file()
    receipt_path = root / "public/ink-v0f-level3-epoch5-receipt-v0.json"
    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_path.read_bytes())
    assert receipt.authority_epoch == 5
    assert receipt.serial == 1
    assert receipt.issued_at_epoch_s == issued_at
    assert int(receipt.authority_policy.granted_level) == 3
    assert receipt.authority_policy.permitted_repository_commit == (
        "af5edb2eaf9e6ab55a8295da4a9cb5f2e7d549b6"
    )
    assert receipt.authority_policy.permitted_implementation_digest == (
        "f0f3dfb14ddc5be1b2b500fdd4bf134f37dc63c56116e8be39a5496b95db707a"
    )
    assert receipt.authority_policy.permitted_network_id == "evm:57073"
    assert receipt.authority_policy.permitted_taker_address == (
        "0x3e604be3293d930069d0805e85379e0ca5fa01cb"
    )
    assert receipt.authority_policy.permitted_venue_id == "inkyswap-v2-ink-mainnet"
    assert receipt.authority_policy.max_reservation_atomic == 10**15
    assert receipt.authority_policy.max_cumulative_atomic == 10**15


def test_active_ink_preflight_refuses_before_key_access(tmp_path: Path, monkeypatch) -> None:
    module = _module()
    private_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _production_root(tmp_path, public, trust_bytes)
    monkeypatch.setattr(module, "EXPECTED_PUBLIC_KEY_FINGERPRINT", fingerprint)
    monkeypatch.setattr(module, "EXPECTED_TRUST_CONFIG_DIGEST", trust_digest)
    monkeypatch.setattr(
        module,
        "_run_read_only_preflight",
        lambda root, *, now_epoch_s, allow_active_request_id: {
            "active_ink_grants": [{"receipt_id": "existing"}]
        },
    )
    monkeypatch.setattr(
        module,
        "_load_private_key",
        lambda path: (_ for _ in ()).throw(AssertionError("key must not be read")),
    )

    with pytest.raises(RuntimeError, match="active Ink grant"):
        module.issue_once(
            production_root=root,
            private_key_path=private_path,
            issued_at_epoch_s=2_000_000_000,
        )
    assert not (root / "state/epoch-5").exists()


def test_wrong_private_key_fingerprint_creates_no_epoch5_ledger(tmp_path: Path, monkeypatch) -> None:
    module = _module()
    private_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _production_root(tmp_path, public, trust_bytes)
    monkeypatch.setattr(module, "EXPECTED_PUBLIC_KEY_FINGERPRINT", fingerprint)
    monkeypatch.setattr(module, "EXPECTED_TRUST_CONFIG_DIGEST", trust_digest)
    monkeypatch.setattr(
        module,
        "_run_read_only_preflight",
        lambda root, *, now_epoch_s, allow_active_request_id: {"active_ink_grants": []},
    )

    wrong = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"wrong-key").digest())
    private_path.write_bytes(
        wrong.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)

    with pytest.raises(RuntimeError, match="does not match provisioned AuthorityRoot fingerprint"):
        module.issue_once(
            production_root=root,
            private_key_path=private_path,
            issued_at_epoch_s=2_000_000_000,
        )
    assert not (root / "state/epoch-5").exists()



def test_different_issued_at_cannot_append_second_epoch5_grant(
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
        lambda root, *, now_epoch_s, allow_active_request_id: {"active_ink_grants": []},
    )

    first_issued_at = 2_000_000_000
    module.issue_once(
        production_root=root,
        private_key_path=private_path,
        issued_at_epoch_s=first_issued_at,
    )

    with pytest.raises(RuntimeError, match="different request"):
        module.issue_once(
            production_root=root,
            private_key_path=private_path,
            issued_at_epoch_s=first_issued_at + 1,
        )

    import sqlite3

    db = root / "state/epoch-5/authority-root-issuance-v0-epoch-5.sqlite3"
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM issuances").fetchone()[0] == 1
