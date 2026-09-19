from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qnty_authority_root import AuthorityGrantReceiptV0, canonical_json_bytes, sha256_hex

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "issue_ink_v0f_epoch6_successor_grant.py"
GOVERNANCE = ROOT / "artifacts" / "INK_V0F_LEVEL3_EPOCH6_SUCCESSOR_GOVERNANCE_V0.json"


def _module():
    spec = importlib.util.spec_from_file_location("ink_epoch6_issuer", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _key_material(tmp_path: Path):
    key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"ink-v0f-epoch6-successor-test").digest()
    )
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
    key_path = tmp_path / "root.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return key_path, public, fingerprint, trust_bytes, sha256_hex(trust_bytes)


def _root(tmp_path: Path, public: bytes, trust_bytes: bytes) -> Path:
    root = tmp_path / "production"
    (root / "public").mkdir(parents=True)
    (root / "state").mkdir()
    (root / "public/authority-root-ed25519-v0.pub").write_bytes(public)
    (root / "public/trusted-authority-root-v0.json").write_bytes(trust_bytes)
    return root


def _configure(module, monkeypatch, fingerprint: str, trust_digest: str) -> None:
    monkeypatch.setattr(module, "EXPECTED_PUBLIC_KEY_FINGERPRINT", fingerprint)
    monkeypatch.setattr(module, "EXPECTED_TRUST_CONFIG_DIGEST", trust_digest)


def test_epoch6_governance_is_canonical_and_exact() -> None:
    raw = GOVERNANCE.read_bytes()
    doc = json.loads(raw)
    assert raw == canonical_json_bytes(doc)
    assert sha256_hex(raw) == "0142595a4dcb4a046ac30d520266d0434b1557ae7a227867a362d0e57f942070"
    assert doc["epoch_6"]["authority_epoch"] == 6
    assert doc["epoch_6"]["successor_policy"] == "REUSABLE_SHORT_LIVED_NON_OVERLAPPING"
    assert doc["exact_grant_scope"]["grant_duration_seconds"] == 900
    assert doc["exact_grant_scope"]["max_reservation_atomic"] == "1000000000000000"
    assert doc["renewal_contract"]["new_request_before_prior_expiry"] == "FORBIDDEN"
    assert doc["renewal_contract"]["new_request_after_prior_expiry"] == "ALLOWED"


def test_epoch6_exact_retry_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    module = _module()
    key_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _root(tmp_path, public, trust_bytes)
    _configure(module, monkeypatch, fingerprint, trust_digest)
    calls = {"n": 0}

    def preflight(root, *, now_epoch_s, allow_active_request_id):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"active_ink_grants": []}
        return {"active_ink_grants": [{
            "authority_epoch": 6,
            "relative_path": module.EPOCH6_RELATIVE_DB,
            "request_id": allow_active_request_id,
        }]}

    monkeypatch.setattr(module, "_run_read_only_preflight", preflight)
    t = 2_000_000_000
    first = module.issue_once(
        production_root=root, private_key_path=key_path, issued_at_epoch_s=t
    )
    second = module.issue_once(
        production_root=root, private_key_path=key_path, issued_at_epoch_s=t
    )
    assert first == second
    assert first["authority_epoch"] == 6
    assert first["serial"] == 1
    receipt = AuthorityGrantReceiptV0.from_bytes(
        (root / first["receipt_path"]).read_bytes()
    )
    assert receipt.issued_at_epoch_s == t
    assert receipt.authority_policy.not_after_epoch_s == t + 900


def test_epoch6_allows_new_exact_grant_after_expiry(tmp_path: Path, monkeypatch) -> None:
    module = _module()
    key_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _root(tmp_path, public, trust_bytes)
    _configure(module, monkeypatch, fingerprint, trust_digest)
    monkeypatch.setattr(
        module,
        "_run_read_only_preflight",
        lambda root, *, now_epoch_s, allow_active_request_id: {"active_ink_grants": []},
    )

    first_t = 2_000_000_000
    second_t = first_t + 901
    first = module.issue_once(
        production_root=root, private_key_path=key_path, issued_at_epoch_s=first_t
    )
    second = module.issue_once(
        production_root=root, private_key_path=key_path, issued_at_epoch_s=second_t
    )
    assert first["serial"] == 1
    assert second["serial"] == 2
    db = root / module.EPOCH6_RELATIVE_DB
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM issuances").fetchone()[0] == 2


def test_epoch6_refuses_overlapping_new_request_before_key_access(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _module()
    key_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _root(tmp_path, public, trust_bytes)
    _configure(module, monkeypatch, fingerprint, trust_digest)

    first_t = 2_000_000_000
    monkeypatch.setattr(
        module,
        "_run_read_only_preflight",
        lambda root, *, now_epoch_s, allow_active_request_id: {"active_ink_grants": []},
    )
    module.issue_once(
        production_root=root, private_key_path=key_path, issued_at_epoch_s=first_t
    )

    monkeypatch.setattr(
        module,
        "_run_read_only_preflight",
        lambda root, *, now_epoch_s, allow_active_request_id: {
            "active_ink_grants": [{"request_id": "different"}]
        },
    )
    monkeypatch.setattr(
        module,
        "_load_private_key",
        lambda path: (_ for _ in ()).throw(AssertionError("key must not be read")),
    )
    with pytest.raises(
        RuntimeError,
        match="start at or after latest receipt expiry",
    ):
        module.issue_once(
            production_root=root,
            private_key_path=key_path,
            issued_at_epoch_s=first_t + 1,
        )

    db = root / module.EPOCH6_RELATIVE_DB
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM issuances").fetchone()[0] == 1



def test_epoch6_refuses_backdated_new_request_even_when_not_active_at_backdate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _module()
    key_path, public, fingerprint, trust_bytes, trust_digest = _key_material(tmp_path)
    root = _root(tmp_path, public, trust_bytes)
    _configure(module, monkeypatch, fingerprint, trust_digest)
    monkeypatch.setattr(
        module,
        "_run_read_only_preflight",
        lambda root, *, now_epoch_s, allow_active_request_id: {"active_ink_grants": []},
    )

    first_t = 2_000_001_000
    module.issue_once(
        production_root=root,
        private_key_path=key_path,
        issued_at_epoch_s=first_t,
    )

    with pytest.raises(RuntimeError, match="start at or after latest receipt expiry"):
        module.issue_once(
            production_root=root,
            private_key_path=key_path,
            issued_at_epoch_s=first_t - 100,
        )

    db = root / module.EPOCH6_RELATIVE_DB
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM issuances").fetchone()[0] == 1
