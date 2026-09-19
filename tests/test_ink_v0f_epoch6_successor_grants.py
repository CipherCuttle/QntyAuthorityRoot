from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    AuthorityIssuanceRequestV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    canonical_json_bytes,
    sha256_hex,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "issue_ink_v0f_epoch6_successor_grant.py"
GOVERNANCE = ROOT / "artifacts" / "INK_V0F_LEVEL3_EPOCH6_SUCCESSOR_GOVERNANCE_V0.json"
NATIVE_REBIND = ROOT / "artifacts" / "INK_V0F_LEVEL3_EPOCH6_NATIVE_ETH_REBIND_V0.json"
RECONCILE_REBIND = (
    ROOT / "artifacts" / "INK_V0F_LEVEL3_EPOCH6_RECONCILE_RUNTIME_REBIND_V0.json"
)


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


def test_epoch6_native_eth_rebind_is_canonical_and_exact() -> None:
    raw = NATIVE_REBIND.read_bytes()
    doc = json.loads(raw)
    assert raw == canonical_json_bytes(doc)
    assert sha256_hex(raw) == "d2db45a9615c06babbf2b1a73564bc78f4060371d281f019c4a3d0987a96e039"
    assert doc["current_grant_preparation_digest"] == (
        "6da9c107fdb1e67e1f9284c2065c0254e86d55eaa61af574501dba7c063cb009"
    )
    assert doc["exact_grant_scope"]["permitted_repository_commit"] == (
        "95aaa869f490474968d16f51bfac5ad939a3a074"
    )
    assert doc["exact_grant_scope"]["permitted_implementation_digest"] == (
        "b841661bde3b438e15f8709d82feb39de72ba96802c921837eb55a521d80811f"
    )
    assert doc["execution_funding"] == {
        "buy_wallet_asset": "NATIVE_ETH",
        "pool_quote_leg": "WETH",
        "sell_wallet_settlement": "NATIVE_ETH",
    }
    assert doc["production_effects"]["authority_receipt_issued_now"] == "NO"


def test_epoch6_reconcile_runtime_rebind_is_canonical_and_exact() -> None:
    raw = RECONCILE_REBIND.read_bytes()
    doc = json.loads(raw)
    assert raw == canonical_json_bytes(doc)
    assert sha256_hex(raw) == "a8e860e99c37daf22afa8ec4ab36061957e593c827f61afa91eed2e0a33d850f"
    assert doc["current_grant_preparation_digest"] == (
        "45420e0863b97248c21420ba2df295be115955c9e9955f62ef0d36baf5dbb584"
    )
    assert doc["exact_grant_scope"]["permitted_repository_commit"] == (
        "deab9e91ee3986f223ec66e21f9438d0d62ff6df"
    )
    assert doc["exact_grant_scope"]["permitted_implementation_digest"] == (
        "8ebcc89564ebd554015b16c44f8ca964d069105c991a1455dd7f8d2c3a8455e6"
    )
    assert doc["historical_epoch6_serial_1"]["request_id"] == (
        "ink-v0f-1789848200-900"
    )
    assert doc["historical_epoch6_serial_1"]["status"] == (
        "EXPIRED_PREPARE_FAILED_NO_SIGNING_NO_BROADCAST"
    )
    assert doc["renewal_contract"]["historical_request_recovery_after_rebind"] == (
        "FORBIDDEN"
    )


def test_epoch6_scope_accepts_only_exact_historical_serial1_when_requested() -> None:
    module = _module()
    policy = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        permitted_repository_commit="95aaa869f490474968d16f51bfac5ad939a3a074",
        permitted_implementation_digest=(
            "b841661bde3b438e15f8709d82feb39de72ba96802c921837eb55a521d80811f"
        ),
        permitted_network_id="evm:57073",
        permitted_taker_address="0x3e604be3293d930069d0805e85379e0ca5fa01cb",
        permitted_venue_id="inkyswap-v2-ink-mainnet",
        max_reservation_atomic=10**15,
        max_cumulative_atomic=10**15,
        not_before_epoch_s=1789848200,
        not_after_epoch_s=1789849100,
    )
    receipt = AuthorityGrantReceiptV0(
        root_id="qnty-authority-root-v0",
        public_key_fingerprint="11" * 32,
        signature_algorithm="Ed25519",
        authority_epoch=6,
        serial=1,
        issued_at_epoch_s=1789848200,
        authority_policy=policy,
        signature=b"\x01" * 64,
    )
    assert module._assert_scope(
        receipt,
        allow_historical_serial1=True,
    ) == "HISTORICAL_SERIAL1"
    with pytest.raises(RuntimeError, match="QntySpot commit mismatch"):
        module._assert_scope(receipt)
    with pytest.raises(RuntimeError):
        module._assert_scope(
            AuthorityGrantReceiptV0(
                root_id=receipt.root_id,
                public_key_fingerprint=receipt.public_key_fingerprint,
                signature_algorithm=receipt.signature_algorithm,
                authority_epoch=6,
                serial=2,
                issued_at_epoch_s=receipt.issued_at_epoch_s,
                authority_policy=policy,
                signature=receipt.signature,
            ),
            allow_historical_serial1=True,
        )


def test_epoch6_historical_validator_allows_only_real_v2_request_tuple() -> None:
    module = _module()
    policy = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        permitted_repository_commit="95aaa869f490474968d16f51bfac5ad939a3a074",
        permitted_implementation_digest=(
            "b841661bde3b438e15f8709d82feb39de72ba96802c921837eb55a521d80811f"
        ),
        permitted_network_id="evm:57073",
        permitted_taker_address="0x3e604be3293d930069d0805e85379e0ca5fa01cb",
        permitted_venue_id="inkyswap-v2-ink-mainnet",
        max_reservation_atomic=10**15,
        max_cumulative_atomic=10**15,
        not_before_epoch_s=1789848200,
        not_after_epoch_s=1789849100,
    )
    request = AuthorityIssuanceRequestV0(
        repository_identity="CipherCuttle/QntySpot",
        authority_policy=policy,
        issued_at_epoch_s=1789848200,
    )
    receipt = AuthorityGrantReceiptV0(
        root_id="qnty-authority-root-v0",
        public_key_fingerprint="11" * 32,
        signature_algorithm="Ed25519",
        authority_epoch=6,
        serial=1,
        issued_at_epoch_s=1789848200,
        authority_policy=policy,
        signature=b"\x01" * 64,
    )
    assert module._allow_exact_historical_epoch6_request(
        "ink-v0f-1789848200-900",
        request,
        receipt,
    )
    assert not module._allow_exact_historical_epoch6_request(
        "ink-v0f-1789848201-900",
        request,
        receipt,
    )
    assert not module._allow_exact_historical_epoch6_request(
        "ink-v0f-1789848200-900",
        request,
        AuthorityGrantReceiptV0(
            root_id=receipt.root_id,
            public_key_fingerprint=receipt.public_key_fingerprint,
            signature_algorithm=receipt.signature_algorithm,
            authority_epoch=6,
            serial=2,
            issued_at_epoch_s=receipt.issued_at_epoch_s,
            authority_policy=policy,
            signature=receipt.signature,
        ),
    )


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
    assert receipt.authority_policy.permitted_repository_commit == (
        "deab9e91ee3986f223ec66e21f9438d0d62ff6df"
    )
    assert receipt.authority_policy.permitted_implementation_digest == (
        "8ebcc89564ebd554015b16c44f8ca964d069105c991a1455dd7f8d2c3a8455e6"
    )


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
