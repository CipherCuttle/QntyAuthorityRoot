from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    canonical_json_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "inspect_ink_v0f_production_state.py"
ANCHOR = bytes.fromhex(
    "b8254f9dc8aec38671a5c6b851e461a0d676a31e48805f6c4bd01ca035756cde"
)
TRUST = {
    "minimum_authority_epoch": 1,
    "public_key_fingerprint": "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe",
    "root_id": "qnty-authority-root-v0",
    "schema": "qntyspot.authority_root.v0.trust_config",
    "signature_algorithm": "Ed25519",
    "trust_config_version": 1,
}


def _module():
    spec = importlib.util.spec_from_file_location("ink_prod_inspector", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "production"
    (root / "public").mkdir(parents=True)
    (root / "state").mkdir()
    (root / "public" / "authority-root-ed25519-v0.pub").write_bytes(ANCHOR)
    (root / "public" / "trusted-authority-root-v0.json").write_bytes(
        canonical_json_bytes(TRUST)
    )
    return root


def _ledger(root: Path, *, authority_epoch: int = 1) -> Path:
    path = root / "state" / "authority-root-issuance-v0.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE issuer_metadata ("
            "singleton INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, "
            "root_id TEXT NOT NULL, public_key_fingerprint TEXT NOT NULL, "
            "authority_epoch INTEGER NOT NULL, minimum_authority_epoch INTEGER NOT NULL, "
            "trust_config_version INTEGER NOT NULL, trust_config_digest TEXT NOT NULL, "
            "repository_identity TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE issuances ("
            "request_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, "
            "request_bytes BLOB NOT NULL, authority_epoch INTEGER NOT NULL, "
            "serial INTEGER NOT NULL UNIQUE, receipt_id TEXT NOT NULL UNIQUE, "
            "receipt_bytes BLOB NOT NULL)"
        )
        connection.execute(
            "INSERT INTO issuer_metadata VALUES (1, 2, ?, ?, ?, 1, 1, ?, ?)",
            (
                "qnty-authority-root-v0",
                "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe",
                authority_epoch,
                "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6",
                "CipherCuttle/QntySpot",
            ),
        )
    return path


def test_inspector_reports_compatible_empty_production_ledger(tmp_path: Path) -> None:
    module = _module()
    root = _root(tmp_path)
    _ledger(root)

    result = module.inspect_production_root(root, now_epoch_s=2_000_000_000)

    assert result["active_ink_grants"] == []
    assert len(result["compatible_ledgers"]) == 1
    assert result["compatible_ledgers"][0]["authority_epoch"] == 1
    assert result["compatible_ledgers"][0]["issuance_count"] == 0
    assert result["trust_config_version"] == 1


def test_inspector_refuses_active_ink_grant(tmp_path: Path) -> None:
    module = _module()
    root = _root(tmp_path)
    path = _ledger(root)
    policy = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        permitted_repository_commit="a" * 40,
        permitted_implementation_digest="b" * 64,
        permitted_network_id="evm:57073",
        permitted_taker_address="0x3e604be3293d930069d0805e85379e0ca5fa01cb",
        permitted_venue_id="inkyswap-v2-ink-mainnet",
        max_reservation_atomic=10**15,
        max_cumulative_atomic=10**15,
        not_before_epoch_s=2_000_000_000,
        not_after_epoch_s=2_000_000_900,
    )
    receipt = AuthorityGrantReceiptV0(
        root_id="qnty-authority-root-v0",
        public_key_fingerprint=TRUST["public_key_fingerprint"],
        signature_algorithm="Ed25519",
        authority_epoch=1,
        serial=1,
        issued_at_epoch_s=2_000_000_000,
        authority_policy=policy,
        signature=b"\x00" * 64,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO issuances VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "active-ink",
                "0" * 64,
                b"{}",
                1,
                1,
                receipt.receipt_id,
                receipt.serialized,
            ),
        )

    with pytest.raises(RuntimeError, match="active Ink V0F"):
        module.inspect_production_root(root, now_epoch_s=2_000_000_001)
