from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    sha256_hex,
    strict_json_loads,
)

EXPECTED_PUBLIC_KEY_FINGERPRINT = (
    "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe"
)
EXPECTED_TRUST_CONFIG_DIGEST = (
    "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
)
INK_NETWORK_ID = "evm:57073"


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def inspect_production_root(production_root: Path, *, now_epoch_s: int) -> dict[str, Any]:
    root = production_root.resolve()
    if not root.is_dir():
        raise RuntimeError("production root is not an existing directory")

    anchor_path = root / "public" / "authority-root-ed25519-v0.pub"
    trust_path = root / "public" / "trusted-authority-root-v0.json"
    if not anchor_path.is_file() or not trust_path.is_file():
        raise RuntimeError("production root is missing required public trust files")

    anchor = anchor_path.read_bytes()
    anchor_digest = sha256_hex(anchor)
    if anchor_digest != EXPECTED_PUBLIC_KEY_FINGERPRINT:
        raise RuntimeError("production authority public-key fingerprint mismatch")

    trust_bytes = trust_path.read_bytes()
    trust_digest = sha256_hex(trust_bytes)
    if trust_digest != EXPECTED_TRUST_CONFIG_DIGEST:
        raise RuntimeError("production authority trust-config digest mismatch")
    trust = strict_json_loads(trust_bytes)
    if not isinstance(trust, dict):
        raise RuntimeError("production authority trust config is not a JSON object")

    state_dir = root / "state"
    ledger_paths = sorted(state_dir.rglob("*.sqlite3")) if state_dir.is_dir() else []
    ledgers: list[dict[str, Any]] = []
    active_ink: list[dict[str, Any]] = []

    for ledger_path in ledger_paths:
        relative = ledger_path.relative_to(root).as_posix()
        with _read_only_connection(ledger_path) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise RuntimeError(f"ledger integrity failure: {relative}")

            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "issuer_metadata" not in tables or "issuances" not in tables:
                continue

            metadata = connection.execute(
                "SELECT * FROM issuer_metadata WHERE singleton = 1"
            ).fetchone()
            if metadata is None:
                continue

            rows = connection.execute(
                "SELECT request_id, authority_epoch, serial, receipt_id, receipt_bytes "
                "FROM issuances ORDER BY serial"
            ).fetchall()

            ledger_info = {
                "authority_epoch": int(metadata["authority_epoch"]),
                "issuance_count": len(rows),
                "minimum_authority_epoch": int(metadata["minimum_authority_epoch"]),
                "public_key_fingerprint": str(metadata["public_key_fingerprint"]),
                "relative_path": relative,
                "repository_identity": str(metadata["repository_identity"]),
                "trust_config_digest": str(metadata["trust_config_digest"]),
                "trust_config_version": int(metadata["trust_config_version"]),
            }
            ledgers.append(ledger_info)

            for row in rows:
                receipt = AuthorityGrantReceiptV0.from_bytes(bytes(row["receipt_bytes"]))
                policy = receipt.authority_policy
                if (
                    policy.permitted_network_id == INK_NETWORK_ID
                    and policy.not_before_epoch_s <= now_epoch_s < policy.not_after_epoch_s
                ):
                    active_ink.append(
                        {
                            "authority_epoch": receipt.authority_epoch,
                            "not_after_epoch_s": policy.not_after_epoch_s,
                            "not_before_epoch_s": policy.not_before_epoch_s,
                            "receipt_id": receipt.receipt_id,
                            "relative_path": relative,
                            "request_id": str(row["request_id"]),
                            "serial": receipt.serial,
                        }
                    )

    compatible = [
        row
        for row in ledgers
        if row["public_key_fingerprint"] == EXPECTED_PUBLIC_KEY_FINGERPRINT
        and row["trust_config_digest"] == EXPECTED_TRUST_CONFIG_DIGEST
        and row["repository_identity"] == "CipherCuttle/QntySpot"
    ]

    result = {
        "active_ink_grants": active_ink,
        "compatible_ledgers": compatible,
        "ledger_count": len(ledgers),
        "ledgers": ledgers,
        "now_epoch_s": now_epoch_s,
        "public_key_fingerprint": anchor_digest,
        "schema": "qnty.authority_root.ink_v0f.production_state_preflight.v0",
        "trust_config_digest": trust_digest,
        "trust_config_version": trust.get("trust_config_version"),
    }
    if active_ink:
        raise RuntimeError(
            "an active Ink V0F authority grant already exists; refusing grant preparation"
        )
    if not compatible:
        raise RuntimeError("no compatible production authority ledger was found")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-root", required=True)
    parser.add_argument("--now-epoch-s", type=int)
    args = parser.parse_args()
    now_epoch_s = int(time.time()) if args.now_epoch_s is None else args.now_epoch_s
    try:
        result = inspect_production_root(
            Path(args.production_root),
            now_epoch_s=now_epoch_s,
        )
    except Exception as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
