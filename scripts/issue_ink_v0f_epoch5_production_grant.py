from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sqlite3
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    canonical_json_bytes,
    sha256_hex,
    verify_receipt_signature,
)
from qnty_authority_root.ink_v0f_grant import (
    ink_v0f_request_id,
    issue_ink_v0f_grant,
)

EXPECTED_PUBLIC_KEY_FINGERPRINT = (
    "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe"
)
EXPECTED_TRUST_CONFIG_DIGEST = (
    "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
)
AUTHORITY_EPOCH = 5
MINIMUM_AUTHORITY_EPOCH = 1
TRUST_CONFIG_VERSION = 1
DURATION_S = 900

EXPECTED_QNTYSPOT_COMMIT = "af5edb2eaf9e6ab55a8295da4a9cb5f2e7d549b6"
EXPECTED_IMPLEMENTATION_DIGEST = (
    "f0f3dfb14ddc5be1b2b500fdd4bf134f37dc63c56116e8be39a5496b95db707a"
)
EXPECTED_TAKER = "0x3e604be3293d930069d0805e85379e0ca5fa01cb"
EXPECTED_NETWORK = "evm:57073"
EXPECTED_VENUE = "inkyswap-v2-ink-mainnet"
EXPECTED_ATOMIC = 10**15

RECEIPT_NAME = "ink-v0f-level3-epoch5-receipt-v0.json"
RECEIPT_SIDECAR_NAME = "ink-v0f-level3-epoch5-receipt-v0.sha256"
ISSUANCE_RECORD_NAME = "ink-v0f-level3-epoch5-issuance-v0.json"
ISSUANCE_RECORD_SIDECAR_NAME = "ink-v0f-level3-epoch5-issuance-v0.sha256"


class FileEd25519Signer:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def _run_read_only_preflight(
    root: Path,
    *,
    now_epoch_s: int,
    allow_active_request_id: str | None,
) -> dict[str, object]:
    inspector_path = Path(__file__).with_name("inspect_ink_v0f_production_state.py")
    spec = importlib.util.spec_from_file_location("ink_v0f_production_state_inspector", inspector_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load production-state inspector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_production_root(
        root,
        now_epoch_s=now_epoch_s,
        allow_active_request_id=allow_active_request_id,
    )


def _load_private_key(path: Path) -> FileEd25519Signer:
    if not path.is_file():
        raise RuntimeError("explicit private-key path is not a file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError("private-key file permissions must not allow group/other access")
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except Exception as exc:
        raise RuntimeError("could not load unencrypted PKCS#8 PEM Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("private key is not Ed25519")
    signer = FileEd25519Signer(key)
    fingerprint = sha256_hex(signer.public_key_bytes)
    if fingerprint != EXPECTED_PUBLIC_KEY_FINGERPRINT:
        raise RuntimeError("private key does not match provisioned AuthorityRoot fingerprint")
    return signer


def _assert_exact_receipt(receipt: AuthorityGrantReceiptV0, *, issued_at_epoch_s: int) -> None:
    policy = receipt.authority_policy
    if receipt.authority_epoch != AUTHORITY_EPOCH:
        raise RuntimeError("receipt authority epoch mismatch")
    if receipt.issued_at_epoch_s != issued_at_epoch_s:
        raise RuntimeError("receipt issued-at mismatch")
    if policy.not_before_epoch_s != issued_at_epoch_s:
        raise RuntimeError("receipt not-before mismatch")
    if policy.not_after_epoch_s != issued_at_epoch_s + DURATION_S:
        raise RuntimeError("receipt duration mismatch")
    if policy.permitted_repository_commit != EXPECTED_QNTYSPOT_COMMIT:
        raise RuntimeError("receipt QntySpot commit mismatch")
    if policy.permitted_implementation_digest != EXPECTED_IMPLEMENTATION_DIGEST:
        raise RuntimeError("receipt implementation digest mismatch")
    if policy.permitted_taker_address != EXPECTED_TAKER:
        raise RuntimeError("receipt taker mismatch")
    if policy.permitted_network_id != EXPECTED_NETWORK:
        raise RuntimeError("receipt network mismatch")
    if policy.permitted_venue_id != EXPECTED_VENUE:
        raise RuntimeError("receipt venue mismatch")
    if policy.max_reservation_atomic != EXPECTED_ATOMIC:
        raise RuntimeError("receipt reservation cap mismatch")
    if policy.max_cumulative_atomic != EXPECTED_ATOMIC:
        raise RuntimeError("receipt cumulative cap mismatch")
    if int(policy.granted_level) != 3:
        raise RuntimeError("receipt authority level mismatch")


def _inspect_epoch5_history(
    root: Path,
    *,
    anchor: bytes,
    issued_at_epoch_s: int,
) -> bytes | None:
    db_path = root / "state" / "epoch-5" / "authority-root-issuance-v0-epoch-5.sqlite3"
    if not db_path.exists():
        return None
    if not db_path.is_file():
        raise RuntimeError("epoch-5 issuance database path is not a file")

    expected_request_id = ink_v0f_request_id(
        issued_at_epoch_s=issued_at_epoch_s,
        duration_s=DURATION_S,
    )
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("epoch-5 issuance database failed integrity_check")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "issuer_metadata" not in tables or "issuances" not in tables:
            raise RuntimeError("epoch-5 issuance database has unsupported schema")
        metadata = connection.execute(
            "SELECT * FROM issuer_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None:
            raise RuntimeError("epoch-5 issuance database is missing issuer metadata")
        if (
            int(metadata["authority_epoch"]) != AUTHORITY_EPOCH
            or int(metadata["minimum_authority_epoch"]) != MINIMUM_AUTHORITY_EPOCH
            or int(metadata["trust_config_version"]) != TRUST_CONFIG_VERSION
            or str(metadata["root_id"]) != "qnty-authority-root-v0"
            or str(metadata["public_key_fingerprint"]) != EXPECTED_PUBLIC_KEY_FINGERPRINT
            or str(metadata["trust_config_digest"]) != EXPECTED_TRUST_CONFIG_DIGEST
            or str(metadata["repository_identity"]) != "CipherCuttle/QntySpot"
        ):
            raise RuntimeError("epoch-5 issuance database metadata mismatch")

        rows = connection.execute(
            "SELECT request_id, authority_epoch, serial, receipt_id, receipt_bytes "
            "FROM issuances ORDER BY serial"
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RuntimeError("epoch-5 lane already contains foreign or multiple issuance history")
        row = rows[0]
        if str(row["request_id"]) != expected_request_id:
            raise RuntimeError("epoch-5 lane is already committed to a different request")
        receipt_bytes = bytes(row["receipt_bytes"])
        receipt = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
        verify_receipt_signature(receipt, anchor)
        if (
            receipt.authority_epoch != int(row["authority_epoch"])
            or receipt.serial != int(row["serial"])
            or receipt.receipt_id != str(row["receipt_id"])
        ):
            raise RuntimeError("epoch-5 receipt does not match immutable ledger row")
        _assert_exact_receipt(receipt, issued_at_epoch_s=issued_at_epoch_s)
        return receipt_bytes


def _atomic_write_new(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError(f"existing export conflicts: {path}")
        return
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        raise RuntimeError(f"temporary export already exists: {tmp}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def issue_once(
    *,
    production_root: Path,
    private_key_path: Path,
    issued_at_epoch_s: int,
) -> dict[str, object]:
    if type(issued_at_epoch_s) is not int or issued_at_epoch_s <= 0:
        raise RuntimeError("issued_at_epoch_s must be a positive explicit integer")

    root = production_root.resolve()
    if not root.is_dir():
        raise RuntimeError("production root is not an existing directory")

    anchor_path = root / "public" / "authority-root-ed25519-v0.pub"
    trust_path = root / "public" / "trusted-authority-root-v0.json"
    if not anchor_path.is_file() or not trust_path.is_file():
        raise RuntimeError("production root is missing public AuthorityRoot continuity files")
    anchor = anchor_path.read_bytes()
    if sha256_hex(anchor) != EXPECTED_PUBLIC_KEY_FINGERPRINT:
        raise RuntimeError("public AuthorityRoot fingerprint mismatch")
    if sha256_hex(trust_path.read_bytes()) != EXPECTED_TRUST_CONFIG_DIGEST:
        raise RuntimeError("public AuthorityRoot trust-config digest mismatch")

    expected_request_id = ink_v0f_request_id(
        issued_at_epoch_s=issued_at_epoch_s,
        duration_s=DURATION_S,
    )
    committed_before = _inspect_epoch5_history(
        root,
        anchor=anchor,
        issued_at_epoch_s=issued_at_epoch_s,
    )
    preflight = _run_read_only_preflight(
        root,
        now_epoch_s=issued_at_epoch_s,
        allow_active_request_id=expected_request_id,
    )
    active = preflight["active_ink_grants"]
    if active and committed_before is None:
        raise RuntimeError("active Ink grant detected without exact epoch-5 recovery state")

    public_dir = root / "public"
    epoch_dir = root / "state" / "epoch-5"
    receipt_path = public_dir / RECEIPT_NAME
    receipt_sidecar = public_dir / RECEIPT_SIDECAR_NAME
    record_path = epoch_dir / ISSUANCE_RECORD_NAME
    record_sidecar = epoch_dir / ISSUANCE_RECORD_SIDECAR_NAME
    if committed_before is None and any(
        path.exists() for path in (receipt_path, receipt_sidecar, record_path, record_sidecar)
    ):
        raise RuntimeError("orphan epoch-5 export exists before issuance")

    signer = _load_private_key(private_key_path)
    if signer.public_key_bytes != anchor:
        raise RuntimeError("private key public bytes do not equal provisioned public anchor")

    epoch_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(epoch_dir, 0o700)
    db_path = epoch_dir / "authority-root-issuance-v0-epoch-5.sqlite3"

    bundle = issue_ink_v0f_grant(
        db_path=db_path,
        signer=signer,
        authority_epoch=AUTHORITY_EPOCH,
        minimum_authority_epoch=MINIMUM_AUTHORITY_EPOCH,
        trust_config_version=TRUST_CONFIG_VERSION,
        issued_at_epoch_s=issued_at_epoch_s,
        duration_s=DURATION_S,
    )

    if bundle.trust_config_digest != EXPECTED_TRUST_CONFIG_DIGEST:
        raise RuntimeError("issued bundle trust-config digest mismatch")
    if bundle.public_anchor_bytes != anchor:
        raise RuntimeError("issued bundle public anchor mismatch")

    receipt = AuthorityGrantReceiptV0.from_bytes(bundle.receipt_bytes)
    _assert_exact_receipt(receipt, issued_at_epoch_s=issued_at_epoch_s)
    policy = receipt.authority_policy
    if committed_before is not None and bundle.receipt_bytes != committed_before:
        raise RuntimeError("exact epoch-5 recovery returned different committed bytes")
    receipt_digest = sha256_hex(bundle.receipt_bytes)

    record = {
        "authority_epoch": AUTHORITY_EPOCH,
        "authority_policy_digest": receipt.authority_policy_digest,
        "issued_at_epoch_s": issued_at_epoch_s,
        "not_after_epoch_s": policy.not_after_epoch_s,
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": receipt_digest,
        "request_id": bundle.request_id,
        "schema": "qnty.authority_root.ink_v0f_level3_epoch5_issuance.v0",
        "serial": receipt.serial,
        "trust_config_digest": bundle.trust_config_digest,
    }
    record_bytes = canonical_json_bytes(record)
    record_digest = sha256_hex(record_bytes)

    _atomic_write_new(receipt_path, bundle.receipt_bytes, mode=0o644)
    _atomic_write_new(
        receipt_sidecar,
        f"{receipt_digest}  {RECEIPT_NAME}\n".encode("ascii"),
        mode=0o644,
    )
    _atomic_write_new(record_path, record_bytes, mode=0o600)
    _atomic_write_new(
        record_sidecar,
        f"{record_digest}  {ISSUANCE_RECORD_NAME}\n".encode("ascii"),
        mode=0o600,
    )

    return {
        **record,
        "db_path": db_path.relative_to(root).as_posix(),
        "receipt_path": receipt_path.relative_to(root).as_posix(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-root", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--issued-at-epoch-s", required=True, type=int)
    args = parser.parse_args()
    try:
        result = issue_once(
            production_root=Path(args.production_root),
            private_key_path=Path(args.private_key),
            issued_at_epoch_s=args.issued_at_epoch_s,
        )
    except Exception as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
