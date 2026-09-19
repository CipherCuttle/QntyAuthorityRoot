from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qnty_authority_root import (
    AuthorityGrantReceiptV0,
    canonical_json_bytes,
    sha256_hex,
)
from qnty_authority_root.ink_v0f_grant import issue_ink_v0f_grant

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


def _run_read_only_preflight(root: Path, *, now_epoch_s: int) -> dict[str, object]:
    inspector_path = Path(__file__).with_name("inspect_ink_v0f_production_state.py")
    spec = importlib.util.spec_from_file_location("ink_v0f_production_state_inspector", inspector_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load production-state inspector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_production_root(root, now_epoch_s=now_epoch_s)


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

    preflight = _run_read_only_preflight(root, now_epoch_s=issued_at_epoch_s)
    if preflight["active_ink_grants"]:
        raise RuntimeError("active Ink grant detected during production preflight")

    signer = _load_private_key(private_key_path)
    if signer.public_key_bytes != anchor:
        raise RuntimeError("private key public bytes do not equal provisioned public anchor")

    epoch_dir = root / "state" / "epoch-5"
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

    public_dir = root / "public"
    receipt_path = public_dir / RECEIPT_NAME
    receipt_sidecar = public_dir / RECEIPT_SIDECAR_NAME
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
    _atomic_write_new(epoch_dir / ISSUANCE_RECORD_NAME, record_bytes, mode=0o600)
    _atomic_write_new(
        epoch_dir / ISSUANCE_RECORD_SIDECAR_NAME,
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
