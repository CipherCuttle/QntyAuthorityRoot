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
from qnty_authority_root.ink_v0f_binding import (
    INK_V0F_QNTYSPOT_COMMIT,
    INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
)
from qnty_authority_root.ink_v0f_grant import (
    ink_v0f_request_id,
    issue_ink_v0f_grant,
)

EXPECTED_PUBLIC_KEY_FINGERPRINT = "baf4f9034a0ae76066a245138ce7c6891102755e3262e34a9a1140d12b45adbe"
EXPECTED_TRUST_CONFIG_DIGEST = "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
AUTHORITY_EPOCH = 6
MINIMUM_AUTHORITY_EPOCH = 1
TRUST_CONFIG_VERSION = 1
DURATION_S = 900
EXPECTED_QNTYSPOT_COMMIT = INK_V0F_QNTYSPOT_COMMIT
EXPECTED_IMPLEMENTATION_DIGEST = INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST
EXPECTED_TAKER = "0x3e604be3293d930069d0805e85379e0ca5fa01cb"
EXPECTED_NETWORK = "evm:57073"
EXPECTED_VENUE = "inkyswap-v2-ink-mainnet"
EXPECTED_ATOMIC = 10**15
EPOCH6_RELATIVE_DB = "state/epoch-6/authority-root-issuance-v0-epoch-6.sqlite3"
HISTORICAL_EPOCH6_SERIAL1 = {
    "serial": 1,
    "issued_at_epoch_s": 1789848200,
    "not_after_epoch_s": 1789849100,
    "receipt_id": "ead512e27a4f49b09f26de3ef42419941e35b1a171d082096ab53a5521c2fcc7",
    "repository_commit": "95aaa869f490474968d16f51bfac5ad939a3a074",
    "implementation_digest": "b841661bde3b438e15f8709d82feb39de72ba96802c921837eb55a521d80811f",
}


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
    path = Path(__file__).with_name("inspect_ink_v0f_production_state.py")
    spec = importlib.util.spec_from_file_location("ink_v0f_production_state_inspector", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load production-state inspector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_production_root(
        root,
        now_epoch_s=now_epoch_s,
        allow_active_request_id=allow_active_request_id,
        allow_active_authority_epoch=AUTHORITY_EPOCH,
        allow_active_relative_path=EPOCH6_RELATIVE_DB,
    )


def _load_private_key(path: Path) -> FileEd25519Signer:
    if not path.is_file():
        raise RuntimeError("explicit private-key path is not a file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("private-key file permissions must not allow group/other access")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise RuntimeError("could not load unencrypted PKCS#8 PEM Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("private key is not Ed25519")
    signer = FileEd25519Signer(key)
    if sha256_hex(signer.public_key_bytes) != EXPECTED_PUBLIC_KEY_FINGERPRINT:
        raise RuntimeError("private key does not match provisioned AuthorityRoot fingerprint")
    return signer


def _assert_scope(
    receipt: AuthorityGrantReceiptV0,
    *,
    allow_historical_serial1: bool = False,
    allow_expired_historical_before_epoch_s: int | None = None,
) -> str:
    p = receipt.authority_policy
    if receipt.authority_epoch != AUTHORITY_EPOCH:
        raise RuntimeError("receipt authority epoch mismatch")
    if p.not_before_epoch_s != receipt.issued_at_epoch_s:
        raise RuntimeError("receipt not-before mismatch")
    if p.not_after_epoch_s != receipt.issued_at_epoch_s + DURATION_S:
        raise RuntimeError("receipt duration mismatch")
    if p.permitted_taker_address != EXPECTED_TAKER:
        raise RuntimeError("receipt taker mismatch")
    if p.permitted_network_id != EXPECTED_NETWORK:
        raise RuntimeError("receipt network mismatch")
    if p.permitted_venue_id != EXPECTED_VENUE:
        raise RuntimeError("receipt venue mismatch")
    if p.max_reservation_atomic != EXPECTED_ATOMIC or p.max_cumulative_atomic != EXPECTED_ATOMIC:
        raise RuntimeError("receipt capital ceiling mismatch")
    if int(p.granted_level) != 3:
        raise RuntimeError("receipt authority level mismatch")

    current = (
        p.permitted_repository_commit == EXPECTED_QNTYSPOT_COMMIT
        and p.permitted_implementation_digest == EXPECTED_IMPLEMENTATION_DIGEST
    )
    if current:
        return "CURRENT"

    historical = (
        allow_historical_serial1
        and receipt.serial == HISTORICAL_EPOCH6_SERIAL1["serial"]
        and receipt.issued_at_epoch_s
        == HISTORICAL_EPOCH6_SERIAL1["issued_at_epoch_s"]
        and p.not_after_epoch_s
        == HISTORICAL_EPOCH6_SERIAL1["not_after_epoch_s"]
        and p.permitted_repository_commit
        == HISTORICAL_EPOCH6_SERIAL1["repository_commit"]
        and p.permitted_implementation_digest
        == HISTORICAL_EPOCH6_SERIAL1["implementation_digest"]
    )
    if historical:
        return "HISTORICAL_SERIAL1"

    if (
        allow_expired_historical_before_epoch_s is not None
        and p.not_after_epoch_s <= allow_expired_historical_before_epoch_s
    ):
        return "HISTORICAL_EXPIRED"

    if p.permitted_repository_commit != EXPECTED_QNTYSPOT_COMMIT:
        raise RuntimeError("receipt QntySpot commit mismatch")
    raise RuntimeError("receipt implementation digest mismatch")


def _allow_exact_historical_epoch6_request(
    request_id: str,
    request: object,
    receipt: AuthorityGrantReceiptV0,
) -> bool:
    if request_id != "ink-v0f-1789848200-900":
        return False
    if not hasattr(request, "authority_policy") or not hasattr(request, "issued_at_epoch_s"):
        return False
    policy = request.authority_policy
    return bool(
        receipt.serial == HISTORICAL_EPOCH6_SERIAL1["serial"]
        and receipt.issued_at_epoch_s == HISTORICAL_EPOCH6_SERIAL1["issued_at_epoch_s"]
        and request.issued_at_epoch_s == HISTORICAL_EPOCH6_SERIAL1["issued_at_epoch_s"]
        and policy.not_before_epoch_s == HISTORICAL_EPOCH6_SERIAL1["issued_at_epoch_s"]
        and policy.not_after_epoch_s == HISTORICAL_EPOCH6_SERIAL1["not_after_epoch_s"]
        and policy.permitted_repository_commit
        == HISTORICAL_EPOCH6_SERIAL1["repository_commit"]
        and policy.permitted_implementation_digest
        == HISTORICAL_EPOCH6_SERIAL1["implementation_digest"]
        and policy.permitted_taker_address == EXPECTED_TAKER
        and policy.permitted_network_id == EXPECTED_NETWORK
        and policy.permitted_venue_id == EXPECTED_VENUE
        and policy.max_reservation_atomic == EXPECTED_ATOMIC
        and policy.max_cumulative_atomic == EXPECTED_ATOMIC
        and int(policy.granted_level) == 3
    )


def _inspect_epoch6_history(
    root: Path,
    *,
    anchor: bytes,
    issued_at_epoch_s: int,
) -> bytes | None:
    db_path = root / EPOCH6_RELATIVE_DB
    if not db_path.exists():
        return None
    if not db_path.is_file():
        raise RuntimeError("epoch-6 issuance database path is not a file")

    expected_request_id = ink_v0f_request_id(
        issued_at_epoch_s=issued_at_epoch_s,
        duration_s=DURATION_S,
    )
    exact: bytes | None = None
    previous_not_after: int | None = None
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("epoch-6 issuance database failed integrity_check")
        metadata = connection.execute(
            "SELECT * FROM issuer_metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None:
            raise RuntimeError("epoch-6 issuance database is missing issuer metadata")
        if (
            int(metadata["authority_epoch"]) != AUTHORITY_EPOCH
            or int(metadata["minimum_authority_epoch"]) != MINIMUM_AUTHORITY_EPOCH
            or int(metadata["trust_config_version"]) != TRUST_CONFIG_VERSION
            or str(metadata["root_id"]) != "qnty-authority-root-v0"
            or str(metadata["public_key_fingerprint"]) != EXPECTED_PUBLIC_KEY_FINGERPRINT
            or str(metadata["trust_config_digest"]) != EXPECTED_TRUST_CONFIG_DIGEST
            or str(metadata["repository_identity"]) != "CipherCuttle/QntySpot"
        ):
            raise RuntimeError("epoch-6 issuance database metadata mismatch")

        rows = connection.execute(
            "SELECT request_id, authority_epoch, serial, receipt_id, receipt_bytes "
            "FROM issuances ORDER BY serial"
        ).fetchall()
        for row in rows:
            receipt_bytes = bytes(row["receipt_bytes"])
            receipt = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
            verify_receipt_signature(receipt, anchor)
            if (
                receipt.authority_epoch != int(row["authority_epoch"])
                or receipt.serial != int(row["serial"])
                or receipt.receipt_id != str(row["receipt_id"])
            ):
                raise RuntimeError("epoch-6 receipt does not match immutable ledger row")
            scope_kind = _assert_scope(
                receipt,
                allow_historical_serial1=True,
                allow_expired_historical_before_epoch_s=issued_at_epoch_s,
            )
            if (
                previous_not_after is not None
                and receipt.authority_policy.not_before_epoch_s < previous_not_after
            ):
                raise RuntimeError("epoch-6 history contains overlapping or backdated grants")
            previous_not_after = receipt.authority_policy.not_after_epoch_s
            if str(row["request_id"]) == expected_request_id:
                if receipt.issued_at_epoch_s != issued_at_epoch_s:
                    raise RuntimeError("epoch-6 exact request has different issued-at")
                if scope_kind != "CURRENT":
                    raise RuntimeError(
                        "historical epoch-6 request cannot be recovered after authority rebind"
                    )
                if exact is not None:
                    raise RuntimeError("epoch-6 history contains duplicate request id")
                exact = receipt_bytes
        if (
            exact is None
            and previous_not_after is not None
            and issued_at_epoch_s < previous_not_after
        ):
            raise RuntimeError(
                "new epoch-6 successor request must start at or after latest receipt expiry"
            )
    return exact


def _atomic_write_new(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError(f"existing export conflicts: {path}")
        return
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
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
    anchor_path = root / "public" / "authority-root-ed25519-v0.pub"
    trust_path = root / "public" / "trusted-authority-root-v0.json"
    if not anchor_path.is_file() or not trust_path.is_file():
        raise RuntimeError("production root is missing public AuthorityRoot continuity files")
    anchor = anchor_path.read_bytes()
    if sha256_hex(anchor) != EXPECTED_PUBLIC_KEY_FINGERPRINT:
        raise RuntimeError("public AuthorityRoot fingerprint mismatch")
    if sha256_hex(trust_path.read_bytes()) != EXPECTED_TRUST_CONFIG_DIGEST:
        raise RuntimeError("public AuthorityRoot trust-config digest mismatch")

    request_id = ink_v0f_request_id(
        issued_at_epoch_s=issued_at_epoch_s,
        duration_s=DURATION_S,
    )
    committed_before = _inspect_epoch6_history(
        root,
        anchor=anchor,
        issued_at_epoch_s=issued_at_epoch_s,
    )
    preflight = _run_read_only_preflight(
        root,
        now_epoch_s=issued_at_epoch_s,
        allow_active_request_id=request_id,
    )
    if preflight["active_ink_grants"] and committed_before is None:
        raise RuntimeError("active Ink grant detected without exact epoch-6 recovery state")

    signer = _load_private_key(private_key_path)
    if signer.public_key_bytes != anchor:
        raise RuntimeError("private key public bytes do not equal provisioned public anchor")

    db_path = root / EPOCH6_RELATIVE_DB
    db_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(db_path.parent, 0o700)

    bundle = issue_ink_v0f_grant(
        db_path=db_path,
        signer=signer,
        authority_epoch=AUTHORITY_EPOCH,
        minimum_authority_epoch=MINIMUM_AUTHORITY_EPOCH,
        trust_config_version=TRUST_CONFIG_VERSION,
        issued_at_epoch_s=issued_at_epoch_s,
        duration_s=DURATION_S,
        historical_request_validator=_allow_exact_historical_epoch6_request,
    )
    if bundle.trust_config_digest != EXPECTED_TRUST_CONFIG_DIGEST or bundle.public_anchor_bytes != anchor:
        raise RuntimeError("issued bundle trust continuity mismatch")

    receipt = AuthorityGrantReceiptV0.from_bytes(bundle.receipt_bytes)
    _assert_scope(receipt)
    if receipt.issued_at_epoch_s != issued_at_epoch_s:
        raise RuntimeError("receipt issued-at mismatch")
    if committed_before is not None and bundle.receipt_bytes != committed_before:
        raise RuntimeError("exact epoch-6 recovery returned different committed bytes")

    digest = sha256_hex(bundle.receipt_bytes)
    receipt_dir = root / "public" / "ink-v0f-level3-epoch6"
    record_dir = root / "state" / "epoch-6" / "records"
    receipt_name = f"{request_id}.json"
    record_name = f"{request_id}.json"
    receipt_path = receipt_dir / receipt_name
    record_path = record_dir / record_name

    record = {
        "authority_epoch": AUTHORITY_EPOCH,
        "authority_policy_digest": receipt.authority_policy_digest,
        "issued_at_epoch_s": issued_at_epoch_s,
        "not_after_epoch_s": receipt.authority_policy.not_after_epoch_s,
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": digest,
        "request_id": request_id,
        "schema": "qnty.authority_root.ink_v0f_level3_epoch6_native_eth_issuance.v0",
        "serial": receipt.serial,
        "trust_config_digest": bundle.trust_config_digest,
    }
    record_bytes = canonical_json_bytes(record)
    _atomic_write_new(receipt_path, bundle.receipt_bytes, mode=0o644)
    _atomic_write_new(
        receipt_path.with_suffix(".sha256"),
        f"{digest}  {receipt_name}\n".encode("ascii"),
        mode=0o644,
    )
    _atomic_write_new(record_path, record_bytes, mode=0o600)
    _atomic_write_new(
        record_path.with_suffix(".sha256"),
        f"{sha256_hex(record_bytes)}  {record_name}\n".encode("ascii"),
        mode=0o600,
    )
    return {
        **record,
        "db_path": EPOCH6_RELATIVE_DB,
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
