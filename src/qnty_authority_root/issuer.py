"""Offline authority receipt issuance with durable SQLite continuity."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Protocol

from .canon import canonical_json_bytes, sha256_hex, strict_json_loads
from .contract import (
    AUTHORITY_ROOT_SCHEMA,
    ED25519_SIGNATURE_ALGORITHM,
    AuthorityGrantReceiptV0,
    TrustedAuthorityRootV0,
    verify_receipt_signature,
)
from .errors import AuthorityRootError, DatabaseError, IssuanceConflictError, IssuancePolicyError
from .policy import (
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    assert_issuance_request_admissible,
    snapshot_issuance_policy,
    snapshot_issuance_request,
    validate_request_id,
)

_SCHEMA_VERSION = 2
_REQUEST_RECORD_SCHEMA = "qntyspot.authority_root.v0.issuance_record"


class Ed25519Signer(Protocol):
    """The only signing seam: an explicitly injected authority-receipt signer."""

    @property
    def public_key_bytes(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


class AuthorityIssuer:
    """Issue only exact authority receipts, never blockchain transactions."""

    def __init__(
        self,
        *,
        db_path: str | Path,
        issuer_policy: AuthorityIssuancePolicyV0,
        authority_epoch: int,
        minimum_authority_epoch: int,
        trust_config_version: int,
        signer: Ed25519Signer,
    ) -> None:
        issuer_policy = snapshot_issuance_policy(issuer_policy)
        if type(authority_epoch) is not int or authority_epoch <= 0:
            raise IssuancePolicyError("authority_epoch must be positive")
        if type(minimum_authority_epoch) is not int or minimum_authority_epoch <= 0:
            raise IssuancePolicyError("minimum_authority_epoch must be positive")
        if authority_epoch < minimum_authority_epoch:
            raise IssuancePolicyError("authority_epoch is below minimum_authority_epoch")
        if type(trust_config_version) is not int or trust_config_version <= 0:
            raise IssuancePolicyError("trust_config_version must be positive")
        if not isinstance(db_path, (str, Path)) or not str(db_path):
            raise IssuancePolicyError("db_path must be explicit")
        if not hasattr(signer, "sign") or not hasattr(signer, "public_key_bytes"):
            raise IssuancePolicyError("signer must be an injected Ed25519Signer")
        public_key = signer.public_key_bytes
        if type(public_key) is not bytes or len(public_key) != 32:
            raise IssuancePolicyError("signer public_key_bytes must be exactly 32 bytes")

        self._db_path = str(db_path)
        self._policy = issuer_policy
        self._authority_epoch = authority_epoch
        self._minimum_authority_epoch = minimum_authority_epoch
        self._trust_config_version = trust_config_version
        self._signer = signer
        self._public_key_bytes = public_key
        self._root = self._build_trusted_root()
        self._initialize_database()

    @property
    def issuer_policy(self) -> AuthorityIssuancePolicyV0:
        return self._policy

    @property
    def trusted_root(self) -> TrustedAuthorityRootV0:
        return self._root

    @property
    def public_anchor_bytes(self) -> bytes:
        """Public Ed25519 bytes, supplied separately from the config bytes."""
        return self._public_key_bytes

    @property
    def trust_config_bytes(self) -> bytes:
        return self._root.serialized_config

    @property
    def trust_config_digest(self) -> str:
        return self._root.trust_config_digest

    def issue(self, *, request_id: str, request: AuthorityIssuanceRequestV0) -> bytes:
        """Return committed receipt bytes, or fail without returning a receipt."""
        validate_request_id(request_id)
        request = snapshot_issuance_request(request)
        assert_issuance_request_admissible(self._policy, request)
        request_record_bytes = self._request_record_bytes(request_id, request)
        request_digest = sha256_hex(request_record_bytes)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT request_id, request_digest, request_bytes, authority_epoch, serial, receipt_id, receipt_bytes "
                "FROM issuances WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest:
                    raise IssuanceConflictError(
                        "request_id is already committed to different canonical content"
                    )
                committed = bytes(existing["receipt_bytes"])
                self._validate_committed_receipt(
                    committed,
                    row=existing,
                    request=request,
                    request_id=request_id,
                    expected_request_record_bytes=request_record_bytes,
                )
                self._commit(connection)
                return committed

            serial_row = connection.execute("SELECT COALESCE(MAX(serial), 0) + 1 FROM issuances").fetchone()
            serial = int(serial_row[0])
            unsigned = AuthorityGrantReceiptV0(
                root_id=self._policy.root_id,
                public_key_fingerprint=sha256_hex(self._public_key_bytes),
                signature_algorithm=ED25519_SIGNATURE_ALGORITHM,
                authority_epoch=self._authority_epoch,
                serial=serial,
                issued_at_epoch_s=request.issued_at_epoch_s,
                authority_policy=request.authority_policy,
                signature=bytes(64),
            )
            signature = self._signer.sign(unsigned.signed_body_bytes)
            if type(signature) is not bytes or len(signature) != 64:
                raise IssuancePolicyError("signer returned an invalid Ed25519 signature")
            receipt = AuthorityGrantReceiptV0(
                root_id=unsigned.root_id,
                public_key_fingerprint=unsigned.public_key_fingerprint,
                signature_algorithm=unsigned.signature_algorithm,
                authority_epoch=unsigned.authority_epoch,
                serial=unsigned.serial,
                issued_at_epoch_s=unsigned.issued_at_epoch_s,
                authority_policy=unsigned.authority_policy,
                signature=signature,
            )
            receipt_bytes = receipt.serialized
            parsed = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
            verify_receipt_signature(parsed, self._public_key_bytes)
            connection.execute(
                "INSERT INTO issuances "
                "(request_id, request_digest, request_bytes, authority_epoch, serial, receipt_id, receipt_bytes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    request_digest,
                    request_record_bytes,
                    receipt.authority_epoch,
                    receipt.serial,
                    receipt.receipt_id,
                    receipt_bytes,
                ),
            )
            # Nothing is returned until this call has completed successfully.
            self._commit(connection)
            return receipt_bytes
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def get_committed(self, request_id: str) -> bytes | None:
        validate_request_id(request_id)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT request_id, request_digest, request_bytes, authority_epoch, serial, receipt_id, receipt_bytes "
                "FROM issuances WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                return None
            committed = bytes(row["receipt_bytes"])
            self._validate_committed_receipt(committed, row=row, request_id=request_id)
            return committed
        finally:
            connection.close()

    def list_committed(self) -> tuple[tuple[str, int, str], ...]:
        """Read-only application view of committed issuance history."""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT request_id, serial, receipt_id FROM issuances ORDER BY serial"
            ).fetchall()
            return tuple((str(row[0]), int(row[1]), str(row[2])) for row in rows)
        finally:
            connection.close()

    def _build_trusted_root(self) -> TrustedAuthorityRootV0:
        config = {
            "minimum_authority_epoch": self._minimum_authority_epoch,
            "public_key_fingerprint": sha256_hex(self._public_key_bytes),
            "root_id": self._policy.root_id,
            "schema": AUTHORITY_ROOT_SCHEMA + ".trust_config",
            "signature_algorithm": ED25519_SIGNATURE_ALGORITHM,
            "trust_config_version": self._trust_config_version,
        }
        config_bytes = canonical_json_bytes(config)
        return TrustedAuthorityRootV0(
            root_id=self._policy.root_id,
            signature_algorithm=ED25519_SIGNATURE_ALGORITHM,
            public_key_fingerprint=sha256_hex(self._public_key_bytes),
            minimum_authority_epoch=self._minimum_authority_epoch,
            trust_config_version=self._trust_config_version,
            trust_config_digest=sha256_hex(config_bytes),
            anchor_bytes=self._public_key_bytes,
        )

    def _validate_committed_receipt(
        self,
        receipt_bytes: bytes,
        *,
        row: sqlite3.Row,
        request: AuthorityIssuanceRequestV0 | None = None,
        request_id: str,
        expected_request_record_bytes: bytes | None = None,
    ) -> None:
        """Validate stored bytes before any application API exposes them."""
        try:
            request_record_bytes = row["request_bytes"]
            if type(request_record_bytes) is not bytes:
                raise DatabaseError("committed request record is not bytes")
            request_record = strict_json_loads(request_record_bytes)
            expected_request_fields = {
                "authority_policy", "issued_at_epoch_s", "repository_identity", "request_id", "schema"
            }
            if type(request_record) is not dict or set(request_record) != expected_request_fields:
                raise DatabaseError("committed request record has unknown or missing fields")
            if request_record["schema"] != _REQUEST_RECORD_SCHEMA:
                raise DatabaseError("committed request record has an unknown schema")
            if canonical_json_bytes(request_record) != request_record_bytes:
                raise DatabaseError("committed request record is not canonical JSON")
            if request_record["request_id"] != request_id:
                raise DatabaseError("committed request record is bound to a different request id")
            if sha256_hex(request_record_bytes) != row["request_digest"]:
                raise DatabaseError("committed request record digest does not match its ledger row")
            if expected_request_record_bytes is not None and request_record_bytes != expected_request_record_bytes:
                raise DatabaseError("committed request record does not match the canonical request")
            receipt = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
            verify_receipt_signature(receipt, self._public_key_bytes)
        except AuthorityRootError as exc:
            raise DatabaseError(f"committed receipt failed integrity validation: {exc}") from exc
        expected_fingerprint = sha256_hex(self._public_key_bytes)
        if (
            receipt.root_id != self._policy.root_id
            or receipt.public_key_fingerprint != expected_fingerprint
            or receipt.authority_epoch != int(row["authority_epoch"])
            or receipt.serial != int(row["serial"])
            or receipt.receipt_id != row["receipt_id"]
            or request_record["authority_policy"] != receipt.authority_policy.canonical_object()
            or request_record["issued_at_epoch_s"] != receipt.issued_at_epoch_s
        ):
            raise DatabaseError("committed receipt does not match its immutable ledger row")
        stored_request = AuthorityIssuanceRequestV0(
            repository_identity=request_record["repository_identity"],
            authority_policy=receipt.authority_policy,
            issued_at_epoch_s=request_record["issued_at_epoch_s"],
        )
        try:
            assert_issuance_request_admissible(self._policy, stored_request)
        except IssuancePolicyError as exc:
            raise DatabaseError(f"committed request is no longer admissible: {exc}") from exc
        if request is not None and request != stored_request:
            raise DatabaseError("committed receipt does not match the canonical request")

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._db_path,
                timeout=30.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            raise DatabaseError(f"could not open issuance database: {exc}") from exc

    def _initialize_database(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version not in (0, _SCHEMA_VERSION):
                raise DatabaseError(
                    f"unsupported issuance database schema version {current_version}"
                )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS issuer_metadata ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "schema_version INTEGER NOT NULL, root_id TEXT NOT NULL, "
                "public_key_fingerprint TEXT NOT NULL, authority_epoch INTEGER NOT NULL, "
                "minimum_authority_epoch INTEGER NOT NULL, trust_config_version INTEGER NOT NULL, "
                "trust_config_digest TEXT NOT NULL, repository_identity TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS issuances ("
                "request_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, request_bytes BLOB NOT NULL, "
                "authority_epoch INTEGER NOT NULL, serial INTEGER NOT NULL UNIQUE, "
                "receipt_id TEXT NOT NULL UNIQUE, receipt_bytes BLOB NOT NULL)"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS issuances_no_update BEFORE UPDATE ON issuances "
                "BEGIN SELECT RAISE(ABORT, 'issuance history is append-only'); END"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS issuances_no_delete BEFORE DELETE ON issuances "
                "BEGIN SELECT RAISE(ABORT, 'issuance history is non-deletable'); END"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS issuer_metadata_no_update BEFORE UPDATE ON issuer_metadata "
                "BEGIN SELECT RAISE(ABORT, 'issuer metadata is append-only'); END"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS issuer_metadata_no_delete BEFORE DELETE ON issuer_metadata "
                "BEGIN SELECT RAISE(ABORT, 'issuer metadata is non-deletable'); END"
            )
            self._assert_table_shape(
                connection,
                "issuer_metadata",
                (
                    "singleton",
                    "schema_version",
                    "root_id",
                    "public_key_fingerprint",
                    "authority_epoch",
                    "minimum_authority_epoch",
                    "trust_config_version",
                    "trust_config_digest",
                    "repository_identity",
                ),
            )
            self._assert_table_shape(
                connection,
                "issuances",
                (
                    "request_id",
                    "request_digest",
                    "request_bytes",
                    "authority_epoch",
                    "serial",
                    "receipt_id",
                    "receipt_bytes",
                ),
            )
            expected = (
                _SCHEMA_VERSION,
                self._policy.root_id,
                sha256_hex(self._public_key_bytes),
                self._authority_epoch,
                self._minimum_authority_epoch,
                self._trust_config_version,
                self._root.trust_config_digest,
                self._policy.repository_identity,
            )
            row = connection.execute("SELECT * FROM issuer_metadata WHERE singleton = 1").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO issuer_metadata "
                    "(singleton, schema_version, root_id, public_key_fingerprint, authority_epoch, "
                    "minimum_authority_epoch, trust_config_version, trust_config_digest, repository_identity) "
                    "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)",
                    expected,
                )
            elif tuple(row[index] for index in range(1, 9)) != expected:
                raise DatabaseError("issuance database belongs to a different authority configuration")
            self._commit(connection)
        except DatabaseError:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise DatabaseError(f"issuance database schema failure: {exc}") from exc
        finally:
            connection.close()

    def _assert_table_shape(
        self, connection: sqlite3.Connection, table: str, expected_columns: tuple[str, ...]
    ) -> None:
        actual = tuple(row[1] for row in connection.execute(f"PRAGMA table_info({table})"))
        if actual != expected_columns:
            raise DatabaseError(f"issuance database table {table!r} has an unsupported schema")

    def _request_record_bytes(
        self, request_id: str, request: AuthorityIssuanceRequestV0
    ) -> bytes:
        return canonical_json_bytes(
            {
                "authority_policy": request.authority_policy.canonical_object(),
                "issued_at_epoch_s": request.issued_at_epoch_s,
                "repository_identity": request.repository_identity,
                "request_id": request_id,
                "schema": _REQUEST_RECORD_SCHEMA,
            }
        )

    def _commit(self, connection: sqlite3.Connection) -> None:
        connection.commit()
