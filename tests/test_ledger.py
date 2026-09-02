from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from qnty_authority_root import AuthorityGrantReceiptV0, AuthorityIssuer, IssuanceConflictError


def test_duplicate_request_id_returns_exact_committed_bytes(issuer, request_factory) -> None:
    request = request_factory()
    first = issuer.issue(request_id="same-request", request=request)
    second = issuer.issue(request_id="same-request", request=request)
    assert second is not first
    assert second == first
    assert issuer.list_committed() == (("same-request", 1, AuthorityGrantReceiptV0.from_bytes(first).receipt_id),)


def test_duplicate_request_id_cannot_rebind_content(issuer, request_factory) -> None:
    issuer.issue(request_id="bound-request", request=request_factory())
    with pytest.raises(IssuanceConflictError, match="different canonical content"):
        issuer.issue(request_id="bound-request", request=request_factory(issued_at_epoch_s=NOW_PLUS_ONE))


def test_committed_receipt_survives_reopening(tmp_path, issuer_policy, signer, request_factory) -> None:
    path = tmp_path / "restart.sqlite3"
    first_issuer = AuthorityIssuer(
        db_path=path,
        issuer_policy=issuer_policy,
        authority_epoch=8,
        minimum_authority_epoch=7,
        trust_config_version=1,
        signer=signer,
    )
    request = request_factory()
    first = first_issuer.issue(request_id="survives-restart", request=request)
    second_issuer = AuthorityIssuer(
        db_path=path,
        issuer_policy=issuer_policy,
        authority_epoch=8,
        minimum_authority_epoch=7,
        trust_config_version=1,
        signer=signer,
    )
    assert second_issuer.get_committed("survives-restart") == first
    assert second_issuer.issue(request_id="survives-restart", request=request) == first


def test_idempotent_and_read_paths_reject_tampered_stored_bytes(issuer, request_factory) -> None:
    request = request_factory()
    issuer.issue(request_id="tampered-row", request=request)
    connection = sqlite3.connect(issuer._db_path)
    try:
        connection.execute("DROP TRIGGER issuances_no_update")
        connection.execute(
            "UPDATE issuances SET receipt_bytes = ?, receipt_id = ? WHERE request_id = ?",
            (b"not-a-receipt", "00" * 32, "tampered-row"),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(Exception, match="integrity"):
        issuer.issue(request_id="tampered-row", request=request)
    with pytest.raises(Exception, match="integrity"):
        issuer.get_committed("tampered-row")


def test_concurrent_distinct_requests_have_unique_monotone_serials(issuer, request_factory) -> None:
    def issue(index: int) -> bytes:
        return issuer.issue(request_id=f"concurrent-{index}", request=request_factory())

    with ThreadPoolExecutor(max_workers=8) as executor:
        receipts = list(executor.map(issue, range(24)))
    serials = [AuthorityGrantReceiptV0.from_bytes(raw).serial for raw in receipts]
    assert sorted(serials) == list(range(1, 25))
    assert len(set(serials)) == 24


def test_commit_failure_does_not_return_or_expose_new_receipt(issuer, request_factory, monkeypatch) -> None:
    def fail_commit(_connection) -> None:
        raise sqlite3.OperationalError("simulated commit failure")

    monkeypatch.setattr(issuer, "_commit", fail_commit)
    with pytest.raises(sqlite3.OperationalError, match="simulated"):
        issuer.issue(request_id="commit-fails", request=request_factory())
    assert issuer.get_committed("commit-fails") is None


def test_issuance_history_is_append_only(tmp_path, issuer_policy, signer, request_factory) -> None:
    issuer = AuthorityIssuer(
        db_path=tmp_path / "append-only.sqlite3",
        issuer_policy=issuer_policy,
        authority_epoch=8,
        minimum_authority_epoch=7,
        trust_config_version=1,
        signer=signer,
    )
    raw = issuer.issue(request_id="append-only", request=request_factory())
    receipt_id = AuthorityGrantReceiptV0.from_bytes(raw).receipt_id
    connection = sqlite3.connect(tmp_path / "append-only.sqlite3")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE issuances SET serial = 99 WHERE request_id = 'append-only'")
        with pytest.raises(sqlite3.IntegrityError, match="non-deletable"):
            connection.execute("DELETE FROM issuances WHERE request_id = 'append-only'")
        connection.rollback()
    finally:
        connection.close()
    assert issuer.get_committed("append-only") == raw
    assert receipt_id


NOW_PLUS_ONE = 1_700_000_101
