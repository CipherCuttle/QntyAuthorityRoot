from __future__ import annotations

import hashlib
import importlib
import io
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qnty_authority_root import (
    ALLOWED_NETWORK_ID,
    AuthorityIssuancePolicyV0,
    AuthorityIssuanceRequestV0,
    AuthorityIssuer,
    AuthorityLevel,
    AuthorityPolicyRefV0,
)

NOW = 1_700_000_100
PARENT_SHA = "982a0b38d9226523679c8e59c6abc22ccb5242fd"
ROOT_ID = "qnty-authority-root-v0"
COMMIT = PARENT_SHA
IMPLEMENTATION_DIGEST = "11" * 32
TAKER = "0x00000000000000000000000000000000000000aa"
VENUE_ID = "zero-x-allowance-holder"


class TestOnlySigner:
    """Deterministic in-memory test signer; never used by production code."""

    def __init__(self, label: str = "qnty-authority-root-tests") -> None:
        seed = hashlib.sha256(label.encode("utf-8")).digest()
        self._private = Ed25519PrivateKey.from_private_bytes(seed)

    @property
    def public_key_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)


@pytest.fixture
def signer() -> TestOnlySigner:
    return TestOnlySigner()


@pytest.fixture
def issuer_policy() -> AuthorityIssuancePolicyV0:
    return AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        allowed_network_ids=(ALLOWED_NETWORK_ID,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE_ID,),
        max_reservation_atomic=1_000_000,
        max_cumulative_atomic=4_000_000,
        max_grant_duration_s=3600,
    )


@pytest.fixture
def request_factory():
    def make(
        *,
        level: AuthorityLevel = AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        network: str = ALLOWED_NETWORK_ID,
        taker: str = TAKER,
        venue: str = VENUE_ID,
        root_id: str = ROOT_ID,
        commit: str = COMMIT,
        implementation_digest: str = IMPLEMENTATION_DIGEST,
        max_reservation_atomic: int = 1_000_000,
        max_cumulative_atomic: int = 4_000_000,
        not_before_epoch_s: int = NOW - 100,
        not_after_epoch_s: int = NOW + 900,
        issued_at_epoch_s: int = NOW,
        repository_identity: str = "CipherCuttle/QntySpot",
    ) -> AuthorityIssuanceRequestV0:
        return AuthorityIssuanceRequestV0(
            repository_identity=repository_identity,
            authority_policy=AuthorityPolicyRefV0(
                authority_root_id=root_id,
                granted_level=level,
                permitted_repository_commit=commit,
                permitted_implementation_digest=implementation_digest,
                permitted_network_id=network,
                permitted_taker_address=taker,
                permitted_venue_id=venue,
                max_reservation_atomic=max_reservation_atomic,
                max_cumulative_atomic=max_cumulative_atomic,
                not_before_epoch_s=not_before_epoch_s,
                not_after_epoch_s=not_after_epoch_s,
            ),
            issued_at_epoch_s=issued_at_epoch_s,
        )

    return make


@pytest.fixture
def issuer(tmp_path, issuer_policy, signer) -> AuthorityIssuer:
    return AuthorityIssuer(
        db_path=tmp_path / "authority.sqlite3",
        issuer_policy=issuer_policy,
        authority_epoch=8,
        minimum_authority_epoch=7,
        trust_config_version=1,
        signer=signer,
    )


@pytest.fixture
def canonical_qntyspot(tmp_path):
    """Materialize the exact local Git object for test-only consumer loading."""
    qntyspot_repo = Path(__file__).resolve().parents[2] / "QntySpot"
    checkout = tmp_path / "canonical-qntyspot"
    archive = subprocess.run(
        ["git", "-C", str(qntyspot_repo), "archive", PARENT_SHA],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(checkout)
    sys.path.insert(0, str(checkout))
    for name in list(sys.modules):
        if name == "qntyspot" or name.startswith("qntyspot."):
            del sys.modules[name]
    try:
        yield importlib.import_module("qntyspot")
    finally:
        sys.path.remove(str(checkout))
        for name in list(sys.modules):
            if name == "qntyspot" or name.startswith("qntyspot."):
                del sys.modules[name]
        shutil.rmtree(checkout, ignore_errors=True)
