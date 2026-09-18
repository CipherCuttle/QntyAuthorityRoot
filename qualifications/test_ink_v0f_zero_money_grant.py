from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qnty_authority_root.ink_v0f_binding import (
    INK_V0F_QNTYSPOT_COMMIT,
    INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_TAKER_ADDRESS,
)
from qnty_authority_root.ink_v0f_grant import issue_ink_v0f_grant
from qntyspot import LIVE_CAPITAL_AUTHORIZED, SIGNING_AUTHORIZED
from qntyspot.authority_root import (
    AuthorityGrantReceiptV0,
    effective_authority_level,
    effective_capabilities,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.execution_contract import (
    PHASE_GRANTED_AUTHORITY_LEVEL,
    AuthorityLevel,
    Capability,
    ExecutionSessionV0,
)

NOW = 1_800_000_000


class QualificationSigner:
    def __init__(self) -> None:
        seed = hashlib.sha256(b"ink-v0f-zero-money-qualification").digest()
        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def test_short_lived_level3_receipt_verifies_but_cannot_escape_source_ceiling(tmp_path) -> None:
    bundle = issue_ink_v0f_grant(
        db_path=tmp_path / "qualification.sqlite3",
        signer=QualificationSigner(),
        authority_epoch=10,
        minimum_authority_epoch=10,
        trust_config_version=3,
        issued_at_epoch_s=NOW,
        duration_s=900,
    )

    root = load_trusted_authority_root(
        bundle.trust_config_bytes,
        expected_config_digest=bundle.trust_config_digest,
        anchor_bytes=bundle.public_anchor_bytes,
    )
    receipt = AuthorityGrantReceiptV0.from_bytes(bundle.receipt_bytes)
    assert receipt.authority_policy.granted_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION

    session = ExecutionSessionV0(
        repository_commit=INK_V0F_QNTYSPOT_COMMIT,
        implementation_digest=INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id="22" * 32,
        authority_policy_digest=receipt.authority_policy_digest,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id="evm:57073",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=NOW,
        session_ordinal=0,
    )
    verified = verify_authority_grant(
        receipt=receipt,
        trusted_root=root,
        session=session,
        now_epoch_s=NOW,
    )
    assert verified.authority_policy.granted_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION

    effective = effective_authority_level(
        source_phase_ceiling=PHASE_GRANTED_AUTHORITY_LEVEL,
        verified_grant=verified,
        now_epoch_s=NOW,
    )
    assert effective is PHASE_GRANTED_AUTHORITY_LEVEL
    assert effective < AuthorityLevel.HUMAN_SIGNED_EXECUTION

    capabilities = effective_capabilities(
        source_phase_ceiling=PHASE_GRANTED_AUTHORITY_LEVEL,
        verified_grant=verified,
        now_epoch_s=NOW,
    )
    assert Capability.CONSTRUCT_ENVELOPE not in capabilities
    assert Capability.AUTHORIZE_APPROVAL not in capabilities
    assert Capability.PRODUCE_SIGNATURE not in capabilities
    assert SIGNING_AUTHORIZED is False
    assert LIVE_CAPITAL_AUTHORIZED is False
