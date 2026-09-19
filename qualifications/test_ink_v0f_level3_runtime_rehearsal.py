from __future__ import annotations

import hashlib

import pytest
import rlp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_keys import keys

from qnty_authority_root.ink_v0f_binding import (
    INK_V0F_QNTYSPOT_COMMIT,
    INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
    INK_V0F_TAKER_ADDRESS,
)
from qnty_authority_root.ink_v0f_grant import issue_ink_v0f_grant

from qntyspot.authority_root import (
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import sha256_hex
from qntyspot.economics import build_intent
from qntyspot.errors import EnvelopeValidationError
from qntyspot.exact_signed_bytes import ExactSignedBytesScopeV0
from qntyspot.execution_contract import (
    AuthorityLevel,
    Capability,
    ExecutionSessionV0,
    PHASE_GRANTED_AUTHORITY_LEVEL,
)
from qntyspot.ink import INK_CHAIN_ID, KRAKMASK_ADDRESS, WETH9_ADDRESS
from qntyspot.ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    encode_swap_exact_tokens_for_tokens,
)
from qntyspot.keccak import keccak256
from qntyspot.ledger import ExecutionRuntime, open_ledger
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState


NOW = 1_800_000_000
DURATION_S = 900
ENTRY_ATOMIC = 10**15


class RehearsalAuthoritySigner:
    """Ephemeral AuthorityRoot signer used only inside this qualification."""

    def __init__(self) -> None:
        seed = hashlib.sha256(b"ink-v0f-level3-runtime-rehearsal").digest()
        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def _policy_doc() -> dict[str, object]:
    return {
        "schema": "qntyspot.policy.v0",
        "policy_name": "ink-v0f-level3-zero-money-rehearsal",
        "side": "BUY",
        "base": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": KRAKMASK_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "KRAKMASK",
        },
        "quote": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": WETH9_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "WETH",
        },
        "entry_ladder": {
            "levels": [
                {
                    "level_id": "E1",
                    "trigger_price": "1",
                    "input_amount": "0.001",
                }
            ]
        },
        "exit_ladder": {
            "levels": [
                {
                    "level_id": "X1",
                    "trigger_price": "2",
                    "input_ratio": "1",
                }
            ]
        },
        "capital": {
            "allocation_quote": "0.001",
            "per_order_cap_quote": "0.001",
            "per_instrument_cap_quote": "0.001",
            "per_network_cap_quote": "0.001",
            "global_portfolio_cap_quote": "0.001",
            "reserved_cash_quote": "0",
        },
        "limits": {
            "max_executable_price": "2",
            "min_executable_price": "0.5",
            "max_price_impact_bps": 100,
            "max_slippage_bps": 50,
        },
        "timing": {
            "valid_from_epoch_s": NOW - 60,
            "expiry_epoch_s": NOW + 3_600,
            "quote_ttl_s": 30,
        },
        "reentry": {
            "max_cycles": 1,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
    }


def _int_bytes(value: int) -> bytes:
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def _sign_type2(fields: dict[str, object], key: keys.PrivateKey) -> bytes:
    unsigned = [
        _int_bytes(int(fields["chainId"])),
        _int_bytes(int(fields["nonce"])),
        _int_bytes(int(fields["maxPriorityFeePerGas"])),
        _int_bytes(int(fields["maxFeePerGas"])),
        _int_bytes(int(fields["gas"])),
        bytes.fromhex(str(fields["to"])[2:]),
        _int_bytes(int(fields["value"])),
        bytes.fromhex(str(fields["data"])[2:]),
        [],
    ]
    message_hash = keccak256(b"\x02" + rlp.encode(unsigned))
    signature = key.sign_msg_hash(message_hash)
    signed = unsigned + [
        _int_bytes(signature.v),
        _int_bytes(signature.r),
        _int_bytes(signature.s),
    ]
    return b"\x02" + rlp.encode(signed)


def test_real_level3_grant_reaches_durable_signing_boundary_without_broadcast(
    tmp_path,
) -> None:
    signer = RehearsalAuthoritySigner()
    bundle = issue_ink_v0f_grant(
        db_path=tmp_path / "authority.sqlite3",
        signer=signer,
        authority_epoch=20,
        minimum_authority_epoch=20,
        trust_config_version=4,
        issued_at_epoch_s=NOW,
        duration_s=DURATION_S,
    )
    root = load_trusted_authority_root(
        bundle.trust_config_bytes,
        expected_config_digest=bundle.trust_config_digest,
        anchor_bytes=bundle.public_anchor_bytes,
    )
    from qntyspot.execution_contract import AuthorityGrantReceiptV0 as QntySpotAuthorityGrantReceiptV0

    receipt = QntySpotAuthorityGrantReceiptV0.from_bytes(bundle.receipt_bytes)

    policy = parse_policy(_policy_doc())
    ledger = open_ledger(str(tmp_path / "qntyspot.sqlite3"))
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    assert intent.quote_exposure_atomic == ENTRY_ATOMIC
    ledger.create_intent(intent, now_epoch_s=NOW)
    for state in (
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
    ):
        ledger.transition(intent.economic_action_id, state, now_epoch_s=NOW)

    session = ExecutionSessionV0(
        repository_commit=INK_V0F_QNTYSPOT_COMMIT,
        implementation_digest=INK_V0F_QNTYSPOT_IMPLEMENTATION_DIGEST,
        runtime_identity="cpython-3.11",
        db_schema_version=2,
        policy_id=policy.policy_id,
        authority_policy_digest=receipt.authority_policy_digest,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id=f"evm:{INK_CHAIN_ID}",
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
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert verified.authority_policy.granted_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert verified.authority_policy.max_reservation_atomic == ENTRY_ATOMIC
    assert verified.authority_policy.max_cumulative_atomic == ENTRY_ATOMIC

    runtime = ExecutionRuntime(ledger)
    assert runtime.record_verified_authority(verified, accepted_at_epoch_s=NOW) is True
    assert runtime.create_execution_session(session, verified, now_epoch_s=NOW) is True
    assert runtime.reserve_action(
        intent.economic_action_id,
        session=session,
        verified_grant=verified,
        now_epoch_s=NOW,
    ) is True
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RESERVED
    assert ledger.held_atomic() == ENTRY_ATOMIC

    # The real Level-3 gate has been crossed for this exact session, but
    # QntySpot still has no internal signature-production capability.
    from qntyspot.authority_root import effective_capabilities

    capabilities = effective_capabilities(
        source_phase_ceiling=PHASE_GRANTED_AUTHORITY_LEVEL,
        verified_grant=verified,
        session=session,
        now_epoch_s=NOW,
    )
    assert Capability.RESERVE_CAPITAL in capabilities
    assert Capability.CONSTRUCT_ENVELOPE in capabilities
    assert Capability.AUTHORIZE_APPROVAL in capabilities
    assert Capability.SUBMIT_EXACT_BYTES in capabilities
    assert Capability.PRODUCE_SIGNATURE not in capabilities

    calldata = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=ENTRY_ATOMIC,
        amount_out_min_atomic=1,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=NOW + 600,
    )
    scope = ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=intent.economic_action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=INK_CHAIN_ID,
        taker_address=INK_V0F_TAKER_ADDRESS,
        target_address=INK_V0F_ROUTER_ADDRESS,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        account_nonce=7,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
    )

    # Deliberately sign with a synthetic non-owner key. The exact-byte path
    # must reach cryptographic signer recovery and fail because the recovered
    # sender is not the frozen real taker.
    wrong_key = keys.PrivateKey(bytes.fromhex("01" * 32))
    wrong_sender = "0x" + keccak256(wrong_key.public_key.to_bytes())[-20:].hex()
    assert wrong_sender != INK_V0F_TAKER_ADDRESS
    raw = _sign_type2(
        {
            "chainId": INK_CHAIN_ID,
            "nonce": 7,
            "maxPriorityFeePerGas": 100_000_000,
            "maxFeePerGas": 2_000_000_000,
            "gas": 250_000,
            "to": INK_V0F_ROUTER_ADDRESS,
            "value": 0,
            "data": "0x" + calldata.hex(),
        },
        wrong_key,
    )

    with pytest.raises(EnvelopeValidationError, match="sender"):
        runtime.admit_exact_signed_bytes(
            scope,
            raw,
            session,
            verified,
            frozen_at_epoch_s=NOW + 1,
        )

    # Nothing crossed the human signing boundary and no transport exists in
    # this qualification.
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RESERVED
    assert ledger.held_atomic() == ENTRY_ATOMIC
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM signed_transactions"
    ).fetchone()[0] == 0
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM submission_attempts"
    ).fetchone()[0] == 0
