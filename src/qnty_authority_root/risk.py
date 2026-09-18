"""Frozen V0F Ink dust-live risk envelope.

This module is public governance material only. It contains no signer, wallet,
secret, RPC, transaction, or capital-execution path.

The policy is deliberately stricter than the generic authority-receipt
contract. A V0F Ink issuance may be narrower, but never wider. Exact QntySpot
repository commit and implementation identity remain separately bound by the
ordinary authority receipt, avoiding circular cross-repository identities.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .canon import canonical_json_bytes, digest_object
from .contract import AuthorityLevel, AuthorityPolicyRefV0
from .errors import IssuancePolicyError

INK_V0F_RISK_SCHEMA = "qnty.authority_root.ink_v0f_dust_risk_policy.v0"
QNTYSPOT_REPOSITORY_IDENTITY = "CipherCuttle/QntySpot"

INK_V0F_NETWORK_ID = "evm:57073"
INK_V0F_VENUE_ID = "inkyswap-v2-ink-mainnet"
INK_V0F_POOL_ADDRESS = "0xed11ed4b195e84ba9b74c4d6ce13b7a43b354264"
INK_V0F_BASE_INSTRUMENT_ID = (
    "evm:57073:0x32bcb803f696c99eb263d60a05cafd8689026575"
)
INK_V0F_QUOTE_INSTRUMENT_ID = (
    "evm:57073:0x4200000000000000000000000000000000000006"
)

# 0.001 WETH, expressed in WETH atomic units.
INK_V0F_MAX_ENTRY_ATOMIC = 1_000_000_000_000_000
INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC = 1_000_000_000_000_000
INK_V0F_MAX_OPEN_POSITIONS_GLOBAL = 1
INK_V0F_MAX_OPEN_POSITIONS_PER_NETWORK = 1
INK_V0F_MAX_OPEN_POSITIONS_PER_INSTRUMENT = 1
INK_V0F_MAX_IN_FLIGHT_ENTRIES = 1
INK_V0F_MAX_PRICE_IMPACT_BPS = 100
INK_V0F_MAX_SLIPPAGE_BPS = 50
INK_V0F_MAX_GRANT_DURATION_S = 900
INK_V0F_PROFIT_RECYCLE_RATIO = Fraction(0, 1)
INK_V0F_BANKED_PROFIT_RATIO = Fraction(1, 1)


def _positive(value: Any, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise IssuancePolicyError(f"{field}: expected positive integer")
    return value


def _bps(value: Any, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 10_000:
        raise IssuancePolicyError(f"{field}: expected integer basis points in [0, 10000]")
    return value


def _fraction_object(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


@dataclass(frozen=True, slots=True)
class InkV0FDustRiskPolicyV0:
    repository_identity: str = QNTYSPOT_REPOSITORY_IDENTITY
    network_id: str = INK_V0F_NETWORK_ID
    venue_id: str = INK_V0F_VENUE_ID
    pool_address: str = INK_V0F_POOL_ADDRESS
    base_instrument_id: str = INK_V0F_BASE_INSTRUMENT_ID
    quote_instrument_id: str = INK_V0F_QUOTE_INSTRUMENT_ID
    max_entry_atomic: int = INK_V0F_MAX_ENTRY_ATOMIC
    max_cumulative_entry_atomic: int = INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC
    max_open_positions_global: int = INK_V0F_MAX_OPEN_POSITIONS_GLOBAL
    max_open_positions_per_network: int = INK_V0F_MAX_OPEN_POSITIONS_PER_NETWORK
    max_open_positions_per_instrument: int = INK_V0F_MAX_OPEN_POSITIONS_PER_INSTRUMENT
    max_in_flight_entries: int = INK_V0F_MAX_IN_FLIGHT_ENTRIES
    max_price_impact_bps: int = INK_V0F_MAX_PRICE_IMPACT_BPS
    max_slippage_bps: int = INK_V0F_MAX_SLIPPAGE_BPS
    max_grant_duration_s: int = INK_V0F_MAX_GRANT_DURATION_S
    profit_recycle_ratio: Fraction = INK_V0F_PROFIT_RECYCLE_RATIO
    banked_profit_ratio: Fraction = INK_V0F_BANKED_PROFIT_RATIO
    schema: str = INK_V0F_RISK_SCHEMA

    def __post_init__(self) -> None:
        expected = (
            ("repository_identity", self.repository_identity, QNTYSPOT_REPOSITORY_IDENTITY),
            ("network_id", self.network_id, INK_V0F_NETWORK_ID),
            ("venue_id", self.venue_id, INK_V0F_VENUE_ID),
            ("pool_address", self.pool_address, INK_V0F_POOL_ADDRESS),
            ("base_instrument_id", self.base_instrument_id, INK_V0F_BASE_INSTRUMENT_ID),
            ("quote_instrument_id", self.quote_instrument_id, INK_V0F_QUOTE_INSTRUMENT_ID),
            ("max_entry_atomic", self.max_entry_atomic, INK_V0F_MAX_ENTRY_ATOMIC),
            (
                "max_cumulative_entry_atomic",
                self.max_cumulative_entry_atomic,
                INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC,
            ),
            (
                "max_open_positions_global",
                self.max_open_positions_global,
                INK_V0F_MAX_OPEN_POSITIONS_GLOBAL,
            ),
            (
                "max_open_positions_per_network",
                self.max_open_positions_per_network,
                INK_V0F_MAX_OPEN_POSITIONS_PER_NETWORK,
            ),
            (
                "max_open_positions_per_instrument",
                self.max_open_positions_per_instrument,
                INK_V0F_MAX_OPEN_POSITIONS_PER_INSTRUMENT,
            ),
            (
                "max_in_flight_entries",
                self.max_in_flight_entries,
                INK_V0F_MAX_IN_FLIGHT_ENTRIES,
            ),
            (
                "max_price_impact_bps",
                self.max_price_impact_bps,
                INK_V0F_MAX_PRICE_IMPACT_BPS,
            ),
            ("max_slippage_bps", self.max_slippage_bps, INK_V0F_MAX_SLIPPAGE_BPS),
            (
                "max_grant_duration_s",
                self.max_grant_duration_s,
                INK_V0F_MAX_GRANT_DURATION_S,
            ),
            (
                "profit_recycle_ratio",
                self.profit_recycle_ratio,
                INK_V0F_PROFIT_RECYCLE_RATIO,
            ),
            (
                "banked_profit_ratio",
                self.banked_profit_ratio,
                INK_V0F_BANKED_PROFIT_RATIO,
            ),
            ("schema", self.schema, INK_V0F_RISK_SCHEMA),
        )
        for field, actual, frozen in expected:
            if type(actual) is not type(frozen) or actual != frozen:
                raise IssuancePolicyError(
                    f"{field}: Ink V0F dust-risk policy is frozen and cannot be widened or changed"
                )

        _positive(self.max_entry_atomic, field="max_entry_atomic")
        _positive(self.max_cumulative_entry_atomic, field="max_cumulative_entry_atomic")
        _positive(self.max_open_positions_global, field="max_open_positions_global")
        _positive(self.max_open_positions_per_network, field="max_open_positions_per_network")
        _positive(self.max_open_positions_per_instrument, field="max_open_positions_per_instrument")
        _positive(self.max_in_flight_entries, field="max_in_flight_entries")
        _positive(self.max_grant_duration_s, field="max_grant_duration_s")
        _bps(self.max_price_impact_bps, field="max_price_impact_bps")
        _bps(self.max_slippage_bps, field="max_slippage_bps")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "banked_profit_ratio": _fraction_object(self.banked_profit_ratio),
            "base_instrument_id": self.base_instrument_id,
            "max_cumulative_entry_atomic": str(self.max_cumulative_entry_atomic),
            "max_entry_atomic": str(self.max_entry_atomic),
            "max_grant_duration_s": self.max_grant_duration_s,
            "max_in_flight_entries": self.max_in_flight_entries,
            "max_open_positions_global": self.max_open_positions_global,
            "max_open_positions_per_instrument": self.max_open_positions_per_instrument,
            "max_open_positions_per_network": self.max_open_positions_per_network,
            "max_price_impact_bps": self.max_price_impact_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "network_id": self.network_id,
            "pool_address": self.pool_address,
            "profit_recycle_ratio": _fraction_object(self.profit_recycle_ratio),
            "quote_instrument_id": self.quote_instrument_id,
            "repository_identity": self.repository_identity,
            "schema": self.schema,
            "venue_id": self.venue_id,
        }

    @property
    def serialized(self) -> bytes:
        return canonical_json_bytes(self.canonical_object())

    @property
    def policy_digest(self) -> str:
        return digest_object(self.canonical_object())


INK_V0F_DUST_RISK_POLICY = InkV0FDustRiskPolicyV0()


def assert_ink_v0f_authority_policy_admissible(
    authority: AuthorityPolicyRefV0,
    *,
    repository_identity: str,
) -> None:
    """Reject any Ink authority scope wider than the frozen dust envelope."""

    risk = INK_V0F_DUST_RISK_POLICY
    if type(authority) is not AuthorityPolicyRefV0:
        raise IssuancePolicyError("Ink V0F authority must be AuthorityPolicyRefV0")
    if repository_identity != risk.repository_identity:
        raise IssuancePolicyError("Ink V0F request targets a different repository")
    if authority.permitted_network_id != risk.network_id:
        raise IssuancePolicyError("Ink V0F request targets a different network")
    if authority.permitted_venue_id != risk.venue_id:
        raise IssuancePolicyError("Ink V0F request targets a different venue")
    if authority.granted_level > AuthorityLevel.HUMAN_SIGNED_EXECUTION:
        raise IssuancePolicyError("Ink V0F does not authorize an autonomous signer")
    if authority.max_reservation_atomic > risk.max_entry_atomic:
        raise IssuancePolicyError("Ink V0F reservation exceeds the dust entry cap")
    if authority.max_cumulative_atomic > risk.max_cumulative_entry_atomic:
        raise IssuancePolicyError("Ink V0F cumulative capital exceeds the dust cap")
    duration = authority.not_after_epoch_s - authority.not_before_epoch_s
    if duration > risk.max_grant_duration_s:
        raise IssuancePolicyError("Ink V0F grant duration exceeds the dust-risk policy")
