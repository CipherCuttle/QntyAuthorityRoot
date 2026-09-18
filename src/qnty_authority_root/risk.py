"""Frozen V0F Ink dust-live risk envelope.

This module is public governance material only. It contains no signer, wallet,
secret, RPC, transaction, or capital-execution path.

The policy is deliberately stricter than the generic authority-receipt
contract. A V0F Ink issuance may be narrower, but never wider.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .canon import digest_object
from .contract import AuthorityLevel, AuthorityPolicyRefV0
from .errors import IssuancePolicyError

INK_V0F_RISK_SCHEMA = "qnty.authority_root.ink_v0f_dust_risk_policy.v0"
QNTYSPOT_REPOSITORY_IDENTITY = "CipherCuttle/QntySpot"
QNTYSPOT_V0F_REPOSITORY_COMMIT = "bd518c670fd982595461a342f8fcae8fb6920329"
QNTYSPOT_V0F_IMPLEMENTATION_DIGEST = (
    "0951b951d9ba2beaba352a4d8c25f9b983f04cba3ec0c18797fa341e23fd2170"
)

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
    repository_identity: str
    permitted_repository_commit: str
    permitted_implementation_digest: str
    network_id: str
    venue_id: str
    pool_address: str
    base_instrument_id: str
    quote_instrument_id: str
    max_entry_atomic: int
    max_cumulative_entry_atomic: int
    max_open_positions_global: int
    max_open_positions_per_network: int
    max_open_positions_per_instrument: int
    max_in_flight_entries: int
    max_price_impact_bps: int
    max_slippage_bps: int
    max_grant_duration_s: int
    profit_recycle_ratio: Fraction
    banked_profit_ratio: Fraction
    schema: str = INK_V0F_RISK_SCHEMA

    def __post_init__(self) -> None:
        if self.repository_identity != QNTYSPOT_REPOSITORY_IDENTITY:
            raise IssuancePolicyError("Ink V0F risk policy targets the wrong repository")
        if self.permitted_repository_commit != QNTYSPOT_V0F_REPOSITORY_COMMIT:
            raise IssuancePolicyError("Ink V0F risk policy targets the wrong QntySpot commit")
        if self.permitted_implementation_digest != QNTYSPOT_V0F_IMPLEMENTATION_DIGEST:
            raise IssuancePolicyError("Ink V0F risk policy targets the wrong implementation digest")
        if self.network_id != INK_V0F_NETWORK_ID:
            raise IssuancePolicyError("Ink V0F network must be evm:57073")
        if self.venue_id != INK_V0F_VENUE_ID:
            raise IssuancePolicyError("Ink V0F venue identity mismatch")
        if self.pool_address != INK_V0F_POOL_ADDRESS:
            raise IssuancePolicyError("Ink V0F pool identity mismatch")
        if self.base_instrument_id != INK_V0F_BASE_INSTRUMENT_ID:
            raise IssuancePolicyError("Ink V0F base instrument identity mismatch")
        if self.quote_instrument_id != INK_V0F_QUOTE_INSTRUMENT_ID:
            raise IssuancePolicyError("Ink V0F quote instrument identity mismatch")
        _positive(self.max_entry_atomic, field="max_entry_atomic")
        _positive(self.max_cumulative_entry_atomic, field="max_cumulative_entry_atomic")
        if self.max_entry_atomic > self.max_cumulative_entry_atomic:
            raise IssuancePolicyError("Ink V0F per-entry cap exceeds cumulative cap")
        for field, value in (
            ("max_open_positions_global", self.max_open_positions_global),
            ("max_open_positions_per_network", self.max_open_positions_per_network),
            ("max_open_positions_per_instrument", self.max_open_positions_per_instrument),
            ("max_in_flight_entries", self.max_in_flight_entries),
            ("max_grant_duration_s", self.max_grant_duration_s),
        ):
            _positive(value, field=field)
        if self.max_open_positions_per_network > self.max_open_positions_global:
            raise IssuancePolicyError("Ink V0F network position cap exceeds global cap")
        if self.max_open_positions_per_instrument > self.max_open_positions_per_network:
            raise IssuancePolicyError("Ink V0F instrument position cap exceeds network cap")
        _bps(self.max_price_impact_bps, field="max_price_impact_bps")
        _bps(self.max_slippage_bps, field="max_slippage_bps")
        if type(self.profit_recycle_ratio) is not Fraction:
            raise IssuancePolicyError("profit_recycle_ratio must be an exact Fraction")
        if type(self.banked_profit_ratio) is not Fraction:
            raise IssuancePolicyError("banked_profit_ratio must be an exact Fraction")
        if self.profit_recycle_ratio < 0 or self.banked_profit_ratio < 0:
            raise IssuancePolicyError("profit ratios must be non-negative")
        if self.profit_recycle_ratio + self.banked_profit_ratio > 1:
            raise IssuancePolicyError("profit ratios exceed one")
        if self.schema != INK_V0F_RISK_SCHEMA:
            raise IssuancePolicyError("unknown Ink V0F risk policy schema")

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
            "permitted_implementation_digest": self.permitted_implementation_digest,
            "permitted_repository_commit": self.permitted_repository_commit,
            "pool_address": self.pool_address,
            "profit_recycle_ratio": _fraction_object(self.profit_recycle_ratio),
            "quote_instrument_id": self.quote_instrument_id,
            "repository_identity": self.repository_identity,
            "schema": self.schema,
            "venue_id": self.venue_id,
        }

    @property
    def policy_digest(self) -> str:
        return digest_object(self.canonical_object())


INK_V0F_DUST_RISK_POLICY = InkV0FDustRiskPolicyV0(
    repository_identity=QNTYSPOT_REPOSITORY_IDENTITY,
    permitted_repository_commit=QNTYSPOT_V0F_REPOSITORY_COMMIT,
    permitted_implementation_digest=QNTYSPOT_V0F_IMPLEMENTATION_DIGEST,
    network_id=INK_V0F_NETWORK_ID,
    venue_id=INK_V0F_VENUE_ID,
    pool_address=INK_V0F_POOL_ADDRESS,
    base_instrument_id=INK_V0F_BASE_INSTRUMENT_ID,
    quote_instrument_id=INK_V0F_QUOTE_INSTRUMENT_ID,
    max_entry_atomic=INK_V0F_MAX_ENTRY_ATOMIC,
    max_cumulative_entry_atomic=INK_V0F_MAX_CUMULATIVE_ENTRY_ATOMIC,
    max_open_positions_global=INK_V0F_MAX_OPEN_POSITIONS_GLOBAL,
    max_open_positions_per_network=INK_V0F_MAX_OPEN_POSITIONS_PER_NETWORK,
    max_open_positions_per_instrument=INK_V0F_MAX_OPEN_POSITIONS_PER_INSTRUMENT,
    max_in_flight_entries=INK_V0F_MAX_IN_FLIGHT_ENTRIES,
    max_price_impact_bps=INK_V0F_MAX_PRICE_IMPACT_BPS,
    max_slippage_bps=INK_V0F_MAX_SLIPPAGE_BPS,
    max_grant_duration_s=INK_V0F_MAX_GRANT_DURATION_S,
    profit_recycle_ratio=INK_V0F_PROFIT_RECYCLE_RATIO,
    banked_profit_ratio=INK_V0F_BANKED_PROFIT_RATIO,
)


def assert_ink_v0f_authority_policy_admissible(
    authority: AuthorityPolicyRefV0,
    *,
    repository_identity: str,
    risk: InkV0FDustRiskPolicyV0 = INK_V0F_DUST_RISK_POLICY,
) -> None:
    """Reject any Ink authority scope wider than the frozen dust envelope."""

    if type(authority) is not AuthorityPolicyRefV0:
        raise IssuancePolicyError("Ink V0F authority must be AuthorityPolicyRefV0")
    if repository_identity != risk.repository_identity:
        raise IssuancePolicyError("Ink V0F request targets a different repository")
    if authority.permitted_repository_commit != risk.permitted_repository_commit:
        raise IssuancePolicyError("Ink V0F request targets an unreviewed QntySpot commit")
    if authority.permitted_implementation_digest != risk.permitted_implementation_digest:
        raise IssuancePolicyError("Ink V0F request targets an unreviewed implementation digest")
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
