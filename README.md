# QntyAuthorityRoot

An independent, offline V0 issuer for QntySpot authority receipts.

This repository has one narrow responsibility: validate an explicitly supplied
QntySpot authority-policy request, sign the canonical authority receipt body
with an injected Ed25519 signer, and durably commit the resulting receipt in
an append-only SQLite ledger before returning its bytes.

The V0 boundary is mechanical:

- the historical Robinhood testnet profile remains `evm:46630`;
- one separate V0F Ink dust profile admits only `evm:57073` /
  `inkyswap-v2-ink-mainnet` and binds the reviewed QntySpot implementation;
- `evm:4663`, unknown networks, and wildcard/alias scopes are rejected;
- the maximum issuable level is `HUMAN_SIGNED_EXECUTION`;
- grant duration is at most 3600 seconds;
- no service, RPC, HTTP, wallet, transaction, or capital-execution path exists;
- no production root provisioning or ambient secret discovery exists;
- the Ink V0F profile is capped at 0.001 WETH total entry capital, one open
  position, one in-flight entry, 100 bps price impact, 50 bps slippage, and
  zero profit recycling for the first dust phase.

The signer is an injected interface. Production root material is intentionally
not created, read, or provisioned here. Tests use ephemeral deterministic
test-only material held in memory.

The receipt contract is frozen against QntySpot commit
`982a0b38d9226523679c8e59c6abc22ccb5242fd`.


## Ink V0F dust-risk profile

`qnty_authority_root.risk.INK_V0F_DUST_RISK_POLICY` is a public,
content-addressed governance object. It is not a receipt and grants no
authority by itself.

It binds:

- QntySpot canonical merge `bd518c670fd982595461a342f8fcae8fb6920329`;
- implementation digest
  `0951b951d9ba2beaba352a4d8c25f9b983f04cba3ec0c18797fa341e23fd2170`;
- Ink chain `evm:57073`;
- InkySwap V2 venue `inkyswap-v2-ink-mainnet`;
- exact KRAKMASK/WETH pool and token identities;
- 0.001 WETH maximum per-entry and cumulative entry capital;
- one global/network/instrument position and one in-flight entry;
- 100 bps maximum price impact and 50 bps maximum slippage;
- at most a 900-second authority grant;
- zero profit recycling and 100% banking during the first dust phase.

An Ink issuance policy must bind exactly one taker address. This repository
does not choose that address and this change issues no grant. The QntySpot V0F
runtime must independently consume/enforce the same risk-policy digest before
any live-capital transition.
