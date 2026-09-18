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
content-addressed governance object. Its canonical artifact digest is
`c7058aec58f3fbcb4f2b390a6eac35bdb9d8cab2484a2ff22731f2dc586e8ee3`. It is not a receipt and grants no
authority by itself.

It binds:

- Ink chain `evm:57073`;
- InkySwap V2 venue `inkyswap-v2-ink-mainnet`;
- exact KRAKMASK/WETH pool and token identities;
- 0.001 WETH maximum per-entry and cumulative entry capital;
- one global/network/instrument position and one in-flight entry;
- 100 bps maximum price impact and 50 bps maximum slippage;
- at most a 900-second authority grant;
- zero profit recycling and 100% banking during the first dust phase.

An Ink issuance policy must bind exactly one taker address. This repository
does not choose that address and this change issues no grant. The ordinary
authority receipt separately binds the exact QntySpot repository commit and
implementation digest; those identities are intentionally not duplicated in
the risk object, avoiding a circular cross-repository digest dependency.

The QntySpot V0F runtime must independently consume canonical risk-policy bytes
under an externally pinned expected digest and enforce the same limits before
any live-capital transition.


## Ink V0F first-grant preparation

The first Ink dust-live grant is now prepared against one exact public taker
and one exact reviewed QntySpot runtime identity. This preparation is not a
signed grant and gives no authority by itself.

Canonical taker:

`0x3e604be3293d930069d0805e85379e0ca5fa01cb`

QntySpot canonical merge:

`428f373e61f76966cbbf1ebe1d565f50faa27e5c`

QntySpot implementation digest:

`9feaf53cddb6d6fa5dbdd7f9d25d8dbe57d00be008813e444cef7208d180f6b8`

Preparation artifact:

`artifacts/INK_V0F_GRANT_PREPARATION_V0.json`

Preparation digest:

`8ddfcf13fcbdf2f0111ac24a52cd554a2f67cf4b7db3ad760992f3729ca6c726`

For Ink V0F, the issuer now rejects a different taker, QntySpot commit,
implementation digest, venue, network, authority level, or capital envelope
before a receipt can be signed. The grant window remains dynamic but cannot
exceed 900 seconds.

No signer material or signed production receipt is included in this
preparation.


## Ink V0F short-lived grant issuance

`qnty_authority_root.ink_v0f_grant` provides the one-shot issuance path for
the already frozen first-grant tuple.

The caller must supply:

- a durable issuance database path;
- an injected Ed25519 signer implementation;
- authority epoch and minimum authority epoch;
- trust-config version;
- explicit issuance epoch seconds;
- grant duration, at most 900 seconds.

The helper reads no clock and no environment. It derives the exact issuer
policy, exact request scope, and deterministic request id from explicit inputs,
then delegates to the existing append-only `AuthorityIssuer`.

The returned bundle contains only the signed receipt bytes plus public trust
material required by QntySpot verification. Production signing material is
neither stored nor discovered by this repository.

The zero-money qualification is documented in
`docs/INK_V0F_ZERO_MONEY_GRANT_QUALIFICATION_V0.md`.
