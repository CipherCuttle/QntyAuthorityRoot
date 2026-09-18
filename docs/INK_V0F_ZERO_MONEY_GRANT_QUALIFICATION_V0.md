# Ink V0F short-lived grant path — zero-money qualification

This phase implements the one-shot issuance path for the already frozen first
Ink V0F grant tuple.

The issuer helper requires explicit:

- durable issuance database path;
- injected Ed25519 signer interface;
- authority epoch and minimum epoch;
- trust-config version;
- issuance epoch seconds;
- grant duration, at most 900 seconds.

It reads no clock or environment and discovers no signing material.

The cross-repository qualification uses an ephemeral deterministic test signer
only. It issues a serialized `HUMAN_SIGNED_EXECUTION` receipt, loads the
resulting public trust configuration in the canonical QntySpot verifier, binds
the receipt to the exact QntySpot commit/implementation/taker/network/venue,
and verifies the signature.

The qualification now targets QntySpot's merged
`HUMAN_SIGNED_EXECUTION` source ceiling. For the exact bound
commit/digest/network/taker/venue tuple, the verified receipt reaches effective
Level 3 and makes the already-reviewed envelope, exact approval, and exact
externally signed-byte submission capabilities eligible. `PRODUCE_SIGNATURE`
remains unavailable because it is Level 4 only.

This qualification does not broadcast a transaction or move capital. The exact
`ink-v0f` adapter-version fence is enforced by QntySpot's phase-scope gate;
the V0 authority receipt schema itself binds repository commit, implementation
digest, network, taker, and venue.

No production receipt or production signer material is created by this phase.


## Trust and overlap properties

The issuance bundle's public anchor and trust-config digest are issuer outputs,
not self-authenticating trust. A production QntySpot consumer must compare them
against independently frozen public trust pins. The zero-money qualification
models that requirement with separately pinned deterministic test values rather
than accepting the bundle's own values as its trust decision.

The durable issuer also refuses a second Ink V0F receipt whose validity interval
overlaps an already committed Ink V0F receipt. The check runs inside the same
SQLite `BEGIN IMMEDIATE` critical section as serial allocation and receipt
commit, so concurrent issuers cannot race around the single-active-grant rule.


## Canonical QntySpot identity

This qualification is pinned to the canonical QntySpot Level-3 merge:

`79d66648b80173f71c2e5a3b307984d525edf479`

with implementation digest:

`ac408e3c0ccfdac8106b3c5aef44904e07504112aacc49a2097affdd3e025aea`

The original first-grant preparation artifact remains immutable historical
evidence, but its old QntySpot commit/digest tuple is intentionally stale and
inadmissible for new Ink V0F issuance.
