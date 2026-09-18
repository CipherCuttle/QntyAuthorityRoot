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

The qualification additionally proves the external Level-3 receipt cannot
escape QntySpot's binding `RECONCILE_ONLY` source phase ceiling. Effective
authority remains Level 1: exact-byte submission, construction, approval,
signature, and live-capital authority all remain unavailable.

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

This qualification is pinned to the post-repair canonical QntySpot merge:

`7b10a1a74607a9d2bf35438b89f02755b689d4ec`

with implementation digest:

`0df376585a874e773d65b5dda0010a3d2eca28c541da474c6ca1cc60b3e929ec`

The previous first-grant tuple is intentionally stale and inadmissible.
