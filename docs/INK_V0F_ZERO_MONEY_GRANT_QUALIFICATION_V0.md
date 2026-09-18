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
escape QntySpot's current source phase ceiling. Effective authority remains
below `HUMAN_SIGNED_EXECUTION`, and construction, approval, signature, and
live-capital authority remain unavailable.

No production receipt or production signer material is created by this phase.
