# Ink V0F Level-3 zero-money runtime rehearsal

This qualification exercises the real current authority and runtime gates without
broadcasting a transaction and without requiring access to the real wallet
private key.

## Exact bound identities

AuthorityRoot canonical merge:

`dfd91595896723a78fe892f80daabe68efa60e7b`

QntySpot canonical Level-3 merge:

`79d66648b80173f71c2e5a3b307984d525edf479`

QntySpot implementation digest:

`ac408e3c0ccfdac8106b3c5aef44904e07504112aacc49a2097affdd3e025aea`

Frozen taker:

`0x3e604be3293d930069d0805e85379e0ca5fa01cb`

## What the rehearsal does

The qualification:

1. issues a cryptographically valid 900-second Level-3 receipt using an
   ephemeral qualification-only AuthorityRoot signer;
2. verifies that receipt through canonical QntySpot;
3. persists the verified authority continuity record;
4. persists the exact Level-3 execution session;
5. creates and reserves one 0.001 WETH BUY intent;
6. proves Level-3 capabilities include reservation, envelope construction,
   exact approval authorization, and exact signed-byte submission;
7. proves `PRODUCE_SIGNATURE` remains absent;
8. constructs a valid exact EIP-1559 swap scope for the frozen router/taker;
9. deliberately signs those bytes with a synthetic non-owner EVM key;
10. proves QntySpot reaches cryptographic signer recovery and rejects the bytes
    because the recovered sender is not the frozen taker;
11. proves no signed-transaction row and no submission-attempt row is created.

## What it does not do

It does not:

- request or read the real wallet private key;
- produce a signature for the real taker;
- call `eth_sendRawTransaction`;
- instantiate a submission transport;
- broadcast an approval or swap;
- move capital;
- claim synthetic bytes are equivalent to the real wallet signature.

## Meaning

A PASS establishes that the current merged AuthorityRoot and QntySpot can reach
the real human-signing boundary under the exact 0.001 WETH Level-3 grant scope,
and that a non-owner signer cannot cross that boundary.

The next real-world action after PASS is an externally controlled wallet
signature over the exact reviewed transaction bytes. That separate action must
remain byte-for-byte validated before any broadcast is considered.
