# QntyAuthorityRoot

An independent, offline V0 issuer for QntySpot authority receipts.

This repository has one narrow responsibility: validate an explicitly supplied
QntySpot authority-policy request, sign the canonical authority receipt body
with an injected Ed25519 signer, and durably commit the resulting receipt in
an append-only SQLite ledger before returning its bytes.

The V0 boundary is mechanical:

- only `evm:46630` is admissible;
- `evm:4663` and wildcard/alias scopes are rejected;
- the maximum issuable level is `HUMAN_SIGNED_EXECUTION`;
- grant duration is at most 3600 seconds;
- no service, RPC, HTTP, wallet, transaction, or capital-execution path exists;
- no production root provisioning or ambient secret discovery exists.

The signer is an injected interface. Production root material is intentionally
not created, read, or provisioned here. Tests use ephemeral deterministic
test-only material held in memory.

The receipt contract is frozen against QntySpot commit
`982a0b38d9226523679c8e59c6abc22ccb5242fd`.
