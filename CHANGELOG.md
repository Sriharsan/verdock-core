# Changelog

## 0.1.0 (2026-10-31)

First release.

* `policy`: policy files in JSON or a strict YAML subset, validation, `policy_hash`, `decide`.
* `approvals`: SQLite approval store with exact match, expiry and single use.
* `invariants`: group caps with reservations, customer daily caps, locks with expiry, stable request ids, all inside `BEGIN IMMEDIATE` transactions.
* `outcome`: `VERIFIED`, `MISMATCH`, `UNKNOWN`, `PENDING`; `compare`, `may_retry`, `Reconciler`, `OutcomeLog`.
* `receipts`: draft-sahu-agent-action-receipts-00 receipts with pure Python Ed25519, `ReceiptLog`, `verify_log`.
* `python -m verdock_core verify` command.
* `js/verify.js`: browser verifier with the same checks and report shape.
