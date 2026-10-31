# Third party specifications

verdock-core has no third party code and no dependencies. All code in this repository was written for it; no code was copied from any other project. Two public specifications define what parts of it do.

## draft-sahu-agent-action-receipts-00

The receipt format, canonical signed bytes, hash chain and verification procedure in `verdock_core/receipts.py` and `js/verify.js` follow the IETF Internet Draft "Agent Action Receipts" (draft-sahu-agent-action-receipts-00). The test vectors in `tests/vectors.py` and `js/verify.test.mjs` are the draft's Appendix A vectors, used to check that the output matches the draft byte for byte.

Choices this package makes where the draft leaves room:

* Any non integer number token, and any integer outside plus or minus 2^53 minus 1, anywhere in a line is a failure, so the Python and browser verifiers always agree.
* `actor` may hold `agent`, `user` or both; any other member inside `actor` is a failure.
* An empty line is a failure. A single trailing newline at the end of the log is not a line.
* Failure reasons are short fixed strings, such as `signature invalid` and `chain break`.

## RFC 8032

`verdock_core/ed25519.py` implements Ed25519 from the description in RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)", section 5.1. The tests include RFC 8032 section 7.1 test 1. The browser verifier uses the platform's WebCrypto Ed25519.
