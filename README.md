# verdock-core

verdock-core lets an app decide from a written policy what an AI agent may do with money, hold approvals and amount caps that many agents share, and check afterwards that each action really happened. It also writes and verifies signed, hash chained receipts in the format of draft-sahu-agent-action-receipts-00, in Python and in the browser.

Python standard library only. No third party JavaScript. MIT licensed.

## Use as a git submodule

```
git submodule add <url of this repository> vendor/verdock-core
```

Then put `vendor/verdock-core` on the Python path (for example `sys.path.insert(0, "vendor/verdock-core")` or `PYTHONPATH`) and import `verdock_core`. Nothing needs to be installed. Python 3.12 or newer.

The browser verifier is a single ES module, `js/verify.js`, that you can serve as a static file.

## Usage

```python
from verdock_core.policy import load_policy, decide, policy_hash
from verdock_core.approvals import ApprovalStore
from verdock_core.invariants import Invariants
from verdock_core.outcome import compare, may_retry, VERIFIED
from verdock_core.receipts import ReceiptLog, create_seed, verify_log

policy = load_policy("policy.yaml")
decision = decide(policy, "refund", 2500, currency="USD")
if not decision.allowed:
    raise SystemExit(decision.reason)

approvals = ApprovalStore("approvals.sqlite3")
if decision.needs_approval:
    approval_id = approvals.request("refund", "refund order 42", "order-42", 2500, "USD",
                                    decision.limit_minor, "refund-agent", ttl_seconds=900)
    # ... a person calls approvals.approve(approval_id, "sri") ...
    approvals.require(approval_id, "refund", "order-42", 2500, "USD")
    approvals.consume(approval_id)

inv = Invariants("invariants.sqlite3")
reservation = inv.reserve("capture-7", cap_minor=10000, amount_minor=2500,
                          customer_id="cust-9", day="2026-10-31",
                          per_customer_day_cap_minor=policy["caps"]["per_customer_per_day_minor"])
request_id = inv.request_id("refund:order-42")  # same id on every retry
# ... call the provider with request_id, then read its record back ...
observed = {"id": "r-1", "amount_minor": 2500, "currency": "USD"}
state = compare({"id": "r-1", "amount_minor": 2500, "currency": "USD"}, observed,
                ["id", "amount_minor", "currency"])
if state == VERIFIED:
    inv.commit(reservation)
elif not may_retry(state, policy["operations"]["refund"]["retry"]):
    pass  # UNKNOWN or PENDING: reconcile later, never send the action again

log = ReceiptLog("receipts.ndjson", create_seed("agent.seed"))
log.append("step-1", "refund.create", {"order": "order-42", "amount_minor": 2500},
           state == VERIFIED, actor={"agent": "refund-agent", "user": "sri"},
           extra={"policy_hash": policy_hash(policy)})
print(verify_log("receipts.ndjson", log.public_key))
```

Policy file (`policy.yaml`):

```yaml
version: 1
operations:
  refund:
    level: Execute within Limits
    max_amount_minor: 5000
    approval_above_minor: 2000
    currency: USD
    retry: safe
  reply:
    level: Draft
caps:
  per_customer_per_day_minor: 10000
```

The YAML subset and the policy hash are described in `verdock_core/policy.py`.

Verify a log from the command line (no network):

```
python -m verdock_core verify receipts.ndjson --public-key <64 hex characters>
```

Exit status 0 means every line passed, 1 means at least one line failed, 2 means a usage or file error.

In the browser:

```js
import { verifyLog } from './verify.js';
const report = await verifyLog(text, trustedPublicKeyHex);
// { ok, count, failures: [{ line, reason }] }
```

The browser needs WebCrypto Ed25519 support.

## Egress gateway and held queue

For apps whose agents run on a network isolated container network (Docker `internal: true`). The gateway is the only process on both networks.

* `verdock_core.egress.EgressGateway`: an HTTP CONNECT proxy. It opens a tunnel only to host names in the policy's `egress.allow_hosts`, only on port 443, and signs a receipt for every request: `verdock.egress.allowed` (host, bytes each way), `verdock.egress.blocked`, `verdock.egress.offline`. TLS stays end to end, so the gateway sees host names and byte counts, not bodies or credentials.
* A refusal (403 blocked, 502 upstream unreachable) is answered before any byte reaches the provider, so the app knows the action did not happen.
* `verdock_core.queue.HeldQueue`: actions that could not leave are held as "held, offline" with their stable request id. The app reads the provider's record first, then resumes each one with the same request id.

```
python -m verdock_core egress --policy policy.yaml --listen 0.0.0.0:8080 --receipts egress.ndjson --seed egress.seed
```

```yaml
egress:
  allow_hosts:
    - api-m.sandbox.paypal.com
```

A policy without `egress` lets nothing out. Adding `egress` changes the policy hash; policies without it hash as before.

## Tests

```
python -m unittest discover -s tests
node --test js/verify.test.mjs
```

The receipt tests reproduce the draft's Appendix A vectors byte for byte.

## Limits

* No key management service. The signing seed is a local file; keeping it private, rotating it and publishing the trusted public key are up to the app.
* Removing the newest lines of a receipt log cannot be detected from the log itself (draft section 9). Keep the latest line hash and count somewhere the agent cannot rewrite if you need that.
* Anyone holding the seed can sign a new history. Receipts show tampering by others, not by the key holder.
* `ts_ms` is the writer's clock, not a trusted timestamp.
* Numbers in receipts must be integers within plus or minus 2^53 minus 1. Amounts are integers in minor units with a currency string.
* The Ed25519 code is not constant time. Use it on hosts you control.
* ReceiptLog expects one writer per file.
* The egress gateway checks host names, not IP addresses, and trusts the container network to make it the only way out. It does not inspect TLS.
* SQLite stores are safe across threads and processes on one machine. They are not a distributed database.
