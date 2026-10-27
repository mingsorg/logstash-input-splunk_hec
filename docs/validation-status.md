# Current validation status

The HTTP implementation is packaged as `logstash-input-splunk_hec-0.1.0-java.gem`.
It is a preview with finite compatibility coverage, not complete Splunk equivalence.

## Passing on the reviewed implementation

- 45 Java tests, including saved real-Splunk HTTP corpus replay, captured UF/HF
  payloads, native value precision, S2S framing/identity, TLS/mTLS, queue-failure
  ACK behavior, `100-continue`, write deadlines and lifecycle regressions.
- Seven Python build/fixture regression tests.
- Packaged installation and trusted HTTPS on Logstash 9.5.0 and 9.5.5, with both
  memory and persistent queues. The final 9.5.5/PQ case passed on targeted rerun
  after an initial empty-log startup failure. `runtime.json` retains the four
  passing outcomes.
- Actual Event/PQ recovery of exact decimals, large integers, source time and
  internal timestamp precision; ACK reset and TLS identity reuse after a crash.
- Two clean builds of the reviewed source produced byte-identical gems; the
  reproducibility report records the resulting artifact hashes.

## Real sender evidence and the remaining blocker

An earlier implementation candidate passed live Splunk UF/HF 10.6.1.1 tests:
18 relay requests, 36 source events including replay/direct HTTPS, malformed-batch
retries, and certificate/hostname verification. The reviewed decoder continues to
pass replay of the captured real bodies and oracle response corpus.

That earlier `senders.json` is **not** a fresh live qualification of every final
review patch. The final live rerun could not complete provisioning of the test
senders. In the last attempt the oracle became available, but the UF had sent
zero requests by its 600-second deadline. Its retained console output showed
official Ansible provisioning still configuring certificates after more than
nine minutes. This is a startup-stage failure, not an observed plugin rejection.

The final live sender stage therefore remains **blocked**, not passed. Run it
with already-provisioned latest test senders or a sufficiently provisioned native
amd64 runner before treating that qualification as complete. The test tooling
and pinned images are included; production credentials are not required.

## TCP

Classic S2S TCP is not implemented or enabled. The bounded capture attempt did
not establish handshake/framing/ACK behavior. `tests/tcp/check.py` intentionally
returns blocked (exit 2). See `tcp-feasibility.md`.
