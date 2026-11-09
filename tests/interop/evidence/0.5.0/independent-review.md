# Independent review — 0.5.0

Three context-isolated OpenCode Task reviewers examined the baseline diff,
surrounding implementation/tests and final repository-contained claims. Each
returned an exact source/claims/artifact-bound passing verdict after fixes.
Their distinct native session IDs and verbatim final JSON are retained in the
three `review-*.json` records and authenticated by `review-identity.json`.

Initial findings were individually triaged. Corrected: cached-state retention,
interim-response acquisition accounting, TCP shutdown acceptance counting,
qualification initial/direct/reset/range checks, exact measurement/investigation
binding, and mismatched benchmark inputs. Added deterministic full HTTP/TCP
response-loss tests, positive capacity-reserve assertions, disabled assembly
failure/replay parity, and partial-registration fault coverage/documentation.

The assembly performance claim remains explicitly limited to the exercised
direct HTTP and synthetic Consumer workloads. Same-state-directory automatic
pipeline reload remains a pre-existing ACK-lock lifecycle limitation: an installed
probe demonstrated replacement construction before the original lock is released.
It is deferred separately; process restart/recovery is qualified here.

Final lenses:

- Adversarial correctness and durability — pass, no unresolved high/medium findings.
- Edge cases and migration integrity — pass, no unresolved high/medium findings.
- Verification gaps and performance claims — pass, no unresolved high/medium findings.

Artifact: `bf2e1c9126e18650bad8232120ac92f5db2e5996f8214fad6f2329029654fa63`.
Claims: `docs/ingestion-metrics-0.5.0.md`.

Fresh sender capture binaries referenced by this run's sender traffic report are
retained in `sender-captures/`; historical golden fixtures remain unchanged.
