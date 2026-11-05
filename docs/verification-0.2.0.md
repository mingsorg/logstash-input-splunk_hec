# 0.2.0 development verification

This is an unreleased development artifact. `VERSION` selects the exact gem;
qualification scripts fail if it is absent, rather than choosing a different gem.
New evidence is isolated under `tests/interop/evidence/0.2.0/`. The existing lab
remains on its captured 0.1.0 configuration and is not an upgrade target.

Required gates: Gradle framing/state/listener regressions; Python build-harness
checks; startup examples/negative policies; two clean byte-identical gems after
packaged docs are final; exact-digest install/upgrade and real UF/HF HTTP/TCP
qualification on pinned Logstash 9.5.0/9.5.5 with memory/PQ, provenance/selected
metadata modes and failure injection. A missing or failed gate is incomplete,
never qualification inferred from historical evidence.

The assembly snapshot is a bounded correctness-first implementation. Each commit
rewrites the snapshot; measure sustained disk throughput for the intended workload.
At-least-once handoff can duplicate events. Positionless traffic has deliberately
limited assembly/retry scope. Policy migration and oversized blocked-stream
reconciliation require explicit operator handling as described in configuration.md.

Review corrections add pre-ACK finalization-capacity checks, byte-budgeted receipt
retention, and per-sender direct/outbox dispatch gates. The unreleased snapshot
format fingerprint is now `assembly-v2`; older development snapshots fail startup
instead of being silently loaded without sender ordering identity. Preserve such
state for explicit operator reconciliation.

The qualification gate reruns Java tests and builds a fresh jar, then compares the
selected gem's jar and every packaged file to those fresh inputs. It does not rebuild
or replace the gem to make a mismatch pass. Queue-cancellation reports identify the
selected artifact and probe digest, while remaining core Logstash API prerequisites.
Native sender assertions check exact terminal/blank-line behavior. Indexer checks
explicitly project selected metadata in the qualification output and verify indexed
fields/multivalues and source `_time` within the millisecond precision of Splunk search export. The TLS capture fixture
has a finite per-client handshake outside its listener accept loop.

Completion-review corrections: recovery now repeats the pre-ACK finalization-capacity
and stream-bound checks under the configured limits and fails startup closed rather
than accepting a snapshot whose tails cannot complete; recovery reads snapshots under
the store's own byte bound instead of Jackson's default 20M-character string limit; a
record the standard path ignores (for example a delimiter-only record with a
disallowed index) stays ignored when an unrelated rule is enabled. Strict same-sender
ordering applies while the input runs; after a stop or failed insertion between a
batch's journal commit and its direct-record handoff, delivery is at-least-once and
order is not guaranteed (see configuration.md). Qualification reports now also bind the
digest of their producing validators/fixtures, so an edited assertion invalidates them.

Measured assembly cost (development host, macOS/APFS, JDK 23, one sender, one
line per acknowledged request, `hec_metadata=full`, so every line is its own durable
commit): 500 lines/event 15.8 s total, 1,000 lines 18.0 s, 2,000 lines 48.8 s,
4,000 lines 203 s, 8,000 lines 605 s. That is about 18 ms per acknowledged request
for small retained state, rising roughly linearly with the retained event size, so
total work per event is quadratic in its line count: each commit rewrites and
fsyncs the whole bounded snapshot. All senders share that single commit under one
monitor, so a large slow stream also delays other senders' matched-mode requests.
Typical events (tens to a few hundred lines) are dominated by the fsync cost. Size
`s2s_assembly_max_bytes`, `max_event_bytes` and the sender's batching for the
intended workload and re-measure on the target filesystem; Linux/ext4/XFS fsync costs
differ. Batching many lines per request, which UF and HF normally do, amortizes the
commit. An append-only journal would remove the quadratic term but is not part of 0.2.0.

Operator diagnostics: every HTTP request rejected with a non-authentication 4xx/5xx
now logs one value-free WARN line, at most once per 10 s with a count of suppressed
similar rejections: route, status, HEC code, the fixed message and the rejecting source
line (for example `HEC request rejected: route=s2s status=400 HEC code 6 "Invalid data
format" at S2SDecoder:123`). Payloads, tokens and headers are never logged and 401/403
are not logged. This exists because a forwarder that retries a rejected batch forever
(observed in the demo lab on the 0.1.0 plugin) was otherwise undiagnosable.

