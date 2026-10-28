# Compatibility and evidence

See [current validation status](validation-status.md) for final-artifact results.
Evidence files name the SHA-256 of the gem they exercised; a file that names a
different digest is historical, not qualification of the current artifact.

## Pinned test environments

| Component | Pinned baseline | Platform exercised |
|---|---|---|
| Minimum Logstash | 9.5.0 / bundled Java 21.0.11 | linux/arm64 |
| Latest verified Logstash GA | 9.5.5 / bundled Java 21.0.12.1 | linux/arm64 |
| Splunk Enterprise oracle/HF | 10.6.1.1, build b2ae2962645c | linux/amd64, emulated on Apple Silicon |
| Universal Forwarder | 10.6.1.1, build b2ae2962645c | linux/amd64, emulated on Apple Silicon |
| Java plugin API | 2.1.16 | Extracted from the pinned distribution, not the old parent jars |

All image digests and registry platform observations are in
[`versions.properties`](../versions.properties) and
[`images.json`](../tests/interop/evidence/images.json). The reusable API does not
enforce the runtime floor: the Ruby entry point independently rejects reported
Logstash versions below 9.5.0. The negative guard test injects a 9.4.99 runtime
identity into each current distribution; it is not an installation test on an old
Logstash distribution. No pre-9.5 compatibility is offered.

## Wire observations

[`oracle-http.json`](../tests/interop/evidence/oracle-http.json) records real
server responses, relevant headers, exact request bytes, accepted counts and
indexed source values. It is captured independently from the plugin using
[`oracle/`](../tests/interop/oracle/) configuration. The JUnit HTTP corpus test
replays the non-stateful cases and compares response JSON, status and applicable
accepted counts; stateful ACK consumption has a separate test. IDs are compared
for type/semantics rather than requiring the same allocator sequence.

Observed paths are **exact**:

| Route | Method / aliases |
|---|---|
| `/services/collector` | POST, event envelopes; no `/1.0` alias |
| `/services/collector/event` | POST; `/event/1.0` also works |
| `/services/collector/raw` | POST; `/raw/1.0` also works |
| `/services/collector/s2s` | POST; `/s2s/1.0` also works |
| `/services/collector/ack` | POST; `/ack/1.0` also works |
| `/services/collector/health` | GET; `/health/1.0` also works |

Trailing slashes and unknown paths returned 404. Tested wrong methods returned
405 with the oracle's JSON code 404. No speculative aliases such as
`/services/collector/1.0` are installed.

The oracle accepted event strings, numbers, objects and arrays, including empty
objects/arrays; it rejected boolean/null event values with code 6, blank strings
with code 13, and missing events with code 12. Nested indexed-field objects were
rejected with code 15; scalar indexed multivalues were accepted. Duplicate JSON
keys used the last value. Concatenated and array batches retained valid prefixes
on malformed member N, with zero-based `invalid-event-number`; incorrect-index
errors used the measured one-based event number. These observations are tested,
not inferred from prose documentation.

Basic token-password and Splunk-header authentication were accepted. Per-token
query auth was enforced; query-token auth took precedence over a conflicting
header. For ACK channels, a nonempty header took precedence, but an empty header
fell back to the query. Missing/invalid GUIDs were rejected when ACK was enabled;
raw requests without ACK did not require a channel. Duplicate IDs in one poll
collapsed to one true, followed by false on the next poll. Strings, fractional
IDs, null and empty ACK lists were rejected.

## Intentional differences and supported representation

1. **Queue-boundary ACK:** true is queue acceptance, not Splunk replication or
   downstream completion. It is not a disk-durability claim. Memory queues can
   lose accepted events. PQ durability depends on checkpoints/storage. The
   restart test holds output, kills Logstash, recovers the unacked PQ event,
   observes false for the old ACK, and observes a new ID in a non-overlapping
   reserved range. The TLS certificate is reused across the same restart.
2. **Transport raw framing:** LF/CRLF only, request-local, no empty manufactured
   records, whitespace-only records retained, final unterminated tail emitted.
   The oracle is configured with known newline sourcetypes for comparisons.
   There is no props.conf parsing engine, timestamp extraction from raw text or
   inferred indentation merging. Wire acceptance and parsed/indexed
   representations are separate observations.
3. **Strict S2S rejection:** unsupported/corrupt/compression/reference/encoding
   errors reject the whole batch with 400/code 6, zero source events and no ACK.
   There is no diagnostic replacement or salvage. Real UF retrying the same body
   after two injected invalid-opcode rejections is recorded. Rejected batches
   must be diagnosed; retries alone cannot fix unsupported wire data.
4. **Resource limits:** plugin defaults are configurable and are not Splunk
   defaults. A captured 1,241,048-byte configuration-change log line exceeds the
   default logical event cap; the sender retried it after 503/code 9. Increase an
   appropriate limit or change that source before expecting progress. No event
   is truncated. A queue error can leave accepted data even when `accept` did
   not return; failed requests have no success ACK and retries can duplicate.
5. **Lossless runtime storage:** signed-64 integers and exactly representable
   finite doubles use compact representations; larger integers and other decimals
   retain BigInteger/BigDecimal values through Event/PQ serialization, subject to
   documented numeric length/scale limits. A source time
   string preserves nanosecond precision through actual Event/PQ serialization.
   Native S2S epoch time uses a decimal string, preserving the decoded fraction.
   In the real JSON sender fixtures, the wire fraction was six digits even
   though a payload field retained its original nine-digit time string.
6. **Runtime internals and source envelope:** required Logstash internals are
   retained. Source HEC envelopes cannot overwrite `@timestamp`, `@version` or
   `@metadata`; those names remain ordinary literal payload/indexed-field keys
   inside their own containers. This is validation, not field extraction.

## Matrix coverage and replay authority

| Matrix | Executed coverage |
|---|---|
| M1 Event | Oracle HTTP corpus; native maps/lists/booleans/nulls inside payloads; valid prefixes, duplicate keys, strict encoding/depth/precision; packaged Event/PQ round trips |
| M2 Raw | LF/CRLF/tail/whitespace/request boundaries; gzip over chunked HTTP; ACK on/off channel fixtures; strict UTF-8 |
| M3 S2S | Attributed binary goldens for structured multiline, metrics, multivalues, CSV header and conflicting names; captured actual bodies; whole-batch rejection, invalid references, amplification bounds, control-only probes; real UF/HF source records and retries |
| M4 Auth | Oracle credentials/query conflicts/index errors; full file reload/revocation, last-good retention, rename/rotation/ACK-disable and admitted-request snapshots |
| M5 Capacity | Positive-limit validation/accounting; HTTP overload/health/read shutdown; actual memory/PQ writer interruption in both distributions; no worker activity after joining/release |
| M6 ACK | Pending/consume/duplicates/concurrent poll/token/channel isolation; small-cap exhaustion and pinned monotonic cleanup; high-water restart; actual PQ crash with outstanding polling |
| M7 TLS | Generated identity/reuse, DNS/IP SANs, wrong trust/hostname rejection; PEM/PKCS12/JKS; mTLS positive/negative; packaged HTTPS on both runtimes; direct UF/HF verified HTTPS |
| M8 TCP | Optional cooked `tcpout` listener: real captured UF/HF stream replay (plain and verified TLS, compressed and plain), ACK-after-queue/no-ACK-on-failure, truncation, shared back-pressure and shutdown; live UF/HF 10.6.1.1 matrix and receiver SIGKILL/resume (`tcp-senders.json`) |

[`queue-cancellation.json`](../tests/interop/evidence/queue-cancellation.json)
uses the actual Java `QueueWriter` implementations passed to Java inputs. Full
memory queues threw on interruption. Full PQ writes also terminated on
interruption, but the first write could already have stored an event. This
distinction is why the input uses owned workers and joins them rather than
reporting a timeout while a detached producer remains active.

[`pq-recovery.json`](../tests/interop/evidence/pq-recovery.json) halts the process
without closing the queue, then opens it in a new process. It verifies signed-64
and larger integers, exact decimals/doubles, literal dotted keys, source time, nanosecond internal time
and metadata IDs in both distributions, with checkpoints of 1.

[`runtime.json`](../tests/interop/evidence/runtime.json) records packaged-gem
installation, trusted HTTPS, black-box HTTP checks, memory/PQ output and the
latest-runtime outstanding-ACK crash/recovery case.

[`senders.json`](../tests/interop/evidence/senders.json) records actual UF/HF
versions, received bytes and responses, initial native source values, explicit
invalid-batch retries, identical-body reconnect/replay, and direct HTTPS using
sender certificate **and** hostname verification. The public test tokens are
dedicated fixture credentials. Binary bodies are retained in
[`fixtures/senders/`](../tests/interop/fixtures/senders/). Native repeats are
preserved; replay IDs remain stable rather than the input deduplicating them.

## Evidence boundaries and remaining qualification

- This is a finite corpus, not full Splunk equivalence or a throughput/heap
  benchmark. Sustained slow-client/load testing at every maximum setting is not
  established by the small-cap concurrency tests. Memory accounting is an
  allocation gate, not a precise JVM heap measurement.
- Typed metric and CSV wire goldens are synthetic, derived from the pinned
  reference. Live UF/HF text and indexed JSON are exercised; there is no blanket
  claim covering every real metric source/CSV producer or future wire tag.
- Rebatch/reconnect IDs are stable when source identity, stream/sequence and
  absolute logical byte positions remain stable. Changed sender coordinates are
  not promised to deduplicate. Missing coordinates restrict IDs to identical
  batch retries.
- `inputs.conf` writers must publish complete files atomically. A syntactically
  valid file prefix is indistinguishable from an intentionally smaller valid
  policy without a publisher-side transaction. Empty/malformed/truncated files
  are retained as last-good failures; directory/app layering is unsupported.
- Linux arm64 runtimes and emulated amd64 senders were exercised here. There is
  no separate native-amd64 performance qualification. The pre-9.5 guard was
  tested by runtime-identity injection, not by installing on a pre-9.5 image.
- TCP is qualified only for latest UF/HF 10.6.1.1 cooked `tcpout` as recorded in
  [`tcp-senders.json`](../tests/interop/evidence/tcp-senders.json) and described in
  [`s2s-tcp.md`](s2s-tcp.md). Uncooked streams, legacy protocol levels,
  heartbeats/token/certificate controls, indexer discovery and cluster
  features are not supported, and older forwarder versions were not tested. The
  classic protocol has no HEC token; TLS/mTLS is the trust boundary, and the
  sender GUID is self-declared. Live TCP sender runs used the persistent queue
  with the 9.5.5 runtime; the minimum 9.5.0 runtime received a reduced TLS set.
  TCP behavior under sustained load or with senders blocked for long periods is
  not measured beyond the small-cap Java back-pressure test.

## Verification execution notes

The HTTP stages were run separately as well as through the combined driver.
`runtime.json` contains successful final-gem installs on both runtime versions
and both queue types. `senders.json` contains the successful real UF/HF comparison
and direct verified-HTTPS stage (18 relay requests, 36 source events including
replay/direct traffic). JUnit replays the saved real bodies and oracle corpus.
Startup/time-budget failures from earlier attempts are not evidence of protocol
compatibility; the successful stage records establish the finite tested scope.
The sender fixture now uses the official image entrypoint, isolated bridge
namespaces, and readiness rather than assuming first-start completion from the
first data request. Local-gem installation uses `--local` to avoid unrelated
network dependency resolution during runtime tests.

## Implementation-review regressions

The regression suite additionally covers a body-withholding `100-continue`
client, a non-reading response peer, canceled-timer removal, reserved health
capacity during aggregate-memory saturation, interrupted input shutdown with ACK
lock reacquisition, and unexpected listener failure propagation. A failed queue
write after a valid prefix cannot return or complete a success ACK. Token
revocation while waiting for admission is separate from admitted-request policy
snapshots. Malformed ACK corpus cases are executed rather than skipped.

Native decoder cases include zero-output gzip members, controls at the data-record
limit, full consumption of escaped references, native future-seconds fractions,
provenance-inclusive event size, field-container copy amplification, and canonical
indexed-content identity. Comments-only policies and comma-only index allowlists
cannot replace a valid policy with a different authorization scope.

`python3 -m unittest discover -s tests/build -v` checks API-cache invalidation and
last-good extraction, Gradle pin dispatch, native-Linux/Desktop network selection,
ID/label-scoped fixture cleanup and negative/stalled relay reads without launching
Docker resources. Native Linux network selection is unit-verified; the real sender
results above remain Docker Desktop observations.
