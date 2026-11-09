# Live ingestion and assembly metrics (0.5.0)

Each input exposes a bounded `hec` namespace through Logstash's existing Node
Stats API. Set an explicit input `id` to find it reliably:

```logstash
input { splunk_hec { id => "hec-primary" } }
```

Read `GET /_node/stats/pipelines/main` on the configured Logstash monitoring
address, then select `pipelines.main.plugins.inputs[]` by `id == "hec-primary"`
and read its `hec` object. The plugin adds no listener or endpoint. The standard
`enable_metric => false` option registers no custom metrics and preserves
ingestion and operational resource accounting. Assembly stays opt-in.

## Schema and units

All leaves below are signed 64-bit integer scalars, including zeros; dots denote
nested JSON objects. The fixed schema is the same for every metrics-enabled
input. Disabled transports/assembly keep their inapplicable values at zero.
The custom Logstash adapter uses `gauge/number` to expose these integer values;
the semantics below distinguish cumulative counters from state gauges.

| Path under `hec` | Meaning |
|---|---|
| `http.<route>.<outcome>` | Completed HTTP processing outcomes, one per handled request |
| `http.connection_rejected` | Sockets refused because the shared connection limit is full |
| `http.response_failures` | Failed response-write attempts, including `100 Continue`; a request may have more than one failed write attempt |
| `tcp.connection_accepted`, `tcp.connection_rejected` | Accepted connection permits, or connections refused at the shared limit |
| `tcp.connection_closed`, `tcp.connection_failures` | Handled connections that ended, and those ending through an exception; failures include disconnect/reset/timeout/shutdown exceptions |
| `tcp.data.success`, `tcp.data.failure` | Data record processing outcomes; a malformed `FC` record counts as data failure |
| `tcp.control.success`, `tcp.control.failure` | Compact metadata/control record outcomes, separate from data; handshake failures are connection failures |
| `tcp.response_failures` | Failed hello or ACK writes |
| `handoff.<kind>.returned` | Individual synchronous queue consumer calls that returned normally |
| `handoff.<kind>.attempts`, `.count`, `.failures`, `.total_nanos` | Calls started, calls finished (including failures), failed calls, and total elapsed nanoseconds for finished calls |
| `handoff.active` | Consumer calls currently executing, including blocked calls |
| `assembly.contributions` | Newly committed selected logical lines, including orphan/blank logical lines, excluding suppressed retries and recovered contributions |
| `assembly.flush.<reason>` | Real committed stream finalizations by reason; excludes sizing probes and rolled-back staging |
| `assembly.enabled`, `assembly.blocked` | State flags: 0 or 1; blocked means accepted state is retained and needs operator attention |
| `assembly.pending`, `assembly.outbox`, `assembly.receipts` | Retained pending streams, output envelopes (including orphan lines), and retry receipts |
| `assembly.live_bytes`, `assembly.reserved_bytes`, `assembly.quota_bytes` | Last measured serialized live state, reserved finalization growth, and configured quota in bytes |
| `assembly.utilization_basis_points` | Integer floor of `(live_bytes + reserved_bytes) * 10000 / quota_bytes`; 10000 means 100% |
| `assembly.physical_bytes_last_observed` | Bytes observed during an existing storage inventory; may lag current disk usage |
| `assembly.journal_bytes_last_observed` | Last observed authoritative journal size; publication resets it to zero |
| `store.<operation>.attempts`, `.count`, `.failures`, `.total_nanos` | Storage operations started, finished (including failures), failed, and total elapsed nanoseconds for finished operations |
| `last_durable_acceptance_epoch_millis` | Time of the latest successful commit of new selected contributions |
| `last_handoff_epoch_millis` | Time of the latest normally returning consumer call |
| `last_commit_epoch_millis` | Time of the latest normally returning state commit, including outbox removal |

The dimensions have exactly these values:

- **route:** `event`, `raw`, `s2s`, `ack`, `health`, `unknown`. Aliases share their
  canonical route; arbitrary paths use `unknown`.
- **outcome:** `success`, `unauthorized` (401), `forbidden` (403), `invalid`
  (other non-5xx rejections), `busy` (503/admission interruption), `internal`
  (unexpected processing exceptions or other 5xx). Unexpected exceptions can
  still return the existing 503 response while counting as `internal`.
- **kind:** `http_event`, `http_raw`, `http_s2s`, `tcp`, `assembly_direct`, `outbox`.
  When assembly is enabled, unmatched/structured direct output is counted under
  `assembly_direct`; selected output goes through `outbox`, without double counting.
- **reason:** `timeout`, `metadata_conflict`, `structured_transition`,
  `coordinate_gap_or_reordering`, `reordering`, `new_start`.
- **operation:** `capacity` (finalization-capacity comparison), `commit`,
  `publication` (initial publication or later compaction), `compaction` (later
  generations only, also included in publication), `fsync` (file/directory forces).
  Nested operations overlap; their durations must not be added together.

Counters reset for each input instance, start at zero, and saturate at
`Long.MAX_VALUE` instead of wrapping. Timestamps start at `-1`, use epoch
milliseconds, and never decrease within an instance. Timings use the monotonic
clock. Counters and timestamps are not restored from disk. Recovery restores
state gauges and may perform measured storage work and output handoffs; it does
not invent new accepted contributions or flush counts.

## Counting boundaries

HTTP success is recorded after successful processing and before writing the
reply; a reply failure does not undo it. Health and ACK polling have their own
outcomes and add no ingestion contributions. A partially failed direct batch can
have returned handoffs and a failed request outcome. A TCP record is successful
before its ACK write, so an ACK failure is separate from data acceptance.

Selected contribution/flush counters change only after their state commit returns
successfully, even when a later ordering barrier fails. A failed commit can leave
durable bytes: failure counters do not prove that nothing was persisted. A queue
handoff counts each normally returning call, even if outbox removal fails and the
same output is handed off again after recovery. These metrics do not establish
indexing success, unique documents, PQ fsync, or exactly-once delivery.

Getters read cached atomic scalars without disk scans, serialization, queue locks
or the assembly monitor. A scrape is not a transactional snapshot across leaves;
concurrent updates can show an operation between its attempt and completion.
Missing/failing collectors produce a bounded value-free diagnostic and do not
control ingestion. If the collector fails partway through registration, its
namespace can be partial; the complete fixed schema applies to healthy collectors.
Treat missing leaves as unavailable rather than zero. No token, sender ID, source path, channel, payload or arbitrary
error text becomes a metric dimension. Metrics are not persisted and introduce
no rule reload, repair, or inspection-format change.

## Verification and qualification

Build the gem, then run the installed Node Stats check:

```sh
./gradlew test gem --offline --max-workers=1
python3 tests/interop/run.py --stage metrics
```

The installed check exercises pinned Logstash 9.5.0 and 9.5.5, exact schema and
integer types, initial values, HTTP partial failure/auth/control, TCP data/control,
retry suppression, blocked-queue scrapes with a two-second deadline, and
reset/replay. Java tests also inject append/fsync/post-force/queue failures,
rollback and later-barrier interruption, validate all flush reasons, collector
fault isolation, compaction, concurrency and saturation.

`metrics.json` retains three randomized paired rounds of 60 raw HTTP batches per
mode, 32 events each, with raw samples, median and nearest-rank p99. Measurements
include HTTP, queue backpressure, pipeline output and host scheduling. Median
regressions above 5% require a retained investigation; neither small samples nor
negative overhead establish universal performance equivalence. Results and the
investigation are bound to the exact gem and validator digest.

The final command is `python3 tests/interop/check_metrics_qualification.py`.
It requires the complete prior assembly/inspection/runtime matrix, fresh Java and
Python tests, Linux inspector tests, two byte-identical builds, installed metrics,
an overhead investigation, and three independent source/claims/artifact-bound
review lenses. Evidence lives in `tests/interop/evidence/0.5.0/`; require matching
digests, all checks passing and `release_ready: true` before relying on it.
