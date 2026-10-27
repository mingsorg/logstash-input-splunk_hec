# Logstash Splunk HEC input

A Java input for **Logstash 9.5.0+ / Java 21** that receives HEC event, raw and S2S HTTP envelopes. Payloads stay native for later filters. The default listener is **HTTPS**. No tokens are accepted until configured.

Build and install locally:

```sh
./gradlew test gem
bin/logstash-plugin install --local /absolute/path/logstash-input-splunk_hec-0.1.0-java.gem
```

The build needs Python 3, a JDK capable of `--release 21`, Docker and network access for the first dependency download. Gradle is checksum-pinned; the compile-only Logstash API is extracted from the pinned 9.5.5 image. The obsolete parent `.logstash/` is never used. Dependency versions and verification checksums are locked. The gem contains one plugin jar bundling Jackson, not Logstash or Elasticsearch.

See [compatibility and evidence](docs/compatibility.md) for the exact tested scope and outstanding qualification work. This is not a claim of complete Splunk parsing-engine equivalence.
The [current validation status](docs/validation-status.md) distinguishes passing
final-artifact checks from the blocked fresh live UF/HF qualification. Classic
S2S TCP is not implemented.

## Configuration

```logstash
input {
  splunk_hec {
    host => "0.0.0.0"              # bind address, not a certificate identity
    port => 8088
    state_directory => "/var/lib/logstash/hec-input-1"
    inputs_conf => "/etc/logstash/hec-inputs.conf"
    ssl_self_signed_sans => "dns:localhost,dns:logs.example.test,ip:127.0.0.1,ip:::1"
  }
}
output { stdout { codec => json_lines } }
```

For inline policy use `tokens_json => '${HEC_TOKENS_JSON}'`, with an environment/Logstash-keystore value such as `[ {"token":"...","index":"main","indexes":"main,application","useACK":false} ]`. Inline secrets and keystore passwords use Logstash's password configuration type. Duplicate inline/imported token identities fail configuration.

Use a **different persistent state directory for each input**. It holds a process-locked ACK high-water counter and, when generated, the TLS identity. Keep it across restarts. Deleting or rolling back this directory invalidates the no-ID-reuse guarantee; do not reuse it as an ephemeral container filesystem.

### Single-file `inputs.conf`

```ini
[http]
disabled = false
index = main
ackIdleCleanup = false
maxIdleTime = 600

[http://forwarder]
token = 11111111-1111-4111-8111-111111111111
disabled = false
indexes = main, application
useACK = false
allowQueryStringAuth = false
```

Replace this example secret. Supported global/token policy keys are `disabled`, `index`, `host`, `source`, `sourcetype`, `useACK`, `allowQueryStringAuth`, `ackIdleCleanup` and `maxIdleTime`; tokens additionally support `token` and `indexes` (comma-separated). Global disablement wins. Unknown keys produce named, value-free diagnostics. This imports **one explicit file**, not Splunk app-directory precedence.

The file is checked every second. Publish a complete UTF-8 file with a final newline using an **atomic rename**. Unreadable, empty, comments-only, syntactically partial or invalid candidates retain the last good policy. An explicit valid `[http]`-only file revokes imported tokens. Empty members in an index allowlist are rejected, never interpreted as unrestricted access. Inline tokens still remain if configured. Authorization is rechecked when an ingestion slot is acquired, then snapshotted for the whole request. Already-admitted work continues under that snapshot. New requests and ACK queries use current policy; disabled/revoked secrets cannot poll, and current ACK-disable policy returns code 14. Renaming a stanza preserves identity; rotating its secret does not.

Metadata precedence is event/wire value → request query metadata → token defaults → global defaults. The final index must pass the token's allowlist. Empty, null and invalid values are validated, not indiscriminately replaced by defaults. Query-token authorization is off by default and requires that token's permission. As observed in the oracle, a query token takes precedence over an Authorization header. Header-based authentication supports `Splunk <token>` and Basic authentication with the token as password.

### TLS

With no supplied key material, startup creates `state_directory/identity/` atomically: `server.p12`, `password` and a public `server.crt`. The directory is mode 0700 and its files 0600 on POSIX filesystems. Subsequent starts reuse it; an unreadable existing identity fails startup. Default SANs cover `localhost`, `127.0.0.1` and `::1`; configure remote/container identities before first creation. Changing SAN configuration does not silently replace a persisted identity. Distribute `server.crt` through your normal trust mechanism and verify both trust and hostname:

```sh
curl --cacert /trusted/hec-server.crt \
  -H "Authorization: Splunk $HEC_TOKEN" \
  https://logs.example.test:8088/services/collector/event \
  -d '{"event":{"message":"native","a.b":[1,2.5]},"time":"1700000000.123456789"}'
```

Provided identity options:

| Setting | Purpose |
|---|---|
| `ssl_keystore` | PKCS12 or JKS identity with a private key and certificate chain |
| `ssl_keystore_type` | `PKCS12` (default) or `JKS` |
| `ssl_keystore_password` | Secret password for the supplied store/key |
| `ssl_certificate`, `ssl_key` | PEM certificate chain and unencrypted PKCS8 private key; alternative to a keystore |
| `ssl_client_ca` | Explicit trusted client certificates/CA bundle in X.509/PEM form |
| `ssl_client_authentication` | Require a valid client certificate; default false |
| `ssl_enabled` | Default true; set false explicitly only for isolated plaintext tests |

TLS 1.2/1.3 are enabled. Invalid stores, expired certificates, missing SANs, mismatched PEM keys and inconsistent TLS options fail startup. The implementation never falls back to plaintext. Protect supplied unencrypted PEM keys with filesystem permissions.

## Native events

`/services/collector` and `/services/collector/event` accept concatenated envelopes and top-level array batches. `/raw` frames LF/CRLF records within a request. `/s2s` decodes the attributed reference wire format. Supported `/1.0` aliases are listed in the compatibility document. `GET /services/collector/health` is independent of the ingestion-slot semaphore.

An event envelope retains `event` as its original string, number, object or array and keeps supplied HEC metadata. It does not gain a top-level `message`, ECS fields, guessed multiline merges or parsed event fields. A source-provided nested `message` remains intact. Only required Logstash internals (`@timestamp`, `@version`, `@metadata`) are added by the runtime. Protected internal names are not accepted as source envelope overrides; they remain valid payload keys inside `event` or literal indexed-field keys inside `fields`.

Numbers are parsed losslessly. Integers outside signed 64-bit use `BigInteger`; decimals such as `0.1` and values requiring more than double precision use `BigDecimal`. Both preserve their numeric JSON values through Logstash Event/PQ serialization. Exactly representable finite doubles can use the compact double representation. Supplied `time` is kept independently of `@timestamp`; string and numeric times preserve fractional precision. Seconds and 13/16/19-digit millisecond/microsecond/nanosecond forms are interpreted for internal time. Numeric literals are bounded to 1,024 characters, decimal precision/absolute scale to 1,024, and timestamps to representable epoch values with at most nanosecond nonzero fractional precision. Values beyond these limits fail validation before insertion rather than being rounded. Source time omitted by a sender stays omitted from the envelope.

Unstructured S2S records terminate logical lines even if the sender stripped their delimiter. Indentation is not a merge instruction. Structured records produce one event even with embedded newlines. S2S indexed multivalues remain ordered arrays under `fields`, with literal keys. Metric measurements remain doubles and dimensions retain their wire types; there is no synthetic metrics JSON/ECS wrapper. Decoded source epoch time is represented as a decimal **string** to preserve its fractional digits; provenance includes date-part tags, timezone, CSV header, flags, channel and source coordinates under `@metadata.splunk_hec.s2s`. Unsigned stream identifiers above signed-64 range are preserved there as decimal strings.

## ACK, retry and delivery boundary

`useACK` defaults false. When enabled, provide a GUID channel in `X-Splunk-Request-Channel` (or `channel` query metadata). A nonempty header wins; an empty header falls back to the query. Successful requests return a numeric `ackId`; poll `POST /services/collector/ack` with `{"acks":[0,1]}` on the same token identity/channel. The first completed poll consumes true; pending, unknown, consumed and stale IDs return false. Duplicate IDs in one poll collapse before consumption; concurrent polls cannot both consume true.

**True means every source event in that successful request entered the Logstash queue.** It does not mean output completion, successful Elasticsearch indexing, Splunk replication or exactly-once delivery. Memory queues are volatile. PQ crash durability depends on `queue.checkpoint.writes`, `queue.checkpoint.acks`, filesystem/fsync behavior and storage. A returning Java consumer alone is not a durability proof. The tests use checkpoints of 1 for explicit recovery measurements.

Malformed S2S is completely validated before enqueue: HTTP 400/code 6, zero source events and no ACK. Valid HEC prefixes follow the measured oracle errors. Size/count/memory and ACK-capacity checks happen before insertion. An insertion error, stop or disconnect can leave a prefix; even a failed PQ `accept` can have stored an event. A failed request receives no success ACK. Resending may duplicate the prefix; disconnecting does not undo it. Client timeouts are therefore not evidence of nonacceptance.

ACK IDs are allocated from a fsynced, atomically replaced, locked high-water file, reserving blocks before use and staying within JSON's safe integer range. The completion cache is in memory and separate from the PQ. After restart old polls are unknown/false even if events recover; unused numeric ranges are skipped, not reused. Limits are 1,000 channels, 10,000 outstanding IDs/channel and 100,000 globally, without eviction to make room. Idle cleanup is off by default; when enabled it uses a monotonic clock and a 600-second default. An active request pins its channel.

S2S IDs are versioned SHA-256 values at `@metadata.splunk_hec.id`. Version 1 includes an immutable token fingerprint, wire source identity/channel/index, stream, absolute UTF-8 byte offset, sequence, logical occurrence and source content, including canonically ordered indexed fields/measurements and structured source time. It excludes receipt time, peer port and connection identity. Distinct repeated lines have distinct IDs. Rebatch/reconnect stability applies only when that wire source-coordinate tuple remains stable. Zero stream/offset positions without file identity use the batch-scoped fallback. If coordinates are unavailable, scope is explicitly `identical-batch-retry`, using batch identity and occurrence; there is no general content-based deduplication claim. [Routing examples](examples/pipeline.conf) show optional idempotent outputs; the input does not drop repeats.

## Limits and lifecycle

These are **plugin defaults**, not Splunk defaults. Sizes are bytes.

| Setting | Default |
|---|---:|
| `max_concurrent_requests` | 16 |
| `max_connections` | 64, including idle/unauthenticated peers |
| `max_wire_bytes` | 10 MiB |
| `max_expanded_bytes` | 64 MiB, combined outer gzip and inner zlib output |
| `max_inflight_bytes` | 128 MiB aggregate accounted allocations |
| `max_event_bytes` | 1 MiB serialized logical envelope, including S2S provenance; excludes required runtime timestamp/version |
| `max_events` | 10,000/request |
| `max_json_depth` | 100 |
| `body_read_timeout_ms` | 30,000, absolute TLS/header/body-read deadline and separate response-write deadline |
| `admission_timeout_ms` | 1,000 |
| `shutdown_grace_ms` | 10,000 |

Positive/consistent limits are checked at startup. Memory accounting reserves wire growth/copies, parser objects, per-event field-container copies, decoded fields and inflation before their application allocations. A 256 KiB allowance inside the aggregate budget is reserved for one lightweight health request under ingestion-memory pressure; the aggregate must exceed that allowance. The connection cap still applies, including to health: this does not promise availability through unlimited connection floods. It is an accounting gate, not a JVM heap-size guarantee; memory pressure can admit fewer than 16 requests. Both gzip trailers/CRC and S2S sync-flush framing are validated, including valid empty gzip members. No event is truncated/split to fit a cap. Busy/queue-unavailable results use HTTP 503/code 9 without an invented `Retry-After` policy. HTTP `100-continue` is handled after authentication/admission.

Shutdown stops admission, closes transport reads, interrupts the actual queue-writing workers, joins them, and then disposes policy/ACK state. No timed-out detached worker is allowed to continue enqueueing. A still-live worker is a shutdown error, not a reported clean stop.

## Verification

```sh
./gradlew test gem
python3 -m unittest discover -s tests/build -v
python3 scripts/resolve-versions.py
docker compose -f docker/compose.yml run --rm interop
```

For a targeted rerun, append `--stage runtime` or `--stage senders` to the Compose
command. The latter starts an owned oracle and runs the real sender stage; it
does not recapture the complete HTTP oracle corpus.

Run Compose from this plugin directory. It uses the host Docker socket and matching absolute bind paths; Docker Desktop needs host networking enabled. Auto networking uses bridge senders with Desktop's host gateway on Docker Desktop, and host-network senders accessing loopback on native Linux. Set `HEC_SENDER_NETWORK=host` or `bridge` explicitly to override detection. The native-Linux selection has unit coverage; the measured end-to-end environment is Docker Desktop, as recorded in compatibility evidence. Real Splunk/UF containers run amd64, with emulation on Apple Silicon. Test licenses/terms acceptance is explicit in the disposable setup. Each owned container has finite waits and ID-scoped cleanup; no package/image is published. The equivalent host orchestration is `python3 tests/interop/run.py`. It refuses to adopt an existing `hec-spec-oracle` container.

`scripts/resolve-versions.py --refresh-ga` discovers only numeric stable release candidates and writes `versions-candidate.json` for review; builds do not refresh pins. Review and update `versions.properties`/checksums explicitly, then regenerate real fixtures and minimum/latest evidence. Bootstrap invalidates the API cache when its source image pin changes and runs the Gradle version selected by the same pins file.

TCP is not enabled or implemented. See [the conditional feasibility record](docs/tcp-feasibility.md); `python3 tests/tcp/check.py` exits 2 while real TCP evidence is absent.
