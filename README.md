# Logstash Splunk HEC input

A Java input for **Logstash 9.5.0+ / Java 21** that receives HEC event, raw and S2S HTTP envelopes, and optionally the classic UF/HF cooked `tcpout` stream. Payloads stay native for later filters. The HEC listener uses **TLS by default**; the optional TCP listener is **plaintext by default** and can be switched to TLS separately. No HEC tokens are accepted until configured.

Build and install locally (the full step-by-step guide, including Docker, Kubernetes, verification, upgrade and
troubleshooting, is [docs/installation.md](docs/installation.md)):

```sh
./gradlew test gem
bin/logstash-plugin install /absolute/path/logstash-input-splunk_hec-0.1.0-java.gem
bin/logstash-plugin list --verbose splunk      # logstash-input-splunk_hec (0.1.0)
```

Installation needs access to rubygems.org (Logstash resolves dependencies even for a local gem) and a Logstash of
**9.5.0 or newer**; older versions are refused at install time. For air-gapped sites bake the plugin into a Docker image
with [`docker/Dockerfile.logstash`](docker/Dockerfile.logstash).

The build needs Python 3, a JDK capable of `--release 21`, Docker and network access for the first dependency download. Gradle is checksum-pinned; the compile-only Logstash API is extracted from the pinned 9.5.5 image. The obsolete parent `.logstash/` is never used. Dependency versions and verification checksums are locked. The gem contains one plugin jar bundling Jackson, not Logstash or Elasticsearch.

**Installation:** [docs/installation.md](docs/installation.md). **All configuration options, token policy, TLS, TCP, limits, sender settings and troubleshooting are in the [configuration reference](docs/configuration.md).**

For the complete **UF → HTTPS HEC S2S → Logstash → HTTPS HEC → Splunk indexer**
setup, use the [end-to-end reference configuration](docs/uf-logstash-splunk-reference.md).
It includes all companion files, `_internal`/`_audit` forwarding, the indexer
audit-source override, TLS/token wiring, persistent queues and verification searches.
The existing Docker environment is also packaged as a
[documented test lab](https://github.com/mingsorg/logstash-input-splunk_hec/tree/main/docker/test-lab), with configuration files,
a Compose reference, bootstrap sources and read-only validation scripts.

See [compatibility and evidence](docs/compatibility.md) for the exact tested scope and outstanding qualification work. This is not a claim of complete Splunk parsing-engine equivalence.
The [current validation status](docs/validation-status.md) lists the passing
final-artifact checks and live UF/HF qualification. Classic S2S TCP is optional,
off by default and documented in [docs/s2s-tcp.md](docs/s2s-tcp.md).

## Event, raw and S2S on the same listener

**One input serves these endpoints concurrently on HTTPS port 8088 by default:**

| Endpoint | Payload |
|---|---|
| `POST /services/collector/event` | JSON event envelopes, concatenated or array batches |
| `POST /services/collector/raw` | UTF-8 text with request metadata |
| `POST /services/collector/s2s` | Native UF/HF `[httpout]` binary records |

They share TLS, token policies, resource limits and the Logstash pipeline. The
request path selects its decoder. See the [detailed endpoint guide](docs/http-endpoints.md)
for exact aliases, simultaneous-use behavior, curl/forwarder examples, payload
shapes, ACK requirements, error responses and downstream routing. A
[shared-listener pipeline](examples/shared-listener.conf) and matching
[token policy](examples/hec-inputs.conf) are included. The
[bit-level S2S guide](docs/s2s-wire-format.md) explains the binary wire grammar.

## Optional classic S2S TCP (`tcpout`)

Set `s2s_tcp_enabled => true` to also accept cooked-mode UF/HF `tcpout` on
`s2s_tcp_port` (default 9997). It shares the certificate identity, limits and queue
back-pressure of the HTTPS listener, but has its own TLS switch
(`s2s_tcp_ssl_enabled`, default **off**). TCP has **no HEC token**: the network and
TLS/mTLS are the trust boundary, and the sender GUID is self-declared. With `useACK = true` the
sender is acknowledged only after the record's events entered the Logstash queue.
Uncooked and legacy protocol levels are not supported. Details, observed wire
facts and evidence are in [docs/s2s-tcp.md](docs/s2s-tcp.md); examples are
[`examples/tcp-listener.conf`](examples/tcp-listener.conf) and
[`examples/outputs-tcp.conf`](examples/outputs-tcp.conf).

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
| `ssl_enabled` | TLS on the HEC (HTTP) listener; default true. Set false only on isolated networks |
| `s2s_tcp_ssl_enabled` | TLS on the TCP listener; default **false** (plaintext) |
| `ssl_client_authentication`, `s2s_tcp_ssl_client_authentication` | Client-certificate auth per listener |
| `hec_metadata` | `full` (default), `id_only` or `none`: provenance under `@metadata.splunk_hec`. `@timestamp`/`@version` are unaffected |
| `s2s_metadata_fields_json` | `{}` (default, disabled): exact wire-metadata key → simple name inside searchable `s2s_metadata`, for HTTP/TCP independently of `hec_metadata` |
| `s2s_tcp_enabled`, `s2s_tcp_port` | Optional classic TCP listener; default off, port 9997 |
| `s2s_tcp_default_index`, `s2s_tcp_indexes` | TCP default index (`main`) and optional comma-separated allowlist |
| `s2s_tcp_max_event_bytes` | TCP logical-event cap; 0 (default) allows at least 8 MiB because real HFs send >1 MiB internal records |

TLS 1.2/1.3 are enabled. Invalid stores, expired certificates, missing SANs, mismatched PEM keys and inconsistent TLS options fail startup. The implementation never falls back to plaintext. Protect supplied unencrypted PEM keys with filesystem permissions.

## Native events

`/services/collector` and `/services/collector/event` accept concatenated envelopes and top-level array batches. `/raw` frames LF/CRLF records within a request. `/s2s` decodes the attributed reference wire format. Supported `/1.0` aliases are listed in the compatibility document. `GET /services/collector/health` is independent of the ingestion-slot semaphore.

An event envelope retains `event` as its original string, number, object or array and keeps supplied HEC metadata. It does not gain a top-level `message`, ECS fields, guessed multiline merges or parsed event fields. A source-provided nested `message` remains intact. Only required Logstash internals (`@timestamp`, `@version`, `@metadata`) are added by the runtime. Protected internal names are not accepted as source envelope overrides; they remain valid payload keys inside `event` or literal indexed-field keys inside `fields`.

Numbers are parsed losslessly. Integers outside signed 64-bit use `BigInteger`; decimals such as `0.1` and values requiring more than double precision use `BigDecimal`. Both preserve their numeric JSON values through Logstash Event/PQ serialization. Exactly representable finite doubles can use the compact double representation. Supplied `time` is kept independently of `@timestamp`; string and numeric times preserve fractional precision. Seconds and 13/16/19-digit millisecond/microsecond/nanosecond forms are interpreted for internal time. Numeric literals are bounded to 1,024 characters, decimal precision/absolute scale to 1,024, and timestamps to representable epoch values with at most nanosecond nonzero fractional precision. Values beyond these limits fail validation before insertion rather than being rounded. Source time omitted by a sender stays omitted from the envelope.

Unstructured S2S records terminate logical lines even if the sender stripped their delimiter. Indentation is not a merge instruction. Structured records produce one event even with embedded newlines. S2S indexed multivalues remain ordered arrays under `fields`, with literal keys. Metric measurements remain doubles and dimensions retain their wire types; there is no synthetic metrics JSON/ECS wrapper. Decoded source epoch time is represented as a decimal **string** to preserve its fractional digits; provenance includes date-part tags, timezone, CSV header, flags, channel and source coordinates under `@metadata.splunk_hec.s2s`. Unsigned stream identifiers above signed-64 range are preserved there as decimal strings.

To retain selected per-record metadata in searchable output, set
`s2s_metadata_fields_json => '{"_path":"path","crcSalt":"salt"}'`. A record carrying
those exact keys gains `"s2s_metadata":{"path":"/var/log/app.log","salt":"<SOURCE>"}`.
Missing keys are omitted, and an empty mapping or no matches produces no namespace.
Values stay strings; destination names match `[A-Za-z_][A-Za-z0-9_]*`, never field paths.
Indexed values stay in `fields`, handshake facts stay in provenance. The mapping works
with `hec_metadata => "none"` and does not change native fields, timestamps or ID
derivation: selected metadata does not participate in coordinate-based IDs. Copies
and logical size are bounded before insertion/ACK. See the
[mapping reference](docs/configuration.md#34b-searchable-s2s-metadata) and
[example pipeline](examples/metadata-fields.conf).

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
python3 tests/interop/metadata_fields.py
python3 scripts/resolve-versions.py
docker compose -f docker/compose.yml run --rm interop
```

For a targeted rerun, append `--stage runtime`, `--stage senders`, `--stage tcp`,
`--stage config`, `--stage install` or `--stage metadata`
to the Compose command. `senders` starts an owned oracle and runs the real HTTP
sender stage followed by the TCP stage; it does not recapture the complete HTTP
oracle corpus. `config` validates every snippet in the configuration reference with `logstash -t` on both runtimes. `tcp` runs only the real UF/HF classic TCP matrix against an owned
Logstash receiver. `metadata` runs the real UF/HF searchable-metadata checks over
HTTPS and TLS TCP; the default full run includes this stage too.

Run Compose from this plugin directory. It uses the host Docker socket and matching absolute bind paths; Docker Desktop needs host networking enabled. Auto networking uses bridge senders with Desktop's host gateway on Docker Desktop, and host-network senders accessing loopback on native Linux. Set `HEC_SENDER_NETWORK=host` or `bridge` explicitly to override detection. The native-Linux selection has unit coverage; the measured end-to-end environment is Docker Desktop, as recorded in compatibility evidence. Real Splunk/UF containers run amd64, with emulation on Apple Silicon. Test licenses/terms acceptance is explicit in the disposable setup. Each owned container has finite waits and ID-scoped cleanup; no package/image is published. The equivalent host orchestration is `python3 tests/interop/run.py`. It refuses to adopt an existing `hec-spec-oracle` container.

`scripts/resolve-versions.py --refresh-ga` discovers only numeric stable release candidates and writes `versions-candidate.json` for review; builds do not refresh pins. Review and update `versions.properties`/checksums explicitly, then regenerate real fixtures and minimum/latest evidence. Bootstrap invalidates the API cache when its source image pin changes and runs the Gradle version selected by the same pins file.

`python3 tests/tcp/check.py` exits 0 only when the retained real UF/HF TCP evidence is complete and names the exact gem in this directory; otherwise it exits 2. See [docs/s2s-tcp.md](docs/s2s-tcp.md).
