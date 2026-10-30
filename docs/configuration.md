# Configuration reference

To install the plugin first, see the [installation guide](installation.md). Everything you can configure for the `splunk_hec` input: the Logstash options, the
token-policy file, TLS, the optional classic TCP listener, resource limits, and
the matching UF/HF sender settings. Defaults below are the plugin's own, not
Splunk's. Requires **Logstash 9.5.0+ (Java 21)**.

For the complete UF → HEC S2S → Logstash → HEC → Splunk indexer chain, including
all companion files and internal/audit forwarding, see the
[end-to-end reference configuration](uf-logstash-splunk-reference.md).

Contents: [1 Quick start](#1-quick-start) · [2 What is configured where](#2-what-is-configured-where) ·
[3 Option reference](#3-option-reference) · [4 Tokens and policy](#4-tokens-and-policy) ·
[5 TLS](#5-tls) · [6 TCP listener](#6-optional-classic-tcp-listener) ·
[7 Limits and sizing](#7-limits-and-sizing) · [8 Logstash pipeline settings](#8-logstash-pipeline-and-host-settings) ·
[9 Sender configuration](#9-sender-configuration) · [10 Output shape](#10-output-shape) ·
[11 Startup validation](#11-startup-validation-errors) · [12 Troubleshooting](#12-troubleshooting) ·
[13 What was tested](#13-what-was-tested)

## 1. Quick start

### A. HEC only (the default)

```logstash
input {
  splunk_hec {
    state_directory => "/var/lib/logstash/hec-1"   # persistent, one per input
    ssl_self_signed_sans => "dns:localhost,dns:logs.example.test,ip:127.0.0.1"
    tokens_json => '${HEC_TOKENS_JSON}'            # Logstash keystore / env value
  }
}
```

`HEC_TOKENS_JSON` example:
`[{"token":"11111111-1111-4111-8111-111111111111","index":"main","indexes":"main,app","useACK":false}]`

This serves HTTPS on port 8088: `/services/collector[/event|/raw|/s2s|/ack|/health]`.
Until at least one token exists every ingestion request is rejected.

### B. HEC over TLS + classic UF/HF `tcpout` (port 9997)

```logstash
input {
  splunk_hec {
    state_directory => "/var/lib/logstash/hec-1"
    ssl_self_signed_sans => "dns:logs.example.test,ip:10.0.0.5"
    inputs_conf => "/etc/logstash/hec-inputs.conf"
    s2s_tcp_enabled => true
    s2s_tcp_default_index => "main"
  }
}
```

With only `s2s_tcp_enabled => true`, HEC stays on TLS (the default) and the TCP listener is
**plaintext** (its default, like a stock Splunk 9997 receiver). The plugin logs a warning at
startup. To encrypt TCP as well, add `s2s_tcp_ssl_enabled => true`:

```logstash
input {
  splunk_hec {
    state_directory => "/var/lib/logstash/hec-1"
    ssl_self_signed_sans => "dns:logs.example.test,ip:10.0.0.5"
    s2s_tcp_enabled => true
    s2s_tcp_ssl_enabled => true
  }
}
```

### C. Two independent inputs (different TLS, tokens or limits per listener)

Each block has its own state directory, ports, TLS and limits:

```logstash
input {
  splunk_hec { id => "hec-apps"  port => 8088 state_directory => "/var/lib/logstash/hec-apps"
               tokens_json => '${APP_TOKENS_JSON}' }
  splunk_hec { id => "hec-fwd"   port => 8089 state_directory => "/var/lib/logstash/hec-fwd"
               tokens_json => '${FWD_TOKENS_JSON}'
               s2s_tcp_enabled => true s2s_tcp_port => 9997 }
}
```

## 2. What is configured where

| Concern | Setting | Applies to |
|---|---|---|
| Bind address | `host` | **Both** listeners |
| HTTPS port | `port` | HEC/S2S-over-HTTP only |
| TCP port | `s2s_tcp_port` | TCP only |
| Enable TCP | `s2s_tcp_enabled` | TCP only (**default off**) |
| HTTP listener on/off | *(not configurable)* | Always starts, even with TCP enabled |
| TLS on/off | `ssl_enabled` (HTTP, **default on**), `s2s_tcp_ssl_enabled` (TCP, **default off**) | Each listener separately |
| Client-certificate auth (mTLS) | `ssl_client_authentication` (HTTP), `s2s_tcp_ssl_client_authentication` (TCP) | Each listener separately; needs TLS on that listener |
| Certificate, key, keystore, client CA, generated-certificate SANs | `ssl_keystore*`, `ssl_certificate`, `ssl_key`, `ssl_client_ca`, `ssl_self_signed_sans` | **Shared** by whichever listeners use TLS (one identity) |
| Authentication | tokens (`tokens_json`, `inputs_conf`) | HEC/S2S-over-HTTP only. **TCP has no token**; TLS/mTLS and the network are its boundary |
| Index policy | token `index`/`indexes` | HTTP; TCP uses `s2s_tcp_default_index` / `s2s_tcp_indexes` |
| Event-size cap | `max_event_bytes` | HTTP; TCP uses `s2s_tcp_max_event_bytes` |
| Provenance in `@metadata` | `hec_metadata` | Both listeners (`full`, `id_only`, `none`) |
| Searchable per-record metadata | `s2s_metadata_fields_json` | S2S over HTTP and TCP, independently of `hec_metadata` |
| Connection/memory/concurrency limits, timeouts | `max_*`, `*_timeout_ms` | **Shared budget** across both listeners |
| ACK state and TLS identity directory | `state_directory` | One per input, shared by both listeners |

TLS can be set per listener (for example HEC over TLS with plaintext TCP, which is the
default, or the reverse). Certificates are shared: both listeners present the same identity.
For different certificates, tokens or limits per listener, use two inputs (recipe C). There
is no option to disable the HTTP listener; with no tokens it rejects everything
but still binds `port`, so choose a free one.

## 3. Option reference

Types: string, number, boolean. `secret` values are never logged. Sizes are bytes,
times are milliseconds unless stated. Logstash `${VAR}` and keystore substitution
work in any value.

### 3.1 Listener and state

| Option | Type | Default | Notes |
|---|---|---|---|
| `host` | string | `0.0.0.0` | Bind address only; it is **not** a certificate identity. |
| `port` | number | `8088` | 1..65535. HTTPS (or HTTP when `ssl_enabled => false`). |
| `state_directory` | string | `data/splunk_hec` | Use an **absolute, persistent path, unique per input**. Holds a process-locked ACK high-water counter and, when generated, `identity/`. A relative path resolves against the Logstash working directory. Deleting or rolling it back voids the no-ID-reuse guarantee; do not put it on an ephemeral container filesystem. Two inputs sharing one directory fail at startup with `ACK state already owned`. |

### 3.2 Authentication and policy

| Option | Type | Default | Notes |
|---|---|---|---|
| `tokens_json` | secret string | `[]` | JSON array of token objects (see [4](#4-tokens-and-policy)). Inline secrets: prefer the keystore or `${ENV}`. |
| `inputs_conf` | string | empty | Path to **one** Splunk-style `inputs.conf` file. Checked every second; an invalid or partial replacement keeps the last good policy. |

Both sources are merged. A duplicate token (same secret) anywhere fails startup.

### 3.3 TLS (per-listener switches, shared certificate)

| Option | Type | Default | Notes |
|---|---|---|---|
| `ssl_enabled` | boolean | `true` | TLS on the **HTTP (HEC)** listener. `false` serves HEC over plaintext HTTP, so tokens travel unencrypted; isolated networks only. A startup warning is logged. |
| `ssl_client_authentication` | boolean | `false` | Require a client certificate on the **HTTP** listener (mTLS). Needs `ssl_enabled` and `ssl_client_ca`. |
| `s2s_tcp_ssl_enabled` | boolean | `false` | TLS on the **TCP** listener. Only relevant when `s2s_tcp_enabled` is true. Default plaintext matches a stock Splunk 9997 receiver; the plugin logs a warning because the classic protocol has no token. |
| `s2s_tcp_ssl_client_authentication` | boolean | `false` | Require a client certificate on the **TCP** listener (mTLS). Needs `s2s_tcp_ssl_enabled` and `ssl_client_ca`. |
| `ssl_self_signed_sans` | string | `dns:localhost,ip:127.0.0.1,ip:::1` | keytool SAN list used **only when generating** the identity (first start). Include every DNS name/IP the senders connect to. Later changes do not replace an existing identity. |
| `ssl_keystore` | string | empty | PKCS12/JKS identity with a private key and chain. Exclusive with `ssl_certificate`/`ssl_key`. |
| `ssl_keystore_type` | string | `PKCS12` | `PKCS12` or `JKS`. |
| `ssl_keystore_password` | secret | empty | Password for the store/key. |
| `ssl_certificate` | string | empty | PEM certificate chain. Requires `ssl_key`. |
| `ssl_key` | string | empty | **Unencrypted PKCS8** PEM private key (RSA, EC or Ed25519). Protect with file permissions. |
| `ssl_client_ca` | string | empty | PEM bundle of client CAs/certificates to trust. |

TLS 1.3 and 1.2 only. The server certificate must be valid, carry SANs, and match
its key. A listener never falls back to plaintext on its own: plaintext happens only when that
listener's switch is off. The certificate options (`ssl_keystore`, `ssl_certificate`, `ssl_key`,
`ssl_client_ca`) are used by every listener that has TLS on; supplying them when **neither**
listener uses TLS is a startup error, because they would be silently unused.

### 3.4 Optional TCP listener

| Option | Type | Default | Notes |
|---|---|---|---|
| `s2s_tcp_enabled` | boolean | `false` | Start the classic cooked-mode `tcpout` receiver. |
| `s2s_tcp_port` | number | `9997` | 1..65535, must differ from `port`. |
| `s2s_tcp_default_index` | string | `main` | Index for records that name none. Must be in `s2s_tcp_indexes` if that is set. |
| `s2s_tcp_indexes` | string | empty | Comma-separated allowlist (no empty members). Empty = unrestricted. A record for another index closes the connection **without ACK**. |
| `s2s_tcp_max_event_bytes` | number | `0` (automatic) | Serialized logical-event cap for TCP. `0` = larger of `max_event_bytes` and `min(8 MiB, max_expanded_bytes)`. An explicit value must be positive and ≤ `max_expanded_bytes`. |

### 3.4a Event provenance

| Option | Type | Default | Notes |
|---|---|---|---|
| `hec_metadata` | string | `full` | How much provenance is attached under `@metadata.splunk_hec`: `full` (stable `id`, `s2s` wire details, and for TCP the `tcp` connection block), `id_only` (only the stable `id`, enough for idempotent outputs) or `none` (no `@metadata` at all). Applies to S2S over HTTP and TCP. The `id` is identical in `full` and `id_only`. `@metadata` is never written by outputs unless a filter copies it; it only affects memory and the size cap (provenance counts toward the event-size cap only when attached). **`@timestamp` and `@version` are added by Logstash itself and are never affected.** |

### 3.4b Searchable S2S metadata

| Option | Type | Default | Notes |
|---|---|---|---|
| `s2s_metadata_fields_json` | string | `{}` | JSON object mapping exact decoded per-record wire keys to literal destination names inside `s2s_metadata`. Applies equally to S2S over HTTP and classic TCP, including `hec_metadata => "none"`. Empty mapping disables the namespace. |

```logstash
input {
  splunk_hec {
    state_directory => "/var/lib/logstash/hec-mapped"
    tokens_json => '${HEC_TOKENS_JSON}'
    s2s_metadata_fields_json => '{"_path":"path","crcSalt":"salt"}'
    hec_metadata => "none"
  }
}
```

For a record with `_path=/var/log/app.log` and `crcSalt=<SOURCE>`, the searchable
output gains `"s2s_metadata":{"path":"/var/log/app.log","salt":"<SOURCE>"}`.
These keys were observed on the synthetic monitor fixtures; metadata availability
depends on the sender and record. A custom mapping such as `{"custom_tenant":"tenant"}`
copies `acme` only if the record actually carries that exact decoded key.

- Source keys are nonblank, case-sensitive exact strings; no trimming, aliases,
  wildcard matching, inference, text parsing or automatic protocol-field copying.
- Destination names must match `[A-Za-z_][A-Za-z0-9_]*`. Dots/brackets and field
  paths are invalid. `{"custom_tenant":"host"}` writes `s2s_metadata.host` and
  cannot overwrite root `host` or `fields.host`.
- All selected values remain **strings**, including numeric-looking values. Typed
  indexed values remain in `fields`; handshake facts are not mapping sources.
- Missing source keys are omitted; if none match, `s2s_metadata` is absent. No nulls
  or empty namespace are invented. Each logical line gets its own selected map.
- Parsed once at startup, immutable until restart. Nonobjects, nonstring values,
  duplicate JSON source keys (including escaped equivalents), duplicate destinations,
  blank names, invalid identifiers and trailing JSON fail startup with a value-free
  diagnostic; a partially loaded policy is never used.
- Copies are charged to the shared allocation budget before allocation. The complete
  logical event including selected metadata must fit the transport's cap **before
  insertion**. Failure yields HTTP 503/code 9 without a success ACK, or TCP close
  without ACK. Limits are not raised automatically.
- Mapping does **not** change event-ID derivation. Selected metadata is not an input
  to coordinate-based IDs; changing only selected metadata can retain the same ID.
  The existing positionless fallback still includes original batch/record bytes.
  Unknown wire tags remain unsupported and rejected.

### 3.5 Limits (shared)

| Option | Default | Constraint / meaning |
|---|---:|---|
| `max_concurrent_requests` | 16 | Requests/records processed at once (HTTP requests and TCP records share it). |
| `max_connections` | 64 | Open connections incl. idle/unauthenticated; ≥ `max_concurrent_requests`. Counts HTTP and TCP together. |
| `max_wire_bytes` | 10 MiB | Largest HTTP body as received. |
| `max_expanded_bytes` | 64 MiB | Largest body after gzip/zlib expansion (also bounds one TCP record); ≥ `max_wire_bytes`. |
| `max_inflight_bytes` | 128 MiB | Aggregate accounted allocations; ≥ `max_expanded_bytes` and > 256 KiB. |
| `max_event_bytes` | 1 MiB | Serialized logical event incl. provenance (HTTP); ≤ `max_expanded_bytes`. |
| `max_events` | 10,000 | Events per HTTP request. |
| `max_json_depth` | 100 | JSON nesting depth. |
| `body_read_timeout_ms` | 30,000 | Absolute TLS-handshake/header/body deadline per request and per TCP read; separate response-write deadline. |
| `admission_timeout_ms` | 1,000 | How long a request waits for a processing slot before `503`/code 9. |
| `shutdown_grace_ms` | 10,000 | Time to stop and join workers on shutdown. |

All must be positive; violations fail startup with `inconsistent positive resource
limits`. Memory accounting is an allocation gate, not a JVM heap guarantee.

### 3.6 Standard Logstash input options

`id`, `enable_metric`, `add_field`, `tags` and `type` are accepted and applied by
Logstash (for example `type` adds a `type` field and `tags` adds `tags`; this is
an explicit choice, never a default). **`codec` is not accepted**: the input emits
native maps and has no codec stage. Set a unique `id` per input for monitoring.

## 4. Tokens and policy

Authentication is checked on every HEC/S2S-over-HTTP request: `Authorization:
Splunk <token>` or `Basic` (token as the password). Query `?token=` works only for
tokens with `allowQueryStringAuth = true`, and then takes precedence over the
header. `GET /services/collector/health` needs no token.

### 4.1 `tokens_json`

A JSON **array of objects**. Allowed keys per object:

| Key | Type | Meaning |
|---|---|---|
| `token` | string | Secret value (required, unique). Any non-empty string; GUIDs are customary. |
| `disabled` | boolean | Reject this token. |
| `index` | string | Default index when the sender names none (default `main`). |
| `indexes` | string | Comma-separated allowlist; the final index must be in it. Empty members are rejected. Absent = unrestricted. |
| `host`, `source`, `sourcetype` | string | Defaults used only when absent from the event and request query. |
| `useACK` | boolean | Enable HEC acknowledgements (requires a GUID channel). Default `false`. |
| `allowQueryStringAuth` | boolean | Allow `?token=`. Default `false`. |
| `ackIdleCleanup` | boolean | Drop idle ACK channels. Default `false`. |
| `maxIdleTime` | number (seconds) | Idle threshold when cleanup is on. Default 600. |

Unknown keys, nulls, nested values, or non-string metadata fail startup.

### 4.2 `inputs_conf` file

```ini
[http]                      ; global defaults and switches
disabled = false
index = main
useACK = false
ackIdleCleanup = false
maxIdleTime = 600

[http://forwarders]         ; one stanza per token; the name is only a label
token = REPLACE_ME
indexes = main, application
useACK = false
allowQueryStringAuth = false
```

- Global keys: `disabled index host source sourcetype useACK allowQueryStringAuth ackIdleCleanup maxIdleTime`.
  Token stanzas add `token` and `indexes`. A global `disabled = true` disables every token.
- Unknown keys are logged (name only, never the value) and ignored.
- Publish by **atomic rename**: a complete UTF-8 file with a final newline.
  Empty, comments-only, partial or invalid candidates are rejected and the last
  good policy stays in force. An explicit valid `[http]`-only file revokes imported
  tokens (inline tokens remain).
- Renaming a stanza keeps its identity; rotating `token =` is a new identity.
- Directory/app layering and Splunk's full `inputs.conf` precedence are **not** implemented.

### 4.3 Precedence

Metadata: event/wire value → request query (`index`, `host`, `source`, `sourcetype`,
`channel`) → token defaults → global `[http]` defaults. The resulting index must
pass the token's allowlist. Authorization is rechecked when a slot is acquired and
then snapshotted for that request; revocation affects new requests and ACK polls.

### 4.4 ACKs

With `useACK = true` each ingestion request needs a GUID in `X-Splunk-Request-Channel`
(or `?channel=`). Poll `POST /services/collector/ack` with `{"acks":[1,2]}`.
`true` means every event of that request **entered the Logstash queue**, not that it
was output or indexed downstream. Memory queues are volatile; persistent-queue
durability depends on your `queue.checkpoint.*` settings. Old IDs are unknown after
a restart. Caps: 1,000 channels, 10,000 outstanding IDs per channel, 100,000 total.
UF/HF `httpout` sends no channel: keep `useACK = false` for those tokens.

## 5. TLS

### 5.0 Which listener uses TLS

| Goal | Settings |
|---|---|
| HEC TLS, TCP plaintext (default) | nothing, or `s2s_tcp_enabled => true` |
| HEC TLS, TCP TLS | `s2s_tcp_enabled => true  s2s_tcp_ssl_enabled => true` |
| HEC plaintext, TCP TLS | `ssl_enabled => false  s2s_tcp_enabled => true  s2s_tcp_ssl_enabled => true` |
| Both plaintext (isolated test only) | `ssl_enabled => false  s2s_tcp_enabled => true` |
| mTLS on TCP only | `s2s_tcp_ssl_enabled => true  s2s_tcp_ssl_client_authentication => true  ssl_client_ca => "..."` |

### 5.1 Generated identity (default)

On first start the input creates `state_directory/identity/` (`server.p12`,
`password`, public `server.crt`; directory mode 0700, files 0600) and reuses it on
every start. Put every name or IP that senders use into `ssl_self_signed_sans`
**before** the first start. Distribute `server.crt` to senders and verify both
trust and hostname.

### 5.2 Your own certificate

PKCS12 or JKS keystore:

```logstash
splunk_hec {
  state_directory => "/var/lib/logstash/hec-1"
  ssl_keystore => "/etc/logstash/hec.p12"
  ssl_keystore_password => "${HEC_P12_PASSWORD}"
}
```

or PEM certificate chain and PKCS8 key:

```logstash
splunk_hec {
  state_directory => "/var/lib/logstash/hec-1"
  ssl_certificate => "/etc/logstash/hec.crt"
  ssl_key => "/etc/logstash/hec.pkcs8.key"
}
```

Convert an encrypted or PKCS1 key first, for example
`openssl pkcs8 -topk8 -nocrypt -in key.pem -out hec.pkcs8.key`.

### 5.3 Client certificates (mTLS)

```logstash
splunk_hec {
  state_directory => "/var/lib/logstash/hec-1"
  ssl_client_ca => "/etc/logstash/clients-ca.pem"
  ssl_client_authentication => true
}
```

`ssl_client_authentication` applies to the HTTPS listener only. For the TCP listener use
`s2s_tcp_ssl_enabled => true` together with `s2s_tcp_ssl_client_authentication => true` (both
listeners trust the same `ssl_client_ca`). For TCP, client certificates are the strongest
available authentication, since the classic protocol has no token.

## 6. Optional classic TCP listener

Details, wire facts and unsupported modes: [s2s-tcp.md](s2s-tcp.md). Summary:

- Accepts UF/HF cooked-mode `tcpout` (`sendCookedData = true`, protocol level 7), over
  plaintext by default or TLS with `s2s_tcp_ssl_enabled => true`. Plaintext means anyone who
  can reach the port can send events: restrict it by network or use TLS with client certificates.
- Replies with reverse ACKs **after** the record's events entered the queue. A
  failed or interrupted insertion closes the connection without ACK; the sender
  retries (a prefix may already be queued, so duplicates are possible; IDs stay
  stable when the sender coordinates do).
- The sender's GUID namespaces IDs but is **self-declared**, not authenticated.
- Keep the persistent-queue `queue.page_capacity` above the largest event (see 8.2).

## 7. Limits and sizing

- Concurrency: `max_concurrent_requests` is a pool of slots shared by HTTP requests
  and TCP records. Slow queue consumers hold slots, which pushes back on **both**
  listeners (HTTP `503`/code 9; TCP simply stops reading).
- Memory: size `max_inflight_bytes` well under the Logstash heap. A 1 MiB event with
  nesting can cost several times its size while parsed. The default 128 MiB assumes
  the default 1 GiB Logstash heap.
- Large events: heavy forwarders send ~1.2 MB internal records; the automatic TCP
  cap (≥ 8 MiB) covers this. HTTP `max_event_bytes` stays 1 MiB unless you raise it.
- Heavy senders: raise `max_connections` for many forwarders; keep it ≥ concurrency.
- Valid raised example:
  `max_connections => 256 max_concurrent_requests => 32 max_inflight_bytes => 268435456`
  (needs a larger heap).

## 8. Logstash pipeline and host settings

### 8.1 Pipeline

- Events are written to the pipeline queue as they arrive. For ACKs to mean
  something durable, use `queue.type: persisted` with `queue.checkpoint.writes: 1`
  and `queue.checkpoint.acks: 1`, accepting the throughput cost.
- `pipeline.workers`/`pipeline.batch.size` are ordinary pipeline tuning; the input
  imposes no order guarantee across concurrent requests.
- Use filters/outputs for any transformation; the input adds none. Use
  `[@metadata][splunk_hec][id]` as `document_id` for idempotent outputs
  ([examples/pipeline.conf](../examples/pipeline.conf)).

### 8.2 Persistent queue sizing

A persistent queue **rejects any single event larger than `queue.page_capacity`**
(Logstash default 64 MB). If it is smaller than the biggest event, a TCP forwarder
retries the same record forever. Keep `queue.page_capacity` comfortably above
`s2s_tcp_max_event_bytes` and `max_event_bytes`, and `queue.max_bytes` large enough
for your backlog.

### 8.3 Host and container

- Open `port` (and `s2s_tcp_port` if enabled) in the firewall/security group and map
  both in Docker (`-p 8088:8088 -p 9997:9997`).
- Mount `state_directory` on persistent storage; run one Logstash instance per
  directory.
- The JDK `keytool` bundled with Logstash is used once to create the identity.
- Pre-9.5 Logstash is refused at plugin load.

## 9. Sender configuration

### 9.1 UF/HF `httpout` (S2S over HTTP)

```ini
# outputs.conf on the forwarder
[httpout]
httpEventCollectorToken = <token from tokens_json / inputs.conf>
uri = https://logs.example.test:8088
batchSize = 65536
batchTimeout = 5
sslVerifyServerCert = true
sslVerifyServerName = true

[indexAndForward]            ; heavy forwarders only
index = false
```

```ini
# server.conf on the forwarder: trust the generated certificate
[sslConfig]
sslRootCAPath = /etc/splunk/certs/hec-server.crt
```

The token must have `useACK = false`. Do not restrict `indexes` unless you list
every index the forwarder sends (heavy forwarders also send internal indexes).

### 9.2 UF/HF `tcpout` (classic)

Plaintext (the plugin's default for TCP):

```ini
[tcpout]
defaultGroup = logstash

[tcpout:logstash]
server = logs.example.test:9997
sendCookedData = true
useACK = true
```

TLS (requires `s2s_tcp_ssl_enabled => true` on the plugin):

```ini
[tcpout:logstash]
server = logs.example.test:9997
sendCookedData = true
useACK = true
useSSL = true
sslVerifyServerCert = true
sslVerifyServerName = true
```

The TLS form also needs the same `server.conf [sslConfig] sslRootCAPath` as above. The sender
setting must match the listener: a TLS sender cannot talk to a plaintext listener and vice versa.
`compressed` is optional. If you enabled mTLS, present a client certificate with `clientCert = <pem>` (this
sender-side mTLS setting was **not** exercised with a live forwarder). `sendCookedData = false` (uncooked) is **not supported**.

### 9.3 Generic HEC clients

```sh
curl --cacert hec-server.crt -H "Authorization: Splunk $TOKEN" \
  https://logs.example.test:8088/services/collector/event \
  -d '{"event":{"message":"native"},"time":"1700000000.123456789"}'

curl --cacert hec-server.crt -H "Authorization: Splunk $TOKEN" \
  "https://logs.example.test:8088/services/collector/raw?sourcetype=app" --data-binary @file.log
```

See [http-endpoints.md](http-endpoints.md) for every route, alias and error code.

## 10. Output shape

The input preserves HEC-native fields: `event`, `time`,
`host`, `source`, `sourcetype`, `index`, `fields`, plus Logstash's `@timestamp`,
`@version`, `@metadata`. No `message`, ECS fields, flattening or guessed multiline.

| Location | Contents |
|---|---|
| `fields` | Typed indexed fields/measurements, with literal names and ordered multivalues |
| `s2s_metadata` | Opt-in selected per-record metadata strings; searchable, independent of provenance mode |
| `@metadata.splunk_hec.id` | S2S event identity (`s2s-v1:<sha256>`) for idempotent outputs (S2S over HTTP and TCP) |
| `@metadata.splunk_hec.s2s` | Wire provenance: channel, flags, stream/offset/sequence, `date_parts`, timezone, CSV header, `wire_metadata` (including `resent`), `identity_scope` |
| `@metadata.splunk_hec.tcp` | TCP only: `protocol`, `sender_guid`, `sender_hostname`, `management_port`, `peer_ip`, `compression_requested`, `stream_compressed`, `ack_requested`, `forwarder_info`, `event_id` |

`@metadata` is not written by most outputs; copy fields you want to keep in a
filter. Set `hec_metadata => "id_only"` or `"none"` to attach less (or nothing) when you do not
need the provenance; `@timestamp` and `@version` always remain. HEC event/raw requests carry no `@metadata.splunk_hec` entry. Numbers are
lossless (`BigInteger`/`BigDecimal` when needed). Source `time` is kept separately
from `@timestamp`.

## 11. Startup validation errors

| Message | Cause |
|---|---|
| `Unknown setting '<x>' specified for plugin 'splunk_hec'` | Misspelled option, or `codec` |
| `port must be 1..65535` | Bad `port` |
| `S2S TCP port must be distinct and within 1..65535` | `s2s_tcp_port` equals `port` or is out of range |
| `TCP default index must not be blank` / `must be allowed` / `empty TCP allowed index` | `s2s_tcp_default_index`/`s2s_tcp_indexes` |
| `s2s_tcp_max_event_bytes must not be negative` / `must not exceed max_expanded_bytes` | TCP cap |
| `inconsistent positive resource limits` | A limit is ≤ 0 or violates a constraint in 3.5 |
| `TLS material requires TLS enabled` | Keystore/certificate/key/client CA supplied while **neither** listener uses TLS |
| `ssl_client_authentication requires ssl_enabled` | mTLS requested on a plaintext HTTP listener |
| `s2s_tcp_ssl_client_authentication requires s2s_tcp_ssl_enabled and s2s_tcp_enabled` | mTLS requested on a plaintext or disabled TCP listener |
| `hec_metadata must be full, id_only or none` | Bad `hec_metadata` value |
| `s2s_metadata_fields_json requires a JSON object ...` | Invalid mapping; see 3.4b. Diagnostic omits configured names/values |
| `choose keystore or PEM` / `both PEM certificate and PKCS8 key required` | Conflicting/missing TLS inputs |
| `server certificate requires SANs` / `certificate and key mismatch` | Bad identity |
| `mTLS requires an explicit client CA` | Client authentication without `ssl_client_ca` |
| `existing TLS identity unreadable; refusing regeneration` | Damaged `identity/` (never silently recreated) |
| `ACK state already owned` | Two inputs (or two Logstash processes) use the same `state_directory`; give each its own |
| `invalid inline token JSON` / `unknown inline token key` / `duplicate token identity` | `tokens_json` problems |
| `invalid maxIdleTime` / `invalid boolean <key>` | Policy value types |

Run `bin/logstash -t -f pipeline.conf` to validate a configuration.

## 12. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Sender cannot connect to 9997 / handshake errors | TLS mismatch: the sender's `useSSL` must match `s2s_tcp_ssl_enabled` (default off) |
| Startup warning "plaintext" | A listener has TLS off; expected for the TCP default |
| Sender gets `401/403` | Missing/invalid token or `disabled`; check `tokens_json`/`inputs_conf` and the log line `token reload rejected` |
| Sender gets `400` code 6 | Malformed body; S2S batches are all-or-nothing, nothing was queued |
| Sender gets `503` code 9 | Slots or memory exhausted (slow outputs, small limits); retry is safe |
| TLS errors on the sender | Certificate not trusted, or the name is not in `ssl_self_signed_sans`. SANs cannot be changed after first start: remove `identity/` deliberately and redistribute `server.crt` |
| Log: `S2S TCP connection closed ... event above s2s_tcp_max_event_bytes` | Raise the cap (and `queue.page_capacity`) |
| Log: `... QueueRuntimeException ... queue.page_capacity` | An event is larger than the persistent-queue page; raise `queue.page_capacity` |
| Duplicates after a forwarder restart | Expected at-least-once; use the `@metadata.splunk_hec.id` as `document_id` |
| Nothing arrives on 9997 | `s2s_tcp_enabled` is false, port not published/open, or the sender uses uncooked mode |
| `ACK` poll returns `false` after Logstash restart | By design; old IDs are unknown after restart |

## 13. What was tested

The option names, defaults and examples in this document were validated by
`logstash -t` on the packaged gem, and a unit test asserts every configuration
option is documented here. Live forwarder coverage (UF/HF 10.6.1.1, Logstash
9.5.0/9.5.5) is summarised in [validation-status.md](validation-status.md); the
evidence files in `tests/interop/evidence/` name the exact gem digest.
