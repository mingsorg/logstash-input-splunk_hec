# UF → Logstash → Splunk: complete reference configuration

Use this configuration set as the tested baseline for **UF → HTTPS HEC S2S →
Logstash → HTTPS HEC → Splunk indexer**, preserving the forwarder's original
indexes, raw payloads and standard source metadata, and adding two indexed route
markers in the downstream pipeline. It includes the companion
files needed to forward `_internal` and `_audit`, not just the application logs.

The live reference uses UF/Splunk **10.6.1.1** and Logstash **9.5.5 / Java 21**.
Install the plugin using the [installation guide](installation.md). For individual
plugin options, see the [configuration reference](configuration.md).

The [existing Docker test lab folder](https://github.com/mingsorg/logstash-input-splunk_hec/tree/main/docker/test-lab) stores the
configuration files, a Compose topology reference, equivalent bootstrap sources
and read-only inspection/validation commands. It documents the current manually
created environment; it does not require building or starting a replacement lab.

## 1. Topology, identities and file locations

```mermaid
flowchart LR
    UF[Universal Forwarder] -->|HTTPS /services/collector/s2s| LS[Logstash splunk_hec input]
    LS --> PQ[Persistent queue and envelope filter]
    PQ -->|HTTPS /services/collector/event| IDX[Splunk indexer]
```

The local Docker network is `hec-demo-chain`. These are its service names and
loopback-published host ports; the two data-plane services both use port 8088
inside their separate containers.

| Service | Container/network name | Access from the host |
|---|---|---|
| UF | `hec-demo-uf` | No published port |
| Logstash HTTPS input | `hec-demo-logstash:8088` | `https://localhost:18888` |
| Indexer HTTPS HEC | `hec-demo-indexer:8088` | `https://localhost:19088` |
| Splunk Web | `hec-demo-indexer:8000` | `http://localhost:18000` |
| Splunk management API | `hec-demo-indexer:8089` | `https://localhost:19089` |

### Credentials

Replace the token placeholders in the INI files before deploying them. They are
not environment-variable syntax for Splunk configuration files.

| Value | Used by |
|---|---|
| `<UF_TO_LOGSTASH_TOKEN>` | UF `httpEventCollectorToken` and Logstash's imported token-policy file; the values must match |
| `<LOGSTASH_TO_SPLUNK_TOKEN>` | Indexer HEC token; pass the same value to Logstash as the `SPLUNK_HEC_TOKEN` environment variable |
| Splunk Web administrator password | Interactive login to the indexer; separate from both HEC tokens |

The existing local demo stores these values in `../demo-hec-chain/connection.json`
relative to the repository root, outside Git, with mode 0600:

- `input_token`: UF → Logstash token.
- `indexer_hec_token`: Logstash → Splunk token.
- `username` / `password` / `url`: the Splunk Web login, currently user `admin`
  at `http://localhost:18000`.

Live passwords, HEC tokens and private keys are intentionally not reproduced in
this guide. Use the local connection file for that existing deployment and
provision separate credentials when deploying this reference elsewhere.

### Configuration and persistent mounts

| Component | Configuration location in its container |
|---|---|
| UF app | `/opt/splunkforwarder/etc/apps/hec_chain_demo/local/` |
| Indexer app | `/opt/splunk/etc/apps/hec_chain_demo/local/` |
| Logstash settings and pipeline | `/run-hec/config/` |
| Logstash imported token policy | `/demo/hec-inputs.conf` |
| Logstash input TLS identity and ACK state | `/run-hec/state/` |
| Logstash persistent queue | `/run-hec/data/` |
| Local decoded-event inspection output | `/run-hec/received.ndjson` |

In the local deployment, the host directory `../demo-hec-chain/` is mounted at
`/demo` read-only, and its `logstash/` subdirectory is also mounted read-write at
`/run-hec` in Logstash. Retain the indexer's and UF's attached `etc`/`var` volumes
and Logstash's state/data directories across restarts.

### TLS material

- Logstash generates and persists its input identity under
  `/run-hec/state/identity/`. Its SANs include `hec-demo-logstash` and `localhost`.
  Before first UF startup, copy its public `server.crt` to the UF app as
  `trusted-logstash.crt`.
- `/demo/tls/indexer.pem` is the indexer's server certificate and private key in
  PEM form. Its certificate SANs include `hec-demo-indexer` and `localhost`.
- `/demo/tls/indexer.crt` is the public certificate trusted by Logstash's HTTP
  output. The local indexer certificate is self-signed and has a 30-day lifetime.
- Both data-plane hops verify certificate trust **and** hostname. Changing a
  hostname requires matching certificates and trust distribution; changing the
  input SAN option does not replace an already persisted Logstash identity.

## 2. Universal Forwarder configuration

Place these files under the UF app's `local/` directory identified above.

### `outputs.conf`

<!-- reference-config: uf/outputs.conf -->
```ini
[httpout]
httpEventCollectorToken = <UF_TO_LOGSTASH_TOKEN>
uri = https://hec-demo-logstash:8088
sslVerifyServerCert = true
sslVerifyServerName = true
batchSize = 65536
batchTimeout = 1

[tcpout]
forwardedindex.filter.disable = true

[indexAndForward]
index = false
```

`[httpout]` selects native S2S-over-HTTP forwarding. The `[tcpout]` setting
disables the UF's index filter; there is no configured classic TCP destination.
All indexes produced by the **configured inputs** are eligible for forwarding.
This does not monitor every file on the forwarder's filesystem automatically.

### `inputs.conf`

<!-- reference-config: uf/inputs.conf -->
```ini
[monitor://$SPLUNK_HOME/var/log/splunk]
disabled = false
index = _internal
blacklist = audit(?:_v2)?\.log(?:\.\d+)?$

[monitor://$SPLUNK_HOME/var/log/splunk/audit.log]
disabled = false
index = _audit
sourcetype = audittrail
crcSalt = <SOURCE>:hec-chain-audit-enabled-v1

[monitor://$SPLUNK_HOME/var/log/splunk/audit_v2.log]
disabled = false
index = _audit
sourcetype = audittrailv2
crcSalt = <SOURCE>:hec-chain-audit-enabled-v1

[monitor:///tmp/hec-chain.log]
disabled = false
index = hec_demo
sourcetype = hec_chain_text
crcSalt = <SOURCE>

[monitor:///tmp/hec-chain.json]
disabled = false
index = hec_demo
sourcetype = hec_chain_json
crcSalt = <SOURCE>
```

The parent log monitor excludes audit filenames so the explicit audit monitors
can route them to `_audit`. Other built-in, more-specific UF input stanzas retain
their native index assignments, including configuration-change events destined
for `_configtracker`. Use `btool inputs list --debug` to inspect the merged input
configuration rather than assuming this app file replaces all vendor defaults.

`<SOURCE>` is Splunk's literal CRC-salt syntax, not a secret placeholder. The
audit salt suffix above was introduced once to reread the audit files after
fixing the indexer discard rule. Keep it stable afterward: changing CRC salts
can reread files and duplicate data.

The `/tmp/hec-chain.*` monitors are the demonstration sources. The local demo
appends a text event every five seconds and a JSON event every thirty seconds.
Replace or extend those monitor stanzas for your own application sources.

### `props.conf`

<!-- reference-config: uf/props.conf -->
```ini
[hec_chain_text]
SHOULD_LINEMERGE = false
DATETIME_CONFIG = CURRENT

[hec_chain_json]
INDEXED_EXTRACTIONS = json
TIMESTAMP_FIELDS = time
TIME_FORMAT = %s.%9N
SHOULD_LINEMERGE = false
```

These parsing decisions belong to the forwarder. Logstash preserves the decoded
raw text/JSON string, typed indexed fields and the source-provided timestamp;
it does not infer a timestamp from the raw log text.

### `server.conf`

<!-- reference-config: uf/server.conf -->
```ini
[sslConfig]
sslRootCAPath = /opt/splunkforwarder/etc/apps/hec_chain_demo/local/trusted-logstash.crt
[kvstore]
disabled = true
```

### `limits.conf`

<!-- reference-config: uf/limits.conf -->
```ini
[thruput]
maxKBps = 0
```

The demo removes the UF throughput cap. It is not a measured throughput claim.

### `web.conf`

<!-- reference-config: uf/web.conf -->
```ini
[settings]
startwebserver = false
```

## 3. Logstash configuration

### `/demo/hec-inputs.conf`: input token policy

<!-- reference-config: logstash/hec-inputs.conf -->
```ini
[http://uf-demo]
disabled = false
token = <UF_TO_LOGSTASH_TOKEN>
index = hec_demo
useACK = false
```

There is no `indexes` allowlist. `hec_demo` is a fallback only: a decoded event's
native `_internal`, `_audit` or other index takes precedence. The plugin imports
this one explicitly named file, not Splunk app-directory precedence.

### `/run-hec/config/pipeline.conf`

<!-- reference-config: logstash/pipeline.conf -->
```logstash
input {
  splunk_hec {
    id => "uf-hec-s2s-input"
    host => "0.0.0.0"
    port => 8088
    # UF also sends large internal records alongside monitored source data.
    # Accept those batches rather than wedging the forwarder's shared httpout queue.
    max_event_bytes => 8388608
    max_inflight_bytes => 536870912
    state_directory => "/run-hec/state"
    ssl_self_signed_sans => "dns:localhost,dns:hec-demo-logstash,ip:127.0.0.1"
    inputs_conf => "/demo/hec-inputs.conf"
    s2s_metadata_fields_json => '{"_path":"path","crcSalt":"salt"}'
  }
}
filter {
  # Forward every received index, including _internal and _audit. Preserve
  # the UF's original index in the outbound HEC envelope.
  # Construct a valid outbound HEC envelope from the native input fields.
  # The original raw text/JSON and source metadata pass through unchanged.
  ruby {
    code => '
      body = {}
      ["event", "time", "host", "source", "sourcetype", "index", "fields"].each do |key|
        value = event.get(key)
        body[key] = value unless value.nil?
      end
      # HEC indexed fields survive into Splunk; a root Logstash tags/demo_path
      # field would be omitted from this explicitly constructed HEC envelope.
      indexed = (body["fields"] || {}).dup
      indexed["ingest_via"] = "logstash"
      indexed["logstash_pipeline"] = "uf_hec_s2s_to_splunk"
      body["fields"] = indexed
      event.set("[fields]", indexed)
      event.set("[@metadata][hec_body]", LogStash::Json.dump(body))
      event.set("demo_path", "UF -> HEC S2S -> Logstash -> HEC -> Splunk")
    '
  }
}
output {
  http {
    id => "splunk-indexer-hec-output"
    url => "https://hec-demo-indexer:8088/services/collector/event"
    http_method => "post"
    format => "message"
    message => "%{[@metadata][hec_body]}"
    content_type => "application/json"
    headers => { "Authorization" => "Splunk ${SPLUNK_HEC_TOKEN}" }
    ssl_enabled => true
    ssl_certificate_authorities => ["/demo/tls/indexer.crt"]
    connect_timeout => 10
    socket_timeout => 30
    request_timeout => 60
    retry_failed => true
  }
  file {
    path => "/run-hec/received.ndjson"
    codec => json_lines
    flush_interval => 0
  }
}
```

Set `SPLUNK_HEC_TOKEN` in the Logstash process/container environment to
`<LOGSTASH_TO_SPLUNK_TOKEN>`. The output uses standard HEC JSON envelopes; the
forwarder-to-input hop uses binary HEC S2S. No index-dropping filter is present.

The input's 8 MiB logical-event cap and 512 MiB allocation-accounting budget admit
large UF internal records alongside application data. These are explicit demo
settings, not new plugin defaults or a JVM heap-size guarantee.

The outbound envelope contains only `event`, `time`, `host`, `source`,
`sourcetype`, `index` and `fields` when present. The filter preserves existing
indexed fields and adds `fields.ingest_via = "logstash"` and
`fields.logstash_pipeline = "uf_hec_s2s_to_splunk"`. Those names are reserved for
the route markers in this pipeline; existing producer values with those exact
names are overwritten deliberately. Splunk exposes them as searchable fields
`ingest_via` and `logstash_pipeline`, rather than nested `fields.*` fields.

`s2s_metadata` and `demo_path` are
visible in the local file output, but are **not** added to the outbound HEC
envelope. Diagnostic protocol provenance stays in Logstash `@metadata`.

### `/run-hec/config/logstash.yml`

<!-- reference-config: logstash/logstash.yml -->
```yaml
pipeline.workers: 1
pipeline.batch.size: 1
api.enabled: false
xpack.monitoring.enabled: false
path.data: /run-hec/data
path.logs: /run-hec/logs
queue.type: persisted
queue.max_bytes: 256mb
queue.page_capacity: 16mb
queue.checkpoint.writes: 1
queue.checkpoint.acks: 1
```

The queue page must accommodate the serialized Logstash event, including its
overhead. The 16 MiB page above handled the observed internal records; retain
both the queue data and plugin state directories across restarts.

### `/run-hec/config/pipelines.yml`

<!-- reference-config: logstash/pipelines.yml -->
```yaml
- pipeline.id: uf_hec_s2s_to_splunk
  path.config: /run-hec/config/pipeline.conf
```

## 4. Splunk indexer configuration

Place these files under `/opt/splunk/etc/apps/hec_chain_demo/local/`.

### `inputs.conf`

<!-- reference-config: indexer/inputs.conf -->
```ini
[http]
disabled = false
enableSSL = true
port = 8088
serverCert = /demo/tls/indexer.pem

[http://logstash-demo]
disabled = false
token = <LOGSTASH_TO_SPLUNK_TOKEN>
index = hec_demo
sourcetype = hec_chain_text
```

There is deliberately no `indexes` allowlist on this HEC token. The incoming
envelope's index and sourcetype override these defaults. All destination indexes
must exist; forwarding an index name does not create it automatically.

### `props.conf`: required audit-file override

<!-- reference-config: indexer/props.conf -->
```ini
[source::/opt/splunkforwarder/var/log/splunk/audit.log]
TRANSFORMS =
sourcetype = audittrail
SHOULD_LINEMERGE = false

[source::/opt/splunkforwarder/var/log/splunk/audit_v2.log]
TRANSFORMS =
sourcetype = audittrailv2
SHOULD_LINEMERGE = false
```

**Keep this companion file.** In the tested Splunk distribution, default source
rules matching `.../var/log/splunk/audit.log` and `audit_v2.log` apply
`TRANSFORMS = send_to_nullqueue`. Audit data can therefore reach Logstash, receive
HEC acceptance from the indexer, and still be discarded during indexer parsing.

The exact-source overrides above clear that transform for the UF paths only.
Adapt them to the actual incoming `source` values when changing UF installation
paths. This is an indexer parsing rule, not a plugin decoding limitation.

### `fields.conf`: searchable indexed route markers

<!-- reference-config: indexer/fields.conf -->
```ini
[ingest_via]
INDEXED = true

[logstash_pipeline]
INDEXED = true
```

The route fields are added to the HEC envelope by the Logstash filter, not the
UF or indexer's token defaults. These definitions identify them as indexed
fields for Splunk searches. `field::value` syntax can also explicitly search
their indexed terms.

### `indexes.conf`

<!-- reference-config: indexer/indexes.conf -->
```ini
[hec_demo]
homePath = $SPLUNK_DB/hec_demo/db
coldPath = $SPLUNK_DB/hec_demo/colddb
thawedPath = $SPLUNK_DB/hec_demo/thaweddb
```

The tested indexer already provides `_internal`, `_audit` and `_configtracker`.
Provision additional application indexes explicitly before forwarding to them.

### `web.conf`

<!-- reference-config: indexer/web.conf -->
```ini
[settings]
startwebserver = true
httpport = 8000
enableSplunkWebSSL = false
```

The local demo publishes this HTTP web interface on loopback port 18000. The
data-plane HEC service remains HTTPS. Use the credentials provisioned for this
indexer; its Web password is not a HEC token.

### `server.conf`

<!-- reference-config: indexer/server.conf -->
```ini
[kvstore]
disabled = true
```

KV Store is disabled in this lightweight local demo. Features that depend on it
are outside this configuration's verified search/ingestion scope.

## 5. Start, verify and troubleshoot

### Startup order

1. Install the built Java input gem into Logstash and deploy the files above.
2. Start the indexer with its index, HEC token, TLS identity and audit overrides.
3. Start Logstash with persistent mounts, its input token file and the output's
   `SPLUNK_HEC_TOKEN` environment variable.
4. Distribute Logstash's public input certificate to the UF and start the UF.
5. Verify actual indexer search results, not just HTTP health or acceptance.

Restarting a container does not inject changed environment variables; recreate
the affected container with its retained volumes when changing those variables.
For configuration files, use the appropriate service reload/restart. A password
used to seed the initial Splunk administrator account does not rotate an existing
account merely by changing the startup environment.

### Inspect effective Splunk configuration

Run from the Docker host for this existing deployment:

```sh
docker exec --user splunk hec-demo-uf \
  /opt/splunkforwarder/bin/splunk btool outputs list --debug
docker exec --user splunk hec-demo-uf \
  /opt/splunkforwarder/bin/splunk btool inputs list --debug
docker exec --user splunk hec-demo-indexer \
  /opt/splunk/bin/splunk btool inputs list --debug
docker exec --user splunk hec-demo-indexer \
  /opt/splunk/bin/splunk btool props list --debug
```

These commands can display token values or encrypted token material; keep their
output with the deployment credentials rather than publishing it as documentation.

### Search for the forwarder's events

Get the UF hostname, which is different from the indexer's hostname:

```sh
docker inspect hec-demo-uf --format '{{.Config.Hostname}}'
```

In Splunk Web, select **All time**, replace `<UF_HOST>` with that hostname, and run:

```spl
(index=* OR index=_*) host="<UF_HOST>"
| stats count by index sourcetype source
```

For internal and audit events specifically:

```spl
(index=_internal OR index=_audit) host="<UF_HOST>"
| stats count by index sourcetype source
```

Filter on the UF host so the indexer's own internal/audit events do not produce a
false positive. Live checking on 2026-10-30 confirmed UF-originated `_internal`,
`_audit`, `_configtracker` and `hec_demo` events after the all-index changes. Other
indexes are permitted, but only appear in searches when configured inputs emit
events for them.

### Prove that new events passed through Logstash

The route markers are included in every outbound HEC event after deploying the
filter. Use this search to verify UF-originated internal events:

```spl
index=_internal host="<UF_HOST>"
ingest_via::logstash logstash_pipeline::uf_hec_s2s_to_splunk
| stats count by host source sourcetype ingest_via logstash_pipeline
```

To inspect all tagged indexes and individual raw events:

```spl
(index=* OR index=_*) host="<UF_HOST>"
ingest_via::logstash logstash_pipeline::uf_hec_s2s_to_splunk
| stats count by index ingest_via logstash_pipeline
```

```spl
index=_internal host="<UF_HOST>" ingest_via::logstash
| table _time host source sourcetype ingest_via logstash_pipeline _raw
```

The original `_raw` text is unchanged; the markers are separate HEC indexed
fields. Old indexed events are not retroactively tagged. Use a time range after
the marker was deployed when checking that new traffic has the fields.

For configuration-level corroboration, the UF's effective `[httpout]` URI points
only to `hec-demo-logstash:8088`; the Logstash HTTP output points to the indexer.
Together with the filter-added markers and matching local decoded output, this
demonstrates the observed route in this controlled setup. The fields are an
operational tracing marker, not a cryptographic attestation against other
writers authorized to submit the same indexed field names.

Live route verification found tagged UF events in `_internal`, `_audit` and
`hec_demo`, including a `splunkd.log` event whose `_raw` text remained unchanged.
The local `../demo-hec-chain/route-verification.json` records the searches,
per-index counts, an indexed sample and matching Logstash inspection output.

The original demo-only chain has retained
[artifact-specific evidence](../tests/interop/evidence/hec-chain-demo.json).
The subsequent all-index check and its per-source counts are saved locally in
`../demo-hec-chain/all-index-verification.json` relative to the repository root;
that local file and its verification script are outside the plugin repository.

### Common failure points

| Symptom | Check |
|---|---|
| Only `hec_demo` is visible | No Logstash index-dropping filter; no restrictive `indexes` entries in either HEC token policy; UF log monitors enabled |
| UF `_internal` missing | Search explicitly with `index=_internal` and UF host; inspect effective input and forwarding settings |
| Audit seen in Logstash but missing from `_audit` | Indexer default audit-source `nullQueue` transform; exact-source override must match incoming `source` |
| No new events after a large internal record | Sender HTTP status and input admission limits; this reference raises the HTTP cap explicitly |
| HEC 401/403 | Match the correct token for each hop; the two tokens and Web password are separate |
| TLS failure | Certificate trust, SAN/hostname, expiration and readable mounted public certificates |
| HEC accepts but an application index stays empty | Destination index exists and is allowed; inspect parsing transforms and search time range |

## 6. Using this as a golden baseline

Version and deploy the **whole configuration set**, including the certificate
distribution, token policy, audit-source overrides and persistent mounts. Preserve
the original index in the outbound envelope and verify new source types with
UF-host-specific indexer searches.

This is a qualified **functional reference**, with these deployment decisions
still to make before adopting it as a production standard:

| Area | Reference setting and qualification boundary |
|---|---|
| Versions | Live chain: UF/Splunk 10.6.1.1, Logstash 9.5.5; use `versions.properties` for pinned image identities |
| TLS | Generated/self-signed identities; replace with managed certificates and renewal appropriate to the deployment |
| Index authorization | All configured indexes allowed, as requested; retain or constrain deliberately for the intended sources |
| Delivery | `useACK=false` on the UF → Logstash token; ordinary HTTP output with retries, no downstream HEC ACK polling or exactly-once guarantee |
| Queue/disk | Persistent queue with small-demo sizing; local inspection output has no rotation configured |
| Performance | One worker, batch size one, frequent checkpoints; throughput, long-duration soak and HA are not qualified by this demo |
| UI/management | Loopback-published local UI/API; Web uses HTTP and KV Store is disabled |
| Credentials | Supply per-deployment secrets; do not distribute the live demo login, tokens or private keys as configuration examples |

HEC success confirms acceptance at that hop, not final indexing. The audit
discard case above demonstrates why indexer search verification is part of this
baseline. See [validation status](validation-status.md) and
[compatibility](compatibility.md) for the plugin's wider evidence boundaries.
