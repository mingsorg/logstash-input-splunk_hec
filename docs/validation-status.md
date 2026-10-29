# Current validation status

The plugin is packaged as `logstash-input-splunk_hec-0.1.0-java.gem`. It is a
preview with finite compatibility coverage, not complete Splunk equivalence.
Each evidence file below records the SHA-256 of the gem it exercised; compare it
with `sha256sum logstash-input-splunk_hec-0.1.0-java.gem` before relying on it.

## Passing on the reviewed implementation

- 66 Java tests (counted from the Gradle test reports): saved real-Splunk HTTP corpus replay, captured UF/HF HTTP bodies,
  native value precision, S2S HTTP framing/identity, TLS/mTLS, queue-failure ACK
  behavior, `100-continue`, write deadlines, lifecycle regressions, and the
  classic-TCP protocol/server tests that replay eight real captured UF/HF streams
  (plain and verified TLS, compressed and uncompressed).
- 14 Python build/fixture regression tests, including a check that every plugin option and policy key is documented in `configuration.md` with its source default.
- `install-check.json`: on the pinned 9.5.0 and 9.5.5 images the gem installs, is listed, validates, serves verified TLS
  and accepts an event with a token, rejects a request without one, reinstalls, and removes cleanly; the documented
  Dockerfile builds (named state volume writable); Logstash 9.4.0 rejects the install.
- `config-check.json`: every `splunk_hec` snippet in the configuration reference passes `logstash -t` with the packaged gem on Logstash 9.5.0 and 9.5.5, and 12 documented startup errors (unknown option, `codec`, port clash, inconsistent limits, TLS misuse, token JSON, shared state directory, ...) are rejected with the documented messages.
- Packaged installation and trusted HTTPS on Logstash 9.5.0 and 9.5.5 with
  memory and persistent queues (`runtime.json`), actual Event/PQ recovery of exact
  numerics and timestamps, ACK reset and TLS identity reuse after a crash.
- Two clean builds of the reviewed source produced byte-identical gems
  (`reproducibility.json`).

## Per-listener TLS and provenance control

- `ssl_enabled` (HEC, default on) and `s2s_tcp_ssl_enabled` (TCP, default **off**) are independent, as are the two
  client-authentication switches; certificate material is shared. Java tests start real inputs in all four
  combinations and check which port speaks TLS, and that inconsistent settings fail at startup. The live UF/HF
  matrix exercises TCP TLS (verified hostname) and the plaintext **default** (option omitted).
- `hec_metadata` (`full`, `id_only`, `none`): a Java test shows the event ID is identical in `full` and `id_only`
  and that `none` attaches no `@metadata`; real UF runs in both reduced modes still deliver all six events with the
  expected `@metadata` (`tcp-senders.json`). `@timestamp` and `@version` are always present.

## Defects found while writing the installation guide

Testing the documented install flow in real Logstash containers found three packaging problems, now fixed and
covered by `install_check.py` (`install-check.json`):

- After a successful install, `logstash-plugin list` did **not** show the plugin, because the gem did not contain
  its own `.gemspec` (Logstash reads the plugin metadata from it). It is now shipped inside the gem.
- Once Logstash could see the plugin metadata it treated it as a Java plugin and required exactly one jar on the
  gem's require paths named `<gem>-<version>.jar`. `vendor/jars` is now a require path.
- A Logstash older than 9.5.0 accepted the install and failed later with "Couldn't find any input plugin". The gem
  now depends on `logstash-core >= 9.5.0`, so a real **Logstash 9.4.0** rejects the install with a version
  conflict (previously only simulated by injecting a runtime identity).

Also documented from observation: installs need rubygems.org even for a local gem; fully offline installs fail by
Logstash's own design, so the Docker-image route is the air-gapped path.

## Defects found while documenting configuration

Writing the configuration reference and validating it with `logstash -t` showed the
plugin rejected Logstash's standard `id`, `enable_metric`, `add_field`, `tags` and
`type` options. They are now accepted (a unit test and the live `logstash -t`
check cover this and confirm `type`/`tags`/`add_field` are applied); `codec`
remains deliberately unsupported.

## Real sender evidence

- HTTP (`senders.json`): UF and HF 10.6.1.1 `httpout` through a recording relay to
  the plugin and a real HEC oracle: malformed-batch retries, identical-body
  replay with stable IDs, and direct sender trust **and** hostname verification.
  Fixtures start the real Splunk daemon through its native CLI with a readiness
  marker instead of the slow Ansible entrypoint.
- Classic TCP (`tcp-senders.json`): UF and HF 10.6.1.1 connect directly to the
  plugin. Matrix: compressed on/off x `useACK` on/off x verified TLS/test-only
  plaintext (16 runs, six source events each, no loss or duplication), a receiver
  `SIGKILL` and restart on the same persistent queue/TLS identity while an
  ACK-enabled compressed TLS UF stayed running (all events written during the
  outage arrived with stable IDs), and a reduced TLS set on Logstash 9.5.0.
  `python3 tests/tcp/check.py` verifies completeness and the gem digest.
- Wire facts were captured from the same senders against a real Splunk indexer
  (`tests/tcp/evidence/decoded-capture*.json`): source values match the oracle and
  every positive event ID is covered by a real reverse ACK.

## Limits of the evidence

Senders and the oracle run amd64 under emulation on Apple Silicon; Logstash ran
linux/arm64. Datasets are small synthetic files. Throughput, long-duration soak
and heap behavior are not measured. See [compatibility](compatibility.md) and
[S2S TCP](s2s-tcp.md) for unsupported modes.
