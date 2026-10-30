# Installation guide

How to build the `splunk_hec` input and install it into Logstash: from a source checkout,
onto a package/tarball Logstash, into a Docker image, and on Kubernetes. It also covers
first-run verification, upgrade, removal and troubleshooting.

Each step is marked **Verified** when it was run for this guide in the official Logstash
containers (see [What was verified](#12-what-was-verified)) or **Not tested here** when it
relies on standard Logstash/OS behaviour that was not exercised in this project.

Contents: [1 Requirements](#1-requirements) · [2 Get the gem](#2-get-the-gem-build-from-source) ·
[3 Choose an install method](#3-choose-an-install-method) · [4 Package or tarball Logstash](#4-install-on-a-linux-logstash-package-or-tarball) ·
[5 Docker](#5-install-into-a-docker-image) · [6 Kubernetes](#6-kubernetes) ·
[7 First pipeline](#7-your-first-pipeline) · [8 Verify](#8-verify-the-installation) ·
[9 Connect forwarders](#9-connect-forwarders) · [10 Upgrade and remove](#10-upgrade-and-remove) ·
[11 Troubleshooting](#11-troubleshooting) · [12 What was verified](#12-what-was-verified)

## 1. Requirements

| Item | Requirement |
|---|---|
| Logstash | **9.5.0 or newer.** Older versions are refused at install time (see 11). Tested: 9.5.0 and 9.5.5 |
| Java | Logstash's **bundled JDK (21)**; no system Java is needed to run the plugin |
| Network at install time | `logstash-plugin install` must reach **rubygems.org** (or an internal mirror) to resolve the plugin's dependencies, even for a local `.gem` file. **Fully offline installs fail**, see 3 |
| Build host (only to build the gem) | Git, **Docker**, a **JDK 21 or newer** for Gradle (JDK 23 was used), Python 3, network for the first dependency download |
| Open ports | `8088/tcp` HEC (TLS by default) and, if enabled, `9997/tcp` classic S2S |

The gem bundles its own dependencies in one jar; it does not need Elasticsearch or extra Ruby gems
beyond what Logstash already ships.

## 2. Get the gem (build from source)

There is no published release; build the gem from the repository.

```sh
git clone https://github.com/mingsorg/logstash-input-splunk_hec.git     # private repo: needs access
cd logstash-input-splunk_hec
./gradlew test gem
ls -l logstash-input-splunk_hec-0.1.0-java.gem
sha256sum logstash-input-splunk_hec-0.1.0-java.gem
```

**Verified.** What the build does:

- `./gradlew test` runs the unit tests (needs the JDK; the first run downloads Gradle and dependencies,
  all checksum-pinned).
- `gem` compiles the plugin, bundles Jackson into one jar, and runs `gem build` inside the pinned Logstash
  image's JRuby with the network disabled. That is why Docker is required but no local Ruby is.
- The build is **reproducible**: two clean builds give byte-identical gems. `python3 scripts/check-reproducible.py`
  checks that and records the digest.

Compare the SHA-256 you build with the one in `tests/interop/evidence/*.json` for the commit you are using
if you want to confirm you built the qualified artifact.

Copy the `.gem` file to the Logstash host (scp, artifact store, image build context). Only this one file is
needed.

## 3. Choose an install method

| Where Logstash runs | Method | Section |
|---|---|---|
| Linux server from a `.deb`/`.rpm` package | `logstash-plugin install` as root | 4 |
| Tarball/zip unpacked in a directory | `bin/logstash-plugin install` | 4 |
| Docker / Compose | Bake the plugin into an image | 5 |
| Kubernetes | Bake into an image, run it as a Deployment/StatefulSet | 6 |
| **No internet access at all** | Build the Docker image on a connected machine, then ship the image | 5 |

**Why fully offline installs fail.** `logstash-plugin install` always resolves the plugin's dependencies
against a gem index. In a container with networking disabled the install aborts with
`Could not reach host index.rubygems.org`, with or without `--local` and `--no-verify` (**Verified**).
This is Logstash behaviour, not specific to this plugin. For air-gapped hosts build the image where the
internet is available and transfer the image. Behind a proxy, Logstash honours the standard `http_proxy` /
`https_proxy` environment variables (**Not tested here**).

## 4. Install on a Linux Logstash (package or tarball)

The commands are the ones verified in the official Logstash image; package and tarball layouts differ only in
where Logstash lives.

Package install (`/usr/share/logstash`):

```sh
sudo /usr/share/logstash/bin/logstash-plugin install /path/to/logstash-input-splunk_hec-0.1.0-java.gem
```

Tarball install (the directory you unpacked):

```sh
cd /opt/logstash-9.5.5
bin/logstash-plugin install /path/to/logstash-input-splunk_hec-0.1.0-java.gem
```

Expected output **(Verified)**:

```
Validating /path/to/logstash-input-splunk_hec-0.1.0-java.gem
Installing logstash-input-splunk_hec
Installation successful
```

Notes:

- Use the **absolute path** of the `.gem` file. A `file://` URL is **not** accepted (Logstash treats it as an
  offline pack and answers `the pack must be in zip format`).
- Run as root (packages) or as the user that owns the Logstash directory (tarball). Logstash records the
  plugin in its `Gemfile` and vendors it under `vendor/local_gems`.
- Re-running the same install is harmless (**Verified**).
- **Restart Logstash** after installing so a running service loads the plugin: `sudo systemctl restart logstash`
  (**Not tested here**; standard for package installs).
- Installing creates no configuration. Plugin settings live in your pipeline file (section 7).

## 5. Install into a Docker image

This is the recommended method for containers and the only practical one for air-gapped sites.

`docker/Dockerfile.logstash` in the repository is the file to use (**Verified**: built from the pinned
9.5.5 image, plugin listed, pipeline validated, certificate generated on a named volume):

```dockerfile
ARG LOGSTASH_IMAGE=docker.elastic.co/logstash/logstash:9.5.5
FROM ${LOGSTASH_IMAGE}
COPY --chown=logstash:logstash logstash-input-splunk_hec-0.1.0-java.gem /tmp/
RUN bin/logstash-plugin install /tmp/logstash-input-splunk_hec-0.1.0-java.gem \
 && rm /tmp/logstash-input-splunk_hec-0.1.0-java.gem
USER root
RUN install -d -o logstash -g logstash -m 0750 /var/lib/logstash/hec
USER logstash
EXPOSE 8088 9997
```

Build and run:

```sh
mkdir build-ctx && cp logstash-input-splunk_hec-0.1.0-java.gem docker/Dockerfile.logstash build-ctx/
docker build -f build-ctx/Dockerfile.logstash \
  --build-arg LOGSTASH_IMAGE=docker.elastic.co/logstash/logstash:9.5.5 \
  -t logstash-splunk-hec:0.1.0 build-ctx

docker run -d --name logstash-hec \
  -p 8088:8088 -p 9997:9997 \
  -v "$PWD/pipeline:/usr/share/logstash/pipeline:ro" \
  -v hec-state:/var/lib/logstash/hec \
  logstash-splunk-hec:0.1.0
```

Points that matter:

- **Mount a persistent volume for `state_directory`** (here `hec-state` at `/var/lib/logstash/hec`, with the
  input set to `state_directory => "/var/lib/logstash/hec"`). It holds the ACK counter and the generated TLS
  identity. If it is lost, a new certificate is generated and forwarders must trust it again, and the
  no-ID-reuse guarantee is void. The Dockerfile creates `/var/lib/logstash/hec` owned by the `logstash` user
  (uid 1000), so a **named volume** mounted there is writable (**Verified**). A bind mount keeps the host
  directory's ownership: `chown 1000:1000` it first.
- The image defaults to the Logstash user, so the plugin is installed without root.
- Pin the base image by digest (`@sha256:...`) in production for reproducible builds.
- A base image older than 9.5.0 makes the build fail at the install step (section 11).

Docker Compose:

```yaml
services:
  logstash:
    image: logstash-splunk-hec:0.1.0
    ports: ["8088:8088", "9997:9997"]
    volumes:
      - ./pipeline:/usr/share/logstash/pipeline:ro
      - hec-state:/var/lib/logstash/hec
volumes:
  hec-state:
```

To ship the image to an air-gapped host: `docker save logstash-splunk-hec:0.1.0 | gzip > hec.tar.gz`, then
`docker load < hec.tar.gz` there (**Not tested here**; standard Docker).

## 6. Kubernetes

**Not tested here.** Use the image from section 5 and note the plugin-specific requirements:

- Run **one replica per `state_directory`**. Two Logstash processes cannot share one directory (the second fails
  with `ACK state already owned`). For several replicas give each its own volume, for example a `StatefulSet`
  with `volumeClaimTemplates`.
- Mount the persistent volume at the `state_directory` path and make it writable by uid 1000
  (`securityContext: fsGroup: 1000`).
- Expose `8088` (HEC) and, if enabled, `9997` (S2S) through a `Service`. Forwarders keep long-lived TCP
  connections, so a layer-4 load balancer works and per-connection balancing is fine.
- Ship the generated certificate to forwarders (`<state_directory>/identity/server.crt`), or supply your own
  certificate from a `Secret` with `ssl_keystore` or `ssl_certificate`/`ssl_key`
  ([configuration reference](configuration.md#5-tls)).
- Put `tokens_json` in a `Secret` exposed as an environment variable and reference it as `${HEC_TOKENS_JSON}`.

## 7. Your first pipeline

Create `/etc/logstash/conf.d/hec.conf` (package install) or put the file in the pipeline directory you use:

```logstash
input {
  splunk_hec {
    id => "hec-main"                               # unique per input, shows in monitoring
    state_directory => "/var/lib/logstash/hec"     # persistent, writable by the logstash user
    tokens_json => '${HEC_TOKENS_JSON}'            # see below
    ssl_self_signed_sans => "dns:localhost,dns:logs.example.test,ip:10.0.0.5"
    # Optional classic Universal/Heavy Forwarder tcpout receiver (plaintext by default):
    # s2s_tcp_enabled => true
  }
}
output {
  stdout { codec => rubydebug }                    # replace with your real output
}
```

**State directory.** Create it before the first start and give it to the Logstash user:

```sh
sudo install -d -o logstash -g logstash -m 0750 /var/lib/logstash/hec
```

**Tokens.** `HEC_TOKENS_JSON` is a JSON array, for example
`[{"token":"11111111-1111-4111-8111-111111111111","index":"main","useACK":false}]`. Generate a real token
(for example `uuidgen`), and keep it out of the pipeline file. Use the Logstash keystore:

```sh
sudo -u logstash /usr/share/logstash/bin/logstash-keystore create
sudo -u logstash /usr/share/logstash/bin/logstash-keystore add HEC_TOKENS_JSON
```

(**Not tested here**; the `${VAR}` substitution itself was exercised with environment variables.) All policy
keys are in the [configuration reference](configuration.md#4-tokens-and-policy).

**Subject alternative names.** Set `ssl_self_signed_sans` to every DNS name and IP address the forwarders and
clients will use, **before the first start**: the certificate is generated once and reused.

**Validate, then start:**

```sh
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t   # Configuration OK
sudo systemctl restart logstash
sudo journalctl -u logstash -f        # or /var/log/logstash/logstash-plain.log
```

The first start creates `/var/lib/logstash/hec/identity/` containing `server.crt` (public), `server.p12` and
`password` (private). All three files are owned by the Logstash user with mode 0600, so read the
certificate with `sudo` when copying it to forwarders. Open port 8088 (and 9997) in the firewall.

At startup the plugin logs a WARN for any listener running without TLS (for example the default plaintext
TCP listener). That is expected and by design.

## 8. Verify the installation

Run these in order; all were **Verified** in Docker for Logstash 9.5.0 and 9.5.5.

1. The plugin is installed and listed:

   ```sh
   bin/logstash-plugin list --verbose splunk
   # logstash-input-splunk_hec (0.1.0)
   ```

2. The pipeline parses and the plugin options are valid:

   ```sh
   bin/logstash -t -f hec.conf
   # Configuration OK
   ```

3. After starting Logstash, the health endpoint answers over verified TLS (no token needed):

   ```sh
   curl --cacert /var/lib/logstash/hec/identity/server.crt \
        https://localhost:8088/services/collector/health
   # {"text":"HEC is healthy","code":17}
   ```

4. An event with a token is accepted and appears in the output:

   ```sh
   curl --cacert /var/lib/logstash/hec/identity/server.crt \
        -H "Authorization: Splunk $TOKEN" \
        https://localhost:8088/services/collector/event \
        -d '{"event":{"msg":"hello"},"sourcetype":"demo"}'
   # {"text":"Success","code":0}
   ```

   Logstash's output then shows `"event" => { "msg" => "hello" }`, `"sourcetype" => "demo"`, `"index" => "main"`.

5. A request **without** a token is refused with HTTP 401:

   ```sh
   curl -s -o /dev/null -w '%{http_code}\n' --cacert /var/lib/logstash/hec/identity/server.crt \
        https://localhost:8088/services/collector/event -d '{"event":"x"}'
   # 401
   ```

`curl` verifies both the certificate chain and the host name, so use a host name that is in
`ssl_self_signed_sans` (`localhost` is by default).

The script `python3 tests/interop/install_check.py` runs exactly these steps, plus reinstall, removal and the
Docker build, on both supported Logstash versions.

## 9. Connect forwarders

Copy `server.crt` from `<state_directory>/identity/` to each forwarder and point it at the listener. The
sender-side `outputs.conf` and `server.conf` for `httpout` (HTTPS, token) and `tcpout` (classic, plaintext or
TLS) are in the [configuration reference, section 9](configuration.md#9-sender-configuration) and in
[`examples/`](../examples/). Remember that the sender's TLS setting must match the listener:
HEC defaults to TLS, the TCP listener defaults to plaintext.

For a complete forwarding chain into a Splunk indexer, see the
[UF → Logstash → Splunk reference configuration](uf-logstash-splunk-reference.md).
It documents the UF and indexer apps, Logstash pipeline and persistent queue,
both TLS/token boundaries, and the settings required to retain `_internal` and
`_audit` through the destination HEC input.

To retain selected forwarder per-record metadata in output, add
`s2s_metadata_fields_json => '{"_path":"path","crcSalt":"salt"}'` to the input.
It applies to both transports and works even with `hec_metadata => "none"`.
The default `{}` leaves output unchanged. Only exact present wire keys become
string values inside `s2s_metadata`; typed indexed fields remain in `fields`,
and handshake provenance is separate. See the
[configuration contract](configuration.md#34b-searchable-s2s-metadata) for startup
validation, limits and event-ID limitations, and
[`examples/metadata-fields.conf`](../examples/metadata-fields.conf) for a pipeline.

## 10. Upgrade and remove

### Upgrade

1. Build the new gem (section 2) and keep the **same `state_directory`**.
2. `bin/logstash-plugin install /path/to/new.gem`, then restart Logstash.

Re-installing the same version is **Verified**. Installing a different version over an older one relies on
Logstash's normal behaviour and was **Not tested here**; if unsure, remove the plugin first, then install.
Never delete or roll back `state_directory` during an upgrade: the ACK counter there is what stops event
acknowledgement IDs being reused.

### Remove

Remove or comment out every pipeline that uses `splunk_hec` first, then:

```sh
bin/logstash-plugin remove logstash-input-splunk_hec
```

**Verified**: the plugin disappears from `list`. If a pipeline still uses it, Logstash refuses to start with
`Couldn't find any input plugin named 'splunk_hec'`. Removing the plugin leaves `state_directory` in place.

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Plugin version conflict, aborting ... depends on logstash-core >= 9.5.0` at install | Logstash is older than 9.5.0 (**Verified** on 9.4.0). Upgrade Logstash. In a Docker build use a 9.5+ base image |
| `Could not reach host index.rubygems.org` | The install needs rubygems.org (or a mirror) even for a local gem. Fix connectivity/proxy, or build the image elsewhere (section 3) |
| `Invalid pack for: file:///..., the pack must be in zip format` | Do not use a `file://` URL. Pass the plain path to the `.gem` |
| `Couldn't find any input plugin named 'splunk_hec'` | Not installed on **this** Logstash, removed, or Logstash was not restarted. Check `bin/logstash-plugin list --verbose splunk` on the host that runs the pipeline |
| `Unknown setting '<name>' specified for plugin 'splunk_hec'` | Misspelled option, or `codec` (not supported). See [configuration.md](configuration.md#3-option-reference) |
| `ACK state already owned` | Another input or process uses the same `state_directory`. Give each input its own |
| Start fails with a permission error under `state_directory` | The directory is not writable by the Logstash user (`install -d -o logstash ...`, or fix the volume's ownership) |
| TLS errors on forwarders or curl | Wrong or missing `server.crt`, or the host name is not in `ssl_self_signed_sans`. SANs cannot change after the first start; to regenerate, deliberately move `identity/` away and redistribute the new `server.crt` |
| Connection refused on 8088/9997 | Firewall, container port mapping missing, or the TCP listener is not enabled (`s2s_tcp_enabled`) |
| Sender cannot connect to 9997 | TLS mismatch: the sender's `useSSL` must match `s2s_tcp_ssl_enabled` (default off) |
| HEC returns `401`/`403` | Missing or wrong token, or it is disabled in `tokens_json`/`inputs_conf` |

More runtime problems (limits, queue page size, large events) are in
[configuration.md, section 12](configuration.md#12-troubleshooting).

## 12. What was verified

`python3 tests/interop/install_check.py` (evidence in `tests/interop/evidence/install-check.json`, which names the
gem digest) ran in fresh official Logstash containers:

- On the pinned **9.5.0** and **9.5.5** images: install, `list`, `logstash -t`, a real run with the generated
  certificate, verified-TLS health, event accepted and present in the output, a request without a token refused,
  reinstall, remove, gone from `list`, and the clear failure after removal.
- The **Docker image** from `docker/Dockerfile.logstash` builds from the pinned 9.5.5 image and validates a
  pipeline.
- **Logstash 9.4.0** (older than the floor): the install is **rejected** with a version conflict and nothing is
  left installed.
- **Offline** install (`--network none`) fails by Logstash's own design (section 3), which is why the Docker-image
  route is documented for air-gapped sites.

Not verified here: package (`.deb`/`.rpm`) and tarball installs on a host, `systemctl` service handling, the
Logstash keystore, proxy settings, installing a different version over an old one, and Kubernetes.
