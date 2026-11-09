# Offline assembly spool inspection (0.4.0)

`splunk-hec-inspect` reports aggregate retained assembly work without starting an
input. It uses installed Logstash's bundled Java 21, core jars and the installed
plugin jar. It does not need Python, a compiler, Gradle, a checkout or network.

## Installed usage

Stop the ingestion input, then run as the spool's owner:

```sh
PLUGIN=/usr/share/logstash/vendor/local_gems/<installed-plugin-directory>
sh "$PLUGIN/lib/splunk-hec-inspect" --assembly-directory /var/lib/logstash/hec/assembly
sh "$PLUGIN/lib/splunk-hec-inspect" --assembly-directory /var/lib/logstash/hec/assembly --json
sh "$PLUGIN/lib/splunk-hec-inspect" --help --json
```

Find the exact installed directory from its matching gemspec under
`vendor/local_gems`. The launcher walks its installed parents to locate Logstash;
`LOGSTASH_HOME` can explicitly select that installation. It resolves the jar
matching the packaged `VERSION`, never a development `.cache`. Use `sh` to invoke
the packaged script; executable file permission is unnecessary.

An explicit directory and an existing regular `lock` file are required. The tool
opens read-only descriptors and holds a shared Java lock over the same whole-file
range as the writer's exclusive lock. Multiple inspectors can coexist in separate
processes. A writer or unavailable compatible locking produces exit 4. It never
creates a missing directory/lock. It performs no write, truncate, fsync, chmod,
rename, migration, promotion, repair, payload export or reset. Reading may update
atime; file bytes, entries, identities, modes and mtimes are preserved.

Use trusted private local storage, with no group/other directory permissions.
The implementation requires POSIX identities and Java `SecureDirectoryStream`
descriptor-relative, no-follow traversal. Every directory component and entry
must be safe: symlink components, symlink entries, directories inside the spool,
FIFOs and other special files are refused. Providers without these guarantees
(including the macOS JDK used for development) fail closed with exit 5. The pinned
Linux Logstash images are the qualified runtime. Advisory locks cannot prevent
hostile replacement by another process with access to the private directory.
Metadata and directory identities are rechecked before returning a summary.
On qualified Linux/JDK 21 the launcher opens the JDK Unix filesystem package and
pins regular files with Linux `O_PATH` before opening their kernel-owned
`/proc/self/fd` reference for reading. This prevents replacement FIFOs/devices
from being opened for data. A missing procfs or incompatible runtime fails closed.

## Inputs, outputs and exit codes

`--stdin` explicitly reads a JSON object from stdin; `--input-file PATH` reads one
bounded regular JSON file. These options are mutually exclusive. Accepted keys:
`schema_version` (optional, must be integer 1), `assembly_directory` (string),
`json` (boolean). Flags override supplied JSON; duplicate keys, unknown keys,
unknown/duplicate flags and trailing JSON are usage errors. No implicit stdin read
can hang a plain invocation. `--help --json` describes the versioned contract.

```sh
printf '%s\n' '{"schema_version":1,"assembly_directory":"/var/lib/logstash/hec/assembly","json":true}' |
  sh "$PLUGIN/lib/splunk-hec-inspect" --stdin
```

Summary JSON (`schema_version: 1`) is written to stdout. Errors are value-free
stderr JSON with `schema_version` and `error.code/message` when `--json` is used.
Incomplete summaries also emit a warning to stderr. No host/source identifiers,
paths, text, configuration hashes, native field values or exception details are
returned. Text output uses the same aggregate fields.

| Exit | Meaning |
|---|---|
| 0 | Complete authoritative v3 or original legacy v2 summary |
| 2 | Incomplete journal suffix or incomplete/ambiguous publication |
| 3 | Complete corrupt or unsupported state; no final counts |
| 4 | Locked or compatible shared Java locking unavailable |
| 5 | Unsafe, missing, unreadable, changed storage or resource budget exceeded |
| 64 | Usage or input schema error |
| 70 | Internal error or installed runtime cannot be resolved |

`format`, `authority` and `classification` identify what was actually read:

- `v3` / `published_v3`: authenticated `current-v3`, matching snapshot and valid
  committed journal prefix. `generation`, `snapshot_sequence`, `sequence` and
  `transactions` describe that selected generation (transactions is replayed
  records, not lifetime history). A short final header or authenticated short
  payload yields `incomplete_suffix: {offset, length}`, prefix counts and exit 2.
  A bad complete header, sequence, checksum, operation or native codec yields
  exit 3 with no summary. No backup or older generation is substituted.
- `v2` / `original_v2`: valid original `state`; sequence/generation are null and
  journal/transaction counts are zero. It is never migrated. An original remains
  authoritative before a migration refusal marker even if backup candidates exist.
- `unpublished` / `none`: missing authoritative state, interrupted first
  publication or migration, or a missing established pointer. Classified
  `incomplete_publication` or `ambiguous`, exit 2. No work counts are asserted,
  no candidate is promoted and `backup-v2` is never replayed as current work.

Counts are `pending`, `outbox`, `receipts`, pending `contributions` and replayed
`transactions`; `blocked` is the persisted flag. `physical_bytes` counts all
regular directory entries, `journal_bytes` includes any suffix, and
`journal_prefix_bytes` counts complete records. `entries`,
`publication_candidates`, `marker`, `established_marker` and `backup` describe
observed storage. `backup: present_not_current` reports existence, not validation
or equivalence. Unreferenced publication candidates are counted, not decoded.

`restart_compatibility` is always `not_evaluated`. Structural validity and counts
do not establish compatibility with current rules, stream limits, byte quota or
finalization capacity, nor guarantee delivery or restartability. Repair, payload
export, rule reload and metrics are deferred. Existing journal/writer/migration
formats and downgrade requirements remain as documented for 0.3.0.

## Resource budgets

Inspection caps entries at 256; each physical file at 134,221,887 bytes, aggregate
physical bytes at 536,903,672 bytes; the selected pointer at 4,161 bytes, snapshot
at 67,113,024 bytes and journal at 134,221,822 bytes. Legacy payloads are capped
at 67,108,863 bytes (plus 65-byte checksum envelope). JSON is capped at depth 64,
1,000,000 tokens/document, 67,108,863 characters/string and 1,024 characters/number.
Replay is capped at 100,000 records, reconstructed state at 67,108,863 JSON bytes,
10,000 pending streams, 40,000 outputs, 4,096 receipts and 1,000,000 pending
contributions. Cumulative state serialization output is capped at 1 GiB to bound
replay amplification. CLI JSON input is capped at 65,536 bytes. The launcher sets
a 768 MiB heap. Budget refusals never return final counts.

## Development and qualification

Development builds need external Maven/Gradle dependencies and Docker image
access; installing a local gem normally needs RubyGems dependency resolution.
Those are development/install accesses, not inspection runtime dependencies.
Use `./gradlew test gem`, `python3 -m unittest discover -s tests/build -v`, and
`python3 tests/interop/inspection_qualification.py` for fresh installed-command
qualification on pinned minimum/latest runtimes. The latter extracts only the
selected gem, seeds fixtures with the SHA-pinned 0.3.0 artifact, compares against
an independent Python oracle and production recovery of isolated copies, and
runs the installed command outside a checkout with networking disabled.
The installed scenarios include an unprivileged spool owner and a genuinely
read-only spool volume, malformed input controls, compacted snapshots with
additional transactions, and torn-prefix comparisons against recovery of copies.

`python3 tests/interop/linux_inspection_tests.py` runs the current Linux-only
suite using the pinned image and existing Gradle cache with networking disabled.
It records source, artifact, validator, class and XML identities and validates
captured outputs against the published schemas. Final qualification executes this
suite afresh; cached test names/counters alone cannot qualify a new build. On
native Linux the freshly executed host suite supplies that proof instead.

Evidence is release-scoped under `tests/interop/evidence/0.4.0/`. Historical 0.3.0
reports are not current-artifact proof. `check_inspection_qualification.py` binds
inspection and ingestion evidence to exact gem and validator digests, includes
fresh package identity and an independent source/artifact review gate. Read its
output before making qualification claims. No release is published automatically.
