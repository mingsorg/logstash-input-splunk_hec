# Offline retained-assembly recovery and export (0.6.0)

Use the installed `lib/splunk-hec-recover` command to export retained assembly
work and rebuild it in a **new directory**. Stop ingestion before export. The
source spool is opened read-only under its existing Java shared lock. Export
never calls ingestion recovery, truncates a journal, selects a backup, or
promotes publication candidates.

```sh
# PLUGIN is the installed logstash-input-splunk_hec gem directory.
# The existing destination parent must be private (0700), owned/trusted local storage.
mkdir -m 700 /private/recovery
sh "$PLUGIN/lib/splunk-hec-recover" export \
  --assembly-directory /private/original-assembly \
  --output /private/recovery/retained.archive --json
sh "$PLUGIN/lib/splunk-hec-recover" rebuild \
  --archive /private/recovery/retained.archive \
  --assembly-directory /private/recovery/rebuilt-assembly --json
sh "$PLUGIN/lib/splunk-hec-recover" --help --json
```

Neither archive nor rebuilt directory may already exist. Concurrent attempts
have exactly one destination owner. Paths traversing symlinks, `..`, special
files, unsafe storage or overlapping sources are refused. No overwrite, force,
in-place repair, activation or adoption option exists. Use a different absent
destination after a failed attempt. Outputs are 0600 files / 0700 directories;
the caller needs permission to read the source and create entries in the
private output parent. The command reads the installed VERSION, plugin jar,
bundled Java and core/JRuby jars. It uses kernel-owned `/proc/self/fd` paths for
pinned I/O and fsync, not external application files. It makes no network calls.

## What is retained

* **Pending** entries retain their keys, envelope template, exact text,
  delimiter, rule/configuration/chain/origin/attribute fingerprints,
  contribution order and coordinates, timeout/touched time, event limit and
  sender. Pending work has no finalized output ID. Export does not finish tails.
* **Outbox** entries retain their finalized envelope, occurrence ID, sender and
  list order. Identical envelopes can have distinct occurrence IDs.
* **Receipts** retain their exact ordered key/value pairs. They record accepted
  input, **not proof of downstream delivery**. No delivery status is inferred.
* Blocked state, native numeric types, decimal precision/scale, large integers,
  IEEE double negative zero, nulls, nested lists/maps and nanosecond timestamps
  survive transfer. All application maps use tagged key/value pairs, so keys
  cannot collide with codec tags. This is not deliverable-event NDJSON.

Structurally valid incompatible or blocked state can be transferred. The tool
does not rewrite configuration fingerprints, make it compatible, or unblock it.
`restart_compatibility` is always `not_evaluated`.

## Schema 1 and integrity

The UTF-8 archive is one strict JSON object:

```text
{schema_version: 1, byte_count: N, sha256: H, payload: {origin: ORIGIN, state: STATE}}
ORIGIN = {source: {format, authority, generation, snapshot_sequence, sequence},
          completeness: {classification, omitted_range: null | {offset, length}},
          previous: null | ORIGIN}
```

`byte_count` and `sha256` cover the canonical compact UTF-8 serialization of
`payload` emitted by the installed codec, including provenance, completeness
and tagged state. They do not cover whitespace/field ordering in the enclosing
archive. Rebuild decodes with strict fields/types, validates structure and
budgets, reserializes to this canonical form and verifies both length and hash
**before claiming a destination**. Unknown/duplicate/missing fields, coercions,
trailing input, unsupported schemas, broken tags and checksum mismatches fail
closed. Checksums detect integrity errors; they do not establish authenticity.
Only accept archives from trusted custodians.

Source authority is `published_v3` or `original_v2`; v2 coordinates are null.
Only a short journal header or an authenticated header with a short payload
permits validated-prefix export. It returns status 2, identifies the exact
omitted journal byte range and preserves the last validated state. Complete
record corruption returns 3 and produces no export. An ambiguous/unpublished
spool has no exportable authority even if a backup/candidate appears valid.

Rebuild publishes a fresh v3 snapshot at generation 1 / sequence 0, with an
empty journal. The logical state is unchanged. Checksummed
`recovery-origin-v1` retains archive provenance and omissions; later exports
chain that history (at most 17 origin records, 16 KiB metadata). Status 2
propagates through rebuild, inspection and re-export. Current journal
completeness and original omissions remain distinguishable. No omitted bytes
are invented or recovered.
The authenticated snapshot binds the exact metadata-file SHA-256. Missing or
substituted bound metadata is refused by inspection and ingestion recovery;
writer compaction carries the binding forward. Ordinary spools retain their
existing snapshot encoding without a recovery binding. Exhausting valid history
is a resource-budget refusal (exit 5), not a corruption diagnosis.

Budgets match inspection: 256 entries; 100,000 replay records; 1,000,000 JSON
tokens per record/document; nesting depth 64; 1,024-character numeric values;
10,000 pending entries, 40,000 outbox entries, 4,096 receipts and 1,000,000
contributions; retained-state ceiling 67,108,863 bytes, cumulative validation
1 GiB. Archive overhead is separately bounded to 65,536 bytes above that state
ceiling (total 67,174,399 bytes). The launcher uses a fixed 768 MiB maximum
heap. Excesses refuse rather than silently dropping work.

## Output, failure and interruption

Stdout contains only command/status classification, counts, blocked flag,
provenance, byte counts and digest. Payloads are only in the private archive and
rebuilt spool. Errors are value-free on stderr. `--help --json` publishes
argument, output and error schemas. No Python, compiler, source checkout or
network is needed at runtime. Supported secure filesystem behavior is the same
Linux/JDK 21 boundary as inspection; unsupported hosts refuse before output.

| Exit | Meaning |
|---|---|
| 0 | Complete transfer |
| 2 | Validated prefix / inherited incomplete recovery |
| 3 | Corrupt, unsupported or non-authoritative source/archive |
| 4 | Source locked / compatible shared locking unavailable |
| 5 | Storage, unsafe path, existing destination, write/fsync/cleanup or budget failure |
| 64 | Usage error |
| 70 | Runtime/bootstrap/internal failure or interruption |

File writes handle short progress, force contents and fsync directories. A
write, fsync, close or cleanup failure never reports success. Failed archive
writes are removed only while still owned; a crash may leave a partial archive,
which cannot pass length/hash/JSON validation. Rebuild stages storage in a private
sibling directory and durably writes `recovery-incomplete` before exposing the
final path. An exclusive sibling claim refuses conflicting rebuild attempts;
abandoned staging/claim entries are never adopted automatically. Inspection,
export and ingestion recovery refuse guarded partial directories. Before final
publication, a crash leaves either no final directory or a guarded directory.
A crash at the final durability boundary can leave a fully published, valid
output without a success response. The same ambiguity exists if final fsync
fails and storage also refuses to restore the guard. That double failure returns
an error, never success; the fully written output may still validate. Partial
outputs always refuse adoption. Inspect ambiguous fully published output
explicitly, do not automatically activate it. Existing outputs are
never retried/adopted/overwritten automatically. Advisory locks and identity
rechecks require trusted local storage; they cannot exclude hostile same-user
mutation or filesystems that lie about durability.

## Operator adoption

Keep the original spool and archive until recovery has been independently
checked. Inspect the new directory and compare retained counts, IDs, ordering,
native values and recorded omissions on isolated copies. A blocked copy remains
blocked; successful export/rebuild is not an indication that ingestion can run.

Adoption is a separate operator action with ingestion stopped. SplunkHec always
uses `state_directory/assembly`; there is no configurable assembly-directory
setting in the input (the offline command's flag only selects its file input or
output). Keep the original `state_directory`, ACK high-water files and TLS
identity. With all inputs sharing that state stopped, preserve the old `assembly`
directory at a separate backup path and move the independently verified rebuilt
directory into exactly `state_directory/assembly`, preserving its private modes
and ownership. Use matching assembly policy/metadata configuration and adequate
quotas before restarting. Do not reset ACK IDs, replace
parent state, replay a queue, or infer that an outbox item was delivered.
Existing ingestion compatibility/admission checks still apply on restart.
ACK-lock hot reload is separate deferred work.

## Qualification

`S2SAssemblyRecoveryTest` exercises native values/order, both source formats,
torn prefixes, strict archives, claims, storage faults and process halts on
fresh Linux. `tests/interop/recovery_qualification.py` installs the selected
exact gem in pinned minimum/latest images and uses only installed launchers
with networking off, a read-only source mount and an unprivileged owner. An
independent Python storage/tag decoder and isolated Java store recovery compare
logical state. `check_recovery_qualification.py` fails closed on missing/stale
evidence, including the prior release guarantees, reproducibility and three
artifact-bound reviews; targeted test success alone is not release qualification.
