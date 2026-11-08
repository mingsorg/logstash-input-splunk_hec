# Durable S2S assembly journal (0.3.0)

Matched records are acknowledged after a single delta transaction has been written and
`fsync` has completed. Unmatched and structured records retain queue-acceptance ACKs.
Whole-batch validation, native values, first-contribution timestamps, metadata and
`s2s-v1`/`s2s-assembled-v1` identities are unchanged.

## Storage and recovery

`state_directory/assembly/current-v3` selects one snapshot/journal generation. The
pointer and snapshot have SHA-256 checksums. Each journal record has an 88-byte header:
big-endian magic `S2S3`, version 3, sequence and payload length, a SHA-256 of those
24 framing bytes, and a SHA-256 of the UTF-8 JSON delta payload. Sequences must be
contiguous. These checks detect corruption; they are not keyed signatures against
an attacker who can modify the private spool.

Recovery validates the published pointer, its exact snapshot and committed records.
Only a short trailing header or a payload shorter than its authenticated declared
length is an incomplete suffix eligible for truncation. A fully present bad checksum,
invalid operation or invalid sequence fails startup, including in the final record.
An invalid published pointer never falls back to another generation or a backup.

Compaction writes and synchronizes a complete new snapshot and empty journal, then
synchronizes their directory entries. Only then is a checksummed pointer atomically
replaced and the directory synchronized. Superseded files are removed afterwards.
Any storage failure blocks ingestion; restart re-establishes authoritative state.
An unacknowledged transaction that reached durable storage may replay.

## Capacity

Let **M** be `s2s_assembly_max_bytes`. Its meaning remains the serialized JSON payload
of live pending streams, outbox, receipts and configuration. Admission also reserves
every positive pending-to-output replacement delta, so any subset of accepted tails
can complete before handoff frees space. Recovery repeats the proof under the
currently configured stream and byte limits. Tightening a limit can fail startup;
it never silently drops an accepted tail.

Journal history is bounded separately to **2M + 4096 bytes** (including record
headers). Before exceeding this bound, the current state is compacted. Total spool
file contents are bounded to **8M + 32768 bytes**, including active and candidate
generations, pointer temporaries, the refusal marker, and preserved migration backup.
This allows two snapshots (each at most M + 4096 + 65 bytes), bounded old history,
one bounded new transaction, a migration backup (M + 65), and control-file allowance.
Compaction checks projected peak usage before writing. Provision filesystem space
above this file-content allowance for filesystem block allocation, directory metadata,
and Logstash's independent persistent queue/TLS/ACK storage. ENOSPC still causes no
successful ACK and blocked health; repair capacity before restart.

Suffix chunks are immutable. Appending a fixed-size contribution does not copy or
serialize the accepted text/provenance prefix. Exact serializer-compatible sizes are
cached for live-state and completion checks. Final output and compaction necessarily
materialize complete events; benchmark results report these costs separately.

## Upgrade and downgrade

Stop the input before replacing the gem. On its first open of a 0.2.0 spool, 0.3.0
checks the old checksum, configuration, tagged native values and current capacity
before migration. It preserves the exact original bytes in private `backup-v2`,
synchronizes the backup, and atomically installs a short refusal marker at `state`
before publishing v3. The 0.2.0 reader rejects that marker instead of reading stale
accepted work. Interrupted migration resumes from the valid original or backup;
unpublished candidate generations are not authoritative. Do not delete the backup.

Downgrade requires stopping the input and restoring `backup-v2` to `state` in a
separate restored spool with v3 files removed. The backup is the **pre-migration**
state: it does not contain work accepted by 0.3.0. Drain/export that work first and
account for possible at-least-once replay. Merely installing 0.2.0 cannot downgrade
a migrated spool.

## Delivery limitation

Delivery remains at least once. Per-sender ordering is preserved while the input runs
and handoffs succeed. A crash or failed insertion between a batch's durable assembly
commit and its direct-record queue handoff can replay journaled output before the
retried direct record. Stronger cross-crash ordering, group commit, hot rule reload
and new ingestion metrics are deferred.

## Qualification

Use `./gradlew test --max-workers=1` and
`python3 -m unittest discover -s tests/build -v`. Build two clean reproducible gems
with `python3 scripts/check-reproducible.py`. All packaged probes select `VERSION`
and write fresh evidence under `tests/interop/evidence/0.3.0/`.
`journal_qualification.py` compares packaged 0.2.0 continuation with migrated 0.3.0,
runs 500–8000-line scaling probes, and runs bounded 2000-event sustained traffic on
each pinned runtime. Run the existing full sender/runtime/wire/disk-full matrix too.
`check_assembly_qualification.py` rejects missing or stale artifact/validator proof.
Independent three-lens review and exact-artifact closure are required before a
human creates `v0.3.0`; no tag or publication is automatic.
