# Changelog

## 0.4.0

- Add the installed, offline `lib/splunk-hec-inspect` assembly summary command,
  using bundled Logstash Java/core/plugin jars and compatible shared Java locks.
- Share pure checksummed framing, native codec, replay and structural validation
  with production recovery. Inspection reports committed prefixes, legacy v2,
  incomplete/ambiguous publication, corruption and bounded resource refusals.
- Add versioned JSON input/help/output, stable exit codes and value-free errors.
  Counts do not evaluate restart compatibility or finalization capacity.
- See [inspection operations and qualification](docs/spool-inspection-0.4.0.md).
- Qualified with 143 existing Java tests, 20 Linux inspection tests, 44 Python
  tests, all 30 qualification checks, and three source/artifact-bound reviews.

## 0.3.0

- Replace per-request assembly snapshots with authenticated append-only delta
  transactions, durable generation publication and bounded compaction.
- Use immutable text/provenance suffixes and cached exact completion accounting.
- Migrate validated 0.2.0 state with an exact private backup and old-reader refusal
  marker. Downgrade requires explicit restoration of the pre-migration backup.
- Preserve live-state byte quotas; separately bound physical spool file contents to
  `8 * s2s_assembly_max_bytes + 32768`. See [journal operations](docs/assembly-journal-0.3.0.md).
- Preserve at-least-once delivery and the existing cross-crash direct-record ordering
  limitation. Qualified with 143 Java tests, 41 Python tests, all 28 automated
  checks and three source/artifact-bound independent review verdicts.

## 0.2.0

### Added
- Opt-in sourcetype-specific assembly of unstructured S2S events
  (`s2s_line_breaker_rules_json`): exact/ordered-glob sourcetype rules, RE2/J start patterns,
  idle flush timeouts, source-isolated streams, first-contribution timestamp and optional full
  provenance. Over HTTP `/s2s` and classic TCP.
- Durable, checksummed, atomically replaced assembly snapshot under `state_directory/assembly/`.
  Matched-mode ACK means durable acceptance into the assembly stage; delivery to Logstash is
  at-least-once with stable `s2s-assembled-v1` IDs.
- Per-sender ordering between completed assembly output and direct (unmatched/structured) records
  while the input runs; recovery re-validates finalization headroom and stream bounds under the
  configured limits and fails startup closed.
- Value-free, rate-limited WARN diagnostics for rejected HTTP requests (route, status, HEC code,
  rejecting source line); 401/403 are not logged.

### Fixed (completion review)
- HTTP S2S coordinate and timestamp flags are decoded independently. UF telemetry
  with coordinates but no timestamp previously shifted field parsing, causing
  repeated HTTP 400 responses and blocking the forwarder's shared output queue.
- Recovery no longer fails to read an acknowledged tail above Jackson's default 20M-character limit.
- Recovery no longer starts with state whose tails cannot be finalized under the configured quota.
- Enabling an unrelated rule no longer turns a record the standard path ignores into a rejected batch;
  resource-pressure (503) is still reported to the sender.

### Known limits
- Each commit rewrites and fsyncs the whole bounded snapshot: total work per event is quadratic in its
  line count (see docs/verification-0.2.0.md). Planned for 0.3.0 (append-only journal).
- After a stop or failed insertion between a batch's journal commit and its direct-record handoff,
  delivery is at-least-once without a strict order guarantee for that batch.
- Lowering `max_event_bytes` does not shrink an already retained tail.

## 0.1.0
Initial release: HEC `/event`, `/raw`, `/s2s` and optional classic S2S TCP input with tokens, ACKs, TLS and limits.
