# Changelog

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
