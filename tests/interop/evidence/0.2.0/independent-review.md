# 0.2.0 independent re-review (post-fix)

Three read-only reviewers (adversarial, edge-case, verification-gap) examined the changes since
baseline `4cf64e1` after the first completion review (R1-R4). Their raw reports are summarised here
with dispositions. This file is bound into the qualification summary by SHA-256.

## Findings and dispositions

| Lens | Severity | Finding | Disposition |
|---|---|---|---|
| adversarial/edge | medium | Zero-event-record skip swallowed 503 (memory pressure), silently dropping a record and ACKing | Fixed: only 4xx identity/validation errors are skipped; 5xx is rethrown |
| edge | medium | Legacy-empty selected record with incomplete identity still rejected the batch | Fixed: skipped like the standard path |
| edge | low | Legacy-empty unselected record created a gate/barrier and could return 503 | Fixed + regression test `legacyIgnoredUnselectedRecordCreatesNoGateStateOrBarrier` |
| edge | low | Recovery exception mapping incomplete / cause dropped | Fixed: all runtime failures map to a startup IOException naming `s2s_assembly_max_bytes`/`max_streams`, cause retained |
| adversarial | low | Constructor cleanup could mask the original error or leak the reservation | Fixed (suppressed + finally) |
| adversarial | low | Rejection log limiter used wall clock | Fixed (`nanoTime`) |
| adversarial | low | Lowered `max_event_bytes` does not shrink a retained tail; failed shutdown may hold the assembly lock | Documented in docs/verification-0.2.0.md and CHANGELOG known limits (accepted, not fixed) |
| verification | high | Committed evidence did not match HEAD | Fixed: gem rebuilt and every report regenerated for the final commit |
| verification | medium | `raw_only` negative control was a no-op | Fixed: replaced by digest-of-a-different-event control |
| verification | medium | 401/403 log-filter assertion was vacuous (same suppression window) | Fixed: separate fresh server |
| verification | medium | No TCP / listener-level coverage of ordering and ACK-after-insertion | Added HTTP + TCP blocked-predecessor tests and an HTTP mixed-batch exact-order test; mutation-checked (bypassing the listener's `ordered.enqueue` fails the mixed-batch test). TCP failed-insertion leg remains uncovered (low) |
| verification | medium | `validators_info()` bound only part of the producing inputs; baseline 0.1.0 gem unpinned | Fixed: now binds tests/http, tests/tcp, scripts, versions.properties, VERSION and top-level evidence corpora; baseline gem SHA-256 pinned and checked |
| verification | medium | Scaling numbers presented as evidence | Fixed: labelled anecdotal; cross-sender claim reworded as unmeasured |
| verification | low | README claimed unchanged unmatched behaviour; doc wording | Fixed |

## Not covered / residual (low)
- TCP failed-insertion no-ACK leg; SIGKILL/power-loss fsync durability beyond the retained crash probes.
- Unclean-stop upgrade and assembly-store upgrade are not exercised (no rules in the upgrade check).
- Performance: per-commit full-snapshot rewrite (quadratic per event); scheduled for 0.3.0.
- The fixes in this round were verified by new/mutation-checked tests and the regenerated live matrix, not by a third review pass.

No unresolved high or medium findings remain after the dispositions above.
