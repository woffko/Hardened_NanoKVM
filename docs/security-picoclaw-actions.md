# PicoClaw action preflight and bounded execution

The current development source prepares a complete, immutable action plan before
the first HID effect. This is one part of WP-06/H3, not completion of cancellation
or release acceptance. Both the direct `/actions` route and MCP `kvm_actions`
consume the same prepared representation.

## Per-call limits

| Input | Limit |
| --- | --- |
| Actions | 1–64 per call |
| Wait | 0–5000 ms per action |
| Scroll | At most 100 ticks per action; legacy amount 0 still means one tick |
| Typing | At most 4096 UTF-8 bytes across all type actions in a call |
| Scheduled delays | At most 30 seconds in total |

The delay budget includes waits, click/hotkey holds, scroll tick delays and the
existing 30 ms typing delay per character. For example, 1001 ASCII characters
already exceed the scheduled-time budget even though they fit the byte limit.
Device writes/recovery add time: this preflight does not establish a 30-second
wall-clock deadline or preempt a kernel operation.

These are call limits, not a limit on the complete user task. A long terminal
interaction continues with successive bounded calls under the original task;
the planner neither truncates text/actions nor asks for approval per batch.
Successful typing retains the existing layout mapping, Enter/newline, Tab and
hotkey semantics and report order. Unsupported text is rejected before typing
its valid prefix.

## Parsing and validation

The array deserializer stops at the action-count limit. A malformed, empty,
duplicate or oversized `actions` member is not retried as a single action;
mixed single/batch payloads are rejected. Coordinates, buttons, directions,
hotkeys and complete text are validated before an executable plan is returned.
Hotkey normalization is bounded and rejects non-string array entries rather
than silently dropping them. The MCP tool schema advertises the call limits
and tells the agent to continue long tasks in subsequent calls.

## Bounded executor

Direct and MCP actions and screenshots share one lazy executor owned by
`AppState`, including its clones used by the HTTP, HTTPS and loopback listeners.
Blocking work runs on one dedicated thread, outside the Tokio worker and
blocking pools. There is at most one active call and one queued call. Queue
overflow is rejected immediately without HID/capture effects; the rejected call
was not admitted. Invalid actions fail preflight before the thread is started.

A queued request whose receiver has disappeared is skipped. Abandoning an
already running request does not free the executor or let the next call overlap
it: the executor still owns execution and per-call session cleanup. Losing an
executor/result does not automatically replace the executor or replay a call.
Only an explicitly non-admitted call can safely be retried without investigating
its effects. An admitted call with a lost result is not proof that nothing ran.

The thread holds no `AppState` or sender reference. Dropping the last app-owned
sender closes admission and lets the thread exit after outstanding work; it
does not interrupt a blocked capture/device syscall. Explicit shutdown/drain
and ownership-aware cancellation are still required.

## Still required for H3

The executor is bounded but not yet cancellable inside an action. Session
generation, independent Stop/logout/expiry, safe ownership-aware HID release,
and execution/queue-age deadlines remain required. The old global session/HID
cleanup is not a new ownership guarantee. Do not treat this development step
as a complete H3 fix.

Tokio timeout alone cannot prove that synchronous MCP code did not block. The
late-invalid rejection test therefore also measures wall-clock time for both
routes against a one-second host allowance and the deliberately requested
five-second wait. This proves rejection latency only, not valid-call latency.

Host tests cover plan boundaries, malformed/late-invalid actions and report
ordering; worker bounds, canceled queued calls, shared actions/screenshot
admission and fail-closed executor loss; and valid direct/MCP waits leaving a
single-thread Tokio runtime responsive. These are handler/worker tests, not
authenticated router or device tests. They do not prove device input, real
multi-batch HID execution, in-action cancellation, revocation or manual/Pico
handoff. H2, M10 and the remaining WP-06 gateway/token/URL and privilege
boundaries are separate unresolved work.
