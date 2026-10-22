# PicoClaw mutation jobs: protocol decision, implementation in progress

This is the protocol selected for the stopped-mutation handoff. It is not an
activation or acceptance report. A broker-library acceptance producer now exists,
but ordinary model/profile/install/uninstall writers, new transport, execution
and recovery paths are not yet migrated.
The legacy onboarding completion boolean is not a durable job receipt.

## Current connected reader, fence and factory bootstrap

The fixed-root reader recognizes an 8,608-byte private `NKPJOB01` metadata
snapshot: store epoch, monotonic head, at most one active job and a contiguous
last-32 terminal ring. It validates fixed kinds/phases/results/runtime intent,
nonzero private identities, canonical encoding and a domain-separated checksum.
The checksum detects corruption, not a malicious root writer. Parsed records
are data, never native-closure, bootstrap or recovery capabilities.

Existing snapshots are consulted before returning a Config permit or either
synchronous/asynchronous writer drain. Active, uncertain, corrupt, unsafe,
missing-state or extra-member evidence refuses admission and is preserved.
Reads do not initialize, rewrite, settle, resume or prune a job. Producers must
own Update then Config before taking the store's exclusive lock; this short
read-side shared lock is not a substitute for their lifetime ownership.
The temporary read lease explicitly unlocks on drop, so a pre-exec inherited
description cannot spuriously block the admitted producer's following EX lease.

A separate protected 96-byte `/etc/kvm/picoclaw-enrollment` anchor now records
Factory, Pending(epoch) or Ready(epoch). Only offline full-image producers seed
the deterministic Factory input; it is not an app-archive member. Early S02
activation takes Update then Config and performs this explicit bootstrap before
the broker/backend can need Config. Backend boot-support preparation validates
the same path. Neither ordinary API/status calls nor missing files create it.

Factory requires an absent store, selects a nonzero random epoch and durably
publishes Pending before creating the empty store. The exact empty state and
its directory are synced before Ready publication. Pending retry retains the
same epoch and refuses anything except that exact empty store. Ready requires
the matching state and cannot recreate a missing store or reset its sequence.
An existing store without its anchor also refuses. A staged anchor, partial
file, corrupt or foreign member is preserved and fenced, not automatically
adopted or cleaned. Explicit recovery of ambiguous bootstrap staging remains
to be implemented. This bootstrap supplies no native closure authority.
Its owning directory lease explicitly unlocks on all exits before the normal
read-side fence reopens it; a pre-exec inherited FD cannot prolong that lease.

Only absence of BOTH anchor and store remains legacy preactivation, not an
enrolled empty store. Future job acceptance must require Ready even in that
legacy case; old installations still need explicit trusted migration rather
than factory seeding from an app archive. Raw preservation/recovery must carry
anchor and store together, and is not implemented by this bootstrap.

Existing onboarding does not publish these records yet. There is still NO
phase-transition/execution API, retirement or job recovery bypass. Ordinary
unmanaged Pico writers and OS-level H2 isolation remain outside this connected
cooperative fence.

## Current retained acceptance producer

`Broker::prepare_picoclaw_submission` transfers Update and Config admission into
an owned `PicoSubmission`. Its one-shot fixed worker retains those guards, the
exclusive store lease, source lease and credential-bearing payload through
errors and host unwind. Poll joins only an already finished worker; final owner
drop joins before releasing guards. A failed spawn cannot retry that submission.
The owning broker engine still needs integration so disconnect/shutdown retains
the submission until settlement; this library API does not supply native closure.

Acceptance requires Ready enrollment and a canonical inactive store with no
foreign/staged members. It cannot initialize, reset or recover one. A request is
one of six fixed operations, never a command, path, worker or callback selector.
Model values use bounded zeroizing buffers without Debug/Serialize. The worker
binds the actual kernel boot epoch and pinned executing producer image, then
captures the current config/security pair (including absence) and checked Home
or nearest existing ancestor. Missing Home is not created. This is only a base
source snapshot: workspace/generated/install assets, after-Stop revalidation and
operation-specific bindings are still required before execution.

The fixed immutable `active` intent is published and synced first, then private
`payload` and `source`, then `.state.next` is synced and renamed over `state`.
Only final directory sync, reread and identity/inventory checks permit the exact
accepted ID acknowledgement. Every newly created file is mode 0600; unknown
write/sync/rename results retain evidence and the durable admission fence. No
acceptance path mutates a target, stops/restarts Pico, removes evidence, advances
a phase or clears an accepted job.

The epoch/head/nonce checks reject wraparound, future/stale requests and changed
payload or Home reuse. An exact retained terminal replay observes its old ID;
current boot/image/source/runtime need not equal its historical receipt because
this is observation only, not permission to execute that payload again. Active
job observation and the correlated private transport are not wired yet.

Disposable namespace/root tests exercise all six actual acceptance requests,
default/custom absent or present Home, orphan YAML, protected source/store
rejection, retained owner on fail/spawn/panic, ten publication error boundaries
and real SIGKILL at five pre/post-state-rename points. They are host process-death
checks, not physical power cuts, target execution or completed mutation recovery.

## Authority and scope

The native broker owns each accepted operation, not its HTTP caller. Admission
is UpdateEX followed by Configuration, with the effective Home, trusted support
and source documents pinned before acceptance. Live Pico work is stopped by its
existing owner; import/mutation starts only after receipt, owner reap and EOF.
An unchanged config generation, absent PID or closed caller socket is not that
proof. The broker continues supervising native cells during filesystem work.

There are six fixed operations: onboarding, model configuration, startup-default
reconciliation, profile selection, runtime installation and runtime removal.
Their payloads are bounded typed data, never executable/path/shell/callback
selectors. Custom Home/workspace remain supported checked rootfs destinations.
Runtime removal removes exactly managed configuration and executable/cache
assets, not the user's workspace. Profile replacement must explicitly handle
custom generated assets rather than silently overwriting them.

This authority does not establish upstream package provenance or the H2 local
privilege boundary. It does not add approvals to target-computer GUI/HID, BIOS,
installer or target-terminal actions.

## Durable identity and replay

The fixed store is `/etc/kvm/picoclaw-operations`, root-owned mode 0700 on the
same root filesystem, opened with descriptor-confined, no-symlink/no-mount I/O.
It must not live on `/data` or in a client-selected directory. It has its own
exclusive lease; neither that lease nor its durable identity is unlinked during
normal operation. Raw preservation/recovery must carry this state explicitly.
Only explicit bootstrap/recovery authority initializes the store; an ordinary
submission or status query may not create/reset it after absence or corruption.

A fresh store has a random 128-bit epoch and a monotonic 64-bit sequence. A
submission carries the observed epoch/sequence plus a random client nonce.
Acceptance increments the sequence without wrap and binds the nonce, operation,
boot epoch, Home identity and private payload/source snapshots. The broker
returns that exact job ID only after the complete accepted intent is durable.
Before that acknowledgement, a lost connection has an unknown outcome; the
client observes/reconciles the same ID/nonce, never blindly submits a new one.

An exact replay of the current request observes its existing result. A changed
payload with the same nonce/ID is invalid. A stale epoch/sequence cannot create
new work. At most one job is active and the last 32 terminal receipts are retained
without depending on wall-clock time. An expired result is reported as expired,
never treated as permission to execute that old request.
Retiring a receipt never resets the sequence or reopens its request identity.
Store loss/corruption is a recovery condition, not an implicit fresh start.

Before acceptance or any target mutation, the producer durably publishes a
separate immutable `active` intent bound to that job ID/source/payload. It
remains present across every state/payload/scratch/activation transition,
including publication of the final completed snapshot. Only known-success
sync of that snapshot and its parent, with the entire operation settled,
permits exact retirement of `active`. A completed snapshot with that fence
still present is completion-pending, not an acknowledged public result.
Unknown state-publication sync cannot remove the fence. If final fence-unlink
sync is unknown, either the fence remains and recovery is conservative, or it
is absent beside an already durable completed state. Recovery may retire the
exact remaining fence; it must never repeat the mutation from observation.
The acceptance producer implements initial intent publication only; finalization
and exact retirement remain required and unimplemented.

Credential-bearing payload and source snapshots stay in protected 0600 files
and bounded zeroizing buffers. They are not argv, environment, log, Debug or
public status data. The in-memory `Generation` type remains nonserializable;
recovery compares the checked private document snapshots, not a public hash of
credentials. Public observations contain job ID, fixed kind, phase and bounded
result codes only. Error text must not echo upstream documents or credentials.

## State and runtime intent

The persisted state graph is:

`Accepted -> Stopping -> Closed -> Applying -> Committed -> Retiring -> Activating -> Completed`

A proven absent/Closed Pico cell can skip Stopping. A genuine no-op can finish
from Accepted after recording its result; target bytes, inodes and generation
remain unchanged and a live runtime is not stopped. Every other skipped,
backwards or replayed transition is refused. Filesystem work and its state
publication run in fixed joined workers, not the broker's control loop.

The accepted intent records whether Pico was running and the selected Home,
source pair/workspace identities, support identity and operation. Successful
mutation does not mean the old task resumed. Restart is a separate Activating
step requiring the complete settled pair, current support/generation admission
and an explicit runtime result. Removing the runtime never restarts it.

The intent separately persists `resume_allowed`, initially set from the observed
running state except for removal. An authorized Stop or session revocation must
durably lower this flag before its acknowledgement; it cannot be re-enabled by
observation, recovery or a new boot. A previously running job whose restart was
suppressed records the distinct runtime result `Suppressed`, not `NotRequested`
or `Resumed`. This flag is not permission to restart: current runtime admission
and all settlement checks are still required. The reader checks these record
shapes and the acceptance producer writes the initial permission, but monotonic
transition enforcement and Stop/revoke acknowledgement remain unimplemented.

Failure before any mutation can become a terminal failed/cancelled receipt only
after native closure and exact scratch/payload retirement. Once mutation may
have begun, an error, worker panic, process death or unknown sync result remains
nonterminal and fenced until operation-specific checked settlement. A returned
Err, worker join, reconnect, timeout or new boot cannot clear that fence.
Observation never performs mutation/recovery or retries a worker.

## Onboarding settlement

The scratch directory is created only after durable acceptance and bound to the
job by exact directory/file identities and a bounded manifest. Foreign scratch
with the same name is preserved/refused. The completed one-shot is imported
only after native closure; all generated-asset collisions are preflighted,
existing user files preserved and the credential pair published last.

The job records destination absence/identity and each owned publication before
progress can be acknowledged. Recovery verifies the exact manifest, scratch,
destination identities and pair-local journal under Update/Config admission.
It settles the supported prefix or retains an explicit recovery-required fence;
it never adopts arbitrary scratch or recursively deletes an unknown tree.
Scratch retirement is its own checked durable phase after the complete import.
An existing config pair does not by itself prove that scratch/job settlement
has finished.

Fresh-boot recovery first proves no prior native scope can survive, then takes
the same writer barriers and operation-specific recovery authority. Same-boot
owner loss remains subject to the native journal's conservative fence. Recovery
does not replay the upstream onboarding command or an unknown accepted payload.

## Integration and acceptance still required

The new private bounded SEQPACKET request/result transport must migrate ordinary
API and S96 callers together, with exact helper/ABI bindings. No mutation opcode
is added to the old 48-byte service frame as an interim arbitrary-command path.
The development raw-update barrier and unsupported support transition stay shut.

Required checks include every fixed writer; live/closed/uncertain native states;
disconnect and concurrent/replayed IDs; no-op inode/byte preservation; real
partial import and pair/sync failures; retained ownership on worker spawn/panic;
SIGKILL/boot recovery; exact scratch retirement; custom data preservation;
install/remove error truthfulness; current helper/root/Rust integration; and
later device/raw/autonomous target-HID acceptance. Until those paths are wired
and verified, C1/H2 and the complete stopped-mutation handoff remain open.
