# PicoClaw mutation jobs: protocol decision, implementation in progress

This is the protocol selected for the stopped-mutation handoff. It is not an
activation or acceptance report. Broker-library acceptance, explicit Stop/Closed
publication, the Startup executor and its prior-boot settlement now exist, but
ordinary model/profile/install/uninstall writers, new transport, the other
executors and same-boot recovery are not yet migrated.
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
target-execution API, retirement or job recovery bypass. Ordinary
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

The running configuration generation is attached to the exact owned Pico
process cell, not to a separately reconstructed engine. Moving that same broker
retains the association; a failed/rejected launch cannot replace it. Stop,
completion or uncertain ownership makes it unavailable, and a new unbound scope
cannot inherit its predecessor's value. This association is not a readiness or
closure proof: acceptance separately polls the same Group and requires Running
plus its bound generation, or a proven absent/Closed scope. A Running scope
without that association is refused without stopping it or publishing a job.

The private source snapshot is now explicitly `NKPSRC02`, with a v2 digest
domain and a presence bit plus the exact 32-byte launch generation. The public
`NKPJOB01` record layout is unchanged; `was_running` and initial resume intent
are derived from the captured association. Version 1 source files are not
reinterpreted or adopted: active/foreign state remains fenced. No source decoder,
old-source migration, operation executor or recovery authority is supplied by
this format change. These private values remain credential-bearing material,
not public status fields.

The fixed immutable `active` intent is published and synced first, then private
`payload` and `source`, then `.state.next` is synced and renamed over `state`.
Only final directory sync, reread and identity/inventory checks permit the exact
accepted ID acknowledgement. Every newly created file is mode 0600; unknown
write/sync/rename results retain evidence and the durable admission fence. No
acceptance path mutates a target, stops/restarts Pico, removes evidence or clears
an accepted job. Stop/Closed uses the separate retained owner described below.

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

## Current owned explicit Stop and Closed publication

`Broker::begin_picoclaw_mutation` consumes the same broker into `PicoMutation`;
refused admission returns that broker intact. The owner retains its submission,
Update/Config/store/source leases and native Group. It exposes no extraction,
restart, arbitrary worker, phase selector or target mutation API. All acceptance
and phase workers are joined before the broker may be dropped. The standalone
acceptance API remains acceptance-only; it is not native closure authority.

Accepting a job does not stop a live runtime. An explicit administrative
`request_stop` only queues intent; it is not an acknowledgement. The fixed worker
checks the exact current state and immutable private active/payload/source
identities and bytes, then durably publishes Stopping with `resume_allowed=false`.
Only after successful checked publication does the owner send native Stop.
Control-loop polls never join unfinished workers or wait on their filesystem I/O.

The same retained Group must report its completion receipt, matching owner reap
and control EOF before a private noncopyable job/boot/Home-bound closure proof
can publish Closed. A valid FailedExit or RuntimeError proves tree closure,
not successful Pico work: the native subreaper emits those receipts only after
kernel ECHILD. A Group with no owned Pico cell can skip Stopping and publish
Closed directly. An absent PID or unrelated process status is not used as proof.
Neither path proves unmanaged/legacy process closure or all-writer/raw quiescence.

Spawn/work/panic/publication errors and native uncertainty retain the fence;
late worker success cannot clear a latched RecoveryRequired. Repeated Stop cannot
reenable resume. Dropping even a closed owner does not finalize/retire its active
job. Closed remains nonterminal and protected until future checked settlement.

Disposable host fixtures cover live/absent/paused/error-completed native trees,
an independently live backend, blocked acceptance/phase work, joined teardown,
late uncertainty, changed private members, Stop/Closed publication failures and
real SIGKILL during Stop publication. They do not establish production launch
ordering, hardware execution or recovery. Automatic quiescence, the change paths
of all six operation executors, transport/API/S96 integration, activation and
recovery remain unimplemented.

## Current Startup no-op settlement

The startup-default transform is a pure shared module
(`update::picoclaw_startup`) used by both the API writer and the job. It
performs no I/O, entropy or provisioning: callers pass the tokens they selected
or planned. Gateway-token preference is security settings, then the legacy
security location, then the config copy.

An owner queues ordinary settlement explicitly with `request_settlement`;
accepting a request never starts it, and an explicit Stop keeps priority. The
fixed joined `pico-job-settle` worker re-checks the exact accepted state and
members. It then decodes the private source, takes a read-only snapshot of the
internal credential and classifies the accepted pair.

- **Canonical no-op.** The worker publishes a terminal Completed receipt
  (outcome Noop, runtime Unchanged or Suppressed) into the job's ring slot. It
  then retires payload and source, syncs, and retires the active fence last.
  Each member is re-checked against its owned identity and content immediately
  before its unlink. The pair's bytes, comments and inodes, its generation and a
  live runtime with its launch association are untouched.
- **Return of the broker.** `into_broker` returns the same broker only when no
  durable job is left to it: a terminal Completed, Superseded or
  SettlementRefused job, or a submission that never accepted one. It polls
  first, so an acceptance still in flight is never released. Dropping the
  submission first joins its workers and releases the store, source, Config
  and Update leases.
- **Missing token or value change.** A missing gateway or internal token, or a
  changed value, continues as the change settlement below.
- **Refused.** A missing Home or config, unparsable documents, malformed
  local-tool policy or a kind without an executor reports SettlementRefused.
  Nothing was planned, stopped or changed, so the refusal ends like the
  canonical no-op: a terminal Failed receipt (runtime Unchanged, or Suppressed
  when resume was already lowered), retirement, a live runtime untouched and
  the broker returned. A later explicit Stop cannot reopen the job. Otherwise
  a refused job would hold the Config fence until the next boot.
- **Publication or retirement errors.** These latch RecoveryRequired. A durable
  terminal receipt with remaining members stays fenced until early boot retires
  the remainder exactly; observation never re-runs the job.

Disposable chroot fixtures cover:

- absent and live runtimes;
- comment and format preservation;
- the change, missing-token and refused cases;
- the explicit Stop that follows them;
- injected failures before and after terminal publication and during each
  retirement step.

They are host checks, not physical power cuts or device acceptance.

## Current Startup change settlement

When settlement finds work, the worker selects any missing gateway or internal
token exactly once. It records the complete desired canonical pair and the
internal value as a protected 0600 `plan` member, bound by a domain-separated
digest to the job and its accepted source, before anything is stopped. A
retry or crash replays this plan and never draws new entropy. The store's
inventory follows the members it owns; the reader fence refuses any extra
member.

The same retained Group is then quiesced by automatic Stopping/Closed
transitions. These keep resume permission and are refused without a durable
plan; an explicit Stop instead lowers the permission monotonically.

Apply, from Closed:

1. **Lock and revalidate.** Convert the job's own Home lease to exclusive on the
   same open description, with a bounded wait for transient readers. Because a
   refused conversion can drop the shared lease, revalidation happens only under
   the exclusive lease.
2. **Superseded check.** If the pair or the internal credential differs from the
   accepted source and plan, publish a terminal Failed receipt (runtime
   NotRequested) and retire the job. Nothing is changed.
3. **Applying.** Publish Applying durably before any target change.
4. **Credential.** Install the planned internal value. An existing equal value
   is a replay; any other value refuses.
5. **Pair.** Publish the planned pair through its own crash-safe journal and
   re-read it exactly.
6. **Committed.** Publish Committed, carrying the installed generation.
7. **Activation**, only when resume is still allowed. Activating is durable
   before the SAME broker launches one scope bound to that generation under
   the job's retained admissions. The job waits for Starting to become Running
   and records Resumed, or ResumeFailed for any other result.
8. **No activation.** Otherwise the receipt records NotRequested (no runtime
   before) or Suppressed (an explicit Stop lowered resume).
9. **Retirement.** Payload, source and plan are retired, then the active fence.

An explicit Stop that arrives before apply lowers resume and then lets the
planned change apply without resuming. After apply has started, an explicit
Stop only suppresses resume.

The job's Source ends its Home lease explicitly on drop. A duplicated or
inherited description therefore cannot extend the lease; a host test proves
this against an uncontrolled alias.

Chroot fixtures cover:

- absent, live, missing-credential and stop-during-preflight changes;
- a relaunch of a real owned fixture scope with the installed generation;
- a superseded source;
- injected failures after Applying, after the credential, after the pair and
  after Committed. Each keeps the fence with its exact partial state.

Settlement after a reboot is described next. Same-boot recovery, the other
five executors and the transport/API/S96 wiring are not implemented yet.

## Current prior-boot settlement

A job that a previous kernel boot left behind would otherwise keep the fence
closed for every later boot: early S02 activation and backend boot support
both take Config through the bootstrap path, and that path refuses an active
job. Early boot therefore settles such a job first, under the Update and
Config it already holds and before enrollment and the normal fence run.

**Authority.** The job's boot tag is compared with the current kernel boot's
tag, computed exactly as the native broker computes it from the kernel boot
identity. A different tag proves that the job's native scope cannot have
survived. A job of the SAME boot is left for its native owner: the scope may
still exist, so nothing is settled and the fence remains. An uncertain record
is never adopted.

**Exact binding.** The recovery opener takes the store's exclusive lease,
requires a Ready anchor with the matching epoch, and reads each fixed member
once with root/0600/single-link/size checks. Its inventory must equal the
members found. Every present member must belong to the job: the active intent
embeds the accepted record (sequence, nonce, boot, Home, support, request,
source, kind, initial runtime facts; resume permission may only have fallen),
payload and source match the record's digests, and the plan its own binding.
Foreign or damaged data refuses; nothing is cleaned or rewritten by
observation.

Settlement by durable phase:

- **Accepted, Stopping or Closed.** No target change began. The job records a
  terminal Cancelled receipt (runtime NotRequested, resume lowered).
- **Applying (Startup).** The SAME durable plan completes under the job's own
  Home identity (device, inode, owner and mode must match the source). An
  interrupted pair journal is completed first. The pair must then be either
  the accepted source or already the plan, and the credential either the
  planned value or, for a new one, absent; the plan's value is installed and
  the plan's pair published only where missing. Any other state keeps the
  fence. No entropy is drawn and no classification is repeated.
- **Committed (Startup).** The change is complete. The receipt records Changed
  with Suppressed (resume lowered) for a previously running runtime, otherwise
  NotRequested. Recovery never starts a runtime.
- **Activating (Startup).** The relaunched scope cannot have survived the
  boot: Changed with ResumeFailed.
- **Any other phase or kind.** No executor exists; the fence remains.

Each settled job then retires payload, source and plan, syncs, and retires the
active fence last, re-checking every member just before its unlink.

**Completion pending.** A durable terminal receipt whose members were not all
retired needs only that exact retirement. It is finished in any boot, because
the outcome is already recorded and no native work remains; the receipt itself
is never rewritten. Members that do not belong to the head receipt, such as an
unpublished acceptance, keep the fence.

**Still fenced.** A staged `.state.next` from an interrupted publication, a
partial or damaged member, an interrupted acceptance and a same-boot owner
loss are preserved and refused, not cleaned. Explicit recovery of those
states remains to be implemented.

Chroot fixtures run the real early S02 entry after each injected failure:
first in the same boot, which must stay fenced with the state unchanged, then
in an emulated later boot, which must settle once and change nothing when
repeated. They cover:

- each Startup failure point from the durable plan through Activating, with
  existing and new internal credentials and with a live quiesced runtime;
- terminal publication and each retirement step;
- the explicit Stop and Closed publication failures, after their fixture
  processes are gone.

They are host checks, not physical power cuts or device acceptance.

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
Terminal publication and exact retirement are implemented for the Startup job,
including early-boot completion of an interrupted retirement.

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
remain unchanged and a live runtime is not stopped. A settlement refusal before
any plan or stop finishes the same way, as Failed. Every other skipped,
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
shapes and the acceptance producer writes the initial permission. The retained
library owner implements monotonic explicit-Stop suppression and
Accepted/Stopping-to-Closed publication. Automatic quiescence of a planned
change keeps the permission. Session revocation integration and durable HTTP
acknowledgements remain unimplemented.

Failure before any mutation can become a terminal failed/cancelled receipt only
after native closure and exact scratch/payload retirement. The one exception is
that settlement refusal: it never touched the native scope, which keeps running
as before the job. Once mutation may
have begun, an error, worker panic, process death or unknown sync result remains
nonterminal and fenced until operation-specific checked settlement. A returned
Err, worker join, reconnect, timeout or new boot cannot clear that fence.
Observation never performs mutation/recovery or retries a worker. For the
Startup job, early boot of a later kernel performs that checked settlement
(see Current prior-boot settlement).

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
