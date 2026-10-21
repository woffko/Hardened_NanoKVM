# PicoClaw mutation jobs: protocol decision, implementation in progress

This is the protocol selected for the stopped-mutation handoff. It is not an
activation or acceptance report. The ordinary model/profile/install/uninstall
writers, durable store, new transport and recovery path are not yet migrated.
The legacy onboarding completion boolean is not a durable job receipt.

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
