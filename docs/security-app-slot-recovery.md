# Independent app-slot recovery component

This describes source/host-tested preparation, independent daemon delivery,
native-closed publication, rollback and early consumer gates, not a completed
API installation lifecycle or WP-04/C1 fix. Since 2026-10-23 the online and
offline app update API hands its verified candidate to this installer instead
of swapping `/kvmapp` itself; that path is host-tested with the fixed-root daemon
and is not accepted on a device. The new helper is compile-bound into the linked RV64 backend and
packaged under `/kvmapp/system/bin`. Build recipes now install an independent
`/usr/libexec/nanokvm-app-recovery` copy, and the target backend attempts atomic
installation for an app-only bridge. S02 and individual consumer gates now invoke
it, but device acceptance of the API submission and the broker, the remaining
producer activation, legacy first-bridge target acceptance and helper migration
remain open. The full remediation scope is unchanged.

## Authority and fixed storage

The standalone `nanokvm-app-recovery` accepts only `status`, `recover` and `gate`.
There are no root, journal, stage, phase, force, prepare or commit arguments.
Recovery cannot publish a new app or issue a trusted installation receipt.
After acquiring common update admission, recovery retains the native singleton
and requires a canonical native `Closed` in this boot or a valid record from a
different kernel boot. Missing native state is not closure. Same-boot Active,
Maintenance or Stopping, a live owner, and ambiguous/unsafe state refuse mutation.
It also holds both enrolled-writer exclusions, and writes durable current-boot
Stopping before app mutation. Installer death releasing UpdateEX is not proof
that independent runtime descendants stopped. See the recovery boundary below;
changed boot identity never grants app health or raw/restore authority.

Production storage is fixed at `/etc/kvm/application-slot/current`. Root, `/etc`
and `/etc/kvm` must be protected root-owned directories on the same rootfs.
The slot store/current directories require root ownership and mode 0700. Opens
reject symlinks, magic links and mount crossings, including same-device binds.
Recorded slots must be root-owned, non-group/other-writable directories on the
same device. Legacy ownership requires an explicit installer migration before
this protocol is activated; the recovery helper does not silently chown paths.

The fixed store directory retains a nonblocking `flock`. Its inode is never
unlinked or replaced to release admission. Status takes a shared store lease;
recovery takes an exclusive lease and the existing shared app/system update
admission. The store owner explicitly unlocks at teardown so a concurrent fork's
pre-exec alias cannot prolong completed work. This is not descendant quiescence.

The canonical mode-0600 single-link regular `state` is exactly 512 bytes. It
contains a versioned magic, phase, explicit signed/manual/unsigned-lab import
kind, nonzero transaction ID, distinct old/new device+inode identities, archive
SHA-512, exact metadata/signature SHA-256 context, and bounded numeric x.y.z
version. Reserved bytes and the whole domain-separated SHA-256 checksum are
validated. These hashes detect corruption and retain context: they do not
perform RSA verification or authenticate an attacker-supplied manifest.

The new preparation issuer takes an opaque `AppCandidate` produced by the app
API's private bounded extraction path, plus the app-only retained update/writer
handoff. It does not accept a directory, caller-supplied import mode or digest as
authority. The factory fingerprints the actual readonly archive descriptor,
rechecks its size/hash against authenticated online metadata, binds the candidate
version and records exact metadata/signature byte hashes. Manual import and
policy-authorized unsigned-lab metadata remain distinct; neither is relabeled
as signed. The API passes this candidate to the journal issuer and then to the
installer endpoint, as described under independent daemon delivery. Rootfs
protection, issuer provenance and the closed restore policy are mandatory.
Neither a copied p3 record nor a valid checksum creates installation authority.
Host tests require the new journal, temporary records and old/new code slots to
be absent from restore capture, rejected on restore import, and undeletable by
restore absence records. Legacy S01 p3 import and API p3 pending authority are
now retired; raw installation is temporarily refused in the development branch.
The authenticated raw/early-restore replacement is still an open C1 blocker and
must preserve these exclusions. Removal of the old path does not itself activate
early app recovery or authenticate old rootfs state from a compromised boot.

## Supported rollback layouts

`old` and `new` below mean the exact recorded directory identities, not names
chosen by a manifest. Only these layouts are admitted before recovery:

| Active `/kvmapp` | `current/new` | `current/old` | Recovery before commit |
| --- | --- | --- | --- |
| old | new | absent | Keep old; record rolled-back |
| absent | new | old | Restore old; record rolled-back |
| new | absent | old | Park new, restore old; record rolled-back |

All other layouts, missing/foreign identities, aliases or unsafe objects refuse
mutation and retain evidence. A terminal committed record additionally requires
new to be active; rolled-back requires old to be active. The candidate is always
retained at `current/new` after rollback, not deleted. Recovery never scans
orphan preparation directories, selects a temporary record, reads legacy p3
markers, or repairs an unknown layout by guessing.

For an uncommitted transaction, recovery first publishes `rolling-back` using a
fresh exclusive mode-0600 temporary, file sync, canonical rename and directory
sync. Mode 0600 is set on that newly created FD independently of inherited
umask; unsafe existing records are still refused rather than chmod-repaired.
If new is active, it is parked at `current/new` using NOREPLACE. The recorded
old is restored to `/kvmapp`, also NOREPLACE. Root/current/store directories are
synced, the resulting layout is checked, and `rolled-back` is published. Errors
leave the last durable state and evidence for a fresh inspection. Torn temporary
records are retained but never selected as authority or reused for publication.

Repeated recovery of a terminal record validates the layout and completes the
directory durability barrier without replaying renames. `committed` denotes
publication state only, not accepted runtime health. The complete first-restart/
boot composition, rollback policy and actual new-runtime health acceptance
remain to be integrated and tested before the new installer
can be considered complete. `no-transaction` is diagnostics, not boot-good or
permission to execute an arbitrary app directory.

Absence means no canonical `current` transaction or exact recovery intent, even
when protected unpublished preparation siblings remain. Such siblings are retained but never scanned,
decoded, selected or promoted by recovery/bootstrap. Installing the trusted
backend's compile-bound independent helper in that state is the same operation
as the ordinary historical-absence case; it does not use orphan bytes as authority
and does not publish/execute an app. Unknown installed helpers still refuse.
The issuer retains its own unpublished preparation material after an ambiguous
move/sync failure. No deletion or automatic orphan activation is implied here;
explicit orphan disposition and physical fresh-boot acceptance remain required.
Successful live commit/rollback now archives its exact terminal directory as
described below; generic early recovery does not infer that live capability.

## Durable preparation and lease acceptance (not activated)

Preparation takes the protected store's exclusive lease and refuses any existing
`current`, including terminal transactions and unsafe/foreign entries. It verifies
the live old directory and the candidate's same-rootfs identities, exact stage
binding, bounded depth/member/byte totals, ownership and modes. The recursive
durability walk refuses symlinks, hard-linked files, special objects and mount
crossings; it checks the entry's type before opening it and verifies the opened
inode. Candidate files and directories are synced before publication.

A fresh `.prepare-<transaction-id>` sibling receives the candidate with
`RENAME_NOREPLACE`; source and destination directories are synced. The complete
mode-0600 `prepared` record is published and synced there before the whole
preparation directory becomes `current`, also with `RENAME_NOREPLACE`, followed
by parent sync. `/kvmapp` is never renamed or written in this phase. A process
failure before the final rename leaves only unpublished evidence; after it,
existing recovery can select the recorded old slot. These are process-death
claims, not proof of physical power-loss/write-cache behavior.

`PreparedInstall` retains store serialization and the three close-only update/
writer exclusions. `into_handoff` releases only store serialization. The receiver
must call `accept_prepared` with its validated lease: this reopens only the fixed
canonical journal, requires the same transaction ID, phase `prepared` and exact
old-live/new-staged/no-old-parked layout. Another ID, later phase or already-swapped
layout is rejected without rewriting the journal. `AcceptedInstall` retains both
the store and accepted exclusions; it alone is not a native Stop, slot publication
or health capability. Publication additionally requires the retained native owner
described below.

An early-rejection owner groups candidate staging before the retained handoff
in field order, before any fallible fixed-root/store inspection. Candidate
cleanup therefore finishes before update/writer exclusions close, even when
the original frontend owner has already gone. A child-process test pauses inside
the real staging destructor and probes all three kernel exclusions before
allowing cleanup to finish.

Host tests feed real synthetic archives through the production candidate factory,
verify signed/manual/unsigned provenance and reject different archive bytes even
when their extracted payload would be identical. Eleven actual SIGKILL boundaries
cover preparation/record/publication; unpublished candidate inode identity and
old-live preservation are checked. A fresh user/mount/PID namespace with a real
private procfs exercises the actual fixed-root issuer, an exec'd lease receiver,
canonical acceptance, sender teardown, continued three-domain exclusion and
ordinary recovery after receiver exit. That anonymous-worker fixture is not the
named daemon endpoint, HTTP/device acceptance or a complete install lifecycle.
The independent delivery test below additionally covers queued transfer and
actual frontend death before daemon acceptance with canonical prepared state.

## Native-closed publication and retained rollback (not activated)

`Broker::begin_app_install` consumes an accepted install and the live broker.
The accepted install already retains UpdateEX and both writer exclusions; this
path must not reacquire those locks or an enrolled Configuration permit. It
durably publishes native `Stopping` before requesting Stop from KVM, hwmon and
backend. A failed journal publication returns both complete owners and does not
start the drain. The retained session owns the group, journal, boot enrollment,
app store and all three transferred exclusions. Losing the frontend is not a
reason to release these owners or resume native work.

Only this session can produce a transaction-bound closed-runtime capability,
and only after all three scopes prove completion by receipt, direct-owner reap
and EOF. `Stopping` remains durable after they drain: app work is still ongoing.
Missing or uncertain receipts prevent publication and rollback-resume; even
reaping the direct owners does not grant closure of their descendants.

Publication rereads the canonical prepared receipt and exact slot layout. Before
changing the live slot it preserves only `kvm/{ap.ssid,ap.pass,type,fps,qlty,gop,res}`,
the exact existing restore-policy app-data subset. Each optional source must be a
protected single-link regular same-rootfs file, at most 4096 bytes; symlinks,
mount crossings, special objects and unsafe permissions are refused. Values are
held in zeroizing buffers, old files/directories are synced for rollback, and new
copies are atomically published mode 0600. Absence remains absence instead of
silently installing a packaged default. Arbitrary old scripts, keys and trees
are never copied. This is not a claim that unenrolled writers are quiescent.

The canonical phase is then synced as `publishing`, old `/kvmapp` is parked by
NOREPLACE rename, candidate `new` is renamed live, both parent sets are synced,
and `published` is synced. An I/O error is not retried from a cached in-memory
phase: the retained owner must inspect durable state. `published` is not healthy,
committed or API success. Before any trial runtime starts, explicit rollback
restores the old slot under the same exclusions, durably resumes native Active,
and returns a terminal owner that still holds install admission until explicit
release. An uncertain failure retains the whole session; Drop never resumes it.

Host tests exercise all three actual controller-protocol child processes,
delayed backend closure, missing receipt and native-journal publication failure.
Nineteen SIGKILL boundaries cover seven data publications, both phase records,
slot renames and directory syncs; recovery restores the recorded old inode and
data and is repeatable. These process-death fixtures are not target power-cut or
vendor-native acceptance. The existing standalone scope tests separately cover
subreaper descendant closure; the new protocol stubs do not replace that proof.

Production API activation, full runtime health, physical terminal-failure/
fresh-boot acceptance and bounded history retention remain open. The daemon now drives
the typed trial/commit policy below in host tests. Ordinary backend startup is
not a usable trial path while
writer exclusions are retained: it acquires writer/update
admission and performs storage, helper, trust and init-script writes. Do not
release/reacquire the exclusions to make that startup succeed.

## Independent daemon delivery and API submission

The ordinary online and offline POSTs now end with this delivery. After the
verified candidate is ready they connect once to the installer endpoint and
close again, so that an absent installer is refused before any durable record:
a prepared record that nobody accepts would block every later update until boot
recovery retires it. Then they prepare the record under the retained
update/writer handoff, connect again (the daemon drops an offer idle for five
seconds, and preparation syncs the whole candidate) and send the handoff. The
reply carries the transaction ID; the broker then stops this backend for the
frozen trial. A failed send reports that ID and must be inspected through
`/update/jobs/{id}`, never submitted again. The legacy `/kvmapp` swap, its
`/root/old` backup and the S95 restart after the reply are gone. The web UI
polls the job across the drain and trial; the restarted backend has no session,
so its 401 leads to login, after which the update page reads the stored
transaction once more. The fixed-root delivery fixture drives this exact API
composition, including the refusal with no installer listening.

The existing independent native broker is itself the installation owner; an
additional installer child is not spawned below the backend's subreaper. This
keeps the real native controller/journal owners and accepted app store together.
The fixed root-only `/etc/kvm/native-runtime-owner/app-install.sock` is mode0600
SEQPACKET, distinct from the mode0600 STREAM lifecycle endpoint. Parent checks,
pinned proc-fd addressing, CLOEXEC/NONBLOCK and exact-inode cleanup apply to both.
There is no generic pathname/program/root selector or FD-carrying lifecycle op.

`Sender::connect_broker` selects only this protected endpoint. `offer` answers
Taken, Refused or Unknown. Taken arrives before the backend is told to stop and
says who owns the transaction, not that it is published, committed or healthy.
On Refused nothing started and every lease of the offer is closed: the API
withdraws the prepared record, which would otherwise block further updates,
backend restarts and Pico until a reboot. An older daemon closes without a word,
which reads as Unknown, and Unknown does not authorize submitting another
transaction. The daemon retains at most four
nonblocking offers, with the normal five-second idle budget, while continuing
lifecycle servicing. It reuses the exact 72-byte/three-rights lease parser,
validates the pinned protected lock domains and requires canonical prepared
receipt/layout acceptance before any native Stop. A root peer or lease packet
alone cannot supply candidate/signature authority.

After acceptance the daemon owns Session independently of the offer socket.
Sender death/EOF does not cancel it or release its three exclusions. It drains
all three runtime scopes and attempts publication once. Published stays
`Installing` and holds admission while the Engine starts the fixed frozen trial.
Ready drives durable app/native commit and the explicit backend Commit relay;
its complete acknowledgement permits terminal archival. Only successful archival
releases admission and returns ordinary supervision. KVM/hwmon desired-role
retries resume after that release, never inside the freeze. `BackendRunning`
is Unavailable while an install owner exists,
even if its trial has reported Ready; it is not a full KVM health API.

No ordinary launch/restart/pause/resume/shutdown replaces an install owner.
The fixed `CancelAppInstall` action can request precommit cancellation: Stop,
fresh complete join, then durable rollback. Ok plus Installing acknowledges
owned cancellation, not completed rollback; observe the later mode/state.
CommitPending refuses cancellation. Failed/uncertain commit retains its owner
without automatic retry; canonical Committed cannot roll back. Failure before
commit automatically follows the same stop/join/rollback path. Missing receipts
remain Uncertain even when the process is reaped. This is local root
administration, not a remote unauthenticated cancellation API, durable app job
status or an app-health success response.

Host tests run broker and sender as separate exec'd processes. They kill the
sender after queuing but before daemon acceptance, then prove retained exclusion,
canonical publication, blocked ordinary lifecycle operations, explicit rollback
or complete trial/commit and post-freeze native restart. Replacing the observing
client during trial does not transfer or cancel the job. Readiness and Commit
acknowledgement can be held independently to check no early release or success.
Other tests cover malformed/stalled offers, expiry and slot reuse, invalid receipt
before Stop, endpoint type/permissions and preserving a foreign replacement on
Drop. These use cfg(test)-only rooted data and native protocol stubs. A second
private user/mount/PID namespace with real procfs exercises production
`Sender::connect_broker`, `Incoming::open`, fixed-root preparation/acceptance,
publication and rollback without their rooted-path overrides. That minimal chroot
intentionally stops at Published via a test-only hold and has no executable
native/backend runtime. Enrollment is fixture supplied: this is not production
daemon CLI, target boot, vendor-native or device acceptance.

## Space admission (not reservation or history GC)

Private app staging now checks the pinned filesystem with `fstatvfs` before
creating stage directories, an unnamed archive, and each archive append. It
uses available blocks (`f_bavail`), not privileged free blocks, and available
inodes. Read-only filesystems, unsupported/invalid counters, overflow and lack
of room refuse admission. The current policy leaves 16 MiB and 128 inodes for
journal/recovery/metadata work; these are safety margins, not a reserved extent.

Online and manual offline candidate preparation share `AppStage::extract`.
It validates the entire immutable archive without creating extraction output,
rewinds that same descriptor, rechecks the stage binding and rereads capacity
before extracting. Inspection/extraction share one parser and all existing
GNU long-name, path/type/member/decoded-byte/tail/CRC limits. One bounded path
map distinguishes files/directories and rejects duplicate files or parent/type
collisions; it does not keep a second copy of the path inventory or archive.

Space is estimated from actual members, not the maximum allowed expanded
archive size: rounded file data, namespace/directory overhead and new inodes.
The compressed archive has already consumed its own space and is not charged
again. Before the trusted installer overlays its seven bounded settings files,
it separately budgets that complete snapshot before replacing candidate data.
No recovery/journal operation is refused merely for dipping into this admission
margin: failed installs must still be able to use available recovery space.

This check is advisory, not a guarantee against quota, fragmentation or a
concurrent writer consuming space after the observation. ENOSPC/I/O handling,
all-writer freeze and physical acceptance remain required. Host tests include
synthetic boundary/counter cases and private namespace tmpfs low-block,
low-inode, read-only and successful small-archive scenarios. They neither fill
the host disk nor prove target ext4/power-loss acceptance.

The check never deletes staging or history to manufacture a PASS. Separate
inactive-payload pruning below uses retained lifetime authority and its own
protected journal. Bounded receipt expiry/cutoff and full GC acceptance remain
required. App
Committed, archived status, mtime/UUID order and PID absence do not authorize
deleting a known fallback. The ordinary app API submits through the installer
but is not accepted on a device.

## Terminal archival and per-transaction observation

Terminal retirement now records protected ordering and retention pins before
moving `current` into history. A fixed 256-byte `order` receipt in the exact
transaction directory and `application-slot/history-head` bind a monotonically
increasing sequence, predecessor transaction/digest, full terminal-record
digest, directory device/inode, source baseline, fallback and resulting live
identity. Neither random UUIDs, versions, mtime nor wall time select ordering.

The baseline is the source app of the first enrolled terminal transaction,
not an assertion that it was physically tested or healthy. It is never promoted
by `Committed`. A committed transition pins its previous live app as fallback;
a rollback preserves the earlier fallback. These pins do not execute a retained
app, approve a downgrade or themselves grant permission to delete any tree.

Receipts are written and fsynced as anonymous files before their first link.
Only the publisher's held FD in verified procfs is followed for that link;
there is no caller-supplied source pathname. Fresh files have exact mode 0600.
The per-transaction receipt is durable before the next head is published, and
the head is durable before archival. An interrupted complete head publication
can resume only for the same terminal context and exact directory. Missing,
foreign, malformed, linked or unsafe receipts are retained and refused, not
repaired. A published head cannot recreate a missing transaction receipt.

Issuing a subsequent app requires the head's exact archived directory/receipt
and the expected current live identity. An unordered pre-policy history cannot
be silently enrolled; it stays preserved and needs an explicit migration policy.
This is development-only state: it is not a requirement imposed on published
legacy RC12 assets, nor device acceptance of the ordinary app API.

Inactive payload expiry and bounded receipt retention now have separate journaled
development paths below. Full GC acceptance and baseline health/promotion policy
remain required; order records and the advisory space guard alone are not GC.

An acknowledged `Committed` or fully joined `RolledBack` owner now attempts
terminal archival before releasing install admission. Only those typed owners
mint the transaction/phase-bound capability; a status read or root peer cannot
turn a journal phase into runtime-closure authority.

The retained store rereads the complete canonical record, requires the expected
terminal phase and exact old/new/live layout, and checks the pinned `current`
directory identity. It syncs the terminal record and parents, then renames
`current` to the fixed protected `history/<32-hex-transaction-id>` with
`RENAME_NOREPLACE`. The archived record and directory identity are checked again,
then the archive directory and both rename parents are synced. Newly created
history is mode0700 independently of root's umask; unsafe existing history is
refused, never chmod-repaired. The archival rename does not delete the current
transaction's app trees or temporary evidence. Committed history initially
retains the old slot and rollback history the new candidate; older unpinned
payloads may later expire through the separate path below.

Only completed pruning and successful archival release the store/update/writer exclusions and allow
another prepared transaction. Any collision or ambiguous I/O returns the whole
terminal owner. The Engine remains Uncertain and does not restart native writers,
automatically retry retirement, or roll back a canonically Committed candidate.
The still-pinned exact owner can retry after an earlier rename/sync error; a new
process must not fabricate that capability from a diagnostic phase alone.
Live terminal archival can now be retried explicitly as described below.
Safe stopped/prior-boot recovery uses a separate retained boundary below; it
does not fabricate a live daemon owner or authorize a same-boot Active orphan.
Bounded retention/space accounting and safe garbage collection are also
required before activation: keeping evidence indefinitely is not an acceptable
final disk-space policy.

`app_slot::job_status(transaction)` supplies a bounded read-only observation for
a nonzero transaction ID from the fixed protected root. It does not acquire the
store flock, so another process can read a canonical snapshot while the installer
owns EX. It checks exact directory ownership/modes and the same single-link,
mode0600, 512-byte regular record. A history/current/history lookup closes the
single archival-rename observation gap without scanning or selecting orphan
directories. The installer may publish a new current record during the read:
its rename unlinks the pinned inode, or makes the name refer to another one.
The read then starts again, up to 8 times, instead of reporting the normal
publish as unsafe. Unknown IDs return no result; unsafe/corrupt entries return an
error without repair. Locked readers (installer, recovery) still refuse a
record replaced under them. Archived records are historical context, not assertions
about today's live slot or rootfs device identity.

`Committed` still means durable publication, not accepted runtime health.
`archived` reports namespace observation, not a successful physical durability
barrier or end-to-end install result. A record can become visible before the
retained owner's final sync/release, including on an I/O failure. The future HTTP
job API must compose this snapshot with the retained owner/failure lifecycle;
it must not report success merely from either field. No HTTP endpoint or helper
CLI selector is added by this read API.

Host tests cover three successive Engine installs with distinct queryable results,
both typed release failures and explicit retries, both retained Engine terminal
owners on foreign archive collisions, and frontend-death commit archival.
The real fixed-root sender/receiver fixture reads the public per-ID snapshot
during exclusive ownership and after rollback archival. File-layer tests inject
I/O errors and actual SIGKILL at thirteen archival/order boundaries for both
terminal phases and initial/subsequent heads, retaining the exact descriptor for
retry; they do not simulate fresh-boot
authority or physical power-loss/write-cache behavior. Foreign/symlinked paths,
special/oversized/linked records and mismatched context are rejected without
deleting evidence. These tests do not complete WP-04/C1 or target acceptance.

### Inactive payload pruning

Before advancing the terminal head or archiving the current transaction, its
retained native/update/store/writer owner may retire older inactive payloads.
It follows the exact protected predecessor chain, validates every receipt and
archive name, and preserves baseline, fallback, live and both current app
identities. UUID order, time, phase alone and root peer identity do not authorize
this operation. Unknown archives, extra archive-level evidence, unsupported
types, unsafe ownership/modes, hardlinks and mount crossings refuse.

The deletion unit is the **whole obsolete private app-slot payload**, not an
arbitrary user directory. Its bounded inventory records exact paths, types,
file sizes/modes, device/inode and parent identity. User-state ownership and
migration must be accepted before enabling the new updater: a valid inventory
does not prove that account/profile/workspace data was preserved elsewhere.
Default PicoClaw state lives outside the app, but its effective config/home and
workspace are configurable. Resolve the actual selected paths: a custom workspace
inside a replaceable app/slot tree needs explicit durable migration before swap
or GC; default-path coverage is not proof of custom-state preservation.
The ordinary app API submits through the installer; no device acceptance is claimed.

The immutable manifest is bound to both current and victim order receipts.
Only complete fsynced anonymous files are linked into the protected namespace.
The payload moves with NOREPLACE to a fixed quarantine in its own archive.
For each deterministic postorder member, a durable pending cursor precedes
unlink; the checked parent's fsync precedes cursor advancement. Recovery
revalidates the remaining tree and permits absence only for the one pending
member. Missing/foreign/corrupt progress and substitutions refuse without repair.
No recursive pathname deletion or collision overwrite is used.

Cursor replacement keeps its file and directory durability fences on both fresh
publication and retry. A fresh `NEXT` already passed the publisher's file sync
and parent-directory sync; the caller does not repeat that same parent sync
without an intervening write. A surviving `NEXT` found on retry is still synced
as a file and directory before canonical rename. The post-rename directory sync
remains mandatory before deletion or cursor advancement proceeds. Targeted
subprocess tests distinguish these paths and recover a real process kill after
the temporary link, in addition to the existing full prune crash/fault matrix.
They also cover replacing an existing ready cursor with a pending cursor and
recovering an orphaned advancing cursor after the node's durable removal.
This removes duplicate flushes, not a required durable boundary or a test timeout.

After the entire payload and its parent are durable, a protected expiry receipt
is published and the current manifest/cursor are removed. The historical state
and order receipts remain. `inactive_payload_retained=false` requires that valid
expiry and absence of both payload/quarantine; a missing pathname alone is an
error, not expiry. Reads during pruning may return Busy rather than a false
availability result. Expired old inode numbers do not claim or clear a new app's
current pins when the filesystem reuses them.

Inventory limits are 8193 nodes, depth64, 4096-byte paths, 32 MiB aggregate path
bytes and 256 MiB plus64 KiB file data. Validation streams manifests and borrows
their paths instead of keeping duplicate full inventories. The separate bounded
receipt path below replaces the permanent128-operation admission backstop.
Actual ENOSPC/I/O, mutable-state, native/runtime and physical power-cut acceptance
remain required; development source or host fixture success is not release acceptance.

Journal creation separately checks the manifest's exact serialized length and
peak cursor/replacement, expiry, history-head and namespace demand against
fresh pinned-FD available blocks/inodes. This preserves the separate16MiB/
128inode recovery margin; the up-to34MiB manifest must not spend that margin.
No future reclaimed payload space is counted before deletion. A resumed
unfinished prune refreshes the remaining journal budget without double-charging
the resident manifest. Fully published expiry cleanup needs no new allocation
and is not blocked by this admission margin. These are advisory checks, not
reservations or a guarantee against concurrent writers or real storage failure.

Host tests cover exact deletion and retained pins/receipts, CRC/schema failures,
per-step process death/I/O recovery, unknown input/substitution, non-UTF8 names,
hardlinks/FIFO and an actual private-namespace bind mount. Engine tests prove a
GC error retains the terminal owner and exclusions until an explicit retry;
repairing the fixture fault alone does not release it. These are not physical
reboot/write-cache or full updater acceptance results.

### Bounded terminal receipts (development)

The retained terminal owner keeps the latest32 ordered terminal receipts plus
at most two older archives needed by actual baseline/fallback payloads. The
monotonic sequence is not reset when receipts expire. The protected anchor
binds the exact retained floor Order, publication owner and out-of-window pins;
older predecessor records are not reconstructed, scanned for adoption or rewritten.
The baseline is still a source identity, not a known-good health assertion.

Before issuing another candidate, admission requires no current transaction,
validates the complete bounded archive namespace and its payload/expiry states,
and checks actual source/fallback presence. A source that is still the exact
live root needs no invented historical archive; later commit may move it into
an archived pin. Missing/foreign anchors or history are preserved and refused.

Receipt expiry follows payload pruning and durable head publication but finishes
before current->history archival. Its bounded immutable manifest binds current
owner/head, prior anchor digest, target cutoff, history-directory identity and
the exact expired victims, including state/order/expiry bytes and file inodes.
Only already-expired unpinned archives can be selected. The remaining chain,
payload/expiry states, pin presence and namespace are revalidated before deletion.
Both native/update/store/writer exclusions and the exact current directory remain
owned on failure; no API snapshot or phase grants permission to finish it.

A pending cursor precedes each NOREPLACE quarantine, fixed-file unlink and empty
directory removal. Fsync precedes progress advancement. Missing or substituted
evidence refuses; a missing cursor cannot reconstruct authority after quarantine.
The new anchor is published only after exact victims are durably removed, and
manifest cleanup follows anchor durability. Space admission includes receipt
journal/cursors/anchor without spending the separate recovery margin.

Queries for victims of an active manifest return Busy, not partial state.
After receipt expiry a missing transaction means unknown **or no longer retained**,
never proof that an update failed or never ran. Retained/pinned records keep their
ordinary diagnostics; these remain distinct from health and durable HTTP-job
acceptance. Host fault and long-history tests pass; this development path is
not deployed and has not passed target or complete updater acceptance.

### Read-only transaction status (development)

Authenticated `GET /api/application/update/jobs/{transaction}` reads one exact
canonical app-slot transaction. Its ID is 32 lowercase hexadecimal characters,
nonzero; it is not a path or an execution capability. The production reader
uses only the fixed protected root, never a request-selected directory or a
history scan. The endpoint does not acquire update/writer admission or mutate
the app, and it cannot install, cancel, retry or promote a candidate.

HTTP 200 / code 0 describes successful **lookup**, not successful installation:

- `state: observed` carries `transactionId`, canonical `phase`, `version`,
  `archived` and `inactivePayloadRetained`. Even `committed` is an observed record,
  not a new assertion of runtime/device health; `archived` is namespace observation.
- `state: busy` means a safe observation is temporarily unavailable. No partial
  phase or success is inferred while a selected receipt is being pruned.
- `state: unknownOrExpired` covers absent or no-longer-retained receipts. It does
  not mean that an installation failed or never happened.

Malformed IDs return 400. Four shared read permits bound accepted filesystem
lookups across cloned server state; excess requests return 429 without waiting
for admission. A lookup runs outside the async executor and retains its permit
even if the HTTP waiter disappears, including before the blocking callback starts.
The accepted work can wait in the runtime's bounded-by-these-permits blocking
queue; this is not a claim that kernel I/O is preemptible. Corruption, unsafe
layout, I/O, mismatched identity or a reported worker-join failure returns 503
with a fixed error, never an inferred absence or private path. A fatal server
abort produces no response and must not be interpreted as installation failure.
Responses are `no-store`; the shared API security layer also adds `max-age=0`.

This route grants no install authority and does not replace the old in-memory
`/update/status` snapshot. The ordinary POSTs return the transaction ID and the
web UI polls this route; reconnect after the trial restart goes through login.
The mutable-state allowlist (`ap.ssid`, `ap.pass`, `type`, `fps`, `qlty`, `gop`,
`res`) covers every persistent setting written under `/kvmapp`; `width`,
`height`, `state`, `now_fps`, `wifi_state` and `wifi_try_connect` are runtime
status or one-shot requests, and `/kvmapp/picoclaw` is shipped content. Complete
target acceptance remains required before release.

### Explicit live-terminal archival retry

Support preparation/exchange and the subsequent app publication use a retained
closed-runtime owner and the same fixed worker machinery as terminal retirement.
The broker retains native supervision; filesystem work borrows, never consumes,
accepted admission. Publication is a distinct fixed operation, with the same
preserve/journal/rename/fsync protocol; only its exact Published result can
advance toward trial after native closure is rechecked. Cancel while support
or publication I/O is active queues rollback until the worker has joined and
closure/layout are revalidated. It cannot overlap a
support exchange/publication or override native uncertainty. Failed preparation
or publication is not implicitly replayed by observation/reconnect; terminal
retry below does not address these nonterminal stages.

Durable commit uses a separate fixed worker holding both the accepted install
and native journal, including their exclusion leases. The live trial Group and
boot enrollment remain supervised by the broker; its control path never waits
on the worker's mutex or filesystem writes. The worker commits the app record
and resumes the native journal in that order, without sending backend Commit.
Only a finished, joined, known-success result and fresh native health permit
the broker to acknowledge the trial on a later tick. Native uncertainty is
latched across both writes and the acknowledgement gap. Failed or uncertain
commit retains the complete owner, even if the app record is already Committed;
observation, reconnect, cancellation and terminal retry cannot replay it or
authorize Stop/rollback. Teardown joins before releasing journal/update leases.

Rollback now has its own fixed joined worker. A fresh complete native drain
authorizes the exact accepted transaction; the same broker retains that Drain
while the worker restores support/app state and then resumes the native journal.
Both journals and the accepted store/update/writer leases remain with one owner.
Only successful joined work, fresh native closure and journal readiness permit
conversion to the RolledBack terminal owner; archival/release remains a separate
step. No callback, path, executable or caller-selected phase is accepted.

Spawn failure, caught panic, layout/write failure or forfeited closure authority
retains the rollback owner without replay, resume or early release. This includes
failure between the app rollback record and native resume, and panic after both
writes. Removing a collision, observation, reconnect and another Cancel cannot
retry that unknown rollback or turn it into terminal-retirement authority.
Cancel during rollback reports unknown completion rather than launching a second
operation. Teardown joins before releasing singleton and accepted admission;
production panic=abort still needs durable process recovery.

Host fixtures hold work before rollback, between the two durable boundaries and
after both writes while checking control responsiveness and retained exclusions.
They cover real missing native receipt before admission, publication-error and
foreign-layout refusal, cancellation and joining teardown. A separate private
fixture forfeits main-thread authority after a real completed drain and verifies
that later successful I/O cannot clear it; that models proof loss, not a physical
owner loss after all scope owners have already reaped. Other synchronous steps
and actual kernel-blocked I/O still require responsiveness acceptance; these host
checks are not target/device or whole-install latency acceptance.

Root may issue `nanokvm-native-ctl retry-app-retirement` through the existing
protected lifecycle channel. This is the fixed `RetryAppRetirement` opcode in
the same closed lifecycle protocol (now 48-byte NKC2/NKR2 frames), not a new
unauthenticated endpoint. It accepts
no path, transaction selector, phase, force option, archive or executable.
It addresses only the **current retained live** Committed/RolledBack owner;
it does not recreate an owner after daemon death or from a journal snapshot.

Retry can only repeat that owner's exact retirement/prune/archival/sync/release operation. It
cannot install, publish, commit, cancel, roll back or repair foreign objects.
The operator must first inspect and resolve the actual I/O/space/path fault;
the command itself never deletes a collision. A denied or failed retry retains
the complete owner and exclusions. The command refuses when no install is
retained, during a nonterminal trial or pending Commit acknowledgement, and after
an earlier failed commit.
Connection EOF, observation and repairing a path do not implicitly retry it.

Terminal retirement is asynchronous: one broker-retained worker performs the
same exact filesystem operations, including all durability syncs. The broker
retains its native group for supervision, and separately retains the accepted
install while the worker only borrows it. Spawn failure, caught unwind or failed
I/O keeps the owner and exclusions. The release profile is panic=abort: a
production panic kills the daemon and requires durable recovery, not live retry.
An active attempt is not replaceable by retry
or cancellation. Ordinary caller loss does not drop or detach the worker.

Both ordinary terminal release and retry poll the group's latched ownership
uncertainty before archival and again before release after successful I/O.
They do not turn later owner loss into Running simply because the earlier app
phase was terminal.
This is the same guard used by ordinary scope launch admission; it is not a
health receipt or a reset of the group. PID disappearance/direct reap alone
cannot clear it.

Ok/Installing acknowledges a new retry attempt, not completed archival. The
fixed CLI waits by observation rather than repeating the opcode. Exact frame
replay returns the cached admission reply, even after completion; use a fresh
observation for current state. Ok/Running means exact retirement, archival and release completed and
ordinary supervision may proceed; it does not mean native/backend health or
device acceptance. The action is current-owner administration, not a per-ID
durable HTTP job API. No S02/S95/watchdog path automatically invokes it.

The worker must finish and join, with known success and a fresh ownership check,
before exclusions are released. Successful filesystem retirement after native
owner loss does not authorize Running. Daemon teardown joins the worker before
dropping accepted admission; genuinely blocked kernel I/O can therefore delay
teardown. Process death still requires durable recovery, not PID adoption or
reconstruction of this live proof from a terminal status snapshot.
The future HTTP control path needs transaction-bound authority; checking a job
snapshot and then calling this current-owner action is not an atomic ID binding.
An exact request replay on the same connection returns the cached result;
that cached reply is not a fresh observation of current mode. Conflicting
serial reuse closes the connection. The CLI reports a lost reply/deadline as
unknown completion and does not silently reconnect/reissue the operation.

Host tests cover failed and successful retry for both terminal outcomes, no
automatic retry after a collision is removed, refusal during trial/CommitPending
and failed commit, and a later SIGKILL of the exact childless fixture owner that
remains Uncertain after the direct child is reaped. An independent daemon with
an actually killed frontend checks fragmented retry, cached reply replay and
conflicting serial rejection. The production fixed-root channel fixture covers
rollback retirement failure/retry under real exclusions. CLI negatives reject
extra arguments and path selectors. These are not target/runtime health tests.

Fresh-boot completion uses its own retained authority below. S02 runs app gate
before native boot activation, and native Ready enrollment alone is not app
retirement authority. This separate path retains common update/store admission
and a verified native lifetime/boot boundary, rejects same-boot unresolved or
ambiguous native state, and preserves exact app context/layout. Absence, a phase
checksum, a CLI retry or PID disappearance must not stand in for that boundary.

## Stopped or prior-boot recovery and retirement

`ReadyAppRecovery` retains the protected native singleton and validates the
canonical record against real procfs kernel boot identity. Only same-boot
Closed or a different valid epoch is admitted. Native absence, socket/PID
absence, a free update lock, and boot Ready alone are not this capability.
NEXT/recovery evidence, invalid storage and same-boot unresolved ownership are
preserved and refused, not repaired. Acquisition itself is read-only.

The synchronous early path retains UpdateEX, StoreEX and both WriterAdmissionEX
and WriterActivityEX. It does not wait on a Tokio runtime or claim enrollment
of every native/network/AP/optional writer. Before app mutation it durably
publishes current-boot native Stopping under the retained singleton. Dropping
the helper or any subsequent error cannot auto-publish Closed.

A fixed protected `application-slot/recovery` receipt binds the initial complete
512-byte app record and exact transaction-directory device/inode. Its 568-byte
format has separate magic and checksum, root-owned single-link mode0600 storage
and bounded strict reads. It is published exclusively through `.recovery.next`,
file sync, NOREPLACE rename and parent sync before the native fence. Interrupted
temporary publication is retained and blocks recovery; it is never promoted or
deleted automatically. Checksums are corruption detection, not signatures.

The receipt selects only that exact current directory or the fixed
`history/<transaction>` after archival; there is no history scan/latest/force
selector. Context changes, backwards phase changes, uncommitted-to-Committed
changes, nonterminal history records or a different directory with identical
record bytes refuse. New install
preparation cannot bypass a pending recovery receipt, including when current is
already absent. A status reader may observe its selected phase, never health.

Under the retained fence, recovery restores the recorded old slot for an
uncommitted transaction or preserves a canonical Committed candidate. It then
archives and syncs the exact terminal directory, publishes native Closed, and
removes/syncs only the exact recovery receipt. Store/writer/native/update guards
remain held through cleanup. Crashes after current->history or after Closed but
before receipt cleanup can therefore be completed without adopting another
transaction. A crash after Stopping requires a different kernel epoch; no
same-boot automatic retry assumes that a dead helper proves native closure.

Terminal boot gates may remain read-only when a restart owns UpdateEX or no
safe native/writer boundary is available. Unsafe/ambiguous data and any failure
after fencing are not converted into a successful deferral. NoTransaction
retains the legacy/factory path, not a health or execution receipt.

Disposable fixed-root tests combine real SIGKILL with procfs identity and
synthetic prior-epoch native records. These are process-death/selection tests,
not actual reboot, power-loss, target filesystem or vendor-runtime acceptance.
Physical cold boot, I/O/ENOSPC/mount failures, all-writer lifecycle and bounded
history/space/GC remain mandatory before activation.

## Early consumer integration (development branch)

`/etc/init.d/S02apprecover` invokes the independent helper after S01 mounts and
before app consumers. A failed init script does not necessarily stop rcS, so
the DHCPv6 client/hook path in S30eth, Wi-Fi AP credentials in S30wifi, S95 start/
restart and native/backend/watchdog/delayed-hwmon launch paths also call the fixed
helper. Ordinary Ethernet IPv4/SLAAC and STA startup do not read `/kvmapp` and
are not gated by this app-slot protocol. This is NOT the future global raw
identity/restore boot gate; raw installation remains temporarily refused.

`gate` first reads/validates the protected journal and exact slot layout. A
terminal committed/rolled-back state or absence returns without acquiring common
update admission: the restart requester may still hold that admission. An
uncommitted state enters the existing recovery path, which must acquire it.
A concurrent consumer therefore receives Busy while an installer owns admission,
rather than rolling that installer back. If that installer dies, the additional
same-boot native Stop fence still denies early rollback. A bound-root fixture
with real procfs verifies both direct recovery and `gate` refuse without changing
the app/native records or live/old inodes; a synthetic previous epoch then permits
guarded rollback. This is not a physical reboot test.
Corrupt/foreign layouts fail closed. NoTransaction preserves
the pre-existing trusted legacy/factory path; it is not a new authorization,
candidate signature, bootstrap ticket or runtime-health receipt.

The backend embeds exact S02/S30eth/S30wifi/S95 source bytes. Its startup first
establishes/verifies the static helper and protected init directory, then
atomically publishes these compile-bound scripts. If support establishment fails,
it skips new critical gate publication and keeps management for diagnosis.
Ordinary script-copy failures still fail startup. The publisher establishes mode
0755 on its fresh FD independently of umask. S95 no longer recopies these four
scripts (including itself) from a possibly rolled-back bundle. The app install
prerequisite verifies their exact bytes, owner/mode/link count and protected
parents, not just presence of a helper. An absent optional hwmon remains a normal
startup condition; a denied recovery gate does not.

Optional S96 onboarding/skill/profile consumers are gated. The picoclaw API also
runs the fixed helper before selecting either an already installed S96 or the
bundled fallback for start/onboard, so an older installed script cannot bypass
that API gate. Stop does not depend on recovery or execute either script: it
uses fixed `/bin/busybox killall picoclaw`, preserving S96's existing best-effort
stop semantics even when the app slot is unresolved. This is not process-tree
quiescence or the remaining MCP worker cancellation/revocation acceptance.
No optional service is installed/enabled merely to update its guards. The API
command has a 20-second deadline and owned direct-child cleanup; a killed recovery
must be resumed from durable journal state, not assumed complete. This does not
implement the separate unprivileged picoclaw/capability work or alter autonomous
target-computer HID operations. Manual root execution is not sandboxed.

These are startup snapshot checks, NOT a retained native launch capability or
process-tree quiescence proof. State can change after a gate returns. Existing
system boot-health monitoring and other native/configuration producers still
need the composed native-owner lifecycle; passive app-file health probes are
not individually fenced by this protocol. Do not claim that all concurrent
runtime reads/writes are excluded or that an app install is now crash-safe.

**Legacy first-bridge target acceptance is still a release blocker.** An old S95
can copy new bundled gated scripts before the backend has established the helper.
In RC12 source `387793ab944437bbedc534d2ba231dd88d1fd2ca`, the old app API first
swaps `/kvmapp`, then invokes S95 `restart`. S95's `start_runtime` calls
`install_boot_scripts` before starting either native runtime or backend; its
copier also overwrites S95 itself in place. Safe continuation of that already
running shell must not be assumed. The old backend's own script synchronization
occurs only after it has been launched and cannot close this earlier window.
Power loss in that window is not covered by the backend's safer publication
order alone. The archive-delivery profile below addresses premature gate/self-copy
publication for exact RC12/app42 inputs at source/host scope. It is not the full
legacy migration, old-installer crash-safety or helper-version lifecycle. Old
backends may also overwrite rootfs gates after rollback; this still needs acceptance.

Host user-namespace/chroot fixtures exercise the actual fixed-root gate with
held admission in no-transaction/terminal states, Busy for active nonterminal
states, and recovery of all three supported interrupted layouts. Shell fixtures
check refusal before side effects, repeated launch guards, S02 exit propagation,
protected-script non-copying and rootfs validator errors. Historical ungated
bodies are rejected structurally, never executed on the host. Source guards for
the picoclaw API (including independent Stop selection) are not HTTP/device
acceptance; no live processes are signalled by those tests.

### App archive delivery versus full-image staging

`package-rust-kvmapp.sh` now keeps its ordinary full-image staging tree canonical,
with all four current compile-bound scripts. The app archive is produced from a
separate private copy. That copy omits S02apprecover/S30eth/S30wifi and carries an
exact historical S95 from app 2.0.42, SHA-256
`8030d0f81581a417eca91e3db7e0c3d96cba197b519022d7c73c3c5caca05365`.
The historical source and provenance are retained as a non-executable data asset
under `support/update-compat/rc12`, not as the current rootfs init script.

S95 cannot simply be omitted: the old app archive validator requires it. For the
exact supported installed RC12/app42 S95 bytes, the old copier's equality check
leaves the executing shell untouched. Absent ancillary sources leave the old
rootfs files untouched too. The new backend then verifies/installs the independent
helper and publishes its compile-bound canonical scripts. Once current rootfs S95
is installed, its protected-script skip never recopies the archive's legacy S95.
Full SD/raw rootfs construction uses the unchanged canonical stage, not the
app-archive view. Do not substitute an unpacked app archive for that image stage.

`app-boot-delivery.py` refuses a backend lacking any exact canonical embedded
script, a changed historical asset, or a final archive with premature gate paths,
aliases, links, special objects, duplicate/foreign/missing S95 or exceeded bounds.
The manifest labels `app_archive_boot_profile: rc12-compat-bootstrap-v1`; this is
build consistency metadata, not a signature, runtime receipt or recovery authority.
The normal app metadata/checksum/signature rules are unchanged.

This profile does not add another user bridge step: app 2.0.40/41 still need the
existing published 2.0.42 key bridge; exact app42 proceeds to one fixing app.
It does not authorize arbitrary customized/unknown old S95 bytes, for which the
old copier could still overwrite its executing script. Exact legacy init identity
and first-restart/power-loss behavior must be verified before any device acceptance.
The already-vulnerable portion of an old install cannot be made retrospectively
atomic or safe against prior root compromise. Keep USB-data isolated and use
trusted reflash/recovery for unsupported or compromised states.

Host tests cover the exact old copier's equal/missing-source behavior and detect
the pre-fix copy attempt, plus package fault rejection and unchanged full-image
staging. Repeated packaging of the same actual RV64 inputs gives equal archives;
this is NOT independent backend/full-pipeline reproducibility. A retained-input
Rust test feeds those exact archive bytes through private production extraction
and candidate preflight without invoking installation, helper migration or restart.
No `/kvmapp` recovery-helper execution fallback, forced helper replacement,
journal deletion or trust relaxation is introduced.

## Build and verification boundaries

`server-rust/scripts/build-app-recovery.sh --locked --offline` builds this helper
statically as an ELF64 RV64 executable in the separate restore-runtime target
directory. It refuses an ELF interpreter or shared-library dependencies/RPATH/
RUNPATH. The recovery
component must not load `/kvmapp` libraries before establishing its boundary.
This command builds/checks only; no installation, boot-hook activation, signing
provenance or independent A/B reproducibility is implied.

The linked backend build first builds both static helpers in the separate
restore-runtime target directory. It requires a distinct `NKAPPBT1` app-recovery
envelope as well as the existing `NKSSHRT1` SSH envelope. Both inputs are
validated before either Cargo output is written. Host/unbound helper builds
contain no usable binding; neither envelope domain can substitute for the other.
The backend validates and retains the embedded app-recovery image. There is no
runtime path, environment, bundled-file or manifest fallback.

The app packager extracts the exact embedded image exclusively into
`kvmapp/system/bin/nanokvm-app-recovery` and records its SHA-256 and size in the
package inventory. An unrelated bundled helper cannot replace a missing or bad
binding. Buildroot checks source helper/backend equality, restores the bundled
helper after generic ELF fixups and checks the final pair again. These are
build/package consistency checks, not RSA release authentication or permission
to execute code supplied by an attacker. A helper living only inside `/kvmapp`
still cannot recover a missing app slot.

### Independent publication and app-only bridge

On linked RV64 startup, after closing legacy USB storage and loading config,
the backend prepares app recovery and all four native executables under one
shared app/system admission lock. A retained `BootSupport` guard holds admission
through the subsequent compile-bound consumer-script publication, not merely
through the helper rename. Missing/invalid native support withholds publication;
it is not an app-slot success or a native-process ownership receipt.
All of `/`, `/usr` and `/usr/libexec` must be root-owned,
non-group/other-writable and on the same rootfs, with symlink/mount crossings
rejected. A missing `libexec` directory may be created under the protected `/usr`;
no existing directory or helper is chmod-repaired. Publication uses only the
compile-bound bytes, not the bundled helper as a runtime fallback.

An existing helper must be a single-link regular root-owned file of mode 0755.
Current-helper verification requires exact size and exact bytes. It is opened
for inspection without data access, then reopened read-only/nonblocking, with
inode/layout checks before/after the read. An unknown or unsafe helper is
retained and refused, not overwritten. No installed helper is executed to
identify or authorize itself.
First helper publication supports the historical absence case; this does not
prove the complete old-installer/first-restart bridge described above.
The directed v1 predecessor migration below covers only explicitly pinned
previous bytes. Old-backend rollback and transitions to a different journal
protocol still need separate lifecycle acceptance. Do not delete journals or
replace files manually to turn a mismatch into a successful check.

A missing helper is written to a fresh exclusive random sibling, chmodded only
through that new FD, file-synced, renamed with NOREPLACE and directory-synced.
The result is rechecked. A competing canonical winner must be exact; an unknown
winner and all torn temporaries are preserved. Temporary names are never read
as fallback or selected as authority. A pending, terminal or corrupt canonical app-slot
journal never permits a new helper to be installed over missing support.

### Directed v1 helper migration

Startup holds the same update admission from fixed-root journal inspection
through helper publication. The internal publication primitive requires a
borrow of that live admission owner. It does not call recovery while holding
the lock, avoiding nested admission. Corrupt/foreign journal or layout fails
before publication; no journal is retired or rewritten by bootstrap.

| Validated app-slot state | Exact current helper | Missing helper | Pinned v1 predecessor |
| --- | --- | --- | --- |
| No transaction | Verify only | Install exact embedded helper | Forward migration |
| Committed / rolled-back v1 | Verify only | Refuse | Forward migration |
| Nonterminal v1 | Verify only | Refuse | Refuse |

Unknown/unsafe helpers are refused in every state. The build-owned predecessor
registry binds both size and SHA-256, not an executable's version output or a
runtime manifest. The initial entry is the retained development helper from
`89aa736`, 373,048 bytes, SHA-256
`9095522caf08d9f0a0bf2f70917b9ce733930d9cedb85f50249b745cc2b535e8`.
Historical RC12 has no independent helper. Adding a predecessor requires exact
byte and journal compatibility review; a matching hash is not a new release
signature or authorization from an untrusted app directory.

Migration verifies the predecessor before staging, writes only the compile-bound
new image to a fresh exclusive sibling, establishes mode 0755 on that new FD and
syncs it. It rechecks the prior digest and canonical inode, then uses atomic
`RENAME_EXCHANGE`: the canonical name is never intentionally absent or updated
in place. After directory sync it verifies the exact new canonical image and
retained old inode. The old file stays under the random sibling name as evidence;
it is never selected as an executable fallback or transaction authority.

An error after exchange does not mean nothing changed and does not assert
rollback. Startup keeps authenticated management for diagnosis and skips new
critical-script publication on that failure. A fresh invocation must inspect
canonical state: if the new helper is already exact, it completes file/directory
durability without exchanging again. Torn/retained sibling files are not scanned
or selected. Cooperating privileged writers must honor update admission; this
does not sandbox hostile root or promise protection against an unrelated
privileged writer racing after the final check.

Host tests cover the state decision, pinned actual old RV64 bytes (never executed),
unknown/unsafe refusal, competing admission, SIGKILL at staging/exchange boundaries,
pre-exchange canonical replacement and a post-exchange sync-error path. Migration
unit tests supply status enums; the separate bound-root gate now calls the actual
fixed-root `ensure_installed()` in disposable user-namespace/chroot children.
It independently encodes v1 records using real directory device/inodes and checks
terminal/nonterminal/corrupt/foreign/orphan cases, exact-current verification,
both update-admission and store-lock contention, and SIGKILL before/after exchange
with repeated inspection. Actual old/new RV64 files are data, never executed.
This covers the bootstrap entry, not the full main/S95/native lifecycle, target
startup or physical power-cut acceptance. The retained-input unit test is
explicitly ignored by default and was run in
the full `--include-ignored` gate; ordinary default tests do not cover that input.
The new test image is synthetic, not a deployable successor helper. This
is forward publication, not automatic executable rollback, the trusted app-slot
producer, retained native ownership or full C1 closure.

Run `server-rust/scripts/test-app-bootstrap-root.sh` for the bound-root gate. It
requires matching retained backend/helper build inputs and the exact predecessor
evidence; it verifies their binding before compiling the explicit
`app-bootstrap-bound-test-fixture` feature. Missing/unbound inputs fail, rather
than silently skipping composition checks. The feature only selects a `cfg(test)`
module and adds no shipped CLI, root override or runtime fallback. The harness
bounds child execution and captured output, drains pipes and kills/reaps its own
direct child on timeout or assertion unwind. This is not a generic process-tree
supervisor or a bounded-kernel-I/O guarantee. Ordinary default tests do not
select this retained-input gate.

If the backend has already launched, a helper-bootstrap failure alone is logged
without terminating it, preserving authenticated management for diagnosis.
The app install API no longer swaps slots itself. `check_before_legacy_install`
(exact app helper, complete native family and critical consumer scripts, no
app-slot transaction) remains a read-only bootstrap check. The submission path
instead relies on preparation's refusal of any current transaction and on the
trial backend's own `check_trial_support` before it serves.

Buildroot installs both copies up front and restores/verifies both after ELF
fixups. The legacy SD assembler also writes a mode-0755 root-owned independent
copy. `scripts/verify-app-recovery-rootfs.py` reads an ext image without mounting,
checks protected independent parents/owner/mode/link count and verifies both
helper copies against the final backend's exact embedded image. Its real ext4
fixtures include missing/mismatched payloads, missing binding, symlink/hardlink,
permissions, ownership and oversized data. These are not full pipeline/boot gates.

Current generic/Buildroot rootfs validators require this new protocol by default;
they must reject historical images missing independent recovery, not silently
skip it based on a version label. Historical RC12 validation remains separate:
`scripts/verify-rc12-raw-bundle.sh` pins the accepted rootfs/boot hashes and does
not call the new rootfs gate. Its default now requires signed metadata and uses
the production public key; supply the matching retained metadata/signature.
Explicit unsigned inspection is fixture-only, not release acceptance; see
[historical raw verification](security-raw-bundle-verification.md). This is not a way to
authorize a new candidate without independent support.

`server-rust/scripts/test-embedded-app-recovery.sh` checks host capture of the
actual static RV64 input, without executing that foreign-architecture image.
The binding CLI tests cover distinct domains, corruption, ambiguity, ELF
constraints, exact extraction/verification, cache conflicts and unsafe input
types. Package and post-build fixtures additionally reject missing, corrupt,
duplicate or wrong-domain bindings and helper mismatch. These synthetic fixtures
do not replace a real target package, full rootfs build or device gate.

Host tests cover strict framing/context, each supported uncommitted phase/layout,
idempotence, terminal layout mismatches, foreign/missing/symlink objects, FIFO/
hard-link/permissions/device checks, a subprocess with restrictive umask,
corrupt canonical records, ignored/preserved
torn temporaries, same-inode lock admission and inherited-description teardown.
Real subprocess SIGKILL tests interrupt all 12 recovery record-publication and
slot-rename boundaries and then recover twice. These are process-crash tests,
not physical power-loss, ext4 write-cache or target acceptance.

## Frozen backend trial startup

The backend now has one explicit `--app-trial` entry. Before constructing Tokio
it adopts an unnamed STREAM socket from fd0, verifies a root direct parent,
marks its private duplicate CLOEXEC and replaces fd0 with `/dev/null`. A strict
32-byte Begin/Ready/Commit protocol binds each event to the same nonzero
transaction ID. This private parent capability is not a signed release receipt,
an HTTP health check or permission to activate an arbitrary app slot.

Trial startup reads existing fixed-root config, session identity, account and
TLS state without acquiring the parent's writer locks, generating a session
secret, seeding an account, migrating media, publishing trust/helpers/scripts
or invoking normal storage/bootstrap initialization. Reads are bounded,
descriptor-relative, root-owned, single-link and same-rootfs; symlinks, special
files, writable metadata and mount crossings fail. Missing required identity
fails instead of silently replacing it. Parser errors do not include secret
contents. This does not establish full credential/password-hash validity or
prove successful login on the device.

All required HTTP/HTTPS/redirect/optional loopback listeners are bound before
Ready. The backend initializes libkvm and retains a shutdown guard before that
acknowledgement. No request-serving task starts until the exact Commit arrives.
EOF, a malformed/mismatched acknowledgement or the 30-second commit timeout
fails startup and drops listeners. The file/config freeze is not a promise of
zero hardware effects: libkvm initialization may reset HDMI. Its current void
native initialization API cannot prove a frame, HID or native-service health.
Actual device checks and daemon-to-real-backend integration remain separate
requirements.
The video guard invokes vendor deinit best-effort; this is not a bounded native
join or a guarantee that a hung vendor call returns at the protocol deadline.

Candidate extraction still ignores archive-supplied execute bits. Before
publication, bounded pinned traversal assigns 0755 only to the fixed backend,
kvm-system/hwmon, direct `system/bin` and `system/init.d` members, the DHCPv6
hook and the KVM-control bridge script. Other regular files become 0600 and
directories 0755. The private staging parent remains protected; old-live files
are not chmodded. This preserves required execution without treating all web,
library, module or settings data as executable. A future unprivileged consumer
requires its separately reviewed data-access policy.

Host tests exercise the actual `run(Some(startup))` HTTP and HTTPS startup in
disposable root namespaces, with the three production exclusion inodes held.
They observe no response before Commit, HTTP/TLS service after Commit, listener
closure on wrong Commit/EOF and unchanged identity files. libkvm in this test is
an explicit no-device host ABI fixture; it is not vendor-runtime acceptance.
Separate frozen-read tests reject absent, aliased, FIFO and oversized secrets.
The bound-root gate uses actual embedded static RV64 helper bytes as data and
checks trial support while the app store and update/writer exclusions are held;
it must not reacquire the busy store. These backend tests do not exercise
daemon-driven trial/commit/retirement.

## Broker-owned trial policy

`Session::start_trial` requires canonical Published state, the exact accepted
transaction/layout and proven closure of all prior scopes. It can launch only
the fixed owner `backend-trial` role and moves ownership into `TrialSession`.

The support check before the trial runs on its own fixed joined worker
(`app-trial-check`), like publication, commit and rollback. It verifies the
published support namespace and syncs `application-support` and `etc/kvm`,
which a loaded host or slow card can stretch to hundreds of milliseconds.
Meanwhile the control loop keeps answering within its bound.

Only a complete, certain check by this Session's own worker lets
`start_trial` skip the support part; the cheap Published-phase guard always
runs. A Session without that check runs the whole check inline. A failed or
spawn-failed check ends Failed, and so Uncertain, as the inline failure did,
and cancellation still rolls back.
KVM-system/hwmon stay stopped: they may write settings without Rust permits.
The normal post-commit broker path can restart them after the writer freeze is
released. Native spawn receipts are not substituted for service/hardware health.

After its inherited-FD audit, the owner creates a fresh stdin socketpair for
the backend. Begin/Ready/Commit use one shared strict frame implementation and
the same transaction. Owner `R` now means exact backend Ready for this role,
not just successful spawn. Failure `F` is not closure; Commit-forwarded `K` is
sent only after all Commit bytes reach the backend socket, not after a public
HTTP request or physical check. Normal roles keep their old R/D protocol.
The owner drops Command's retained child-side Stdio alias after spawn so backend
EOF is observable. Partial Commit sends finish before an admitted Stop is sent;
Stop cannot be inserted into a frame. The owner forwards from a separate
immutable Commit buffer, so subsequent control input cannot corrupt a partially
forwarded backend frame. Root direct-parent checks and fixed executable paths
remain.

The ownership order is:

```text
Published -> joined support check -> frozen backend trial -> Ready
          -> durable app Committed
          -> durable native Active -> explicit Commit relay / K
          -> exact terminal archival -> release install freeze
          -> ordinary native service starts

uncommitted trial -> explicit Stop -> receipt + owner reap + EOF / ECHILD
                  -> old-slot rollback under the same exclusions
                  -> durable native Active -> exact terminal archival
                  -> release install freeze
```

`TrialSession` exposes no direct rollback. Stop consumes it into a drain and
old-slot recovery requires a fresh complete closure proof. A failed Ready or
pre-Ready leader death does not wait passively for UpdateEX while the broker
holds it: explicit admitted Stop remains usable and joins surviving descendants.
Missing receipts remain uncertain even after the owner exits. There is no
forced unlock, PID-marker adoption or timeout-as-closure shortcut.

Commit checks canonical transaction/context/layout again, writes and syncs app
Committed before native resume and backend authorization, and retains all install
exclusions until explicit completion/release. A failed or lost acknowledgement
does not permit rolling back an already Committed app. Old-slot evidence and
terminal journal move together into protected history before release; failed
archival retains the complete terminal owner. Safe recovery/retirement now has
a separate stopped/prior-boot boundary; bounded history retention, physical
fresh-boot acceptance and the complete commit/crash/I/O matrix
are still required. The daemon Engine now retains and drives this
nonblocking policy, without a handler-owned task or admission release/reacquire.
An injected native-journal publication collision after durable app Committed
checks that no backend Commit is sent and no Stop/rollback owner is minted from
the ambiguous journal; all installation exclusions remain retained.

Host tests separately exercise the real scope/controller with fake backend
frames (including a setsid orphan under held UpdateEX), and the actual broker
policy and Engine with protocol probes and real app journals/locks. Independent
daemon tests include frontend death and observer disconnect through trial/commit;
Engine tests cover failed-trial join/rollback, missing receipt and a post-app-commit
native-journal failure that retains Uncertain without authorization or retry.
These are not a daemon-to-real-backend/native-runtime acceptance test. The
ordinary API submits to the daemon; no device deployment is implied.

## Remaining activation prerequisites

- The API now hands updates to the independently delivered native-closed
  installer (source and host tests). Before release it still needs exact
  metadata/key/policy lifetime review, daemon-to-real-backend/native-runtime
  health acceptance, physical fresh-boot/terminal-failure acceptance and the
  bounded history/space policy.
  Execution modes, frozen backend startup and daemon-driven broker transitions
  now have host tests; they are not target/runtime acceptance. Host-tested
  publication/rollback is not a complete lifecycle.
- Full pipeline/target acceptance of independent rootfs installation and the
  atomic app-only bootstrap, including actual I/O failure and mount negatives.
- Complete helper-version lifecycle across subsequent app updates. The pinned
  v1 forward-publication path and fixed-root decoded-journal bootstrap are
  host-tested, but target startup, released successor/predecessor pairs and
  old-backend rollback still
  need acceptance. This remains required for WP-04, not an implicit waiver of
  app-only updates or permission to replace unknown support.
- Full target/first-bridge acceptance of the archive-delivery profile and the
  early/individual consumer gates; verify exact old S95 identity, establish
  independent support before publishing gates, and preserve legacy rollback.
  Nonzero rcS exits alone are not gates.
- Native/S95/watchdog/raw lifecycle coordination, first restart and runtime
  acceptance; current S95 KVM/hwmon source wiring has a separate fresh-boot
  enrollment fence, not a complete transaction-level writer join. Legacy
  bootstrap may arm a new boot but never adopt current processes. See
  `security-native-owner.md`. Do not replace code used by a running
  shell/executable in place.
- Actual installation crash tests, ENOSPC/I/O failure, target mount negatives,
  legacy migration and complete device/release acceptance.

The app API now refuses missing/mismatched independent support/scripts or any
app-slot journal before legacy slot mutation. Early gates invoke recovery, but
the app API still does not publish a journal. No account, SSH setting, signature
algorithm/key ID,
version, release channel or accepted image is changed by this component.
