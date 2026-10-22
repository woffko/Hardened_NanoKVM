# Account credential preflight

New account credentials are checked after frontend decoding and before the
serialized setup/password-change operation hashes anything or writes either
credential store. Passwords containing NUL, CR or LF are rejected: these bytes
cannot be passed as one line on `mkpasswd`'s stdin. Usernames containing
control characters are also rejected. Error messages do not repeat the
submitted input.

Existing length limits remain byte-based: username 1–64 bytes, password 8–256
bytes. Passwords are not trimmed or shell-escaped; spaces, punctuation and
Unicode remain supported. They are sent on finite stdin, not command arguments.

This policy applies to creating/changing credentials, not to verifying an
existing account. Legacy bcrypt and Argon2 verification remain unchanged,
including an existing password that would fail the new-password preflight.
The legacy default-account configuration and seeding policy are unchanged.

Regression tests cover decoded CR/LF/NUL, username control characters, supported
characters/byte limits and actual temporary-store legacy verification:

```sh
cargo test --manifest-path server-rust/Cargo.toml --locked --offline --lib \
  auth::password::tests
```

## Verification and lockout

Login and terminal unlock verify a password on a blocking thread, one at a
time. Inline Argon2 on the single-core SoC would stall HID, video and every
other request. A second verification waits up to 2 seconds for the one slot and
is then refused with 429 rather than queued. A dropped request keeps the slot
until its hash finishes.

The stored hash is verified even when the username is wrong, so the reply time
does not reveal whether a username exists. Only a matching username and
password succeed.

The lockout counts failures per source and username. A source is an IPv4
address or the /64 network of an IPv6 address; an IPv4-mapped IPv6 address
counts as its IPv4 address. One host cannot rotate out of its lockout inside
its own /64.

## Reauthentication

A password change needs the current password in `currentPassword`, encoded
like `password`. Without it the request is refused (`-1`). The check runs
through the same hashing slot and the same lockout as a login, keyed by the
source network and the username. A wrong current password counts as a failed
login (`-2`); a locked source gets `-5`, even with the right password. A stolen
session therefore cannot change the password, or test password guesses beyond
the login budget. First setup has no current password.

## Credential transaction

Setup and password change replace root's entry in `/etc/shadow` and the web
account file `/etc/kvm/pwd` as one journaled change, under the account permit:

1. BusyBox `mkpasswd -m sha512 -S <salt>` hashes the new password, read from
   stdin. The 16-character salt comes from the OS random source; a failing
   source is an error, never a weaker fallback. `mkpasswd` writes no file. Only
   one line, `$6$<salt>$` and 86 crypt characters, is accepted. Native `passwd`
   is no longer used: its own rename of `/etc/shadow` could not be bound to the
   journal. musl's `crypt()`, used by sshd, verifies SHA-512 hashes.
2. Both stores are read without following symlinks, within 64 KiB each. Exactly
   one well-formed root entry must exist. The web account must be absent for
   setup and present for a change.
3. The journal `/etc/kvm/pwd.journal` records both previous files with their
   modes and owners, under a SHA-256 digest. It is written to a fixed scratch
   name, synced and renamed, and its directory is synced.
4. `/etc/shadow` is replaced the same way. Only root's hash and change day
   change; every other line, mode and owner stay. A clock before 2020 (no RTC,
   no NTP yet) keeps the previous change day, because 0 would force a password
   change at the next SSH login.
5. The web account is replaced the same way, with mode 0600.
6. Removing the journal and syncing its directory commits the change. Only
   then is success returned and, if configured, the user's sessions revoked.

A failure in steps 4–6 restores both previous files at once and removes the
journal; the request gets the original error. If that restoration fails, the
journal stays and the two passwords may differ until the next start. At the
next start, before any request is served, the backend restores both files from
the journal and removes it, along with scratch files. A damaged journal is kept
and logged. While a journal exists, every credential change is refused. After a
crash the next start therefore finds either both new passwords, committed, or
restores both previous ones. The frozen app trial never writes; a journal waits
for the next ordinary start.

Limits: another process writing `/etc/shadow` during the change, such as
`passwd` run by hand over SSH, is not excluded and can be overwritten. A
failed directory sync after the commit is reported as an unconfirmed commit,
not rolled back. The account file is also replaced atomically when the legacy
default account is seeded.

No real root password is changed by these tests; accounts and passwords in them
are synthetic temporary fixtures. The hash format was checked on the host with
BusyBox 1.38.0 built from the image's patched tree: `mkpasswd -m sha512 -S salt`
reading stdin prints the same line as `openssl passwd -6`. Tests cover:

- a change of both stores, with other shadow lines, modes and owners kept;
- setup and change preconditions;
- a failure after each step, restored at once;
- an interruption after each step, restored at the next start;
- leftover scratch files, a damaged journal, a malformed root entry, a symlinked
  store and the accepted hash format;
- the handler: the current password requirement, the shared lockout and the
  password reaching the hasher only on stdin.

```sh
cargo test --manifest-path server-rust/Cargo.toml --locked --offline --lib \
  auth:: api::account
```
