# Account credential preflight

New account credentials are checked after frontend decoding and before the
serialized setup/password-change operation can invoke native `passwd`.
Passwords containing NUL, CR or LF are rejected: these bytes cannot be passed
through the existing two-line password input protocol as one credential.
Usernames containing control characters are also rejected. Error messages do
not repeat the submitted input.

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

This is not a transaction across the root and web credential stores. Recovery
after a partial change, recent reauthentication, atomic account-file publication,
bounded password hashing/rate limits and complete session revocation remain
separate remediation requirements. No real root password is changed by these
tests; accounts and passwords in them are synthetic temporary fixtures.
