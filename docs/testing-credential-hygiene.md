# Device-test credential handling

The kernel dmesg host verifier and reboot-soak runner receive the test password
on stdin and pass it to `sshpass` on a separate descriptor (`-d 3`). Do not put
the password in arguments, environment variables, reports or command history.
Use the enrolled test-asset secret-stdin workflow for automated runs.

`SSHPASS_BIN` selects the `sshpass` executable. Without an override, both runners
use `build/host-deps/sshpass/usr/bin/sshpass` under the project root. `SSHPASS` is
not read: that name is conventionally used for a password, not a binary path.
Existing automation that used it as a binary override must use `SSHPASS_BIN`.

Failure reports contain local operation summaries and exit codes, not arbitrary
exception messages, executable paths, remote error text or captured SSH stderr.
Missing tools and unavailable files therefore produce a safe category instead
of echoing their configured value. This is deliberately less detailed than a raw
process-error dump. Successful device-verifier evidence remains separate and
must itself be reviewed before publication; this is not a general log-redactor.

The explicit matching `--confirm-device` argument, host-key checking, private
result files and the distinction between failure and success remain required.
These changes do not establish a trusted first host-key enrollment: review that
identity through the project's independent device-verification procedure.

Run `node scripts/test-device-test-error-hygiene.cjs` for isolated synthetic
failure/success coverage. It mocks filesystem, process and network operations;
it does not log in to, reboot or otherwise test physical equipment.
