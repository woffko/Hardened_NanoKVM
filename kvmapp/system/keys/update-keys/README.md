# System update public-key ring

Only reviewed public keys named `<key-id>.pub.pem` belong in this directory.
Private keys must never be copied into the repository or application archive.

Rotation sequence:

1. ship the new public key in an authenticated manual offline bridge
   application update because the legacy private key is unavailable;
2. sign the following system metadata with the new key ID;
3. keep the legacy IDs and the new production ID in
   `system/keys/update-key-policy` throughout the migration window;
4. after the new metadata verifies and the migration window closes, ship a
   later policy containing only the production key ID;
5. verify app and system update checks after reboot and after rollback.

The RC12 bridge policy permitted both historical key IDs and
`hardened-system-prod-2026q3`. Step 4 is done: the policy now lists the
production key ID alone, so metadata signed with a legacy ID is refused. The
legacy public key file still ships, because the trust installer reads it at
every start. An application older than this policy brings the bridge policy back
if it is installed again.
