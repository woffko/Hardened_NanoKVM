# Historical RC12 raw verification

`scripts/verify-rc12-raw-bundle.sh` checks the fixed historical RC12 archive,
manifest, decompressed payload hashes/sizes and matching format-2 metadata.
It is not the current remediation-candidate verifier: historical integrity does
not prove that an image implements the subsequent storage/recovery protocol.
A new candidate still needs its own manifest-bound verification and full
build/device acceptance; historical PASS must not substitute for those gates.

Signed metadata is required by default:

```sh
scripts/verify-rc12-raw-bundle.sh \
  /path/to/hardened-nanokvm-system-0.3.0-raw.12.tar.gz \
  /path/to/system-latest.json \
  /path/to/system-latest.json.sig
```

The default public key is the existing
`kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem`. There is no
fallback to the legacy key if verification fails. A fourth argument can select
a separately reviewed public key; never take that key from an untrusted bundle.
Algorithm and key ID must still match the fixed historical production identity.
The exact metadata bytes are authenticated before any archive inspection or
payload decompression. Archive, payload and manifest checks remain mandatory
after that admission; a valid signature alone does not accept a bundle.

For deliberate historical unsigned-fixture inspection only, explicitly set
`EXPECTED_SIGNATURE_MODE=unsigned`, supply metadata marked unsigned and omit the
signature argument. The verifier emits a warning and a distinct fixture-only
success label. It is not release acceptance. This opt-in does not relax any of
the pinned historical versions, payload hashes or sizes; older superseded
fixtures may therefore still be rejected.

`node scripts/test-raw-bundle-signature-admission.cjs` checks the signature/mode
admission boundary with public RC12 metadata, its existing detached signature
and real OpenSSL. Its archive sentinel stops execution before extraction. It
does not verify a raw payload, generate a private key, sign metadata, access a
device or replace a complete historical-bundle check.
