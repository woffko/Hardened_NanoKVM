# Public verification fixtures

`rc12-system-latest.json` and its base64-encoded detached signature are public
RC12 release metadata, retained byte-exact from the local accepted release
evidence. They are not a new release candidate or evidence that RC12 contains
the subsequent remediation. No private key is present or needed for these tests.

The metadata SHA-256 is
`b2397c9aaea621619c63b89e068bd434d82af2557ebbd8a8038aa0f82963e642`;
the decoded signature SHA-256 is
`48515a9fb8d4e902fb9528d6b1417d845e772471845108dfe07edee20fce0380`.
The matching public key is the existing
`kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem`, whose DER
SHA-256 is
`97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75`.
