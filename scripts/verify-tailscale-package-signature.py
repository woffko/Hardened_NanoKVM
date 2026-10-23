#!/usr/bin/env python3
"""Verify a Tailscale package with Tailscale's own signature chain (distsign).

Usage:
  verify-tailscale-package-signature.py ROOTS_DIR DISTSIGN_PUB DISTSIGN_PUB_SIG PACKAGE PACKAGE_SIG

ROOTS_DIR holds the root public keys from Tailscale's source tree
(clientupdate/distsign/roots/*.pem at the release tag). DISTSIGN_PUB and its
.sig come from https://pkgs.tailscale.com/distsign.pub[.sig]; PACKAGE and its
.sig from the package URL. A root key must sign the signing key bundle, and a
signing key must sign BLAKE2s-256(package) || little-endian u64 length, as
clientupdate/distsign/distsign.go does. Prints the package size and SHA-256
to pin; exits non-zero when any check fails. Needs python3-cryptography.
"""
import base64
import hashlib
import os
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def pem_keys(data, tag):
    keys, body, inside = [], [], False
    for line in data.decode("ascii").splitlines():
        if line == f"-----BEGIN {tag}-----":
            inside, body = True, []
        elif line == f"-----END {tag}-----":
            raw = base64.b64decode("".join(body), validate=True)
            if len(raw) != 32:
                sys.exit(f"{tag}: not an Ed25519 public key")
            keys.append(Ed25519PublicKey.from_public_bytes(raw))
            inside = False
        elif inside:
            body.append(line)
        elif line.strip():
            sys.exit(f"unexpected data outside a {tag} block")
    if inside or not keys:
        sys.exit(f"no complete {tag} block")
    return keys


def verified_by(keys, message, signature):
    for key in keys:
        try:
            key.verify(signature, message)
            return True
        except InvalidSignature:
            pass
    return False


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    roots_dir, bundle_path, bundle_sig, package_path, package_sig = sys.argv[1:]
    roots = []
    for name in sorted(os.listdir(roots_dir)):
        if name.endswith(".pem"):
            with open(os.path.join(roots_dir, name), "rb") as file:
                roots += pem_keys(file.read(), "ROOT PUBLIC KEY")
    with open(bundle_path, "rb") as file:
        bundle = file.read()
    with open(bundle_sig, "rb") as file:
        if not verified_by(roots, bundle, file.read()):
            sys.exit("the signing key bundle is not signed by a root key")
    signers = pem_keys(bundle, "SIGNING PUBLIC KEY")
    with open(package_path, "rb") as file:
        package = file.read()
    message = hashlib.blake2s(package, digest_size=32).digest() + struct.pack("<Q", len(package))
    with open(package_sig, "rb") as file:
        if not verified_by(signers, message, file.read()):
            sys.exit("the package is not signed by a current signing key")
    print(f"verified size={len(package)} sha256={hashlib.sha256(package).hexdigest()}")


if __name__ == "__main__":
    main()
