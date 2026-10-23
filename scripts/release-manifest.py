#!/usr/bin/env python3
"""Release manifest: the exact asset set of a prepared release directory.

create DIR --field KEY=VALUE... --input LABEL=SHA256...
    Record every regular file in DIR (except the manifest and the notes) with
    its size and SHA-256, the notes, the release fields and the pinned input
    hashes, as DIR/RELEASE_MANIFEST.json.
check DIR [--allow-draft]
    Fail unless DIR holds exactly the recorded files, each nonempty and
    unchanged, SHA256SUMS lists every other asset with its hash, and every
    required field is present. DRAFT_ONLY is refused unless --allow-draft.
field DIR KEY
    Print one release field of a checked manifest.
"""

import hashlib
import json
import os
import re
import sys

MANIFEST = "RELEASE_MANIFEST.json"
NOTES = "RELEASE_NOTES.md"
DRAFT = "DRAFT_ONLY"
SUMS = "SHA256SUMS"
FIELDS = (
    "tag",
    "app_version",
    "system_version",
    "kernel_version",
    "signature_key_id",
    "source_commit",
    "build_commit",
)
INPUTS = ("app", "system", "sd")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class Refused(Exception):
    pass


def digest(path):
    hash = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1 << 20), b""):
            hash.update(chunk)
    return hash.hexdigest()


def regular(directory, name):
    path = os.path.join(directory, name)
    stat = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise Refused(f"{name} is not a regular file")
    if stat.st_size == 0:
        raise Refused(f"{name} is empty")
    return path, stat.st_size


def record(directory, name):
    path, size = regular(directory, name)
    return {"name": name, "bytes": size, "sha256": digest(path)}


def pairs(values, what):
    result = {}
    for value in values:
        key, sep, item = value.partition("=")
        if not sep or not key or not item or key in result:
            raise Refused(f"invalid {what}: {value}")
        result[key] = item
    return result


def create(directory, arguments):
    fields, inputs = [], []
    while arguments:
        flag = arguments.pop(0)
        if flag not in ("--field", "--input") or not arguments:
            raise Refused(f"unexpected argument: {flag}")
        (fields if flag == "--field" else inputs).append(arguments.pop(0))
    fields, inputs = pairs(fields, "field"), pairs(inputs, "input")
    names = sorted(
        name for name in os.listdir(directory) if name not in (MANIFEST, NOTES, DRAFT)
    )
    manifest = {
        "format": "hardened-nanokvm-release-v1",
        "fields": fields,
        "inputs": inputs,
        "notes": record(directory, NOTES),
        "assets": [record(directory, name) for name in names],
    }
    validate(manifest)
    temporary = os.path.join(directory, MANIFEST + ".tmp")
    with open(temporary, "x") as file:
        json.dump(manifest, file, indent=2, sort_keys=True)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    os.rename(temporary, os.path.join(directory, MANIFEST))


def validate(manifest):
    if manifest.get("format") != "hardened-nanokvm-release-v1":
        raise Refused("unknown manifest format")
    fields = manifest.get("fields", {})
    for key in FIELDS:
        if not fields.get(key):
            raise Refused(f"missing release field: {key}")
    for key in ("source_commit", "build_commit"):
        if not HEX40.match(fields[key]):
            raise Refused(f"{key} is not a full commit hash")
    inputs = manifest.get("inputs", {})
    if sorted(inputs) != sorted(INPUTS) or not all(HEX64.match(inputs[k]) for k in INPUTS):
        raise Refused("the app, system and sd input pins are required")
    names = [asset["name"] for asset in manifest.get("assets", [])]
    if not names or len(set(names)) != len(names) or SUMS not in names:
        raise Refused("the asset list is empty, repeated or lacks SHA256SUMS")
    for name in names:
        if "/" in name or name.startswith("."):
            raise Refused(f"invalid asset name: {name}")


def check(directory, allow_draft):
    with open(os.path.join(directory, MANIFEST)) as file:
        manifest = json.load(file)
    validate(manifest)
    expected = {asset["name"] for asset in manifest["assets"]} | {MANIFEST, NOTES}
    present = set(os.listdir(directory))
    if DRAFT in present:
        if not allow_draft:
            raise Refused("the release is marked draft-only")
        present.discard(DRAFT)
    if present != expected:
        extra = sorted(present - expected)
        missing = sorted(expected - present)
        raise Refused(f"asset set differs: extra {extra}, missing {missing}")
    for entry in manifest["assets"] + [manifest["notes"]]:
        if record(directory, entry["name"]) != entry:
            raise Refused(f"{entry['name']} differs from the manifest")
    listed = {}
    with open(os.path.join(directory, SUMS)) as file:
        for line in file:
            hash, sep, name = line.rstrip("\n").partition("  ")
            if not sep or not HEX64.match(hash) or name in listed:
                raise Refused("SHA256SUMS is malformed")
            listed[name] = hash
    others = {a["name"]: a["sha256"] for a in manifest["assets"] if a["name"] != SUMS}
    if listed != others:
        raise Refused("SHA256SUMS does not list exactly the other assets")
    return manifest


def main(argv):
    if len(argv) >= 3 and argv[1] == "create":
        create(argv[2], argv[3:])
    elif len(argv) in (3, 4) and argv[1] == "check":
        if len(argv) == 4 and argv[3] != "--allow-draft":
            raise Refused(f"unexpected argument: {argv[3]}")
        check(argv[2], len(argv) == 4)
    elif len(argv) == 4 and argv[1] == "field":
        print(check(argv[2], False)["fields"][argv[3]])
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (Refused, OSError, KeyError, ValueError) as error:
        print(f"release manifest: {error}", file=sys.stderr)
        sys.exit(1)
