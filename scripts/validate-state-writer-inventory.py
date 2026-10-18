#!/usr/bin/env python3
"""Closed source-policy coverage lint; never runtime quiescence authorization."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys

KINDS = {"REQUIRED", "FIXED", "PRESENCE", "TREES"}
STATUSES = {"enrolled", "partial", "open"}


class InventoryError(ValueError):
    """Only fixed, non-private validation diagnostics may use this type."""


def require(condition, message):
    if not condition:
        raise InventoryError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def policy_members(source):
    tables = {}
    pattern = r"pub\(super\) const ([A-Z_]+): &\[&str\] = &\[(.*?)\];"
    for name, body in re.findall(pattern, source, re.S):
        require(name not in tables, "duplicate policy table")
        members = []
        for line in body.splitlines():
            line = line.split("//", 1)[0].strip()
            if not line:
                continue
            match = re.fullmatch(r'"([A-Za-z0-9._/-]+)",', line)
            require(match is not None, "unsupported policy syntax; review parser")
            require(all(part not in {"", ".", ".."} for part in match[1].split("/")),
                    "noncanonical policy member")
            members.append(match[1])
        require(bool(members), "empty policy table")
        require(len(set(members)) == len(members), "duplicate policy member")
        tables[name] = set(members)
    require(set(tables) == KINDS, "missing or unknown policy table")
    return tables


def text_list(value, label):
    require(isinstance(value, list) and bool(value), "empty/invalid " + label)
    require(all(isinstance(item, str) and item.strip() for item in value),
            "invalid " + label)


def validate(inventory, policy, root):
    require(isinstance(inventory, dict), "inventory must be an object")
    require(set(inventory) == {"schema", "source_basis", "runtime_authority",
            "cross_cutting", "groups", "dynamic_inputs", "constraints"},
            "unknown or missing inventory field")
    require(type(inventory["schema"]) is int and inventory["schema"] == 1,
            "unsupported inventory schema")
    require(re.fullmatch(r"[0-9a-f]{40}", inventory["source_basis"]) is not None,
            "invalid source basis")
    require(inventory["runtime_authority"] is False,
            "static inventory cannot authorize runtime quiescence")
    text_list(inventory["constraints"], "constraints")
    seen_ids = set()
    mapped = {kind: set() for kind in KINDS}
    all_paths = set()
    for section, extra in [("cross_cutting", "scope"), ("groups", "members"),
                           ("dynamic_inputs", "readset")]:
        rows = inventory[section]
        require(isinstance(rows, list) and bool(rows), "empty/invalid inventory section")
        for row in rows:
            require(isinstance(row, dict) and set(row) == {
                "id", "status", "writers", "evidence", extra}, "invalid inventory row")
            identifier = row["id"]
            require(isinstance(identifier, str) and
                    re.fullmatch(r"[a-z][a-z0-9-]*", identifier) is not None,
                    "invalid producer ID")
            require(identifier not in seen_ids, "duplicate producer ID")
            seen_ids.add(identifier)
            require(row["status"] in STATUSES, "unknown producer status")
            text_list(row["writers"], "writers")
            text_list(row["evidence"], "evidence")
            for reference in row["evidence"]:
                path = PurePosixPath(reference)
                require(not path.is_absolute() and ".." not in path.parts,
                        "invalid source reference")
                require((root / reference).is_file(), "missing source reference")
            if extra != "members":
                require(isinstance(row[extra], str) and row[extra].strip(),
                        "missing source boundary")
                continue
            members = row[extra]
            require(isinstance(members, dict) and bool(members) and
                    set(members) <= KINDS, "invalid member kinds")
            for kind, paths in members.items():
                text_list(paths, "member paths")
                for path in paths:
                    require(path in policy[kind], "unknown or wrong-kind schema member")
                    require(path not in all_paths, "duplicate member assignment")
                    mapped[kind].add(path)
                    all_paths.add(path)
    require(mapped == policy, "unclassified restore schema member")
    return len(all_paths)


def inspect(root):
    inventory = json.loads((root / "docs/security-state-writers.json").read_text(),
                           object_pairs_hook=unique_object)
    policy = policy_members((root / "server-rust/src/update/restore_policy.rs").read_text())
    return validate(inventory, policy, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        count = inspect(args.root)
    except InventoryError as error:
        print("writer inventory coverage: FAIL (" + str(error) + ")", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError) as error:
        # No source file contents, credentials or private runtime paths printed.
        print("writer inventory coverage: FAIL (" + type(error).__name__ + ")", file=sys.stderr)
        return 1
    print(f"writer inventory coverage: PASS ({count} schema roots/paths); "
          "runtime quiescence NOT ESTABLISHED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
