#!/usr/bin/env python3
"""Inspect a Sipeed/LicheeRV Nano vendor upgrade.zip without extracting it."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from xml.etree import ElementTree


REQUIRED_ENTRIES = (
    "boot.sd",
    "rootfs.sd",
    "META/misc_info.txt",
    "META/metadata.txt",
    "partition_sd.xml",
)


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def safe_zip_name(name: str) -> bool:
    if not name or name.startswith("/") or name.startswith("../"):
        return False
    return "/../" not in name and not name.endswith("/..")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def zip_text(zip_file: zipfile.ZipFile, name: str) -> str:
    with zip_file.open(name) as file_obj:
        return file_obj.read().decode("utf-8")


def parse_misc_info(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            die(f"META/misc_info.txt:{line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def parse_md5_metadata(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            die(f"META/metadata.txt:{line_number}: expected '<md5> <path>'")
        md5, name = parts
        if len(md5) != 32 or any(char not in "0123456789abcdefABCDEF" for char in md5):
            die(f"META/metadata.txt:{line_number}: invalid md5 '{md5}'")
        if not safe_zip_name(name):
            die(f"META/metadata.txt:{line_number}: unsafe path '{name}'")
        result[name] = md5.lower()
    return result


def parse_partitions(text: str) -> List[Dict[str, object]]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        die(f"partition_sd.xml is not valid XML: {exc}")

    if root.tag != "physical_partition":
        die(f"partition_sd.xml root must be physical_partition, got {root.tag}")

    partitions: List[Dict[str, object]] = []
    for element in root.findall("partition"):
        label = element.get("label")
        size_text = element.get("size_in_kb")
        file_name = element.get("file")
        readonly_text = element.get("readonly", "false").lower()

        if not label:
            die("partition_sd.xml partition is missing label")
        if not size_text or not size_text.isdigit() or int(size_text) <= 0:
            die(f"partition_sd.xml partition {label} has invalid size_in_kb")
        if not file_name or not safe_zip_name(file_name):
            die(f"partition_sd.xml partition {label} has invalid file")
        if readonly_text not in ("true", "false"):
            die(f"partition_sd.xml partition {label} has invalid readonly")

        partitions.append(
            {
                "label": label,
                "size_kb": int(size_text),
                "readonly": readonly_text == "true",
                "file": file_name,
            }
        )

    if not partitions:
        die("partition_sd.xml does not list any partitions")

    return partitions


def inspect_zip_entry(
    zip_file: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    expected_md5: Optional[str],
) -> Dict[str, object]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size = 0

    with zip_file.open(info, "r") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            size += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)

    if size != info.file_size:
        die(f"{info.filename}: zip reported {info.file_size} bytes but read {size}")

    actual_md5 = md5.hexdigest()
    metadata_ok = expected_md5 is None or expected_md5 == actual_md5
    if not metadata_ok:
        die(f"{info.filename}: md5 mismatch, expected {expected_md5}, got {actual_md5}")

    return {
        "path": info.filename,
        "size": size,
        "md5": actual_md5,
        "metadata_md5": expected_md5,
        "metadata_md5_ok": metadata_ok,
        "sha256": sha256.hexdigest(),
    }


def inspect_upgrade(upgrade_zip: Path) -> Dict[str, object]:
    if not upgrade_zip.is_file():
        die(f"upgrade zip does not exist: {upgrade_zip}")

    try:
        zip_file = zipfile.ZipFile(upgrade_zip)
    except zipfile.BadZipFile as exc:
        die(f"not a valid zip file: {exc}")

    with zip_file:
        infos = [info for info in zip_file.infolist() if not info.is_dir()]
        by_name = {info.filename: info for info in infos}

        for name in by_name:
            if not safe_zip_name(name):
                die(f"unsafe zip entry path: {name}")

        for required in REQUIRED_ENTRIES:
            if required not in by_name:
                die(f"missing required zip entry: {required}")

        metadata_md5 = parse_md5_metadata(zip_text(zip_file, "META/metadata.txt"))
        misc_info = parse_misc_info(zip_text(zip_file, "META/misc_info.txt"))
        partitions = parse_partitions(zip_text(zip_file, "partition_sd.xml"))

        for name in metadata_md5:
            if name not in by_name:
                die(f"META/metadata.txt references missing zip entry: {name}")

        files = [
            inspect_zip_entry(zip_file, by_name[name], metadata_md5.get(name))
            for name in sorted(by_name)
        ]
        file_lookup = {entry["path"]: entry for entry in files}

        for partition in partitions:
            file_name = str(partition["file"])
            if file_name not in file_lookup:
                die(f"partition {partition['label']} references missing file {file_name}")
            file_entry = file_lookup[file_name]
            partition["file_size"] = file_entry["size"]
            partition["file_sha256"] = file_entry["sha256"]

    return {
        "kind": "sipeed-licheerv-nano-vendor-upgrade-inspection",
        "upgrade_zip": {
            "path": str(upgrade_zip),
            "size": upgrade_zip.stat().st_size,
            "sha256": sha256_file(upgrade_zip),
        },
        "misc_info": misc_info,
        "partitions": partitions,
        "files": files,
    }


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and describe a Sipeed/LicheeRV Nano vendor upgrade.zip"
    )
    parser.add_argument("upgrade_zip", help="path to vendor upgrade.zip")
    parser.add_argument(
        "output",
        nargs="?",
        help="optional JSON output path; stdout is used when omitted",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    inspection = inspect_upgrade(Path(args.upgrade_zip))

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(inspection, indent=2, sort_keys=True) + "\n")
        print(output)
    else:
        json.dump(inspection, sys.stdout, indent=2, sort_keys=True)
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
