#!/usr/bin/python3 -I
"""Test stand-in for the GitHub CLI and curl used by publish-release.sh.

Releases live under $FAKE_GH_STATE/releases/<tag>/ (meta.json and assets/);
every call is appended to $FAKE_GH_STATE/log. Faults, by FAKE_GH_FAIL:
  create          upload half the assets of a new draft, then fail
  upload:<tag>    replace only the first file of an upload to <tag>, then fail
  edit-after      apply an edit, then fail as if the reply was lost
FAKE_GH_CORRUPT=<asset> stores that asset of a new release with a flipped byte.
Run as "curl", it serves https://github.com/<repo>/releases/latest/download/.
"""

import json
import os
import shutil
import sys

STATE = os.environ["FAKE_GH_STATE"]
RELEASES = os.path.join(STATE, "releases")
FAULT = os.environ.get("FAKE_GH_FAIL", "")


def die(message, code=1):
    print(message, file=sys.stderr)
    sys.exit(code)


def path(tag, *parts):
    return os.path.join(RELEASES, tag, *parts)


def meta(tag):
    with open(path(tag, "meta.json")) as file:
        return json.load(file)


def save(tag, data):
    with open(path(tag, "meta.json"), "w") as file:
        json.dump(data, file)


def options(arguments):
    flags, values, files = set(), {}, []
    while arguments:
        item = arguments.pop(0)
        if item in ("--repo", "--dir", "--target", "--title", "--notes-file", "--json"):
            values[item] = arguments.pop(0)
        elif item == "--pattern":
            values.setdefault("--pattern", []).append(arguments.pop(0))
        elif item.startswith("--"):
            flags.add(item)
        else:
            files.append(item)
    return flags, values, files


def store(tag, source):
    name = os.path.basename(source)
    target = path(tag, "assets", name)
    shutil.copyfile(source, target)
    if os.environ.get("FAKE_GH_CORRUPT") == name:
        with open(target, "r+b") as file:
            byte = file.read(1)
            file.seek(0)
            file.write(bytes([byte[0] ^ 1]))


def release(arguments):
    command, tag = arguments[0], arguments[1] if len(arguments) > 1 else None
    flags, values, files = options(arguments[2:] if tag and not tag.startswith("--") else arguments[1:])
    exists = tag is not None and os.path.isdir(path(tag))
    if command == "view":
        if not exists:
            die("release not found")
        print(json.dumps({"isDraft": meta(tag)["draft"]}))
    elif command == "list":
        tags = sorted(os.listdir(RELEASES)) if os.path.isdir(RELEASES) else []
        print(json.dumps([
            {"tagName": t, "isLatest": meta(t)["latest"]} for t in tags if not meta(t)["draft"]
        ]))
    elif command == "create":
        if exists:
            die("a release with the same tag name already exists")
        os.makedirs(path(tag, "assets"))
        save(tag, {"draft": "--draft" in flags, "latest": False, "target": values.get("--target")})
        upload = files[: len(files) // 2] if FAULT == "create" else files
        for source in upload:
            store(tag, source)
        if FAULT == "create":
            die("connection reset during upload")
    elif command == "download":
        if not exists:
            die("release not found")
        assets = sorted(os.listdir(path(tag, "assets")))
        wanted = values.get("--pattern") or assets
        for name in wanted:
            if name not in assets:
                die(f"no assets match {name}")
            shutil.copyfile(path(tag, "assets", name), os.path.join(values["--dir"], name))
    elif command == "edit":
        if not exists:
            die("release not found")
        data = meta(tag)
        if "--draft=false" in flags:
            data["draft"] = False
        if "--latest" in flags:
            for other in os.listdir(RELEASES):
                if other != tag:
                    other_data = meta(other)
                    other_data["latest"] = False
                    save(other, other_data)
            data["latest"] = True
        save(tag, data)
        if FAULT == "edit-after":
            die("the reply was lost")
    elif command == "upload":
        if not exists:
            die("release not found")
        for index, source in enumerate(files):
            name = os.path.basename(source)
            if os.path.exists(path(tag, "assets", name)) and "--clobber" not in flags:
                die(f"asset {name} already exists")
            shutil.copyfile(source, path(tag, "assets", name))
            if FAULT == f"upload:{tag}" and index == 0:
                die("connection reset during upload")
    else:
        die(f"unsupported release command {command}", 2)


def curl(arguments):
    url, output = None, None
    while arguments:
        item = arguments.pop(0)
        if item == "-o":
            output = arguments.pop(0)
        elif item == "--retry":
            arguments.pop(0)
        elif not item.startswith("-"):
            url = item
    prefix = "/releases/latest/download/"
    name = url.split(prefix, 1)[1] if url and prefix in url else None
    tags = [t for t in os.listdir(RELEASES) if meta(t)["latest"]] if os.path.isdir(RELEASES) else []
    if not name or len(tags) != 1 or not os.path.exists(path(tags[0], "assets", name)):
        die("curl: (22) The requested URL returned error: 404", 22)
    shutil.copyfile(path(tags[0], "assets", name), output)


def main():
    program = os.path.basename(sys.argv[0])
    with open(os.path.join(STATE, "log"), "a") as log:
        log.write(" ".join([program] + sys.argv[1:]) + "\n")
    if program == "curl":
        curl(sys.argv[1:])
    elif sys.argv[1:3] == ["auth", "status"]:
        return
    elif sys.argv[1] == "release" and len(sys.argv) > 2:
        release(sys.argv[2:])
    else:
        die(f"unsupported gh call: {sys.argv[1:]}", 2)


main()
