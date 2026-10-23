#!/usr/bin/env python3
"""Check the closed input policy; --engine also tests real Docker/BuildKit.

This is deliberately NOT a Docker glob interpreter. The host check accepts only
one restricted policy: deny all, exact directory traversal plus immediate child
deny, and exact file exceptions. Engine checks use synthetic data only.
"""
import argparse
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INPUTS = (
    "docker/Dockerfile", "docker/entrypoint", "docker/maixcdk-requirements.lock",
    "support/sg2002/build",
    "support/sg2002/additional/kvm", "support/sg2002/additional/kvm_mmf",
    "support/sg2002/additional/vision",
    "support/sg2002/additional/peripheral/port/maixcam/maix_i2c.cpp",
    "support/sg2002/additional/sophgo-middleware/v2/sample/common/sample_common_sensor.c",
    "support/sg2002/kvm_system/main", "support/sg2002/kvm_vision_test/main",
)
DENIED = (
    ".git/config", ".aws/credentials", ".codex/config.toml", ".env",
    "AGENTS.override.md", "build/audit/secret-sentinel.pem", "local/secret.key",
    "server-rust/target/cache", "web/node_modules/cache", "kvmapp/local.conf",
    "support/unrelated/secret.cpp", "support/sg2002/local.cpp",
    "support/sg2002/additional/original/secret.cpp",
    "support/sg2002/additional/kvm/.git/config",
    "support/sg2002/additional/kvm/src/local-secret.cpp",
    "support/sg2002/additional/vision/include/local-secret.hpp",
    "support/sg2002/kvm_system/build/cache",
    "support/sg2002/kvm_system/dist/private.pem",
    "support/sg2002/kvm_system/main/src/.env",
    "support/sg2002/kvm_system/main/src/private.pem",
    "support/sg2002/kvm_vision_test/main/src/local-secret.cpp",
)
OLD_POLICY = """Dockerfile
!server/go.mod
server/go.sum
server/NanoKVM-Server
web
support/sg2002/kvm_system/build
support/sg2002/kvm_system/dist
support/sg2002/kvm_system/CMakeLists.txt
support/sg2002/kvm_vision_test/build
support/sg2002/kvm_vision_test/dist
support/sg2002/kvm_vision_test/CMakeLists.txt
"""


def tracked_inputs():
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", *INPUTS], cwd=ROOT,
        check=True, capture_output=True, timeout=10,
    )
    files = set(result.stdout.decode().rstrip("\0").split("\0"))
    if not files or "" in files:
        raise ValueError("empty tracked input inventory")
    return files


def parents(files):
    return {str(parent) for file in files for parent in PurePosixPath(file).parents
            if str(parent) != "."}


def check_policy(text, expected):
    rules = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not rules or rules[0] != "**":
        raise ValueError("context must start with deny-all")
    directories, files = set(), set()
    index = 1
    while index < len(rules):
        rule = rules[index]
        if not rule.startswith("!"):
            raise ValueError("only exact exceptions and immediate directory fences are allowed")
        path = rule[1:]
        if (not path or str(PurePosixPath(path)) != path or path.startswith("/")
                or ".." in PurePosixPath(path).parts
                or any(char in path for char in "*?![]\\:$\t\r ")
                or path in directories or path in files):
            raise ValueError("invalid or duplicate exact exception")
        if str(PurePosixPath(path).parent) not in directories | {"."}:
            raise ValueError("missing earlier fenced parent")
        if index + 1 < len(rules) and rules[index + 1] == path + "/**":
            directories.add(path)
            index += 2
        else:
            files.add(path)
            index += 1
    if files != expected or directories != parents(expected):
        raise ValueError("context differs from the reviewed native input inventory")
    return files


def check_source_files(files, root=ROOT):
    for file in files:
        path = root / file
        if not path.is_file() or any((root / parent).is_symlink()
                                     for parent in [file, *parents({file})]):
            raise ValueError("input is missing, nonregular, or traverses a symlink")


def check_copy_inputs(text, expected):
    """Fail closed outside this Dockerfile's simple COPY dialect, not all Docker syntax."""
    sources, pending = set(), ""
    stage_copies = {
        ("--from=host_tools", "/usr/local/host-tools", "/usr/local/host-tools"),
        ("--from=sdk", "/home/$DOCKER_USER/MaixCDK", "/home/$DOCKER_USER/MaixCDK"),
    }
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") and line[1:].lstrip().lower().startswith("escape"):
            raise ValueError("nondefault Dockerfile escape syntax requires review")
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        row = (pending + line).split()
        pending = ""
        if row[0].upper() == "ADD":
            raise ValueError("ADD is not a reviewed context input")
        if row[0].upper() != "COPY":
            continue
        if len(row) != 4:
            raise ValueError("COPY syntax requires explicit review")
        if row[1].startswith("--from="):
            if tuple(row[1:]) not in stage_copies:
                raise ValueError("unreviewed stage COPY")
        elif row[1] in {"--chown=$DOCKER_USER", "--chmod=+x"}:
            sources.add(row[2])
        else:
            raise ValueError("unreviewed COPY flags")
    if pending or sources != expected:
        raise ValueError("COPY inputs differ from the reviewed native inventory")


class ContextPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = (ROOT / ".dockerignore").read_text()
        cls.files = tracked_inputs()

    def reject(self, text):
        with self.assertRaises(ValueError):
            check_policy(text, self.files)

    def test_exact_tracked_native_inventory_and_regular_sources(self):
        self.assertEqual(check_policy(self.policy, self.files), self.files)
        check_source_files(self.files)
        self.assertTrue(set(INPUTS[:4]) <= self.files)

    def test_old_policy_is_rejected(self):
        self.reject(OLD_POLICY)

    def test_missing_default_deny_rejected(self):
        self.reject(self.policy.replace("**\n", "", 1))

    def test_broad_glob_or_directory_exceptions_rejected(self):
        for extra in ["!**", "!support/**", "!support/sg2002/additional/kvm/src/*"]:
            self.reject(self.policy + "\n" + extra + "\n")

    def test_directory_must_be_immediately_refenced(self):
        self.reject(self.policy.replace("support/**\n", "", 1))
        self.reject(self.policy + "\n!extra\n")

    def test_required_source_cannot_disappear(self):
        self.reject(self.policy.replace("!support/sg2002/build\n", "", 1))

    def test_new_tracked_source_requires_explicit_review(self):
        with self.assertRaises(ValueError):
            check_policy(self.policy, self.files | {"support/sg2002/additional/kvm/src/new.cpp"})

    def test_sentinel_exceptions_and_late_refencing_rejected(self):
        for file in DENIED:
            self.reject(self.policy + "\n!" + file + "\n")
        self.reject(self.policy + "\nsupport/**\n")

    def test_duplicate_path_parent_gap_and_noncanonical_path_rejected(self):
        for extra in ["!docker/entrypoint", "!docker//entrypoint", "!../outside",
                      "!./docker/entrypoint", "!unfenced/child", "!/absolute"]:
            self.reject(self.policy + "\n" + extra + "\n")

    def test_missing_and_symlinked_sources_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                check_source_files({"missing.cpp"}, root)
            (root / "source.cpp").write_text("synthetic source\n")
            (root / "alias.cpp").symlink_to("source.cpp")
            with self.assertRaises(ValueError):
                check_source_files({"alias.cpp"}, root)
            (root / "alias-dir").symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                check_source_files({"alias-dir/source.cpp"}, root)

    def test_no_broad_repository_copy(self):
        expected = {path + "/" if (ROOT / path).is_dir() else path
                    for path in INPUTS if path != "docker/Dockerfile"}
        check_copy_inputs((ROOT / "docker/Dockerfile").read_text(), expected)

    def test_no_dockerfile_specific_ignore_policy_override(self):
        override = ROOT / "docker/Dockerfile.dockerignore"
        self.assertFalse(override.exists() or override.is_symlink())

    def test_copy_case_indent_continuations_add_and_unknown_forms_cannot_hide_new_inputs(self):
        source = (ROOT / "docker/Dockerfile").read_text()
        expected = {path + "/" if (ROOT / path).is_dir() else path
                    for path in INPUTS if path != "docker/Dockerfile"}
        for extra in ["copy . /leak", "  CoPy --chown=$DOCKER_USER . /leak",
                      "COPY " + "\\" + "\n    . /leak", 'COPY [".", "/leak"]', "  add . /leak",
                      "COPY --from=foreign / /leak", "# escape=`", "#escape=`",
                      "# EsCaPe = `"]:
            with self.assertRaises(ValueError):
                check_copy_inputs(source + "\n" + extra + "\n", expected)


def engine_check():
    """Exercise the real matcher/exporter without sending any repository bytes."""
    docker = shutil.which("docker")
    if docker is None:
        raise ValueError("Docker engine gate NOT TESTED: docker executable unavailable")
    files = tracked_inputs()
    policy = (ROOT / ".dockerignore").read_text()
    check_policy(policy, files)
    with tempfile.TemporaryDirectory(prefix="nanokvm-context-fixture-") as directory:
        root = Path(directory)
        context = root / "context"
        for file in files | set(DENIED):
            path = context / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("SYNTHETIC-INPUT\n" if file in files else "SYNTHETIC-SECRET-SENTINEL\n")
        old_inputs = files | (set(DENIED) - {"web/node_modules/cache"})
        for name, rules, expected in [("before", OLD_POLICY, old_inputs),
                                       ("after", policy, files)]:
            (context / ".dockerignore").write_text(rules)
            output = root / name
            result = subprocess.run(
                [docker, "buildx", "build", "--network=none", "--no-cache", "--file", "-",
                 "--output", "type=local,dest=" + str(output), str(context)],
                input="FROM scratch\nCOPY . /context/\n", text=True,
                capture_output=True, timeout=120,
            )
            if result.returncode != 0:
                raise ValueError("Docker synthetic context build/export failed")
            exported = {str(path.relative_to(output / "context"))
                        for path in (output / "context").rglob("*") if path.is_file()}
            # An unfiltered fixture may copy its own ignore file; it is not an input.
            exported.discard(".dockerignore")
            if exported != expected:
                raise ValueError("Docker synthetic context inventory mismatch")
        print("PASS: real Docker context keeps every required input and excludes all sentinels")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", action="store_true", help="require the real Docker engine gate")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ContextPolicyTests)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        raise SystemExit(1)
    print("PASS: static closed-policy checks; real Docker/SDK build is a separate gate")
    if args.engine:
        try:
            engine_check()
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print(str(error) if isinstance(error, ValueError) else "Docker fixture execution failed")
            raise SystemExit(1)
