#!/usr/bin/env python3
"""Exercise the actual compiled Cargo build script, without rebuilding deps."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("ssh-runtime-binding.py"))
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


def main():
    if len(sys.argv) != 4:
        raise ValueError("usage: test-ssh-runtime-build-script.py BUILD_SCRIPT STATIC_SSH_HELPER STATIC_APP_HELPER")
    executable, helper, app_helper = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    with binding.regular(helper, binding.MAX_HELPER) as source:
        valid = binding.envelope(source.read(binding.MAX_HELPER + 1))
    with binding.regular(app_helper, binding.MAX_HELPER) as source:
        valid_app = binding.envelope(source.read(binding.MAX_HELPER + 1), binding.APP_RECOVERY_MAGIC)
    with tempfile.TemporaryDirectory(prefix="nanokvm-build-binding-") as directory:
        work = Path(directory)
        inputs = {}
        for name, data in [("valid", valid), ("trailing", valid + b"x"),
                           ("truncated", valid[:-1]), ("corrupt", valid[:16] + bytes(32) + valid[48:]),
                           ("app", valid_app), ("app-trailing", valid_app + b"x"),
                           ("app-truncated", valid_app[:-1]),
                           ("app-corrupt", valid_app[:16] + bytes(32) + valid_app[48:])]:
            path = work / name
            path.write_bytes(data)
            inputs[name] = path
        for name, target, linked, value, app_value, success in [
            ("linked missing both", "riscv64gc-unknown-linux-musl", True, None, None, False),
            ("linked missing SSH", "riscv64gc-unknown-linux-musl", True, None, inputs["app"], False),
            ("linked missing app", "riscv64gc-unknown-linux-musl", True, inputs["valid"], None, False),
            ("linked relative", "riscv64gc-unknown-linux-musl", True, "valid", inputs["app"], False),
            ("linked app relative", "riscv64gc-unknown-linux-musl", True, inputs["valid"], "app", False),
            ("linked valid", "riscv64gc-unknown-linux-musl", True, inputs["valid"], inputs["app"], True),
            ("linked trailing", "riscv64gc-unknown-linux-musl", True, inputs["trailing"], inputs["app"], False),
            ("linked truncated", "riscv64gc-unknown-linux-musl", True, inputs["truncated"], inputs["app"], False),
            ("linked corrupt", "riscv64gc-unknown-linux-musl", True, inputs["corrupt"], inputs["app"], False),
            ("linked app trailing", "riscv64gc-unknown-linux-musl", True, inputs["valid"], inputs["app-trailing"], False),
            ("linked app truncated", "riscv64gc-unknown-linux-musl", True, inputs["valid"], inputs["app-truncated"], False),
            ("linked app corrupt", "riscv64gc-unknown-linux-musl", True, inputs["valid"], inputs["app-corrupt"], False),
            ("linked app as SSH", "riscv64gc-unknown-linux-musl", True, inputs["app"], inputs["app"], False),
            ("linked SSH as app", "riscv64gc-unknown-linux-musl", True, inputs["valid"], inputs["valid"], False),
            ("host absent", "x86_64-unknown-linux-gnu", False, None, None, True),
            ("static helper absent", "riscv64gc-unknown-linux-musl", False, None, None, True),
        ]:
            output = work / name.replace(" ", "-")
            output.mkdir()
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TARGET": target,
                   "CARGO_MANIFEST_DIR": str(executable.parent), "OUT_DIR": str(output)}
            if linked:
                env["CARGO_FEATURE_LINKED_LIBKVM"] = "1"
            if value is not None:
                env["NANOKVM_SSH_RUNTIME_BINDING"] = str(value)
            if app_value is not None:
                env["NANOKVM_APP_RECOVERY_BINDING"] = str(app_value)
            result = subprocess.run([str(executable)], env=env, cwd=work, capture_output=True,
                                    text=True, timeout=10)
            assert (result.returncode == 0) == success, (name, result.stderr)
            bound = output / "ssh-runtime.binding"
            bound_app = output / "app-recovery.binding"
            if success:
                assert bound.read_bytes() == (valid if value is not None else b""), name
                assert bound_app.read_bytes() == (valid_app if app_value is not None else b""), name
            else:
                assert not bound.exists(), name
                assert not bound_app.exists(), name
            print("PASS", name)


if __name__ == "__main__":
    main()
