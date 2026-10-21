#!/usr/bin/env python3
"""Exercise the actual compiled Cargo build script, without rebuilding deps."""

import importlib.util
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("ssh-runtime-binding.py"))
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)


def main():
    if len(sys.argv) != 5:
        raise ValueError("usage: test-ssh-runtime-build-script.py BUILD_SCRIPT STATIC_SSH_HELPER STATIC_APP_HELPER STATIC_NATIVE_DIR")
    executable, helper, app_helper, native_directory = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    with binding.regular(helper, binding.MAX_HELPER) as source:
        valid = binding.envelope(source.read(binding.MAX_HELPER + 1))
    with binding.regular(app_helper, binding.MAX_HELPER) as source:
        valid_app = binding.envelope(source.read(binding.MAX_HELPER + 1), binding.APP_RECOVERY_MAGIC)
    native_frames = {}
    for role, magic in binding.NATIVE_MAGICS.items():
        with binding.regular(native_directory / ("nanokvm-native-" + role), binding.MAX_NATIVE_HELPER) as source:
            native_frames[role] = binding.envelope(source.read(binding.MAX_NATIVE_HELPER + 1), magic)
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
        native_inputs = {}
        for role, data in native_frames.items():
            path = work / ("native-" + role)
            path.write_bytes(data)
            native_inputs[role] = path
        cases = [
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
        ]
        cases = [(name, target, linked, value, app_value, native_inputs if linked else {}, success)
                 for name, target, linked, value, app_value, success in cases]
        for role, magic in binding.NATIVE_MAGICS.items():
            valid_native = native_frames[role]
            faults = [("missing", None), ("relative", native_inputs[role].name),
                      ("SSH-domain", inputs["valid"]), ("app-domain", inputs["app"])]
            for fault, data in [("trailing", valid_native + b"x"), ("truncated", valid_native[:-1]),
                                ("corrupt", valid_native[:16] + bytes(32) + valid_native[48:]),
                                ("oversized", magic + (binding.MAX_NATIVE_HELPER + 1).to_bytes(8, "little") + valid_native[16:])]:
                path = work / (role + "-" + fault)
                path.write_bytes(data)
                faults.append((fault, path))
            for other, path in native_inputs.items():
                if other != role:
                    faults.append(("other-" + other, path))
            for fault, path in faults:
                values = dict(native_inputs)
                values[role] = path
                cases.append(("native " + role + " " + fault, "riscv64gc-unknown-linux-musl", True,
                              inputs["valid"], inputs["app"], values, False))
        for name, target, linked, value, app_value, native_values, success in cases:
            output = work / name.replace(" ", "-")
            output.mkdir()
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TARGET": target,
                   "CARGO_MANIFEST_DIR": str(Path(__file__).resolve().parent.parent / "server-rust"), "OUT_DIR": str(output)}
            if linked:
                env["CARGO_FEATURE_LINKED_LIBKVM"] = "1"
            if value is not None:
                env["NANOKVM_SSH_RUNTIME_BINDING"] = str(value)
            if app_value is not None:
                env["NANOKVM_APP_RECOVERY_BINDING"] = str(app_value)
            for role, path in native_values.items():
                if path is not None:
                    env["NANOKVM_NATIVE_" + role.upper() + "_BINDING"] = str(path)
            result = subprocess.run([str(executable)], env=env, cwd=work, capture_output=True,
                                    text=True, timeout=10)
            assert (result.returncode == 0) == success, (name, result.stderr)
            bound = output / "ssh-runtime.binding"
            bound_app = output / "app-recovery.binding"
            bound_native = {role: output / ("nanokvm-native-" + role + ".binding")
                            for role in binding.NATIVE_MAGICS}
            if success:
                scripts = Path(__file__).resolve().parent.parent / "kvmapp/system/init.d"
                assert (output / "native-boot-digests").read_bytes() == b"".join(
                    hashlib.sha256((scripts / name).read_bytes()).digest()
                    for name in ["S02apprecover", "S30eth", "S30wifi", "S95nanokvm", "S96picoclaw"]), name
                assert bound.read_bytes() == (valid if value is not None else b""), name
                assert bound_app.read_bytes() == (valid_app if app_value is not None else b""), name
                for role, path in bound_native.items():
                    assert path.read_bytes() == (native_frames[role] if native_values.get(role) is not None else b""), name
            else:
                assert not bound.exists(), name
                assert not bound_app.exists(), name
                assert not any(path.exists() for path in bound_native.values()), name
                assert not (output / "native-boot-digests").exists(), name
            print("PASS", name)
        # Real build.rs must fail before publishing ANY frame if a source boot
        # identity is unavailable. Host-only success must not mask this gate.
        trusted = Path(__file__).resolve().parent.parent / "kvmapp/system/init.d"
        names = ["S02apprecover", "S30eth", "S30wifi", "S95nanokvm", "S96picoclaw"]
        for name in names:
            for fault in ["missing", "empty", "oversized"]:
                source_root = work / (name + "-" + fault)
                manifest = source_root / "server-rust"
                manifest.mkdir(parents=True)
                scripts = source_root / "kvmapp/system/init.d"
                scripts.mkdir(parents=True)
                for member in names:
                    (scripts / member).write_bytes((trusted / member).read_bytes())
                if fault == "missing": (scripts / name).unlink()
                elif fault == "empty": (scripts / name).write_bytes(b"")
                else: (scripts / name).write_bytes(bytes(1024 * 1024 + 1))
                output = source_root / "out"
                output.mkdir()
                env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TARGET": "riscv64gc-unknown-linux-musl",
                       "CARGO_FEATURE_LINKED_LIBKVM": "1", "CARGO_MANIFEST_DIR": str(manifest), "OUT_DIR": str(output),
                       "NANOKVM_SSH_RUNTIME_BINDING": str(inputs["valid"]),
                       "NANOKVM_APP_RECOVERY_BINDING": str(inputs["app"])}
                env.update({"NANOKVM_NATIVE_" + role.upper() + "_BINDING": str(path)
                            for role, path in native_inputs.items()})
                result = subprocess.run([str(executable)], env=env, cwd=work,
                                        capture_output=True, text=True, timeout=10)
                assert result.returncode != 0, (name, fault)
                assert list(output.iterdir()) == [], (name, fault, "partial binding output")
                print("PASS boot identity", name, fault)


if __name__ == "__main__":
    main()
