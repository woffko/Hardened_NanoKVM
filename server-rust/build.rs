use std::{env, fs::File, io::Read, path::PathBuf};

#[path = "src/update/restore_binding.rs"]
mod restore_binding;

#[derive(Clone, Copy)]
enum Runtime {
    Ssh,
    AppRecovery,
    Native(restore_binding::NativeRuntime),
}

fn read_runtime(runtime: Runtime, required: bool) -> Vec<u8> {
    let variable = match runtime {
        Runtime::Ssh => "NANOKVM_SSH_RUNTIME_BINDING",
        Runtime::AppRecovery => "NANOKVM_APP_RECOVERY_BINDING",
        Runtime::Native(runtime) => runtime.variable(),
    };
    let maximum = match runtime {
        Runtime::Native(_) => restore_binding::MAX_NATIVE_HELPER,
        _ => restore_binding::MAX_HELPER,
    };
    println!("cargo:rerun-if-env-changed={variable}");
    match env::var_os(variable) {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(path.is_absolute(), "{variable} path must be absolute");
            println!("cargo:rerun-if-changed={}", path.display());
            let file = File::open(&path).expect("open embedded runtime binding");
            assert!(
                file.metadata().expect("runtime binding metadata").is_file(),
                "runtime binding must be regular"
            );
            let mut bytes = Vec::new();
            file.take(maximum + restore_binding::HEADER as u64 + 1)
                .read_to_end(&mut bytes)
                .expect("read runtime binding");
            let binding = match runtime {
                Runtime::Ssh => restore_binding::validate(&bytes),
                Runtime::AppRecovery => restore_binding::validate_app_recovery(&bytes),
                Runtime::Native(runtime) => restore_binding::validate_native(&bytes, runtime),
            }
            .expect("invalid runtime binding domain, digest or ELF");
            assert!(!binding.image.is_empty() && binding.digest != [0; 32]);
            bytes
        }
        None => {
            assert!(
                !required,
                "linked RV64 backend requires {variable}; use scripts/build-linked-libkvm.sh"
            );
            Vec::new() // host/helper builds cannot accidentally authorize a runtime
        }
    }
}

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let linked_libkvm = env::var_os("CARGO_FEATURE_LINKED_LIBKVM").is_some();

    let required = target.contains("riscv64") && linked_libkvm;
    // Validate the complete set before publishing any output. A missing or
    // cross-domain member cannot authorize a newly updated partial family.
    let ssh = read_runtime(Runtime::Ssh, required);
    let app = read_runtime(Runtime::AppRecovery, required);
    let native = restore_binding::NATIVE_RUNTIMES
        .map(|runtime| (runtime, read_runtime(Runtime::Native(runtime), required)));
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(output.join("ssh-runtime.binding"), ssh).expect("write embedded SSH runtime");
    std::fs::write(output.join("app-recovery.binding"), app).expect("write embedded app recovery");
    for (runtime, bytes) in native {
        std::fs::write(
            output.join(format!("{}.binding", runtime.filename())),
            bytes,
        )
        .expect("write embedded native runtime");
    }

    println!("cargo:rerun-if-env-changed=NANOKVM_SYSROOT_LIB");

    if !target.contains("riscv64") || !linked_libkvm {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let lib_dir = manifest_dir.join("native/dl_lib");
    let sysroot_lib_dir = env::var_os("NANOKVM_SYSROOT_LIB")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("sysroot/lib"));

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    if sysroot_lib_dir.exists() {
        println!(
            "cargo:rustc-link-search=native={}",
            sysroot_lib_dir.display()
        );
    }
}
