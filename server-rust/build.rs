use std::{env, fs::File, io::Read, path::PathBuf};

#[path = "src/update/restore_binding.rs"]
mod restore_binding;

fn bind_restore_runtime(required: bool) {
    println!("cargo:rerun-if-env-changed=NANOKVM_SSH_RUNTIME_BINDING");
    let bytes = match env::var_os("NANOKVM_SSH_RUNTIME_BINDING") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.is_absolute(),
                "SSH runtime binding path must be absolute"
            );
            println!("cargo:rerun-if-changed={}", path.display());
            let file = File::open(&path).expect("open SSH runtime binding");
            assert!(
                file.metadata().expect("SSH runtime metadata").is_file(),
                "SSH runtime binding must be regular"
            );
            let mut bytes = Vec::new();
            file.take(restore_binding::MAX_HELPER + restore_binding::HEADER as u64 + 1)
                .read_to_end(&mut bytes)
                .expect("read SSH runtime binding");
            let binding = restore_binding::validate(&bytes).expect("invalid SSH runtime binding");
            assert!(!binding.image.is_empty() && binding.digest != [0; 32]);
            bytes
        }
        None => {
            assert!(
                !required,
                "linked RV64 backend requires NANOKVM_SSH_RUNTIME_BINDING; use scripts/build-linked-libkvm.sh"
            );
            Vec::new() // host/helper builds cannot accidentally authorize a runtime
        }
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(output.join("ssh-runtime.binding"), bytes).expect("write embedded SSH runtime");
}

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let linked_libkvm = env::var_os("CARGO_FEATURE_LINKED_LIBKVM").is_some();

    bind_restore_runtime(target.contains("riscv64") && linked_libkvm);

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
