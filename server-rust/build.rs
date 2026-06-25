use std::{env, path::PathBuf};

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let linked_libkvm = env::var_os("CARGO_FEATURE_LINKED_LIBKVM").is_some();

    println!("cargo:rerun-if-env-changed=NANOKVM_SYSROOT_LIB");

    if !target.contains("riscv64") || !linked_libkvm {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let lib_dir = manifest_dir.join("../server/dl_lib");
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
