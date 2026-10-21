#![cfg(feature = "sandbox-test-fixture")]

use std::{
    ffi::{OsStr, OsString},
    fs,
    path::Path,
    process::{Command, Output},
};

fn resolve(home: Option<&OsStr>, cwd: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-ctl"));
    command
        .arg("picoclaw-home")
        .current_dir(cwd)
        .env_clear()
        .env("HOME", "/not-the-service-home");
    if let Some(home) = home {
        command.env("PICOCLAW_HOME", home);
    }
    command.output().unwrap()
}

#[test]
fn cli_home_resolution_is_read_only_and_matches_library_selection() {
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    for home in [None, Some(OsStr::new(" \u{2003}\t"))] {
        let output = resolve(home, root.path());
        assert!(output.status.success());
        assert_eq!(output.stdout, b"/root/.picoclaw\n");
        assert!(output.stderr.is_empty());
    }
    let output = resolve(Some(OsStr::new("custom/./home")), root.path());
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("{}/custom/home\n", root.path().display()).as_bytes()
    );
    for value in [
        OsString::from("../foreign"),
        OsString::from("/bad\nname"),
        OsString::from_vec(b"/bad\xff".to_vec()),
    ] {
        let output = resolve(Some(&value), root.path());
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"invalid picoclaw home; no runtime action taken\n"
        );
    }
    assert_eq!(
        fs::read_dir(root.path()).unwrap().count(),
        0,
        "path selection must not onboard, create or repair runtime state"
    );
}

#[test]
fn actual_s96_setup_exports_the_same_absolute_home_before_chdir() {
    let source = if let Some(reference) = std::env::var_os("NANOKVM_PICO_HOME_SOURCE_REF") {
        let output = Command::new("git")
            .args([
                "show",
                &format!(
                    "{}:kvmapp/system/init.d/S96picoclaw",
                    reference.to_str().unwrap()
                ),
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    } else {
        include_str!("../../kvmapp/system/init.d/S96picoclaw").to_string()
    };
    let prefix = source
        .split("resolve_kvm_control_source() {")
        .next()
        .unwrap();
    let helper = env!("CARGO_BIN_EXE_nanokvm-native-ctl");
    let script = format!(
        "{}\nsetup_runtime_env || exit 91\n\"$BIN_PATH\" gateway\n",
        prefix.replace("/usr/libexec/nanokvm-native-ctl", helper)
    );
    for relative in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let expected = root.path().join("custom home");
        let selected = if relative {
            OsStr::new("custom home")
        } else {
            expected.as_os_str()
        };
        let output = Command::new("/bin/sh")
            .args(["-c", &script, "s96-home-fixture"])
            .current_dir(root.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", root.path())
            .env("PICOCLAW_HOME", selected)
            .env(
                "PICOCLAW_BIN_PATH",
                env!("CARGO_BIN_EXE_nanokvm-native-owner-fixture"),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "private S96 setup failed: {:?}",
            output.status
        );
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(expected.join("picoclaw-runtime.fixture")).unwrap())
                .unwrap();
        assert_eq!(
            value["home"].as_str().unwrap(),
            expected.to_str().unwrap(),
            "native PICOCLAW_HOME must be absolute before cd"
        );
        assert_eq!(value["cwd"].as_str().unwrap(), expected.to_str().unwrap());
        assert_eq!(value["user_home"], "/root");
    }
}
