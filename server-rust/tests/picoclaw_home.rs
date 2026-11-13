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
fn invalid_home_check_refuses_before_contacting_a_broker_or_creating_state() {
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    for home in [
        OsString::from("../other"),
        OsString::from("/bad\nname"),
        OsString::from_vec(b"/bad\xff".to_vec()),
    ] {
        for operation in [
            "picoclaw-home-check",
            "picoclaw-control-ready",
            "onboard-picoclaw",
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-ctl"))
                .arg(operation)
                .current_dir(root.path())
                .env_clear()
                .env("PICOCLAW_HOME", &home)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(64));
            assert!(output.stdout.is_empty());
            assert_eq!(
                output.stderr,
                b"invalid picoclaw home; no runtime action taken\n"
            );
        }
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn actual_s96_delegates_home_selection_and_never_changes_cwd_or_creates_state() {
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
    // Refuse historical direct launch bodies BEFORE executing any shell fixture.
    assert!(!source.contains("setup_runtime_env"));
    assert!(!source.contains("mkdir"));
    assert!(!source.contains("cd "));
    for relative in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let expected = root.path().join("custom home");
        let selected = if relative {
            OsStr::new("custom home")
        } else {
            expected.as_os_str()
        };
        let script = source.replace(
            "/usr/libexec/nanokvm-native-ctl",
            root.path().join("missing-ctl").to_str().unwrap(),
        );
        for action in ["start", "stop", "onboard", "restart"] {
            let output = Command::new("/bin/sh")
                .args(["-c", &script, "s96-home-fixture", action])
                .current_dir(root.path())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", root.path())
                .env("PICOCLAW_HOME", selected)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(127));
            assert!(!expected.exists());
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }
}
