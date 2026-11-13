use std::process::{Command, Stdio};
#[test]
fn shipped_broker_and_ctl_reject_generic_paths_and_maintenance_cli() {
    for (binary, cases) in [
        (
            env!("CARGO_BIN_EXE_nanokvm-native-broker"),
            vec![
                vec![],
                vec!["--serve", "extra"],
                vec!["--fixture"],
                vec!["/bin/sh"],
                vec!["--raw-writer"],
                vec!["--raw-writer", "--transaction"],
            ],
        ),
        (
            env!("CARGO_BIN_EXE_nanokvm-native-ctl"),
            vec![
                vec![],
                vec!["pause"],
                vec!["resume"],
                vec!["status", "extra"],
                vec!["--path", "/tmp/other"],
                vec!["retry-app-retirement", "extra"],
                vec!["retry-app-retirement", "/tmp/other"],
                vec!["picoclaw-home", "extra"],
                vec!["picoclaw-home-check", "extra"],
                vec!["picoclaw-control-ready", "extra"],
                vec!["picoclaw-control-ready", "/tmp/other"],
                vec!["ensure-picoclaw", "extra"],
                vec!["ensure-picoclaw", "/tmp/other"],
                vec!["picoclaw-running", "extra"],
                vec!["picoclaw-running", "/tmp/other"],
                vec!["stop-picoclaw", "extra"],
                vec!["stop-picoclaw", "/tmp/other"],
                vec!["picoclaw-stopped", "extra"],
                vec!["picoclaw-stopped", "/tmp/other"],
                vec!["onboard-picoclaw", "extra"],
                vec!["onboard-picoclaw", "/tmp/other"],
                // The older onboarding completion query no longer exists.
                vec!["picoclaw-onboard-complete"],
                vec!["picoclaw-onboard-complete", "extra"],
                vec!["picoclaw-onboard-complete", "/tmp/other"],
            ],
        ),
        (
            env!("CARGO_BIN_EXE_nanokvm-native-recovery"),
            vec![
                vec![],
                vec!["reset"],
                vec!["--force"],
                vec!["complete", "extra"],
                vec!["--path", "/tmp/other"],
            ],
        ),
    ] {
        for args in cases {
            let status = Command::new(binary)
                .args(args)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(64));
        }
    }
}

#[test]
fn the_raw_writer_mode_refuses_outside_the_brokers_sealed_memory_copy() {
    // Well-formed, but a test process is neither root nor a sealed memfd: the
    // writer refuses before reading its inputs or touching the system.
    let transaction = "07".repeat(16);
    let (boot, rootfs) = ("01".repeat(32), "ab".repeat(32));
    let status = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-broker"))
        .args([
            "--raw-writer",
            "--transaction",
            transaction.as_str(),
            "--version",
            "0.3.0-raw.13",
            "--boot-size",
            "1025",
            "--rootfs-size",
            "65537",
            "--boot-sha256",
            boot.as_str(),
            "--rootfs-sha256",
            rootfs.as_str(),
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(65));
}
