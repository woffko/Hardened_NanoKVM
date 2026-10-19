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
