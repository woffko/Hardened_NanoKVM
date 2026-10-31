use super::*;
use std::{os::unix::fs::PermissionsExt, sync::mpsc, time::Duration};

const TOKEN: &str = "synthetic-token";

struct Fixture {
    root: tempfile::TempDir,
    console: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let console = root.path().join("console");
        fs::write(&console, b"").unwrap();
        Self { root, console }
    }
    fn account(&self) -> PathBuf {
        self.root.path().join("pwd")
    }
    fn ensure(&self, moment: &Moment) -> Option<String> {
        ensure_at(&self.account(), moment, &self.console).unwrap()
    }
}

fn moment(boot: &str, seconds: u64) -> Moment {
    Moment {
        boot: boot.to_string(),
        seconds,
    }
}

#[test]
fn a_first_boot_token_is_private_one_time_and_checked_before_setup() {
    let fixture = Fixture::new();
    let account = fixture.account();
    let token = fixture.ensure(&now().unwrap()).unwrap();
    assert_eq!(token.len(), 12);
    let file = path(&account);
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
    check(&account, &token).unwrap();
    assert!(check(&account, "wrong-token").is_err());
    assert!(check(&account, &token[..11]).is_err());
    consume(&account).unwrap();
    assert!(!file.exists());
    assert!(check(&account, &token).is_err());
}

#[test]
fn a_restart_of_the_backend_keeps_the_token_and_shows_it_again() {
    let fixture = Fixture::new();
    let first = fixture.ensure(&moment("boot-a", 100)).unwrap();
    let second = fixture.ensure(&moment("boot-a", 200)).unwrap();
    assert_eq!(first, second);
    let shown = fs::read_to_string(&fixture.console).unwrap();
    assert_eq!(shown.matches(first.as_str()).count(), 2);
}

#[test]
fn a_token_ends_with_its_boot_or_a_day_of_uptime_whatever_the_wall_clock_says() {
    let fixture = Fixture::new();
    let account = fixture.account();
    let token = fixture.ensure(&moment("boot-a", 100)).unwrap();
    let file = path(&account);
    assert!(
        read(&file, &moment("boot-a", 100 + TTL_SECONDS))
            .unwrap()
            .is_some()
    );
    assert!(
        read(&file, &moment("boot-a", 101 + TTL_SECONDS))
            .unwrap()
            .is_none()
    );
    assert!(read(&file, &moment("boot-b", 100)).unwrap().is_none());
    assert_ne!(fixture.ensure(&moment("boot-b", 5)).unwrap(), token);
}

#[test]
fn anything_in_the_way_is_replaced_and_the_backend_goes_on() {
    for (bytes, mode) in [
        (format!("{TOKEN}\nboot-a 1\n"), 0o644),
        (format!("{TOKEN}\n"), 0o600),
        ("short\nboot-a 1\n".to_string(), 0o600),
        (format!("{TOKEN}\nboot-a many\n"), 0o600),
        ("x".repeat(MAX as usize + 1), 0o600),
    ] {
        let fixture = Fixture::new();
        let file = path(&fixture.account());
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
        assert!(read(&file, &moment("boot-a", 1)).is_err());
        let token = fixture.ensure(&moment("boot-a", 1)).unwrap();
        assert_ne!(token, TOKEN);
        assert_eq!(read(&file, &moment("boot-a", 1)).unwrap(), Some(token));
    }
}

#[test]
fn a_link_in_place_of_the_file_is_replaced_not_followed() {
    let fixture = Fixture::new();
    let elsewhere = fixture.root.path().join("elsewhere");
    fs::write(&elsewhere, format!("{TOKEN}\nboot-a 1\n")).unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).unwrap();
    let file = path(&fixture.account());
    std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
    assert!(read(&file, &moment("boot-a", 1)).is_err());
    assert_ne!(fixture.ensure(&moment("boot-a", 1)).unwrap(), TOKEN);
    assert!(fs::symlink_metadata(&file).unwrap().is_file());
    assert!(fs::read_to_string(&elsewhere).unwrap().starts_with(TOKEN));
}

#[test]
fn a_console_that_nobody_reads_does_not_hold_up_the_backend() {
    let fixture = Fixture::new();
    nix::unistd::mkfifo(
        &fixture.root.path().join("port"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let account = fixture.account();
    let port = fixture.root.path().join("port");
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(ensure_at(&account, &moment("boot-a", 1), &port).is_ok());
    });
    assert_eq!(finished.recv_timeout(Duration::from_secs(5)), Ok(true));
}

#[test]
fn a_console_that_is_missing_leaves_the_token_in_its_file() {
    let fixture = Fixture::new();
    fs::remove_file(&fixture.console).unwrap();
    let token = fixture.ensure(&moment("boot-a", 1)).unwrap();
    assert_eq!(
        read(&path(&fixture.account()), &moment("boot-a", 1)).unwrap(),
        Some(token)
    );
}

#[test]
fn an_initialized_account_removes_the_stale_claim() {
    let fixture = Fixture::new();
    let account = fixture.account();
    fixture.ensure(&moment("boot-a", 1)).unwrap();
    fs::write(&account, b"synthetic account").unwrap();
    assert!(fixture.ensure(&moment("boot-a", 2)).is_none());
    assert!(!path(&account).exists());
}

#[test]
fn the_token_stays_out_of_the_kernel_log() {
    assert_eq!(CONSOLE, "/dev/console");
}
