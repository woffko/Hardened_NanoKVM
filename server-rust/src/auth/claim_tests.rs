use super::*;

#[test]
fn a_first_boot_token_is_private_one_time_and_checked_before_setup() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let account = root.path().join("pwd");
    let token = ensure(&account).unwrap().unwrap();
    assert_eq!(token.len(), 12);
    let file = path(&account);
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
    check(&account, &token).unwrap();
    assert!(check(&account, "wrong-token").is_err());
    consume(&account).unwrap();
    assert!(!file.exists());
    assert!(check(&account, &token).is_err());
}

#[test]
fn an_initialized_account_removes_the_stale_claim() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let account = root.path().join("pwd");
    ensure(&account).unwrap().unwrap();
    fs::write(&account, b"synthetic account").unwrap();
    assert!(ensure(&account).unwrap().is_none());
    assert!(!path(&account).exists());
}

#[test]
fn an_unsafe_claim_file_is_refused() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let account = root.path().join("pwd");
    let file = path(&account);
    fs::write(&file, b"synthetic-token\n").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ensure(&account).is_err());
}
