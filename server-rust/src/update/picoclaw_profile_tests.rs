use super::*;
use serde_json::json;

#[test]
fn only_an_absent_or_exact_shipped_profile_is_replaced() {
    let default = b"name: pico\n".as_slice();
    let kvm = b"name: pico-kvm\n".as_slice();
    let shipped = [default, kvm];
    assert_eq!(classify(Some(kvm), kvm, shipped), Decision::Noop);
    assert_eq!(classify(None, kvm, shipped), Decision::Replace);
    assert_eq!(classify(Some(default), kvm, shipped), Decision::Replace);
    for custom in [
        b"name: pico\nmy own notes\n".as_slice(),
        b"".as_slice(),
        b"name: pico-kvm".as_slice(),
    ] {
        assert_eq!(classify(Some(custom), kvm, shipped), Decision::Custom);
    }
    assert_eq!(shipped_name(false), "AGENT.md");
    assert_eq!(shipped_name(true), "AGENT_KVM.md");
}

#[test]
fn a_startup_job_never_changes_a_profile_that_stands() {
    assert!(settles(None));
    assert!(!settles(Some(SHIPPED_AGENT)));
    assert!(!settles(Some(b"my own notes\n")));
    assert!(!settles(Some(b"")));
    // The superseded list holds this document, the one last shipped as KVM.
    assert!(settles(Some(SHIPPED_AGENT_KVM)));
}

#[test]
fn the_workspace_follows_the_config_or_defaults_below_home() {
    let home = Path::new("/root/.picoclaw");
    assert_eq!(
        workspace(&json!({}), home),
        Some(PathBuf::from("/root/.picoclaw/workspace"))
    );
    for (selected, expected) in [
        ("~", "/root"),
        ("~/work", "/root/work"),
        ("/srv/pico", "/srv/pico"),
        ("  /srv/pico  ", "/srv/pico"),
    ] {
        let config = json!({"agents": {"defaults": {"workspace": selected}}});
        assert_eq!(workspace(&config, home), Some(PathBuf::from(expected)));
    }
    // An empty selection falls back below Home; a relative one has no fixed
    // meaning for the broker.
    let empty = json!({"agents": {"defaults": {"workspace": " "}}});
    assert_eq!(
        workspace(&empty, home),
        Some(PathBuf::from("/root/.picoclaw/workspace"))
    );
    let relative = json!({"agents": {"defaults": {"workspace": "work"}}});
    assert_eq!(workspace(&relative, home), None);
}
