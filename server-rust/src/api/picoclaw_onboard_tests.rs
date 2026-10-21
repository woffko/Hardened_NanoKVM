use super::*;
use crate::update::{picoclaw_config::Onboarding, state_writers::ConfigPermit};

#[test]
fn completed_fresh_onboard_imports_defaults_and_kvm_fallback_without_overwriting_user_data() {
    run_private_root("onboard-import");
}

#[test]
fn onboard_rejects_a_workspace_symlink_before_publishing_credentials() {
    run_private_root("onboard-destination-link");
}

#[test]
fn onboard_preserves_a_custom_generated_profile_and_refuses_implicit_replacement() {
    run_private_root("onboard-profile-collision");
    run_private_root("onboard-nested-collision");
}

#[test]
fn onboard_never_reads_symlink_or_hardlinked_scratch_payloads() {
    run_private_root("onboard-source-links");
}

#[test]
fn onboard_refuses_an_unexpected_upstream_workspace_or_unknown_scratch_member() {
    run_private_root("onboard-shape");
}

#[test]
fn onboard_orphans_and_dangling_security_are_preserved_not_adopted() {
    run_private_root("onboard-orphan");
}

#[test]
fn onboard_existing_legacy_pair_is_a_noop_including_valid_yaml_null() {
    run_private_root("onboard-existing");
}

#[test]
fn onboard_enforces_depth_and_global_entry_bounds_including_empty_directories() {
    run_private_root("onboard-bounds");
}

fn output(home: &Path) -> PathBuf {
    home.join(crate::native_owner::picoclaw_home::ONBOARD_DIRECTORY)
}

fn populate(home: &Path) {
    let stage = output(home);
    fs::create_dir_all(stage.join("workspace/memory")).unwrap();
    put_private(&stage.join("config.json"), &serde_json::to_vec(&json!({
        "agents":{"defaults":{"workspace":stage.join("workspace"),"restrict_to_workspace":false}},
        "model_list":[], "custom_default": {"keep": true}
    })).unwrap());
    put_private(&stage.join(".security.yml"), b"model_list: []\n");
    put_private(&stage.join("workspace/SOUL.md"), b"upstream default");
    put_private(
        &stage.join("workspace/memory/README.md"),
        b"memory template",
    );
}

pub(super) fn exercise(case: &str, permit: &ConfigPermit, home: &Path) {
    let config = home.join("config.json");
    if case == "onboard-existing" {
        put_private(&config, b"{ \"custom\": true }\n");
        put_private(&home.join(".security.yml"), b"null\n");
        let before = [
            fs::metadata(&config).unwrap().ino(),
            fs::metadata(home.join(".security.yml")).unwrap().ino(),
        ];
        assert!(Onboarding::prepare(permit, &config).unwrap().is_none());
        assert_eq!(
            before,
            [
                fs::metadata(&config).unwrap().ino(),
                fs::metadata(home.join(".security.yml")).unwrap().ino()
            ]
        );
        assert_eq!(fs::read(&config).unwrap(), b"{ \"custom\": true }\n");
        assert_eq!(fs::read(home.join(".security.yml")).unwrap(), b"null\n");
        assert!(!output(home).exists());
        return;
    }
    if case == "onboard-orphan" {
        fs::create_dir(output(home)).unwrap();
        put_private(&output(home).join("evidence"), b"do not adopt or delete");
        assert!(Onboarding::prepare(permit, &config).is_err());
        assert_eq!(
            fs::read(output(home).join("evidence")).unwrap(),
            b"do not adopt or delete"
        );
        fs::remove_file(output(home).join("evidence")).unwrap();
        fs::remove_dir(output(home)).unwrap();
        put_private(&home.join(".security.yml"), b"orphan: preserve\n");
        assert!(Onboarding::prepare(permit, &config).is_err());
        assert!(!output(home).exists());
        return;
    }
    if case == "onboard-source-links" || case == "onboard-shape" || case == "onboard-bounds" {
        for index in 0..2 {
            let selected = home.join(format!("case{index}"));
            let config = selected.join("config.json");
            let stage = Onboarding::prepare(permit, &config).unwrap().unwrap();
            populate(&selected);
            if case == "onboard-source-links" {
                fs::remove_file(output(&selected).join("workspace/SOUL.md")).unwrap();
                if index == 0 {
                    std::os::unix::fs::symlink(
                        "/outside/synthetic-sentinel",
                        output(&selected).join("workspace/SOUL.md"),
                    )
                    .unwrap();
                } else {
                    fs::hard_link(
                        "/outside/synthetic-sentinel",
                        output(&selected).join("workspace/SOUL.md"),
                    )
                    .unwrap();
                }
            } else if case == "onboard-bounds" {
                if index == 0 {
                    fs::create_dir_all(
                        output(&selected).join("workspace").join(
                            std::iter::repeat_n("deep", 15)
                                .collect::<Vec<_>>()
                                .join("/"),
                        ),
                    )
                    .unwrap();
                } else {
                    for first in 0..20 {
                        for second in 0..20 {
                            fs::create_dir_all(
                                output(&selected).join(format!("workspace/d{first}/d{second}")),
                            )
                            .unwrap();
                        }
                    }
                }
            } else if index == 0 {
                put_private(
                    &output(&selected).join("config.json"),
                    br#"{"agents":{"defaults":{"workspace":"/outside"}}}"#,
                );
            } else {
                put_private(&output(&selected).join("unexpected"), b"unknown preserved");
            }
            assert!(stage.finish(permit).is_err());
            assert!(!config.exists());
            assert!(!selected.join("workspace").exists());
        }
        assert_eq!(
            fs::read("/outside/synthetic-sentinel").unwrap(),
            b"synthetic-sentinel-unchanged"
        );
        return;
    }
    let stage = Onboarding::prepare(permit, &config).unwrap().unwrap();
    assert_eq!(fs::metadata(output(home)).unwrap().mode() & 0o777, 0o700);
    populate(home);
    match case {
        "onboard-destination-link" => {
            std::os::unix::fs::symlink("/outside", home.join("workspace")).unwrap();
            assert!(stage.finish(permit).is_err());
            assert!(!config.exists());
            assert!(!Path::new("/outside/AGENT.md").exists());
        }
        "onboard-profile-collision" | "onboard-nested-collision" => {
            let relative = if case == "onboard-profile-collision" {
                "workspace/AGENT.md"
            } else {
                "workspace/skills/kvm-control/SKILL.md"
            };
            fs::create_dir_all(home.join(relative).parent().unwrap()).unwrap();
            put_private(&home.join(relative), b"custom profile");
            assert!(stage.finish(permit).is_err());
            assert_eq!(fs::read(home.join(relative)).unwrap(), b"custom profile");
            assert!(!home.join("workspace/SOUL.md").exists());
            assert!(!home.join("workspace/memory").exists());
            assert!(!home.join("workspace/skills/kvm-control/scripts").exists());
            assert!(!config.exists());
        }
        "onboard-import" => {
            fs::create_dir_all(home.join("workspace/memory")).unwrap();
            put_private(
                &home.join("workspace/SOUL.md"),
                b"user personality, never reset",
            );
            put_private(&home.join("workspace/memory/notes"), b"user notes");
            let inode = fs::metadata(home.join("workspace/SOUL.md")).unwrap().ino();
            stage.finish(permit).unwrap();
            assert_eq!(
                fs::metadata(home.join("workspace/SOUL.md")).unwrap().ino(),
                inode
            );
            assert_eq!(
                fs::read(home.join("workspace/SOUL.md")).unwrap(),
                b"user personality, never reset"
            );
            assert_eq!(
                fs::read(home.join("workspace/memory/notes")).unwrap(),
                b"user notes"
            );
            assert_eq!(
                fs::read(home.join("workspace/memory/README.md")).unwrap(),
                b"memory template"
            );
            assert_eq!(
                fs::read(home.join("workspace/AGENT.md")).unwrap(),
                include_bytes!("../../../kvmapp/picoclaw/AGENT_KVM.md")
            );
            let bridge = home.join("workspace/skills/kvm-control/scripts/nanokvm-bridge.sh");
            assert_eq!(
                fs::read(&bridge).unwrap(),
                include_bytes!(
                    "../../../kvmapp/picoclaw/skills/kvm-control/scripts/nanokvm-bridge.sh"
                )
            );
            assert_eq!(fs::metadata(&bridge).unwrap().mode() & 0o777, 0o700);
            let document = load_config_document_at(config.clone()).unwrap();
            assert_eq!(
                document.raw["agents"]["defaults"]["workspace"],
                home.join("workspace").to_str().unwrap()
            );
            assert_eq!(
                document.raw["agents"]["defaults"]["restrict_to_workspace"],
                true
            );
            assert_eq!(
                document.raw["agents"]["defaults"]["allow_read_outside_workspace"],
                false
            );
            assert_eq!(document.raw["custom_default"]["keep"], true);
            let inode = fs::metadata(&config).unwrap().ino();
            assert!(Onboarding::prepare(permit, &config).unwrap().is_none());
            assert_eq!(fs::metadata(&config).unwrap().ino(), inode);
        }
        _ => panic!("unknown onboard fixture"),
    }
}
