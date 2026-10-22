use super::*;
use serde_json::json;

fn yaml(text: &str) -> serde_yaml::Value {
    serde_yaml::from_str(text).unwrap()
}

#[test]
fn model_name_is_the_last_identifier_segment() {
    assert_eq!(model_name("openai/gpt-4.1").as_deref(), Some("gpt-4.1"));
    assert_eq!(model_name(" vendor/sub/name ").as_deref(), Some("name"));
    assert_eq!(model_name("gpt-4.1").as_deref(), Some("gpt-4.1"));
    assert_eq!(model_name("   "), None);
}

#[test]
fn apply_updates_the_matching_entry_in_place_and_keeps_custom_fields() {
    let mut config = json!({
        "custom": {"keep": true},
        "agents": {"defaults": {"custom": "retained", "model": "legacy"}},
        "model_list": [{
            "model_name": "chosen",
            "model": "old/chosen",
            "api_base": "https://old.invalid",
            "api_key": "synthetic-legacy",
            "api_keys": ["synthetic-legacy"],
            "custom": "retained"
        }]
    });
    let mut security = yaml("custom: retained\nmodel_list: {}\n");
    let name = apply(
        &mut config,
        &mut security,
        "new/chosen",
        "https://new.invalid/v1",
        "synthetic-new-key",
    )
    .unwrap();
    assert_eq!(name, "chosen");
    assert_eq!(config["custom"], json!({"keep": true}));
    assert_eq!(config["agents"]["defaults"]["custom"], "retained");
    assert_eq!(config["agents"]["defaults"]["model_name"], "chosen");
    assert!(config["agents"]["defaults"].get("model").is_none());
    let entry = &config["model_list"][0];
    assert_eq!(entry["custom"], "retained");
    assert_eq!(entry["model"], "new/chosen");
    assert_eq!(entry["api_base"], "https://new.invalid/v1");
    // The key lives only in the security document.
    assert!(entry.get("api_key").is_none() && entry.get("api_keys").is_none());
    assert_eq!(security["custom"].as_str(), Some("retained"));
    assert_eq!(
        security["model_list"]["chosen:0"]["api_keys"][0].as_str(),
        Some("synthetic-new-key")
    );
}

#[test]
fn apply_appends_a_new_model_and_is_a_fixed_point() {
    let mut config = json!({"model_list": [{"model_name": "first", "model": "a/first"}]});
    let mut security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let args = ("b/second", "https://second.invalid", "synthetic-second-key");
    assert_eq!(
        apply(&mut config, &mut security, args.0, args.1, args.2).unwrap(),
        "second"
    );
    let (once_config, once_security) = (config.clone(), security.clone());
    apply(&mut config, &mut security, args.0, args.1, args.2).unwrap();
    assert_eq!(config, once_config);
    assert_eq!(security, once_security);
    assert_eq!(config["model_list"][0]["model_name"], "first");
    assert_eq!(config["model_list"][1]["model_name"], "second");
    assert_eq!(
        security["model_list"]["second:1"]["api_keys"][0].as_str(),
        Some("synthetic-second-key")
    );
}

#[test]
fn apply_refuses_an_empty_identifier_or_a_non_object_root_unchanged() {
    for (config, model) in [(json!({}), "  "), (json!([]), "a/b"), (json!("x"), "a/b")] {
        let mut changed = config.clone();
        let mut security = yaml("kept: true\n");
        assert!(apply(&mut changed, &mut security, model, "https://x.invalid", "k").is_err());
        assert_eq!(changed, config);
        assert_eq!(security, yaml("kept: true\n"));
    }
}
