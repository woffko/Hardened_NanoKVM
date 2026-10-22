use super::*;
use serde_json::json;

fn yaml(text: &str) -> serde_yaml::Value {
    serde_yaml::from_str(text).unwrap()
}

#[test]
fn apply_is_a_pure_fixed_point_that_preserves_unrelated_and_custom_fields() {
    let mut config = json!({
        "agents": {"defaults": {"restrict_to_workspace": false, "model": "custom"}},
        "gateway": {"host": "0.0.0.0", "port": 1, "extra": true},
        "channel_list": {"pico": {"settings": {"allow_token_query": true, "kept": 7}}},
        "unrelated": [1, 2, 3]
    });
    let mut security = yaml("model_list:\n  m:0:\n    api_keys: [secret]\n");
    apply(
        &mut config,
        &mut security,
        "gateway-token",
        "internal-token",
    )
    .unwrap();
    let (once_config, once_security) = (config.clone(), security.clone());
    apply(
        &mut config,
        &mut security,
        "gateway-token",
        "internal-token",
    )
    .unwrap();
    assert_eq!(config, once_config);
    assert_eq!(security, once_security);

    // Explicit custom local-tool choice and unrelated fields survive.
    assert_eq!(config["agents"]["defaults"]["restrict_to_workspace"], false);
    assert_eq!(
        config["agents"]["defaults"]["allow_read_outside_workspace"],
        false
    );
    assert_eq!(config["agents"]["defaults"]["model"], "custom");
    assert_eq!(config["unrelated"], json!([1, 2, 3]));
    assert_eq!(config["gateway"]["extra"], true);
    assert_eq!(config["channel_list"]["pico"]["settings"]["kept"], 7);
    // Fixed values are enforced.
    assert_eq!(config["gateway"]["host"], GATEWAY_HOST);
    assert_eq!(config["gateway"]["port"], GATEWAY_PORT);
    assert_eq!(
        config["channel_list"]["pico"]["settings"]["allow_token_query"],
        false
    );
    assert_eq!(
        config["channel_list"]["pico"]["settings"]["read_timeout"],
        60
    );
    assert_eq!(
        config["tools"]["mcp"]["servers"]["nanokvm"]["headers"][INTERNAL_TOKEN_HEADER],
        "internal-token"
    );
    assert_eq!(
        security["channel_list"]["pico"]["settings"]["token"].as_str(),
        Some("gateway-token")
    );
    assert!(security["model_list"]["m:0"]["api_keys"].is_sequence());
}

#[test]
fn absent_local_defaults_become_restrictive_and_tokens_are_caller_supplied() {
    let mut config = json!({});
    let mut security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    apply(&mut config, &mut security, "g", "i").unwrap();
    assert_eq!(config["agents"]["defaults"]["restrict_to_workspace"], true);
    assert_eq!(
        config["agents"]["defaults"]["allow_read_outside_workspace"],
        false
    );
    // The same inputs give the same documents: no hidden entropy.
    let mut again = json!({});
    let mut again_security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    apply(&mut again, &mut again_security, "g", "i").unwrap();
    assert_eq!(config, again);
    assert_eq!(security, again_security);
}

#[test]
fn malformed_policy_or_root_is_refused_before_any_change() {
    for value in [
        json!({"agents": []}),
        json!({"agents": {"defaults": "x"}}),
        json!({"agents": {"defaults": {"restrict_to_workspace": "yes"}}}),
        json!({"agents": {"defaults": {"allow_read_outside_workspace": 1}}}),
        json!([]),
        json!("text"),
    ] {
        let mut config = value.clone();
        let mut security = yaml("kept: true\n");
        assert!(apply(&mut config, &mut security, "g", "i").is_err());
        assert_eq!(config, value);
        assert_eq!(security, yaml("kept: true\n"));
    }
}

#[test]
fn gateway_token_preference_and_absence() {
    let config = json!({"channel_list": {"pico": {"settings": {"token": " config "}}}});
    let settings =
        yaml("channel_list:\n  pico:\n    settings:\n      token: settings\n    token: legacy\n");
    let legacy = yaml("channel_list:\n  pico:\n    token: legacy\n");
    assert_eq!(
        existing_gateway_token(&config, &settings).as_deref(),
        Some("settings")
    );
    assert_eq!(
        existing_gateway_token(&config, &legacy).as_deref(),
        Some("legacy")
    );
    assert_eq!(
        existing_gateway_token(&config, &serde_yaml::Value::Null).as_deref(),
        Some("config")
    );
    let blank = yaml("channel_list:\n  pico:\n    settings:\n      token: '  '\n");
    assert_eq!(existing_gateway_token(&json!({}), &blank), None);
    assert_eq!(
        existing_gateway_token(&json!({}), &serde_yaml::Value::Null),
        None
    );
}

#[test]
fn non_mapping_security_shapes_are_replaced_only_on_the_token_path() {
    let mut config = json!({});
    let mut security = yaml("channel_list: 5\nother: kept\n");
    apply(&mut config, &mut security, "g", "i").unwrap();
    assert_eq!(security["other"].as_str(), Some("kept"));
    assert_eq!(
        security["channel_list"]["pico"]["settings"]["token"].as_str(),
        Some("g")
    );
    let mut scalar = serde_yaml::Value::String("scalar".into());
    apply(&mut json!({}), &mut scalar, "g", "i").unwrap();
    assert_eq!(
        scalar["channel_list"]["pico"]["settings"]["token"].as_str(),
        Some("g")
    );
}
