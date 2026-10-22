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

fn canonical_pair(gateway: &str, internal: &str) -> (Vec<u8>, Vec<u8>) {
    let mut config = json!({"agents": {"defaults": {"model": "m"}}});
    let mut security = yaml("model_list:\n  m:0:\n    api_keys: [secret]\n");
    apply(&mut config, &mut security, gateway, internal).unwrap();
    let encoded = encode(&config, &security).unwrap();
    (
        encoded.config.to_vec(),
        encoded.security.as_bytes().to_vec(),
    )
}

#[test]
fn canonical_defaults_with_both_tokens_are_a_noop_even_with_other_formatting() {
    let (config, security) = canonical_pair("gateway", "internal");
    let documents = decode(&config, Some(&security)).unwrap();
    assert_eq!(
        classify(&documents, Some("internal")).unwrap(),
        Decision::Noop
    );
    // Same values, different on-disk formatting: still a no-op, nothing to
    // publish, so original bytes/comments are kept.
    let compact = serde_json::to_vec(&documents.config).unwrap();
    let commented = format!("# kept comment\n{}", String::from_utf8(security).unwrap());
    let reformatted = decode(&compact, Some(commented.as_bytes())).unwrap();
    assert_eq!(
        classify(&reformatted, Some("internal")).unwrap(),
        Decision::Noop
    );
}

#[test]
fn missing_or_different_tokens_and_values_are_a_change_without_inventing_tokens() {
    let (config, security) = canonical_pair("gateway", "internal");
    let documents = decode(&config, Some(&security)).unwrap();
    assert_eq!(
        classify(&documents, None).unwrap(),
        Decision::Change {
            gateway_token: false,
            internal_token: true
        }
    );
    assert_eq!(
        classify(&documents, Some("rotated")).unwrap(),
        Decision::Change {
            gateway_token: false,
            internal_token: false
        }
    );
    let bare = decode(b"{}", None).unwrap();
    assert_eq!(
        classify(&bare, Some("internal")).unwrap(),
        Decision::Change {
            gateway_token: true,
            internal_token: false
        }
    );
    // A changed default (gateway port) is a value change, not a no-op.
    let mut drifted = decode(&config, Some(&security)).unwrap();
    drifted.config["gateway"]["port"] = json!(1);
    assert_eq!(
        classify(&drifted, Some("internal")).unwrap(),
        Decision::Change {
            gateway_token: false,
            internal_token: false
        }
    );
    // desired() never modifies its input documents.
    let before = encode(&drifted.config, &drifted.security).unwrap();
    let wanted = desired(&drifted, "gateway", "internal").unwrap();
    assert!(wanted != before);
    assert!(encode(&drifted.config, &drifted.security).unwrap() == before);
    assert!(wanted == encode(&documents.config, &documents.security).unwrap());
}

#[test]
fn decoding_requires_config_json_and_treats_absent_security_as_empty() {
    assert!(decode(b"not json", None).is_err());
    assert!(decode(b"{}", Some(b": : not yaml")).is_err());
    let documents = decode(b"{}", None).unwrap();
    assert_eq!(
        documents.security,
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    );
    assert!(classify(&decode(br#"{"agents": []}"#, None).unwrap(), Some("i")).is_err());
}

#[test]
fn a_request_change_is_a_noop_only_when_the_source_already_equals_its_target() {
    let mut config = json!({"agents": {"defaults": {}}});
    let mut security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    apply(&mut config, &mut security, "gateway", "internal").unwrap();
    let source = Documents {
        config: config.clone(),
        security: security.clone(),
    };
    let mut target = Documents { config, security };
    crate::update::picoclaw_model::apply(
        &mut target.config,
        &mut target.security,
        "vendor/model",
        "https://model.invalid",
        "synthetic-key",
    )
    .unwrap();
    // The defaults are canonical, but the requested model is not selected yet.
    assert_eq!(
        classify_change(&source, &target, Some("internal")).unwrap(),
        Decision::Change {
            gateway_token: false,
            internal_token: false,
        }
    );
    // Once the source equals its target, the same request is a no-op.
    let selected = Documents {
        config: target.config.clone(),
        security: target.security.clone(),
    };
    assert_eq!(
        classify_change(&selected, &target, Some("internal")).unwrap(),
        Decision::Noop
    );
    // The target's local policy is checked, not only the source's.
    let mut broken = Documents {
        config: target.config.clone(),
        security: target.security.clone(),
    };
    broken.config["agents"]["defaults"]["restrict_to_workspace"] = json!("no");
    assert!(classify_change(&selected, &broken, Some("internal")).is_err());
}
