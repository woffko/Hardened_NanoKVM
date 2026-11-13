use super::*;
use serde_json::json;

const HOME: &str = "/root/.picoclaw";

fn home() -> &'static Path {
    Path::new(HOME)
}

// The pair RC12 forced on every start, with upstream's own tool defaults
// spelled out and one configuration of each other kind.
fn legacy() -> JsonValue {
    json!({
        "agents": {
            "defaults": {
                "restrict_to_workspace": false,
                "allow_read_outside_workspace": true,
                "model": "custom"
            }
        },
        "tools": {
            "exec": {"enabled": true, "custom_allow_patterns": ["^ls"]},
            "cron": {"enabled": true, "allow_command": true},
            "i2c": {"enabled": true},
            "allow_read_paths": ["^/"],
            "allow_write_paths": ["^/etc"],
            "web": {"enabled": true},
            "mcp": {
                "enabled": true,
                "servers": {
                    "nanokvm": {"enabled": true, "type": "http", "url": "http://127.0.0.1:80/api/picoclaw/mcp"},
                    "shell": {"enabled": true, "command": "/bin/sh", "args": ["-c", "id"]},
                    "stdio": {"enabled": true, "type": "stdio"},
                    "remote": {"enabled": true, "type": "sse", "url": "https://mcp.invalid/sse"}
                }
            }
        },
        "channel_list": {"pico": {"enabled": true}}
    })
}

#[test]
fn enforcement_closes_every_local_tool_and_keeps_remote_and_unrelated_settings() {
    let mut config = legacy();
    assert!(
        check(&config, home()).is_err(),
        "the RC12 pair is not launchable"
    );
    enforce(&mut config, home()).unwrap();
    let defaults = &config["agents"]["defaults"];
    assert_eq!(defaults["restrict_to_workspace"], true);
    assert_eq!(defaults["allow_read_outside_workspace"], false);
    assert_eq!(defaults["workspace"], "/root/.picoclaw/workspace");
    assert_eq!(defaults["model"], "custom");
    let tools = &config["tools"];
    for name in ["exec", "serial", "spi", "i2c"] {
        assert_eq!(tools[name]["enabled"], false, "{name}");
    }
    assert_eq!(tools["exec"]["custom_allow_patterns"], json!(["^ls"]));
    assert_eq!(tools["cron"]["enabled"], true, "scheduled prompts stay");
    assert_eq!(tools["cron"]["allow_command"], false);
    assert_eq!(tools["allow_read_paths"], json!([]));
    assert_eq!(tools["allow_write_paths"], json!([]));
    assert_eq!(tools["web"]["enabled"], true);
    let servers = &tools["mcp"]["servers"];
    assert_eq!(servers["nanokvm"]["enabled"], true);
    assert_eq!(servers["shell"]["enabled"], false);
    assert_eq!(servers["shell"]["args"], json!(["-c", "id"]));
    assert_eq!(servers["stdio"]["enabled"], false);
    assert_eq!(servers["remote"]["enabled"], true);
    assert_eq!(config["channel_list"], json!({"pico": {"enabled": true}}));
    check(&config, home()).unwrap();
    let again = config.clone();
    enforce(&mut config, home()).unwrap();
    assert_eq!(config, again, "enforcement is a fixed point");
}

#[test]
fn absent_keys_are_created_and_only_an_enforced_pair_is_launchable() {
    let mut config = json!({});
    assert!(check(&config, home()).is_err());
    enforce(&mut config, home()).unwrap();
    check(&config, home()).unwrap();
    assert_eq!(config["tools"]["exec"]["enabled"], false);
    assert_eq!(
        config["agents"]["defaults"]["workspace"],
        "/root/.picoclaw/workspace"
    );
    for (pointer, value) in [
        ("/agents/defaults/restrict_to_workspace", json!(false)),
        ("/agents/defaults/allow_read_outside_workspace", json!(true)),
        ("/tools/exec/enabled", json!(true)),
        ("/tools/spi/enabled", json!(true)),
        ("/tools/cron/allow_command", json!(true)),
    ] {
        let mut changed = config.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(check(&changed, home()).is_err(), "{pointer}");
    }
    for (key, value) in [
        ("allow_read_paths", json!(["^/root"])),
        ("allow_write_paths", json!(["^/tmp"])),
    ] {
        let mut changed = config.clone();
        changed["tools"][key] = value;
        assert!(check(&changed, home()).is_err(), "{key}");
    }
    let mut empty = config.clone();
    empty["tools"]["allow_read_paths"] = json!([]);
    check(&empty, home()).unwrap();
    let mut local = config.clone();
    local["tools"]["mcp"] = json!({"servers": {"local": {"command": "/bin/sh"}}});
    assert!(check(&local, home()).is_err(), "a local command server");
    local["tools"]["mcp"]["servers"]["local"]["enabled"] = json!(false);
    check(&local, home()).unwrap();
}

#[test]
fn every_workspace_stays_inside_the_home_workspace() {
    for inside in [
        "/root/.picoclaw/workspace",
        "/root/.picoclaw/workspace/",
        "/root/.picoclaw/workspace/agents/a",
        "/root/.picoclaw/./workspace/x",
    ] {
        let config = json!({
            "agents": {
                "defaults": {"workspace": inside},
                "list": [{"id": "a", "workspace": inside}, {"id": "b"}]
            }
        });
        validate(&config, home()).unwrap();
    }
    for outside in [
        "/",
        "/root/.picoclaw",
        "/root/.picoclaw/config.json",
        "/root/.picoclaw/.security.yml",
        "/root/.picoclaw/workspace/../config.json",
        "/root/.picoclaw/workspace2",
        "/etc/kvm",
        "workspace",
        "",
    ] {
        for config in [
            json!({"agents": {"defaults": {"workspace": outside}}}),
            json!({"agents": {"list": [{"id": "a", "workspace": outside}]}}),
        ] {
            let mut changed = config.clone();
            assert!(enforce(&mut changed, home()).is_err(), "{outside}");
            assert_eq!(changed, config, "nothing changes before a refusal");
        }
    }
}

#[test]
fn malformed_policy_shapes_refuse_before_any_change() {
    for config in [
        json!([]),
        json!({"agents": []}),
        json!({"agents": {"defaults": "x"}}),
        json!({"agents": {"defaults": {"restrict_to_workspace": "true"}}}),
        json!({"agents": {"defaults": {"allow_read_outside_workspace": null}}}),
        json!({"agents": {"defaults": {"workspace": 1}}}),
        json!({"agents": {"list": {}}}),
        json!({"agents": {"list": ["a"]}}),
        json!({"agents": {"list": [{"workspace": false}]}}),
        json!({"tools": []}),
        json!({"tools": {"exec": true}}),
        json!({"tools": {"exec": {"enabled": "no"}}}),
        json!({"tools": {"i2c": {"enabled": 0}}}),
        json!({"tools": {"cron": {"allow_command": "yes"}}}),
        json!({"tools": {"allow_read_paths": "^/"}}),
        json!({"tools": {"allow_write_paths": {}}}),
        json!({"tools": {"mcp": []}}),
        json!({"tools": {"mcp": {"servers": []}}}),
        json!({"tools": {"mcp": {"servers": {"x": "sh"}}}}),
        json!({"tools": {"mcp": {"servers": {"x": {"enabled": "yes"}}}}}),
        json!({"tools": {"mcp": {"servers": {"x": {"command": ["sh"]}}}}}),
        json!({"tools": {"mcp": {"servers": {"x": {"type": 1}}}}}),
    ] {
        let mut changed = config.clone();
        assert!(enforce(&mut changed, home()).is_err(), "{config}");
        assert_eq!(changed, config);
        assert!(check(&config, home()).is_err(), "{config}");
    }
}

#[test]
fn only_the_nanokvm_server_is_exempt_by_name() {
    let mut config = json!({
        "tools": {"mcp": {"servers": {
            "nanokvm": {"enabled": true, "type": "http"},
            "nanokvm-copy": {"enabled": true, "command": "nanokvm"},
            "blank": {"enabled": true, "command": "  "}
        }}}
    });
    enforce(&mut config, home()).unwrap();
    let servers = &config["tools"]["mcp"]["servers"];
    assert_eq!(servers["nanokvm"]["enabled"], true);
    assert_eq!(servers["nanokvm-copy"]["enabled"], false);
    assert_eq!(
        servers["blank"]["enabled"], true,
        "a blank command starts nothing"
    );
}
