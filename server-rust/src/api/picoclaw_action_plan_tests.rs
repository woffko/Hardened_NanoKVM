use super::super::{ActionBatch, normalize_actions};
use super::*;
use serde_json::json;

fn action(value: serde_json::Value) -> Action {
    serde_json::from_value(value).unwrap()
}

fn wait(ms: i32) -> Action {
    action(json!({"action":"wait", "duration_ms":ms}))
}

fn error(actions: Vec<Action>, index: Option<usize>) -> PicoclawErrorData {
    let Err(error) = Batch::prepare(actions) else {
        panic!("invalid batch accepted")
    };
    assert_eq!(error.code, CODE_INVALID_ACTION);
    assert_eq!(error.index, index);
    error
}

#[test]
fn action_count_is_bounded_during_both_deserialization_paths_without_single_fallback() {
    assert!(Batch::prepare(vec![wait(0); MAX_ACTIONS]).is_ok());
    error(Vec::new(), None);
    error(vec![wait(0); MAX_ACTIONS + 1], None);
    for count in [64, 65, 10_000] {
        let value = json!({"actions":vec![json!({"action":"wait"});count]});
        let raw = serde_json::to_vec(&value).unwrap();
        assert_eq!(normalize_actions(&raw).is_ok(), count == MAX_ACTIONS);
        assert_eq!(
            serde_json::from_value::<ActionBatch>(value.clone()).is_ok(),
            count == MAX_ACTIONS
        );
        let mut mixed = value;
        mixed["action"] = json!("wait");
        assert!(normalize_actions(&serde_json::to_vec(&mixed).unwrap()).is_err());
    }
    for raw in [
        br#"{"actions":[],"action":"wait"}"#.as_slice(),
        br#"{"actions":null,"action":"wait"}"#,
        br#"{"actions":{}}"#,
        br#"{"actions":[{"action":"wait"}],"actions":[]}"#,
    ] {
        assert!(normalize_actions(raw).is_err());
    }
}

#[test]
fn wait_scroll_and_all_delay_boundaries_are_checked_without_integer_wrap() {
    for ms in [i32::MIN, -1, 5_001, i32::MAX] {
        error(vec![wait(0), wait(ms)], Some(1));
    }
    assert!(Batch::prepare(vec![wait(0), wait(5_000)]).is_ok());
    assert!(Batch::prepare(vec![wait(5_000); 6]).is_ok());
    error(vec![wait(5_000); 7], Some(6));
    for amount in [i32::MIN, -1, 101, i32::MAX] {
        error(
            vec![action(json!({"action":"scroll", "amount":amount}))],
            Some(0),
        );
    }
    for amount in [0, 1, 100] {
        let plan =
            Batch::prepare(vec![action(json!({"action":"scroll", "amount":amount}))]).unwrap();
        assert!(
            matches!(plan.actions[0], PreparedAction::Scroll { amount: actual, wheel: 1, .. } if actual == if amount==0 {1} else {amount as u16})
        );
    }
    assert!(Batch::prepare(vec![action(json!({"action":"scroll", "amount":100})); 15]).is_ok());
    error(
        vec![action(json!({"action":"scroll", "amount":100})); 16],
        Some(15),
    );
}

#[test]
fn typing_budget_counts_utf8_bytes_across_actions_and_delay_counts_reports() {
    let mut bytes = 0;
    let (prepared, cost) = prepare_action(
        &action(json!({"action":"type", "text":"a".repeat(4096)})),
        &mut bytes,
    )
    .unwrap();
    assert_eq!(bytes, 4096);
    assert_eq!(cost, Duration::from_millis(4096 * 30));
    assert!(matches!(prepared, PreparedAction::Type(reports) if reports.len()==4096));
    let err = prepare_action(&action(json!({"action":"type", "text":"b"})), &mut bytes)
        .err()
        .unwrap();
    assert!(err.message.contains("4096 UTF-8 bytes"));
    for text in ["a".repeat(4097), "é".repeat(2049)] {
        let err = error(vec![action(json!({"action":"type", "text":text}))], Some(0));
        assert!(err.message.contains("4096 UTF-8 bytes"));
    }
    assert!(
        Batch::prepare(vec![action(
            json!({"action":"type", "text":"a".repeat(1000)})
        )])
        .is_ok()
    );
    let err = error(
        vec![action(json!({"action":"type", "text":"a".repeat(1001)}))],
        Some(0),
    );
    assert!(err.message.contains("30 seconds"));
    let err = error(
        vec![
            wait(5_000),
            action(json!({"action":"type", "text":"a".repeat(834)})),
        ],
        Some(1),
    );
    assert!(err.message.contains("30 seconds"));
    let mut bytes = usize::MAX;
    assert!(prepare_action(&action(json!({"action":"type", "text":"a"})), &mut bytes).is_err());
}

#[test]
fn complete_semantics_are_validated_before_any_plan_is_returned() {
    for invalid in [
        json!({"action":"click","x":1.1,"y":0.5}),
        json!({"action":"move","x":0.5}),
        json!({"action":"drag","from":{"x":0.5,"y":0.5}}),
        json!({"action":"scroll","direction":"sideways"}),
        json!({"action":"click","x":0.5,"y":0.5,"button":"unknown"}),
        json!({"action":"type","text":"prefix then unsupported 🙂"}),
        json!({"action":"type","text":""}),
        json!({"action":"hotkey","keys":["ctrl",99]}),
        json!({"action":"hotkey","keys":["a","b","c","d","e","f","g"]}),
        json!({"action":"hotkey","keys":vec!["ctrl";15]}),
        json!({"action":"hotkey","keys":"ctrl,".repeat(15)}),
        json!({"action":"hotkey","keys":["x".repeat(65)]}),
        json!({"action":"unknown"}),
        json!({"action":" ".repeat(65)}),
    ] {
        error(vec![wait(0), action(invalid)], Some(1));
    }
    error(
        vec![Action {
            action: "move".into(),
            x: Some(f64::NAN),
            y: Some(0.5),
            ..Action::default()
        }],
        Some(0),
    );
    error(
        vec![Action {
            action: "move".into(),
            x: Some(0.5),
            y: Some(f64::INFINITY),
            ..Action::default()
        }],
        Some(0),
    );
}

#[test]
fn typing_enter_hotkeys_and_later_batches_keep_exact_order_without_truncation() {
    for _ in 0..8 {
        let plan = Batch::prepare(vec![
            action(json!({"action":"TyPe", "text":"aA\n\t"})),
            action(json!({"action":"hotkey", "keys":["ctrl","alt","Delete"]})),
            action(json!({"action":"hotkey", "keys":"Enter"})),
            action(json!({"action":"scroll", "amount":2, "direction":"DOWN"})),
        ])
        .unwrap();
        assert_eq!(plan.result_action, "batch");
        let PreparedAction::Type(reports) = &plan.actions[0] else {
            panic!("missing text")
        };
        assert_eq!(
            reports,
            &[
                [0, 0, 4, 0, 0, 0, 0, 0],
                [2, 0, 4, 0, 0, 0, 0, 0],
                [0, 0, 40, 0, 0, 0, 0, 0],
                [0, 0, 43, 0, 0, 0, 0, 0]
            ]
        );
        assert!(matches!(
            plan.actions[1],
            PreparedAction::Hotkey([5, 0, 0x4c, 0, 0, 0, 0, 0])
        ));
        assert!(matches!(
            plan.actions[2],
            PreparedAction::Hotkey([0, 0, 40, 0, 0, 0, 0, 0])
        ));
        assert!(matches!(
            plan.actions[3],
            PreparedAction::Scroll {
                amount: 2,
                wheel: -1,
                ..
            }
        ));
    }
    assert_eq!(
        Batch::prepare(vec![action(json!({"action":" MOVE ","x":0.0,"y":1.0}))])
            .unwrap()
            .result_action,
        " MOVE "
    );
}

#[tokio::test(flavor = "current_thread")]
async fn direct_and_mcp_reject_a_late_invalid_action_before_wait_or_hid_execution() {
    let mut config = crate::config::Config::default();
    config.security.allow_default_admin = false;
    let state = crate::state::AppState::new(config).await.unwrap();
    let body = json!({"actions":[{"action":"wait","duration_ms":5000},{"action":"unknown"}]});
    let mut headers = super::super::HeaderMap::new();
    headers.insert(
        super::super::SESSION_ID_HEADER,
        "preflight-only-test-session".parse().unwrap(),
    );
    let started = std::time::Instant::now();
    let direct = tokio::time::timeout(
        Duration::from_millis(200),
        super::super::actions(
            super::super::State(state.clone()),
            headers.clone(),
            serde_json::to_vec(&body).unwrap().into(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    let bytes = axum::body::to_bytes(direct.into_body(), 64 * 1024)
        .await
        .unwrap();
    let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(data["code"], CODE_INVALID_ACTION);
    assert_eq!(data["index"], 1);
    let rpc = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kvm_actions","arguments":body}});
    // A Tokio timeout cannot interrupt a synchronous future that blocks and
    // then returns Ready. Also measure wall time against the deliberate 5s wait.
    let started = std::time::Instant::now();
    let response = tokio::time::timeout(
        Duration::from_millis(200),
        super::super::mcp(
            super::super::State(state.clone()),
            headers,
            serde_json::to_vec(&rpc).unwrap().into(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(data["result"]["isError"], true);
    assert!(
        data["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("invalid action")
    );
    assert!(!state.picoclaw_worker.started());
}

#[test]
fn advertised_schema_matches_per_call_preflight_and_preserves_task_continuation() {
    let tools = super::super::mcp_tool_definitions();
    let tool = tools
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "kvm_actions")
        .unwrap();
    let actions = &tool["inputSchema"]["properties"]["actions"];
    assert_eq!(actions["minItems"], 1);
    assert_eq!(actions["maxItems"], MAX_ACTIONS);
    assert_eq!(
        actions["items"]["properties"]["duration_ms"]["maximum"],
        MAX_WAIT_MS
    );
    assert_eq!(
        actions["items"]["properties"]["amount"]["maximum"],
        MAX_SCROLL
    );
    assert_eq!(actions["items"]["properties"]["keys"]["maxItems"], 14);
    assert!(
        tool["description"]
            .as_str()
            .unwrap()
            .contains("sequential bounded calls")
    );
    assert!(
        tool["description"]
            .as_str()
            .unwrap()
            .contains("never truncated")
    );
}
