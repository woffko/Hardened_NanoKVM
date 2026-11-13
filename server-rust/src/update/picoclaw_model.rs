//! Pure model-selection transform shared by the API writer and the broker's
//! Model job. No I/O, entropy or provisioning: callers pass the decoded pair
//! and the request's trimmed fields. The key goes only into the security
//! document; config keeps no copy, and nothing here logs or echoes it.
use crate::{AppError, Result};
use serde_json::{Map as JsonMap, Value as JsonValue};

pub(crate) const MAX_MODEL_BYTES: usize = 256;
pub(crate) const MAX_API_BASE_BYTES: usize = 2048;
pub(crate) const MAX_API_KEY_BYTES: usize = 4096;

/// Bounded request fields, already trimmed, without control characters, and
/// a non-empty short name. Anything else refuses before a job is accepted.
pub(crate) fn check_request(model: &str, api_base: &str, api_key: &str) -> Result<()> {
    for (value, limit) in [
        (model, MAX_MODEL_BYTES),
        (api_base, MAX_API_BASE_BYTES),
        (api_key, MAX_API_KEY_BYTES),
    ] {
        if value.is_empty()
            || value.len() > limit
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(AppError::BadRequest("invalid model configuration".into()));
        }
    }
    match model_name(model) {
        Some(name) if !name.is_empty() => Ok(()),
        _ => Err(AppError::BadRequest("invalid model configuration".into())),
    }
}

/// The model's short name: the last segment of its identifier.
pub(crate) fn model_name(model: &str) -> Option<String> {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(
        trimmed
            .rsplit('/')
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_string(),
    )
}

/// Select `model` with its endpoint and key: the entry with the same short
/// name is updated in place (or appended), its config key copies are
/// dropped, the default agent selects it and the key is stored in security.
/// Unrelated and custom fields are preserved.
pub(crate) fn apply(
    config: &mut JsonValue,
    security: &mut serde_yaml::Value,
    model: &str,
    api_base: &str,
    api_key: &str,
) -> Result<String> {
    let model_name = model_name(model)
        .ok_or_else(|| AppError::Internal("model identifier is required".to_string()))?;
    let raw = config
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("picoclaw config root is not an object".to_string()))?;

    let models = raw
        .entry("model_list".to_string())
        .or_insert_with(|| JsonValue::Array(Vec::new()));
    if !models.is_array() {
        *models = JsonValue::Array(Vec::new());
    }
    let models = models.as_array_mut().expect("model_list array");
    let mut updated_index = None;
    for (idx, item) in models.iter_mut().enumerate() {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        if item
            .get("model_name")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            == Some(model_name.as_str())
        {
            item.insert(
                "model_name".to_string(),
                JsonValue::String(model_name.clone()),
            );
            item.insert("model".to_string(), JsonValue::String(model.to_string()));
            item.insert(
                "api_base".to_string(),
                JsonValue::String(api_base.to_string()),
            );
            item.remove("api_key");
            item.remove("api_keys");
            updated_index = Some(idx);
            break;
        }
    }
    let updated_index = match updated_index {
        Some(idx) => idx,
        None => {
            let mut item = JsonMap::new();
            item.insert(
                "model_name".to_string(),
                JsonValue::String(model_name.clone()),
            );
            item.insert("model".to_string(), JsonValue::String(model.to_string()));
            item.insert(
                "api_base".to_string(),
                JsonValue::String(api_base.to_string()),
            );
            models.push(JsonValue::Object(item));
            models.len() - 1
        }
    };

    let agents = raw
        .entry("agents".to_string())
        .or_insert_with(|| JsonValue::Object(JsonMap::new()));
    if !agents.is_object() {
        *agents = JsonValue::Object(JsonMap::new());
    }
    let defaults = agents
        .as_object_mut()
        .expect("agents object")
        .entry("defaults".to_string())
        .or_insert_with(|| JsonValue::Object(JsonMap::new()));
    if !defaults.is_object() {
        *defaults = JsonValue::Object(JsonMap::new());
    }
    let defaults = defaults.as_object_mut().expect("defaults object");
    defaults.insert(
        "model_name".to_string(),
        JsonValue::String(model_name.clone()),
    );
    defaults.remove("model");

    set_model_secret(security, &model_name, updated_index, api_key);
    Ok(model_name)
}

fn set_model_secret(
    security: &mut serde_yaml::Value,
    model_name: &str,
    index: usize,
    api_key: &str,
) {
    if !security.is_mapping() {
        *security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let root = security.as_mapping_mut().expect("security mapping");
    let model_list_key = serde_yaml::Value::String("model_list".to_string());
    root.entry(model_list_key.clone())
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    if !root[&model_list_key].is_mapping() {
        root.insert(
            model_list_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    let model_list = root
        .get_mut(&model_list_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .expect("model_list mapping");
    let mut entry = serde_yaml::Mapping::new();
    entry.insert(
        serde_yaml::Value::String("api_keys".to_string()),
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(api_key.to_string())]),
    );
    model_list.insert(
        serde_yaml::Value::String(format!("{model_name}:{index}")),
        serde_yaml::Value::Mapping(entry),
    );
}

#[cfg(test)]
#[path = "picoclaw_model_tests.rs"]
mod tests;
