use axum::{Json, response::IntoResponse};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{LazyLock, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{AppError, Result, error::ApiResponse};

const SHORTCUT_FILE: &str = "/etc/kvm/shortcuts.json";
const LEADER_KEY_FILE: &str = "/etc/kvm/leader-key";
const MODE_FLAG_FILE: &str = "/sys/kernel/config/usb_gadget/g0/bcdDevice";
const MODE_NORMAL: &str = "normal";
const MODE_HID_ONLY: &str = "hid-only";
const MAX_SHORTCUT_KEYS: usize = 6;
const MAX_KEY_CODE_LEN: usize = 64;
const MAX_KEY_LABEL_LEN: usize = 64;

static SHORTCUT_LOCK: LazyLock<RwLock<()>> = LazyLock::new(|| RwLock::new(()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShortcutKey {
    pub code: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shortcut {
    pub id: String,
    pub keys: Vec<ShortcutKey>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ShortcutStore {
    #[serde(default)]
    shortcuts: Vec<Shortcut>,
}

#[derive(Debug, Serialize)]
pub struct GetShortcutsRsp {
    shortcuts: Vec<Shortcut>,
}

#[derive(Debug, Deserialize)]
pub struct AddShortcutReq {
    keys: Vec<ShortcutKey>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteShortcutReq {
    id: String,
}

#[derive(Debug, Deserialize)]
pub struct SetLeaderKeyReq {
    #[serde(default)]
    key: String,
}

#[derive(Debug, Serialize)]
pub struct GetLeaderKeyRsp {
    key: String,
}

#[derive(Debug, Serialize)]
pub struct GetHidModeRsp {
    mode: String,
}

pub async fn get_shortcuts() -> Result<impl IntoResponse> {
    let _guard = SHORTCUT_LOCK
        .read()
        .map_err(|_| AppError::Internal("shortcut lock poisoned".to_string()))?;
    let store = load_shortcuts()?;
    Ok(Json(ApiResponse::ok(GetShortcutsRsp {
        shortcuts: store.shortcuts,
    })))
}

pub async fn add_shortcut(Json(req): Json<AddShortcutReq>) -> Result<impl IntoResponse> {
    validate_shortcut_keys(&req.keys)?;

    let _guard = SHORTCUT_LOCK
        .write()
        .map_err(|_| AppError::Internal("shortcut lock poisoned".to_string()))?;
    let mut store = load_shortcuts()?;
    store.shortcuts.push(Shortcut {
        id: new_shortcut_id(),
        keys: req.keys,
    });
    save_shortcuts(&store)?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn delete_shortcut(Json(req): Json<DeleteShortcutReq>) -> Result<impl IntoResponse> {
    if req.id.trim().is_empty() || req.id.len() > 128 {
        return Err(AppError::BadRequest("invalid arguments".to_string()));
    }

    let _guard = SHORTCUT_LOCK
        .write()
        .map_err(|_| AppError::Internal("shortcut lock poisoned".to_string()))?;
    let mut store = load_shortcuts()?;
    let before = store.shortcuts.len();
    store.shortcuts.retain(|shortcut| shortcut.id != req.id);
    if store.shortcuts.len() == before {
        return Err(AppError::BadRequest("shortcut not found".to_string()));
    }
    save_shortcuts(&store)?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_leader_key() -> Result<impl IntoResponse> {
    let key = match fs::read_to_string(LEADER_KEY_FILE) {
        Ok(key) => key
            .chars()
            .filter(|ch| *ch != '\n' && *ch != '\r')
            .collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err.into()),
    };

    Ok(Json(ApiResponse::ok(GetLeaderKeyRsp { key })))
}

pub async fn set_leader_key(Json(req): Json<SetLeaderKeyReq>) -> Result<impl IntoResponse> {
    let key = req.key.trim();
    if key.is_empty() {
        remove_file_if_exists(LEADER_KEY_FILE)?;
    } else {
        validate_key_code(key)?;
        write_file(Path::new(LEADER_KEY_FILE), key.as_bytes(), 0o644)?;
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_mode() -> Result<impl IntoResponse> {
    let mode = read_hid_mode()?;
    Ok(Json(ApiResponse::ok(GetHidModeRsp { mode })))
}

fn load_shortcuts() -> Result<ShortcutStore> {
    let content = match fs::read_to_string(SHORTCUT_FILE) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ShortcutStore::default());
        }
        Err(err) => return Err(err.into()),
    };
    if content.trim().is_empty() {
        return Ok(ShortcutStore::default());
    }

    let store: ShortcutStore = serde_json::from_str(&content)
        .map_err(|err| AppError::Internal(format!("invalid shortcuts file: {err}")))?;
    for shortcut in &store.shortcuts {
        validate_shortcut_keys(&shortcut.keys)?;
    }
    Ok(store)
}

fn save_shortcuts(store: &ShortcutStore) -> Result<()> {
    let data = serde_json::to_vec(store)
        .map_err(|err| AppError::Internal(format!("serialize shortcuts failed: {err}")))?;
    write_file(Path::new(SHORTCUT_FILE), &data, 0o644)
}

fn validate_shortcut_keys(keys: &[ShortcutKey]) -> Result<()> {
    if keys.is_empty() || keys.len() > MAX_SHORTCUT_KEYS {
        return Err(AppError::BadRequest("invalid shortcut keys".to_string()));
    }

    for key in keys {
        validate_key_code(&key.code)?;
        validate_key_label(&key.label)?;
    }
    Ok(())
}

fn validate_key_code(code: &str) -> Result<()> {
    if code.is_empty() || code.len() > MAX_KEY_CODE_LEN {
        return Err(AppError::BadRequest("invalid key code".to_string()));
    }
    if !code
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AppError::BadRequest("invalid key code".to_string()));
    }
    Ok(())
}

fn validate_key_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > MAX_KEY_LABEL_LEN {
        return Err(AppError::BadRequest("invalid key label".to_string()));
    }
    if label.chars().any(char::is_control) {
        return Err(AppError::BadRequest("invalid key label".to_string()));
    }
    Ok(())
}

fn new_shortcut_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_hid_mode() -> Result<String> {
    let flag = fs::read_to_string(MODE_FLAG_FILE)?;
    match flag.trim() {
        "0x0510" => Ok(MODE_NORMAL.to_string()),
        "0x0623" => Ok(MODE_HID_ONLY.to_string()),
        other => Err(AppError::Internal(format!(
            "invalid HID mode flag: {other}"
        ))),
    }
}

fn write_file(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp = tmp_path_for(path);
    fs::write(&tmp, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(".{filename}.{}.{}.tmp", std::process::id(), stamp))
}

fn remove_file_if_exists(path: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_shortcut_keys() {
        let keys = vec![ShortcutKey {
            code: "ControlLeft".to_string(),
            label: "Ctrl".to_string(),
        }];
        assert!(validate_shortcut_keys(&keys).is_ok());
        assert!(validate_shortcut_keys(&[]).is_err());
    }

    #[test]
    fn rejects_control_chars_in_shortcuts() {
        assert!(validate_key_code("ControlLeft").is_ok());
        assert!(validate_key_code("Control Left").is_err());
        assert!(validate_key_label("Ctrl").is_ok());
        assert!(validate_key_label("Ctrl\n").is_err());
    }

    #[test]
    fn shortcut_ids_are_hex() {
        let id = new_shortcut_id();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
