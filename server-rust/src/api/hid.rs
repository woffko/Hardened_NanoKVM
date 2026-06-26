use axum::{Json, response::IntoResponse};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{LazyLock, RwLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time;

use crate::{
    AppError, Result,
    error::ApiResponse,
    system::command::{AllowedCommand, run_allowed},
    ws::hid as hid_ws,
};

const SHORTCUT_FILE: &str = "/etc/kvm/shortcuts.json";
const LEADER_KEY_FILE: &str = "/etc/kvm/leader-key";
const MODE_FLAG_FILE: &str = "/sys/kernel/config/usb_gadget/g0/bcdDevice";
const MODE_NORMAL_SCRIPT: &str = "/kvmapp/system/init.d/S03usbdev";
const MODE_HID_ONLY_SCRIPT: &str = "/kvmapp/system/init.d/S03usbhid";
const USB_DEV_SCRIPT: &str = "/etc/init.d/S03usbdev";
const MODE_NORMAL: &str = "normal";
const MODE_HID_ONLY: &str = "hid-only";
const MAX_SHORTCUT_KEYS: usize = 6;
const MAX_KEY_CODE_LEN: usize = 64;
const MAX_KEY_LABEL_LEN: usize = 64;
const MAX_PASTE_BYTES: usize = 1024;
const PASTE_KEY_DELAY: Duration = Duration::from_millis(30);

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

#[derive(Debug, Deserialize)]
pub struct SetHidModeReq {
    mode: String,
}

#[derive(Debug, Deserialize)]
pub struct PasteReq {
    content: String,
    #[serde(default)]
    langue: String,
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

pub async fn set_mode(Json(req): Json<SetHidModeReq>) -> Result<impl IntoResponse> {
    let mode = validate_hid_mode(&req.mode)?;
    if read_hid_mode().ok().as_deref() == Some(mode) {
        return Ok(Json(ApiResponse::<()>::ok_empty()));
    }

    copy_hid_mode_file(mode)?;
    tokio::spawn(async {
        time::sleep(Duration::from_millis(500)).await;
        if let Err(err) = run_allowed(
            AllowedCommand::Reboot,
            std::iter::empty::<&str>(),
            Duration::from_secs(5),
        )
        .await
        {
            tracing::error!(error = %err, "failed to reboot after HID mode change");
        }
    });

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn reset_hid() -> Result<impl IntoResponse> {
    let output = run_allowed(
        AllowedCommand::ServiceUsbDev,
        ["restart_phy"],
        Duration::from_secs(15),
    )
    .await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "failed to reset HID",
            output,
        )));
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn paste(Json(req): Json<PasteReq>) -> Result<impl IntoResponse> {
    validate_paste_request(&req)?;
    let content = req.content;
    let language = req.langue;

    tokio::task::spawn_blocking(move || paste_blocking(&content, &language))
        .await
        .map_err(|err| AppError::Internal(format!("HID paste task failed: {err}")))??;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

fn validate_paste_request(req: &PasteReq) -> Result<()> {
    if req.content.is_empty() {
        return Err(AppError::BadRequest("invalid arguments".to_string()));
    }
    if req.content.len() > MAX_PASTE_BYTES {
        return Err(AppError::Api {
            code: -2,
            msg: "content too long".to_string(),
        });
    }
    Ok(())
}

fn paste_blocking(content: &str, language: &str) -> Result<()> {
    let key_up = [0_u8; 8];
    for ch in content.chars() {
        let Some(key) = paste_key(ch, language) else {
            tracing::debug!(char = %ch, codepoint = ch as u32, "unknown HID paste character");
            continue;
        };

        let key_down = [key.modifiers, 0x00, key.code, 0x00, 0x00, 0x00, 0x00, 0x00];
        hid_ws::write_keyboard_report(&key_down)?;
        hid_ws::write_keyboard_report(&key_up)?;
        thread::sleep(PASTE_KEY_DELAY);
    }
    Ok(())
}

pub fn type_text_blocking(content: &str, language: &str) -> Result<usize> {
    let key_up = [0_u8; 8];
    let mut writes = 0;
    for ch in content.chars() {
        let Some(key) = paste_key(ch, language) else {
            return Err(AppError::BadRequest(
                "unsupported character in type action".to_string(),
            ));
        };

        let key_down = [key.modifiers, 0x00, key.code, 0x00, 0x00, 0x00, 0x00, 0x00];
        hid_ws::write_keyboard_report(&key_down)?;
        hid_ws::write_keyboard_report(&key_up)?;
        writes += 2;
        thread::sleep(PASTE_KEY_DELAY);
    }
    Ok(writes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PasteKey {
    modifiers: u8,
    code: u8,
}

const fn key(modifiers: u8, code: u8) -> PasteKey {
    PasteKey { modifiers, code }
}

fn paste_key(ch: char, language: &str) -> Option<PasteKey> {
    match language {
        "de" => de_paste_key(ch).or_else(|| base_paste_key(ch)),
        "fr" => fr_paste_key(ch).or_else(|| base_paste_key(ch)),
        _ => base_paste_key(ch),
    }
}

fn base_paste_key(ch: char) -> Option<PasteKey> {
    match ch {
        'a'..='z' => Some(key(0, ch as u8 - b'a' + 4)),
        'A'..='Z' => Some(key(2, ch as u8 - b'A' + 4)),
        '1'..='9' => Some(key(0, ch as u8 - b'1' + 30)),
        '0' => Some(key(0, 39)),
        '!' => Some(key(2, 30)),
        '@' => Some(key(2, 31)),
        '#' => Some(key(2, 32)),
        '$' => Some(key(2, 33)),
        '%' => Some(key(2, 34)),
        '^' => Some(key(2, 35)),
        '&' => Some(key(2, 36)),
        '*' => Some(key(2, 37)),
        '(' => Some(key(2, 38)),
        ')' => Some(key(2, 39)),
        '\n' => Some(key(0, 40)),
        '\t' => Some(key(0, 43)),
        ' ' => Some(key(0, 44)),
        '-' => Some(key(0, 45)),
        '=' => Some(key(0, 46)),
        '[' => Some(key(0, 47)),
        ']' => Some(key(0, 48)),
        '\\' => Some(key(0, 49)),
        ';' => Some(key(0, 51)),
        '\'' => Some(key(0, 52)),
        '`' => Some(key(0, 53)),
        ',' => Some(key(0, 54)),
        '.' => Some(key(0, 55)),
        '/' => Some(key(0, 56)),
        '_' => Some(key(2, 45)),
        '+' => Some(key(2, 46)),
        '{' => Some(key(2, 47)),
        '}' => Some(key(2, 48)),
        '|' => Some(key(2, 49)),
        ':' => Some(key(2, 51)),
        '"' => Some(key(2, 52)),
        '~' => Some(key(2, 53)),
        '<' => Some(key(2, 54)),
        '>' => Some(key(2, 55)),
        '?' => Some(key(2, 56)),
        _ => None,
    }
}

fn de_paste_key(ch: char) -> Option<PasteKey> {
    match ch {
        'y' => Some(key(0, 29)),
        'Y' => Some(key(2, 29)),
        'z' => Some(key(0, 28)),
        'Z' => Some(key(2, 28)),
        '\u{00e4}' => Some(key(0, 52)),
        '\u{00c4}' => Some(key(2, 52)),
        '\u{00f6}' => Some(key(0, 51)),
        '\u{00d6}' => Some(key(2, 51)),
        '\u{00fc}' => Some(key(0, 47)),
        '\u{00dc}' => Some(key(2, 47)),
        '\u{00df}' => Some(key(0, 45)),
        '^' => Some(key(0, 53)),
        '/' => Some(key(2, 36)),
        '(' => Some(key(2, 37)),
        '&' => Some(key(2, 35)),
        ')' => Some(key(2, 38)),
        '`' => Some(key(2, 46)),
        '"' => Some(key(2, 31)),
        '?' => Some(key(2, 45)),
        '{' => Some(key(0x40, 36)),
        '[' => Some(key(0x40, 37)),
        ']' => Some(key(0x40, 38)),
        '}' => Some(key(0x40, 39)),
        '\\' => Some(key(0x40, 45)),
        '@' => Some(key(0x40, 20)),
        '+' => Some(key(0, 48)),
        '*' => Some(key(2, 48)),
        '~' => Some(key(0x40, 48)),
        '#' => Some(key(0, 49)),
        '\'' => Some(key(2, 49)),
        '<' => Some(key(0, 100)),
        '>' => Some(key(2, 100)),
        '|' => Some(key(0x40, 100)),
        ';' => Some(key(2, 54)),
        ':' => Some(key(2, 55)),
        '-' => Some(key(0, 56)),
        '_' => Some(key(2, 56)),
        '\u{00b4}' => Some(key(0, 46)),
        '\u{00b0}' => Some(key(2, 53)),
        '\u{00a7}' => Some(key(2, 32)),
        '\u{20ac}' => Some(key(0x40, 8)),
        '\u{00b2}' => Some(key(0x40, 31)),
        '\u{00b3}' => Some(key(0x40, 32)),
        _ => None,
    }
}

fn fr_paste_key(ch: char) -> Option<PasteKey> {
    match ch {
        'a' => Some(key(0, 20)),
        'A' => Some(key(2, 20)),
        'q' => Some(key(0, 4)),
        'Q' => Some(key(2, 4)),
        'z' => Some(key(0, 26)),
        'Z' => Some(key(2, 26)),
        'w' => Some(key(0, 29)),
        'W' => Some(key(2, 29)),
        'm' => Some(key(0, 51)),
        'M' => Some(key(2, 51)),
        '1'..='9' => Some(key(2, ch as u8 - b'1' + 30)),
        '0' => Some(key(2, 39)),
        '&' => Some(key(0, 30)),
        '\u{00e9}' => Some(key(0, 31)),
        '"' => Some(key(0, 32)),
        '\'' => Some(key(0, 33)),
        '(' => Some(key(0, 34)),
        '-' => Some(key(0, 35)),
        '\u{00e8}' => Some(key(0, 36)),
        '_' => Some(key(0, 37)),
        '\u{00e7}' => Some(key(0, 38)),
        '\u{00e0}' => Some(key(0, 39)),
        ')' => Some(key(0, 45)),
        '\u{00b0}' => Some(key(2, 45)),
        '^' => Some(key(0, 47)),
        '\u{00a8}' => Some(key(2, 47)),
        '$' => Some(key(0, 48)),
        '\u{00a3}' => Some(key(2, 48)),
        '*' => Some(key(0, 49)),
        '\u{00b5}' => Some(key(2, 49)),
        '\u{00f9}' => Some(key(0, 52)),
        '%' => Some(key(2, 52)),
        ',' => Some(key(0, 16)),
        '?' => Some(key(2, 16)),
        ';' => Some(key(0, 54)),
        '.' => Some(key(2, 54)),
        ':' => Some(key(0, 55)),
        '/' => Some(key(2, 55)),
        '!' => Some(key(0, 56)),
        '\u{00a7}' => Some(key(2, 56)),
        '~' => Some(key(0x40, 31)),
        '#' => Some(key(0x40, 32)),
        '{' => Some(key(0x40, 33)),
        '[' => Some(key(0x40, 34)),
        '|' => Some(key(0x40, 35)),
        '`' => Some(key(0x40, 36)),
        '\\' => Some(key(0x40, 37)),
        ']' => Some(key(0x40, 45)),
        '}' => Some(key(0x40, 46)),
        '@' => Some(key(0x40, 39)),
        '\u{20ac}' => Some(key(0x40, 8)),
        _ => None,
    }
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

fn validate_hid_mode(mode: &str) -> Result<&'static str> {
    match mode.trim() {
        MODE_NORMAL => Ok(MODE_NORMAL),
        MODE_HID_ONLY => Ok(MODE_HID_ONLY),
        _ => Err(AppError::BadRequest("invalid HID mode".to_string())),
    }
}

fn copy_hid_mode_file(mode: &str) -> Result<()> {
    let source = match validate_hid_mode(mode)? {
        MODE_NORMAL => MODE_NORMAL_SCRIPT,
        MODE_HID_ONLY => MODE_HID_ONLY_SCRIPT,
        _ => unreachable!("validated HID mode"),
    };

    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::BadRequest("invalid HID mode script".to_string()));
    }
    let data = fs::read(source)?;
    let mode = metadata.permissions().mode() & 0o777;
    write_file(Path::new(USB_DEV_SCRIPT), &data, mode)
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

fn command_error(message: &str, output: crate::system::command::CommandOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr.trim();
    if !detail.is_empty() {
        format!("{message}: {detail}")
    } else {
        let detail = stdout.trim();
        if detail.is_empty() {
            message.to_string()
        } else {
            format!("{message}: {detail}")
        }
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

    #[test]
    fn validates_hid_modes() {
        assert_eq!(validate_hid_mode("normal").unwrap(), MODE_NORMAL);
        assert_eq!(validate_hid_mode("hid-only").unwrap(), MODE_HID_ONLY);
        assert!(validate_hid_mode("storage-only").is_err());
    }

    #[test]
    fn maps_paste_keys_for_supported_layouts() {
        assert_eq!(paste_key('A', "").unwrap(), key(2, 4));
        assert_eq!(paste_key('@', "").unwrap(), key(2, 31));

        assert_eq!(paste_key('y', "de").unwrap(), key(0, 29));
        assert_eq!(paste_key('z', "de").unwrap(), key(0, 28));
        assert_eq!(paste_key('@', "de").unwrap(), key(0x40, 20));

        assert_eq!(paste_key('a', "fr").unwrap(), key(0, 20));
        assert_eq!(paste_key('1', "fr").unwrap(), key(2, 30));
        assert_eq!(paste_key('@', "fr").unwrap(), key(0x40, 39));
    }

    #[test]
    fn validates_paste_request_size() {
        assert!(
            validate_paste_request(&PasteReq {
                content: "abc".to_string(),
                langue: String::new(),
            })
            .is_ok()
        );

        assert!(
            validate_paste_request(&PasteReq {
                content: String::new(),
                langue: String::new(),
            })
            .is_err()
        );

        let err = validate_paste_request(&PasteReq {
            content: "a".repeat(MAX_PASTE_BYTES + 1),
            langue: String::new(),
        })
        .unwrap_err();
        assert!(matches!(err, AppError::Api { code: -2, .. }));
    }
}
