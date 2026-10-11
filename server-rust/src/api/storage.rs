use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Duration,
};
use tokio::{sync::Mutex, time};

use crate::{
    AppError, Result,
    api::download,
    error::ApiResponse,
    state::AppState,
    system::{
        command::{AllowedCommand, run_allowed},
        files::clean_relative_path,
    },
    ws::hid as hid_ws,
};

const IMAGE_NONE: &str = "/dev/mmcblk0p3";
const CDROM_FLAG: &str =
    "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/cdrom";
const MOUNT_DEVICE: &str =
    "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/file";
const INQUIRY_STRING: &str =
    "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/inquiry_string";
const RO_FLAG: &str = "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/ro";
const USB_PRODUCT: &str = "/sys/kernel/config/usb_gadget/g0/strings/0x409/product";
const USB_PRODUCT_DEFAULT: &str = "NanoKVM";
// The SCSI inquiry product field holds 16 bytes, the USB product string 126.
const INQUIRY_PRODUCT_SIZE: usize = 16;
const USB_PRODUCT_SIZE: usize = 126;
const UDC_FILE: &str = "/sys/kernel/config/usb_gadget/g0/UDC";
const UDC_CLASS_DIR: &str = "/sys/class/udc";
const MEDIA_SETTLE_DELAY: Duration = Duration::from_millis(100);
const DATA_MOUNT: &str = "/data";
const REMOUNT_TIMEOUT: Duration = Duration::from_secs(10);

/// Response code for a medium the host will not let go of, so the UI can offer a forced eject.
pub const MEDIA_LOCKED_CODE: i32 = -423;
const MEDIA_LOCKED_MESSAGE: &str =
    "virtual media is busy on the remote host; eject or unmount it there first";

static STORAGE_GADGET_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Serialises everything that changes what the mass storage gadget serves.
pub(crate) async fn lock_gadget() -> tokio::sync::MutexGuard<'static, ()> {
    STORAGE_GADGET_LOCK.lock().await
}

/// The kernel appends this to the path of a backing file that was unlinked or
/// replaced while the LUN still holds it open.
const DELETED_SUFFIX: &str = " (deleted)";

#[derive(Debug, Serialize)]
pub struct GetImagesRsp {
    pub files: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MountImageReq {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub cdrom: bool,
    /// Take the gadget down to release a medium the host has locked.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct GetMountedImageRsp {
    pub file: String,
}

#[derive(Debug, Serialize)]
pub struct GetCdRomRsp {
    pub cdrom: i64,
}

#[derive(Debug, Deserialize)]
pub struct DeleteImageReq {
    pub file: String,
}

pub async fn get_images(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let mut files = Vec::new();
    collect_images(&state.config.paths.image_directory, &mut files)?;
    files.sort();

    Ok(Json(ApiResponse::ok(GetImagesRsp { files })))
}

pub async fn get_mounted_image() -> Result<impl IntoResponse> {
    let image = mounted_file(&read_lun_file(MOUNT_DEVICE)?);

    Ok(Json(ApiResponse::ok(GetMountedImageRsp { file: image })))
}

pub async fn get_cdrom() -> Result<impl IntoResponse> {
    let cdrom = parse_cdrom_flag(&read_lun_file(CDROM_FLAG)?)?;

    Ok(Json(ApiResponse::ok(GetCdRomRsp { cdrom })))
}

/// The LUN's cdrom flag; an empty string, as when the gadget has no mass-storage
/// function, means "not a CD-ROM".
fn parse_cdrom_flag(raw: &str) -> Result<i64> {
    if raw.is_empty() {
        return Ok(0);
    }

    raw.parse::<i64>()
        .map_err(|_| AppError::BadRequest("parse failed".to_string()))
}

pub async fn mount_image(
    State(state): State<AppState>,
    Json(req): Json<MountImageReq>,
) -> Result<impl IntoResponse> {
    let _guard = STORAGE_GADGET_LOCK.lock().await;
    let result = apply_mount(&state, &req).await;

    // A forced mount takes the gadget down. If it failed halfway, bring it back:
    // the host must not be left without its keyboard and mouse.
    if req.force
        && result.is_err()
        && gadget_is_down()
        && let Err(err) = connect_gadget().await
    {
        tracing::warn!(error = %err, "failed to reconnect the USB gadget after a failed mount");
    }

    result?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

async fn apply_mount(state: &AppState, req: &MountImageReq) -> Result<()> {
    if !Path::new(MOUNT_DEVICE).exists() {
        return Err(no_lun_error());
    }
    let previous_cdrom = read_cdrom_flag().unwrap_or(false);

    let image = if req.file.trim().is_empty() {
        None
    } else {
        let image = valid_image_path(req.file.trim(), &state.config.paths.image_directory)?;
        validate_mount_mode(&image, req.cdrom)?;
        Some(image)
    };

    if image.is_none() {
        ensure_no_transfer()?;
    }
    if req.force {
        // The host holds the medium locked, and only a disconnect clears that. Bounce the
        // gadget, then release the medium before the host can lock it again.
        reset_usb_gadget().await?;
    }

    // The host owns the raw partition while the virtual disk serves it, so /data
    // has to be read-only here before the host can write it.
    if image.is_none() {
        // The LUN may still hold an image open, even one that was replaced on disk,
        // and /data cannot go read-only while it does.
        eject_lun().await?;
        set_data_writable(false).await?;
    }

    let mode = mount_mode(image.as_deref(), req.cdrom);
    let previous_product = read_trimmed(USB_PRODUCT).ok();
    // Detach first, so no image is ever served with stale flags.
    eject_lun().await?;
    fs::write(RO_FLAG, mode.ro_flag.as_bytes())?;
    fs::write(CDROM_FLAG, mode.cdrom_flag.as_bytes())?;
    fs::write(INQUIRY_STRING, mode.inquiry.as_bytes())?;
    if let Err(err) = fs::write(USB_PRODUCT, mode.usb_product.as_bytes()) {
        tracing::warn!(error = %err, "failed to set the USB product string");
    }

    let mount_target = image
        .as_ref()
        .map(|path| path_to_string(path))
        .unwrap_or_else(|| IMAGE_NONE.to_string());
    write_lun_file(mount_target.as_bytes())?;
    time::sleep(MEDIA_SETTLE_DELAY).await;
    if previous_cdrom != mode.cdrom || previous_product.as_deref() != Some(&mode.usb_product) {
        reset_usb_gadget().await?;
    }

    // A served image is read-only for the host, so the KVM may write /data again.
    if image.is_some()
        && let Err(err) = set_data_writable(true).await
    {
        tracing::warn!(error = %err, "failed to make /data writable after mounting an image");
    }

    Ok(())
}

/// The gadget has no mass storage function when the virtual disk is off or in HID-only mode.
fn no_lun_error() -> AppError {
    AppError::Conflict(
        "virtual media is not available: the USB gadget has no mass storage function (the virtual \
         disk is off, or the device is in HID-only mode)"
            .to_string(),
    )
}

pub async fn reconnect_usb_gadget() -> Result<impl IntoResponse> {
    let _guard = STORAGE_GADGET_LOCK.lock().await;
    reset_usb_gadget().await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn delete_image(
    State(state): State<AppState>,
    Json(req): Json<DeleteImageReq>,
) -> Result<impl IntoResponse> {
    let image = valid_image_path(req.file.trim(), &state.config.paths.image_directory)?;
    if mounted_image_matches(&image) {
        return Err(AppError::Conflict(
            "cannot delete the currently mounted image".to_string(),
        ));
    }
    ensure_writable(&state.config.paths.image_directory)?;
    fs::remove_file(image)?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// Whether the mass storage device serves the whole /data partition to the host.
pub fn data_disk_attached() -> bool {
    read_trimmed(MOUNT_DEVICE)
        .map(|file| file == IMAGE_NONE)
        .unwrap_or(false)
}

/// Fails with a clear message when `path` lives on a read-only filesystem, so
/// writers do not fail halfway with an obscure write error.
pub fn ensure_writable(path: &Path) -> Result<()> {
    if !is_read_only_fs(path).unwrap_or(false) {
        return Ok(());
    }
    let message = if data_disk_attached() {
        "/data is read-only while the virtual disk is shared with the host; turn the virtual disk off first"
    } else {
        "/data is read-only"
    };
    Err(AppError::Conflict(message.to_string()))
}

/// Refuses to hand /data over while an image transfer still writes to it.
pub fn ensure_no_transfer() -> Result<()> {
    if download::transfer_in_progress() {
        return Err(AppError::Conflict(
            "an image transfer is running; wait for it to finish first".to_string(),
        ));
    }
    Ok(())
}

/// Remounts /data read-write or read-only. Only one side may write the
/// partition at a time: while the virtual disk shares it with the host as a
/// writable disk, /data is read-only here.
pub async fn set_data_writable(writable: bool) -> Result<()> {
    let target = Path::new(DATA_MOUNT);
    if is_read_only_fs(target)? != writable {
        return Ok(());
    }

    let option = if writable { "remount,rw" } else { "remount,ro" };
    let output = run_allowed(
        AllowedCommand::Mount,
        ["-o", option, DATA_MOUNT],
        REMOUNT_TIMEOUT,
    )
    .await?;
    if output.status != 0 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!(
            "remount {DATA_MOUNT} failed: {}",
            stderr.trim()
        )));
    }

    // Never hand a writable /data to the host.
    if is_read_only_fs(target)? == writable {
        return Err(AppError::Internal(format!(
            "{DATA_MOUNT} mount did not change"
        )));
    }
    Ok(())
}

/// Whether the filesystem holding `path` (or its nearest existing parent) is mounted read-only.
fn is_read_only_fs(path: &Path) -> std::io::Result<bool> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let mut probe = path;
    while !probe.exists() {
        match probe.parent() {
            Some(parent) => probe = parent,
            None => break,
        }
    }
    let path = CString::new(probe.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?;
    // SAFETY: `path` is NUL-terminated and `stat` is a plain out-parameter.
    let mut stat: nix::libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat.f_flag & nix::libc::ST_RDONLY as nix::libc::c_ulong != 0)
}

fn collect_images(root: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_images(&path, out)?;
        } else if file_type.is_file() && has_image_extension(&path) {
            out.push(path_to_string(&path));
        }
    }
    Ok(())
}

fn valid_image_path(input: &str, root: &Path) -> Result<PathBuf> {
    if input.is_empty() {
        return Err(AppError::BadRequest("invalid image path".to_string()));
    }

    let raw = Path::new(input);
    let candidate = if raw.is_absolute() {
        let relative = raw
            .strip_prefix(root)
            .map_err(|_| AppError::BadRequest("image path is outside storage".to_string()))?;
        root.join(clean_relative_path(relative)?)
    } else {
        root.join(clean_relative_path(raw)?)
    };

    if !has_image_extension(&candidate) {
        return Err(AppError::BadRequest(
            "only .iso and .img images are allowed".to_string(),
        ));
    }

    let metadata = fs::symlink_metadata(&candidate)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::BadRequest("invalid image file".to_string()));
    }

    let root = fs::canonicalize(root)?;
    let candidate = fs::canonicalize(candidate)?;
    if !candidate.starts_with(root) {
        return Err(AppError::BadRequest(
            "image path is outside storage".to_string(),
        ));
    }

    Ok(candidate)
}

/// What the UI shows as mounted: nothing for an empty LUN or the raw partition,
/// otherwise the backing file without the kernel's "(deleted)" marker.
fn mounted_file(raw: &str) -> String {
    if raw.is_empty() || raw == IMAGE_NONE {
        return String::new();
    }
    raw.strip_suffix(DELETED_SUFFIX).unwrap_or(raw).to_string()
}

/// Whether the LUN serves `image`, including a copy of it that was replaced on disk.
fn lun_serves(raw: &str, image: &Path) -> bool {
    let mounted = mounted_file(raw);
    if mounted.is_empty() {
        return false;
    }
    Path::new(&mounted) == image
        || fs::canonicalize(&mounted)
            .map(|mounted| mounted == image)
            .unwrap_or(false)
}

pub(crate) fn mounted_image_matches(image: &Path) -> bool {
    read_trimmed(MOUNT_DEVICE)
        .map(|raw| lun_serves(&raw, image))
        .unwrap_or(false)
}

struct MountMode {
    cdrom: bool,
    ro_flag: &'static str,
    cdrom_flag: &'static str,
    inquiry: String,
    usb_product: String,
}

/// Flags and names for the LUN. A mounted image is always read-only for the
/// host, in CD-ROM and Mass Storage mode alike.
fn mount_mode(image: Option<&Path>, cdrom: bool) -> MountMode {
    let has_image = image.is_some();
    let cdrom = has_image && cdrom;
    let name = image.and_then(image_name);
    let inquiry_product = match &name {
        Some(name) => cut_name(&ascii_name(name), INQUIRY_PRODUCT_SIZE),
        None => default_inquiry_product(cdrom).to_string(),
    };
    let usb_product = match &name {
        Some(name) => cut_name(name, USB_PRODUCT_SIZE),
        None => USB_PRODUCT_DEFAULT.to_string(),
    };
    MountMode {
        cdrom,
        ro_flag: if has_image { "1" } else { "0" },
        cdrom_flag: if cdrom { "1" } else { "0" },
        inquiry: inquiry_data(&inquiry_product),
        usb_product,
    }
}

/// File name without the extension; the host shows it for the medium and the device.
fn image_name(path: &Path) -> Option<String> {
    let name: String = path
        .file_stem()?
        .to_string_lossy()
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// SCSI inquiry fields are ASCII.
fn ascii_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect()
}

/// Cuts a name to at most `size` bytes without splitting a character.
fn cut_name(name: &str, size: usize) -> String {
    if name.len() <= size {
        return name.to_string();
    }
    let mut end = size;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

fn default_inquiry_product(cdrom: bool) -> &'static str {
    if cdrom {
        "USB CD/DVD-ROM"
    } else {
        "USB Mass Storage"
    }
}

fn validate_mount_mode(image: &Path, cdrom: bool) -> Result<()> {
    match image_kind(image) {
        Some(ImageKind::Iso) => Ok(()),
        Some(ImageKind::MassStorage) if cdrom => Err(AppError::BadRequest(
            "IMG images must be mounted in Mass Storage mode".to_string(),
        )),
        Some(ImageKind::MassStorage) => Ok(()),
        None => Err(AppError::BadRequest(
            "only .iso and .img images are allowed".to_string(),
        )),
    }
}

fn inquiry_data(product: &str) -> String {
    format!("{:<8}{:<16}{:04x}", "NanoKVM", product, 0x0520)
}

pub(crate) async fn eject_lun() -> Result<()> {
    write_lun_file(b"\n")?;
    time::sleep(MEDIA_SETTLE_DELAY).await;
    Ok(())
}

/// Like `eject_lun`, for a caller that does not need the medium: a gadget built without the
/// virtual disk has no mass storage function, so there is nothing to release.
pub(crate) async fn release_lun() -> Result<()> {
    if !Path::new(MOUNT_DEVICE).exists() {
        return Ok(());
    }
    eject_lun().await
}

fn write_lun_file(contents: &[u8]) -> Result<()> {
    fs::write(MOUNT_DEVICE, contents).map_err(lun_write_error)
}

/// The kernel refuses to change the medium with EBUSY while the host has locked it.
fn lun_write_error(err: std::io::Error) -> AppError {
    if is_busy_error(&err) {
        AppError::Api {
            code: MEDIA_LOCKED_CODE,
            msg: MEDIA_LOCKED_MESSAGE.to_string(),
        }
    } else {
        AppError::Internal(format!("{MOUNT_DEVICE}: {err}"))
    }
}

fn is_busy_error(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::ResourceBusy || err.raw_os_error() == Some(nix::libc::EBUSY)
}

fn read_cdrom_flag() -> Result<bool> {
    let value = read_trimmed(CDROM_FLAG)?;
    Ok(value == "1")
}

async fn reset_usb_gadget() -> Result<()> {
    disconnect_gadget().await?;
    connect_gadget().await
}

async fn disconnect_gadget() -> Result<()> {
    if let Err(err) = hid_ws::close_cached_hid_devices() {
        tracing::warn!(error = %err, "failed to close cached HID devices before USB gadget reset");
    }

    // Unbinding a gadget that is already down fails with ENODEV.
    if !gadget_is_down() {
        fs::write(UDC_FILE, b"\n")?;
    }
    time::sleep(Duration::from_secs(1)).await;
    Ok(())
}

async fn connect_gadget() -> Result<()> {
    let udc = first_udc()?;
    fs::write(UDC_FILE, format!("{udc}\n").as_bytes())?;
    time::sleep(Duration::from_millis(300)).await;
    Ok(())
}

fn gadget_is_down() -> bool {
    read_trimmed(UDC_FILE)
        .map(|udc| udc.is_empty())
        .unwrap_or(false)
}

fn first_udc() -> Result<String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(UDC_CLASS_DIR)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    names
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Internal("no USB device controller found".to_string()))
}

fn read_trimmed(path: &str) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

/// The LUN's backing file, or an empty string in HID-only mode, where the gadget has no
/// mass-storage function and the file does not exist.
fn read_lun_file(path: &str) -> Result<String> {
    match read_trimmed(path) {
        Err(AppError::Io(err)) if err.kind() == ErrorKind::NotFound => Ok(String::new()),
        other => other,
    }
}

fn has_image_extension(path: &Path) -> bool {
    image_kind(path).is_some()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImageKind {
    Iso,
    MassStorage,
}

fn image_kind(path: &Path) -> Option<ImageKind> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(|ext| {
            if ext.eq_ignore_ascii_case("iso") {
                Some(ImageKind::Iso)
            } else if ext.eq_ignore_ascii_case("img") {
                Some(ImageKind::MassStorage)
            } else {
                None
            }
        })
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, os::unix::fs as unix_fs};
    use tempfile::tempdir;

    #[test]
    fn cdrom_flag_defaults_to_zero_without_a_lun() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("lun.0/cdrom");

        // the gadget has no mass-storage function, so the flag file does not exist
        let raw = read_lun_file(missing.to_str().unwrap()).unwrap();
        assert_eq!(parse_cdrom_flag(&raw).unwrap(), 0);
        assert_eq!(parse_cdrom_flag("1").unwrap(), 1);
        assert_eq!(parse_cdrom_flag("0").unwrap(), 0);
        assert!(parse_cdrom_flag("yes").is_err());
    }

    #[test]
    fn accepts_image_inside_storage_root() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("installer.iso");
        File::create(&image).unwrap();

        assert_eq!(
            valid_image_path("installer.iso", dir.path()).unwrap(),
            image
        );
    }

    #[test]
    fn rejects_path_traversal_image_path() {
        let dir = tempdir().unwrap();
        let outside = dir.path().parent().unwrap().join("outside.iso");
        File::create(&outside).unwrap();

        let err = valid_image_path("../outside.iso", dir.path()).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn rejects_absolute_path_outside_storage_root() {
        let dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();
        let outside = outside_dir.path().join("outside.iso");
        File::create(&outside).unwrap();

        let err = valid_image_path(&path_to_string(&outside), dir.path()).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn rejects_symlinked_image() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.iso");
        let link = dir.path().join("link.iso");
        File::create(&real).unwrap();
        unix_fs::symlink(&real, &link).unwrap();

        let err = valid_image_path("link.iso", dir.path()).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn rejects_non_image_extension() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("notes.txt");
        File::create(&file).unwrap();

        let err = valid_image_path("notes.txt", dir.path()).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn writable_directory_passes_the_read_only_guard() {
        let dir = tempdir().unwrap();
        assert!(ensure_writable(dir.path()).is_ok());
        // A path that does not exist yet is judged by its nearest existing parent.
        assert!(ensure_writable(&dir.path().join("missing/cache")).is_ok());
        assert!(!is_read_only_fs(dir.path()).unwrap());
    }

    #[test]
    fn mount_mode_sets_cdrom_only_for_images_requested_as_cdrom() {
        let cdrom = mount_mode(Some(Path::new("installer.iso")), true);
        assert!(cdrom.cdrom);
        assert_eq!(cdrom.cdrom_flag, "1");

        let mass_storage = mount_mode(Some(Path::new("disk.img")), false);
        assert!(!mass_storage.cdrom);
        assert_eq!(mass_storage.cdrom_flag, "0");

        let default_media = mount_mode(None, true);
        assert!(!default_media.cdrom);
        assert_eq!(default_media.cdrom_flag, "0");
        assert!(default_media.inquiry.contains("USB Mass Storage"));
        assert_eq!(default_media.usb_product, "NanoKVM");
    }

    #[test]
    fn mounted_images_are_always_read_only() {
        for (image, cdrom) in [
            ("installer.iso", true),
            ("installer.iso", false),
            ("disk.img", false),
        ] {
            let mode = mount_mode(Some(Path::new(image)), cdrom);
            assert_eq!(mode.ro_flag, "1", "{image} cdrom={cdrom}");
        }
        assert_eq!(mount_mode(None, false).ro_flag, "0");
    }

    #[test]
    fn media_are_named_after_the_image() {
        let mode = mount_mode(Some(Path::new("/data/Fedora-Workstation-Live.iso")), true);
        assert!(mode.inquiry.contains("Fedora-Workstati"));
        assert_eq!(mode.usb_product, "Fedora-Workstation-Live");
    }

    #[test]
    fn inquiry_string_stays_28_bytes() {
        for name in [
            "a.iso",
            "ünïcödé-dïsk-ïmägé-with-a-long-name.iso",
            "x".repeat(40).as_str(),
        ] {
            let mode = mount_mode(Some(Path::new(name)), false);
            assert_eq!(mode.inquiry.len(), 28, "{name}");
        }
    }

    #[test]
    fn cut_name_never_splits_a_character() {
        assert_eq!(cut_name("abc", 16), "abc");
        assert_eq!(cut_name("ääää", 3), "ä");
        assert_eq!(cut_name("日本語", 4), "日");
    }

    #[test]
    fn a_missing_lun_file_means_nothing_is_mounted() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");

        // HID-only mode: the mass-storage function, and so the file, is absent.
        assert_eq!(read_lun_file(file.to_str().unwrap()).unwrap(), "");

        fs::write(&file, " /data/a.iso\n").unwrap();
        assert_eq!(
            read_lun_file(file.to_str().unwrap()).unwrap(),
            "/data/a.iso"
        );

        // Any other read failure is still reported.
        assert!(read_lun_file(dir.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn mounted_file_hides_the_raw_partition_and_the_deleted_marker() {
        assert_eq!(mounted_file(""), "");
        assert_eq!(mounted_file(IMAGE_NONE), "");
        assert_eq!(mounted_file("/data/a.iso"), "/data/a.iso");
        assert_eq!(mounted_file("/data/a.iso (deleted)"), "/data/a.iso");
        assert_eq!(
            mounted_file("/data/a (deleted) b.iso"),
            "/data/a (deleted) b.iso"
        );
        // Only one marker comes off.
        assert_eq!(
            mounted_file("/data/a (deleted) (deleted)"),
            "/data/a (deleted)"
        );
    }

    #[test]
    fn lun_serves_the_image_even_after_it_was_replaced() {
        let image = Path::new("/data/installer.iso");
        assert!(lun_serves("/data/installer.iso", image));
        assert!(lun_serves("/data/installer.iso (deleted)", image));
        assert!(!lun_serves("/data/other.iso", image));
        assert!(!lun_serves("/data/other.iso (deleted)", image));
        assert!(!lun_serves("", image));
        assert!(!lun_serves(IMAGE_NONE, image));
    }

    #[test]
    fn lun_serves_follows_a_symlinked_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let image = real.join("installer.iso");
        fs::write(&image, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let canonical = fs::canonicalize(&image).unwrap();
        let via_link = link.join("installer.iso");
        assert!(lun_serves(via_link.to_str().unwrap(), &canonical));
        assert!(lun_serves(
            &format!("{} (deleted)", via_link.to_str().unwrap()),
            &canonical
        ));
    }

    #[test]
    fn a_locked_medium_is_reported_with_its_own_code() {
        let busy = lun_write_error(std::io::Error::from_raw_os_error(nix::libc::EBUSY));
        assert!(
            matches!(&busy, AppError::Api { code, msg }
                if *code == MEDIA_LOCKED_CODE && msg.contains("busy on the remote host")),
            "{busy:?}"
        );

        let other = lun_write_error(std::io::Error::from_raw_os_error(nix::libc::EACCES));
        assert!(!matches!(other, AppError::Api { .. }), "{other:?}");
    }

    #[test]
    fn a_missing_lun_is_explained() {
        let err = no_lun_error();
        assert!(
            matches!(&err, AppError::Conflict(msg)
                if msg.contains("virtual disk is off") && msg.contains("HID-only")),
            "{err:?}"
        );
    }

    #[test]
    fn mount_requests_only_force_when_asked_to() {
        let plain: MountImageReq =
            serde_json::from_str(r#"{"file":"a.iso","cdrom":true}"#).unwrap();
        assert!(!plain.force);
        let empty: MountImageReq = serde_json::from_str("{}").unwrap();
        assert!(!empty.force && empty.file.is_empty() && !empty.cdrom);

        let forced: MountImageReq =
            serde_json::from_str(r#"{"file":"","cdrom":false,"force":true}"#).unwrap();
        assert!(forced.force);
    }

    #[test]
    fn validates_mount_mode_by_image_extension() {
        assert!(validate_mount_mode(Path::new("installer.iso"), true).is_ok());
        assert!(validate_mount_mode(Path::new("installer.iso"), false).is_ok());
        assert!(validate_mount_mode(Path::new("disk.img"), false).is_ok());

        let err = validate_mount_mode(Path::new("disk.img"), true).unwrap_err();
        assert!(err.to_string().contains("Mass Storage mode"));
    }
}
