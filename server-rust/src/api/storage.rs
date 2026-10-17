use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time;

use crate::{
    AppError, Result,
    error::ApiResponse,
    state::AppState,
    system::{files::clean_relative_path, media, usb},
    ws::hid as hid_ws,
};

const CDROM_FLAG: &str =
    "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/cdrom";
const MOUNT_DEVICE: &str =
    "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/file";
const INQUIRY_STRING: &str =
    "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/inquiry_string";
const RO_FLAG: &str = "/sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/ro";
const UDC_FILE: &str = "/sys/kernel/config/usb_gadget/g0/UDC";
const UDC_CLASS_DIR: &str = "/sys/class/udc";
const MEDIA_SETTLE_DELAY: Duration = Duration::from_millis(100);

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
    if state.config.paths.image_directory.exists() {
        media::checked_media_root(&state.config.paths.image_directory)?;
    }
    collect_images(&state.config.paths.image_directory, &mut files)?;
    files.sort();

    Ok(Json(ApiResponse::ok(GetImagesRsp { files })))
}

pub async fn get_mounted_image() -> Result<impl IntoResponse> {
    let image = read_trimmed(MOUNT_DEVICE)?;

    Ok(Json(ApiResponse::ok(GetMountedImageRsp { file: image })))
}

pub async fn get_cdrom() -> Result<impl IntoResponse> {
    let flag = read_trimmed(CDROM_FLAG)?;
    let cdrom = flag
        .parse::<i64>()
        .map_err(|_| AppError::BadRequest("parse failed".to_string()))?;

    Ok(Json(ApiResponse::ok(GetCdRomRsp { cdrom })))
}

pub async fn mount_image(
    State(state): State<AppState>,
    Json(req): Json<MountImageReq>,
) -> Result<impl IntoResponse> {
    usb::run_exclusive(async move { mount_image_locked(&state, req).await }).await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

async fn mount_image_locked(state: &AppState, req: MountImageReq) -> Result<()> {
    let previous_cdrom = read_cdrom_flag().unwrap_or(false);

    let image = if req.file.trim().is_empty() {
        None
    } else {
        let image = valid_image_path(req.file.trim(), &state.config.paths.image_directory)?;
        validate_mount_mode(&image, req.cdrom)?;
        media::ensure_not_loop_backed(&image, Path::new("/sys/block"))?;
        Some(image)
    };

    let mode = mount_mode(image.is_some(), req.cdrom);
    eject_lun().await?;
    fs::write(RO_FLAG, mode.flag.as_bytes())?;
    fs::write(CDROM_FLAG, mode.flag.as_bytes())?;
    fs::write(INQUIRY_STRING, mode.inquiry.as_bytes())?;

    let mount_target = image
        .as_ref()
        .map(|path| path_to_string(path))
        .unwrap_or_default();
    // An empty request ejects the media. Never export the data partition as a
    // fallback: it contains private update state and is mounted by NanoKVM.
    if !mount_target.is_empty() {
        write_lun_file(mount_target.as_bytes())?;
    }
    time::sleep(MEDIA_SETTLE_DELAY).await;
    if previous_cdrom != mode.cdrom {
        reset_usb_gadget().await?;
    }

    Ok(())
}

pub async fn reconnect_usb_gadget() -> Result<impl IntoResponse> {
    usb::run_exclusive(reset_usb_gadget()).await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn delete_image(
    State(state): State<AppState>,
    Json(req): Json<DeleteImageReq>,
) -> Result<impl IntoResponse> {
    usb::run_exclusive(async move {
        let image = valid_image_path(req.file.trim(), &state.config.paths.image_directory)?;
        ensure_image_not_in_use(&image)?;
        fs::remove_file(image)?;
        Ok(())
    })
    .await?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
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
    media::checked_media_root(root)?;
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

    media::check_file(&candidate, root)?;

    let root = fs::canonicalize(root)?;
    let candidate = fs::canonicalize(candidate)?;
    if !candidate.starts_with(root) {
        return Err(AppError::BadRequest(
            "image path is outside storage".to_string(),
        ));
    }

    Ok(candidate)
}

fn mounted_image_matches(image: &Path) -> Result<bool> {
    let mounted = match read_trimmed(MOUNT_DEVICE) {
        Ok(mounted) => mounted,
        Err(AppError::Io(err)) if err.kind() == ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    if mounted.is_empty() {
        return Ok(false);
    }
    if Path::new(&mounted) == image {
        return Ok(true);
    }
    match fs::canonicalize(mounted) {
        Ok(mounted) => Ok(mounted == image),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn ensure_image_not_in_use(image: &Path) -> Result<()> {
    if mounted_image_matches(image)? {
        return Err(AppError::Conflict(
            "cannot replace or delete the currently mounted image".to_string(),
        ));
    }
    media::ensure_not_loop_backed(image, Path::new("/sys/block"))?;
    Ok(())
}

// Called before opening management listeners. App-only migration must close an
// already-active legacy raw LUN, not merely replace next-boot scripts.
pub fn secure_existing_storage() -> Result<()> {
    secure_storage_at(Path::new(MOUNT_DEVICE), Path::new(UDC_FILE))
}

fn secure_storage_at(lun: &Path, udc: &Path) -> Result<()> {
    match fs::symlink_metadata(lun) {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    }
    let close_result = fs::write(lun, b"\n").and_then(|()| {
        if fs::read_to_string(lun)?.trim().is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other("USB medium did not close"))
        }
    });
    if let Err(err) = close_result {
        // Vendor 5.10 has no forced_eject. A target can prevent removal. In
        // that case disconnect the whole gadget and refuse API startup.
        fs::write(udc, b"\n")?;
        return Err(AppError::Internal(format!(
            "legacy USB storage migration failed; gadget disconnected: {err}"
        )));
    }
    Ok(())
}

struct MountMode {
    cdrom: bool,
    flag: &'static str,
    inquiry: String,
}

fn mount_mode(has_image: bool, cdrom: bool) -> MountMode {
    let cdrom = has_image && cdrom;
    let flag = if cdrom { "1" } else { "0" };
    MountMode {
        cdrom,
        flag,
        inquiry: inquiry_data(cdrom),
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

fn inquiry_data(cdrom: bool) -> String {
    let product = if cdrom {
        "USB CD/DVD-ROM"
    } else {
        "USB Mass Storage"
    };
    format!("{:<8}{:<16}{:04x}", "NanoKVM", product, 0x0520)
}

async fn eject_lun() -> Result<()> {
    write_lun_file(b"\n")?;
    time::sleep(MEDIA_SETTLE_DELAY).await;
    Ok(())
}

fn write_lun_file(contents: &[u8]) -> Result<()> {
    fs::write(MOUNT_DEVICE, contents).map_err(|err| {
        if is_busy_error(&err) {
            AppError::Conflict(
                "virtual media is busy on the remote host; eject or unmount it there first"
                    .to_string(),
            )
        } else {
            err.into()
        }
    })
}

fn is_busy_error(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::ResourceBusy || err.raw_os_error() == Some(nix::libc::EBUSY)
}

fn read_cdrom_flag() -> Result<bool> {
    let value = read_trimmed(CDROM_FLAG)?;
    Ok(value == "1")
}

async fn reset_usb_gadget() -> Result<()> {
    if let Err(err) = hid_ws::close_cached_hid_devices() {
        tracing::warn!(error = %err, "failed to close cached HID devices before USB gadget reset");
    }

    // Resolve before disconnecting: failure to find a controller must leave
    // the existing gadget connected.
    let udc = first_udc()?;
    fs::write(UDC_FILE, b"\n")?;
    time::sleep(Duration::from_secs(1)).await;

    fs::write(UDC_FILE, format!("{udc}\n").as_bytes())?;
    time::sleep(Duration::from_millis(300)).await;
    Ok(())
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
    fn rejects_parent_alias_even_when_it_resolves_inside_media() {
        let dir = tempdir().unwrap();
        let actual = dir.path().join("actual");
        fs::create_dir(&actual).unwrap();
        File::create(actual.join("disk.img")).unwrap();
        unix_fs::symlink(&actual, dir.path().join("alias")).unwrap();
        assert!(valid_image_path("alias/disk.img", dir.path()).is_err());
    }

    #[test]
    fn rejects_private_raw_payload_despite_img_extension() {
        let dir = tempdir().unwrap();
        let media_root = dir.path().join("media");
        let private_root = dir.path().join(".hardened-kvmcache");
        fs::create_dir(&media_root).unwrap();
        fs::create_dir(&private_root).unwrap();
        let payload = private_root.join("rootfs.img");
        File::create(&payload).unwrap();
        assert!(valid_image_path(payload.to_str().unwrap(), &media_root).is_err());
        assert!(valid_image_path("../.hardened-kvmcache/rootfs.img", &media_root).is_err());
        unix_fs::symlink(&private_root, media_root.join("alias")).unwrap();
        assert!(valid_image_path("alias/rootfs.img", &media_root).is_err());
    }

    #[test]
    fn local_loop_backing_cannot_be_exported_or_replaced() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("disk.img");
        File::create(&image).unwrap();
        let block = dir.path().join("block");
        let sys_loop = block.join("loop0/loop");
        fs::create_dir_all(&sys_loop).unwrap();
        fs::write(
            sys_loop.join("backing_file"),
            format!("{}\n", image.display()),
        )
        .unwrap();
        assert!(matches!(
            media::ensure_not_loop_backed(&image, &block),
            Err(AppError::Conflict(_))
        ));
        fs::write(sys_loop.join("backing_file"), "").unwrap();
        assert!(media::ensure_not_loop_backed(&image, &block).is_ok());
    }

    #[test]
    fn startup_closes_existing_raw_lun() {
        let dir = tempdir().unwrap();
        let lun = dir.path().join("file");
        let udc = dir.path().join("UDC");
        fs::write(&lun, "/dev/mmcblk0p3\n").unwrap();
        fs::write(&udc, "controller\n").unwrap();
        secure_storage_at(&lun, &udc).unwrap();
        assert!(fs::read_to_string(&lun).unwrap().trim().is_empty());
        assert_eq!(fs::read_to_string(&udc).unwrap(), "controller\n");
    }

    #[test]
    fn failed_startup_lun_close_disconnects_gadget_and_refuses_startup() {
        let dir = tempdir().unwrap();
        let lun = dir.path().join("file");
        let udc = dir.path().join("UDC");
        // A directory makes the write fail deterministically, including root.
        fs::create_dir(&lun).unwrap();
        fs::write(&udc, "controller\n").unwrap();
        assert!(secure_storage_at(&lun, &udc).is_err());
        assert!(fs::read_to_string(&udc).unwrap().trim().is_empty());
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
    fn mount_mode_sets_cdrom_only_for_images_requested_as_cdrom() {
        let cdrom = mount_mode(true, true);
        assert!(cdrom.cdrom);
        assert_eq!(cdrom.flag, "1");
        assert!(cdrom.inquiry.contains("USB CD/DVD-ROM"));

        let mass_storage = mount_mode(true, false);
        assert!(!mass_storage.cdrom);
        assert_eq!(mass_storage.flag, "0");
        assert!(mass_storage.inquiry.contains("USB Mass Storage"));

        let default_media = mount_mode(false, true);
        assert!(!default_media.cdrom);
        assert_eq!(default_media.flag, "0");
        assert!(default_media.inquiry.contains("USB Mass Storage"));
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
