use std::path::{Path, PathBuf};

use crate::{AppError, Result};

pub fn clean_relative_path(input: &Path) -> Result<PathBuf> {
    if input.is_absolute() {
        return Err(AppError::BadRequest(
            "absolute paths are not allowed".to_string(),
        ));
    }

    let mut out = PathBuf::new();
    for component in input.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => {
                return Err(AppError::BadRequest(
                    "path traversal is not allowed".to_string(),
                ));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(AppError::BadRequest(
            "empty path is not allowed".to_string(),
        ));
    }
    Ok(out)
}
