use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use anyhow::{Context, Result};

pub fn ensure_dir_0700<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("failed to create directory: {}", path.display()))?;
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to change directory permission: {}", path.display()))?;
    }
    Ok(())
}

pub fn ensure_file_0600<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to change file permission: {}", path.display()))?;
    Ok(())
}