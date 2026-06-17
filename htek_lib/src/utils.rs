use std::os::unix::fs::PermissionsExt;
use std::{fs, path::Path};

use anyhow::Result;
use rustix;
use rustix::fs::{Gid, Uid};

///
pub fn set_root_owned_public(fpath: &Path) -> Result<()> {
    rustix::fs::chown(fpath, Some(Uid::ROOT), Some(Gid::ROOT))?;
    fs::set_permissions(fpath, fs::Permissions::from_mode(0o644))?;
    Ok(())
}
