use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::{fs, path::Path};

use anyhow::Result;
use rustix::fs::{Gid, Uid};

use crate::htdirs;

pub fn set_root_owned_public(fpath: &Path) -> Result<()> {
    rustix::fs::chown(fpath, Some(Uid::ROOT), Some(Gid::ROOT))?;
    fs::set_permissions(fpath, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// Returns true if someone is listening on the heretek UDS
pub fn server_is_occupied() -> bool {
    let path = htdirs::socket_path_root();
    if path.exists() && UnixStream::connect(path).is_ok() {
        return true;
    }

    let path = htdirs::socket_path_any();
    if path.exists() && UnixStream::connect(path).is_ok() {
        return true;
    }
    false
}
