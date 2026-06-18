use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};

use crate::config::{ACL_JSON, CONFIG_JSON};

/// A file with this name is put in the config directory.
/// If the config directory exists without this file being present, we assume
/// that the name "heretek" collides with another application already installed
/// on the system.
const HTEK_MAGIC_STR: &str = ".X2fQ147uQnwXTcch9i";

const DATA_DIR: &str = "/usr/local/bin/heretek";
const UDS_DIR: &str = "/run/heretek/";

// /usr/local/bin/htek

pub fn data_dir() -> &'static Path {
    Path::new(DATA_DIR)
}

pub fn config_dir() -> PathBuf {
    data_dir().join("config")
}

pub fn cfgfile_path() -> PathBuf {
    config_dir().join("config.json")
}

pub fn acl_path() -> PathBuf {
    config_dir().join("ACL.json")
}

/// Returns the path to the Unix Domain Socket.
pub fn socket_path_root() -> PathBuf {
    Path::new(UDS_DIR).join("htek-rpc-root.sock")
}

pub fn socket_path_any() -> PathBuf {
    Path::new(UDS_DIR).join("htek-rpc-any.sock")
}

/// Returns the path to the directory that should contain the eBPF objects.
pub fn bpf_obj_path() -> PathBuf {
    data_dir().join("bpf_objects")
}

pub fn violation_log_path() -> PathBuf {
    data_dir().join("violations.log")
}

pub fn tracefile_path() -> PathBuf {
    data_dir().join("daemon_traces.log")
}

pub fn htek_magic_file_path() -> PathBuf {
    data_dir().join(HTEK_MAGIC_STR)
}

pub fn validate_environment() -> Result<()> {
    if whoami::platform() != whoami::Platform::Linux {
        bail!("Unsupported platform; Heretek currently supports Linux");
    }

    let mfile = htek_magic_file_path();
    if !mfile.exists() {
        if whoami::account()? != "root" {
            bail!(
                "The heretek directoies don't seem to be initalized. Please run `sudo htek init`"
            );
        }

        if config_dir().exists() || data_dir().exists() {
            bail!("Htek Directories found without magic file. Possible application name clash?");
        }

        fs::create_dir_all(config_dir())?;
        fs::create_dir_all(data_dir())?;
        fs::create_dir_all(bpf_obj_path())?;
        fs::set_permissions(config_dir(), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(data_dir(), fs::Permissions::from_mode(0o755))?;

        fs::write(cfgfile_path(), CONFIG_JSON)?;
        fs::write(acl_path(), ACL_JSON)?;
        fs::set_permissions(cfgfile_path(), fs::Permissions::from_mode(0o644))?;

        fs::write(
            &mfile,
            "This file prevents collitions on the name heretek. Ignore it but dont delete it.",
        )?;
        fs::set_permissions(&mfile, fs::Permissions::from_mode(0o644))?;
    }

    Ok(())
}
