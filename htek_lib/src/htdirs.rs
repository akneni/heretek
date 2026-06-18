use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// A file with this name is put in the config directory.
/// If the config directory exists without this file being present, we assume
/// that the name "heretek" collides with another application already installed
/// on the system.
const HTEK_MAGIC_STR: &str = ".X2fQ147uQnwXTcch9i";

const DATA_DIR: &str = "/usr/local/bin/heretek";
const UDS_DIR: &str = "/run/heretek/";

pub fn data_dir() -> &'static Path {
    Path::new(DATA_DIR)
}

pub fn uds_dir() -> &'static Path {
    Path::new(UDS_DIR)
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
        bail!("Heretek directoried not yet setup");
    }

    Ok(())
}
