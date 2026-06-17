use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// A file with this name is put in the config directory
/// If the config directory exists without this file being present, we assume that the
/// name "heretek" collides with another application already installed on the system.
const HTEK_MAGIC_STR: &str = "X2fQ147uQnwXTcch9i";

pub const CONFIG_JSON: &str = include_str!("../../documentation/docs_usr/config.json");
pub const ACL_JSON: &str = include_str!("../../documentation/docs_usr/ACL.json");

#[derive(Debug, Clone)]
pub struct HtekDirs;

#[derive(Debug)]
pub struct LoadedConfig {
    pub dirs: HtekDirs,
    pub file: ConfigFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub profile_config: ProfileConfigFile,
    pub quarentine: Vec<String>,
    pub htek_repo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfigFile {
    pub default: String,
    pub profiles: HashMap<String, Vec<String>>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert("unchained".to_string(), vec![]);
        profiles.insert("hardened".to_string(), vec![]);

        Self {
            profile_config: ProfileConfigFile {
                default: "unchained".to_string(),
                profiles,
            },
            quarentine: vec!["kill".to_string(), "quarentine".to_string()],
            htek_repo: None,
        }
    }
}

impl HtekDirs {
    const CFG_DIR: &str = "/root/.config/heretek/";
    const DATA_DIR: &str = "/root/.local/share/heretek/";

    pub fn config_dir(&self) -> &Path {
        Path::new(Self::CFG_DIR)
    }

    pub fn data_dir(&self) -> &Path {
        Path::new(Self::DATA_DIR)
    }

    pub fn config_path(&self) -> PathBuf {
        self.config_dir().join("config.json")
    }

    pub fn acl_path(&self) -> PathBuf {
        self.config_dir().join("ACL.json")
    }

    /// Returns the pack to the Unix Domain Socket
    pub fn socket_path(&self) -> PathBuf {
        self.data_dir().join("RPC-root.sock")
    }

    /// Returns the path to the directory that sould contain the eBPF objects
    pub fn bpf_obj_path(&self) -> PathBuf {
        let bpf_dir = self.data_dir().join("bpf_objects");
        bpf_dir
    }

    pub fn violation_log_path(&self) -> PathBuf {
        self.data_dir().join("violations.log")
    }

    pub fn tracefile_path(&self) -> PathBuf {
        self.data_dir().join("daemon_traces.log")
    }

    pub fn htek_magic_file_path(&self) -> PathBuf {
        self.config_dir().join(HTEK_MAGIC_STR)
    }
}

impl LoadedConfig {
    pub fn load() -> Result<Self> {
        validate_environment()?;

        let hdirs = HtekDirs;

        let config_path = hdirs.config_path();
        if !config_path.exists() {
            fs::write(
                &config_path,
                serde_json::to_string_pretty(&ConfigFile::default())?,
            )?;
        }

        let file = serde_json::from_str(&fs::read_to_string(config_path)?)
            .context("Failed to parse ConfigFile")?;

        Ok(LoadedConfig {
            dirs: HtekDirs,
            file,
        })
    }
}

pub fn validate_environment() -> Result<()> {
    if whoami::platform() != whoami::Platform::Linux {
        bail!("Unsupported platform; Heretek currently supports Linux");
    }

    let mfile = HtekDirs.htek_magic_file_path();
    if !mfile.exists() {
        if whoami::account()? != "root" {
            bail!(
                "The heretek directoies don't seem to be initalized. Please run `sudo htek init`"
            );
        }

        if HtekDirs.config_dir().exists() || HtekDirs.data_dir().exists() {
            bail!("Htek Directories found without magic file. Possible application name clash?");
        }

        // Create all config and data directories
        fs::create_dir_all(HtekDirs.config_dir())?;
        fs::create_dir_all(HtekDirs.data_dir())?;
        fs::create_dir_all(HtekDirs.bpf_obj_path())?;
        fs::set_permissions(HtekDirs.config_dir(), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(HtekDirs.data_dir(), fs::Permissions::from_mode(0o755))?;

        // Create config files
        fs::write(HtekDirs.config_path(), CONFIG_JSON)?;
        fs::write(HtekDirs.acl_path(), ACL_JSON)?;
        fs::set_permissions(HtekDirs.config_path(), fs::Permissions::from_mode(0o644))?;

        // Create magic file
        fs::write(
            &mfile,
            "This file prevents collitions on the name heretek. Ignore it but dont delete it.",
        )?;
        fs::set_permissions(&mfile, fs::Permissions::from_mode(0o644))?;
    }

    Ok(())
}
