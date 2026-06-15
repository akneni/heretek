use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
pub use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct HtekDirs {
    dirs: ProjectDirs,
}

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
        profiles.insert("resonable".to_string(), vec![]);
        profiles.insert("resonable-nogui".to_string(), vec![]);
        profiles.insert("hardened".to_string(), vec!["/usr/bin/npm".to_string()]);

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
    pub fn config_dir(&self) -> &Path {
        self.dirs.config_dir()
    }

    pub fn data_dir(&self) -> &Path {
        self.dirs.data_dir()
    }

    /// Returns the pack to the Unix Domain Socket
    /// Creates its parent directory if it doesnt already exist
    pub fn socket_path(&self) -> Result<PathBuf> {
        fs::create_dir_all(self.data_dir())?;
        Ok(self.data_dir().join("RPC.sock"))
    }

    /// Returns the path to the directory that sould contain the eBPF objects
    pub fn bpf_obj_path(&self) -> Result<PathBuf> {
        let bpf_dir = self.data_dir().join("bpf_objects");
        fs::create_dir_all(&bpf_dir)?;
        Ok(bpf_dir)
    }
}

impl LoadedConfig {
    pub fn load() -> Result<Self> {
        validate_environment()?;

        let dirs = ProjectDirs::from("com", "heretek", "heretek")
            .context("No valid home directory could be found")?;
        let hdirs = HtekDirs { dirs };
        fs::create_dir_all(hdirs.config_dir())?;

        let config_path = hdirs.config_dir().join("config.json");
        if !config_path.exists() {
            fs::write(
                &config_path,
                serde_json::to_string_pretty(&ConfigFile::default())?,
            )?;
        }

        let file = serde_json::from_str(&fs::read_to_string(config_path)?)
            .context("Failed to parse ConfigFile")?;

        Ok(LoadedConfig { dirs: hdirs, file })
    }
}

pub fn validate_environment() -> Result<()> {
    if "root" != whoami::account()? {
        bail!("Heretek needs to be run as root");
    }
    if whoami::platform() != whoami::Platform::Linux {
        bail!("Unsupported platform; Heretek currently supports Linux");
    }
    Ok(())
}
