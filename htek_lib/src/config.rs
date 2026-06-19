use std::{collections::HashMap, fs};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::htdirs;

pub const CONFIG_JSON: &str = include_str!("../../documentation/docs_usr/config.json");
pub const ACL_JSON: &str = include_str!("../../documentation/docs_usr/ACL.json");

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

impl ConfigFile {
    pub fn load() -> Result<Self> {
        validate_environment()?;

        let config_path = htdirs::cfgfile_path();
        if !config_path.exists() {
            fs::write(
                &config_path,
                serde_json::to_string_pretty(&ConfigFile::default())?,
            )?;
        }

        let file: Self = serde_json::from_str(&fs::read_to_string(config_path)?)
            .context("Failed to parse ConfigFile")?;

        Ok(file)
    }
}

pub fn validate_environment() -> Result<()> {
    htdirs::validate_environment()
}
