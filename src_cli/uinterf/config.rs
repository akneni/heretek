use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

use anyhow::{Result, bail};
use directories::ProjectDirs;

use crate::{
    build_params,
    detection::Acl,
    uinterf::{ConfigFile, ProfileConfigFile},
};

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Config {
    pub profile_config: ProfileConfig,
    pub quarentine: Vec<String>,
    pub htek_repo: Option<String>,
    pub acl: Acl,
    pub dirs: ProjectDirs,
}

/// This struct allows us to determine which profile an actro should be
#[derive(Debug, Clone)]
pub struct ProfileConfig {
    default: String,
    mappings: HashMap<String, HashSet<PathBuf>>,
}

impl Config {
    pub fn from(cfg_file: ConfigFile, acl: Acl) -> Result<Self> {
        let dirs = match ProjectDirs::from("com", "heretek", "heretek") {
            Some(r) => r,
            None => {
                bail!("Failed to find home path");
            }
        };
        let s = Self {
            profile_config: ProfileConfig::from(&cfg_file.profile_config),
            quarentine: cfg_file.quarentine,
            htek_repo: cfg_file.htek_repo,
            acl,
            dirs,
        };
        Ok(s)
    }

    pub fn alert_log_path(&self) -> PathBuf {
        self.dirs.data_dir().join("alerts.log")
    }
}

impl ProfileConfig {
    pub fn from(cfg_file: &ProfileConfigFile) -> Self {
        let mut mappings = HashMap::new();

        for (profile, bins) in cfg_file.profiles.iter() {
            let mut mapped_bins = HashSet::new();

            for bin in bins {
                let path = PathBuf::from(bin);
                mapped_bins.insert(fs::canonicalize(&path).unwrap_or(path));
            }

            mappings.insert(profile.clone(), mapped_bins);
        }

        Self {
            default: cfg_file.default.clone(),
            mappings,
        }
    }
}

impl ProfileConfig {
    /// PRECONDITION: bin should be the conacical/absolute path to the binary
    pub fn get_profile<'a>(&'a self, bin: &PathBuf) -> &'a str {
        if build_params::ASSERTS {
            if let Ok(bin_abs) = fs::canonicalize(bin) {
                assert_eq!(&bin_abs, bin);
            }
        }

        for (k, v) in self.mappings.iter() {
            if v.contains(bin) {
                return k;
            }
        }
        &self.default
    }
}
