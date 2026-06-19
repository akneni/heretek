use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

use htek_lib::config::{LoadedConfig, ProfileConfigFile};

use crate::{build_params, detection::Acl};

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Config {
    pub profile_config: ProfileConfig,
    pub quarentine: Vec<String>,
    pub acl: Acl,
}

/// This struct allows us to determine which profile an actro should be
#[derive(Debug, Clone)]
pub struct ProfileConfig {
    default: String,

    // {profile_name: Set[binaries with that profile]}
    mappings: HashMap<String, HashSet<PathBuf>>,
}

impl Config {
    pub fn from(loaded: LoadedConfig, acl: Acl) -> Self {
        let cfg_file = loaded.file;
        Self {
            profile_config: ProfileConfig::from(&cfg_file.profile_config),
            quarentine: cfg_file.quarentine,
            acl,
        }
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

    pub fn profile_exists(&self, profile: &str) -> bool {
        self.mappings.contains_key(profile)
    }
}

impl ProfileConfig {
    /// PRECONDITION: bin should be the conacical/absolute path to the binary
    pub fn get_profile<'a>(&'a self, bin: &PathBuf) -> &'a str {
        if build_params::ASSERTS
            && let Ok(bin_abs) = fs::canonicalize(bin)
        {
            assert_eq!(&bin_abs, bin);
        }

        for (k, v) in self.mappings.iter() {
            if v.contains(bin) {
                return k;
            }
        }
        &self.default
    }
}
