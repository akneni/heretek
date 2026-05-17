use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub trusted_binaries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub trusted_binaries: HashSet<String>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            trusted_binaries: vec![],
        }
    }
}

impl Config {
    pub fn from(cfg_file: &ConfigFile) -> Self {
        Self {
            trusted_binaries: cfg_file.trusted_binaries.clone().into_iter().collect(),
        }
    }
}
