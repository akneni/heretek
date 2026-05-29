use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
