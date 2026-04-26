use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclJsonFile {
    pub protectees: Vec<String>,
    #[serde(rename = "default")]
    pub default_mode: String,
    #[serde(flatten)]
    pub rules: HashMap<String, Vec<String>>,
}
