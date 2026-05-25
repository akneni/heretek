use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclProfileJsonFile {
    #[serde(default)]
    pub inherits: Option<String>,
    pub rules: HashMap<String, String>,
}

pub type AclJsonFile = HashMap<String, AclProfileJsonFile>;
