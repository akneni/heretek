use std::collections::HashMap;
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{acl_file::AclJsonFile, actor::AccessType};



#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Protectee {
    File(String),
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Profile {
    Profile(String),
    Binary(String),
    ProfedBin{b: String, p: String},
}

#[derive(Debug, Clone)]
pub struct AclBlock {
    default: AccessType,
    exceptions: HashMap<Profile, AccessType>,
}

#[derive(Debug, Clone)]
pub struct Acl {
    pub blocks: HashMap<Protectee, AclBlock>,
}

impl AclBlock {
    /// If a process doesn’t match any of the explicit permissions (rwx, rw-, etc.), 
    /// it will use the permissions specified by default. If a process matches multiple 
    /// explicit permissions groups, it’s permissions will be the intersection of all the permissions. 
    pub fn get_atype_for_profile(&self, prof: &Profile) -> AccessType {
        let mut matched = false;
        let mut atype = self.default;

        let matches = |candidate: &Profile, target: &Profile| match (candidate, target) {
            (Profile::Binary(a), Profile::Binary(b)) => a == b,
            (Profile::Profile(a), Profile::Profile(b)) => a == b,
            (Profile::Binary(a), Profile::ProfedBin { b, .. }) => a == b,
            (Profile::Profile(a), Profile::ProfedBin { p, .. }) => a == p,
            (Profile::ProfedBin { b: ab, p: ap }, Profile::ProfedBin { b: tb, p: tp }) => {
                ab == tb && ap == tp
            }
            _ => false,
        };

        for (candidate, access) in &self.exceptions {
            if matches(candidate, prof) {
                if matched {
                    atype.intersection(*access);
                } else {
                    atype = *access;
                    matched = true;
                }
            }
        }

        if matched {
            atype
        } else {
            self.default
        }
    }
}

impl Acl {
    pub fn from(acl_json: Vec<AclJsonFile>) -> Result<Self> {
        let mut blocks = HashMap::new();

        for entry in acl_json {
            let default = AccessType::from_rwx_str(&entry.default_mode)?;
            let mut exceptions = HashMap::new();

            for (mode, subjects) in entry.rules {
                let access = AccessType::from_rwx_str(&mode)?;
                for subject in subjects {
                    let profile = if subject.starts_with('/') {
                        Profile::Binary(subject)
                    } else {
                        Profile::Profile(subject)
                    };
                    exceptions.insert(profile, access);
                }
            }

            for protectee in entry.protectees {
                blocks.insert(
                    Protectee::File(protectee),
                    AclBlock {
                        default,
                        exceptions: exceptions.clone(),
                    },
                );
            }
        }

        Ok(Self { blocks })
    }
}
