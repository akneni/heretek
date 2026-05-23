use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::detection::{AclJsonFile, PolicyVerdict, Protectee, ProtecteeSet};
use crate::pgraph::AccessType;

#[derive(Debug, Clone)]
pub struct AclBlock {
    protectees: ProtecteeSet,
    default: AccessType,
    exceptions: HashMap<String, AccessType>,
}

#[derive(Debug, Clone)]
pub struct Acl {
    pub blocks: Vec<AclBlock>,
}

impl AclBlock {
    /// If a process doesn’t match any of the explicit permissions (rwx, rw-, etc.),
    /// it will use the permissions specified by default. If a process matches multiple
    /// explicit permissions groups, it’s permissions will be the intersection of all the permissions.
    pub fn get_atype_for_profile(&self, prof: &String) -> AccessType {
        self.exceptions
            .get(prof)
            .map(|&x| x)
            .unwrap_or(self.default)
    }
}

impl Acl {
    pub fn from_acl_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let vec: Vec<AclJsonFile> = serde_json::from_str(&contents)?;
        Self::from(vec)
    }

    pub fn from(acl_json: Vec<AclJsonFile>) -> Result<Self> {
        let mut blocks = Vec::new();

        for block in acl_json {
            let protectees = ProtecteeSet::from_strings(block.protectees)?;
            let default = AccessType::from_str(&block.default_mode)?;
            let mut exceptions = HashMap::new();

            for (mode, profiles) in block.rules {
                let access = AccessType::from_str(&mode)?;

                for profile in profiles {
                    exceptions
                        .entry(profile)
                        .and_modify(|existing: &mut AccessType| existing.intersection(access))
                        .or_insert(access);
                }
            }

            blocks.push(AclBlock {
                protectees,
                default,
                exceptions,
            });
        }

        Ok(Self { blocks })
    }

    /// Top level function for detecting violations
    /// If any one of the profiles accessed the file in a way that is not permitted, then its a violation
    pub fn check_violation(
        &self,
        profiles: &HashSet<String>,
        file: &PathBuf,
        mode: AccessType,
    ) -> PolicyVerdict {
        for ablocks in &self.blocks {
            if !ablocks.protectees.contains_file(file) {
                continue;
            }

            for prof in profiles.iter() {
                let atype = ablocks.get_atype_for_profile(prof);
                if !atype.is_superset_of(mode) {
                    return PolicyVerdict::Violation {
                        prote: Protectee::File(file.clone()),
                        attempted_access: mode,
                    };
                }
            }
            break;
        }

        PolicyVerdict::Benign
    }
}
