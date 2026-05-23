use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::detection::AclJsonFile;
use crate::pgraph::AccessType;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Protectee {
    File(PathBuf),
    Syscall(String),
}

#[derive(Debug, Clone)]
pub struct AclBlock {
    default: AccessType,
    exceptions: HashMap<String, AccessType>,
}

#[derive(Debug, Clone)]
pub struct Acl {
    pub blocks: HashMap<Protectee, AclBlock>,
}

impl AclBlock {
    /// If a process doesn’t match any of the explicit permissions (rwx, rw-, etc.),
    /// it will use the permissions specified by default. If a process matches multiple
    /// explicit permissions groups, it’s permissions will be the intersection of all the permissions.
    pub fn get_atype_for_profile(&self, prof: &String) -> AccessType {
        unimplemented!();
    }
}

impl Acl {
    pub fn from(acl_json: Vec<AclJsonFile>) -> Result<Self> {
        unimplemented!();
    }
}
