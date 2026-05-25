use anyhow::{Context, Result, bail};
use glob::Pattern;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::detection::{AclJsonFile, AclProfileJsonFile, PolicyVerdict, Protectee};
use crate::pgraph::AccessType;

#[derive(Debug, Clone, Default)]
pub struct ProfAccessRules {
    prote_files: HashMap<PathBuf, AccessType>,
    prote_glob_files: HashMap<Pattern, AccessType>,
    prote_syscalls: HashMap<String, AccessType>,
}

#[derive(Debug, Clone)]
pub struct Acl {
    pub profiles: HashMap<String, ProfAccessRules>,
}

impl ProfAccessRules {
    fn apply_profile(&mut self, profile_json: &AclProfileJsonFile) -> Result<()> {
        for (protectee, mode) in &profile_json.rules {
            self.insert_rule(protectee, mode)
                .with_context(|| format!("failed to parse ACL rule {protectee} = {mode}"))?;
        }

        Ok(())
    }

    fn insert_rule(&mut self, protectee: &str, mode: &str) -> Result<()> {
        let access_type = AccessType::from_str(mode)?;

        if let Some(syscall) = protectee.strip_prefix("syscall:") {
            self.prote_syscalls.insert(syscall.to_string(), access_type);
            return Ok(());
        }

        let file = protectee.strip_prefix("file:").unwrap_or(protectee);

        if crate::utils::is_glob(file) {
            self.prote_glob_files
                .insert(Pattern::new(file)?, access_type);
        } else {
            let path = PathBuf::from(file);
            self.prote_files
                .insert(fs::canonicalize(&path).unwrap_or(path), access_type);
        }

        Ok(())
    }

    pub fn get_atype(&self, prote: &Protectee) -> AccessType {
        match prote {
            Protectee::File(file) => self.get_atype_file(file),
            Protectee::Syscall(syscall) => self.get_atype_syscall(syscall),
        }
    }

    pub fn get_atype_file(&self, file: &PathBuf) -> AccessType {
        if let Some(atype) = self.prote_files.get(file) {
            return *atype;
        }

        for (k, v) in self.prote_glob_files.iter() {
            if k.matches_path(file) {
                return *v;
            }
        }

        AccessType::from_str("rwxbc").unwrap()
    }

    pub fn get_atype_syscall(&self, syscall: &str) -> AccessType {
        self.prote_syscalls
            .get(syscall)
            .map(|&x| x)
            .unwrap_or(AccessType::from_str("--x--").unwrap())
    }
}

impl Acl {
    pub fn from_acl_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let acl_json: AclJsonFile = serde_json::from_str(&contents)?;
        Self::from(acl_json)
    }

    pub fn from(acl_json: AclJsonFile) -> Result<Self> {
        let mut profiles = HashMap::new();
        let mut resolving = HashSet::new();

        for profile in acl_json.keys() {
            Self::build_profile(profile, &acl_json, &mut profiles, &mut resolving)?;
        }

        Ok(Self { profiles })
    }

    fn build_profile(
        profile: &str,
        acl_json: &AclJsonFile,
        profiles: &mut HashMap<String, ProfAccessRules>,
        resolving: &mut HashSet<String>,
    ) -> Result<ProfAccessRules> {
        if let Some(rules) = profiles.get(profile) {
            return Ok(rules.clone());
        }

        if !resolving.insert(profile.to_string()) {
            bail!("ACL profile inheritance cycle detected at {profile}");
        }

        let profile_json = acl_json
            .get(profile)
            .with_context(|| format!("ACL profile {profile} does not exist"))?;

        let mut rules = if let Some(parent) = &profile_json.inherits {
            Self::build_profile(parent, acl_json, profiles, resolving)?
        } else {
            ProfAccessRules::default()
        };

        rules.apply_profile(profile_json)?;
        resolving.remove(profile);
        profiles.insert(profile.to_string(), rules.clone());

        Ok(rules)
    }

    /// Top level function for detecting violations
    /// If any one of the profiles accessed the file in a way that is not permitted, then its a violation
    pub fn check_violation(
        &self,
        profiles: &HashSet<String>,
        file: &PathBuf,
        mode: AccessType,
    ) -> PolicyVerdict {
        for prof in profiles.iter() {
            let access_list = match self.profiles.get(prof) {
                Some(r) => r,
                None => continue,
            };

            let allowed_atype = access_list.get_atype_file(file);
            if !allowed_atype.is_superset_of(mode) {
                return PolicyVerdict::Violation {
                    prote: Protectee::File(file.clone()),
                    attempted_access: mode,
                    allowed_access: allowed_atype,
                };
            }
        }
        PolicyVerdict::Benign
    }
}
