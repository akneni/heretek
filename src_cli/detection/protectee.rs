use anyhow::Result;
use std::{collections::HashSet, fs, path::PathBuf};

use glob::Pattern;

use crate::utils;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Protectee {
    File(PathBuf),
    Syscall(String),
}

/// This struct is meant to help us answer one question. "Is this protectee contained within this set?"
/// Logically, ProtecteeSet is equivilent to HashSet<Protectee> though it is implemented differently for
/// performance and glob support.
#[derive(Debug, Clone)]
pub struct ProtecteeSet {
    prote_file_glob: Vec<Pattern>,
    prote_file: HashSet<PathBuf>,
    prote_syscall: HashSet<String>,
}

impl ProtecteeSet {
    pub fn from_strings(protectees: Vec<String>) -> Result<Self> {
        let mut prote_file_glob = Vec::new();
        let mut prote_file = HashSet::new();
        let mut prote_syscall = HashSet::new();

        for protectee in protectees {
            if let Some(syscall) = protectee.strip_prefix("syscall:") {
                prote_syscall.insert(syscall.to_string());
                continue;
            }

            let file = protectee.strip_prefix("file:").unwrap_or(&protectee);

            if utils::is_glob(file) {
                prote_file_glob.push(Pattern::new(file)?);
            } else {
                let path = PathBuf::from(file);
                prote_file.insert(fs::canonicalize(&path).unwrap_or(path));
            }
        }

        Ok(Self {
            prote_file_glob,
            prote_file,
            prote_syscall,
        })
    }

    pub fn contains(&self, prote: &Protectee) -> bool {
        match prote {
            Protectee::File(file) => self.contains_file(file),
            Protectee::Syscall(syscall) => self.contains_syscall(syscall),
        }
    }

    pub fn contains_file(&self, file: &PathBuf) -> bool {
        self.prote_file.contains(file)
            || self
                .prote_file_glob
                .iter()
                .any(|pattern| pattern.matches_path(file))
    }

    pub fn contains_syscall(&self, syscall: &str) -> bool {
        self.prote_syscall.contains(syscall)
    }
}
