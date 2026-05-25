use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    detection::{PolicyVerdict, Protectee},
    pgraph::AccessType,
    uinterf::Config,
};

/// Actor Temporally Unique ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorTuid {
    pub pid: i32,
    pub start_ktime: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ActorState {
    Running,
    Exited,
}

#[derive(Debug, Clone)]
pub struct ActorSummary {
    pub events: HashMap<Protectee, AccessType>,
}

#[derive(Debug, Clone)]
pub struct ActorMd {
    pub state: ActorState,

    // This is the list of all binaries this process has ever executed as. If this list is `n`
    // elements long, that that means the process has executed execve `n` times.
    // The last element of this vector is the current binary the process is executing as.
    pub binary: Vec<PathBuf>,

    // This is the CLI arguments of the
    pub argv: Vec<Option<Vec<String>>>,

    // This is the set of all unique profiles that this process has ever had.
    // If multiple binaries executed with the same profile, then this list will be less than `n`
    // elements log
    pub profile: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub id: ActorTuid,
    pub summary: ActorSummary,
    pub actor_md: ActorMd,
}

impl ActorMd {
    fn new() -> Self {
        Self {
            state: ActorState::Running,
            binary: vec![],
            profile: HashSet::new(),
            argv: vec![],
        }
    }

    /// Returns a vector of paths to the fils responsible for executing code for each execve call
    /// For exammple
    /// `/usr/bin/evil_binary arg1 arg2`                 -> `/usr/bin/evil_binary`
    /// `/usr/bin/python /tmp/evil_script.py arg1 arg2`  -> `/tmp/evil_script.py`
    #[allow(unused)]
    pub fn get_actors(&self) -> Vec<PathBuf> {
        unimplemented!();
    }
}

/// This block of implemtnations are generic helpers for this type
impl Actor {
    pub fn new(pid: i32, start_time: u64) -> Self {
        Self {
            id: ActorTuid {
                pid,
                start_ktime: start_time,
            },
            actor_md: ActorMd::new(),
            summary: ActorSummary {
                events: HashMap::new(),
            },
        }
    }

    /// This function is intended to be called for processes that were spawned before the htek
    /// daemon. This will get the command and CLI arguments from /proc (as opposed to execve
    /// events like normal)
    pub fn new_bootstrap_md(pid: i32, start_time: u64) -> Result<Self> {
        let path_str = format!("/proc/{}/exe", pid);
        let exe_path = fs::canonicalize(&path_str)
            .context("failed to get /proc/<pid>/exe (likely bc this is a kthread)")?;

        let cmd_args = Self::get_cmdline(pid).ok();

        let mut actor = Self::new(pid, start_time);

        actor.actor_md.binary.push(exe_path);
        actor.actor_md.argv.push(cmd_args);

        Ok(actor)
    }

    fn get_cmdline(pid: i32) -> std::io::Result<Vec<String>> {
        let path = format!("/proc/{}/cmdline", pid);
        let data = fs::read(path)?;

        Ok(data
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect())
    }
}

/// This block of functoins are event handlers
/// Each of these return a PolicyVerdict type
impl Actor {
    pub fn handle_openat(
        &mut self,
        config: &Config,
        fpath: String,
        mode: AccessType,
    ) -> PolicyVerdict {
        let ffpath = match fs::canonicalize(&fpath) {
            Ok(r) => r,
            Err(_e) => {
                return PolicyVerdict::Benign;
            }
        };
        let protectee = Protectee::File(ffpath.clone());

        let entry = self.summary.events.entry(protectee);
        let v = entry.or_insert(mode);
        v.union(mode);

        config
            .acl
            .check_violation(&self.actor_md.profile, &ffpath, *v)
    }

    pub fn handle_connect_uds(&mut self, config: &Config, fpath: String) -> PolicyVerdict {
        let ffpath = match fs::canonicalize(&fpath) {
            Ok(r) => r,
            Err(_e) => {
                return PolicyVerdict::Benign;
            }
        };
        let protectee = Protectee::File(ffpath.clone());
        let mode = AccessType::from_str("----c").unwrap();

        let entry = self.summary.events.entry(protectee);
        let v = entry.or_insert(mode);
        v.union(mode);

        config
            .acl
            .check_violation(&self.actor_md.profile, &ffpath, *v)
    }

    pub fn handle_rename(&mut self, config: &Config, src: String, dest: String) -> PolicyVerdict {
        self.handle_openat(config, src, AccessType::from_str("rw-").unwrap())
            | self.handle_openat(config, dest, AccessType::from_str("rw-").unwrap())
    }

    pub fn handle_mmap(
        &mut self,
        config: &Config,
        fpath: Option<String>,
        mode: AccessType,
    ) -> PolicyVerdict {
        if let Some(fpath) = fpath {
            return self.handle_openat(config, fpath, mode);
        }
        PolicyVerdict::Benign
    }

    pub fn handle_execve(&mut self, config: &Config, binary: String) -> PolicyVerdict {
        // TODO: Determine the correct way to get the binary path
        let binary_path = match fs::canonicalize(&binary) {
            Ok(r) => r,
            _ => {
                let bin_path = format!("/proc/{}/exe", self.id.pid);
                match fs::canonicalize(&bin_path) {
                    Ok(r) => r,
                    _ => return PolicyVerdict::Benign,
                }
            }
        };

        let args = Self::get_cmdline(self.id.pid).ok();
        let profile = config.profile_config.get_profile(&binary_path);

        self.actor_md.binary.push(binary_path);
        self.actor_md.argv.push(args);
        self.actor_md.profile.insert(profile.to_string());

        PolicyVerdict::Benign
    }
}
