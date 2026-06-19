use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    build_params,
    detection::{PolicyVerdict, Protectee},
    pgraph::{AccessType, Event, EventArgs},
    uinterf::Config,
    utils,
};

/// Actor Temporally Unique ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorTuid {
    pub pid: i32,
    pub start_ktime: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorState {
    Running,
    Exited,
    KilledByHtekd,
}

#[derive(Debug, Clone, Default)]
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

    pub cwd: Option<PathBuf>,

    // This is the set of all unique profiles that this process has ever had.
    // If multiple binaries executed with the same profile, then this list will be less than `n`
    // elements log
    pub profile: HashSet<String>,

    // All profiles in this field will not be used to check permissions for actions this actor
    // takes. All processes this actor spawns will inherit profiles from `.profile` and
    // `.child_profile`
    pub child_profile: HashSet<String>,
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
            child_profile: HashSet::new(),
            argv: vec![],
            cwd: None,
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
            summary: ActorSummary::default(),
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
        let cwd = Self::get_cwd(pid).ok();

        let mut actor = Self::new(pid, start_time);

        actor.actor_md.binary.push(exe_path);
        actor.actor_md.argv.push(cmd_args);
        actor.actor_md.cwd = cwd;

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

    fn get_cwd(pid: i32) -> Result<PathBuf> {
        let path = format!("/proc/{}/cwd", pid);
        Ok(fs::canonicalize(&path)?)
    }

    pub fn resolve_path_str(&self, fpath: &str) -> Result<PathBuf> {
        if fpath.starts_with("/") {
            let fpath_full = fs::canonicalize(fpath).unwrap_or(PathBuf::from(fpath));
            return Ok(fpath_full);
        }

        let mut fullpath = match &self.actor_md.cwd {
            Some(r) => r.join(fpath),
            None => bail!("actor has no cwd"),
        };
        fullpath = fs::canonicalize(&fullpath).unwrap_or(fullpath);
        Ok(fullpath)
    }

    pub fn is_unchained(&self) -> bool {
        match self.actor_md.profile.len() {
            0 => true,
            1 => self.actor_md.profile.contains("unchained"),
            _ => false,
        }
    }

    pub fn set_state(&mut self, state: ActorState) {
        let old_state = self.actor_md.state;
        let new_state = state;

        self.actor_md.state = new_state;
        if !build_params::ASSERTS {
            return;
        }

        match (old_state, new_state) {
            (ActorState::Exited, ActorState::Exited) => {
                tracing::error!("Tried to mark an already exited actor as exited.");
            }
            (ActorState::KilledByHtekd, ActorState::KilledByHtekd) => {
                tracing::error!("Tried to mark an already killed actor as killed.");
            }
            (ActorState::KilledByHtekd, ActorState::Exited) => {
                tracing::error!("Tried to mark an already killed actor as exited.");
            }
            _ => {}
        }
    }
}

/// This block of functoins are event handlers
/// Each of these return a PolicyVerdict type
impl Actor {
    pub fn handle_event(
        &mut self,
        config: &Config,
        event: &Event,
        child_owned: bool,
    ) -> PolicyVerdict {
        match &event.args {
            EventArgs::Mmap { fpath, mode } => {
                self.handle_mmap(config, fpath.as_ref().map(|x| x.as_path()), *mode)
            }
            EventArgs::Openat { fpath, mode } => self.handle_openat(config, fpath, *mode),
            EventArgs::ConnectUds { fpath } => self.handle_connect_uds(config, fpath),
            EventArgs::Rename { src, dst } => self.handle_rename(config, src, dst),
            EventArgs::Execve { binary } => {
                if child_owned {
                    return PolicyVerdict::Benign;
                }
                self.handle_execve_mdupdate(config, binary)
            }
            EventArgs::ChDir { dpath } => {
                if child_owned {
                    return PolicyVerdict::Benign;
                }
                self.actor_md.cwd = Some(dpath.clone());
                PolicyVerdict::Benign
            }
            EventArgs::Exit => {
                if !child_owned {
                    self.actor_md.state = ActorState::Exited;
                }
                PolicyVerdict::Benign
            }
            EventArgs::Start { .. } => {
                utils::unreachable();
                PolicyVerdict::Benign
            }
        }
    }

    pub fn handle_openat(
        &mut self,
        config: &Config,
        fpath: &Path,
        mode: AccessType,
    ) -> PolicyVerdict {
        utils::assert_canonical_asso(fpath);

        let protectee = Protectee::File(fpath.to_path_buf());

        let entry = self.summary.events.entry(protectee);
        let v = *entry.and_modify(|x| x.union(mode)).or_insert(mode);

        config.acl.check_violation(self, fpath, v)
    }

    pub fn handle_connect_uds(&mut self, config: &Config, fpath: &Path) -> PolicyVerdict {
        utils::assert_canonical_asso(fpath);

        let protectee = Protectee::File(fpath.to_path_buf());
        let mode = const { AccessType::from_rwxbc_str_const("----c") };

        let entry = self.summary.events.entry(protectee);
        let v = *entry.and_modify(|x| x.union(mode)).or_insert(mode);

        config.acl.check_violation(self, fpath, v)
    }

    pub fn handle_rename(&mut self, config: &Config, src: &Path, dest: &Path) -> PolicyVerdict {
        let atype = const { AccessType::from_rwxbc_str_const("rw-") };
        self.handle_openat(config, src, atype) | self.handle_openat(config, dest, atype)
    }

    pub fn handle_mmap(
        &mut self,
        config: &Config,
        fpath: Option<&Path>,
        mode: AccessType,
    ) -> PolicyVerdict {
        if let Some(fpath) = fpath {
            return self.handle_openat(config, fpath, mode);
        }
        PolicyVerdict::Benign
    }

    /// Handle execve metadata update
    pub fn handle_execve_mdupdate(&mut self, config: &Config, binary: &Path) -> PolicyVerdict {
        // TODO: Determine the correct way to get the binary path
        let binary_path = match fs::canonicalize(binary) {
            Ok(r) => r,
            _ => {
                let bin_path = format!("/proc/{}/exe", self.id.pid);
                match fs::canonicalize(&bin_path) {
                    Ok(r) => r,
                    _ => return PolicyVerdict::Benign,
                }
            }
        };

        // TODO: processes should inherit profiles from parents, and then reset these profiles at the first execve call
        // All other execve calls should not reset/wipe profiles
        // Make sure not to wipe out creator's child_profile while resetting.

        let args = Self::get_cmdline(self.id.pid).ok();
        let profile = config.profile_config.get_profile(&binary_path);

        self.actor_md.binary.push(binary_path);
        self.actor_md.argv.push(args);
        if profile != "unchained" {
            self.actor_md.profile.insert(profile.to_string());
        }

        PolicyVerdict::Benign
    }
}
