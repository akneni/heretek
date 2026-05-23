use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    fs, io, mem,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    detection::{Acl, Protectee},
    pgraph::{AccessType, Event, EventArgs},
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
pub struct ActorHist {
    events: Vec<Event>,
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
    pub events: ActorHist,
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
    pub fn get_actors(&self) -> Vec<PathBuf> {
        unimplemented!();
    }
}

impl ActorSummary {
    fn get(&mut self, p: Protectee) -> &mut AccessType {
        let entry = self.events.entry(p);
        entry.or_insert(AccessType::default())
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
            events: ActorHist { events: vec![] },
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

    /// Gets the parent PID (NOT the creator ID)
    fn get_ppid(&self) -> Result<i32> {
        let pid = self.id.pid;
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;

        // Format:
        // pid (comm) state ppid ...
        let after_comm = stat
            .rsplit_once(") ")
            .context("malformed /proc stat: missing process name terminator")?
            .1;

        let mut fields = after_comm.split_whitespace();

        let _state = fields.next().context("missing process state")?;
        let ppid = fields
            .next()
            .context("missing parent pid")?
            .parse::<i32>()
            .context("invalid parent pid")?;

        Ok(ppid)
    }

    /// User Space Kernel Time Get Boot Nanoseconds
    /// This returns a timer that has the same semantics as bpf_ktime_get_boot_ns()
    fn usrsp_ktime_get_boot_ns(pid: i32) -> io::Result<u64> {
        let path = format!("/proc/{pid}/stat");
        let stat = fs::read_to_string(path)?;

        let rp = stat
            .rfind(')')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad /proc stat format"))?;

        let after = stat
            .get(rp + 2..) // skip ") "
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad /proc stat format"))?;

        let starttime_ticks_str = after
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing starttime field"))?;

        let starttime_ticks: u64 = starttime_ticks_str
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid starttime field"))?;

        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "sysconf(_SC_CLK_TCK) failed",
            ));
        }

        Ok(starttime_ticks.saturating_mul(1_000_000_000) / hz as u64)
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
/// Each of these return a bool. It will be false if there are no violations and will be true
/// if there is a vioilation the actor has been deemed malicious.
impl Actor {
    pub fn handle_openat(&mut self, config: &Config, fpath: String, mode: AccessType) -> bool {
        let ffpath = match fs::canonicalize(&fpath) {
            Ok(r) => r,
            Err(_e) => {
                return false;
            }
        };
        let protectee = Protectee::File(ffpath);

        let entry = self.summary.events.entry(protectee);
        let v = entry.or_insert(mode);
        v.union(mode);

        false
    }

    pub fn handle_connect_uds(&mut self, config: &Config, fpath: String) -> bool {
        let ffpath = match fs::canonicalize(&fpath) {
            Ok(r) => r,
            Err(_e) => {
                return false;
            }
        };
        let protectee = Protectee::File(ffpath);
        let mode = AccessType::from_str("----c").unwrap();

        let entry = self.summary.events.entry(protectee);
        let v = entry.or_insert(mode);
        v.union(mode);

        false
    }

    pub fn handle_rename(&mut self, config: &Config, src: String, dest: String) -> bool {
        self.handle_openat(config, src, AccessType::from_str("rw-").unwrap())
            || self.handle_openat(config, dest, AccessType::from_str("rw-").unwrap())
    }

    pub fn handle_mmap(
        &mut self,
        config: &Config,
        fpath: Option<String>,
        mode: AccessType,
    ) -> bool {
        if let Some(fpath) = fpath {
            return self.handle_openat(config, fpath, mode);
        }
        false
    }

    pub fn handle_execve(&mut self, config: &Config, binary: String) -> bool {
        let binary_path = match fs::canonicalize(&binary) {
            Ok(r) => r,
            _ => return false,
        };

        let args = Self::get_cmdline(self.id.pid).ok();
        let profile = config.profile_config.get_profile(&binary_path);

        self.actor_md.binary.push(binary_path);
        self.actor_md.argv.push(args);
        self.actor_md.profile.insert(profile.to_string());

        false
    }
}
