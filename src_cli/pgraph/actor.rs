use std::{collections::HashMap, fs, io, mem};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    detection::{Acl, Profile, Protectee},
    pgraph::{AccessType, Event, EventArgs},
    utils::TotalMem,
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
    events: HashMap<Protectee, AccessType>,
}

#[derive(Debug, Clone)]
pub struct ActorMd {
    pub state: ActorState,
    pub binary: Option<String>,
    pub profile: Option<Profile>,
    pub argv: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub id: ActorTuid,
    pub events: ActorHist,
    pub summary: ActorSummary,
    pub actor_md: ActorMd,
}

impl TotalMem for ActorState {
    fn total_mem(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl TotalMem for ActorHist {
    fn total_mem(&self) -> usize {
        let mut size = mem::size_of::<Self>();
        size += self.events.capacity() * mem::size_of::<Event>();
        for event in &self.events {
            size += event.total_mem().saturating_sub(mem::size_of::<Event>());
        }
        size
    }
}

impl TotalMem for ActorSummary {
    fn total_mem(&self) -> usize {
        let mut size = mem::size_of::<Self>();
        size += self.events.capacity() * mem::size_of::<(Protectee, AccessType)>();
        size
    }
}

impl TotalMem for Actor {
    fn total_mem(&self) -> usize {
        let mut size = mem::size_of::<Self>();

        if let Some(binary) = &self.actor_md.binary {
            size += binary.len();
        }

        if let Some(argv) = &self.actor_md.argv {
            size += argv.capacity() * mem::size_of::<String>();
            for arg in argv {
                size += arg.len();
            }
        }

        size += self
            .events
            .total_mem()
            .saturating_sub(mem::size_of::<ActorHist>());
        size += self
            .summary
            .total_mem()
            .saturating_sub(mem::size_of::<ActorSummary>());

        size
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
        let comm = match fs::canonicalize(&format!("/proc/{}/exe", pid)) {
            Ok(r) => Some(r.to_str().unwrap().to_string()),
            Err(_e) => None,
        };

        let actor_md = ActorMd {
            state: ActorState::Running,
            binary: comm.clone(),
            profile: comm.map(|b| Profile::Binary(b)),
            argv: Self::get_cmdline(pid).map(|x| Some(x)).unwrap_or(None),
        };

        Self {
            id: ActorTuid {
                pid,
                start_ktime: start_time,
            },
            actor_md: actor_md,
            events: ActorHist { events: vec![] },
            summary: ActorSummary {
                events: HashMap::new(),
            },
        }
    }

    fn new_infer_ktime(pid: i32) -> Result<Self> {
        let ktime = Self::usrsp_ktime_get_boot_ns(pid)?;
        Ok(Self::new(pid, ktime))
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
    pub fn handle_openat(&mut self, fpath: String, mode: AccessType) -> bool {
        let ffpath = fs::canonicalize(fpath).unwrap();
        let protectee = Protectee::File(ffpath);

        let entry = self.summary.events.entry(protectee);
        let v = entry.or_insert(mode);
        v.union(mode);

        false
    }

    pub fn handle_rename(&mut self, src: String, dest: String) -> bool {        
        self.handle_openat(src, AccessType::from_rwx_str("rw-").unwrap()) ||
        self.handle_openat(dest, AccessType::from_rwx_str("rw-").unwrap())
    }

    pub fn handle_mmap(&mut self, fpath: Option<String>, mode: AccessType) -> bool {
        if let Some(fpath) = fpath {
            return self.handle_openat(fpath, mode);
        }
        false
    }
}