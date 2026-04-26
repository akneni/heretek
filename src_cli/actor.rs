use std::{
    collections::{HashMap, HashSet, VecDeque}, fs, io, mem
};

use anyhow::{Result, bail};

use crate::{
    Violation, acl::{Acl, Profile, Protectee}, bpfmap::CEvent, config::Config, event_types, utils::{TotalMem, bit_test}
};

#[derive(Debug, Clone, Copy)]
pub enum ActorState {
    Running,
    Exited,
}

#[derive(Debug, Clone, Copy, Hash)]
pub struct AccessType {
    read: bool,
    write: bool,
    execute: bool,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub pid: i32,
    pub ktime: u64,
    pub args: EventArgs,
}

#[derive(Debug, Clone)]
pub enum EventArgs {
    // System Calls
    Execve {
        binary: String,
    },
    Openat {
        fpath: String,
        mode: AccessType,
    },
    Mmap {
        fpath: Option<String>,
        mode: AccessType,
    },
    Rename {
        src: String,
        dst: String,
    },

    // Generic Events
    Exit,
    Start {
        creator_pid: i32,
    },
}

/// Actor Temporally Unique ID
#[derive(Debug, Clone, Copy)]
pub struct ActorTuid {
    pub pid: i32,
    pub start_ktime: u64,
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
    pub pid: i32,
    pub start_ktime: u64,
    
    // Note, these fields describe the process that created this process
    // and the processes that this process created. This is distinct from 
    // what is considered a parent and child process. 
    pub creator_pid: Option<i32>,
    pub child_pids: HashSet<ActorTuid>,

    // TODO: Add creator ActorTuid cache 

    pub events: ActorHist,
    pub summary: ActorSummary,
    pub actor_md: ActorMd,
}

#[derive(Debug)]
pub struct ActorsDb {
    pub db: HashMap<i32, VecDeque<Actor>>,
    pub cfg: Config,
}

impl AccessType {
    pub fn from_spare(spare: u8) -> Self {
        const O_RDONLY: u8 = 0;
        const O_WRONLY: u8 = 1;
        const O_RDWR: u8 = 2;

        match spare {
            O_RDONLY => Self {
                read: true,
                write: false,
                execute: false,
            },
            O_WRONLY => Self {
                read: false,
                write: true,
                execute: false,
            },
            O_RDWR => Self {
                read: true,
                write: true,
                execute: false,
            },
            _ => Self {
                read: false,
                write: false,
                execute: false,
            },
        }
    }

    pub fn from_rwx_str(mode: &str) -> Result<Self> {
        let bytes = mode.as_bytes();
        if bytes.len() != 3 {
            bail!("access mode must be exactly 3 characters");
        }

        let valid = |on: u8, off: u8, expected: u8| on == expected || on == off;
        if !valid(bytes[0], b'-', b'r') || !valid(bytes[1], b'-', b'w') || !valid(bytes[2], b'-', b'x') {
            bail!("invalid access mode");
        }

        Ok(Self {
            read: bytes[0] == b'r',
            write: bytes[1] == b'w',
            execute: bytes[2] == b'x',
        })
    }
}

impl Event {
    pub fn from(c_event: &CEvent) -> Result<Self> {
        let args = match c_event.event {
            event_types::SYSCALL_OPENAT => EventArgs::Openat {
                fpath: c_event.fpath_str(1)?,
                mode: AccessType::from_spare(c_event.spare[0]),
            },
            event_types::SYSCALL_EXECVE => EventArgs::Execve {
                binary: c_event.fpath_str(1)?,
            },
            event_types::GENE_START => EventArgs::Start { creator_pid: 0 },
            event_types::GENE_EXIT => EventArgs::Exit,
            _ => bail!("unsupported event"),
        };

        Ok(Self {
            pid: c_event.pid,
            ktime: c_event.ktime,
            args,
        })
    }
}

impl TotalMem for Event {
    fn total_mem(&self) -> usize {
        let mut size = mem::size_of::<Self>();
        match &self.args {
            EventArgs::Execve { binary } => {
                size += binary.len();
            }
            EventArgs::Openat { fpath, .. } => {
                size += fpath.len();
            }
            EventArgs::Mmap { fpath, .. } => {
                if let Some(fpath) = fpath {
                    size += fpath.len();
                }
            }
            EventArgs::Rename { src, dst } => {
                size += src.len();
                size += dst.len();
            }
            EventArgs::Exit => {}
            EventArgs::Start {
                #[allow(unused)]
                creator_pid,
            } => {}
        }
        size
    }
}

impl TotalMem for ActorState {
    fn total_mem(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl TotalMem for AccessType {
    fn total_mem(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl Default for AccessType {
    fn default() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
        }
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

        size += self.events.total_mem().saturating_sub(mem::size_of::<ActorHist>());
        size += self
            .summary
            .total_mem()
            .saturating_sub(mem::size_of::<ActorSummary>());

        size
    }
}

impl TotalMem for ActorsDb {
    fn total_mem(&self) -> usize {
        let mut size = mem::size_of::<Self>();
        size += self.db.capacity() * mem::size_of::<(i32, VecDeque<Actor>)>();

        for actors in self.db.values() {
            size += actors.capacity() * mem::size_of::<Actor>();
            for actor in actors {
                size += actor.total_mem().saturating_sub(mem::size_of::<Actor>());
            }
        }

        size
    }
}

impl AccessType {
    pub fn union(&mut self, other: AccessType) {
        self.read |= other.read;
        self.write |= other.write;
        self.execute |= other.execute;
    }

    pub fn intersection(&mut self, other: AccessType) {
        self.read &= other.read;
        self.write &= other.write;
        self.execute &= other.execute;
    }

    pub fn is_superset_of(&self, other: AccessType) -> bool {
        (!other.read || self.read)
            && (!other.write || self.write)
            && (!other.execute || self.execute)
    }

    pub fn is_subset_of(&self, other: AccessType) -> bool {
        other.is_superset_of(*self)
    }
}

impl ActorSummary {
    fn get(&mut self, p: Protectee) -> &mut AccessType {
        let entry = self.events.entry(p);
        entry.or_insert(AccessType::default())
    }
}

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
            argv: Some(Self::get_cmdline(pid).unwrap()),
        };

        Self {
            pid,
            start_ktime: start_time,
            creator_pid: None,
            child_pids: HashSet::new(),
            actor_md: actor_md,
            events: ActorHist { events: vec![] },
            summary: ActorSummary {
                events: HashMap::new(),
            },
        }
    }

    /// This should only be used when the daemon is first started up to get the 
    /// start time of all already existing processes. 
    pub fn new_bootstrap(pid: i32) -> Self {
        let start_time = Self::usrsp_ktime_get_boot_ns(pid).unwrap();
        Self::new(pid, start_time)
    }

    pub fn update_summary(&mut self, event: &Event, acl: &Acl) -> Option<Violation> {
        match &event.args {
            EventArgs::Openat { fpath, mode } => {
                let p = Protectee::File(fpath.clone());
                let at = self.summary.get(p.clone());
                at.union(*mode);

                if let Some(acl_block) = acl.blocks.get(&p) {
                    if let Some(prof) = self.actor_md.profile.as_ref() {
                        let ap = acl_block.get_atype_for_profile(prof);
                        if !ap.is_superset_of(*at) {
                            return Some(Violation {
                                binary: self.actor_md.binary.clone().unwrap_or("...".to_string()),
                                pid: self.pid,
                                p: p.clone(),
                                atype: *at,
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        None
    }

    /// User Space Kernel Time Get Boot Nanoseconds
    /// This returns a timer that has the same semantics as bpf_ktime_get_boot_ns()
    /// The only caveat is that this 
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

impl ActorsDb {
    pub fn new(cfg: Config) -> Self {
        Self {
            db: HashMap::new(),
            cfg,
        }
    }

    pub fn insert_event(&mut self, event: Event, violations: &mut Vec<Violation>, acl: &Acl) {
        let pid = event.pid;
        let actor = self.get_actor(pid);
        if let EventArgs::Exit = &event.args {
            actor.actor_md.state = ActorState::Exited;
        }

        if let Some(v) = actor.update_summary(&event, acl) {
            println!("{:?}", v);
            violations.push(v);
        }
        // actor.events.events.push(event.clone());

        if let EventArgs::Execve { binary } = &event.args {
            let actors = self.get_pid_dequeue(pid);
            let mut actor = Actor::new_bootstrap(pid);
            actor.events.events.push(Event {
                pid,
                ktime: event.ktime,
                args: EventArgs::Start { creator_pid: pid },
            });
            actor.actor_md.binary = Some(binary.clone());
            actors.push_back(actor);
        }
    }

    fn get_pid_dequeue(&mut self, pid: i32) -> &mut VecDeque<Actor> {
        let entry = self.db.entry(pid);
        entry.or_default()
    }

    fn get_actor(&mut self, pid: i32) -> &mut Actor {
        let actors = self.get_pid_dequeue(pid);
        if actors.len() == 0 {
            actors.push_back(Actor::new_bootstrap(pid));
        }

        let actor = actors.back().unwrap();
        if let ActorState::Exited = actor.actor_md.state {
            actors.push_back(Actor::new_bootstrap(pid));
        }

        actors.back_mut().unwrap()
    }
}
