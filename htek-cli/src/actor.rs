use std::{
    collections::{HashMap, VecDeque},
    fs, mem,
};

use anyhow::{Result, bail};

use crate::{
    bpfmap::CEvent,
    config::Config,
    event_types,
    utils::{TotalMem, bit_test},
};

#[derive(Debug, Clone, Copy)]
pub enum ActorState {
    Running,
    Exited,
}

#[derive(Debug, Clone, Copy)]
pub struct AccessType {
    read: bool,
    write: bool,
    execute: bool,
}

#[derive(Debug, Clone)]
pub enum Event {
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
    Exit,
    Start {
        creator_pid: i32,
    },
}

#[derive(Debug, Clone)]
pub struct Actor {
    pid: i32,
    start_time: Option<u64>,
    state: ActorState,
    creator_pid: Option<i32>,
    binary: Option<String>,
    argv: Option<Vec<String>>,
    events: Vec<Event>,
}

#[derive(Debug)]
pub struct ActorsDb {
    pub db: HashMap<i32, VecDeque<Actor>>,
    pub cfg: Config,
}

impl AccessType {
    pub fn from_spare(spare: u8) -> Self {
        const ACCESS_TYPE_R: u8 = 0;
        const ACCESS_TYPE_W: u8 = 1;
        const ACCESS_TYPE_E: u8 = 2;

        Self {
            read: bit_test(spare, ACCESS_TYPE_R),
            write: bit_test(spare, ACCESS_TYPE_W),
            execute: bit_test(spare, ACCESS_TYPE_E),
        }
    }
}

impl Event {
    pub fn from(c_event: &CEvent) -> Result<Self> {
        match c_event.event {
            event_types::SYSCALL_OPENAT => Ok(Self::Openat {
                fpath: c_event.fpath_str(1)?,
                mode: AccessType::from_spare(c_event.spare[0]),
            }),
            event_types::SYSCALL_EXECVE => Ok(Self::Execve {
                binary: c_event.fpath_str(1)?,
            }),
            event_types::GENE_START => Ok(Self::Start { creator_pid: 0 }),
            event_types::GENE_EXIT => Ok(Self::Exit),
            _ => bail!("unsupported event"),
        }
    }
}

impl TotalMem for Event {
    fn total_mem(&self) -> usize {
        let mut size = mem::size_of::<Self>();
        match self {
            Self::Execve { binary } => {
                size += binary.len();
            }
            Self::Openat { fpath, .. } => {
                size += fpath.len();
            }
            Self::Mmap { fpath, .. } => {
                if let Some(fpath) = fpath {
                    size += fpath.len();
                }
            }
            Self::Rename { src, dst } => {
                size += src.len();
                size += dst.len();
            }
            Self::Exit => {}
            Self::Start {
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

impl TotalMem for Actor {
    fn total_mem(&self) -> usize {
        let mut size = mem::size_of::<Self>();

        if let Some(binary) = &self.binary {
            size += binary.len();
        }

        if let Some(argv) = &self.argv {
            size += argv.capacity() * mem::size_of::<String>();
            for arg in argv {
                size += arg.len();
            }
        }

        size += self.events.capacity() * mem::size_of::<Event>();
        for event in &self.events {
            size += event.total_mem().saturating_sub(mem::size_of::<Event>());
        }

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

impl Actor {
    pub fn new(pid: i32) -> Self {
        let comm = match fs::canonicalize(&format!("/proc/{}/exe", pid)) {
            Ok(r) => Some(r.to_str().unwrap().to_string()),
            Err(_e) => None,
        };
        let start_time = match fs::read_to_string(format!("/proc/{}/stat", pid)) {
            Ok(stat) => {
                let end_comm = stat.rfind(')');
                match end_comm
                    .and_then(|idx| stat.get(idx + 2..))
                    .map(|rest| rest.split_whitespace().collect::<Vec<_>>())
                {
                    Some(fields) => fields.get(19).and_then(|value| value.parse().ok()),
                    None => None,
                }
            }
            Err(_) => None,
        };

        Self {
            pid,
            start_time,
            state: ActorState::Running,
            creator_pid: None,
            binary: comm,
            argv: None,
            events: vec![],
        }
    }
}

impl ActorsDb {
    pub fn new(cfg: Config) -> Self {
        Self {
            db: HashMap::new(),
            cfg,
        }
    }

    pub fn insert_event(&mut self, pid: i32, event: Event, cfg: &Config) {
        let actor = self.get_actor(pid);
        if let Event::Exit = event {
            actor.state = ActorState::Exited;
        }
        let mut push_to_a = true;
        if let Some(binary) = actor.binary.as_ref() {
            if cfg.trusted_binaries.contains(binary) {
                push_to_a = false;
            }
        }
        if push_to_a {
            actor.events.push(event.clone());
        }

        if let Event::Execve { binary } = event {
            let actors = self.get_pid_dequeue(pid);
            let mut actor = Actor::new(pid);
            actor.binary = Some(binary);
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
            actors.push_back(Actor::new(pid));
        }

        let actor = actors.back().unwrap();
        if let ActorState::Exited = actor.state {
            actors.push_back(Actor::new(pid));
        }

        actors.back_mut().unwrap()
    }
}
