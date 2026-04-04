use std::{
    collections::{HashMap, VecDeque}, fs, mem, path::Path
};

use anyhow::{Result, bail};

use crate::{bpfmap::CEvent, syscalls, utils::TotalMem};

#[derive(Debug, Clone)]
pub enum Event {
    Execve { binary: String },
    Openat { fpath: String },
    Mmap { fpath: Option<String> },
    Rename { src: String, dst: String },
}

#[derive(Debug, Clone, Copy)]
pub enum ActroState {
    Running,
    Exited,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pid: i32,
    start_time: u64,
    state: ActroState,
    spawner_pid: Option<i32>,
    binary: Option<String>,
    argv: Option<Vec<String>>,
    events: Vec<Event>,
}

#[derive(Debug)]
pub struct ActorsDb {
    pub db: HashMap<i32, VecDeque<Actor>>,
}

impl Event {
    pub fn from(c_event: &CEvent) -> Result<Self> {
        match c_event.event {
            syscalls::OPENAT => Ok(Self::Openat {
                fpath: c_event.fpath_str(1)?,
            }),
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
            Self::Openat { fpath } => {
                size += fpath.len();
            }
            Self::Mmap { fpath } => {
                if let Some(fpath) = fpath {
                    size += fpath.len();
                }
            }
            Self::Rename { src, dst } => {
                size += src.len();
                size += dst.len();
            }
        }
        size
    }
}

impl TotalMem for ActroState {
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

        Self {
            pid,
            start_time: 0,
            state: ActroState::Running,
            spawner_pid: None,
            binary: comm,
            argv: None,
            events: vec![],
        }
    }
}

impl ActorsDb {
    pub fn new() -> Self {
        Self { db: HashMap::new() }
    }

    pub fn insert_event(&mut self, pid: i32, event: Event) {
        let entry = self.db.entry(pid);
        let actors = entry.or_default();
        if actors.len() == 0 {
            actors.push_back(Actor::new(pid));
        }

        let actor = actors.back_mut().unwrap();
        actor.events.push(event);
    }
}
