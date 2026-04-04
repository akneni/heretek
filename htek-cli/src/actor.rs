use std::collections::{HashMap, VecDeque};

use anyhow::{Result, bail};

use crate::{bpfmap::CEvent, syscalls};

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
struct ActorsDb {
    db: HashMap<i32, VecDeque<Actor>>,
}


impl Event {
    pub fn from(c_event: &CEvent) -> Result<Self> {
        match c_event.event {
            syscalls::OPENAT => {
                Ok(Self::Openat { fpath: c_event.fpath_str(1)? })
            }
            _ => bail!("unsupported event"),
        }
    }
}