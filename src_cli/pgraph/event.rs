use std::mem;

use anyhow::{Result, bail};

use crate::{bpf::CEvent, bpf::event_types, utils::TotalMem};

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
        if !valid(bytes[0], b'-', b'r')
            || !valid(bytes[1], b'-', b'w')
            || !valid(bytes[2], b'-', b'x')
        {
            bail!("invalid access mode");
        }

        Ok(Self {
            read: bytes[0] == b'r',
            write: bytes[1] == b'w',
            execute: bytes[2] == b'x',
        })
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
