use std::fmt;

use anyhow::{Result, bail};

use crate::{bpf::CEvent, bpf::event_types};

#[derive(Clone, Copy, Hash)]
pub struct AccessType {
    read: bool,
    write: bool,
    execute: bool,
}

impl fmt::Debug for AccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = [
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
        ];

        write!(f, "AccessType(\"{}{}{}\")", mode[0], mode[1], mode[2])
    }
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

    pub fn to_rwx_str(&self, out_str: &mut String) {
        out_str.push(if self.read { 'r' } else { '-' });
        out_str.push(if self.write { 'w' } else { '-' });
        out_str.push(if self.execute { 'x' } else { '-' });
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
            event_types::GENE_START => {
                let creator_pid = c_event.get_spare::<i32>(0);
                EventArgs::Start { creator_pid }
            }
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

impl EventArgs {
    pub fn is_complex(&self) -> bool {
        matches!(self, Self::Start { .. } | Self::Exit)
    }
}
