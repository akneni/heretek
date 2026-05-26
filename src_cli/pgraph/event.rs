use std::{
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};

use crate::{
    bpf::{CEvent, event_types},
    pgraph::Actor,
};

#[derive(Default, Clone, Copy, Hash)]
pub struct AccessType {
    read: bool,
    write: bool,
    execute: bool,
    bind: bool,
    connect: bool,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub pid: i32,
    pub ktime: u64,
    pub args: EventArgs,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub enum EventArgs {
    // System Calls
    Execve {
        binary: PathBuf,
    },
    Openat {
        fpath: PathBuf,
        mode: AccessType,
    },
    Mmap {
        fpath: Option<PathBuf>,
        mode: AccessType,
    },
    ConnectUds {
        fpath: PathBuf,
    },
    Rename {
        src: PathBuf,
        dst: PathBuf,
    },
    ChDir {
        dpath: PathBuf,
    },

    // Generic Events
    Exit,
    Start {
        creator_pid: i32,
    },
}

impl fmt::Debug for AccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = [
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
            if self.bind { 'b' } else { '-' },
            if self.connect { 'c' } else { '-' },
        ];

        write!(
            f,
            "AccessType(\"{}{}{}{}{}\")",
            mode[0], mode[1], mode[2], mode[3], mode[4]
        )
    }
}

impl AccessType {
    pub fn from_spare(spare: u8) -> Self {
        const O_RDONLY: u8 = 0;
        const O_WRONLY: u8 = 1;
        const O_RDWR: u8 = 2;

        match spare {
            O_RDONLY => Self {
                read: true,
                ..Self::default()
            },
            O_WRONLY => Self {
                write: true,
                ..Self::default()
            },
            O_RDWR => Self {
                read: true,
                write: true,
                ..Self::default()
            },
            _ => Self::default(),
        }
    }

    pub fn union(&mut self, other: AccessType) {
        self.read |= other.read;
        self.write |= other.write;
        self.execute |= other.execute;
        self.bind |= other.bind;
        self.connect |= other.connect;
    }

    #[allow(unused)]
    pub fn intersection(&mut self, other: AccessType) {
        self.read &= other.read;
        self.write &= other.write;
        self.execute &= other.execute;
        self.bind &= other.bind;
        self.connect &= other.connect;
    }

    /// Returns true if self is a non-strict superset of other
    pub fn is_superset_of(&self, other: AccessType) -> bool {
        (!other.read || self.read)
            && (!other.write || self.write)
            && (!other.execute || self.execute)
            && (!other.bind || self.bind)
            && (!other.connect || self.connect)
    }

    /// Returns true if self is a non-strict subset of other
    #[allow(unused)]
    pub fn is_subset_of(&self, other: AccessType) -> bool {
        other.is_superset_of(*self)
    }

    pub fn from_str(mode: &str) -> Result<Self> {
        let bytes = mode.as_bytes();
        if bytes.len() != 3 && bytes.len() != 5 {
            bail!("access mode must be exactly 3 or 5 characters");
        }

        let valid = |on: u8, off: u8, expected: u8| on == expected || on == off;
        if !valid(bytes[0], b'-', b'r')
            || !valid(bytes[1], b'-', b'w')
            || !valid(bytes[2], b'-', b'x')
            || (bytes.len() == 5 && !valid(bytes[3], b'-', b'b'))
            || (bytes.len() == 5 && !valid(bytes[4], b'-', b'c'))
        {
            bail!("invalid access mode");
        }

        Ok(Self {
            read: bytes[0] == b'r',
            write: bytes[1] == b'w',
            execute: bytes[2] == b'x',
            bind: bytes.len() == 5 && bytes[3] == b'b',
            connect: bytes.len() == 5 && bytes[4] == b'c',
        })
    }

    pub fn to_rwxbc_str(self, out_str: &mut String) {
        out_str.push(if self.read { 'r' } else { '-' });
        out_str.push(if self.write { 'w' } else { '-' });
        out_str.push(if self.execute { 'x' } else { '-' });
        out_str.push(if self.bind { 'b' } else { '-' });
        out_str.push(if self.connect { 'c' } else { '-' });
    }
}

impl Event {
    pub fn from(c_event: &CEvent) -> Result<Self> {
        let args = match c_event.event {
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

    pub fn from_resolve(c_event: &CEvent, actor: &Actor) -> Result<Self> {
        let args = match c_event.event {
            event_types::SYSCALL_OPENAT => EventArgs::Openat {
                fpath: actor.resolve_path_str(&c_event.fpath_str(1)?)?,
                mode: AccessType::from_spare(c_event.spare[0]),
            },
            event_types::GENE_CONNECT_UDS => EventArgs::ConnectUds {
                fpath: actor.resolve_path_str(&c_event.fpath_str(1)?)?,
            },
            event_types::SYSCALL_EXECVE => EventArgs::Execve {
                binary: actor.resolve_path_str(&c_event.fpath_str(1)?)?,
            },
            event_types::SYSCALL_CHDIR => EventArgs::ChDir {
                dpath: actor.resolve_path_str(&c_event.fpath_str(1)?)?,
            },
            event_types::GENE_START | event_types::GENE_EXIT => Self::from(c_event)?.args,
            _ => bail!("unsupported event"),
        };

        Ok(Self {
            pid: c_event.pid,
            ktime: c_event.ktime,
            args,
        })
    }
}
