use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Write,
    fs, io,
};

use crate::pgraph::{Actor, ActorState, ActorTuid};

/// This type represents the bare minimum metadata of each actor/process.
/// It just holds ids we can use to look up the actual actor object in the
/// hashmap contain in the PGraph
#[derive(Debug, Clone)]
pub struct PGraphNode {
    pub creator_tuid: Option<ActorTuid>,
    pub child_tuids: HashSet<ActorTuid>,
    pub actor: Actor,
}

/// This is the main structure that holds the graph of all the processes.
pub struct PGraph {
    // This is where all the actual actor objects are stored
    pub nodes: HashMap<ActorTuid, PGraphNode>,

    // This maps every pid to the ktime (kernel start time) of all processes that have had this PID
    pub pid_map: HashMap<i32, VecDeque<u64>>,
}

impl PGraphNode {
    fn new(actor: Actor, creator_tuid: Option<ActorTuid>) -> Self {
        Self {
            creator_tuid,
            child_tuids: HashSet::new(),
            actor,
        }
    }

    /// Used for debugging
    /// detail = 0 : Just PID and command
    /// detail = 1 : Just PID and command + args
    /// detail = 2 : PID and command + args and all files accessed
    pub fn to_str(&self, detail: i32) -> String {
        let actor = &self.actor;
        let status: &str = match actor.actor_md.state {
            ActorState::Running => "running ",
            ActorState::Exited => "exited  ",
        };

        let ppid = self
            .creator_tuid
            .map(|x| x.pid.to_string())
            .unwrap_or("?".to_string());
        let mut s = format!("(PID = {}) (PPID = {}) ({}) ", actor.id.pid, ppid, status);

        match actor.actor_md.binary.last() {
            Some(r) => {
                let r_str = r.to_str().unwrap();
                s.push_str(r_str);
                s.push(' ');
            }
            None => {
                s.push_str("[binary unkown] ");
            }
        }

        if detail < 1 {
            return s;
        }

        let argv = actor.actor_md.argv.last();
        if let Some(argv) = argv
            && let Some(argv) = argv
            && !argv.is_empty()
        {
            let argv = argv[1..].join(" ");
            s.push_str(&argv);
        }
        s.push('\n');

        if detail < 2 {
            return s;
        }
        s.push_str("Filed Accessed:\n");
        for (k, v) in actor.summary.events.iter() {
            s.push('\t');
            v.to_rwxbc_str(&mut s);
            s.push_str(" | ");
            writeln!(&mut s, "{:?}", k).unwrap();
        }

        if detail < 3 {
            return s;
        }

        s.push_str("Binaries Spawned:\n");
        for (idx, child_tuid) in self.child_tuids.iter().enumerate() {
            writeln!(&mut s, "\t{} | PID = {}", idx, child_tuid.pid).unwrap();
        }

        s
    }
}

impl PGraph {
    pub fn new() -> Self {
        PGraph {
            nodes: HashMap::new(),
            pid_map: HashMap::new(),
        }
    }

    /// Scans the /proc directory and constructs the Pgraph (in a best effort manner)
    /// It will assume that the parent ID of a process is the creator ID.
    pub fn from_existing_processes() -> Self {
        let mut pgraph = Self::new();
        let hz = match clock_ticks_per_second() {
            Ok(hz) => hz,
            Err(_) => return pgraph,
        };

        let proc_entries = match fs::read_dir("/proc") {
            Ok(entries) => entries,
            Err(_) => return pgraph,
        };

        let mut processes = Vec::new();

        for entry in proc_entries.flatten() {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };

            let Ok(pid) = file_name.parse::<i32>() else {
                continue;
            };

            let Ok((ppid, start_ktime)) = read_proc_stat(pid, hz) else {
                continue;
            };

            let actor = match Actor::new_bootstrap_md(pid, start_ktime) {
                Ok(r) => r,
                Err(_e) => {
                    // If this happens, its likely because the /proc/pid directory was for a kthread
                    // rather than a userspace process
                    continue;
                }
            };

            pgraph
                .pid_map
                .entry(pid)
                .or_default()
                .push_back(start_ktime);
            processes.push((actor, ppid));
        }

        let pid_to_tuid = processes
            .iter()
            .map(|(actor, _)| (actor.id.pid, actor.id))
            .collect::<HashMap<_, _>>();

        let mut child_edges = Vec::new();

        for (actor, ppid) in processes {
            let actor_tuid = actor.id;
            let creator_tuid = pid_to_tuid.get(&ppid).copied();

            if let Some(creator_tuid) = creator_tuid {
                child_edges.push((creator_tuid, actor_tuid));
            }

            pgraph
                .nodes
                .insert(actor_tuid, PGraphNode::new(actor, creator_tuid));
        }

        for (creator_tuid, child_tuid) in child_edges {
            if let Some(creator) = pgraph.nodes.get_mut(&creator_tuid) {
                creator.child_tuids.insert(child_tuid);
            }
        }
        pgraph
    }

    /// Returns the most recent actor with the PID passed
    /// Note, this does not guarantee that the actor is alive
    pub fn get_latest_mut(&mut self, pid: i32) -> Option<&mut PGraphNode> {
        let start_ktime = *self.pid_map.get(&pid)?.iter().last()?;
        let tuid = ActorTuid { pid, start_ktime };
        self.nodes.get_mut(&tuid)
    }

    /// Returns the Node whose actor has the same PID as the one passed and the lastest start time
    /// that comes before the start time passed.
    pub fn get_latest_prior_mut(&mut self, pid: i32, ktime: u64) -> Option<&mut PGraphNode> {
        let ktime_vec = self.pid_map.get(&pid)?;
        let mut real_ktime = None;
        for &kt in ktime_vec.iter().rev() {
            if kt < ktime {
                real_ktime = Some(kt);
                break;
            }
        }

        let tuid = ActorTuid {
            pid,
            start_ktime: real_ktime.unwrap(),
        };
        self.nodes.get_mut(&tuid)
    }

    /// Inserts the actor into the PGraph data structure
    /// This makes sure to update the creator PGraphNode and pid_map to keep everything consistent
    pub fn insert_actor(&mut self, mut actor: Actor, creator_tuid: ActorTuid) {
        // Update creator's child vec
        let creator = self.get_or_create(creator_tuid);
        creator.child_tuids.insert(actor.id);

        // Assign the creator's profiles to the child
        for prof in creator.actor.actor_md.profile.iter() {
            actor.actor_md.profile.insert(prof.clone());
        }

        // Update pid map
        let entry = self.pid_map.entry(actor.id.pid);
        let ktimes = entry.or_default();
        ktimes.push_back(actor.id.start_ktime);

        // Insert actor into the nodes map
        let pnode = PGraphNode::new(actor, Some(creator_tuid));
        self.nodes.insert(pnode.actor.id, pnode);
    }

    fn get_or_create(&mut self, tuid: ActorTuid) -> &mut PGraphNode {
        let entry = self.nodes.entry(tuid);
        entry.or_insert_with(|| {
            let actor = Actor::new(tuid.pid, tuid.start_ktime);
            PGraphNode::new(actor, None)
        })
    }
}

fn read_proc_stat(pid: i32, hz: u64) -> io::Result<(i32, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_comm = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad /proc stat format"))?
        .1;

    let fields = after_comm.split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing /proc stat fields",
        ));
    }

    let ppid = fields[1]
        .parse::<i32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ppid field"))?;
    let starttime_ticks = fields[19]
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid starttime field"))?;

    Ok((ppid, starttime_ticks.saturating_mul(1_000_000_000) / hz))
}

fn clock_ticks_per_second() -> io::Result<u64> {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return Err(io::Error::other("sysconf(_SC_CLK_TCK) failed"));
    }

    Ok(hz as u64)
}
