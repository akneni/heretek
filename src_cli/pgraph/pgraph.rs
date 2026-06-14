use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Write as FmtWrite,
    fs, io, process,
    time::Instant,
};

use crate::{
    build_params,
    pgraph::{Actor, ActorState, ActorTuid},
    uinterf::{Config, IncFile},
};

/// This type represents the bare minimum metadata of each actor/process.
/// It just holds ids we can use to look up the actual actor object in the
/// hashmap contain in the PGraph
#[derive(Debug, Clone)]
pub struct PGraphNode {
    pub creator_tuid: Option<ActorTuid>,
    pub child_tuids: HashSet<ActorTuid>,
    pub actor: Actor,

    // If this is set to true, it means that this node as well as all parent nodes have the
    // "unchaned" profile and no others.
    pub unchained_chain: bool,
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
            unchained_chain: false,
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
                let r_str = r.to_str().unwrap_or("[binary unkown] ");
                s.push_str(r_str);
                s.push(' ');
            }
            None => {
                s.push_str("[binary unkown] ");
            }
        }

        if detail < 1 {
            s.push_str(&format!("\nProfiles: {:?}", self.actor.actor_md.profile));
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
        s.push_str(&format!("\nProfiles: {:?}\n", self.actor.actor_md.profile));

        if detail < 2 {
            return s;
        }
        s.push_str("Filed Accessed:\n");
        for (k, v) in actor.summary.events.iter() {
            s.push('\t');
            v.to_rwxbc_str(&mut s);
            s.push_str(" | ");
            let _ = writeln!(&mut s, "{:?}", k);
        }

        if detail < 3 {
            return s;
        }

        s.push_str("Binaries Spawned:\n");
        for (idx, child_tuid) in self.child_tuids.iter().enumerate() {
            let _ = writeln!(&mut s, "\t{} | PID = {}", idx, child_tuid.pid);
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
            start_ktime: real_ktime?,
        };
        self.nodes.get_mut(&tuid)
    }

    /// Inserts the actor into the PGraph data structure
    /// This makes sure to update the creator PGraphNode and pid_map to keep everything consistent
    pub fn insert_actor(&mut self, actor: Actor, creator_tuid: ActorTuid) {
        // Update creator's child vec
        let creator = match self.nodes.get_mut(&creator_tuid) {
            Some(r) => r,
            None => {
                if build_params::ASSERTS {
                    panic!("insert_actor called with a creator_tuid that doesn't exist");
                }
                return;
            }
        };

        creator.child_tuids.insert(actor.id);
        let unchained_chain = creator.unchained_chain && actor.actor_md.profile.is_empty();
        let cwd = creator.actor.actor_md.cwd.clone();

        // Update pid map
        let entry = self.pid_map.entry(actor.id.pid);
        let ktimes = entry.or_default();
        ktimes.push_back(actor.id.start_ktime);

        // Insert actor into the nodes map
        let mut pnode = PGraphNode::new(actor, Some(creator_tuid));
        pnode.unchained_chain = unchained_chain;
        pnode.actor.actor_md.cwd = cwd;
        self.nodes.insert(pnode.actor.id, pnode);
    }

    #[allow(unused)]
    fn get_or_create(&mut self, tuid: ActorTuid) -> &mut PGraphNode {
        let entry = self.nodes.entry(tuid);
        entry.or_insert_with(|| {
            let actor = Actor::new(tuid.pid, tuid.start_ktime);
            PGraphNode::new(actor, None)
        })
    }
}

/// This block only contains from_existing_processes and its helper functions
impl PGraph {
    /// Scans the /proc directory and constructs the Pgraph (in a best effort manner)
    /// It will assume that the parent ID of a process is the creator ID.
    pub fn from_existing_processes(config: &Config) -> Self {
        let mut pgraph = Self::new();
        let hz = match Self::clock_ticks_per_second() {
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

            let Ok((ppid, start_ktime)) = Self::read_proc_stat(pid, hz) else {
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

        for (mut actor, ppid) in processes {
            let actor_tuid = actor.id;
            let creator_tuid = pid_to_tuid.get(&ppid).copied();

            if let Some(creator_tuid) = creator_tuid {
                child_edges.push((creator_tuid, actor_tuid));
            }

            // Get the profile for this action
            let actor_bin = actor.actor_md.binary.last().cloned();
            if let Some(actor_bin) = actor_bin {
                let actor_profile = config.profile_config.get_profile(&actor_bin);
                actor.actor_md.profile.insert(actor_profile.to_string());
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

        pgraph.update_bootstrap_unchained_chains();
        pgraph
    }

    /// Checks that all nodes with unchained_chain = true are really unchaned
    /// and checks that the same is true for all it's parents.
    /// This function does nothing and is compiled out in release builds
    pub fn check_unchained_chains_dbgo(&self, config: &Config) {
        if !build_params::ASSERTS {
            return;
        }

        let timer = Instant::now();
        let mut unchaineds: HashSet<ActorTuid> = HashSet::new();
        let mut errors = vec![];

        for (&tuid, node) in self.nodes.iter() {
            if !node.unchained_chain {
                continue;
            }

            if !node.actor.is_unchained() {
                errors.push(format!(
                    "unchained chain actor isn't unchained\nActor TUID: {:?}",
                    tuid
                ));
            }

            let mut curr_node = node;
            let initial_len = errors.len();
            let mut unchaineds_curr = HashSet::new();
            unchaineds_curr.insert(tuid);
            loop {
                let curr_tuid = match curr_node.creator_tuid {
                    Some(r) => r,
                    None => break,
                };

                if unchaineds.contains(&curr_tuid) {
                    break;
                }
                curr_node = match self.nodes.get(&curr_tuid) {
                    Some(r) => r,
                    None => {
                        errors.push(format!(
                            "Actor has a creator_tuid that doesn't exist\nParent TUID: {:?}\nChild TUID: {:?}",
                            curr_tuid,
                            tuid,
                        ));
                        continue;
                    }
                };

                if !curr_node.actor.is_unchained() {
                    errors.push(format!(
                        "unchained chain actor has a chained parent\nParent TUID: {:?}\nChild TUID: {:?}",
                        curr_node.actor.id,
                        tuid,
                    ));
                }
                unchaineds_curr.insert(curr_tuid);
            }

            if initial_len == errors.len() {
                unchaineds.extend(unchaineds_curr.iter());
            }
        }

        if !errors.is_empty() {
            let mut inc_file =
                match IncFile::new(config, "ASSERTION FAILED [check_unchained_chains_dbgo]") {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Failed to create incident file: {e}");
                        process::exit(1);
                    }
                };

            let _ = inc_file.dmp_stacktrace();
            let _ = inc_file.dmp_debugable("Errors", &errors);
            let _ = inc_file.dmp_pgraph(self);
            process::exit(1);
        }

        if build_params::PERF_TRACKING {
            println!(
                "Time Elapsed [check_unchained_chains_dbgo]: {:?}",
                timer.elapsed()
            );
        }
    }

    pub fn check_cycles_dbgo(&self, config: &Config) {
        if !build_params::ASSERTS {
            return;
        }

        let timer = Instant::now();
        let mut errors = vec![];

        let mut nodes_seen = HashSet::new();
        for (&tuid, node) in self.nodes.iter() {
            nodes_seen.clear();
            nodes_seen.insert(tuid);

            let mut curr_node = node;
            loop {
                let curr_tuid = match curr_node.creator_tuid {
                    Some(r) => r,
                    None => break,
                };

                if nodes_seen.contains(&curr_tuid) {
                    errors.push(format!(
                        "Pgrah has cyclic references.\nTUID: {:?}",
                        curr_tuid
                    ));
                } else {
                    nodes_seen.insert(curr_tuid);
                }

                curr_node = match self.nodes.get(&curr_tuid) {
                    Some(r) => r,
                    None => {
                        errors.push(format!(
                            "Actor has a creator_tuid that doesn't exist\nParent TUID: {:?}\nChild TUID: {:?}",
                            curr_tuid,
                            tuid,
                        ));
                        continue;
                    }
                };
            }
        }

        if !errors.is_empty() {
            let mut inc_file =
                match IncFile::new(config, "ASSERTION FAILED [check_unchained_chains_dbgo]") {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Failed to create incident file: {e}");
                        process::exit(1);
                    }
                };

            let _ = inc_file.dmp_stacktrace();
            let _ = inc_file.dmp_debugable("Errors", &errors);
            let _ = inc_file.dmp_pgraph(self);
            process::exit(1);
        }

        if build_params::PERF_TRACKING {
            println!("Time Elapsed [check_cycles_dbgo]: {:?}", timer.elapsed());
        }
    }

    fn compute_bootstrap_unchained_chain(
        tuid: ActorTuid,
        nodes: &HashMap<ActorTuid, PGraphNode>,
        memo: &mut HashMap<ActorTuid, bool>,
        visiting: &mut HashSet<ActorTuid>,
    ) -> bool {
        if let Some(&unchained_chain) = memo.get(&tuid) {
            return unchained_chain;
        }

        if !visiting.insert(tuid) {
            return false;
        }

        let Some(node) = nodes.get(&tuid) else {
            visiting.remove(&tuid);
            memo.insert(tuid, false);
            return false;
        };

        let has_only_unchained_profile = node.actor.actor_md.profile.len() == 1
            && node.actor.actor_md.profile.contains("unchained");
        let parent_unchained_chain = match node.creator_tuid {
            Some(creator_tuid) => {
                Self::compute_bootstrap_unchained_chain(creator_tuid, nodes, memo, visiting)
            }
            None => node.actor.id.pid == 1,
        };
        let unchained_chain = has_only_unchained_profile && parent_unchained_chain;

        visiting.remove(&tuid);
        memo.insert(tuid, unchained_chain);

        unchained_chain
    }

    fn update_bootstrap_unchained_chains(&mut self) {
        let mut memo = HashMap::new();
        let mut visiting = HashSet::new();

        for tuid in self.nodes.keys().copied().collect::<Vec<_>>() {
            let unchained_chain = Self::compute_bootstrap_unchained_chain(
                tuid,
                &self.nodes,
                &mut memo,
                &mut visiting,
            );
            if let Some(node) = self.nodes.get_mut(&tuid) {
                node.unchained_chain = unchained_chain;
            }
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
}
