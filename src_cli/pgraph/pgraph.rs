use std::collections::{HashMap, HashSet, VecDeque};

use crate::pgraph::{Actor, ActorTuid};

/// This type represents the bare minimum metadata of each actor/process.
/// It just holds ids we can use to look up the actual actor object in the
/// hashmap contain in the PGraph
#[derive(Debug, Clone)]
pub struct PGraphNode {
    creator_tuid: ActorTuid,
    child_tuids: HashSet<ActorTuid>,
    children_alive: u32,
    pub actor: Actor,
}

/// This is the main structure that holds the graph of all the processes.
pub struct PGraph {
    // This is where all the actual actor objects are stored
    actors: HashMap<ActorTuid, PGraphNode>,

    // This maps every pid to the ktime (kernel start time) of all processes that have had this PID
    pid_map: HashMap<i32, VecDeque<u64>>,
}

impl PGraphNode {
    fn new(actor: Actor, creator_tuid: ActorTuid) -> Self {
        Self {
            creator_tuid,
            child_tuids: HashSet::new(),
            children_alive: 0,
            actor,
        }
    }
}

impl PGraph {
    pub fn new() -> Self {
        PGraph {
            actors: HashMap::new(),
            pid_map: HashMap::new(),
        }
    }

    /// Returns the most recent actor with the PID passed
    /// Note, this does not guarantee that the actor is alive
    pub fn get_node_by_latest_pid_mut(&mut self, pid: i32) -> Option<&mut PGraphNode> {
        let start_ktime = *self.pid_map.get(&pid)?.iter().last()?;
        let tuid = ActorTuid { pid, start_ktime };
        self.actors.get_mut(&tuid)
    }

    /// Inserts the actor into the PGraph data structure
    /// This makes sure to update the creator PGraphNode and pid_map to keep everything consistent
    pub fn insert_actor(&mut self, actor: Actor, creator_tuid: ActorTuid) {
        let pnode = PGraphNode::new(actor, creator_tuid);

        let creator = self.actors.get_mut(&creator_tuid).unwrap();

        creator.children_alive += 1;
        creator.child_tuids.insert(pnode.actor.id);
        self.actors.insert(pnode.actor.id, pnode);
    }
}
