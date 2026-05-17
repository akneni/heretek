use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::Result;

use crate::pgraph::{Actor, ActorTuid};

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
    actors: HashMap<ActorTuid, PGraphNode>,

    // This maps every pid to the ktime (kernel start time) of all processes that have had this PID
    pid_map: HashMap<i32, VecDeque<u64>>,
}

impl PGraphNode {
    fn new(actor: Actor, creator_tuid: Option<ActorTuid>) -> Self {
        Self {
            creator_tuid,
            child_tuids: HashSet::new(),
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
    pub fn get_latest_mut(&mut self, pid: i32) -> Option<&mut PGraphNode> {
        let start_ktime = *self.pid_map.get(&pid)?.iter().last()?;
        let tuid = ActorTuid { pid, start_ktime };
        self.actors.get_mut(&tuid)
    }

    /// Returns the Node whose actor has the same PID as the one passed and the lastest start time 
    /// that comes before the start time passed. 
    pub fn get_latest_prior_mut(&mut self, pid: i32, ktime: u64) -> Option<&mut PGraphNode> {
        let ktime_vec = self.pid_map.get(&pid)?;
        let mut real_ktime = None;
        for &kt in ktime_vec.iter().rev() {
            if kt < ktime {
                real_ktime = Some(kt);
                break ;
            }
        }

        let tuid = ActorTuid {pid, start_ktime: real_ktime.unwrap()};
        self.actors.get_mut(&tuid)
    }

    /// Inserts the actor into the PGraph data structure
    /// This makes sure to update the creator PGraphNode and pid_map to keep everything consistent
    pub fn insert_actor(&mut self, actor: Actor, creator_tuid: ActorTuid) {
        let pnode = PGraphNode::new(actor, Some(creator_tuid));

        let creator = self.get_or_create(creator_tuid);

        creator.child_tuids.insert(pnode.actor.id);
        self.actors.insert(pnode.actor.id, pnode);
    }

    fn get_or_create(&mut self, tuid: ActorTuid) -> &mut PGraphNode {
        let entry = self.actors.entry(tuid);
        entry.or_insert_with(|| {
            let actor = Actor::new(tuid.pid, tuid.start_ktime);
            PGraphNode::new(actor, None)
        })
    }
}
