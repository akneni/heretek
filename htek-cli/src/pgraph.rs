use std::collections::HashMap;

use crate::actor::Actor;

pub trait PGraph {
    fn get<'a>(&'a mut self, pid: i32, s_time: u64) -> Option<&'a mut Actor>;
    fn insert(&mut self, actor: Actor);
    fn delete(&mut self, pid: i32, s_time: u64);
    fn get_latest_prior<'a>(&'a mut self, pid: i32, time: u64) -> Option<&'a mut Actor>;
    fn get_latest<'a>(&'a mut self, pid: i32) -> Option<&'a mut Actor>;

    fn get_parent<'a>(&'a mut self, actor: &mut Actor) -> Option<&'a mut Actor>;
}


#[derive(Debug, Clone)]
pub struct PGraphHm {
    map: HashMap<(i32, u64), Actor>,
    pid_list: HashMap<i32, Vec<u64>>,
}


impl PGraph for PGraphHm {
    fn get<'a>(&'a mut self, pid: i32, s_time: u64) -> Option<&'a mut Actor> {
        self.map.get_mut(&(pid, s_time))
    }

    fn insert(&mut self, actor: Actor) {
        if let Some(_) = self.get(actor.pid, actor.start_ktime) {
            panic!("This actor already exists");
        }

        let entry = self.pid_list.entry(actor.pid);
        entry.or_default().push(actor.start_ktime);

        self.map.insert((actor.pid, actor.start_ktime), actor);
    }

    fn delete(&mut self, pid: i32, s_time: u64) {
        self.map.remove(&(pid, s_time));
    }

    fn get_latest<'a>(&'a mut self, pid: i32) -> Option<&'a mut Actor> {
        let s_time = self.pid_list.get(&pid)?.last()?;

        // We're unwrapping this to ensure that it fails if pid_list
        // contains an entry that map does not. 
        Some(self.map.get_mut(&(pid, *s_time)).unwrap())
    }

    fn get_latest_prior<'a>(&'a mut self, pid: i32, time: u64) -> Option<&'a mut Actor> {
        let mut s_time: Option<u64> = None;
        let pids = self.pid_list.get(&pid)?;

        for idx in 0..pids.len() {
            if idx < pids.len() - 1 {
                if pids[idx] < time && pids [idx+1] > time {
                    s_time = Some(pids[idx]);
                    break;
                }
            }
            else {
                if pids[idx] < time {
                    s_time = Some(pids[idx]);
                    break;
                }
            }
        }

        if let Some(s_time) = s_time {
            let actor = self.map.get_mut(&(pid, s_time)).unwrap();
            return Some(actor);
        }

        None
    }

    fn get_parent<'a>(&'a mut self, actor: &mut Actor) -> Option<&'a mut Actor> {
        if let Some(cpid) = actor.creator_pid {
            return self.get_latest_prior(cpid, actor.start_ktime);
        }
        None
    }
}