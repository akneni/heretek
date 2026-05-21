mod actor;
mod event;
mod pgraph;

use std::{fs, mem};

pub use actor::*;
pub use event::*;
pub use pgraph::*;

/// This is the bulk of this program.
/// It updates the Pgraph with the events and detects any violations
pub fn handle_event(pgraph: &mut PGraph, event: Event) {
    if event.args.is_complex() {
        handle_complex_event(pgraph, event);
    } else {
        handle_simple_event(pgraph, event);
    }
}

/// A simple event is one that does not need to add or remove nodes from teh PGraph
fn handle_simple_event(pgraph: &mut PGraph, event: Event) {
    let node = match pgraph.get_latest_prior_mut(event.pid, event.ktime) {
        Some(r) => r,
        None => return,
    };

    let violation;

    match event.args {
        EventArgs::Mmap { fpath, mode } => {
            violation = node.actor.handle_mmap(fpath, mode);
        }
        EventArgs::Openat { fpath, mode } => {
            violation = node.actor.handle_openat(fpath, mode);
        }
        EventArgs::Rename { src, dst } => {
            violation = node.actor.handle_rename(src, dst);
        }
        EventArgs::Execve { binary } => {
            violation = node.actor.handle_execve(binary);
        }
        _ => {
            panic!("Not supported");
        }
    }

    if violation {
        println!("violation:\n\n{:?}", node.actor);
    }
}

fn handle_complex_event(pgraph: &mut PGraph, event: Event) {
    match event.args {
        EventArgs::Start { creator_pid } => {
            let actor = Actor::new(event.pid, event.ktime);
            let creator_tuid = {
                let creator_node = match pgraph.get_latest_prior_mut(creator_pid, event.ktime) {
                    Some(r) => r,
                    None => {
                        eprintln!("START get_latest_prior_mut Failed for ({:?})", (event));
                        eprintln!("{:?}\n\n", pgraph.pid_map.get(&creator_pid));
                        return;
                    }
                };

                creator_node.actor.id
            };
            pgraph.insert_actor(actor, creator_tuid);
        }
        EventArgs::Exit => {
            let node = match pgraph.get_latest_prior_mut(event.pid, event.ktime) {
                Some(r) => r,
                None => return,
            };
            node.actor.actor_md.state = ActorState::Exited;
        }
        _ => {
            panic!("Not supported");
        }
    }
}
