mod actor;
mod event;
mod pgraph;

pub use actor::*;
pub use event::*;
pub use pgraph::*;

use crate::detection::PolicyVerdict;
use crate::uinterf::Config;

/// This is the bulk of this program.
/// It updates the Pgraph with the events and detects any violations
pub fn handle_event(config: &Config, pgraph: &mut PGraph, event: Event) {
    if event.args.is_complex() {
        handle_complex_event(config, pgraph, event);
    } else {
        handle_simple_event(config, pgraph, event);
    }
}

/// A simple event is one that does not need to add or remove nodes from teh PGraph
fn handle_simple_event(config: &Config, pgraph: &mut PGraph, event: Event) {
    let node = match pgraph.get_latest_prior_mut(event.pid, event.ktime) {
        Some(r) => r,
        None => return,
    };

    let violation = match event.args {
        EventArgs::Mmap { fpath, mode } => node.actor.handle_mmap(config, fpath, mode),
        EventArgs::Openat { fpath, mode } => node.actor.handle_openat(config, fpath, mode),
        EventArgs::ConnectUds { fpath } => node.actor.handle_connect_uds(config, fpath),
        EventArgs::Rename { src, dst } => node.actor.handle_rename(config, src, dst),
        EventArgs::Execve { binary } => node.actor.handle_execve(config, binary),
        _ => {
            panic!("Not supported");
        }
    };

    if let PolicyVerdict::Violation { .. } = violation {
        println!(
            "violation:\n{:?}\n\nActor:\n{}\n\n\n",
            violation,
            node.to_str(1)
        );
    }
}

fn handle_complex_event(_config: &Config, pgraph: &mut PGraph, event: Event) {
    match event.args {
        EventArgs::Start { creator_pid } => {
            let actor = Actor::new(event.pid, event.ktime);
            let creator_tuid = {
                let creator_node = match pgraph.get_latest_prior_mut(creator_pid, event.ktime) {
                    Some(r) => r,
                    None => {
                        if cfg!(debug_assertions) {
                            eprintln!("Unknown Creator Process for ({:?})", (event));
                        }
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
