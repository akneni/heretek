mod actor;
mod event;
#[allow(clippy::module_inception)]
mod pgraph;

use std::process;

pub use actor::*;
use anyhow::Result;
pub use event::*;
pub use pgraph::*;

use crate::bpf::{CEvent, event_types};
use crate::detection::PolicyVerdict;
use crate::response::handle_response;
use crate::uinterf::Config;
use crate::{build_params, utils};

/// This is the bulk of this program.
/// It updates the Pgraph with the events and detects any violations
pub fn handle_event(config: &Config, pgraph: &mut PGraph, cevent: &CEvent) -> Result<()> {
    match cevent.event {
        event_types::GENE_START => {
            let event = Event::from(cevent)?;
            let creator_pid = match event.args {
                EventArgs::Start { creator_pid } => creator_pid,
                _ => {
                    utils::unreachable();
                    return Ok(());
                }
            };

            let actor = Actor::new(event.pid, event.ktime);
            let creator_tuid = {
                let creator_node = match pgraph.get_latest_prior_mut(creator_pid, event.ktime) {
                    Some(r) => r,
                    None => {
                        tracing::warn!("Unknown Creator Process for ({:?})", (event));
                        if build_params::ASSERTS {
                            process::exit(1);
                        }
                        return Ok(());
                    }
                };

                creator_node.actor.id
            };
            pgraph.insert_actor(actor, creator_tuid);
        }
        _ => {
            handle_simple_event(config, pgraph, cevent);
        }
    }
    Ok(())
}

/// A simple event is one that does not need to add or remove nodes from teh PGraph
fn handle_simple_event(config: &Config, pgraph: &mut PGraph, cevent: &CEvent) {
    let actor_tuid = {
        let node = match pgraph.get_latest_prior_mut(cevent.pid, cevent.ktime) {
            Some(r) => r,
            None => return,
        };
        node.actor.id
    };

    let event = {
        let node = match pgraph.nodes.get(&actor_tuid) {
            Some(r) => r,
            None => return,
        };

        match Event::from_resolve(cevent, &node.actor) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Error parsing CEvent: {e}");
                return;
            }
        }
    };

    let mut violations = Vec::new();
    let mut current_tuid = Some(actor_tuid);
    let mut child_owned = false;

    while let Some(tuid) = current_tuid {
        let creator_tuid = {
            let node = match pgraph.nodes.get_mut(&tuid) {
                Some(r) => r,
                None => break,
            };

            if node.unchained_chain {
                break;
            }

            let violation = node.actor.handle_event(config, &event, child_owned);
            if let PolicyVerdict::Violation { .. } = violation {
                violations.push(violation);
            }

            node.creator_tuid
        };

        current_tuid = creator_tuid;
        child_owned = true;
    }

    handle_response(config, pgraph, &violations);
}
