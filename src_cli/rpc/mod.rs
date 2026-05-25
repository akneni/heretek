mod ipc;
mod uds_utils;

use std::os::unix::net::UnixListener;

use anyhow::{Context, Result, bail};
pub use ipc::*;
pub use uds_utils::*;

use crate::{
    pgraph::{ActorState, PGraph},
    uinterf::Config,
};

pub fn handle_rpc(config: &Config, pgraph_db: &mut PGraph, socket: &UnixListener) -> Result<()> {
    let mut stream = match socket.accept() {
        Ok((stream, _)) => stream,
        Err(_e) => {
            // We get an "os error 11" if there are no messages in the message queue.
            return Ok(());
        }
    };

    let rpc = Rpc::stream_recv(&mut stream)?;

    match rpc {
        Rpc::GetSummaryExe { exe_path } => {
            let mut payload = String::with_capacity(4096);

            for (_, node) in pgraph_db.nodes.iter() {
                let actor = &node.actor;
                if let Some(bin) = actor.actor_md.binary.last() {
                    if let ActorState::Exited = actor.actor_md.state {
                        continue;
                    }
                    let bin_str = bin.to_str().unwrap();
                    if !bin_str.ends_with(&exe_path) {
                        continue;
                    }
                    let s = node.to_str(3);
                    payload.push_str(&s);
                    payload.push_str("\n\n");
                }
            }
            if payload.is_empty() {
                payload.push_str("No actors found");
            }
            let res = RpcResult::GetSummary(payload);
            res.stream_send(&mut stream)?;
        }
        Rpc::GetSummaryPid { pid } => {
            let res_json = match pgraph_db.get_latest_mut(pid) {
                Some(r) => r.to_str(3),
                None => {
                    format!("PID {} not found", pid)
                }
            };

            let res = RpcResult::GetSummary(res_json);
            res.stream_send(&mut stream)?;
        }
        Rpc::SetProfile { profile, pid } => {
            let res = match handle_set_profile(config, pgraph_db, &profile, pid) {
                Ok(()) => RpcResult::SetProfileRes {
                    msg: "success".to_string(),
                    success: true,
                },
                Err(e) => RpcResult::SetProfileRes {
                    msg: format!("{}", e),
                    success: false,
                },
            };
            res.stream_send(&mut stream)?;
        }
        Rpc::DebugAction => {
            if !cfg!(debug_assertions) {
                let res = RpcResult::DebugActionRes(
                    "debug action not supported in release mode".to_string(),
                );
                res.stream_send(stream)?;
                return Ok(());
            }
            let mut payload = String::new();
            for (_, node) in pgraph_db.nodes.iter() {
                let s = node.to_str(1);
                payload.push_str(&s);
                payload.push_str("");
            }
            let res = RpcResult::DebugActionRes(payload);
            res.stream_send(stream)?;
        }
    }
    Ok(())
}

fn handle_set_profile(
    config: &Config,
    pgraph_db: &mut PGraph,
    profile: &str,
    pid: i32,
) -> Result<()> {
    if !config.acl.profiles.contains_key(profile) {
        bail!("Profile does not exist");
    }
    let node = pgraph_db.get_latest_mut(pid).context("PID not found")?;
    node.actor.actor_md.profile.clear();
    node.actor.actor_md.profile.insert(profile.to_string());
    Ok(())
}
