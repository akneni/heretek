mod uds;

use std::{fmt::Write, path::PathBuf};

use crate::{
    build_params,
    detection::Protectee,
    pgraph::{ActorState, PGraph},
    uinterf::Config,
    utils,
};
use anyhow::{Context, Result, anyhow, bail};
pub use htek_lib::rpc::{Rpc, RpcResult};
pub use uds::*;

pub fn handle_rpc(
    config: &Config,
    pgraph_db: &mut PGraph,
    rpcobj: Rpc,
    is_root: bool,
) -> Result<RpcResult> {
    if !is_root {
        match &rpcobj {
            Rpc::SetChildProfile { .. } => {}
            _ => return Ok(RpcResult::Error("Root permissions required".to_string())),
        }
    }

    let res = match rpcobj {
        Rpc::GetSummaryExe { exe_path } => {
            let mut payload = String::with_capacity(4096);

            for (_, node) in pgraph_db.nodes.iter() {
                let actor = &node.actor;
                if let Some(bin) = actor.actor_md.binary.last() {
                    if let ActorState::Exited = actor.actor_md.state {
                        continue;
                    }
                    let bin_str = bin.to_str().unwrap_or("[unknown binary] ");
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
            RpcResult::GetSummary(payload)
        }
        Rpc::GetSummaryPid { pid } => {
            let res_json = match pgraph_db.get_latest_mut(pid) {
                Some(r) => r.to_str(3),
                None => {
                    format!("PID {} not found", pid)
                }
            };

            RpcResult::GetSummary(res_json)
        }
        Rpc::SetProfile { profile, pid } => {
            match handle_set_profile(config, pgraph_db, &profile, pid) {
                Ok(()) => RpcResult::SetProfileRes {
                    msg: "success".to_string(),
                    success: true,
                },
                Err(e) => RpcResult::SetProfileRes {
                    msg: format!("{}", e),
                    success: false,
                },
            }
        }
        Rpc::SetChildProfile { pid, profiles } => {
            for p in profiles.iter() {
                if !config.profile_config.profile_exists(p) {
                    bail!("Profile {p} doesn't exist");
                }
            }

            let node = pgraph_db
                .get_latest_mut(pid)
                .ok_or(anyhow!("Process with PID {} not found", pid))?;

            for p in profiles.iter() {
                node.actor.actor_md.child_profile.insert(p.clone());
            }

            RpcResult::SetChildProfileRes
        }
        Rpc::Bringdown => {
            tracing::info!("Received shutdown request. Exiting cleanly.");
            utils::clean_shutdown(0);
        }
        Rpc::Touched { file } => handle_touched(pgraph_db, file),
        Rpc::DebugAction => {
            if !(cfg!(debug_assertions) || build_params::ASSERTS) {
                let res = RpcResult::DebugActionRes(
                    "debug action not supported in release/prod mode".to_string(),
                );
                return Ok(res);
            }
            let mut payload = String::new();
            for (_, node) in pgraph_db.nodes.iter() {
                let s = node.to_str(1);
                payload.push_str(&s);
                payload.push_str("");
            }
            RpcResult::DebugActionRes(payload)
        }
    };
    Ok(res)
}

fn handle_set_profile(
    config: &Config,
    pgraph_db: &mut PGraph,
    profile: &str,
    pid: i32,
) -> Result<()> {
    if !config.acl.profiles.contains_key(profile) && profile != "unchained" {
        bail!("Profile does not exist");
    }

    if pid == 1 || pid == std::process::id() as i32 {
        bail!("Cannot attach a profile to the htek daemon or to the init process");
    }

    let node = pgraph_db.get_latest_mut(pid).context("PID not found")?;
    node.actor.actor_md.profile.clear();
    if profile != "unchained" {
        node.actor.actor_md.profile.insert(profile.to_string());
    }
    Ok(())
}

fn handle_touched(pgraph_db: &mut PGraph, fpath: PathBuf) -> RpcResult {
    utils::assert_canonical_asso(&fpath);

    let mut payload = String::new();
    for (_, node) in pgraph_db.nodes.iter() {
        if node.actor.actor_md.profile.contains("unchained") {
            continue;
        }

        let p = Protectee::File(fpath.clone());
        if let Some(atype) = node.actor.summary.events.get(&p) {
            let _ = write!(&mut payload, "{}Access Type: ", node.to_str(1));
            atype.to_rwxbc_str(&mut payload);
            payload.push_str("\n\n");
        }
    }

    RpcResult::TouchedRes(payload)
}
