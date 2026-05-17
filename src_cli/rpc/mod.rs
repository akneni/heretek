mod ipc;
mod uds_utils;

use std::os::unix::net::UnixListener;

use anyhow::Result;
pub use ipc::*;
pub use uds_utils::*;

use crate::pgraph::PGraph;


pub fn handle_rpc(socket: &UnixListener, actor_db: &mut PGraph) -> Result<()> {
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
            let res = RpcResult::GetSummary("unimplemented".to_string());
            res.stream_send(&mut stream)?;
        }
        Rpc::GetSummaryPid { pid } => {
            let res_json = match actor_db.get_latest_mut(pid) {
                Some(r) => {
                    let actor = &r.actor;
                    format!("{:?}", actor.summary)
                }
                None => {
                    format!("PID {} not found", pid)
                }
            };

            let res = RpcResult::GetSummary(res_json);
            res.stream_send(&mut stream)?;
        }
        Rpc::SetParentProfile { profile } => {
            let res = RpcResult::GetSummary("unimplemented".to_string());
            res.stream_send(&mut stream)?;
        }
    }
    Ok(())
}