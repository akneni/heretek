use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
};

use anyhow::Result;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::pgraph::PGraph;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rpc {
    // htek summary <pid | binary-path>
    GetSummaryPid { pid: i32 },
    GetSummaryExe { exe_path: String },

    SetParentProfile { profile: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResult {
    GetSummary(String),
    SetParentProfileRes { msg: String, success: bool },
}

impl StreamSendable for Rpc {}
impl StreamSendable for RpcResult {}

pub trait StreamSendable: Sized + Serialize + DeserializeOwned {
    fn stream_send(&self, mut stream: impl Write) -> Result<()> {
        let self_json = serde_json::to_string(&self)?;
        stream.write(&(self_json.len() as u64).to_le_bytes())?;
        stream.write(self_json.as_bytes())?;

        Ok(())
    }

    fn stream_recv(mut stream: impl Read) -> Result<Self> {
        let mut len_bytes = [0u8; 8];
        stream.read_exact(&mut len_bytes)?;
        let len = u64::from_le_bytes(len_bytes) as usize;

        let mut msg_bytes = vec![0u8; len];
        stream.read_exact(&mut msg_bytes)?;

        let self_obj: Self = serde_json::from_slice(&msg_bytes)?;

        Ok(self_obj)
    }
}

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
            let res_json = match actor_db.get_node_by_latest_pid_mut(pid) {
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
