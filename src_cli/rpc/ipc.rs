use std::{
    io::{Read, Write},
    mem,
};

use anyhow::Result;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rpc {
    // htek summary <pid | binary-path>
    GetSummaryPid { pid: i32 },
    GetSummaryExe { exe_path: String },

    SetParentProfile { profile: String },

    // A debugging mechanism to get some arbitrary RPC to run while debugging.
    DebugAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResult {
    GetSummary(String),
    SetParentProfileRes { msg: String, success: bool },
    DebugActionRes(String),
}

impl StreamSendable for Rpc {}
impl StreamSendable for RpcResult {}

pub trait StreamSendable: Sized + Serialize + DeserializeOwned {
    fn stream_send(&self, mut stream: impl Write) -> Result<()> {
        let self_json = serde_json::to_string_pretty(&self)?;
        let mut bytes_send = stream.write(&(self_json.len() as u64).to_le_bytes())?;
        bytes_send += stream.write(self_json.as_bytes())?;
        assert!(bytes_send == self_json.len() + mem::size_of::<u64>());
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
