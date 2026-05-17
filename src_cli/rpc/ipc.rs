use std::{
    io::{Read, Write},
};

use anyhow::Result;
use serde::{Deserialize, Serialize, de::DeserializeOwned};


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
        let self_json = serde_json::to_string_pretty(&self)?;
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

