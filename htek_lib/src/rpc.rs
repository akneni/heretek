use std::{
    collections::HashSet,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const MAX_RPC_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rpc {
    GetSummaryPid { pid: i32 },
    GetSummaryExe { exe_path: String },
    SetProfile { profile: String, pid: i32 },
    Bringdown,
    SetChildProfile { pid: i32, profiles: HashSet<String> },
    Touched { file: PathBuf },
    Ping,
    DebugAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResult {
    GetSummary(String),
    SetProfileRes { msg: String, success: bool },
    SetChildProfileRes,
    TouchedRes(String),
    Pong,
    DebugActionRes(String),
    Error(String),
}

pub trait StreamSendable: Sized + Serialize + DeserializeOwned {
    fn try_stream_send(&self, mut stream: impl Write) -> Result<()> {
        let message = serde_json::to_vec(self)?;
        if message.len() > MAX_RPC_MESSAGE_SIZE {
            bail!(
                "RPC message is too large: {} bytes (maximum is {})",
                message.len(),
                MAX_RPC_MESSAGE_SIZE
            );
        }

        stream.write_all(&(message.len() as u64).to_le_bytes())?;
        stream.write_all(&message)?;
        Ok(())
    }

    fn try_stream_recv(mut stream: impl Read) -> Result<Self> {
        let mut len_bytes = [0u8; 8];
        stream.read_exact(&mut len_bytes)?;
        let len = u64::from_le_bytes(len_bytes);
        if len > MAX_RPC_MESSAGE_SIZE as u64 {
            bail!("RPC message is too large: {len} bytes (maximum is {MAX_RPC_MESSAGE_SIZE})");
        }

        let mut message = vec![0u8; len as usize];
        stream.read_exact(&mut message)?;
        Ok(serde_json::from_slice(&message)?)
    }
}

impl StreamSendable for Rpc {}
impl StreamSendable for RpcResult {}
