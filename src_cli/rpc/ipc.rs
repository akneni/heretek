use std::{
    io::{Read, Write},
    mem,
    path::PathBuf,
    process,
};

use anyhow::Result;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rpc {
    // htek summary <pid | binary-path>
    GetSummaryPid { pid: i32 },
    GetSummaryExe { exe_path: String },

    // Sets the actor whose pid is passed to the profile specified
    // and removes all other profiles.
    SetProfile { profile: String, pid: i32 },

    // Shut down the daemon
    Bringdown { unload_bpf: bool },

    // See who touched a file
    Touched { file: PathBuf },

    // A debugging mechanism to get some arbitrary RPC to run while debugging.
    DebugAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResult {
    GetSummary(String),
    SetProfileRes { msg: String, success: bool },
    BringdownRes(String),
    TouchedRes(String),
    DebugActionRes(String),
}

impl StreamSendable for Rpc {}
impl StreamSendable for RpcResult {}

pub trait StreamSendable: Sized + Serialize + DeserializeOwned {
    /// Fails fast and returns an error message to the user
    fn stream_send(&self, stream: impl Write) {
        if let Err(e) = self.try_stream_send(stream) {
            eprintln!("Error occured writing to the unix domain socket:\n{e}");
            process::exit(1);
        }
    }

    fn try_stream_send(&self, mut stream: impl Write) -> Result<()> {
        let self_json = serde_json::to_string_pretty(&self)?;
        let mut bytes_send = stream.write(&(self_json.len() as u64).to_le_bytes())?;
        bytes_send += stream.write(self_json.as_bytes())?;
        assert!(bytes_send == self_json.len() + mem::size_of::<u64>());
        Ok(())
    }

    /// Fails fast and returns an error message to the user
    fn stream_recv(stream: impl Read) -> Self {
        match Self::try_stream_recv(stream) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("An error occured reading from the unix domain socket: {e}");
                process::exit(1);
            }
        }
    }

    fn try_stream_recv(mut stream: impl Read) -> Result<Self> {
        let mut len_bytes = [0u8; 8];
        stream.read_exact(&mut len_bytes)?;
        let len = u64::from_le_bytes(len_bytes) as usize;

        let mut msg_bytes = vec![0u8; len];
        stream.read_exact(&mut msg_bytes)?;

        let self_obj: Self = serde_json::from_slice(&msg_bytes)?;

        Ok(self_obj)
    }
}
