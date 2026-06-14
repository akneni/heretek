use std::{
    io::{Read, Write},
    path::PathBuf,
    process,
};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const MAX_RPC_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

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
        let message = serde_json::to_vec(self)?;
        if message.len() > MAX_RPC_MESSAGE_SIZE {
            bail!(
                "RPC message is too large: {} bytes (maximum is {} bytes)",
                message.len(),
                MAX_RPC_MESSAGE_SIZE
            );
        }

        stream.write_all(&(message.len() as u64).to_le_bytes())?;
        stream.write_all(&message)?;
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
        let len = u64::from_le_bytes(len_bytes);
        if len > MAX_RPC_MESSAGE_SIZE as u64 {
            bail!(
                "RPC message is too large: {len} bytes (maximum is {MAX_RPC_MESSAGE_SIZE} bytes)"
            );
        }
        let len = len as usize;

        let mut msg_bytes = vec![0u8; len];
        stream.read_exact(&mut msg_bytes)?;

        let self_obj: Self = serde_json::from_slice(&msg_bytes)?;

        Ok(self_obj)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Write};

    use super::{MAX_RPC_MESSAGE_SIZE, Rpc, StreamSendable};

    struct PartialWriter {
        bytes: Vec<u8>,
        max_write_size: usize,
    }

    impl Write for PartialWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let write_size = buf.len().min(self.max_write_size);
            self.bytes.extend_from_slice(&buf[..write_size]);
            Ok(write_size)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stream_send_handles_partial_writes() {
        let rpc = Rpc::GetSummaryPid { pid: 42 };
        let mut writer = PartialWriter {
            bytes: Vec::new(),
            max_write_size: 2,
        };

        rpc.try_stream_send(&mut writer).unwrap();

        let decoded = Rpc::try_stream_recv(Cursor::new(writer.bytes)).unwrap();
        assert!(matches!(decoded, Rpc::GetSummaryPid { pid: 42 }));
    }

    #[test]
    fn stream_recv_rejects_oversized_messages() {
        let oversized_len = (MAX_RPC_MESSAGE_SIZE as u64 + 1).to_le_bytes();

        let error = Rpc::try_stream_recv(Cursor::new(oversized_len)).unwrap_err();

        assert!(error.to_string().contains("RPC message is too large"));
    }
}
