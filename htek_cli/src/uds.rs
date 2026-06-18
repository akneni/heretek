use std::os::unix::net::UnixStream;

use anyhow::Result;
use htek_lib::{
    htdirs,
    rpc::{Rpc, RpcResult, StreamSendable},
};

pub struct RpcClient {
    stream: UnixStream,
}

impl RpcClient {
    pub fn new() -> Result<Self> {
        let use_root = whoami::username()? == "root";

        let uds_path = if use_root {
            htdirs::socket_path_root()
        } else {
            htdirs::socket_path_any()
        };

        let stream = UnixStream::connect(&uds_path)?;
        Ok(Self { stream })
    }

    pub fn call_rpc_sync(&mut self, rpc: Rpc) -> Result<RpcResult> {
        rpc.try_stream_send(&mut self.stream)?;
        let res = RpcResult::try_stream_recv(&mut self.stream)?;
        Ok(res)
    }
}
