use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixListener,
};

use anyhow::{Result, bail};
use htek_lib::{
    htdirs,
    rpc::{Rpc, RpcResult, StreamSendable},
};

use crate::utils;

pub struct RpcServer {
    root_uds: UnixListener,
    any_uds: UnixListener,
    idx: u8,
}

impl RpcServer {
    pub fn new() -> Result<Self> {
        if htek_lib::server_is_occupied() {
            bail!("Server is already occupied");
        }

        Self::setup_uds_dir()?;

        let rpath = htdirs::socket_path_root();
        let apath = htdirs::socket_path_any();
        let root_uds = UnixListener::bind(&rpath)?;
        let any_uds = UnixListener::bind(&apath)?;

        fs::set_permissions(&rpath, Permissions::from_mode(0o600))?;
        fs::set_permissions(&apath, Permissions::from_mode(0o666))?;

        root_uds.set_nonblocking(true)?;
        any_uds.set_nonblocking(true)?;

        Ok(Self {
            root_uds,
            any_uds,
            idx: 0,
        })
    }

    /// First argument to `cbk` closure is the RPC
    /// Second argument to `cbk` closure is `is_root` (true if it eas received on the root socket, false if otherwise)
    pub fn handle_rpc(
        &mut self,
        mut cbk: impl FnMut(Rpc, bool) -> Result<RpcResult>,
    ) -> Result<()> {
        let is_root = self.idx == 0;
        let active_sock = match self.idx {
            0 => &mut self.root_uds,
            1 => &mut self.any_uds,
            _ => {
                utils::unreachable();
                bail!("reached an unreachable section of code");
            }
        };
        self.idx = (self.idx + 1) % 2;

        let mut stream = match active_sock.accept() {
            Ok((stream, _)) => stream,
            Err(_e) => {
                // We get an "os error 11" if there are no messages in the message queue.
                return Ok(());
            }
        };

        let req = Rpc::try_stream_recv(&mut stream)?;

        let res = match cbk(req, is_root) {
            Ok(r) => r,
            Err(e) => RpcResult::Error(format!("{e}")),
        };

        res.try_stream_send(&mut stream)?;

        Ok(())
    }

    pub fn setup_uds_dir() -> Result<()> {
        let udsdir = htdirs::uds_dir();
        fs::create_dir_all(udsdir)?;
        fs::set_permissions(udsdir, Permissions::from_mode(0o755))?;
        Ok(())
    }
}
