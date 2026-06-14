use std::{
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process,
};

use anyhow::{Result, bail};

use crate::uinterf::Config;

pub fn get_uds_path(config: &Config) -> Result<PathBuf> {
    let proj_data = config.dirs.data_dir();
    fs::create_dir_all(proj_data)?;

    Ok(proj_data.join("RPC.sock"))
}

pub fn check_uds_ipc_inuse(config: &Config) {
    let uds_path = match get_uds_path(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to get uds path: {e}");
            process::exit(1);
        }
    };
    if uds_path.exists() {
        let stream = UnixStream::connect(&uds_path);
        if let Ok(_) = stream {
            eprintln!("Socket already in use. It seems like an htek daemon is already running");
            process::exit(1);
        }
    }
}

pub fn try_create_uds_ipc(config: &Config) -> Result<UnixListener> {
    let uds_path = get_uds_path(config)?;
    if uds_path.exists() {
        let stream = UnixStream::connect(&uds_path);
        if let Ok(_) = stream {
            bail!("Socket already in use. It seems like an htek daemon is already running");
        }

        fs::remove_file(&uds_path)?;
    }

    Ok(UnixListener::bind(&uds_path)?)
}

pub fn try_connect_uds_ipc(config: &Config) -> Result<UnixStream> {
    let uds_path = get_uds_path(config)?;

    Ok(UnixStream::connect(&uds_path)?)
}

pub fn connect_uds_ipc(config: &Config) -> UnixStream {
    match try_connect_uds_ipc(config) {
        Ok(r) => r,
        Err(_e) => {
            eprintln!("Heretek daemon is not running");
            process::exit(1);
        }
    }
}
