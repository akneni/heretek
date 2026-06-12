use std::{
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process,
};

use anyhow::Result;
use directories::ProjectDirs;

use crate::uinterf::Config;

pub fn get_uds_path() -> PathBuf {
    let proj = ProjectDirs::from("com", "heretek", "heretek").unwrap();
    let proj_data = proj.data_dir();
    fs::create_dir_all(proj_data).unwrap();

    proj_data.join("RPC.sock")
}

pub fn check_uds_ipc_inuse(_config: &Config) {
    let uds_path = get_uds_path();
    if uds_path.exists() {
        let stream = UnixStream::connect(&uds_path);
        if let Ok(_) = stream {
            eprintln!("Socket already in use. It seems like an htek daemon is already running");
            process::exit(1);
        }
    }
}

pub fn create_uds_ipc(_config: &Config) -> UnixListener {
    let uds_path = get_uds_path();
    if uds_path.exists() {
        let stream = UnixStream::connect(&uds_path);
        if let Ok(_) = stream {
            eprintln!("Socket already in use. It seems like an htek daemon is already running");
            process::exit(1);
        }

        fs::remove_file(&uds_path).unwrap();
    }

    UnixListener::bind(&uds_path).unwrap()
}

pub fn connect_uds_ipc(_config: &Config) -> Result<UnixStream> {
    let uds_path = get_uds_path();

    Ok(UnixStream::connect(&uds_path)?)
}
