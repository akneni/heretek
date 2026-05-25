use std::{
    fs,
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
};

use directories::ProjectDirs;

use crate::uinterf::Config;

pub fn get_uds_path() -> PathBuf {
    let proj = ProjectDirs::from("com", "heretek", "heretek").unwrap();
    let proj_data = proj.data_dir();
    fs::create_dir_all(proj_data).unwrap();

    proj_data.join("RPC.sock")
}

pub fn create_uds_ipc(_config: &Config) -> UnixListener {
    let uds_path = get_uds_path();
    if uds_path.exists() {
        fs::remove_file(&uds_path).unwrap();
    }

    UnixListener::bind(&uds_path).unwrap()
}

pub fn connect_uds_ipc(_config: &Config) -> UnixStream {
    let uds_path = get_uds_path();

    UnixStream::connect(&uds_path).unwrap()
}
