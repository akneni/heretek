use std::{fs, process};

use anyhow::{Result, bail};
use directories::ProjectDirs;

use crate::{
    acl::{Acl, Protectee}, acl_file::AclJsonFile, actor::{AccessType, ActorsDb}, config::{Config, ConfigFile}, utils::TotalMem
};

mod actor;
mod bpfmap;
mod config;
mod event_types;
mod logic;
mod acl;
mod acl_file;
mod utils;

#[derive(Debug)]
struct Violation {
    pid: i32,
    binary: String,
    p: Protectee,
    atype: AccessType
}

fn preflight() -> Result<Config> {
    if "root" != whoami::account()? {
        bail!("Heretek needs to be ran as root!");
    }

    match whoami::platform() {
        whoami::Platform::Linux => {}
        _ => bail!("Unsupported platform! Currently supported platforms: Linux"),
    }

    let proj = ProjectDirs::from("com", "heretek", "heretek").unwrap();
    fs::create_dir_all(proj.config_dir())?;

    let config_path = proj.config_dir().join("config.json");
    if !config_path.exists() {
        let d_conkfig = ConfigFile::default();
        let dc_str = serde_json::to_string_pretty(&d_conkfig)?;
        fs::write(&config_path, &dc_str)?;
    }

    let c_str = fs::read_to_string(&config_path)?;
    let cfg: Config = Config::from(&serde_json::from_str(&c_str)?);

    Ok(cfg)
}

fn main() {
    let cfg = match preflight() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Preflight Checks Failed:\n{}", e);
            process::exit(1);
        }
    };

    let proj = ProjectDirs::from("com", "heretek", "heretek").unwrap();
    let acl_path = proj.config_dir().join("ACL.json");
    let acl_str = match fs::read_to_string(&acl_path) {
        Ok(r) => r,
        Err(_e) => {
            eprintln!("{:?} does not exist", &acl_path);
            std::process::exit(1);
        },
    };
    let acl_json: Vec<AclJsonFile> = serde_json::from_str(&acl_str).unwrap();
    let acl = Acl::from(acl_json).unwrap();

    let mut reader =
        bpfmap::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events").unwrap();

    let mut events = vec![];
    let mut actor_db = ActorsDb::new(cfg.clone());
    let mut violations: Vec<Violation> = vec![];

    loop {
        reader.poll(&mut events).unwrap();

        for (pid, event) in &events {
            actor_db.insert_event(*pid, event.clone(), &mut violations, &acl);
        }
        events.clear();

        fs::write("actor_db.log", format!("{:#?}\n\n{}", &actor_db, actor_db.total_mem())).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
