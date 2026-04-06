use std::{fs, process};

use anyhow::{Result, bail};
use directories::ProjectDirs;

use crate::{
    actor::ActorsDb,
    config::{Config, ConfigFile},
    utils::TotalMem,
};

mod actor;
mod bpfmap;
mod config;
mod event_types;
mod logic;
mod utils;

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
    dbg!(&cfg);

    let mut reader =
        bpfmap::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events").unwrap();

    let mut events = vec![];
    let mut actor_db = ActorsDb::new(cfg.clone());

    loop {
        reader.poll(&mut events).unwrap();

        for (pid, event) in &events {
            actor_db.insert_event(*pid, event.clone(), &cfg);
        }
        events.clear();

        // println!("SIZE: {}{}", actor_db.total_mem(), "\n".repeat(10));
        fs::write("actor_db.log", format!("{:#?}", &actor_db)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
