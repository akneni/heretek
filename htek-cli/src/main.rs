use std::{fs, process};

use anyhow::{Result, bail};

use crate::{actor::ActorsDb, utils::TotalMem};

mod actor;
mod bpfmap;
mod logic;
mod event_types;
mod utils;

fn preflight() -> Result<()> {
    if "root" != whoami::account()? {
        bail!("Heretek needs to be ran as root!");
    }

    match whoami::platform() {
        whoami::Platform::Linux => {},
        _ => bail!("Unsupported platform! Currently supported platforms: Linux"),
    }

    Ok(())
}

fn main() {
    if let Err(e) = preflight() {
        eprintln!("Preflight Checks Failed:\n{}", e);
        process::exit(1);
    }

    let mut reader =
        bpfmap::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events").unwrap();

    let mut events = vec![];
    let mut actor_db = ActorsDb::new();

    loop {
        reader.poll(&mut events).unwrap();

        for (pid, event) in &events {
            // println!("{:?}", (pid, &event));
            actor_db.insert_event(*pid, event.clone());
        }
        events.clear();

        println!("SIZE: {}{}", actor_db.total_mem(), "\n".repeat(10));
        fs::write("actor_db.log", format!("{:#?}", &actor_db)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
