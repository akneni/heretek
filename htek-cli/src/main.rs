use std::fs;

use crate::{actor::ActorsDb, utils::TotalMem};

mod actor;
mod bpfmap;
mod logic;
mod syscalls;
mod utils;

fn main() {
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
