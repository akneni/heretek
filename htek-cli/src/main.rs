mod actor;
mod bpfmap;
mod logic;
mod syscalls;

use std::time::Duration;

fn main() {
    let mut reader = bpfmap::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events")
        .unwrap();

    let mut events = vec![];

    loop {
        reader.poll(&mut events).unwrap();

        for e in &events {
            println!("{:?}", e);
        }
        events.clear();
    }

}
