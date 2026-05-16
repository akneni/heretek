use std::{fs, io::{Read, Write}, process, thread, time::{Duration, Instant}};
use std::os::unix::net::{UnixListener, UnixStream};

use anyhow::{Result, bail};
use directories::ProjectDirs;

use crate::{
    detection::{Acl, Protectee, AclJsonFile}, config::{Config, ConfigFile}, rpc::{Rpc, StreamSendable}, utils::TotalMem,
    pgraph::{AccessType, ActorsDb},
};

mod bpf;
mod config;
mod detection;
mod utils;
mod pgraph;
mod build_params;
mod rpc;

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

fn temp() {
    // let s = std::env::args().skip(1).next().unwrap();


    // if s == "listen" {
    //     let mut counter = 0;
    //     let mut scoket_l = UnixListener::bind("thing.sock").unwrap();
    //     scoket_l.set_nonblocking(true).unwrap();
        
    
    //     loop {
    //         match scoket_l.accept() {
    //             Ok((mut stream, _)) => {
    //                 let mut msg = vec![];
    //                 stream.read_to_end(&mut msg).unwrap();
                
    //                 println!("{}", String::from_utf8(msg).unwrap());
    //                 break;
    //             },
    //             Err(e) => {
    //                 counter += 1;
    //                 eprintln!("error: {} (counter = {})", e, counter);

    //             }
    //         };
    //     }


    
    //     let _ = fs::remove_file("thing.sock");
    // }
    // else if s == "send" {
    //     let mut stream = UnixStream::connect("thing.sock").unwrap();

    //     stream.write(b"message asoudhfsoih").unwrap();
    //     stream.flush().unwrap();
    // }   

    // std::process::exit(0);
}

fn main() {
    temp();


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

    let uds_path = proj.data_dir().join("RPC.sock");
    let socket = UnixListener::bind(&uds_path).unwrap();
    socket.set_nonblocking(true).unwrap();

    let mut reader =
        bpf::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events").unwrap();

    let mut events = vec![];
    let mut actor_db = ActorsDb::new(cfg.clone());
    let mut violations: Vec<Violation> = vec![];

    let iter_interval = Duration::from_micros(50_000);

    loop {
        let timer = Instant::now();

        // 1) Drain the ring buffers and update it's internal pgraph structure with the events just pulled
        reader.poll(&mut events).unwrap();

        // 2) Run checks against the ACL to check for violations
        for event in &events {
            actor_db.insert_event(event.clone(), &mut violations, &acl);
        }
        events.clear();

        fs::write("actor_db.log", format!("{:#?}\n\n{}", &actor_db, actor_db.total_mem())).unwrap();
        
        // 3) Check for IPC RPCs from CLI invocations of this tool (like `htek desc <pid>`)
        if let Err(e) = rpc::handle_rpc(&socket, &mut actor_db) {
            eprintln!("Error processing RPC: {e}");
        }

        // 4) Sleep for an alloted amount of time. 
        println!("Time Elapsed: {:?}", timer.elapsed());
        let te = timer.elapsed().as_millis() as u64;
        let iter_interval_us = iter_interval.as_millis() as u64;
        if te >= iter_interval_us {
            continue;
        }
        else {
            let time_left_us = iter_interval_us - te;
            if time_left_us > 1000 {
                thread::sleep(Duration::from_millis(time_left_us));
            } 
        }
    }
}
