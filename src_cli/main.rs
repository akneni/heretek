use std::os::unix::net::UnixListener;
use std::{
    fs,
    process, thread,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use directories::ProjectDirs;

use crate::pgraph::PGraph;
use crate::rpc::{RpcResult, StreamSendable};
use crate::uinterf::CliCommand;
use crate::{
    uinterf::{Config, ConfigFile},
    detection::{Acl, AclJsonFile},
};

mod bpf;
mod uinterf;
mod detection;
mod pgraph;
mod rpc;

mod build_params;
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



fn daemon(config: &Config) {
    let proj = ProjectDirs::from("com", "heretek", "heretek").unwrap();
    let acl_path = proj.config_dir().join("ACL.json");
    let acl_str = match fs::read_to_string(&acl_path) {
        Ok(r) => r,
        Err(_e) => {
            eprintln!("{:?} does not exist", &acl_path);
            std::process::exit(1);
        }
    };
    let acl_json: Vec<AclJsonFile> = serde_json::from_str(&acl_str).unwrap();
    let acl = Acl::from(acl_json).unwrap();

    let socket = rpc::create_uds_ipc(&config);
    socket.set_nonblocking(true).unwrap();

    let mut reader =
        bpf::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events").unwrap();

    let mut events = vec![];
    let mut pgraph_db = PGraph::from_existing_processes();

    let iter_interval = Duration::from_micros(50_000);

    loop {
        let timer = Instant::now();

        // 1) Drain the ring buffers and update it's internal pgraph structure with the events just pulled
        reader.poll(&mut events).unwrap();

        // 2) Run checks against the ACL to check for violations
        for event in events.into_iter() {
            pgraph::handle_event(&mut pgraph_db, event);
        }
        events = vec![];

 

        // 3) Check for IPC RPCs from CLI invocations of this tool (like `htek desc <pid>`)
        if let Err(e) = rpc::handle_rpc(&socket, &mut pgraph_db) {
            eprintln!("Error processing RPC: {e}");
        }


        // 4) Sleep for an alloted amount of time.
        println!("Time Elapsed: {:?}", timer.elapsed());
        let te = timer.elapsed().as_millis() as u64;
        let iter_interval_us = iter_interval.as_millis() as u64;
        if te >= iter_interval_us {
            continue;
        } else {
            let time_left_us = iter_interval_us - te;
            if time_left_us > 1000 {
                thread::sleep(Duration::from_millis(time_left_us));
            }
        }
    }
}

fn main() {
    let config = match preflight() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Preflight Checks Failed:\n{}", e);
            process::exit(1);
        }
    };


    let cli_cmd = uinterf::parse_cli();

    match cli_cmd {
        CliCommand::Daemon => {
            daemon(&config);
        }
        CliCommand::SummaryPid { pid } => {
            println!("{:?}", rpc::get_uds_path());
            let stream = rpc::connect_uds_ipc(&config);
            let rpc = rpc::Rpc::GetSummaryPid{pid};
            rpc.stream_send(&stream).unwrap();
            let rpc_res = RpcResult::stream_recv(&stream).unwrap();
            match rpc_res {
                rpc::RpcResult::GetSummary(s) => {
                    println!("{}", s);
                }
                _ => {
                    unreachable!();
                }
            }
        
        }
        CliCommand::SummaryExe { exe_path } => {
            unimplemented!("unimplemented");
        }
    }


}
