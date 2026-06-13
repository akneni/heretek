use std::{
    env, fs,
    process::{self, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;

use crate::rpc::{RpcResult, StreamSendable};
use crate::uinterf::CliCommand;
use crate::{
    detection::Acl,
    uinterf::{Config, ConfigFile},
};
use crate::{pgraph::PGraph, rpc::Rpc};

mod bpf;
mod detection;
mod pgraph;
mod response;
mod rpc;
mod uinterf;

mod build_params;
mod perftracker;
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

    let acl_path = proj.config_dir().join("ACL.json");
    let acl = Acl::from_acl_file(&acl_path)
        .context("Failed to parse ACL")
        .unwrap();

    let c_str = fs::read_to_string(&config_path)?;
    let config_file: ConfigFile =
        serde_json::from_str(&c_str).context("Failed to parse ConfigFile")?;

    let cfg = Config::from(config_file, acl);
    Ok(cfg)
}

fn bringup(config: &Config) {
    rpc::check_uds_ipc_inuse(config);

    if let Err(e) = bpf::load_bpf_objects(config) {
        eprintln!("Error loading eBPF objects: {}", e);
        process::exit(1);
    }

    let bin = env::args().next().unwrap();
    let cmd = process::Command::new(&bin)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match cmd {
        Ok(_) => println!("Spawned daemon successfully!"),
        Err(e) => eprintln!("An error occured while spawning the daemon:\n{}", e),
    }
}

fn bringdown(config: &Config) {
    match rpc::try_connect_uds_ipc(&config) {
        Ok(stream) => {
            let rpc = rpc::Rpc::Bringdown { unload_bpf: false };
            rpc.stream_send(&stream).unwrap();
            match RpcResult::stream_recv(&stream) {
                Ok(r) => match r {
                    rpc::RpcResult::BringdownRes(s) => {
                        println!("{}", s);
                        process::exit(1);
                    }
                    _ => unreachable!(),
                },
                Err(_e) => {
                    println!("Heretek daemon exited!");
                }
            };
        }
        Err(_e) => println!("Heretek daemon not running"),
    };

    if let Err(e) = bpf::unload_bpf_objects(config) {
        eprintln!("Failed to unload eBPF objects: {}", e);
        process::exit(1);
    }
}

fn daemon(config: &Config) {
    //Daemon Specific Preflight Actions
    response::init_alert_log(config);

    let socket = rpc::create_uds_ipc(config);
    socket.set_nonblocking(true).unwrap();

    let reader = bpf::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events");
    let mut reader = match reader {
        Ok(r) => r,
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("code: 2") && err_str.contains("No such file or directory") {
                eprintln!("The BPF map is not loaded");
            } else {
                eprintln!("Unknown error accessing the bpf map: {:?}", e);
            }
            std::process::exit(1);
        }
    };

    let mut events = vec![];
    let mut pgraph_db = PGraph::from_existing_processes(&config);

    let iter_interval = Duration::from_micros(50_000);
    let mut ttracker = perftracker::PerfTracker::new();

    loop {
        let timer = Instant::now();
        ttracker.start_iter();

        // 1) Drain the ring buffers and update it's internal pgraph structure with the events just pulled
        reader.poll(&mut events).unwrap();
        events.sort_by_key(|x| x.ktime);
        ttracker.record_num_events(events.len() as u64);

        // 2) Run checks against the ACL to check for violations
        for event in events.into_iter() {
            if let Err(e) = pgraph::handle_event(config, &mut pgraph_db, &event) {
                eprintln!("Error handling event: {}", e);
            }
        }
        events = vec![];

        // 3) Check for IPC RPCs from CLI invocations of this tool (like `htek desc <pid>`)
        if let Err(e) = rpc::handle_rpc(&config, &mut pgraph_db, &socket) {
            eprintln!("Error processing RPC: {e}");
        }

        // 4) Sleep for an alloted amount of time.
        let te = timer.elapsed().as_micros() as u64;
        ttracker.end_iter();

        if ttracker.total_iterations % 10 == 0 && build_params::PERF_TRACKING {
            ttracker.display_stats();
        }

        pgraph_db.check_unchained_chains_dbgo();
        pgraph_db.check_cycles_dbgo();

        let iter_interval_us = iter_interval.as_micros() as u64;
        if te >= iter_interval_us {
            continue;
        } else {
            let time_left_us = iter_interval_us - te;
            if time_left_us > 1000 {
                thread::sleep(Duration::from_micros(time_left_us));
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
        CliCommand::Bringup => {
            bringup(&config);
        }
        CliCommand::Bringdown => {
            bringdown(&config);
        }
        CliCommand::Daemon => {
            daemon(&config);
        }
        CliCommand::SummaryPid { pid } => {
            let stream = rpc::connect_uds_ipc(&config);

            let rpc = rpc::Rpc::GetSummaryPid { pid };
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
            let rpc = rpc::Rpc::GetSummaryExe { exe_path };
            let stream = rpc::connect_uds_ipc(&config);
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
        CliCommand::SetProfile { profile, pid } => {
            let rpc = Rpc::SetProfile { profile, pid };
            let stream = rpc::connect_uds_ipc(&config);
            rpc.stream_send(&stream).unwrap();
            let rpc_res = RpcResult::stream_recv(&stream).unwrap();
            match rpc_res {
                rpc::RpcResult::SetProfileRes { msg, success } => {
                    println!("{}", msg);
                    if !success {
                        std::process::exit(1);
                    }
                }
                _ => {
                    unreachable!();
                }
            }
        }
        CliCommand::Touched { file } => {
            let fpath = match fs::canonicalize(&file) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error finding file: {}", e);
                    process::exit(1);
                }
            };

            let stream = rpc::connect_uds_ipc(&config);
            let rpc = Rpc::Touched { file: fpath };
            rpc.stream_send(&stream).unwrap();
            let rpc_res = RpcResult::stream_recv(&stream).unwrap();
            match rpc_res {
                rpc::RpcResult::TouchedRes(s) => {
                    println!("{}", s);
                }
                _ => {
                    unreachable!();
                }
            }
        }
        CliCommand::DebugAction => {
            let proj = ProjectDirs::from("com", "heretek", "heretek").unwrap();
            println!("Data:    {}", proj.data_dir().display());
            println!("Config:  {}", proj.config_dir().display());

            // let stream = rpc::connect_uds_ipc(&config);
            // let rpc = rpc::Rpc::DebugAction;
            // rpc.stream_send(&stream).unwrap();
            // let rpc_res = RpcResult::stream_recv(&stream).unwrap();
            // match rpc_res {
            //     rpc::RpcResult::DebugActionRes(s) => {
            //         println!("{}", s);
            //     }
            //     _ => {
            //         unreachable!();
            //     }
            // }
        }
    }
}
