use std::{
    fs,
    os::unix::net::UnixListener,
    process::{self, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;

use crate::uinterf::CliCommand;
use crate::{
    bpf::BpfEventArrayReader,
    rpc::{RpcResult, StreamSendable},
};
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

    let proj = match ProjectDirs::from("com", "heretek", "heretek") {
        Some(r) => r,
        None => {
            bail!("No valid home directory could be found");
        }
    };
    fs::create_dir_all(proj.config_dir())?;

    let config_path = proj.config_dir().join("config.json");
    if !config_path.exists() {
        let d_conkfig = ConfigFile::default();
        let dc_str = serde_json::to_string_pretty(&d_conkfig)?;
        fs::write(&config_path, &dc_str)?;
    }

    let acl_path = proj.config_dir().join("ACL.json");
    let acl = Acl::from_acl_file(&acl_path).context("Failed to parse ACL")?;

    let c_str = fs::read_to_string(&config_path)?;
    let config_file: ConfigFile =
        serde_json::from_str(&c_str).context("Failed to parse ConfigFile")?;

    let cfg = Config::from(config_file, acl)?;
    Ok(cfg)
}

fn bringup(config: &Config) {
    rpc::check_uds_ipc_inuse(config);

    if let Err(e) = bpf::load_bpf_objects(config) {
        eprintln!("Error loading eBPF objects: {}", e);
        process::exit(1);
    }

    let bin = match fs::canonicalize("/proc/self/exe") {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "Failed to find htek binary (could not read /proc/self/exe):\n{}",
                e
            );
            process::exit(1);
        }
    };
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

fn bringdown(config: &Config) -> Result<()> {
    match rpc::try_connect_uds_ipc(config) {
        Ok(stream) => {
            let rpc = rpc::Rpc::Bringdown { unload_bpf: false };
            rpc.try_stream_send(&stream)?;
            match RpcResult::try_stream_recv(&stream) {
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

    bpf::unload_bpf_objects(config)?;
    Ok(())
}

fn daemon_init(config: &Config) -> Result<(UnixListener, BpfEventArrayReader)> {
    response::init_alert_log(config).context("Failed to initalize the alert/violation log")?;

    let socket = rpc::try_create_uds_ipc(config)?;
    socket.set_nonblocking(true)?;

    let bpf_reader = bpf::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events");
    let bpf_reader = match bpf_reader {
        Ok(r) => r,
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("code: 2") && err_str.contains("No such file or directory") {
                bail!("The BPF map is not loaded");
            } else {
                bail!("Unknown error accessing the bpf map: {:?}", e);
            }
        }
    };

    Ok((socket, bpf_reader))
}

fn daemon(config: &Config) {
    // This is the only area in the code where the daemon is allowed to exit/fail (unless ASSERTS is enabled)
    let (socket, mut bpf_reader) = match daemon_init(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("An error occured while initalizing the daemon: {e}");
            process::exit(1);
        }
    };

    let mut events = vec![];
    let mut pgraph_db = PGraph::from_existing_processes(config);

    let iter_interval = Duration::from_micros(50_000);
    let mut ttracker = perftracker::PerfTracker::new();

    loop {
        let timer = Instant::now();
        ttracker.start_iter();

        // 1) Drain the ring buffers and update it's internal pgraph structure with the events just pulled
        if let Err(e) = bpf_reader.poll(&mut events) {
            let sleep_int = Duration::from_millis(500);
            ttracker.end_iter();

            eprintln!("An error occured while polling the eBPF mnaps. Make sure they are loaded:");
            eprintln!("{e}");
            eprintln!("Sleeping for {:?} and retrying", sleep_int);
            thread::sleep(sleep_int);
            continue;
        }
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
        if let Err(e) = rpc::handle_rpc(config, &mut pgraph_db, &socket) {
            eprintln!("Error processing RPC: {e}");
        }

        // 4) Sleep for an alloted amount of time.
        let te = timer.elapsed().as_micros() as u64;
        ttracker.end_iter();

        if ttracker.total_iterations.is_multiple_of(10) && build_params::PERF_TRACKING {
            ttracker.display_stats();
        }

        pgraph_db.check_unchained_chains_dbgo(config);
        pgraph_db.check_cycles_dbgo(config);

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
            if let Err(e) = bringdown(&config) {
                eprintln!("An error occured:\n{}", e);
                process::exit(1);
            }
        }
        CliCommand::Daemon => {
            daemon(&config);
        }
        CliCommand::SummaryPid { pid } => {
            let stream = rpc::connect_uds_ipc(&config);

            let rpc = rpc::Rpc::GetSummaryPid { pid };
            rpc.stream_send(&stream);
            let rpc_res = RpcResult::stream_recv(&stream);
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
            rpc.stream_send(&stream);
            let rpc_res = RpcResult::stream_recv(&stream);
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
            rpc.stream_send(&stream);
            let rpc_res = RpcResult::stream_recv(&stream);
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
            rpc.stream_send(&stream);
            let rpc_res = RpcResult::stream_recv(&stream);
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
            println!("Data:    {}", config.dirs.data_dir().display());
            println!("Config:  {}", config.dirs.config_dir().display());

            // let stream = rpc::connect_uds_ipc(&config);
            // let rpc = rpc::Rpc::DebugAction;
            // rpc.stream_send(&stream);
            // let rpc_res = RpcResult::stream_recv(&stream);
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
