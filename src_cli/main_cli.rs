use std::{
    fs,
    process::{self, Stdio},
};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;

use crate::rpc::Rpc;
use crate::rpc::{RpcResult, StreamSendable};
use crate::uinterf::CliCommand;
use crate::{
    detection::Acl,
    uinterf::{Config, ConfigFile},
};

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

    println!("Loading eBPF objects");
    if let Err(e) = bpf::load_bpf_objects(config) {
        eprintln!("Error loading eBPF objects: {}", e);
        process::exit(1);
    }

    println!("Spawning heretek daemon");
    let cmd = process::Command::new("htekd")
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
