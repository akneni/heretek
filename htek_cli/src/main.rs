use std::{
    fs,
    path::Path,
    process::{self, Stdio},
};

use anyhow::{Context, Result, bail};
use htek_lib::{
    config::LoadedConfig,
    rpc::{self, Rpc, RpcResult, StreamSendable},
};

use crate::cli::CliCommand;

mod cli;

fn bringup(config: &LoadedConfig) -> Result<()> {
    // rpc::check_not_running(&config.dirs)?;
    // println!("Loading eBPF objects");
    // bpf::load(config)?;

    // println!("Spawning Heretek daemon");
    // process::Command::new("htekd")
    //     .stdin(Stdio::null())
    //     .stdout(Stdio::null())
    //     .stderr(Stdio::null())
    //     .spawn()
    //     .context("Failed to spawn htekd")?;
    // println!("Spawned daemon successfully");
    Ok(())
}

fn bringdown(config: &LoadedConfig) -> Result<()> {
    // match rpc::try_connect(&config.dirs) {
    //     Ok(stream) => {
    //         Rpc::Bringdown { unload_bpf: false }.try_stream_send(&stream)?;
    //         let _ = RpcResult::try_stream_recv(&stream);
    //         println!("Heretek daemon exited");
    //     }
    //     Err(_) => println!("Heretek daemon is not running"),
    // }

    // bpf::unload(config)
    Ok(())
}

/// Deletes all .ebpf.o files inside of the eBPF object directory
fn purge_bpf_objects(config: &LoadedConfig) -> Result<()> {
    let bpf_dir = config.dirs.bpf_obj_path()?;

    for entry in
        fs::read_dir(&bpf_dir).with_context(|| format!("Failed to read {}", bpf_dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("Failed to read an entry in {}", bpf_dir.display()))?;
        let path = entry.path();

        if path.is_file()
            && path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".ebpf.o"))
        {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to delete {}", path.display()))?;
        }
    }

    Ok(())
}

fn install_from_repo(config: &LoadedConfig) -> Result<()> {
    let build = Path::new("build");

    for file in ["htek", "htekd"] {
        let file_path = build.join(file);
        if !file_path.exists() || !file_path.is_file() {
            bail!("Failed to find {}", file_path.display());
        }
    }

    let bpf_dir = config.dirs.bpf_obj_path()?;
    purge_bpf_objects(config)?;
    for file in build.read_dir()? {
        let file = file?;
        let fname = file.file_name();
        let fname = fname.to_str().unwrap();

        let dest = if matches!(fname, "htek" | "htekd") {
            Path::new("/").join("usr").join("bin").join(fname)
        } else if fname.ends_with(".ebpf.o") {
            bpf_dir.join(fname)
        } else {
            bail!("unknown file type: {}", file.path().display());
        };

        fs::copy(&file.path(), &dest)?;
    }

    println!("Finished installing htek, htekd, and all eBPF objects!");
    Ok(())
}

fn rpc_call(config: &LoadedConfig, request: Rpc) -> Result<RpcResult> {
    let stream = rpc::try_connect(&config.dirs).context("Heretek daemon is not running")?;
    request.try_stream_send(&stream)?;
    RpcResult::try_stream_recv(&stream)
}

fn run(config: &LoadedConfig, command: CliCommand) -> Result<()> {
    match command {
        CliCommand::Bringup => bringup(config),
        CliCommand::Bringdown => bringdown(config),
        CliCommand::InstallFromRepo => install_from_repo(config),
        CliCommand::SummaryPid { pid } => match rpc_call(config, Rpc::GetSummaryPid { pid })? {
            RpcResult::GetSummary(summary) => {
                println!("{summary}");
                Ok(())
            }
            _ => bail!("Daemon returned an unexpected response"),
        },
        CliCommand::SummaryExe { exe_path } => {
            match rpc_call(config, Rpc::GetSummaryExe { exe_path })? {
                RpcResult::GetSummary(summary) => {
                    println!("{summary}");
                    Ok(())
                }
                _ => bail!("Daemon returned an unexpected response"),
            }
        }
        CliCommand::SetProfile { profile, pid } => {
            match rpc_call(config, Rpc::SetProfile { profile, pid })? {
                RpcResult::SetProfileRes { msg, success } => {
                    println!("{msg}");
                    if success {
                        Ok(())
                    } else {
                        bail!("Failed to set profile")
                    }
                }
                _ => bail!("Daemon returned an unexpected response"),
            }
        }
        CliCommand::Touched { file } => {
            let file = fs::canonicalize(file).context("Failed to resolve file")?;
            match rpc_call(config, Rpc::Touched { file })? {
                RpcResult::TouchedRes(summary) => {
                    println!("{summary}");
                    Ok(())
                }
                _ => bail!("Daemon returned an unexpected response"),
            }
        }
        CliCommand::DebugAction => match rpc_call(config, Rpc::DebugAction)? {
            RpcResult::DebugActionRes(output) => {
                println!("{output}");
                Ok(())
            }
            _ => bail!("Daemon returned an unexpected response"),
        },
    }
}

fn main() {
    let result =
        htek_lib::config::LoadedConfig::load().and_then(|config| run(&config, cli::parse_cli()));
    if let Err(error) = result {
        eprintln!("{error:#}");
        process::exit(1);
    }
}
