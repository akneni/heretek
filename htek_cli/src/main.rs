use std::{
    collections::HashSet,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::Path,
    process::{self, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use htek_lib::{
    config::LoadedConfig,
    rpc::{self, Rpc, RpcResult, StreamSendable},
};

use crate::{
    cli::{CliCommand, SpawnMode},
    utils::{ACL_JSON, CONFIG_JSON, get_nonroot_user, spawn_cmd},
};

mod cli;
mod utils;

fn bringup(config: &LoadedConfig) -> Result<()> {
    if let Ok(_) = rpc::try_connect(&config.dirs) {
        eprintln!("heretek daemon seems to already be running!");
        return Ok(());
    }

    println!("Spawning Heretek daemon...");
    process::Command::new("htekd")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn htekd")?;

    let mut sleep_ms = 75;
    for _i in 0..4 {
        match rpc::try_connect(&config.dirs) {
            Ok(_) => {
                println!("Spawned daemon successfully");
                return Ok(());
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(sleep_ms));
                sleep_ms *= 2;
            }
        }
    }

    eprintln!("Time out exceeded. Daemon spawned but has since crashed or is unresponsive.");
    print_daemon_traces(config)?;

    Ok(())
}

fn bringdown(config: &LoadedConfig) -> Result<()> {
    let mut sleep_ms = 75;
    for i in 0..4 {
        match rpc::try_connect(&config.dirs) {
            Ok(stream) => {
                Rpc::Bringdown.try_stream_send(&stream)?;
            }
            Err(_) => {
                if i == 0 {
                    println!("Heretek daemon is not running");
                } else {
                    println!("Heretek daemon shut down successfully!");
                }
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(sleep_ms));
        sleep_ms *= 2;
    }

    eprintln!("Time out exceeded, daemon doesn't seem to be shutting down");
    process::exit(1);
}

fn print_daemon_traces(config: &LoadedConfig) -> Result<()> {
    let traces = match fs::read(config.dirs.tracefile_path()?) {
        Ok(r) => r,
        Err(_) => {
            println!("Daemon tracefile doesn't exist!");
            return Ok(());
        }
    };

    if traces.is_empty() {
        eprintln!("Daemon's trace file is empty");
        return Ok(());
    }

    eprintln!("Daemon Traces:");
    let mut lk = io::stdout().lock();
    lk.write_all(&traces)?;

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

fn cfgpull(_config: &LoadedConfig) -> Result<()> {
    let cgf_files = [
        (Path::new("/root/.config/heretek/ACL.json"), ACL_JSON),
        (Path::new("/root/.config/heretek/config.json"), CONFIG_JSON),
    ];
    for (fpath_hcfg, default) in cgf_files {
        let fname = fpath_hcfg
            .file_name()
            .ok_or(anyhow!("failed to get filename"))?
            .to_str()
            .ok_or(anyhow!("failed to get filename"))?;

        if fpath_hcfg.exists() {
            fs::copy(fpath_hcfg, fname)?;
        } else {
            fs::write(fname, default)?;
        }

        let fpath_cwd = Path::new(fname);
        let output = process::Command::new("chown")
            .arg(get_nonroot_user()?)
            .arg(fpath_cwd)
            .output()?;
        if !output.status.success() {
            bail!(
                "failed to chown {}: {}",
                fpath_cwd.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    Ok(())
}

/// Pushes config.json and ACL.json from the current directory the heretek config directory
/// Skips over either of these files if they don't exist in the current directory.
fn cfgpush(_config: &LoadedConfig) -> Result<()> {
    bail!("cfgpush is not implemented yet")
}

fn rpc_call(config: &LoadedConfig, request: Rpc) -> Result<RpcResult> {
    let stream = rpc::try_connect(&config.dirs).context("Heretek daemon is not running")?;
    request.try_stream_send(&stream)?;
    RpcResult::try_stream_recv(&stream)
}

fn spawn_as_profile(
    config: &LoadedConfig,
    profile: Option<String>,
    mode: Option<SpawnMode>,
    command: Vec<OsString>,
) -> Result<()> {
    // Sets the profile if one is provides
    if let Some(profile) = profile {
        let mut profiles = HashSet::new();
        profiles.insert(profile);

        let stream = rpc::try_connect(&config.dirs)?;

        let req = rpc::Rpc::SetChildProfile {
            pid: process::id() as i32,
            profiles,
        };
        req.try_stream_send(&stream)?;

        let res = rpc::RpcResult::try_stream_recv(&stream)?;
        if let rpc::RpcResult::SetChildProfileRes { msg, success } = res {
            if !success {
                bail!(msg);
            }
        } else {
            bail!("unknown result");
        }
    }

    // Spawns the command
    let mode = mode.unwrap_or(SpawnMode::Sync);
    spawn_cmd(command, mode)
}

fn run(config: &LoadedConfig, command: CliCommand) -> Result<()> {
    match command {
        CliCommand::Bringup => bringup(config),
        CliCommand::Bringdown => bringdown(config),
        CliCommand::CfgPull => cfgpull(config),
        CliCommand::CfgPush => cfgpush(config),
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
        CliCommand::Spawn {
            profile,
            mode,
            command,
        } => {
            spawn_as_profile(config, profile, mode, command)?;
            Ok(())
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
