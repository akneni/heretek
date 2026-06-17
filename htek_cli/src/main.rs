use std::{
    collections::HashSet,
    ffi::OsString,
    fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{self, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use htek_lib::{
    config::{HtekDirs, LoadedConfig},
    rpc::{self, Rpc, RpcResult, StreamSendable},
};
use rustix::process::{Gid, Uid};

use crate::{
    cli::{CliCommand, SpawnMode},
    utils::spawn_cmd,
};

mod cli;
mod utils;

fn bringup(config: &LoadedConfig) -> Result<()> {
    if whoami::username()? != "root" {
        bail!("Requires root privilages");
    }

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
    if whoami::username()? != "root" {
        bail!("Requires root privilages");
    }

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
    let traces = match fs::read(config.dirs.tracefile_path()) {
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
    let bpf_dir = config.dirs.bpf_obj_path();

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
    if whoami::username()? != "root" {
        bail!("Requires root privilages");
    }

    let build = Path::new("build");

    for file in ["htek", "htekd"] {
        let file_path = build.join(file);
        if !file_path.exists() || !file_path.is_file() {
            bail!("Failed to find {}", file_path.display());
        }
    }

    let bpf_dir = config.dirs.bpf_obj_path();
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

fn cfgpull(config: &LoadedConfig) -> Result<()> {
    let cgf_files = [
        (config.dirs.acl_path(), htek_lib::config::ACL_JSON),
        (config.dirs.config_path(), htek_lib::config::CONFIG_JSON),
    ];

    let owner = if whoami::account()? == "root" {
        let uid = std::env::var("SUDO_UID")
            .context("Cannot determine non-root user: SUDO_UID is not set")?
            .parse()?;
        let gid = std::env::var("SUDO_GID")
            .context("Cannot determine non-root user: SUDO_GID is not set")?
            .parse()?;
        (Uid::from_raw(uid), Gid::from_raw(gid))
    } else {
        (rustix::process::getuid(), rustix::process::getgid())
    };

    for (fpath_hcfg, default) in cgf_files {
        let fname = fpath_hcfg
            .file_name()
            .ok_or(anyhow!("failed to get filename"))?
            .to_str()
            .ok_or(anyhow!("failed to get filename"))?;

        if fpath_hcfg.exists() {
            fs::copy(&fpath_hcfg, fname)?;
        } else {
            fs::write(fname, default)?;
        }

        let fpath_cwd = Path::new(fname);
        rustix::fs::chown(fpath_cwd, Some(owner.0), Some(owner.1))
            .with_context(|| format!("failed to chown {}", fpath_cwd.display()))?;
    }
    Ok(())
}

/// Pushes config.json and ACL.json from the current directory the heretek config directory
/// Skips over either of these files if they don't exist in the current directory.
fn cfgpush(_config: &LoadedConfig) -> Result<()> {
    if whoami::username()? != "root" {
        bail!("Requires root privilages");
    }

    let cgf_files = [
        Path::new("/root/.config/heretek/ACL.json"),
        Path::new("/root/.config/heretek/config.json"),
    ];
    for fpath_hcfg in cgf_files {
        let fname = fpath_hcfg
            .file_name()
            .ok_or(anyhow!("failed to get filename"))?
            .to_str()
            .ok_or(anyhow!("failed to get filename"))?;
        let fpath_cwd = Path::new(fname);

        if !fpath_cwd.exists() {
            continue;
        }

        if let Some(parent) = fpath_hcfg.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(fpath_cwd, fpath_hcfg)?;

        rustix::fs::chown(fpath_hcfg, Some(Uid::ROOT), Some(Gid::ROOT))
            .with_context(|| format!("failed to chown {}", fpath_hcfg.display()))?;

        fs::set_permissions(fpath_hcfg, fs::Permissions::from_mode(0o644))?;

        println!("Successfully pushed {}", fpath_cwd.display());
    }
    Ok(())
}

fn init(force: bool) -> Result<()> {
    if whoami::username()? != "root" {
        bail!("Requires root privilages");
    }

    let mfile = HtekDirs.htek_magic_file_path();
    let cfg_dir = HtekDirs.config_dir();
    let data_dir = HtekDirs.data_dir();

    if !force {
        if !mfile.exists() && (cfg_dir.exists() || data_dir.exists()) {
            let msg = r#"
                It seems like another app is already using the heretek config & data directory.
                If want to forcibly overwrite these directories, run `sudo htek init --force`
            "#;
            bail!(msg);
        } else if mfile.exists() {
            return Ok(());
        }
    }

    fs::remove_dir_all(&cfg_dir)?;
    fs::remove_dir_all(&data_dir)?;

    htek_lib::config::validate_environment()?;

    Ok(())
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
        CliCommand::Init { .. } => unreachable!(),
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
    let cli_args = cli::parse_cli();
    if let &CliCommand::Init { force } = &cli_args {
        if let Err(e) = init(force) {
            eprintln!("{e}");
            process::exit(1);
        }
        process::exit(0);
    }

    let config = match htek_lib::config::LoadedConfig::load() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load config: {e}");
            process::exit(1);
        }
    };

    let result = run(&config, cli_args);

    if let Err(error) = result {
        eprintln!("{error:#}");
        process::exit(1);
    }
}
