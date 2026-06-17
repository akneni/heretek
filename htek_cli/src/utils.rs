use std::ffi::OsString;
use std::{
    os::unix::process::ExitStatusExt,
    process::{self, Command, Stdio},
};

use anyhow::{Result, bail};

use crate::cli::SpawnMode;

pub const CONFIG_JSON: &str = include_str!("../../documentation/docs_usr/config.json");
pub const ACL_JSON: &str = include_str!("../../documentation/docs_usr/ACL.json");

/// Spawns a command.
pub fn spawn_cmd(command: Vec<OsString>, mode: SpawnMode) -> Result<()> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("No command was provided to spawn"))?;

    let mut cmd = Command::new(program);
    cmd.args(args);

    match mode {
        SpawnMode::Async => {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| {
                    anyhow::anyhow!("Failed to spawn {}: {e}", program.to_string_lossy())
                })?;

            Ok(())
        }
        SpawnMode::Sync => {
            let status = cmd
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map_err(|e| {
                    anyhow::anyhow!("Failed to spawn {}: {e}", program.to_string_lossy())
                })?;

            if let Some(code) = status.code() {
                process::exit(code);
            }

            if let Some(signal) = status.signal() {
                process::exit(128 + signal);
            }

            bail!("Spawned command exited without an exit code")
        }
    }
}

/// Gets the current user if we're not running as root.
/// Gets the user that spawned us with `sudo` (or simmilar) if we are running as root.
/// If we are root and no one spawned us with `sudo`, return an error
pub fn get_nonroot_user() -> Result<String> {
    let user = whoami::account()?;
    if user != "root" {
        return Ok(user);
    }

    let sudo_user = std::env::var("SUDO_USER")
        .map_err(|_| anyhow::anyhow!("Cannot determine non-root user: SUDO_USER is not set"))?;
    if sudo_user == "root" || sudo_user.is_empty() {
        bail!("Cannot determine non-root user");
    }

    Ok(sudo_user)
}
