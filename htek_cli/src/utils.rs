use std::ffi::OsString;
use std::{
    os::unix::process::ExitStatusExt,
    process::{self, Command, Stdio},
};

use anyhow::{bail, Result};

use crate::cli::SpawnMode;

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
