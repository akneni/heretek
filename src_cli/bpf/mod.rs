mod bpfmap;
pub mod event_types;

use std::{
    path::Path,
    process::{self, Stdio},
};

use anyhow::Result;
pub use bpfmap::*;

use crate::uinterf::Config;

pub fn load_bpf_objects(config: &Config) -> Result<()> {
    let repo_path = config.htek_repo.as_ref().unwrap();
    let path = Path::new(repo_path);

    let out = process::Command::new("pixi")
        .args(["run", "load"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(path)
        .output()?;

    if !out.status.success() {
        eprintln!(
            "Failed to load eBPF objects:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        process::exit(1);
    }

    Ok(())
}

pub fn unload_bpf_objects(config: &Config) -> Result<()> {
    let repo_path = config.htek_repo.as_ref().unwrap();
    let path = Path::new(repo_path);

    let out = process::Command::new("pixi")
        .args(["run", "unload"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(path)
        .output()?;

    if !out.status.success() {
        eprintln!(
            "Failed to unload eBPF objects:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        process::exit(1);
    }

    Ok(())
}
