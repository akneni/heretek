use std::io::Write;
use std::{path::Path, process};

use anyhow::{Result, bail};
use htek_lib::htdirs;

use crate::uinterf::Config;

/// Loads an eBPF object by its filename.
pub fn load_bpf_obj(_config: &Config) -> Result<()> {
    let obj = "heretek.ebpf.o";

    let bpf_path = htdirs::bpf_obj_path();
    let obj_path = bpf_path.join(obj);
    if !obj_path.exists() {
        bail!("eBPF object does not exist");
    }

    let prog_pin_dir = Path::new("/sys/fs/bpf/heretek");
    let map_pin_dir = Path::new("/sys/fs/bpf/heretek-maps");

    // Make it so that anyone can see perf events
    let perf_event_paranoid = Path::new("/proc/sys/kernel/perf_event_paranoid");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .open(perf_event_paranoid)
    {
        let _ = file.write_all(b"-1\n");
    }

    std::fs::create_dir_all(prog_pin_dir)?;
    std::fs::create_dir_all(map_pin_dir)?;

    let output = process::Command::new("bpftool")
        .arg("prog")
        .arg("loadall")
        .arg(&obj_path)
        .arg(prog_pin_dir)
        .arg("pinmaps")
        .arg(map_pin_dir)
        .arg("autoattach")
        .output()?;

    if !output.status.success() {
        bail!(
            "Failed to load eBPF object with bpftool (status: {}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Unloads all eBPF objects
/// Does *not* raise an error if an object to be unloaded cannot be found.
pub fn unload_all_bpf_obj() -> Result<()> {
    let prog_pin_dir = Path::new("/sys/fs/bpf/heretek");
    let map_pin_dir = Path::new("/sys/fs/bpf/heretek-maps");

    for pin_dir in [prog_pin_dir, map_pin_dir] {
        match std::fs::read_dir(pin_dir) {
            Ok(entries) => {
                for entry in entries {
                    let path = entry?.path();
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => bail!("Failed to remove BPF pin {}: {e}", path.display()),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => bail!(
                "Failed to read BPF pin directory {}: {e}",
                pin_dir.display()
            ),
        }

        match std::fs::remove_dir(pin_dir) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(e) => bail!(
                "Failed to remove BPF pin directory {}: {e}",
                pin_dir.display()
            ),
        }
    }

    Ok(())
}
