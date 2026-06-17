mod config;
mod trcing;

use std::fs::{self, File};
use std::io::Write;

use anyhow::{Result, anyhow};

pub use config::*;
pub use trcing::*;

/// Backsup and Empties log files.
/// Currently, this operates on the violations log and the trace file
pub fn prep_logs(config: &Config) -> Result<()> {
    let files = [
        config.dirs.violation_log_path(),
        config.dirs.tracefile_path(),
    ];

    for f in files {
        if f.exists() {
            let old_name = {
                let fname = f
                    .file_name()
                    .ok_or(anyhow!("failed to get filename"))?
                    .to_str()
                    .ok_or(anyhow!("failed to get filename"))?;

                let (name, ext) = fname
                    .rsplit_once(".")
                    .ok_or(anyhow!("filename doesn't have an extension"))?;
                format!("{}_old.{}", name, ext)
            };

            let existing_contents = fs::read(&f)?;

            let mut f_old = f.clone();
            f_old.pop();
            f_old.push(&old_name);

            let mut fp = File::options().create(true).append(true).open(&f_old)?;

            fp.write_all(&existing_contents)?;
            fp.write_all(b"\n\n=======================\n\n")?;
            drop(fp);

            fs::remove_file(&f)?;
        }

        fs::write(&f, b"")?;
    }

    Ok(())
}
