use std::{backtrace::Backtrace, fs, path::Path, process};

use anyhow::Result;
use htek_lib::htdirs;

use crate::{bpf, build_params, uinterf::Config};

/// Assert Canonical Path Debug Only
pub fn assert_canonical_dbgo(fpath: &Path) {
    if build_params::ASSERTS {
        assert_canonical(fpath);
    }
}

pub fn assert_canonical(fpath: &Path) {
    if let Ok(full_path) = fs::canonicalize(fpath) {
        assert_eq!(full_path, fpath);
    }
}

pub fn unreachable() {
    if build_params::ASSERTS {
        let bt = Backtrace::force_capture();
        let msg = format!("Reached an unreachable section of code:\n{}", bt);
        tracing::error!(msg);
        process::exit(1);
    } else {
        tracing::error!("Reached an unreachable section of code");
    }
}

/// This functions returns an error or never returns.
pub fn clean_shutdown(config: &Config) -> Result<()> {
    bpf::unload_all_bpf_obj(config)?;

    if let Err(e) = fs::remove_file(htdirs::socket_path()) {
        tracing::warn!("Failed to clean up UDS file on exit: {e}");
    }

    process::exit(0);
}
