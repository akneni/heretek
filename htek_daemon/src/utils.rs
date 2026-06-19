use std::{backtrace::Backtrace, fs, path::Path, process};

use htek_lib::htdirs;

use crate::{bpf, build_params};

/// Assert Canonical Path ASSERTS = true only
pub fn assert_canonical_asso(fpath: &Path) {
    if build_params::ASSERTS {
        assert_canonical(fpath);
    }
}

pub fn assert_canonical(fpath: &Path) {
    if let Ok(full_path) = fs::canonicalize(fpath)
        && full_path != fpath {
            tracing::error!("assert_canonical failed: {}", fpath.display());
        }
}

pub fn unreachable() {
    if build_params::ASSERTS {
        let bt = Backtrace::force_capture();
        let msg = format!("Reached an unreachable section of code:\n{}", bt);
        tracing::error!(msg);
        clean_shutdown(1);
    } else {
        tracing::error!("Reached an unreachable section of code");
    }
}

/// This functions returns an error or never returns.
pub fn clean_shutdown(exit_code: i32) -> ! {
    if let Err(e) = bpf::unload_all_bpf_obj() {
        tracing::warn!("Error unloading BPF objects on shutdown: {e}");
    }

    if let Err(e) = fs::remove_file(htdirs::socket_path_root()) {
        tracing::warn!("Failed to clean up UDS file on exit: {e}");
    }

    if let Err(e) = fs::remove_file(htdirs::socket_path_any()) {
        tracing::warn!("Failed to clean up UDS file on exit: {e}");
    }

    process::exit(exit_code);
}
