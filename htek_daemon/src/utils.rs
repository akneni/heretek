use std::{fs, path::Path};

use crate::build_params;

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
