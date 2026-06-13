use std::{fs, path::Path};

/// Assert Canonical Path Debug Only
pub fn assert_canonical_dbgo(fpath: &Path) {
    if cfg!(debug_assertions) {
        assert_canonical(fpath);
    }
}

pub fn assert_canonical(fpath: &Path) {
    if let Ok(full_path) = fs::canonicalize(fpath) {
        assert_eq!(full_path, fpath);
    }
}
