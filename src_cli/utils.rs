use std::{fs, path::Path};

pub fn assert_canonical(fpath: &Path) {
    if let Ok(full_path) = fs::canonicalize(fpath) {
        assert_eq!(full_path, fpath);
    }
}
