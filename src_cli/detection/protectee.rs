use std::path::PathBuf;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Protectee {
    File(PathBuf),
    Syscall(String),
}
