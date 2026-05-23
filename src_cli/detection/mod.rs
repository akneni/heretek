mod acl;
mod acl_file;
mod protectee;

pub use acl::*;
pub use acl_file::*;
pub use protectee::*;

use crate::pgraph::AccessType;

#[derive(Debug, Clone)]
pub enum PolicyVerdict {
    Benign,
    Violation {
        prote: Protectee,
        attempted_access: AccessType,
    },
}
