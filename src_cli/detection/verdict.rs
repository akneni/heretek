use std::ops::BitOr;

use crate::{detection::Protectee, pgraph::AccessType};

#[allow(unused)]
#[derive(Debug, Clone)]
pub enum PolicyVerdict {
    Benign,
    Violation {
        prote: Protectee,
        attempted_access: AccessType,
        allowed_access: AccessType,
    },
}

impl BitOr for PolicyVerdict {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        match self {
            Self::Benign => rhs,
            violation @ Self::Violation { .. } => violation,
        }
    }
}
