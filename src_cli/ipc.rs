use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rpc {
    // htek summary <pid | binary-path>
    GetSummaryPid {
        pid: i32,
    },
    GetSummaryExe {
        exe_path: String,
    },
    GetSummaryRes {
        pid: i32,
        exe_path: String,
    },

    SetParentProfile {
        profile: String,
    },
    SetParentProfileRes {
        msg: String,
        success: bool,
    },
}
