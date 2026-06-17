use anyhow::Result;
use std::fmt::{Debug, Display, Write as FmtWrite};
use std::fs::File;
use std::io::Write as IoWrite;
use std::time::Instant;

use crate::pgraph::PGraph;
use htek_lib::htdirs;

/// Typically, the tracing crate is used for errors. For more complex things (like when we
/// detect a broken invarient in PGraph), this structure is used to create a file that we can
/// dump our state into to help us debug it easier.
pub struct IncFile {
    fp: File,
    timer: Instant,
}

impl IncFile {
    pub fn new(desc: &str) -> Result<Self> {
        let timer = Instant::now();
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
        let inc_path = htdirs::data_dir().join(format!("{}.incident", ts));

        let fp = File::options().create(true).write(true).open(&inc_path)?;
        let mut inc_file = Self { fp, timer };

        writeln!(inc_file.fp, "INCIDENT: {}\n\n\n", desc)?;

        Ok(inc_file)
    }

    pub fn dmp_stacktrace(&mut self) -> Result<()> {
        writeln!(
            self.fp,
            "BACKTRACE:\n{}\n\n\n",
            std::backtrace::Backtrace::force_capture()
        )?;
        Ok(())
    }

    pub fn dmp_pgraph(&mut self, pgraph_db: &PGraph) -> Result<()> {
        let mut payload = String::with_capacity(4096);
        payload.push_str("\n\n\nPgraph:\n\n");

        for (_, node) in pgraph_db.nodes.iter() {
            let _ = writeln!(&mut payload, "{}\n", node.to_str(1));
        }
        payload.push_str("\n\n\n");
        writeln!(self.fp, "{}", &payload)?;

        Ok(())
    }

    #[allow(unused)]
    pub fn dmp_displayable(&mut self, section_name: &str, object: impl Display) -> Result<()> {
        let mut payload = String::with_capacity(4096);
        let _ = writeln!(&mut payload, "{}:\n", section_name);
        let _ = writeln!(&mut payload, "{}\n\n\n", object);
        writeln!(self.fp, "{}", &payload)?;
        Ok(())
    }

    pub fn dmp_debugable(&mut self, section_name: &str, object: impl Debug) -> Result<()> {
        let mut payload = String::with_capacity(4096);
        let _ = writeln!(&mut payload, "{}:\n", section_name);
        let _ = writeln!(&mut payload, "{:#?}\n\n\n", object);
        writeln!(self.fp, "{}", &payload)?;
        Ok(())
    }
}

impl Drop for IncFile {
    fn drop(&mut self) {
        let _ = writeln!(
            self.fp,
            "Time Elapsed Creating Incident file: {:?}\n",
            self.timer.elapsed()
        );
    }
}

/// Convienent oneliner to create and populate an incident file.
/// Usage:
///    - `incident!("an error occured")`
///    - `incident!("an error occured", pgraph)`
#[macro_export]
macro_rules! incident {
    ($desc:expr $(,)?) => {
        match $crate::uinterf::IncFile::new($config, $desc) {
            Ok(mut inc_file) => {
                if let Err(error) = inc_file.dmp_stacktrace() {
                    tracing::warn!("Failed to write incident stack trace: {error}");
                }
            }
            Err(error) => {
                tracing::warn!("Failed to create incident file: {error}");
            }
        }
    };
    ($desc:expr, pgraph = $pgraph:expr $(,)?) => {
        match $crate::uinterf::IncFile::new($config, $desc) {
            Ok(mut inc_file) => {
                if let Err(error) = inc_file.dmp_stacktrace() {
                    tracing::warn!("Failed to write incident stack trace: {error}");
                }
                if let Err(error) = inc_file.dmp_pgraph($pgraph) {
                    tracing::warn!("Failed to write incident process graph: {error}");
                }
            }
            Err(error) => {
                tracing::warn!("Failed to create incident file: {error}");
            }
        }
    };
}
