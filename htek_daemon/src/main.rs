use std::{
    fs::File,
    os::unix::net::UnixListener,
    process, thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tracing_subscriber::prelude::*;

use crate::bpf::BpfEventArrayReader;
use crate::pgraph::PGraph;
use crate::{detection::Acl, uinterf::Config};

mod bpf;
mod detection;
mod pgraph;
mod response;
mod rpc;
mod uinterf;

mod build_params;
mod perftracker;
mod utils;

fn preflight() -> Result<Config> {
    let loaded = htek_lib::config::LoadedConfig::load()?;
    let acl_path = loaded.dirs.config_dir().join("ACL.json");
    let acl = Acl::from_acl_file(&acl_path).context("Failed to parse ACL")?;

    Ok(Config::from(loaded, acl))
}

fn daemon_init(config: &Config) -> Result<(UnixListener, BpfEventArrayReader)> {
    response::init_alert_log(config).context("Failed to initalize the alert/violation log")?;

    let trc_path = config.dirs.data_dir().join("traces.log");
    let trc_fp = File::options().create(true).write(true).open(&trc_path)?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(tracing_subscriber::fmt::layer().with_writer(trc_fp))
        .init();

    tracing::warn!("started up successfully");

    let socket = htek_lib::rpc::try_create_listener(&config.dirs)?;
    socket.set_nonblocking(true)?;

    let bpf_reader = bpf::BpfEventArrayReader::from_pinned_path("/sys/fs/bpf/heretek-maps/events");
    let bpf_reader = match bpf_reader {
        Ok(r) => r,
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("code: 2") && err_str.contains("No such file or directory") {
                bail!("The BPF map is not loaded");
            } else {
                bail!("Unknown error accessing the bpf map: {:?}", e);
            }
        }
    };

    Ok((socket, bpf_reader))
}

fn main() {
    let config = match preflight() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Preflight Checks Failed:\n{}", e);
            process::exit(1);
        }
    };

    // This is the only area in the code where the daemon is allowed to exit/fail (unless ASSERTS is enabled)
    let (socket, mut bpf_reader) = match daemon_init(&config) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("An error occured while initalizing the daemon: {e}");
            process::exit(1);
        }
    };

    let mut events = vec![];
    let mut pgraph_db = PGraph::from_existing_processes(&config);

    let iter_interval = Duration::from_micros(50_000);
    let mut ttracker = perftracker::PerfTracker::new();

    loop {
        let timer = Instant::now();
        ttracker.start_iter();

        // 1) Drain the ring buffers and update it's internal pgraph structure with the events just pulled
        if let Err(e) = bpf_reader.poll(&mut events) {
            let sleep_int = Duration::from_millis(500);
            ttracker.end_iter();

            tracing::warn!(
                "An error occured polling the eBPF mnaps. Make sure they are loaded: {e}"
            );
            thread::sleep(sleep_int);
            continue;
        }
        events.sort_by_key(|x| x.ktime);
        ttracker.record_num_events(events.len() as u64);

        // 2) Run checks against the ACL to check for violations
        for event in events.into_iter() {
            if let Err(e) = pgraph::handle_event(&config, &mut pgraph_db, &event) {
                tracing::warn!("Error handling event: {}", e);
            }
        }
        events = vec![];

        // 3) Check for IPC RPCs from CLI invocations of this tool (like `htek desc <pid>`)
        if let Err(e) = rpc::handle_rpc(&config, &mut pgraph_db, &socket) {
            tracing::warn!("Error processing RPC: {e}");
        }

        // 4) Sleep for an alloted amount of time.
        let te = timer.elapsed().as_micros() as u64;
        ttracker.end_iter();

        if ttracker.total_iterations.is_multiple_of(10) && build_params::PERF_TRACKING {
            ttracker.display_stats();
        }

        pgraph_db.check_unchained_chains_dbgo(&config);
        pgraph_db.check_cycles_dbgo(&config);

        let iter_interval_us = iter_interval.as_micros() as u64;
        if te >= iter_interval_us {
            continue;
        } else {
            let time_left_us = iter_interval_us - te;
            if time_left_us > 1000 {
                thread::sleep(Duration::from_micros(time_left_us));
            }
        }
    }
}
