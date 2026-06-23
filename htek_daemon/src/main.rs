use std::{
    fs::File,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use htek_lib::htdirs;
use tracing_subscriber::prelude::*;

use crate::pgraph::PGraph;
use crate::{bpf::BpfEventArrayReader, rpc::RpcServer};
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
    if whoami::username()? != "root" {
        bail!("root privilages required");
    }

    let loaded = htek_lib::config::ConfigFile::load().context("Failed to load config")?;
    let acl_path = htdirs::acl_path();
    let acl = Acl::from_acl_file(&acl_path).context("Failed to parse ACL")?;

    Ok(Config::from(loaded, acl))
}

fn daemon_init(config: &Config) -> Result<(RpcServer, BpfEventArrayReader)> {
    uinterf::prep_logs(config).context("Failed to prepare the logfiles")?;

    let trc_path = htdirs::tracefile_path();
    let trc_fp = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&trc_path)?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(tracing_subscriber::fmt::layer().with_writer(trc_fp))
        .init();

    bpf::unload_all_bpf_obj()?;
    bpf::load_bpf_obj(config)?;

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

    let rpc_server = RpcServer::new()?;

    Ok((rpc_server, bpf_reader))
}

fn main() {
    let config = match preflight() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Preflight Checks Failed:\n{}", e);
            utils::clean_shutdown(1);
        }
    };

    // This is the only area in the code where the daemon is allowed to exit/fail (unless ASSERTS is enabled)
    let (mut rpc_server, mut bpf_reader) = match daemon_init(&config) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("An error occured while initalizing the daemon: {e}");
            utils::clean_shutdown(1);
        }
    };

    let mut events = vec![];
    let mut pgraph_db = PGraph::from_existing_processes(&config);

    let iter_interval = Duration::from_micros(50_000);
    let mut ttracker = perftracker::PerfTracker::new();
    let mut counter: u64 = 0;

    tracing::info!("htekd started successfully. Entering main loop../");
    loop {
        counter += 1;

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

        if timer.elapsed() >= iter_interval {
            ttracker.end_iter();
            tracing::warn!(
                "Interval {} too long {:?} (skipping RPC handling & maintenence steps)",
                counter,
                timer.elapsed()
            );
            continue;
        }

        // 3) Do misc maintenence things
        pgraph_db.check_unchained_chains_asso();
        pgraph_db.check_cycles_asso();
        pgraph_db.check_killed_children_asso();

        if counter.is_multiple_of(8)
            && let Err(e) = rpc_server.heal_sockets()
        {
            tracing::error!("An error occured recreating sockets: {e}");
        }

        // 4) Check for IPC RPCs from CLI invocations of this tool (like `htek desc <pid>`)
        let res = rpc_server.handle_rpc(|rpcobj, is_root| {
            rpc::handle_rpc(&config, &mut pgraph_db, rpcobj, is_root)
        });
        if let Err(e) = res {
            tracing::warn!("{e}");
        }

        // 5) Sleep for an alloted amount of time.
        let te = timer.elapsed().as_micros() as u64;
        ttracker.end_iter();

        if counter.is_multiple_of(8) && build_params::PERF_TRACKING {
            ttracker.display_stats();
        }

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
