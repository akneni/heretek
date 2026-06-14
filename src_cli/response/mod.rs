use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, Seek, Write as IoWrite},
};

use anyhow::Result;
use notify_rust::Notification;
use rustix::process::Signal;

use crate::{
    build_params,
    detection::PolicyVerdict,
    incident,
    pgraph::{ActorTuid, PGraph, PGraphNode},
    uinterf::{Config, IncFile},
};

pub fn handle_response(config: &Config, pgraph_db: &PGraph, violations: &[PolicyVerdict]) {
    let violating_tuids = violations
        .iter()
        .filter_map(|violation| {
            if let PolicyVerdict::Violation { tuid, .. } = violation {
                Some(*tuid)
            } else {
                None
            }
        })
        .collect::<HashSet<_>>();

    // This is the list of all root/parent processes of the violations.
    let root_violations = violations
        .iter()
        .filter(|violation| {
            let tuid = if let PolicyVerdict::Violation { tuid, .. } = violation {
                *tuid
            } else {
                return false;
            };

            let mut creator_tuid = pgraph_db
                .nodes
                .get(&tuid)
                .and_then(|node| node.creator_tuid);
            while let Some(tuid) = creator_tuid {
                if violating_tuids.contains(&tuid) {
                    return false;
                }

                creator_tuid = pgraph_db
                    .nodes
                    .get(&tuid)
                    .and_then(|node| node.creator_tuid);
            }

            true
        })
        .collect::<Vec<_>>();

    // Handle the root node for each violation
    for violation in root_violations {
        let evil_root = if let PolicyVerdict::Violation { tuid, .. } = violation {
            tuid
        } else {
            return;
        };
        let node = match pgraph_db.nodes.get(evil_root) {
            Some(r) => r,
            None => {
                if !build_params::ASSERTS {
                    continue;
                }

                if let Ok(mut inc_file) =
                    IncFile::new(config, "Seen violation from a node that doesn't exist")
                {
                    let _ = inc_file.dmp_stacktrace();
                    let _ = inc_file.dmp_debugable("Violating TUOD", &violating_tuids);
                    let _ = inc_file.dmp_pgraph(pgraph_db);
                }

                continue;
            }
        };

        if config.quarentine.contains(&"log".to_string())
            && let Err(e) = log(
                config,
                node,
                violation,
                pgraph_db,
                violations,
                &violating_tuids,
            )
        {
            eprintln!("failed to write to alert log: {e}");
        }
        if config.quarentine.contains(&"notify".to_string()) {
            notify(node);
        }
        if config.quarentine.contains(&"terminate".to_string()) {
            terminate(config, pgraph_db, node);
        }
    }
}

/// Moves everything in alerts.log to alerts_bak.log and ensures that alerts.log is empty and ready for this run.
pub fn init_alert_log(config: &Config) -> Result<()> {
    let alert_log = config.dirs.data_dir().join("alerts.log");
    let mut alert_bak = alert_log.clone();
    alert_bak.pop();
    alert_bak.push("alerts_bak.log");

    if alert_log.exists() {
        let alets = fs::read_to_string(&alert_log)?;

        let mut fp = File::options().create(true).append(true).open(&alert_bak)?;

        fp.write_all(alets.as_bytes())?;
        fp.write_all(b"\n\n")?;
        drop(fp);

        fs::remove_file(&alert_log)?;
        fs::write(&alert_log, "")?;
    }

    Ok(())
}

fn log(
    config: &Config,
    node: &PGraphNode,
    violation: &PolicyVerdict,
    pgraph_db: &PGraph,
    violations: &[PolicyVerdict],
    violating_tuids: &HashSet<ActorTuid>,
) -> Result<()> {
    if let PolicyVerdict::Violation {
        prote,
        attempted_access,
        allowed_access,
        ..
    } = violation
    {
        let binary = node
            .actor
            .actor_md
            .binary
            .last()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "[unknown binary]".to_string());
        let resource = match prote {
            crate::detection::Protectee::File(path) => path.display().to_string(),
            crate::detection::Protectee::Syscall(syscall) => format!("syscall:{syscall}"),
        };
        let mut attempted = String::new();
        attempted_access.to_rwxbc_str(&mut attempted);
        let mut allowed = String::new();
        allowed_access.to_rwxbc_str(&mut allowed);
        let mut alert = format!(
            "Heretek blocked a policy violation\n\
             Parent Process: {} (pid {})\n\
             Profiles: {:?}\n\
             Resource: {}\n\
             Attempted:  {}\n\
             Allowed:    {}\n",
            binary, node.actor.id.pid, node.actor.actor_md.profile, resource, attempted, allowed
        );

        for child_violation in violations {
            let PolicyVerdict::Violation {
                tuid,
                prote,
                attempted_access,
                allowed_access,
            } = child_violation
            else {
                continue;
            };

            if *tuid == node.actor.id
                || !violating_tuids.contains(tuid)
                || !is_descendant_of(pgraph_db, *tuid, node.actor.id)
            {
                continue;
            }

            let Some(child_node) = pgraph_db.nodes.get(tuid) else {
                continue;
            };
            let child_binary = child_node
                .actor
                .actor_md
                .binary
                .last()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "[unknown binary]".to_string());
            let child_resource = match prote {
                crate::detection::Protectee::File(path) => path.display().to_string(),
                crate::detection::Protectee::Syscall(syscall) => format!("syscall:{syscall}"),
            };
            let mut child_attempted = String::new();
            attempted_access.to_rwxbc_str(&mut child_attempted);
            let mut child_allowed = String::new();
            allowed_access.to_rwxbc_str(&mut child_allowed);

            alert.push_str(&format!(
                "\tChild Process: {} (pid {})\n\
                 \tProfiles: {:?}\n\
                 \tResource: {}\n\
                 \tAttempted:  {}\n\
                 \tAllowed:    {}\n",
                child_binary,
                child_node.actor.id.pid,
                child_node.actor.actor_md.profile,
                child_resource,
                child_attempted,
                child_allowed
            ));
        }

        let alert_path = config.alert_log_path();
        let mut fp = File::options().write(true).create(true).open(&alert_path)?;

        fp.seek(io::SeekFrom::End(0))?;
        writeln!(fp, "{}", alert)?;
    }

    Ok(())
}

fn is_descendant_of(pgraph_db: &PGraph, child_tuid: ActorTuid, root_tuid: ActorTuid) -> bool {
    let mut creator_tuid = pgraph_db
        .nodes
        .get(&child_tuid)
        .and_then(|node| node.creator_tuid);

    while let Some(tuid) = creator_tuid {
        if tuid == root_tuid {
            return true;
        }

        creator_tuid = pgraph_db
            .nodes
            .get(&tuid)
            .and_then(|node| node.creator_tuid);
    }

    false
}

fn terminate(config: &Config, pgraph_db: &PGraph, evil_root: &PGraphNode) {
    let mut to_kill = evil_root.child_tuids.clone();

    let pid = match rustix::process::Pid::from_raw(evil_root.actor.id.pid) {
        Some(r) => r,
        None => {
            incident!("Rustix PID Conversion Failed 1", config);
            return;
        }
    };
    let _ = rustix::process::kill_process(pid, Signal::KILL);

    while !to_kill.is_empty() {
        let mut to_kill_childs = HashSet::new();
        for tuid in to_kill.iter() {
            let node = match pgraph_db.nodes.get(tuid) {
                Some(r) => r,
                None => continue,
            };

            for cn in node.child_tuids.iter() {
                to_kill_childs.insert(*cn);
            }

            let pid = match rustix::process::Pid::from_raw(tuid.pid) {
                Some(r) => r,
                None => {
                    incident!("Rustix PID Conversion Failed 2", config);
                    continue;
                }
            };
            let _ = rustix::process::kill_process(pid, Signal::KILL);
        }
        to_kill = to_kill_childs;
    }
}

fn notify(node: &PGraphNode) {
    let bin = node
        .actor
        .actor_md
        .binary
        .last()
        .map(|x| x.to_str().unwrap_or("[unknown binary]"))
        .unwrap_or("[unknown binary]");

    let res = Notification::new()
        .summary(&format!("heretek alert! {} flagged", bin))
        .body(&node.to_str(1).to_string())
        .show();

    if let Err(e) = res {
        eprintln!("Failed to send notification: {}", e);
    }
}
