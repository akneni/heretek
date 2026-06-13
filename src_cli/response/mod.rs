use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, Seek, Write},
    path::PathBuf,
};

use directories::ProjectDirs;
use notify_rust::Notification;
use rustix::process::Signal;

use crate::{
    detection::PolicyVerdict,
    pgraph::{ActorTuid, PGraph, PGraphNode},
    uinterf::Config,
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

    for violation in root_violations {
        let evil_root = if let PolicyVerdict::Violation { tuid, .. } = violation {
            tuid
        } else {
            return;
        };
        let node = pgraph_db.nodes.get(&evil_root).unwrap();

        if config.quarentine.contains(&"log".to_string()) {
            log(node, violation, pgraph_db, violations, &violating_tuids);
        }
        if config.quarentine.contains(&"notify".to_string()) {
            notify(node);
        }
        if config.quarentine.contains(&"terminate".to_string()) {
            terminate(pgraph_db, node);
        }
    }
}

fn alert_log_path() -> PathBuf {
    let proj = ProjectDirs::from("com", "heretek", "heretek").unwrap();
    proj.data_dir().join("alerts.log")
}

pub fn init_alert_log(_config: &Config) {
    let alert_log = alert_log_path();
    let mut alert_bak = alert_log.clone();
    alert_bak.pop();
    alert_bak.push("alerts_bak.log");

    if alert_log.exists() {
        let alets = fs::read_to_string(&alert_log).unwrap();

        let mut fp = File::options()
            .create(true)
            .append(true)
            .open(&alert_bak)
            .unwrap();

        fp.write(alets.as_bytes()).unwrap();
        fp.write(b"\n\n").unwrap();
        drop(fp);

        fs::remove_file(&alert_log).unwrap();
        fs::write(&alert_log, "").unwrap();
    }
}

fn log(
    node: &PGraphNode,
    violation: &PolicyVerdict,
    pgraph_db: &PGraph,
    violations: &[PolicyVerdict],
    violating_tuids: &HashSet<ActorTuid>,
) {
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

        println!("{}", alert);

        let alert_path = alert_log_path();
        println!("{}", alert_path.display());
        let mut fp = File::options()
            .write(true)
            .create(true)
            .open(&alert_path)
            .unwrap();

        fp.seek(io::SeekFrom::End(0)).unwrap();
        writeln!(fp, "{}", alert).unwrap();
    }
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

fn terminate(pgraph_db: &PGraph, evil_root: &PGraphNode) {
    let mut to_kill = evil_root.child_tuids.clone();

    let pid = rustix::process::Pid::from_raw(evil_root.actor.id.pid).unwrap();
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

            let pid = rustix::process::Pid::from_raw(tuid.pid).unwrap();
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
        .map(|x| x.to_str().unwrap())
        .unwrap_or("[unknown binary]");

    let res = Notification::new()
        .summary(&format!("heretek alert! {} flagged", bin))
        .body(&format!("{}", node.to_str(1)))
        .show();

    if let Err(e) = res {
        eprintln!("Failed to send notification: {}", e);
    }
}
