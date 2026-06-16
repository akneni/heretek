use std::ffi::OsString;

use clap::{Arg, ArgAction, ArgMatches, Command as ClapCommand, builder::OsStringValueParser};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnMode {
    Async,
    Sync,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Bringup,
    Bringdown,
    InstallFromRepo,
    SummaryPid {
        pid: i32,
    },
    SummaryExe {
        exe_path: String,
    },
    SetProfile {
        profile: String,
        pid: i32,
    },
    Spawn {
        profile: Option<String>,
        mode: Option<SpawnMode>,
        command: Vec<OsString>,
    },
    Touched {
        file: String,
    },
    DebugAction,
}

pub fn parse_cli() -> CliCommand {
    parse_from(std::env::args_os())
}

pub fn parse_from<I, T>(args: I) -> CliCommand
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = command().get_matches_from(args);
    CliCommand::from_matches(&matches)
}

pub fn command() -> ClapCommand {
    ClapCommand::new("htek")
        .about("Heretek endpoint detection and response")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(ClapCommand::new("up").about("Bring up the Heretek daemon"))
        .subcommand(ClapCommand::new("down").about("Bring down the Heretek daemon"))
        .subcommand(
            ClapCommand::new("install-from-repo")
                .about("Install Heretek from the current repository"),
        )
        .subcommand(
            ClapCommand::new("debug-action")
                .about("Run a debug action")
                .hide(true),
        )
        .subcommand(
            ClapCommand::new("summary")
                .about("Query a process summary by PID or executable path")
                .arg(
                    Arg::new("target")
                        .value_name("pid | executable_path")
                        .required(true)
                        .help("PID or executable path to summarize"),
                ),
        )
        .subcommand(
            ClapCommand::new("set-profile")
                .about("Set a process profile")
                .arg(
                    Arg::new("profile")
                        .value_name("profile")
                        .required(true)
                        .help("Profile to assign"),
                )
                .arg(
                    Arg::new("pid")
                        .short('p')
                        .value_name("pid")
                        .required(true)
                        .help("PID to assign the profile to"),
                ),
        )
        .subcommand(
            ClapCommand::new("spawn")
                .about("Spawn a command under a profile")
                .arg(
                    Arg::new("profile")
                        .short('p')
                        .value_name("profile")
                        .help("Profile to assign to the spawned process"),
                )
                .arg(
                    Arg::new("async")
                        .short('a')
                        .action(ArgAction::SetTrue)
                        .conflicts_with("sync")
                        .help("Spawn the command, detach it, and exit"),
                )
                .arg(
                    Arg::new("sync")
                        .short('s')
                        .action(ArgAction::SetTrue)
                        .conflicts_with("async")
                        .help("Spawn the command with stdio attached to htek"),
                )
                .arg(
                    Arg::new("command")
                        .value_name("command-to-run")
                        .value_parser(OsStringValueParser::new())
                        .required(true)
                        .num_args(1..)
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true)
                        .help("Command and arguments to run"),
                ),
        )
        .subcommand(
            ClapCommand::new("touched")
                .about("Show processes that accessed a file")
                .arg(
                    Arg::new("file")
                        .value_name("file")
                        .required(true)
                        .help("File to query"),
                ),
        )
}

impl CliCommand {
    fn from_matches(matches: &ArgMatches) -> Self {
        match matches.subcommand() {
            Some(("up", _)) => Self::Bringup,
            Some(("down", _)) => Self::Bringdown,
            Some(("install-from-repo", _)) => Self::InstallFromRepo,
            Some(("debug-action", _)) => Self::DebugAction,
            Some(("summary", sub_matches)) => {
                let target = sub_matches
                    .get_one::<String>("target")
                    .expect("clap ensures summary target is present");

                Self::summary_from_arg(target)
            }
            Some(("set-profile", sub_matches)) => {
                let profile = sub_matches
                    .get_one::<String>("profile")
                    .expect("clap ensures profile is present")
                    .to_string();
                let pid = sub_matches
                    .get_one::<String>("pid")
                    .expect("clap ensures pid is present")
                    .parse::<i32>()
                    .expect("pid must be an integer");

                Self::SetProfile { profile, pid }
            }
            Some(("spawn", sub_matches)) => {
                let profile = sub_matches.get_one::<String>("profile").cloned();
                let mode = if sub_matches.get_flag("async") {
                    Some(SpawnMode::Async)
                } else if sub_matches.get_flag("sync") {
                    Some(SpawnMode::Sync)
                } else {
                    None
                };
                let command = sub_matches
                    .get_many::<OsString>("command")
                    .expect("clap ensures command is present")
                    .cloned()
                    .collect();

                Self::Spawn {
                    profile,
                    mode,
                    command,
                }
            }
            Some(("touched", sub_matches)) => {
                let file = sub_matches
                    .get_one::<String>("file")
                    .expect("clap ensures file is present")
                    .to_string();

                Self::Touched { file }
            }
            _ => unreachable!("clap ensures a valid subcommand is present"),
        }
    }

    fn summary_from_arg(arg: &str) -> Self {
        match arg.parse::<i32>() {
            Ok(pid) => Self::SummaryPid { pid },
            Err(_) => Self::SummaryExe {
                exe_path: arg.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CliCommand, SpawnMode, parse_from};

    #[test]
    fn parses_install_from_repo() {
        assert_eq!(
            parse_from(["htek", "install-from-repo"]),
            CliCommand::InstallFromRepo
        );
    }

    #[test]
    fn parses_spawn_with_profile() {
        assert_eq!(
            parse_from([
                "htek", "spawn", "-p", "hardened", "-s", "--", "npm", "run", "build"
            ]),
            CliCommand::Spawn {
                profile: Some("hardened".to_string()),
                mode: Some(SpawnMode::Sync),
                command: vec!["npm".into(), "run".into(), "build".into()],
            }
        );
    }

    #[test]
    fn parses_spawn_without_profile() {
        assert_eq!(
            parse_from(["htek", "spawn", "--", "bash", "-lc", "echo hi"]),
            CliCommand::Spawn {
                profile: None,
                mode: None,
                command: vec!["bash".into(), "-lc".into(), "echo hi".into()],
            }
        );
    }

    #[test]
    fn parses_spawn_async() {
        assert_eq!(
            parse_from(["htek", "spawn", "-a", "--", "sleep", "60"]),
            CliCommand::Spawn {
                profile: None,
                mode: Some(SpawnMode::Async),
                command: vec!["sleep".into(), "60".into()],
            }
        );
    }
}
