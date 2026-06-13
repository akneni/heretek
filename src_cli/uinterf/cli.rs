use std::{ffi::OsString, path::PathBuf};

use clap::{Arg, ArgMatches, Command as ClapCommand};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Daemon,
    Bringup,
    Bringdown,
    SummaryPid { pid: i32 },
    SummaryExe { exe_path: String },
    SetProfile { profile: String, pid: i32 },
    Touched { file: String },
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
        .subcommand(ClapCommand::new("daemon").about("Run the Heretek daemon"))
        .subcommand(ClapCommand::new("bringup").about("Bring up the Heretek daemon"))
        .subcommand(ClapCommand::new("bringdown").about("Bring down the Heretek daemon"))
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
            Some(("daemon", _)) => Self::Daemon,
            Some(("bringup", _)) => Self::Bringup,
            Some(("bringdown", _)) => Self::Bringdown,
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
    use super::*;

    #[test]
    fn parses_daemon_command() {
        let cli = parse_from(["htek", "daemon"]);

        assert_eq!(cli, CliCommand::Daemon);
    }

    #[test]
    fn parses_bringup_command() {
        let cli = parse_from(["htek", "bringup"]);

        assert_eq!(cli, CliCommand::Bringup);
    }

    #[test]
    fn parses_bringdown_command() {
        let cli = parse_from(["htek", "bringdown"]);

        assert_eq!(cli, CliCommand::Bringdown);
    }

    #[test]
    fn parses_summary_pid_command() {
        let cli = parse_from(["htek", "summary", "1234"]);

        assert_eq!(cli, CliCommand::SummaryPid { pid: 1234 });
    }

    #[test]
    fn parses_summary_executable_path_command() {
        let cli = parse_from(["htek", "summary", "/usr/bin/bash"]);

        assert_eq!(
            cli,
            CliCommand::SummaryExe {
                exe_path: "/usr/bin/bash".to_string()
            }
        );
    }

    #[test]
    fn parses_set_profile_command() {
        let cli = parse_from(["htek", "set-profile", "hardened", "-p", "1234"]);

        assert_eq!(
            cli,
            CliCommand::SetProfile {
                profile: "hardened".to_string(),
                pid: 1234,
            }
        );
    }

    #[test]
    fn parses_touched_command() {
        let cli = parse_from(["htek", "touched", "/tmp/example"]);

        assert_eq!(
            cli,
            CliCommand::Touched {
                file: "/tmp/example".to_string(),
            }
        );
    }

    #[test]
    fn parses_hidden_debug_action_command() {
        let cli = parse_from(["htek", "debug-action"]);

        assert_eq!(cli, CliCommand::DebugAction);
    }

    #[test]
    fn hides_debug_action_from_help() {
        let mut help = Vec::new();
        command().write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(!help.contains("debug-action"));
    }
}
