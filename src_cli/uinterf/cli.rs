use std::ffi::OsString;

use clap::{Arg, ArgMatches, Command as ClapCommand};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Daemon,
    SummaryPid { pid: i32 },
    SummaryExe { exe_path: String },
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
}

impl CliCommand {
    fn from_matches(matches: &ArgMatches) -> Self {
        match matches.subcommand() {
            Some(("daemon", _)) => Self::Daemon,
            Some(("summary", sub_matches)) => {
                let target = sub_matches
                    .get_one::<String>("target")
                    .expect("clap ensures summary target is present");

                Self::summary_from_arg(target)
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
}
