use std::ffi::OsString;

use clap::{Arg, ArgMatches, Command as ClapCommand};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
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
        .subcommand(ClapCommand::new("up").about("Bring up the Heretek daemon"))
        .subcommand(ClapCommand::new("down").about("Bring down the Heretek daemon"))
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
            Some(("up", _)) => Self::Bringup,
            Some(("down", _)) => Self::Bringdown,
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
