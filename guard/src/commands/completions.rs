use crate::command::Command;
use crate::commands::{APP_NAME, APP_VERSION, COMPLETIONS};
use crate::rules::errors;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use crate::{commands, rules};
use clap::{Arg, ArgAction, ArgMatches, Parser, ValueEnum};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Copy, Clone, ValueEnum, Debug)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}
impl From<String> for Shell {
    fn from(value: String) -> Self {
        match value.as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            "powershell" => Shell::PowerShell,
            _ => unimplemented!(),
        }
    }
}

#[derive(Default, Debug)]
pub struct Completions {}

const SHELL_TYPES: [&str; 4] = ["bash", "zsh", "fish", "powershell"];
const LOCATION: (&str, char) = ("location", 'l');
const SHELL: (&str, char) = ("shell", 's');

impl Command for Completions {
    fn name(&self) -> &'static str {
        COMPLETIONS
    }

    fn command(&self) -> clap::Command {
        clap::Command::new(COMPLETIONS)
            .arg(
                Arg::new(LOCATION.0)
                    .long(LOCATION.0)
                    .short(LOCATION.1)
                    .required(false)
                    .action(ArgAction::Set),
            )
            .arg(
                Arg::new(SHELL.0)
                    .long(SHELL.0)
                    .short(SHELL.1)
                    .required(true)
                    .value_parser(SHELL_TYPES)
                    .action(ArgAction::Set),
            )
    }

    fn execute(&self, args: &ArgMatches, _: &mut Writer, _: &mut Reader) -> rules::Result<i32> {
        let mut app = clap::Command::new(APP_NAME).version(APP_VERSION);

        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(commands::parse_tree::ParseTree::new()),
            Box::new(commands::test::Test::new()),
            Box::new(commands::validate::Validate::new()),
            Box::new(commands::rulegen::Rulegen::new()),
            Box::new(commands::migrate::Migrate::new()),
        ];

        for each in &commands {
            app = app.subcommand(each.command());
        }

        let location = args.get_one::<String>(LOCATION.0);
        match args.get_one::<String>("shell").unwrap().as_str() {
            "bash" => {
                let mut writer = get_writer(location, "bash")?;
                clap_complete::generate(
                    clap_complete::shells::Bash,
                    &mut app,
                    "cfn-guard",
                    &mut writer,
                )
            }
            "zsh" => {
                let mut writer = get_writer(location, "zsh")?;
                clap_complete::generate(
                    clap_complete::shells::Zsh,
                    &mut app,
                    "cfn-guard",
                    &mut writer,
                )
            }
            "fish" => {
                let mut writer = get_writer(location, "fish")?;
                clap_complete::generate(
                    clap_complete::shells::Fish,
                    &mut app,
                    "cfn-guard",
                    &mut writer,
                )
            }
            "powershell" => {
                let mut writer = get_writer(location, "ps1")?;
                clap_complete::generate(
                    clap_complete::shells::PowerShell,
                    &mut app,
                    "cfn-guard",
                    &mut writer,
                )
            }
            _ => unreachable!(),
        }

        Ok(0)
    }
}

fn get_writer(location: Option<&String>, ext: &str) -> rules::Result<Box<dyn Write>> {
    let mut writer = match location {
        Some(location) => {
            let path = Path::new(&location);
            if !path.exists() || !path.is_dir() {
                return Err(errors::Error::InvalidCompletionsPath(String::from(
                    "incompatible path",
                )));
            }

            Box::new(File::create(path.join(format!("cfn-guard.{}", ext)))?) as Box<dyn Write>
        }
        None => Box::new(std::io::stdout()) as Box<dyn Write>,
    };

    Ok(writer)
}
