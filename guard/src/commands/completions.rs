use crate::command::Command;
use crate::commands::{APP_NAME, APP_VERSION, COMPLETIONS};
use crate::rules::errors;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use crate::{commands, rules};
use clap::{ArgMatches, Parser, ValueEnum};
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

#[derive(Parser, Debug)]
struct Completions {
    #[arg(
        long,
        short,
        value_name = LOCATION,
        help = "the location where the completions script will be, if no value is present the script will be written to stdout", 
    )]
    location: Option<String>,
    #[arg(
        long,
        short,
        value_name = "shell",
        required = true,
        help = "the shell you are currently running"
    )]
    shell: Shell,
}

const LOCATION: &str = "location";

impl Command for Completions {
    fn name(&self) -> &'static str {
        COMPLETIONS
    }

    fn command(&self) -> clap::Command {
        self.command()
    }

    fn execute(&self, _: &ArgMatches, _: &mut Writer, _: &mut Reader) -> rules::Result<i32> {
        let mut app = clap::Command::new(APP_NAME).version(APP_VERSION);

        let mut commands: Vec<Box<dyn Command>> = vec![
            Box::new(commands::parse_tree::ParseTree::new()),
            Box::new(commands::test::Test::new()),
            Box::new(commands::validate::Validate::new()),
            Box::new(commands::rulegen::Rulegen::new()),
            Box::new(commands::migrate::Migrate::new()),
        ];

        let mappings = commands.iter().map(|s| (s.name(), s)).fold(
            HashMap::with_capacity(commands.len()),
            |mut map, entry| {
                map.insert(entry.0, entry.1.as_ref());
                map
            },
        );

        for each in &commands {
            app = app.subcommand(each.command());
        }

        let mut writer = match &self.location {
            Some(location) => {
                let path = Path::new(&location);
                if !path.exists() || !path.is_dir() {
                    return Err(errors::Error::InvalidCompletionsPath(String::from(
                        "incompatible path",
                    )));
                }

                Box::new(File::create(path.join("cfn-guard.sh"))?) as Box<dyn Write>
            }
            None => Box::new(std::io::stdout()) as Box<dyn Write>,
        };

        match self.shell {
            Shell::Bash => clap_complete::generate(
                clap_complete::shells::Bash,
                &mut app,
                "cfn-guard",
                &mut writer,
            ),
            Shell::Zsh => clap_complete::generate(
                clap_complete::shells::Zsh,
                &mut app,
                "cfn-guard",
                &mut writer,
            ),
            Shell::Fish => clap_complete::generate(
                clap_complete::shells::Fish,
                &mut app,
                "cfn-guard",
                &mut writer,
            ),
            Shell::PowerShell => clap_complete::generate(
                clap_complete::shells::PowerShell,
                &mut app,
                "cfn-guard",
                &mut writer,
            ),
        }

        Ok(0)
    }
}
