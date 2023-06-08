use crate::command::Command;
use crate::commands::{APP_NAME, APP_VERSION, COMPLETIONS};
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use crate::{rules, utils};
use clap::{Arg, ArgAction, ArgMatches};

#[derive(Copy, Clone, Debug)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl From<String> for Shell {
    fn from(value: String) -> Self {
        match value.as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            _ => unimplemented!(),
        }
    }
}

#[derive(Default, Debug)]
pub struct Completions {}

const SHELL_TYPES: [&str; 3] = ["bash", "zsh", "fish"];
const SHELL: (&str, char) = ("shell", 's');

impl Command for Completions {
    fn name(&self) -> &'static str {
        COMPLETIONS
    }

    fn command(&self) -> clap::Command {
        clap::Command::new(COMPLETIONS).arg(
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

        let commands = utils::get_guard_commands();

        for each in &commands {
            app = app.subcommand(each.command());
        }

        match args.get_one::<String>(SHELL.0).unwrap().as_str() {
            "bash" => generate(clap_complete::shells::Bash, &mut app),
            "zsh" => generate(clap_complete::shells::Zsh, &mut app),
            "fish" => generate(clap_complete::shells::Fish, &mut app),
            _ => unreachable!(),
        }

        Ok(0)
    }
}

fn generate<G: clap_complete::Generator>(gen: G, cmd: &mut clap::Command) {
    clap_complete::generate(gen, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
}
