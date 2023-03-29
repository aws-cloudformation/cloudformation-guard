use clap::ArgMatches;
use std::collections::HashMap;
use std::fs::File;
mod command;
mod commands;
mod migrate;
mod rules;
mod utils;

use crate::commands::{MIGRATE, OUTPUT, PARSE_TREE, RULEGEN};
use crate::utils::reader::{ReadBuffer, Reader};
use crate::utils::writer::WriteBuffer::Stderr;
use crate::utils::writer::{WriteBuffer::File as WBFile, WriteBuffer::Stdout, Writer};
use command::Command;
use commands::{APP_NAME, APP_VERSION};
use rules::errors::Error;
use std::io::Write;
use std::process::exit;
use std::rc::Rc;

fn main() -> Result<(), Error> {
    let mut app = clap::Command::new(APP_NAME)
        .version(APP_VERSION)
        .about(
            r#"
  Guard is a general-purpose tool that provides a simple declarative syntax to define 
  policy-as-code as rules to validate against any structured hierarchical data (like JSON/YAML).
  Rules are composed of clauses expressed using Conjunctive Normal Form
  (fancy way of saying it is a logical AND of OR clauses). Guard has deep
  integration with CloudFormation templates for evaluation but is a general tool
  that equally works for any JSON- and YAML- data."#,
        )
        .arg_required_else_help(true);

    let mut commands: Vec<Box<dyn Command>> = Vec::with_capacity(2);
    commands.push(Box::new(commands::parse_tree::ParseTree::new()));
    commands.push(Box::new(commands::test::Test::new()));
    commands.push(Box::new(commands::validate::Validate::new()));
    commands.push(Box::new(commands::rulegen::Rulegen::new()));
    commands.push(Box::new(commands::migrate::Migrate::new()));

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

    let help = app.render_usage();
    let app = app.get_matches();

    match app.subcommand() {
        Some((name, value)) => {
            if let Some(command) = mappings.get(name) {
                let mut output_writer: Writer = if [PARSE_TREE, MIGRATE, RULEGEN]
                    .contains(&command.name())
                {
                    let writer: Writer = match value.get_one::<String>(OUTPUT.0) {
                        Some(file) => {
                            Writer::new(WBFile(File::create(file)?), Stderr(std::io::stderr()))
                        }
                        None => Writer::new(Stdout(std::io::stdout()), Stderr(std::io::stderr())),
                    };
                    writer
                } else {
                    Writer::new(Stdout(std::io::stdout()), Stderr(std::io::stderr()))
                };

                match (*command).execute(
                    value,
                    &mut output_writer,
                    &mut Reader::new(ReadBuffer::Stdin(std::io::stdin())),
                ) {
                    Err(e) => {
                        output_writer
                            .write_err(format!("Error occurred {e}"))
                            .expect("failed to write to stderr");

                        exit(-1);
                    }
                    Ok(code) => exit(code),
                }
            } else {
                println!("{}", help);
            }
        }
        None => {
            println!("{}", help);
        }
    }

    Ok(())
}
