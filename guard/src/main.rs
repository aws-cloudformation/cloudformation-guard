use std::cell::RefCell;
use clap::App;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

mod command;
mod commands;
mod migrate;
mod rules;
mod utils;

use command::Command;
use commands::{APP_NAME, APP_VERSION};
use rules::errors::Error;
use std::process::exit;
use std::rc::Rc;
use crate::commands::{MIGRATE, OUTPUT, PARSE_TREE, RULEGEN};
use crate::utils::writer::{WriteBuffer, Writer, WriteBuffer::File as WBFile, WriteBuffer::Stdout};

fn main() -> Result<(), Error> {
    let mut app = App::new(APP_NAME).version(APP_VERSION).about(
        r#"
  Guard is a general-purpose tool that provides a simple declarative syntax to define 
  policy-as-code as rules to validate against any structured hierarchical data (like JSON/YAML).
  Rules are composed of clauses expressed using Conjunctive Normal Form
  (fancy way of saying it is a logical AND of OR clauses). Guard has deep
  integration with CloudFormation templates for evaluation but is a general tool
  that equally works for any JSON- and YAML- data."#,
    );

    let mut commands: Vec<Box<dyn Command>> = Vec::with_capacity(2);
    commands.push(Box::new(crate::commands::parse_tree::ParseTree::new()));
    commands.push(Box::new(crate::commands::test::Test::new()));
    commands.push(Box::new(crate::commands::validate::Validate::new()));
    commands.push(Box::new(crate::commands::rulegen::Rulegen::new()));
    commands.push(Box::new(crate::commands::migrate::Migrate::new()));

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

    let app = app.get_matches();
    match app.subcommand() {
        (name, Some(value)) => {
            if let Some(command) = mappings.get(name) {
                let mut output_writer: Writer =
                    if [PARSE_TREE, MIGRATE, RULEGEN].contains(&command.name()) {
                        let writer: Writer = match app.value_of(OUTPUT.0) {
                            Some(file) => Writer::new(WBFile(File::create(file)?)),
                            None => Writer::new(Stdout(std::io::stdout())),
                        };
                        writer
                    } else {
                        Writer::new(Stdout(std::io::stdout()))
                    };

                match (*command).execute(value, &mut output_writer) {
                    Err(e) => {
                        println!("Error occurred {}", e);
                        exit(-1);
                    }
                    Ok(code) => exit(code),
                }
            } else {
                println!("{}", app.usage());
            }
        }

        (_, None) => {
            println!("{}", app.usage());
        }
    }
    Ok(())
}

