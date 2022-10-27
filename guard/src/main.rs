use std::collections::HashMap;
use std::process::exit;

use clap::{App, AppFlags, ArgGroup, ArgMatches};
use clap::error::ContextKind::Usage;
use nom::combinator::map;

use rules::errors::Error;

use crate::command::Command;
use crate::commands::{APP_NAME, APP_VERSION};

mod command;
mod commands;
mod migrate;
mod rules;
mod utils;

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

    let usage = app.render_usage();
    let app = app.get_matches();

    match app.subcommand() {
        Some((name, value)) => {
            if let Some(command) = mappings.get(name) {
                match (*command).execute(value) {
                    Err(e) => {
                        println!("Error occurred {}", e);
                        exit(-1);
                    }
                    Ok(code) => exit(code),
                }
            } else {
                println!("{}", &usage);
            }
        }
        None => {
            println!("{}", &usage);
        }
    }
    Ok(())
}
