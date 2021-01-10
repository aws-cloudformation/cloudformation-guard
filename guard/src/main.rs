use clap::App;
use std::collections::HashMap;


mod rules;
mod commands;
mod command;

use crate::command::Command;
use rules::errors::Error;

fn main() -> Result<(), Error>{
    let mut app =
        App::new("cfn-guard")
            .version("1.1")
            .about(r#"
             Gaurd Rules provides a simple declerative syntax
             based on Conjuctive Normal Form (fancy way of saying
             it is a logical AND of OR clauses). It evaluates
             incoming structured payload (JSON/YAML) against
             the rules specified."#);

    let mut commands: Vec<Box<dyn Command>> = Vec::with_capacity(2);
    commands.push(Box::new(crate::commands::validate::Validate::new()));

    let mappings = commands.iter()
        .map(|s| (s.name(), s)).fold(
        HashMap::with_capacity(commands.len()),
        |mut map, entry| {
            map.insert(entry.0, entry.1.as_ref());
            map
        }
    );

    for each in &commands {
        app = app.subcommand(each.command());
    }

    let app = app.get_matches();
    match app.subcommand() {
        (name, Some(value)) => {
            if let Some(command) = mappings.get(name) {
                match (*command).execute(value) {
                    Err(e) => println!("Error occured {}", e),
                    Ok(_) => {}
                }
            }
            else {
                println!("{}", app.usage());
            }
        },

        (_, None) => {
            println!("{}", app.usage());
        }
    }
    Ok(())
}

