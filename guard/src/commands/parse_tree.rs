use std::fs::File;

use clap::{Arg, ArgMatches};

use crate::command::Command;
use crate::commands::{OUTPUT, PARSE_TREE, PRINT_JSON, PRINT_YAML, RULES};
use crate::rules::Result;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ParseTree {}

impl ParseTree {
    pub(crate) fn new() -> Self {
        ParseTree {}
    }
}

impl Command for ParseTree {
    fn name(&self) -> &'static str {
        PARSE_TREE
    }


    fn command(&self) -> clap::Command {
        clap::Command::new(PARSE_TREE)
            .about(r#"Prints out the parse tree for the rules defined in the file.
"#)
            .arg(Arg::new(RULES.0).long(RULES.0).short(RULES.1).help("Provide a rules file").required(false))
            .arg(Arg::new(OUTPUT.0).long(OUTPUT.0).short(OUTPUT.1).help("Write to output file").required(false))
            .arg(Arg::new(PRINT_JSON.0).long(PRINT_JSON.0).short(PRINT_JSON.1).required(false)
                .help("Print output in JSON format"))
            .arg(Arg::new(PRINT_YAML.0).long(PRINT_YAML.0).short(PRINT_YAML.1).required(false)
                .help("Print output in YAML format"))
    }

    fn execute(&self, app: &ArgMatches) -> Result<i32> {
        let mut file: Box<dyn std::io::Read> = match app.get_one::<String>(RULES.0) {
            Some(file) => Box::new(std::io::BufReader::new(File::open(file)?)),
            None => {
                Box::new(std::io::stdin())
            }
        };

        let out = match app.get_one::<String>(OUTPUT.0) {
            Some(file) => Box::new(File::create(file)?) as Box<dyn std::io::Write>,
            None => Box::new(std::io::stdout()) as Box<dyn std::io::Write>
        };

        let yaml = !app.contains_id(PRINT_JSON.0);
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let span = crate::rules::parser::Span::new_extra(&content, "");
        match crate::rules::parser::rules_file(span) {
            Err(e) => {
                println!("Parsing error handling rule, Error = {}", e);
                return Err(e);
            }

            Ok(rules) => {
                if yaml {
                    serde_yaml::to_writer(out, &rules)?;
                } else {
                    serde_json::to_writer(out, &rules)?;
                }
            }
        }

        Ok(0_i32)
    }
}
