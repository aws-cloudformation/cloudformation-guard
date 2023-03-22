use crate::command::Command;
use crate::commands::{OUTPUT, PARSE_TREE, PRINT_JSON, PRINT_JSON_DEPRECATED, PRINT_YAML, RULES};
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use clap::{Arg, ArgAction, ArgMatches};
use std::fs::File;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParseTree {}

#[allow(clippy::new_without_default)]
impl ParseTree {
    pub fn new() -> Self {
        ParseTree {}
    }
}

impl Command for ParseTree {
    fn name(&self) -> &'static str {
        PARSE_TREE
    }

    fn command(&self) -> clap::Command {
        clap::Command::new(PARSE_TREE)
            .about("Prints out the parse tree for the rules defined in the file.")
            .arg(
                Arg::new(RULES.0)
                    .long(RULES.0)
                    .short(RULES.1)
                    .help("Provide a rules file")
                    .action(ArgAction::Set)
                    .required(false),
            )
            .arg(
                Arg::new(OUTPUT.0)
                    .long(OUTPUT.0)
                    .short(OUTPUT.1)
                    .help("Write to output file")
                    .action(ArgAction::Set)
                    .required(false),
            )
            .arg(
                Arg::new(PRINT_JSON.0)
                    .long(PRINT_JSON.0)
                    .short(PRINT_JSON.1)
                    .short_alias(PRINT_JSON_DEPRECATED)
                    .action(ArgAction::SetTrue)
                    .help("Print output in JSON format"),
            )
            .arg(
                Arg::new(PRINT_YAML.0)
                    .long(PRINT_YAML.0)
                    .short(PRINT_YAML.1)
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("Print output in YAML format"),
            )
            .arg_required_else_help(true)
    }

    fn execute(&self, app: &ArgMatches, writer: &mut Writer, reader: &mut Reader) -> Result<i32> {
        let mut file: Box<dyn std::io::Read> = match app.get_one::<String>(RULES.0) {
            Some(file) => Box::new(std::io::BufReader::new(File::open(file)?)),
            None => Box::new(reader),
        };

        let yaml = !app.get_flag(PRINT_JSON.0);
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let span = crate::rules::parser::Span::new_extra(&content, "");
        match crate::rules::parser::rules_file(span) {
            Err(e) => {
                writer.write_err(format!("Parsing error handling rule, Error = {e}"))?;
                return Err(e);
            }

            Ok(rules) => {
                if yaml {
                    serde_yaml::to_writer(writer, &rules)?;
                } else {
                    serde_json::to_writer(writer, &rules)?;
                }
            }
        }

        Ok(0_i32)
    }
}
