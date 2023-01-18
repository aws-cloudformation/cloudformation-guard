use crate::command::Command;
use crate::commands::{OUTPUT, PARSE_TREE, PRINT_JSON, PRINT_YAML, RULES, wrapper};
use crate::rules::Result;
use clap::{App, Arg, ArgMatches};
use std::fs::File;
use std::io::Write;
use crate::commands::wrapper::Writer;

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

    fn command(&self) -> App<'static, 'static> {
        App::new(PARSE_TREE)
            .about(
                r#"Prints out the parse tree for the rules defined in the file.
"#,
            )
            .arg(
                Arg::with_name(RULES.0)
                    .long(RULES.0)
                    .short(RULES.1)
                    .takes_value(true)
                    .help("Provide a rules file")
                    .required(false),
            )
            .arg(
                Arg::with_name(OUTPUT.0)
                    .long(OUTPUT.0)
                    .short(OUTPUT.1)
                    .takes_value(true)
                    .help("Write to output file")
                    .required(false),
            )
            .arg(
                Arg::with_name(PRINT_JSON.0)
                    .long(PRINT_JSON.0)
                    .short(PRINT_JSON.1)
                    .required(false)
                    .help("Print output in JSON format"),
            )
            .arg(
                Arg::with_name(PRINT_YAML.0)
                    .long(PRINT_YAML.0)
                    .short(PRINT_YAML.1)
                    .required(false)
                    .help("Print output in YAML format"),
            )
    }

    fn execute(&self, app: &ArgMatches<'_>, writer: &mut Writer) -> Result<i32> {
        let mut file: Box<dyn std::io::Read> = match app.value_of(RULES.0) {
            Some(file) => Box::new(std::io::BufReader::new(File::open(file)?)),
            None => Box::new(std::io::stdin()),
        };

        let out = match app.value_of(OUTPUT.0) {
            Some(file) => Box::new(File::create(file)?) as Box<dyn std::io::Write>,
            None => Box::new(std::io::stdout()) as Box<dyn std::io::Write>,
        };

        let yaml = !app.is_present(PRINT_JSON.0);
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

        Ok(0 as i32)
    }
}
