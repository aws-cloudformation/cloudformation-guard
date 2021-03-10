use clap::{App, Arg, ArgMatches};
use colored::*;

use crate::command::Command;
use crate::commands::files::{get_files, regular_ordering, iterate_over};
use crate::rules::Result;
use crate::migrate::parser::parse_rules_file;
use std::fs::{File, OpenOptions};
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;


#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Migrate {}

impl Migrate {
    pub(crate) fn new() -> Self {
        Migrate{}
    }
}

impl Command for Migrate {
    fn name(&self) -> &'static str {
        "migrate"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("migrate")
            .about(r#"
            Migrates 1.0 rulesets to 2.0 compatible rulesets.
        "#)
            .arg(Arg::with_name("rules").long("rules").short("r").takes_value(true).help("provide a rules file").required(true))
            .arg(Arg::with_name("output").long("output").short("o").takes_value(true).help("write migrated rules to output file").required(false))
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<()> {
        let file = app.value_of("rules").unwrap();

        let mut out= match app.value_of("output") {
            Some(file) => Box::new(File::create(file)?) as Box<dyn std::io::Write>,
            None => Box::new(std::io::stdout()) as Box<dyn std::io::Write>
        };

        let mut migrated_rules = String::new();
        let files = get_files(file, regular_ordering)?;
        for each_file_content in iterate_over(&files, |content, file| Ok((content, file.to_str().unwrap_or("").to_string()))) {
            match each_file_content {
                Err(e) => println!("Unable read content from file {}", e),
                Ok((file_content, rule_file_name)) => {
                    match parse_rules_file(&file_content, &rule_file_name) {
                        Err(e) => {
                            println!("Parsing error handling rule file = {}, Error = {}",
                                     rule_file_name.underline(), e);
                            continue;
                        },

                        Ok(rules) => {
                            for rule in rules {
                                writeln!(&mut migrated_rules, "{}", rule);
                            }
                            continue;
                        }
                    }
                }
            }
        }
        // validate rules written
        let span = crate::rules::parser::Span::new_extra(&migrated_rules, "");
        match crate::rules::parser::rules_file(span) {
            Ok(_rules) => {
                write!(out,"{}", migrated_rules);
                Ok(())
            },
            Err(e) => {
                println!("Parsing error with migrated rules file, Error = {}", e);
                Err(e)
            },

        }
    }
}
