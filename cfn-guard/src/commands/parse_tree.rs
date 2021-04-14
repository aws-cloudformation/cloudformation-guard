use std::fs::{File};
use clap::{App, Arg, ArgMatches};
use crate::command::Command;
use crate::rules:: Result;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ParseTree {}

impl ParseTree {
    pub(crate) fn new() -> Self {
        ParseTree{}
    }
}

impl Command for ParseTree {
    fn name(&self) -> &'static str {
        "parse-tree"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("parse-tree")
            .about(r#"print out the parse tree for the rules defined in the file

"#)
            .arg(Arg::with_name("rules").long("rules").short("r").takes_value(true).help("provide a rules file").required(false))
            .arg(Arg::with_name("output").long("output").short("o").takes_value(true).help("write to output file").required(false))
            .arg(Arg::with_name("print-json").long("print-json").short("j").required(false)
                .help("Print output in json format"))
            .arg(Arg::with_name("print-yaml").long("print-yaml").short("y").required(false)
                .help("Print output in json format"))
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<i32> {

        let mut file: Box<dyn std::io::Read> = match app.value_of("rules") {
            Some(file) => Box::new(std::io::BufReader::new(File::open(file)?)),
            None => {
                Box::new(std::io::stdin())
            }
        };

        let out= match app.value_of("output") {
                Some(file) => Box::new(File::create(file)?) as Box<dyn std::io::Write>,
            None => Box::new(std::io::stdout()) as Box<dyn std::io::Write>
        };

        let yaml = !app.is_present("print-json");
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let span = crate::rules::parser::Span::new_extra(&content, "");
        match crate::rules::parser::rules_file(span) {
            Err(e) => {
                println!("Parsing error handling rule, Error = {}", e);
                return Err(e);
            },

            Ok(rules) => {
                if yaml {
                    serde_yaml::to_writer(out, &rules)?;
                }
                else {
                    serde_json::to_writer(out, &rules)?;
                }
            }
        }

        Ok(0 as i32)
    }
}
