use crate::commands::{Executable, PRINT_JSON, PRINT_YAML, SUCCESS_STATUS_CODE};
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use clap::Args;
use std::fs::File;

const ABOUT: &str = "Prints out the parse tree for the rules defined in the file.";
const OUTPUT_HELP: &str = "Write to output file";
const PRINT_JSON_HELP: &str = "Print output in JSON format. Use -p as the short flag";
const PRINT_YAML_HELP: &str = "Print output in YAML format";
const RULES_HELP: &str = "Provide a rules file";

#[derive(Debug, Clone, Eq, PartialEq, Args)]
#[clap(about=ABOUT)]
#[clap(arg_required_else_help = true)]
/// .
/// The ParseTree command prints out the parse tree for a given rule file
pub struct ParseTree {
    // the path to a rules file that a data file will have access to
    // if set to false, will attempt to parse rules from stdin
    // default None
    #[arg(short, long, help=RULES_HELP)]
    pub(crate) rules: Option<String>,
    #[arg(short, long, help=OUTPUT_HELP)]
    // the path to a file a user wants to print the output to
    // default None
    pub(crate) output: Option<String>,
    // print output in json
    // default false
    #[arg(short=PRINT_JSON.1, long=PRINT_JSON.0, help=PRINT_JSON_HELP)]
    pub(crate) print_json: bool,
    // print output in yaml
    // default true
    #[arg(short=PRINT_YAML.1, long=PRINT_YAML.0, help=PRINT_YAML_HELP)]
    pub(crate) print_yaml: bool,
}

impl Executable for ParseTree {
    /// .
    /// prints the parse tree for a given rule file
    ///
    /// This function will return an error if
    /// - any of the specified paths do not exist
    /// - parse errors occur in the rule file
    fn execute(&self, writer: &mut Writer, reader: &mut Reader) -> Result<i32> {
        let mut file: Box<dyn std::io::Read> = match &self.rules {
            Some(file) => Box::new(std::io::BufReader::new(File::open(file)?)),
            None => Box::new(reader),
        };

        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let span = crate::rules::parser::Span::new_extra(&content, "");

        let rules = crate::rules::parser::rules_file(span)?;

        match self.print_json {
            true => serde_json::to_writer_pretty(writer, &rules)?,
            false => serde_yaml::to_writer(writer, &rules)?,
        }

        Ok(SUCCESS_STATUS_CODE)
    }
}
