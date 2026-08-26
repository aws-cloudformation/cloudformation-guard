use crate::commands::validate::file_name_of;
use crate::commands::{Executable, ERROR_STATUS_CODE, PRINT_JSON, PRINT_YAML, SUCCESS_STATUS_CODE};
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use clap::Args;
use colored::Colorize;
use std::fs::File;
use std::path::Path;

const ABOUT: &str = "Prints out the parse tree for the rules defined in the file.";
/// Stands in for the file name when the rules came from stdin, so the parse-error message has
/// something to name. `validate`'s payload path spells the same idea `RULES_STDIN[n]`; this command
/// reads a single stream, so there is no index to carry.
const STDIN_RULES_NAME: &str = "RULES_STDIN";
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

        // Not `?`. A rules file the parser rejects is a mistake in that file, and `?` here carried the
        // error to `main`'s catch-all, which exits -1 -- `INTERNAL_FAILURE` in the table at
        // `guard/tests/utils.rs`. `validate` reports the same file as `ERROR_STATUS_CODE` from its own
        // `Err` arm, so the two subcommands disagreed about whose fault one file was, and a CI step
        // reading the code could not tell a bad ruleset from a broken tool.
        //
        // Reported here rather than left to `main` for the reason `validate` reports it itself: once a
        // command classifies the error, `main`'s "Error occurred" prefix no longer describes what
        // happened. The wording is `validate`'s, because agreeing on the wording is the same fix as
        // agreeing on the code.
        //
        // A missing file still returns `Err` from `File::open` above and so keeps the -1 that
        // `validate`, `test` and `parse-tree` already agree on.
        let rules = match crate::rules::parser::rules_file(span) {
            Ok(rules) => rules,
            Err(e) => {
                // The final component only, which is the name `validate` reports a rules file under
                // (`file_name_of`, shared with it rather than reimplemented). Printing the path as
                // given would put the caller's directory layout in the message, which is both noise
                // and unassertable: the test-side path reducer normalises `.yaml`, `.yml` and `.json`
                // and not `.guard`, so an expected string containing one would only hold for the
                // checkout that produced it.
                let name = match &self.rules {
                    Some(path) => file_name_of(Path::new(path)),
                    None => STDIN_RULES_NAME.to_string(),
                };

                writer.write_err(format!(
                    "Parsing error handling rule file = {}, Error = {e}\n---",
                    name.underline(),
                ))?;

                return Ok(ERROR_STATUS_CODE);
            }
        };

        match self.print_json {
            true => serde_json::to_writer_pretty(writer, &rules)?,
            false => serde_yaml::to_writer(writer, &rules)?,
        }

        Ok(SUCCESS_STATUS_CODE)
    }
}
