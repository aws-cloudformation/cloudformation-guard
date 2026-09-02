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
    // `name=` as well as `long=`, on both this flag and `print_yaml` below. clap derives an argument's
    // *id* from the field name unless `name=` overrides it, so these two ids were `print_json` and
    // `print_yaml` while `PRINT_JSON.0` and `PRINT_YAML.0` are the hyphenated spellings a caller types.
    // `conflicts_with` takes an id, so naming the long flag there is a conflict clap never applies and
    // never reports -- it simply does not fire, in exactly the way the empty `ArgGroup` in `test.rs`
    // did not fire. Setting `name=` makes the constants the ids, so there is one spelling of each flag
    // rather than two that differ by a hyphen. Neither id reaches `--help`, because a boolean flag has
    // no value placeholder to name.
    #[arg(name=PRINT_JSON.0, short=PRINT_JSON.1, long=PRINT_JSON.0, help=PRINT_JSON_HELP,
          conflicts_with=PRINT_YAML.0)]
    pub(crate) print_json: bool,
    // print output in yaml, which is also what this command does when neither flag is given
    //
    // Deliberately `//` and not `///`: clap's derive turns a doc comment into the flag's own
    // `long_about`, so a rationale written here is printed to anyone running `--help` and switches the
    // whole command's help to the expanded layout.
    //
    // This comment used to say "default true", and clap's default for a `bool` flag is `false`. It was
    // describing YAML being the fall-through of `match self.print_json`, and that mismatch is why
    // nobody noticed the field was read nowhere: `--print-yaml` could not change any output, for any
    // input. `-p -y` -- two contradictory format requests -- resolved silently to JSON, and `-y` alone
    // was indistinguishable from passing nothing.
    //
    // `conflicts_with` on `print_json` is what makes the contradiction an error instead of a coin
    // toss, and `ParseTree::output_format` is what makes this field decide something. YAML stays the
    // format when neither flag is given, so `parse-tree --rules x` is unchanged -- this repository's
    // own CI invokes exactly that.
    #[arg(name=PRINT_YAML.0, short=PRINT_YAML.1, long=PRINT_YAML.0, help=PRINT_YAML_HELP)]
    pub(crate) print_yaml: bool,
}

/// The format `parse-tree` writes, which is JSON only when asked for it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ParseTreeFormat {
    Json,
    Yaml,
}

impl ParseTree {
    /// Which format to write, and an error for the one combination that names two.
    ///
    /// Reached from `execute`, so the library path gets the same answer as the CLI. clap rejects
    /// `-p -y` first for a CLI caller, but `ParseTreeBuilder` sets the two fields independently and
    /// validates nothing, so without this check a library caller could still ask for both and be
    /// given JSON without being told.
    fn output_format(&self) -> Result<ParseTreeFormat> {
        match (self.print_json, self.print_yaml) {
            (true, true) => Err(crate::rules::errors::Error::IllegalArguments(String::from(
                "Cannot provide both --print-json and --print-yaml; they name different formats",
            ))),
            (true, false) => Ok(ParseTreeFormat::Json),
            (false, true) | (false, false) => Ok(ParseTreeFormat::Yaml),
        }
    }
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
            Some(path) => {
                // The path is tested before it is opened, because a directory is not openable
                // everywhere. On Unix `File::open` on a directory succeeds and the failure surfaces
                // later, in `read_to_string`, as EISDIR. On Windows it does not open at all:
                // `CreateFileW` requires `FILE_FLAG_BACKUP_SEMANTICS` to return a handle to a
                // directory and `File::open` does not pass it, so the `?` on the open carried an I/O
                // error to `main` as -1 and this check was never reached. A check made through the
                // open handle can only run on the platform where the open succeeds.
                //
                // `fs::metadata` answers on both: its Windows implementation opens with
                // `FILE_FLAG_BACKUP_SEMANTICS` precisely so a directory can be stat'ed, and falls
                // back to `FindFirstFileW` if even that is refused.
                //
                // Either way the caller was told an I/O error naming neither the path nor the flag,
                // under the code this command otherwise reserves for cfn-guard itself failing.
                //
                // `ERROR_STATUS_CODE` for the same reason the parse error below takes it: a rules
                // path that cannot be used as a rules file is a mistake in what the caller named, and
                // this command's vocabulary for that is 5. `test` answers the identical mistake with
                // its own 1 and `validate` walks the directory, which is its documented behaviour --
                // three answers, each in the subcommand's own documented codes, exactly as the three
                // already differ on a rules file the parser rejects.
                //
                // A missing path still keeps -1, now through the `?` on `fs::metadata` rather than on
                // the open: a path whose final component does not exist is `ENOENT` on Unix and
                // `ERROR_FILE_NOT_FOUND` on Windows from either call, so the code and the message are
                // the ones `validate`, `test` and `parse-tree` already agree on.
                if !std::fs::metadata(path)?.is_file() {
                    writer.write_err(format!(
                        "Parsing error handling rule file = {}, Error = a directory is not a rules file\n---",
                        file_name_of(Path::new(path)).underline(),
                    ))?;

                    return Ok(ERROR_STATUS_CODE);
                }

                Box::new(std::io::BufReader::new(File::open(path)?))
            }
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

        match self.output_format()? {
            ParseTreeFormat::Json => serde_json::to_writer_pretty(writer, &rules)?,
            ParseTreeFormat::Yaml => serde_yaml::to_writer(writer, &rules)?,
        }

        Ok(SUCCESS_STATUS_CODE)
    }
}
