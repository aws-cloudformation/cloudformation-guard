use crate::commands::reporters::test::generic::GenericReporter;
use crate::commands::reporters::test::structured::{
    ContextAwareRule, Err, StructuredTestReporter, TestResult,
};
use crate::commands::reporters::test::{
    no_rules_declared_message, test_file_parse_error, unmatched_test_file_message,
    write_diagnostics, Notices, StderrLineKind,
};
use crate::commands::reporters::JunitReport;
use crate::commands::{
    Executable, SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE,
};
use clap::builder::TypedValueParser;
use clap::Args;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::DirEntry;

use validate::validate_path;

use crate::commands::files::{
    alphabetical, get_files_with_filter, iterate_over, last_modified, read_file_content,
    regular_ordering,
};
use crate::commands::validate::{OutputFormatType, OUTPUT_FORMAT_HELP};
use crate::commands::{
    validate, ALPHABETICAL, DIRECTORY, DIRECTORY_ONLY, LAST_MODIFIED, RULES_AND_TEST_FILE,
    RULES_FILE, TEST_DATA,
};
use crate::rules::errors::Error;
use crate::rules::path_value::{KeyCollisions, Location, PathAwareValue};
use crate::rules::values::{LoadedDocument, MarkedValue};
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;

const ABOUT: &str = r#"Built in unit testing capability to validate a Guard rules file against
unit tests specified in YAML format to determine each individual rule's success
or failure testing.
"#;
const RULES_HELP: &str = "Provide a rules file";
const TEST_DATA_HELP: &str = "Provide a file or dir for data files in JSON or YAML";
const DIRECTORY_HELP: &str = "Provide the root directory for rules";
const ALPHABETICAL_HELP: &str = "Sort alphabetically inside a directory";
const LAST_MODIFIED_HELP: &str = "Sort by last modified times within a directory";
const VERBOSE_HELP: &str = "Verbose logging";
const SINGLE_LINE_SUMMARY: &str = "single-line-summary";
/// The output formats `test` has a reporter for. `sarif` is deliberately absent; see `output_format`.
const SUPPORTED_OUTPUT_FORMATS: [&str; 4] = [SINGLE_LINE_SUMMARY, "json", "yaml", "junit"];

#[derive(Debug, Clone, Eq, PartialEq, Args)]
#[clap(about=ABOUT)]
// `.args([..])` is what makes this group enforce anything. Without it the group had no members, and
// a clap `ArgGroup` with no members can never be "present", so neither its `requires_all` nor its
// `conflicts_with` ever fired -- the `DIRECTORY_ONLY` group three lines below has always had its
// `.args`, which is why only this one was inert. Two defects followed:
//
// - `test -r rules.guard` with no `--test-data` satisfied the parser and then panicked on
//   `self.test_data.as_ref().unwrap()`. `arg_required_else_help` hid it, because it only covers the
//   zero-argument invocation.
// - `test -d dir -r rules.guard` was accepted and `--dir` won, silently: `execute` reads
//   `self.directory` first. The doc comments on all three fields claimed the conflict existed.
//
// `.multiple(true)` is required and is not decoration: a clap group is single-use by default, so
// naming both arguments as members without it would reject `-r x -t y` -- the one combination the
// group exists to require.
#[clap(
    group=clap::ArgGroup::new(RULES_AND_TEST_FILE)
    .args([RULES_FILE.0, TEST_DATA.0])
    .multiple(true)
    .requires_all([RULES_FILE.0, TEST_DATA.0])
    .conflicts_with(DIRECTORY_ONLY))
]
#[clap(
    group=clap::ArgGroup::new(DIRECTORY_ONLY).args([DIRECTORY.0])
    .requires_all([DIRECTORY.0])
    .conflicts_with(RULES_AND_TEST_FILE))
]
#[clap(arg_required_else_help = true)]
/// .
/// The test command evaluates rules against data files to determine success or failure based on
/// pre-defined expected outcomes
pub struct Test {
    /// the path to a rules file that a data file will have access to
    /// default None
    /// conflicts with directory attribute
    #[arg(name="rules-file", short, long, help=RULES_HELP)]
    pub(crate) rules: Option<String>,
    /// the path to the test-data file
    /// default None
    /// conflicts with directory attribute
    #[arg(name="test-data", short, long, help=TEST_DATA_HELP)]
    pub(crate) test_data: Option<String>,
    /// the path to the directory that includes rule files, and a subdirectory labeled tests that
    /// includes test-data files
    /// default None
    /// conflicts with rules, and test_data attributes
    #[arg(name=DIRECTORY.0, short, long=DIRECTORY.0, help=DIRECTORY_HELP)]
    pub(crate) directory: Option<String>,
    /// Sort alphabetically inside a directory
    /// default false
    /// conflicts with last_modified attribute
    #[arg(short, long, help=ALPHABETICAL_HELP, conflicts_with=LAST_MODIFIED.0)]
    pub(crate) alphabetical: bool,
    /// Sort by last modified times within a directory
    /// default false
    /// conflicts with last_modified attribute
    #[arg(name="last-modified", short=LAST_MODIFIED.1, long=LAST_MODIFIED.0, help=LAST_MODIFIED_HELP, conflicts_with=ALPHABETICAL.0)]
    pub(crate) last_modified: bool,
    /// Output verbose logging, conflicts with output_format when not using single-line-summary
    /// when set to true
    /// default is false
    #[arg(short, long, help=VERBOSE_HELP)]
    pub(crate) verbose: bool,
    /// Specify the format in which the output should be displayed
    /// default is single-line-summary
    /// if junit, json or yaml are chosen, will conflict with verbose logging if set to true
    //
    // The accepted values are listed rather than taken from `OutputFormatType`'s `ValueEnum`, so that
    // `sarif` -- which this command has no reporter for and rejects at `execute` -- stops appearing in
    // `--help` as a possible value. It was advertised there while being the one value that could never
    // produce output.
    //
    // `//` and not `///` on purpose: clap's derive prints a doc comment as the flag's `long_about`, so
    // a rationale written with `///` lands in `--help` and expands the whole command's help layout.
    #[arg(short, long, help=OUTPUT_FORMAT_HELP, default_value=SINGLE_LINE_SUMMARY,
          value_parser=clap::builder::PossibleValuesParser::new(SUPPORTED_OUTPUT_FORMATS)
              .map(|value| OutputFormatType::from(value.as_str())))]
    pub(crate) output_format: OutputFormatType,
}

#[derive(Debug)]
pub(crate) struct GuardFile {
    prefix: String,
    file: DirEntry,
    test_files: Vec<DirEntry>,
}

impl GuardFile {
    fn get_test_files(&self) -> Vec<PathBuf> {
        self.test_files
            .iter()
            .map(|de| de.path().to_path_buf())
            .collect::<Vec<PathBuf>>()
    }
}

impl Executable for Test {
    /// .
    /// test rules against provided data inputs, comparing expected outcomes to what's evaluated
    ///
    /// This function will return an error if
    /// - conflicting attributes have been set
    /// - any of the specified paths do not exist
    /// - parse errors occur in the rule file
    /// - illegal json or yaml syntax present in any of the data input files
    fn execute(&self, writer: &mut Writer, _: &mut Reader) -> Result<i32> {
        let cmp = if self.alphabetical {
            alphabetical
        } else if self.last_modified {
            last_modified
        } else {
            regular_ordering
        };

        if self.output_format.is_structured() && self.verbose {
            return Err(Error::IllegalArguments(String::from("Cannot provide an output_type of JSON, YAML, or JUnit while the verbose flag is set")));
        } else if matches!(self.output_format, OutputFormatType::Sarif) {
            return Err(Error::IllegalArguments(String::from(
                "Cannot provide an output_type of SARIF, SARIF reporter is unsupported.",
            )));
        }

        if let Some(dir) = &self.directory {
            validate_path(dir)?;
            let walk = walkdir::WalkDir::new(dir);
            let ordered_directory = OrderedTestDirectory::from(walk);

            // Before the report and on stderr, as the unchecked-expectation note is, and here rather
            // than in either handler so that every output format says it. Read now because
            // iterating the directory consumes it.
            let mut orphaned = Notices::new();
            orphaned.extend_sorted(
                StderrLineKind::Message,
                ordered_directory
                    .orphaned_test_files
                    .iter()
                    .map(|path| unmatched_test_file_message(path)),
            );
            write_diagnostics(&orphaned, writer)?;

            match self.output_format {
                OutputFormatType::SingleLineSummary => {
                    handle_plaintext_directory(ordered_directory, writer, self.verbose)
                }
                // Returned as the handler gave it. This merged the handler's code with a local that
                // was `SUCCESS_STATUS_CODE` on every path reaching here and nowhere assigned in
                // between, so the merge could only ever yield the handler's code -- a third spelling
                // of the exit-code policy that decided nothing.
                OutputFormatType::JSON | OutputFormatType::YAML | OutputFormatType::Junit => {
                    handle_structured_directory_report(
                        ordered_directory,
                        writer,
                        self.output_format,
                    )
                }
                OutputFormatType::Sarif => unreachable!(),
            }
        } else {
            // Not `unwrap()`. The `RULES_AND_TEST_FILE` group requires the two together, so the CLI
            // cannot reach here with either missing -- but `TestBuilder::try_build` does not require
            // them, so the library can, and it panicked at exit 101 when it did.
            // A panic is never the right answer to an argument list, and the caller that can still
            // get here is a Rust caller who needs the reason rather than a backtrace.
            let (file, data) = match (self.rules.as_ref(), self.test_data.as_ref()) {
                (Some(file), Some(data)) => (file, data),
                _ => {
                    return Err(Error::IllegalArguments(String::from(
                        "test requires both a rules file and a test data file: \
                         pass --rules-file and --test-data together, or --dir to walk a directory",
                    )))
                }
            };

            validate_path(file)?;
            validate_path(data)?;

            let data_test_files = get_files_with_filter(data, cmp, |entry| {
                entry
                    .file_name()
                    .to_str()
                    .map(|name| {
                        name.ends_with(".json")
                            || name.ends_with(".yaml")
                            || name.ends_with(".JSON")
                            || name.ends_with(".YAML")
                            || name.ends_with(".yml")
                            || name.ends_with(".jsn")
                    })
                    .unwrap_or(false)
            })?;

            let path = PathBuf::from(file);

            // The check runs before the open, and through `fs::metadata` rather than through the open
            // handle, because a directory is not openable everywhere. On Unix `File::open` on a
            // directory succeeds and raises `ErrorKind::InvalidInput` on the first read. On Windows it
            // does not open at all: `CreateFileW` requires `FILE_FLAG_BACKUP_SEMANTICS` to return a
            // handle to a directory, which `File::open` does not pass and `fs::metadata` does. So
            // checking through the handle only ever ran on Unix, and on Windows the `?` on the open
            // reached `main` first.
            //
            // Both spellings said the wrong thing. The Unix one rendered as "I/O error when reading
            // invalid input parameter": it named no path, and "input parameter" is `validate`'s
            // `--input-params`, a flag `test` does not have. Both exited 255, the code
            // `guard/README.md` gives to cfn-guard itself failing.
            //
            // `TEST_ERROR_STATUS_CODE` instead, which that table defines for `test` as "an
            // expectation could not be evaluated, or a rules or test file could not be read" -- a
            // directory handed to `--rules-file` is a rules file that could not be read.
            // `handle_plaintext_single_file` below already answers the sibling case, content that
            // cannot be read, with the same code.
            //
            // 255 stays on a path that does not exist, which `validate_path` above rejects before
            // this point and all three subcommands agree on.
            if !std::fs::metadata(&path)?.is_file() {
                writer.write_err(format!(
                    "`{file}` is not a rules file. --rules-file takes one file; \
                     use --dir to walk a directory of rules files."
                ))?;

                return Ok(TEST_ERROR_STATUS_CODE);
            }

            let rule_file = File::open(&path)?;

            match self.output_format {
                OutputFormatType::SingleLineSummary => handle_plaintext_single_file(
                    rule_file,
                    path.as_path(),
                    writer,
                    &data_test_files,
                    self.verbose,
                ),
                OutputFormatType::Sarif => unreachable!(),
                OutputFormatType::YAML | OutputFormatType::JSON | OutputFormatType::Junit => {
                    handle_structured_single_report(
                        rule_file,
                        path.as_path(),
                        writer,
                        &data_test_files,
                        self.output_format,
                    )
                }
            }
        }
    }
}

fn handle_plaintext_directory(
    directory: OrderedTestDirectory,
    writer: &mut Writer,
    verbose: bool,
) -> Result<i32> {
    let mut exit_code = SUCCESS_STATUS_CODE;

    for (_, guard_files) in directory {
        for each_rule_file in guard_files {
            if each_rule_file.test_files.is_empty() {
                writeln!(
                    writer,
                    "Guard File {} did not have any tests associated, skipping.",
                    each_rule_file.file.path().display()
                )?;
                writeln!(writer, "---")?;
                continue;
            }

            writeln!(
                writer,
                "Testing Guard File {}",
                each_rule_file.file.path().display()
            )?;

            let path = each_rule_file.file.path();
            // Not `?`. Propagating reached `main`'s catch-all and exited 255, `INTERNAL_FAILURE`, the
            // code this repository reserves for the tool itself breaking -- and it abandoned every
            // later rules file in the directory, so one unreadable file cost the whole walk. A rules
            // file that cannot be read is content: `TEST_ERROR_STATUS_CODE` is what
            // `handle_plaintext_single_file` and both structured paths answer, and the structured
            // directory walk carries on to the next file the way this now does.
            let content = match get_rule_content(path) {
                Ok(content) => content,
                Err(e) => {
                    writeln!(writer, "Unable to read rule file content {e}")?;
                    exit_code = get_exit_code(exit_code, TEST_ERROR_STATUS_CODE);
                    writeln!(writer, "---")?;
                    continue;
                }
            };
            // The path, not `each_rule_file.prefix`. `prefix` is the file name with `.guard` or
            // `.ruleset` stripped and no directory at all, so it was the coarsest of the three names
            // this repository gave a rules file: `a/x.guard` and `b/x.guard` both parsed as `x`.
            //
            // Dropping the extension as well as the directory is what made `prefix` strictly worse than
            // a basename, and the pair that shows it is `ra/x.guard` beside `rb/x.ruleset` -- two files
            // whose names differ, which any basename keeps apart and which `prefix` does not. Measured
            // over exactly that tree, one `tests/x_tests.yml` apiece:
            //
            //     prefix     single-line  2 notices, 1 distinct, both `Location[file:x`
            //                -o json      1 notice
            //     path       single-line  2 notices, 2 distinct
            //                -o json      2 notices, 2 distinct
            //
            // Across directories, not within one. The pairing code below rules the same-directory pair
            // out when its tie-break is read: `min_by_key` over `Reverse(prefix.len())` returns the
            // first of equal keys, so in one directory the single `x_tests.yml` goes to `x.guard` and
            // `x.ruleset` is left with no test files at all -- whereupon both walks skip it before it
            // is ever parsed. Measured: that tree reports one notice and one `rule_file`, with `prefix`
            // and with the path alike. The same-directory collision is unreachable; the cross-directory
            // one is not.
            //
            // The name reaches the reader through the source position a deprecation notice ends with,
            // and the walk over a directory is the invocation the aws-guard-rules-registry CI uses, so
            // the collision landed on the corpus most likely to hit it.
            //
            // `prefix` keeps its job of matching test files to rules files, which is what it was built
            // for and where dropping the extension is correct.
            let span = crate::rules::parser::Span::new_extra(&content, path.to_str().unwrap_or(""));

            match crate::rules::parser::rules_file(span) {
                Err(e) => {
                    writeln!(writer, "Parse Error on ruleset file {e}",)?;
                    // `TEST_ERROR_STATUS_CODE`, not `TEST_FAILURE_STATUS_CODE`. A rules file that will
                    // not parse is an expectation that could not be evaluated, not one that was not
                    // met, and `guard/README.md` gives those two different codes. This arm was the only
                    // one of the four that said 7: the same directory answered 7 under
                    // `single-line-summary` and 1 under `json`, `yaml` and `junit`, and
                    // `handle_plaintext_single_file` answers 1 for these same bytes.
                    exit_code = get_exit_code(exit_code, TEST_ERROR_STATUS_CODE);
                }
                Ok(Some(rules)) => {
                    let data_test_files = each_rule_file
                        .test_files
                        .iter()
                        .map(|de| de.path().to_path_buf())
                        .collect::<Vec<PathBuf>>();

                    let mut reporter = GenericReporter {
                        test_data: &data_test_files,
                        rules,
                        verbose,
                        rules_file: path.to_str().unwrap_or(""),
                        writer,
                    };

                    let test_exit_code = reporter.report()?;

                    // `get_exit_code`, not `if exit_code == SUCCESS_STATUS_CODE`. That spelling kept
                    // whatever it already had, so it never promoted a failure to an error: a directory
                    // whose first rules file failed an expectation and whose second could not evaluate
                    // one exited 7, while the structured walk over the same directory exited 1. Each
                    // file on its own already agreed across the formats; only the merge did not.
                    exit_code = get_exit_code(exit_code, test_exit_code);
                }
                Ok(None) => {
                    let mut diagnostics = Notices::new();
                    if report_expectations_against_no_rules(
                        path,
                        &each_rule_file.get_test_files(),
                        &mut diagnostics,
                    ) {
                        exit_code = get_exit_code(exit_code, TEST_ERROR_STATUS_CODE);
                    }
                    write_diagnostics(&diagnostics, writer)?;
                }
            }
            writeln!(writer, "---")?;
        }
    }

    Ok(exit_code)
}

fn handle_plaintext_single_file(
    rule_file: File,
    path: &Path,
    writer: &mut Writer,
    data_test_files: &[PathBuf],
    verbose: bool,
) -> Result<i32> {
    match read_file_content(rule_file) {
        Err(e) => {
            write!(writer, "Unable to read rule file content {e}")?;
            Ok(TEST_ERROR_STATUS_CODE)
        }
        Ok(content) => {
            let span = crate::rules::parser::Span::new_extra(&content, path.to_str().unwrap_or(""));
            match crate::rules::parser::rules_file(span) {
                Err(e) => {
                    writeln!(writer, "Parse Error on ruleset file {e}")?;
                    Ok(TEST_ERROR_STATUS_CODE)
                }

                Ok(Some(rules)) => {
                    let mut reporter = GenericReporter {
                        test_data: data_test_files,
                        writer,
                        verbose,
                        rules,
                        rules_file: path.to_str().unwrap_or(""),
                    };

                    reporter.report()
                }
                Ok(None) => {
                    let mut diagnostics = Notices::new();
                    let dropped = report_expectations_against_no_rules(
                        path,
                        data_test_files,
                        &mut diagnostics,
                    );
                    write_diagnostics(&diagnostics, writer)?;

                    Ok(match dropped {
                        true => TEST_ERROR_STATUS_CODE,
                        false => SUCCESS_STATUS_CODE,
                    })
                }
            }
        }
    }
}
fn get_rule_content(path: &Path) -> Result<String> {
    let rule_file = File::open(path)?;
    read_file_content(rule_file)
}

/// Collects a message for every expectation in `data_test_files`, for a rules file that declares no
/// rules, and answers whether there was one.
///
/// `parse_rules` returns `Ok(None)` for an empty, comment-only or whitespace-only rules file, and
/// every `Ok(None)` arm in this module dropped the run on the floor: `test` had been handed explicit
/// expectations and exited 0 without looking at any of them. The two other ways an expectation goes
/// unchecked -- no such rule, and a parameterized rule -- already report and exit
/// `TEST_ERROR_STATUS_CODE`; this one is being brought in line with them rather than given a new
/// behaviour of its own.
///
/// A test file that will not parse is reported here too. With no rules there is no report for the
/// reporters to put that error in, and staying quiet about it is the defect being fixed.
///
/// Returns false when the test files hold no expectations and every case reads, which is not this
/// defect: nothing was asked, so nothing was dropped, and the caller leaves the exit code alone. A
/// case the command could not read, or whose `input:` the loader refused, is reported and counts as
/// dropped whether or not it carried an expectation: beside a rules file that declares rules it is an
/// errored case at exit 1, and the file's verdict must not depend on which rules file it sits beside.
///
/// The path as given, not `file_name_of`. This is the one arm of the four whose message is the *whole*
/// record of what was dropped: `Ok(None)` pushes no `TestResult`, so the structured document is `[]`
/// and there is no `rule_file` field anywhere in it to recover the name from. Combine that with the
/// single `Diagnostics` set `handle_structured_directory_report` keeps across the walk, and two files
/// named alike collapsed into one line that named neither of them. Measured over two directories each
/// holding a comment-only `declares_nothing.guard` with one expectation apiece:
///
/// ```text
/// test -d <dir> -o json    1 line, stdout [] -- two dropped expectations, one record
/// test -d <dir>            2 lines, byte-identical
/// ```
///
/// So the structured walk lost a whole file's record and the plaintext walk kept both while making
/// neither locatable. Both are repaired by naming the file the way every other record names it.
///
/// `unchecked_expectation_message`, the sibling sentence for an expectation naming a rule the file does
/// not declare, has the same 2-to-1 collapse and is deliberately left alone; see the note on it.
fn report_expectations_against_no_rules(
    rules_file: &Path,
    data_test_files: &[PathBuf],
    diagnostics: &mut Notices,
) -> bool {
    let name = rules_file.display().to_string();
    let mut dropped = false;

    let specs_by_file = iterate_over(data_test_files, |content, path| {
        Ok(parse_test_specs(&content, path.as_path()))
    });
    for (test_file, read) in data_test_files.iter().zip(specs_by_file) {
        match specs_noting_tags(read, diagnostics) {
            Ok(specs) => {
                diagnostics.extend_in_order(
                    StderrLineKind::Notice,
                    duplicate_case_names(&specs, test_file),
                );
                for spec in specs {
                    // A case the command could not read is reported here as the reporters report
                    // it when the file declares rules: as that case's error, whether or not it
                    // carried an expectation, so that a file whose cases are all unreadable exits 1
                    // beside a comment-only rules file as it does beside any other. The
                    // expectations the case did read are still named below.
                    //
                    // The `input:` is converted here for the same reason. A node the loader refused
                    // inside it (a null key, an alias to no anchor, a copy past the budget) is not
                    // an `unreadable` case: `TestSpec::from_marked` passes the input through and
                    // `convert_input` is what surfaces the refusal, here as in the reporters, so
                    // such a case with an empty `rules:` is the same errored case at exit 1 on both
                    // paths.
                    let TestSpec {
                        input,
                        collisions,
                        expectations,
                        unreadable,
                        ..
                    } = spec;
                    let unreadable = unreadable.or_else(|| {
                        convert_input(input, &collisions, test_file, diagnostics)
                            .err()
                            .map(|e| e.to_string())
                    });
                    if let Some(reason) = unreadable {
                        // In order, as the tag lines are: the reason names the case's position, and
                        // a text sort put a case on L:12 before one on L:2.
                        diagnostics.push_in_order(
                            StderrLineKind::Failure,
                            format!(
                                "Unable to process a test case in test file {}: {reason}",
                                test_file.display()
                            ),
                        );
                        dropped = true;
                    }
                    for expectation in expectations.rules.keys() {
                        diagnostics.insert_sorted(
                            StderrLineKind::Failure,
                            no_rules_declared_message(&name, expectation),
                        );
                        dropped = true;
                    }
                }
            }
            Err(e) => {
                // In order too: the refusal names the file and the position the loader stopped at,
                // and it belongs after that file's tag lines and before the next file's lines.
                diagnostics.push_in_order(
                    StderrLineKind::Failure,
                    format!("Unable to process a test file: {e}"),
                );
                dropped = true;
            }
        }
    }

    dropped
}

/// Reads one test file, accepting YAML or JSON.
///
/// Lifted out of `GenericReporter::report`, which had the only copy, so that the empty-rules-file
/// path above reads the expectations exactly as a run with rules would. Two spellings of "what counts
/// as a test file" would let the two disagree about whether an expectation exists. Both reporters
/// call this now, so there is one.
///
/// The file is read through the libyaml loader `validate` reads a data file with, not through
/// `serde_yaml` with a `serde_json` fallback. A spec's `input:` is the document a rule is proven
/// against, and it has to mean what the same bytes mean under `validate`: `serde_yaml::Value` keeps
/// no scalar style, so a quoted `"<<"` was merged where YAML says it is an ordinary key, and neither
/// serde value keeps source text, so `1e-400` was 0.0 and an integer wider than `u64` was a float, or
/// was refused outright with "invalid number". The `input:` stays as the loader left it and is
/// converted per case by the reporters through [`convert_input`], so a case whose `input:` cannot be
/// converted still costs only that case.
///
/// The spec loader differs from the data-file loader in three settings, all selected by
/// [`crate::rules::values::read_spec_from_with_warnings`] rather than configured here, so that the two routes
/// cannot drift apart on anything else. Anchors and aliases are not among them: both routes resolve
/// them, as `serde_yaml` did, within the same budget, so an `input:` shared between cases through
/// `&base` / `*base` is a document `validate` reads the same way.
///
///   - A node the loader will not model -- a mapping whose key is null or a sequence, a merge key
///     given a scalar, an alias to a name no earlier node anchors or one that would cross the
///     expansion budget, a sequence or mapping tagged with an intrinsic's name under `!!` -- is left
///     in the document as a `MarkedValue::Refused` carrying the refusal.
///     Inside an `input:`, [`convert_input`] fails the one case holding it; in a case's other fields,
///     [`TestSpec::from_marked`] records it as that case's `unreadable` reason; either way the other
///     cases keep their verdicts. The same bytes refuse a data file whole. What makes the document
///     itself unreadable still costs the file: nesting past the loader's bound, whether written
///     inline or reached through an alias, or a second document after the first.
///   - The spelling of every integer, float and boolean scalar is kept beside the document, so a
///     case `name` is reported as the author wrote it: `1.50` is "1.50", `1e3` is "1e3" and `True`
///     is "True", as `serde_yaml` handed them over. Names reach JUnit ids and the JSON report, so a
///     name that changed its rendering would change the id a CI dashboard groups by.
///   - The expansion budget is spent per case rather than per document, with a ceiling over the whole
///     file that no case resets; `libyaml::loader::MAX_ALIAS_EXPANSION_NODES` has both bounds.
///
/// A file that holds no document -- empty, comment-only, or a lone `---` -- has zero cases, which is
/// what serde made of it. The loader reports it as a missing document or a null, and either is turned
/// back into no cases rather than into a refusal of a file a rule author has not written yet.
///
/// What refuses the file is exactly what leaves nothing to run: the document is not a sequence of
/// cases, or a case is not a mapping, the alias or key the loader refused standing for the whole of
/// either. Everything inside a case mapping is that case's: `name` and `expectations` are read off
/// the mapping by hand, and a field the command cannot read -- written twice, missing, of the wrong
/// kind, or a node the loader refused -- makes that one case an errored case carrying the reason,
/// while the other cases run. A field written twice names both positions, because the usual way to
/// write one is a case pasted without its leading `- `, and reading the last value would run that
/// case and silently drop the one before it; serde refused the same shape, and refused the whole
/// file for it. A rule named twice under `rules:` has its own message: two expectations for one rule
/// cannot both be checked, and serde's `HashMap` kept the last one in silence. Two cases named alike
/// are both run; when one repeats the other's `input:` the reporters warn about the pair through
/// [`duplicate_case_names`], because the reports tell cases apart by name.
///
/// Beside the specs come the `!!` tags the loader read past, rendered as warning lines that name the
/// test file (see `UnreadTag::in_file`), for the reporter to put in its notices in the order given,
/// which is the document's. The loader collects them rather than printing them because library code
/// writes nothing to stderr. They are returned whatever the load's result, beside the specs, the zero
/// cases of a file holding no document, or the refusal: a tag read before the loader refused the
/// document was still read past, and `validate` prints the same lines for a data file it refuses.
/// Carried inside the `Ok` alone, a refused file would lose them, and the author of a file that is both
/// tagged and broken would see the refusal alone.
pub(crate) fn parse_test_specs(content: &str, path: &Path) -> ParsedSpecs {
    let mut unread_tags = vec![];
    let loaded = crate::rules::values::read_spec_from_with_warnings(content, &mut unread_tags);
    let tag_warnings: Vec<String> = unread_tags
        .iter()
        .map(|warning| warning.in_file(&format!("test file {}", path.display())))
        .collect();

    ParsedSpecs {
        specs: specs_of(loaded, path),
        tag_warnings,
    }
}

/// What [`parse_test_specs`] reads from one spec file: its cases, or the refusal, beside the `!!` tag
/// warning lines the loader read past, which are owed whatever `specs` holds.
pub(crate) struct ParsedSpecs {
    pub(crate) specs: Result<Vec<TestSpec>>,
    pub(crate) tag_warnings: Vec<String>,
}

/// The cases of one spec file as `iterate_over` hands them back, with the file's `!!` tag warnings
/// noted in `notices` first, in order. The outer `Err` is a file the command could not read, which
/// carries no tags; the inner is the loader's refusal, which comes with the tags read before it. The
/// one copy of this unwrapping, for the two reporters and the no-rules path: the defect it repairs
/// (tags lost when the loader refuses a file) is the kind of drift three copies invite.
pub(crate) fn specs_noting_tags(
    read: Result<ParsedSpecs>,
    notices: &mut Notices,
) -> Result<Vec<TestSpec>> {
    read.and_then(|parsed| {
        notices.extend_in_order(StderrLineKind::Notice, parsed.tag_warnings);
        parsed.specs
    })
}

/// The cases of a loaded spec document, or the refusal; see [`parse_test_specs`].
fn specs_of(loaded: Result<LoadedDocument>, path: &Path) -> Result<Vec<TestSpec>> {
    let document = match loaded {
        Ok(document) => document,
        Err(Error::MissingDocument) => return Ok(vec![]),
        // The loader's own failure is wrapped by its text, not by its display, so a file the reader
        // cannot parse gets the one "Parser Error when parsing" prefix every other refusal gets,
        // rather than a parse error quoting another parse error.
        Err(Error::ParseError(message)) => return Err(test_file_parse_error(path, message)),
        Err(e) => return Err(test_file_parse_error(path, e)),
    };
    let spellings = document.scalar_texts;
    // Shared by the file's cases: the records are keyed by position, so each case's conversion meets
    // only those inside its own `input`.
    let collisions = std::rc::Rc::new(document.collisions);

    let cases = match document.value {
        MarkedValue::List(cases, _) => cases,
        MarkedValue::Null(_) => return Ok(vec![]),
        other => {
            return Err(test_file_parse_error(
                path,
                format!("expected a sequence of test cases, found {}", found(&other)),
            ))
        }
    };

    // The one shape refusal left is a plain message, wrapped here exactly once with the file's name,
    // so a refused case reads like a refused document: one "Unable to process data in file ..." and
    // one error prefix, not a parse error quoting another parse error.
    cases
        .into_iter()
        .map(|case| {
            TestSpec::from_marked(case, &spellings, &collisions)
                .map_err(|message| test_file_parse_error(path, message))
        })
        .collect()
}

/// A warning for every case that shares its name with an earlier case of the file and repeats that
/// case's `input:`, naming the file and both positions.
///
/// The reports tell cases apart by name: the JUnit id is the name, the JSON and YAML documents carry
/// it as `name`, and a dashboard grouping by it folds two cases into one. A pasted case whose name
/// was not changed, or two names that spell one value (`1.5` and `"1.5"`) over one input, is the
/// shape this warns about. A name repeated over different inputs is how a suite groups the cases
/// that exercise one scenario, and draws nothing whether or not the expectations agree: a suite with
/// one rule has three verdicts to choose from, so cases agreeing on them is ordinary, and the
/// published rules registry does it in 39 of its 191 paired suites while repeating an input in none.
/// The cases still run; this says which ones collided.
pub(crate) fn duplicate_case_names(specs: &[TestSpec], test_file: &Path) -> Vec<String> {
    let mut seen: HashMap<&str, Vec<(Location, &TestSpec)>> = HashMap::new();
    let mut warnings = vec![];
    for spec in specs {
        let (Some(name), Some(location)) = (&spec.name, spec.name_location) else {
            continue;
        };
        let earlier = seen.entry(name.as_str()).or_default();
        if let Some((first, _)) = earlier.iter().find(|(_, other)| spec.repeats(other)) {
            warnings.push(crate::utils::writer::warning(format_args!(
                "two test cases in test file {} are named `{}`, at {first} and again at \
                 {location}. Reports tell cases apart by name; rename one.",
                crate::utils::writer::escaped_controls_for_display(
                    &test_file.display().to_string()
                ),
                crate::utils::writer::escaped_for_display(name)
            )));
        }
        earlier.push((location, spec));
    }
    warnings
}

/// Whether two loaded values spell the same document, wherever in the file each is written.
///
/// `MarkedValue`'s own equality compares positions too, and two copies of one `input:` never share
/// one. Mapping entries are matched by key and value in any order, each entry once, so a key written
/// twice has to be written twice in both; sequence items are matched in order.
fn same_document(a: &MarkedValue, b: &MarkedValue) -> bool {
    match (a, b) {
        (MarkedValue::Null(_), MarkedValue::Null(_)) => true,
        (MarkedValue::BadValue(a, _, _), MarkedValue::BadValue(b, _, _))
        | (MarkedValue::Refused(a, _), MarkedValue::Refused(b, _))
        | (MarkedValue::String(a, _), MarkedValue::String(b, _))
        | (MarkedValue::Regex(a, _), MarkedValue::Regex(b, _)) => a == b,
        (MarkedValue::Bool(a, _), MarkedValue::Bool(b, _)) => a == b,
        (MarkedValue::Int(a, _), MarkedValue::Int(b, _)) => a == b,
        (MarkedValue::Float(a, _), MarkedValue::Float(b, _)) => {
            a == b || (a.is_nan() && b.is_nan())
        }
        (MarkedValue::Char(a, _), MarkedValue::Char(b, _)) => a == b,
        (MarkedValue::RangeInt(a, _), MarkedValue::RangeInt(b, _)) => a == b,
        (MarkedValue::RangeFloat(a, _), MarkedValue::RangeFloat(b, _)) => a == b,
        (MarkedValue::RangeChar(a, _), MarkedValue::RangeChar(b, _)) => a == b,
        (MarkedValue::List(a, _), MarkedValue::List(b, _)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_document(a, b))
        }
        (MarkedValue::Map(a, _), MarkedValue::Map(b, _)) => {
            if a.len() != b.len() {
                return false;
            }
            let mut unmatched: Vec<(&str, &MarkedValue)> = b
                .iter()
                .map(|((key, _), value)| (key.as_str(), value))
                .collect();
            a.iter().all(|((key, _), value)| {
                let found = unmatched.iter().position(|(other_key, other)| {
                    *other_key == key && same_document(value, other)
                });
                match found {
                    Some(index) => {
                        unmatched.swap_remove(index);
                        true
                    }
                    None => false,
                }
            })
        }
        _ => false,
    }
}

/// The text a scalar in a spec stands for, or `None` for a container or a null.
///
/// A string is itself. An integer, float or boolean is the spelling the loader recorded for it, so
/// `1.50` stays "1.50", `1e3` stays "1e3" and `True` stays "True"; rendering the resolved value
/// changed those to "1.5", "1000.0" and "true", which merged names that differed and renamed names
/// that did not. A scalar with no recorded spelling -- none the loader produces -- falls back to the
/// rendering of a mapping key.
fn scalar_text(value: &MarkedValue, spellings: &HashMap<Location, String>) -> Option<String> {
    match value {
        MarkedValue::String(text, _) => Some(text.clone()),
        MarkedValue::Int(..) | MarkedValue::Float(..) | MarkedValue::Bool(..) => spellings
            .get(value.location())
            .cloned()
            .or_else(|| crate::rules::values::stringify_scalar_key(value)),
        other => crate::rules::values::stringify_scalar_key(other),
    }
}

/// Converts one case's loaded `input:` into the document the rules run against, adding a line to
/// `diagnostics` for every key the input wrote twice.
///
/// The loader keeps both entries of a duplicated key; the conversion keeps the last value and records
/// the duplicate, which `validate` turns into a warning on stderr. The same warning is written here,
/// word for word but naming the test file, because a spec that proves a rule against a document
/// `validate` reads with a warning should show the author that warning too. `serde_yaml` refused the
/// document outright instead, and refusing is not what `validate` does with the same bytes.
pub(crate) fn convert_input(
    input: MarkedValue,
    collisions: &KeyCollisions,
    test_file: &Path,
    diagnostics: &mut Notices,
) -> Result<PathAwareValue> {
    // With the loader's collision records, as `validate` converts a data file: a merged key that
    // collided with a held key of another form, and a key written twice at one position (an anchored
    // key beside an alias of it), are reported here as the plain pair is. Converting without them
    // warned on the plain pair and loaded the aliased one in silence.
    let mut duplicates = vec![];
    let converted = PathAwareValue::try_from_marked_reporting(
        (input, crate::rules::path_value::Path::root()),
        collisions,
        &mut duplicates,
    )?;

    // In order, as the tag lines are: the warnings carry positions, and a text sort put a case on
    // L:15 before one on L:5. Which value stands is the record's to say (`evaluated_sentence`): the
    // last for a key written twice, the first for a merged key that collided with an earlier source's
    // key, and a third site when an alias wrote the standing value at a line the pair does not name.
    diagnostics.extend_in_order(
        StderrLineKind::Notice,
        duplicates.iter().map(|duplicate| {
            crate::utils::writer::warning(format_args!(
                "duplicate key {} in test file {}, first at {} and again at {}. {}",
                crate::utils::writer::escaped_for_display(&duplicate.path),
                crate::utils::writer::escaped_controls_for_display(
                    &test_file.display().to_string()
                ),
                duplicate.first,
                duplicate.repeated,
                duplicate.evaluated_sentence()
            ))
        }),
    );

    Ok(converted)
}

/// The refusal for a case field written twice, naming both positions and the usual cause.
fn written_twice(field: &str, first: &Location, again: &Location) -> String {
    format!(
        "`{field}` is written twice in one test case, at {first} and again at {again}. A case \
         pasted without its leading `- ` reads as one case with two of every field"
    )
}

/// The refusal for a rule named twice under `rules:`. Two expectations for one rule cannot both be
/// checked, and keeping the last one silently would hide the one the author meant.
fn expected_twice(rule: &str, first: &Location, again: &Location) -> String {
    format!(
        "`{rule}` is expected twice in one test case, at {first} and again at {again}. A rule has \
         one expectation per case; delete one, or split the case in two"
    )
}

/// What a loaded value is, for a message saying it is not what a field needed.
fn kind_of(value: &MarkedValue) -> &'static str {
    match value {
        MarkedValue::Map(..) => "a mapping",
        MarkedValue::List(..) => "a sequence",
        MarkedValue::Null(..) => "null",
        MarkedValue::BadValue(..) => "a tagged scalar that is not its type",
        MarkedValue::Refused(..) => "an unreadable value",
        _ => "a scalar",
    }
}

/// What was found where a field needed something else: the value's kind and position, and for a
/// node the loader refused, the refusal itself.
///
/// Under the spec loader a mapping with a null key, an alias to an undeclared anchor, a copy past
/// the expansion budget or a container tagged with an intrinsic's name under `!!` is left in the
/// document as a `Refused` node carrying the loader's message.
/// When that node is a case, its `expectations:` or its `rules:`, the field cannot be read, and the
/// message has to say why: "an unreadable value" alone sent the author to the position with no
/// account of what the loader saw there. A `BadValue` is a `!!int abc`, whose text is the scalar's
/// own, so it is named with the text rather than as a refusal; where the loader attached a reason
/// to it, the reason's `why` follows the position, since "a tagged scalar that is not its type" is
/// exactly what it explains, and `name: !!int 0o755` beside it is accepted. The reason's `fix`, the
/// integer to write instead, is left out: the field's own "must be a string" or "must be a status"
/// says what belongs there, and no integer does.
fn found(value: &MarkedValue) -> String {
    match value {
        MarkedValue::Refused(refusal, location) => {
            format!("an unreadable value at {location}: {refusal}")
        }
        MarkedValue::BadValue(text, Some(reason), location) => {
            format!(
                "{}, `{text}`, at {location}: {}",
                kind_of(value),
                reason.why()
            )
        }
        MarkedValue::BadValue(text, None, location) => {
            format!("{}, `{text}`, at {location}", kind_of(value))
        }
        other => format!("{} at {}", kind_of(other), other.location()),
    }
}

fn missing_field(field: &str, case: &Location) -> String {
    format!("missing field `{field}` in the test case at {case}")
}

fn wrong_kind(field: &str, expected: &str, value: &MarkedValue) -> String {
    format!("`{field}` must be {expected}, found {}", found(value))
}

pub(crate) fn handle_structured_single_report(
    rule_file: File,
    path: &Path,
    writer: &mut Writer,
    data_test_files: &[PathBuf],
    output: OutputFormatType,
) -> Result<i32> {
    let now = Instant::now();

    let mut diagnostics = Notices::new();
    let result = match read_file_content(rule_file) {
        Err(e) => TestResult::Err(Err {
            rule_file: path.to_str().unwrap_or("").to_string(),
            error: e.to_string(),
            time: now.elapsed().as_millis(),
        }),

        Ok(content) => {
            let span = crate::rules::parser::Span::new_extra(&content, path.to_str().unwrap_or(""));
            match crate::rules::parser::rules_file(span) {
                Err(e) => TestResult::Err(Err {
                    rule_file: path.to_str().unwrap_or("").to_string(),
                    error: e.to_string(),
                    time: now.elapsed().as_millis(),
                }),
                Ok(Some(rule)) => {
                    // The public field stays upstream's empty sorted set; the command's own notices
                    // are the collection it writes.
                    let mut reporter = StructuredTestReporter {
                        data_test_files,
                        output,
                        rules: ContextAwareRule {
                            rule,
                            name: path.to_str().unwrap_or("").to_string(),
                        },
                        diagnostics: Default::default(),
                    };

                    reporter.evaluate_noting(&mut diagnostics)?
                }
                Ok(None) => {
                    let dropped = report_expectations_against_no_rules(
                        path,
                        data_test_files,
                        &mut diagnostics,
                    );
                    write_diagnostics(&diagnostics, writer)?;

                    return Ok(match dropped {
                        true => TEST_ERROR_STATUS_CODE,
                        false => SUCCESS_STATUS_CODE,
                    });
                }
            }
        }
    };

    // Read off the report, once, for every arm that produced one.
    //
    // Assigned inside the `Ok(Some(..))` arm alone, from a local initialized to `SUCCESS_STATUS_CODE`,
    // both `TestResult::Err` arms above -- a rules file that could not be read, and one that would not
    // parse -- would return 0: `json`, `yaml` and `junit` exiting 0 on a broken ruleset while
    // `single-line-summary` exits 1 on the same bytes, with the junit document the same run just wrote
    // saying `errors="1"`, so a CI job gating on the exit code reads a ruleset it never managed to load
    // as a pass, with every expectation in the suite unchecked.
    //
    // `TestResult::get_exit_code`'s `Err` arm answers `TEST_ERROR_STATUS_CODE`. Deriving the code from
    // the report here rather than assigning it per arm is what keeps the number the process exits with
    // and the number the report states the same.
    let exit_code = result.get_exit_code();

    // Before the report, as in `validate`, and on stderr so that stdout stays parseable.
    write_diagnostics(&diagnostics, writer)?;

    match output {
        OutputFormatType::YAML => serde_yaml::to_writer(writer, &result)?,
        OutputFormatType::JSON => serde_json::to_writer_pretty(writer, &result)?,
        OutputFormatType::Junit => JunitReport::from(&vec![result]).serialize(writer)?,
        OutputFormatType::SingleLineSummary => unreachable!(),
        OutputFormatType::Sarif => unreachable!(),
    }

    Ok(exit_code)
}

fn handle_structured_directory_report(
    directory: OrderedTestDirectory,
    writer: &mut Writer,
    output: OutputFormatType,
) -> Result<i32> {
    let mut test_results = vec![];
    let mut exit_code = SUCCESS_STATUS_CODE;
    let mut diagnostics = Notices::new();

    for (_, guard_files) in directory {
        for each_rule_file in guard_files {
            let now = Instant::now();

            if each_rule_file.test_files.is_empty() {
                continue;
            }

            let path = each_rule_file.file.path();
            // Both `TestResult::Err` arms below take their code from the report they push, as the
            // `Ok(Some(..))` arm does and as `handle_structured_single_report` now does. They spelled
            // `TEST_ERROR_STATUS_CODE` out instead, which is the same number `TestResult::get_exit_code`
            // gives an `Err` -- a second place stating the policy, and the single-file path is where
            // having two of them cost the run its exit code.
            let content = match get_rule_content(path) {
                Ok(content) => content,
                Err(e) => {
                    let result = TestResult::Err(Err {
                        rule_file: path.to_str().unwrap().to_string(),
                        error: e.to_string(),
                        time: now.elapsed().as_millis(),
                    });
                    exit_code = get_exit_code(exit_code, result.get_exit_code());
                    test_results.push(result);
                    continue;
                }
            };

            // The path, for the reason the plaintext walk above gives, plus one this path makes plain:
            // the `rule_file` field two lines below is already `path.to_str()`, so one document said
            // `a/x.guard` in its own field and `x` in any notice about it.
            let span = crate::rules::parser::Span::new_extra(&content, path.to_str().unwrap_or(""));

            match crate::rules::parser::rules_file(span) {
                Err(e) => {
                    let result = TestResult::Err(Err {
                        rule_file: path.to_str().unwrap().to_string(),
                        error: e.to_string(),
                        time: now.elapsed().as_millis(),
                    });
                    exit_code = get_exit_code(exit_code, result.get_exit_code());
                    test_results.push(result)
                }
                Ok(Some(rules)) => {
                    let data_test_files = each_rule_file.get_test_files();

                    let mut reporter = StructuredTestReporter {
                        data_test_files: &data_test_files,
                        output,
                        rules: ContextAwareRule {
                            rule: rules,
                            name: path.to_str().unwrap().to_string(),
                        },
                        diagnostics: Default::default(),
                    };

                    // Into the one collection of the whole walk, so two rules files with the same
                    // hazard say it once and the once-per-site notices keep their reading between
                    // them.
                    let test = reporter.evaluate_noting(&mut diagnostics)?;
                    let test_code = test.get_exit_code();
                    exit_code = get_exit_code(exit_code, test_code);

                    test_results.push(test);
                }
                Ok(None) => {
                    if report_expectations_against_no_rules(
                        path,
                        &each_rule_file.get_test_files(),
                        &mut diagnostics,
                    ) {
                        exit_code = TEST_ERROR_STATUS_CODE;
                    }
                }
            }
        }
    }

    // One set for the whole directory: two rule files with the same hazard say it once.
    write_diagnostics(&diagnostics, writer)?;

    match output {
        OutputFormatType::YAML => serde_yaml::to_writer(writer, &test_results)?,
        OutputFormatType::JSON => serde_json::to_writer_pretty(writer, &test_results)?,
        OutputFormatType::Junit => JunitReport::from(&test_results).serialize(writer)?,
        // NOTE: safe since output type is checked prior to calling this function
        OutputFormatType::Sarif => unreachable!(),
        OutputFormatType::SingleLineSummary => unreachable!(),
    }

    Ok(exit_code)
}

fn get_exit_code(exit_code: i32, test_code: i32) -> i32 {
    match exit_code {
        SUCCESS_STATUS_CODE => test_code,
        TEST_ERROR_STATUS_CODE => exit_code,
        TEST_FAILURE_STATUS_CODE => {
            if test_code == TEST_ERROR_STATUS_CODE {
                TEST_ERROR_STATUS_CODE
            } else {
                TEST_FAILURE_STATUS_CODE
            }
        }
        _ => unreachable!(),
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TestExpectations {
    pub rules: HashMap<String, String>,
}

impl TestExpectations {
    /// The error is the message alone; `parse_test_specs` wraps it with the file's name.
    fn from_marked(
        value: MarkedValue,
        spellings: &HashMap<Location, String>,
    ) -> std::result::Result<TestExpectations, String> {
        let (entries, location) = match value {
            MarkedValue::Map(entries, location) => (entries, location),
            other => return Err(wrong_kind("expectations", "a mapping", &other)),
        };

        let mut rules: Option<(Location, MarkedValue)> = None;
        for ((key, key_location), value) in entries {
            if key != "rules" {
                continue;
            }
            if let Some((first, _)) = &rules {
                return Err(format!(
                    "`rules` is written twice under `expectations`, at {first} and again at \
                     {key_location}"
                ));
            }
            rules = Some((key_location, value));
        }
        let rules = match rules {
            Some((_, MarkedValue::Map(rules, _))) => rules,
            // `rules:` with nothing after it: no expectations yet, as serde read it.
            Some((_, MarkedValue::Null(_))) => return Ok(TestExpectations::default()),
            Some((_, other)) => return Err(wrong_kind("rules", "a mapping", &other)),
            None => return Err(missing_field("rules", &location)),
        };

        let mut expectations = HashMap::with_capacity(rules.len());
        let mut first_seen: HashMap<String, Location> = HashMap::with_capacity(rules.len());
        for ((name, name_location), value) in rules {
            if let Some(first) = first_seen.get(&name) {
                return Err(expected_twice(&name, first, &name_location));
            }
            let Some(text) = scalar_text(&value, spellings) else {
                return Err(wrong_kind(&name, "a status", &value));
            };
            first_seen.insert(name.clone(), name_location);
            expectations.insert(name, text);
        }

        Ok(TestExpectations {
            rules: expectations,
        })
    }
}

/// One case of a `test` spec file, as `parse_test_specs` reads it.
///
/// This type is reachable through `pub mod commands`, and it is built by the command from a spec
/// file and nowhere else. It derived `Serialize` and `Deserialize` while a spec file was read through
/// serde; the spec file is read through the same loader as a data file now, `input` is that loader's
/// value, which cannot be named outside the crate, and the derives are gone with the serde value they
/// described. Code that deserialized or constructed a `TestSpec` itself has no path to one.
#[derive(Debug)]
pub struct TestSpec {
    pub name: Option<String>,
    /// Where `name` is written, for the warning about two cases that share one.
    pub(crate) name_location: Option<Location>,
    /// The case's document as the loader left it. Converted by the reporters, one case at a time, so
    /// that an `input:` which cannot be converted costs its own case and not the file's. The null
    /// node at the case's position when the case is `unreadable`.
    pub(crate) input: MarkedValue,
    /// The key collisions the loader recorded while reading the spec file, shared by its cases, for
    /// the conversion of `input` to report as duplicate keys where each value lands: a merged key that
    /// collided with a held key of another form, and a key written twice at one position (an anchored
    /// key beside an alias of it). The records are keyed by position, so each case's conversion meets
    /// only the ones inside its own `input`. Converting without them reported the plain pair and let
    /// the aliased one load in silence.
    pub(crate) collisions: std::rc::Rc<KeyCollisions>,
    /// What the case expects of each rule. Read whether or not the case can run: an `unreadable` case
    /// carries the expectations it did read, so that the no-rules path can still name what a
    /// comment-only rules file left unchecked, and the reporters never evaluate them, because they
    /// answer an `unreadable` case with its reason before any rule runs. Empty when the
    /// `expectations:` field is what could not be read.
    pub expectations: TestExpectations,
    /// Why the case cannot be run, when one of its fields could not be read: written twice, missing,
    /// of the wrong kind, or a node the loader refused. The reporters report such a case as an
    /// errored case carrying this reason, as they report a case whose `input:` cannot be converted,
    /// and the other cases of the file keep their verdicts. `None` for a case that reads. A node the
    /// loader refused inside `input:` does not set it: `input` is converted later, by whoever reads
    /// the case, and the refusal surfaces there.
    pub(crate) unreadable: Option<String>,
}

impl TestSpec {
    /// Whether this case repeats `other`'s `input:`, the shape a pasted case takes; see
    /// [`duplicate_case_names`]. Agreeing expectations are not a repetition: two inputs under one
    /// verdict is how a suite groups the cases that exercise one scenario. An unreadable case has no
    /// `input:` to repeat.
    fn repeats(&self, other: &TestSpec) -> bool {
        self.unreadable.is_none()
            && other.unreadable.is_none()
            && same_document(&self.input, &other.input)
    }

    /// Reads one case off its loaded mapping.
    ///
    /// The error is the one refusal that costs the file, a case that is not a mapping, as the message
    /// alone; `parse_test_specs` wraps it with the file's name. Everything else that can go wrong
    /// inside the mapping is the case's own mistake and comes back as an `unreadable` case, so that
    /// the other cases of the file keep their verdicts, as they do when a case's `input:` cannot be
    /// converted: one case's mistake costs that case, and which case it is does not depend on the
    /// order of the file.
    fn from_marked(
        case: MarkedValue,
        spellings: &HashMap<Location, String>,
        collisions: &std::rc::Rc<KeyCollisions>,
    ) -> std::result::Result<TestSpec, String> {
        let (entries, location) = match case {
            MarkedValue::Map(entries, location) => (entries, location),
            other => return Err(wrong_kind("a test case", "a mapping", &other)),
        };

        let mut name: Option<(Location, MarkedValue)> = None;
        let mut input: Option<(Location, MarkedValue)> = None;
        let mut expectations: Option<(Location, MarkedValue)> = None;
        // The first thing that makes the case unreadable, kept while the rest of the mapping is still
        // read: a field written twice is refused rather than resolved last-wins (see
        // `parse_test_specs`), and the scan goes on past the repeat so that a second `name` is seen
        // wherever it sits. A key this struct has no field for is ignored, as it was under serde.
        let mut unreadable: Option<String> = None;
        let mut names_written = 0usize;
        for ((key, key_location), value) in entries {
            let slot = match key.as_str() {
                "name" => {
                    names_written += 1;
                    &mut name
                }
                "input" => &mut input,
                "expectations" => &mut expectations,
                _ => continue,
            };
            if let Some((first, _)) = slot {
                let first = *first;
                unreadable =
                    unreadable.or_else(|| Some(written_twice(&key, &first, &key_location)));
                continue;
            }
            *slot = Some((key_location, value));
        }
        // Two names is no name: reporting the case under the first would make the pasted case look
        // like the one before it. Decided after the scan, because the repeated `name` may come after
        // the repeat that was recorded first, as it does when a case writes `input` before `name`.
        if names_written > 1 {
            name = None;
        }

        let (name, name_location) = match name {
            None | Some((_, MarkedValue::Null(..))) => (None, None),
            Some((_, value)) => match scalar_text(&value, spellings) {
                Some(text) => (Some(text), Some(*value.location())),
                None => {
                    unreadable =
                        unreadable.or_else(|| Some(wrong_kind("name", "a string", &value)));
                    (None, None)
                }
            },
        };

        // A missing `input` is named before a missing or unreadable `expectations`, so that a case
        // with only a `name:` is told about its input. The expectations are read whether or not the
        // case can run, so that a case the command cannot run still names what it expected: the
        // no-rules path reports an expectation a comment-only rules file left unchecked, and an
        // unreadable `name` must not hide that.
        if input.is_none() {
            unreadable = unreadable.or_else(|| Some(missing_field("input", &location)));
        }
        let expectations = match expectations {
            Some((_, expectations)) => match TestExpectations::from_marked(expectations, spellings)
            {
                Ok(expectations) => expectations,
                Err(reason) => {
                    unreadable = unreadable.or(Some(reason));
                    TestExpectations::default()
                }
            },
            None => {
                unreadable = unreadable.or_else(|| Some(missing_field("expectations", &location)));
                TestExpectations::default()
            }
        };
        let input = match input {
            Some((_, input)) if unreadable.is_none() => input,
            _ => MarkedValue::Null(location),
        };

        Ok(TestSpec {
            name,
            name_location,
            input,
            collisions: std::rc::Rc::clone(collisions),
            expectations,
            unreadable,
        })
    }
}

struct OrderedTestDirectory {
    files: BTreeMap<String, Vec<GuardFile>>,
    /// Test files under a `tests/` directory that no rules file took, in walk order.
    ///
    /// Read by the caller before it consumes the directory. Nothing named these before, so a test
    /// file left behind by a rules file rename was discarded in silence.
    orphaned_test_files: Vec<PathBuf>,
}

impl IntoIterator for OrderedTestDirectory {
    fn into_iter(self) -> Self::IntoIter {
        self.files.into_iter()
    }

    type IntoIter = std::collections::btree_map::IntoIter<String, Vec<GuardFile>>;
    type Item = (String, Vec<GuardFile>);
}

impl From<walkdir::WalkDir> for OrderedTestDirectory {
    fn from(walk: walkdir::WalkDir) -> Self {
        let mut non_guard: Vec<DirEntry> = vec![];
        let mut files: BTreeMap<String, Vec<GuardFile>> = BTreeMap::new();
        let mut orphaned_test_files: Vec<PathBuf> = vec![];
        for file in walk
            .follow_links(true)
            .sort_by_file_name()
            .into_iter()
            .flatten()
        {
            if file.path().is_file() {
                let name = file
                    .file_name()
                    .to_str()
                    .map_or("".to_string(), |s| s.to_string());

                if name.ends_with(".guard") || name.ends_with(".ruleset") {
                    let prefix = name
                        .strip_suffix(".guard")
                        .or_else(|| name.strip_suffix(".ruleset"))
                        .unwrap()
                        .to_string();

                    files
                        .entry(
                            file.path()
                                .parent()
                                .map_or("".to_string(), |p| format!("{}", p.display())),
                        )
                        .or_default()
                        .push(GuardFile {
                            prefix,
                            file,
                            test_files: vec![],
                        });
                    continue;
                } else {
                    non_guard.push(file);
                }
            }
        }

        for file in non_guard {
            let name = file
                .file_name()
                .to_str()
                .map_or("".to_string(), |s| s.to_string());

            if name.ends_with(".yaml")
                || name.ends_with(".yml")
                || name.ends_with(".json")
                || name.ends_with(".jsn")
            {
                let parent = file.path().parent();

                if parent.map_or(false, |p| p.ends_with("tests")) {
                    let candidates = parent.unwrap().parent().and_then(|grand| {
                        let grand = format!("{}", grand.display());
                        files.get_mut(&grand)
                    });

                    // The longest matching prefix, not the first match in sort order. A shorter
                    // stem is a prefix of a longer one, so `s3_encryption_tests.yml` starts with
                    // both `s3` and `s3_encryption`, and taking the first left it on `s3.guard`
                    // while `s3_encryption.guard` was reported as having no tests.
                    //
                    // `min_by_key` over the reversed length rather than `max_by_key`: on a tie
                    // the first element in sort order must still win, as it did before, and
                    // `min_by_key` returns the first of equal keys where `max_by_key` returns
                    // the last. Ties are real -- `x.guard` and `x.ruleset` share the prefix `x`.
                    let claimed_by = candidates.and_then(|candidates| {
                        candidates
                            .iter_mut()
                            .filter(|guard_file| name.starts_with(&guard_file.prefix))
                            .min_by_key(|guard_file| Reverse(guard_file.prefix.len()))
                    });

                    // Whether the file was taken is asked once, here, and both halves read the
                    // answer. Deciding it a second time by repeating the prefix test would let the
                    // two drift, and a file could then be both paired and reported as unpaired.
                    match claimed_by {
                        Some(guard_file) => guard_file.test_files.push(file),
                        None => orphaned_test_files.push(file.path().to_path_buf()),
                    }
                }
            }
        }

        OrderedTestDirectory {
            files,
            orphaned_test_files,
        }
    }
}
