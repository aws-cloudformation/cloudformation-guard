use crate::commands::reporters::test::generic::GenericReporter;
use crate::commands::reporters::test::structured::{
    ContextAwareRule, Err, StructuredTestReporter, TestResult,
};
use crate::commands::reporters::test::{
    no_rules_declared_message, unmatched_test_file_message, write_diagnostics, Diagnostics,
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
use crate::commands::validate::{file_name_of, OutputFormatType, OUTPUT_FORMAT_HELP};
use crate::commands::{
    validate, ALPHABETICAL, DIRECTORY, DIRECTORY_ONLY, LAST_MODIFIED, RULES_AND_TEST_FILE,
    RULES_FILE, TEST_DATA,
};
use crate::rules::errors::Error;
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
        let mut exit_code = SUCCESS_STATUS_CODE;
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
            write_diagnostics(
                &ordered_directory
                    .orphaned_test_files
                    .iter()
                    .map(|path| unmatched_test_file_message(path))
                    .collect(),
                writer,
            )?;

            match self.output_format {
                OutputFormatType::SingleLineSummary => {
                    handle_plaintext_directory(ordered_directory, writer, self.verbose)
                }
                OutputFormatType::JSON | OutputFormatType::YAML | OutputFormatType::Junit => {
                    let test_exit_code = handle_structured_directory_report(
                        ordered_directory,
                        writer,
                        self.output_format,
                    )?;
                    exit_code = if exit_code == SUCCESS_STATUS_CODE {
                        test_exit_code
                    } else {
                        exit_code
                    };

                    Ok(exit_code)
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

            let rule_file = File::open(&path)?;
            // A directory opens successfully, so this is the check that catches it, and the error it
            // raised was `ErrorKind::InvalidInput`. That rendered as "I/O error when reading invalid
            // input parameter": it named no path, and "input parameter" is `validate`'s
            // `--input-params`, a flag `test` does not have. It also exited 255, the code
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
            if !rule_file.metadata()?.is_file() {
                writer.write_err(format!(
                    "`{file}` is not a rules file. --rules-file takes one file; \
                     use --dir to walk a directory of rules files."
                ))?;

                return Ok(TEST_ERROR_STATUS_CODE);
            }

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
            let content = get_rule_content(path)?;
            let span = crate::rules::parser::Span::new_extra(&content, &each_rule_file.prefix);

            match crate::rules::parser::rules_file(span) {
                Err(e) => {
                    writeln!(writer, "Parse Error on ruleset file {e}",)?;
                    exit_code = TEST_FAILURE_STATUS_CODE;
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
                        writer,
                    };

                    let test_exit_code = reporter.report()?;

                    exit_code = if exit_code == SUCCESS_STATUS_CODE {
                        test_exit_code
                    } else {
                        exit_code
                    };
                }
                Ok(None) => {
                    let mut diagnostics = Diagnostics::new();
                    if report_expectations_against_no_rules(
                        path,
                        &each_rule_file.get_test_files(),
                        &mut diagnostics,
                    ) {
                        exit_code = TEST_ERROR_STATUS_CODE;
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
                    };

                    reporter.report()
                }
                Ok(None) => {
                    let mut diagnostics = Diagnostics::new();
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
/// Returns false when the test files hold no expectations at all, which is not this defect: nothing
/// was asked, so nothing was dropped, and the caller leaves the exit code alone.
fn report_expectations_against_no_rules(
    rules_file: &Path,
    data_test_files: &[PathBuf],
    diagnostics: &mut Diagnostics,
) -> bool {
    let name = file_name_of(rules_file);
    let mut dropped = false;

    for specs in iterate_over(data_test_files, |content, path| {
        parse_test_specs(&content, path.as_path())
    }) {
        match specs {
            Ok(specs) => {
                for spec in specs {
                    for expectation in spec.expectations.rules.keys() {
                        diagnostics.insert(no_rules_declared_message(&name, expectation));
                        dropped = true;
                    }
                }
            }
            Err(e) => {
                diagnostics.insert(format!("Unable to process a test file: {e}"));
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
/// as a test file" would let the two disagree about whether an expectation exists.
pub(crate) fn parse_test_specs(content: &str, path: &Path) -> Result<Vec<TestSpec>> {
    match serde_yaml::from_str::<Vec<TestSpec>>(content) {
        Ok(spec) => Ok(spec),
        Err(_) => match serde_json::from_str::<Vec<TestSpec>>(content) {
            Ok(specs) => Ok(specs),
            Err(e) => Err(Error::ParseError(format!(
                "Unable to process data in file {}, Error {},",
                path.display(),
                e
            ))),
        },
    }
}

pub(crate) fn handle_structured_single_report(
    rule_file: File,
    path: &Path,
    writer: &mut Writer,
    data_test_files: &[PathBuf],
    output: OutputFormatType,
) -> Result<i32> {
    let mut exit_code = SUCCESS_STATUS_CODE;
    let now = Instant::now();

    let mut diagnostics = Diagnostics::new();
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
                    let mut reporter = StructuredTestReporter {
                        data_test_files,
                        output,
                        rules: ContextAwareRule {
                            rule,
                            name: path.to_str().unwrap_or("").to_string(),
                        },
                        diagnostics: Diagnostics::new(),
                    };

                    let test = reporter.evaluate()?;
                    let test_code = test.get_exit_code();
                    exit_code = get_exit_code(exit_code, test_code);

                    diagnostics.append(&mut reporter.diagnostics);
                    test
                }
                Ok(None) => {
                    if report_expectations_against_no_rules(path, data_test_files, &mut diagnostics)
                    {
                        exit_code = TEST_ERROR_STATUS_CODE;
                    }
                    write_diagnostics(&diagnostics, writer)?;

                    return Ok(exit_code);
                }
            }
        }
    };

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
    let mut diagnostics = Diagnostics::new();

    for (_, guard_files) in directory {
        for each_rule_file in guard_files {
            let now = Instant::now();

            if each_rule_file.test_files.is_empty() {
                continue;
            }

            let path = each_rule_file.file.path();
            let content = match get_rule_content(path) {
                Ok(content) => content,
                Err(e) => {
                    exit_code = TEST_ERROR_STATUS_CODE;
                    test_results.push(TestResult::Err(Err {
                        rule_file: path.to_str().unwrap().to_string(),
                        error: e.to_string(),
                        time: now.elapsed().as_millis(),
                    }));
                    continue;
                }
            };

            let span = crate::rules::parser::Span::new_extra(&content, &each_rule_file.prefix);

            match crate::rules::parser::rules_file(span) {
                Err(e) => {
                    exit_code = TEST_ERROR_STATUS_CODE;
                    test_results.push(TestResult::Err(Err {
                        rule_file: path.to_str().unwrap().to_string(),
                        error: e.to_string(),
                        time: now.elapsed().as_millis(),
                    }))
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
                        diagnostics: Diagnostics::new(),
                    };

                    let test = reporter.evaluate()?;
                    let test_code = test.get_exit_code();
                    exit_code = get_exit_code(exit_code, test_code);

                    diagnostics.append(&mut reporter.diagnostics);
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

#[derive(Serialize, Deserialize, Debug)]
pub struct TestExpectations {
    pub rules: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestSpec {
    pub name: Option<String>,
    pub input: serde_yaml::Value,
    pub expectations: TestExpectations,
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
