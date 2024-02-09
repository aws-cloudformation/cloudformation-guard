use crate::commands::reporters::test::generic::GenericReporter;
use crate::commands::reporters::test::structured::{
    ContextAwareRule, Err, StructuredTestReporter, TestResult,
};
use crate::commands::reporters::JunitReport;
use crate::commands::{SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE};
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, ValueHint};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::DirEntry;

use validate::validate_path;

use crate::command::Command;
use crate::commands::files::{
    alpabetical, get_files_with_filter, last_modified, read_file_content, regular_ordering,
};
use crate::commands::validate::{OutputFormatType, OUTPUT_FORMAT_VALUE_TYPE};
use crate::commands::{
    validate, ALPHABETICAL, DIRECTORY, DIRECTORY_ONLY, LAST_MODIFIED, OUTPUT_FORMAT,
    RULES_AND_TEST_FILE, RULES_FILE, TEST, TEST_DATA, VERBOSE,
};
use crate::rules::errors::Error;
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Test {}
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
#[allow(clippy::new_without_default)]
impl Test {
    pub fn new() -> Self {
        Test {}
    }
}

impl Command for Test {
    fn name(&self) -> &'static str {
        TEST
    }

    fn command(&self) -> clap::Command {
        clap::Command::new(TEST)
            .about(
                r#"Built in unit testing capability to validate a Guard rules file against
unit tests specified in YAML format to determine each individual rule's success
or failure testing.
"#,
            )
            .arg(
                Arg::new(RULES_FILE.0)
                    .long(RULES_FILE.0)
                    .short(RULES_FILE.1)
                    .action(ArgAction::Set)
                    .help("Provide a rules file"),
            )
            .arg(
                Arg::new(TEST_DATA.0)
                    .long(TEST_DATA.0)
                    .short(TEST_DATA.1)
                    .action(ArgAction::Set)
                    .help("Provide a file or dir for data files in JSON or YAML"),
            )
            .arg(
                Arg::new(DIRECTORY.0)
                    .long(DIRECTORY.0)
                    .short(DIRECTORY.1)
                    .action(ArgAction::Set)
                    .help("Provide the root directory for rules"),
            )
            .group(
                ArgGroup::new(RULES_AND_TEST_FILE)
                    .requires_all([RULES_FILE.0, TEST_DATA.0])
                    .conflicts_with(DIRECTORY_ONLY),
            )
            .group(
                ArgGroup::new(DIRECTORY_ONLY)
                    .args(["dir"])
                    .requires_all([DIRECTORY.0])
                    .conflicts_with(RULES_AND_TEST_FILE),
            )
            .arg(
                Arg::new(ALPHABETICAL.0)
                    .long(ALPHABETICAL.0)
                    .short(ALPHABETICAL.1)
                    .action(ArgAction::SetTrue)
                    .help("Sort alphabetically inside a directory"),
            )
            .arg(
                Arg::new(LAST_MODIFIED.0)
                    .long(LAST_MODIFIED.0)
                    .short(LAST_MODIFIED.1)
                    .action(ArgAction::SetTrue)
                    .conflicts_with(ALPHABETICAL.0)
                    .help("Sort by last modified times within a directory"),
            )
            .arg(
                Arg::new(VERBOSE.0)
                    .long(VERBOSE.0)
                    .short(VERBOSE.1)
                    .action(ArgAction::SetTrue)
                    .help("Verbose logging"),
            )
            .arg(
                Arg::new(OUTPUT_FORMAT.0)
                    .long(OUTPUT_FORMAT.0)
                    .short(OUTPUT_FORMAT.1)
                    .value_parser(OUTPUT_FORMAT_VALUE_TYPE)
                    .default_value("single-line-summary")
                    .action(ArgAction::Set)
                    .value_hint(ValueHint::Other)
                    .help("Specify the format in which the output should be displayed"),
            )
            .arg_required_else_help(true)
    }

    fn execute(&self, app: &ArgMatches, writer: &mut Writer, _: &mut Reader) -> Result<i32> {
        let mut exit_code = SUCCESS_STATUS_CODE;
        let cmp = if app.get_flag(ALPHABETICAL.0) {
            alpabetical
        } else if app.get_flag(LAST_MODIFIED.0) {
            last_modified
        } else {
            regular_ordering
        };

        let output_type = match app.get_one::<String>(OUTPUT_FORMAT.0) {
            Some(o) => OutputFormatType::from(o.as_str()),
            None => OutputFormatType::SingleLineSummary,
        };

        let verbose = app.get_flag(VERBOSE.0);

        if output_type.is_structured() && verbose {
            return Err(Error::IllegalArguments(String::from("Cannot provide an output_type of JSON, YAML, or JUnit while the verbose flag is set")));
        }

        if app.contains_id(DIRECTORY_ONLY) {
            let dir = app.get_one::<String>(DIRECTORY.0).unwrap();
            validate_path(dir)?;
            let walk = walkdir::WalkDir::new(dir);
            let ordered_directory = OrderedTestDirectory::from(walk);

            match output_type {
                OutputFormatType::SingleLineSummary => {
                    handle_plaintext_directory(ordered_directory, writer, verbose)
                }
                OutputFormatType::JSON | OutputFormatType::YAML | OutputFormatType::Junit => {
                    let test_exit_code =
                        handle_structured_directory_report(ordered_directory, writer, output_type)?;
                    exit_code = if exit_code == SUCCESS_STATUS_CODE {
                        test_exit_code
                    } else {
                        exit_code
                    };

                    Ok(exit_code)
                }
            }
        } else {
            let file = app.get_one::<String>(RULES_FILE.0).unwrap();
            let data = app.get_one::<String>(TEST_DATA.0).unwrap();

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
            if !rule_file.metadata()?.is_file() {
                return Err(Error::IoError(std::io::Error::from(
                    std::io::ErrorKind::InvalidInput,
                )));
            }

            match output_type {
                OutputFormatType::SingleLineSummary => handle_plaintext_single_file(
                    rule_file,
                    path.as_path(),
                    writer,
                    &data_test_files,
                    verbose,
                ),

                OutputFormatType::YAML | OutputFormatType::JSON | OutputFormatType::Junit => {
                    handle_structured_single_report(
                        rule_file,
                        path.as_path(),
                        writer,
                        &data_test_files,
                        output_type,
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
                Ok(None) => {}
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
                Ok(None) => Ok(SUCCESS_STATUS_CODE),
            }
        }
    }
}
fn get_rule_content(path: &Path) -> Result<String> {
    let rule_file = File::open(path)?;
    read_file_content(rule_file)
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
                    };

                    let test = reporter.evaluate()?;
                    let test_code = test.get_exit_code();
                    exit_code = get_exit_code(exit_code, test_code);

                    test
                }
                Ok(None) => return Ok(exit_code),
            }
        }
    };

    match output {
        OutputFormatType::YAML => serde_yaml::to_writer(writer, &result)?,
        OutputFormatType::JSON => serde_json::to_writer_pretty(writer, &result)?,
        OutputFormatType::Junit => JunitReport::from(&vec![result]).serialize(writer)?,
        OutputFormatType::SingleLineSummary => unreachable!(),
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
                    };

                    let test = reporter.evaluate()?;
                    let test_code = test.get_exit_code();
                    exit_code = get_exit_code(exit_code, test_code);

                    test_results.push(test);
                }
                Ok(None) => {}
            }
        }
    }

    match output {
        OutputFormatType::YAML => serde_yaml::to_writer(writer, &test_results)?,
        OutputFormatType::JSON => serde_json::to_writer_pretty(writer, &test_results)?,
        OutputFormatType::Junit => JunitReport::from(&test_results).serialize(writer)?,
        // NOTE: safe since output type is checked prior to calling this function
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

struct OrderedTestDirectory(BTreeMap<String, Vec<GuardFile>>);

impl IntoIterator for OrderedTestDirectory {
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }

    type IntoIter = std::collections::btree_map::IntoIter<String, Vec<GuardFile>>;
    type Item = (String, Vec<GuardFile>);
}

impl From<walkdir::WalkDir> for OrderedTestDirectory {
    fn from(walk: walkdir::WalkDir) -> Self {
        let mut non_guard: Vec<DirEntry> = vec![];
        let mut files: BTreeMap<String, Vec<GuardFile>> = BTreeMap::new();
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
                    if let Some(candidates) = parent.unwrap().parent().and_then(|grand| {
                        let grand = format!("{}", grand.display());
                        files.get_mut(&grand)
                    }) {
                        for guard_file in candidates {
                            if name.starts_with(&guard_file.prefix) {
                                guard_file.test_files.push(file);
                                break;
                            }
                        }
                    }
                }
            }
        }

        OrderedTestDirectory(files)
    }
}
