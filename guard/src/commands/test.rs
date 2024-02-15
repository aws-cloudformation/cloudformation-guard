use crate::commands::reporters::test::generic::GenericReporter;
use crate::commands::reporters::test::structured::{
    ContextAwareRule, Err, StructuredTestReporter, TestResult,
};
use crate::commands::reporters::JunitReport;
use crate::commands::{
    Executable, SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE,
};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::DirEntry;

use validate::validate_path;

use crate::commands::files::{
    alphabetical, get_files_with_filter, last_modified, read_file_content, regular_ordering,
};
use crate::commands::validate::{OutputFormatType, OUTPUT_FORMAT_HELP};
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

#[derive(Debug, Clone, Eq, PartialEq, Args)]
#[clap(about=ABOUT)]
#[clap(
    group=clap::ArgGroup::new(RULES_AND_TEST_FILE)
    .requires_all([RULES_FILE.0, TEST_DATA.0])
    .conflicts_with(DIRECTORY_ONLY))
]
#[clap(
    group=clap::ArgGroup::new(DIRECTORY_ONLY).args([DIRECTORY.0])
    .requires_all([DIRECTORY.0])
    .conflicts_with(RULES_AND_TEST_FILE))
]
#[clap(arg_required_else_help = true)]
pub struct Test {
    #[arg(name="rules-file", short, long, help=RULES_HELP)]
    pub(crate) rules: Option<String>,
    #[arg(name="test-data", short, long, help=TEST_DATA_HELP)]
    pub(crate) test_data: Option<String>,
    #[arg(name=DIRECTORY.0, short, long=DIRECTORY.0, help=DIRECTORY_HELP)]
    pub(crate) directory: Option<String>,
    #[arg(short, long, help = ALPHABETICAL_HELP, conflicts_with=LAST_MODIFIED.0)]
    pub(crate) alphabetical: bool,
    #[arg(name="last-modified", short=LAST_MODIFIED.1, long=LAST_MODIFIED.0, help=LAST_MODIFIED_HELP, conflicts_with=ALPHABETICAL.0)]
    pub(crate) last_modified: bool,
    #[arg(short, long, help=VERBOSE_HELP)]
    pub(crate) verbose: bool,
    #[arg(short, long, help=OUTPUT_FORMAT_HELP, value_enum, default_value_t=OutputFormatType::SingleLineSummary)]
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
        }

        if let Some(dir) = &self.directory {
            validate_path(dir)?;
            let walk = walkdir::WalkDir::new(dir);
            let ordered_directory = OrderedTestDirectory::from(walk);

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
            }
        } else {
            let file = self.rules.as_ref().unwrap();
            let data = self.test_data.as_ref().unwrap();

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

            match self.output_format {
                OutputFormatType::SingleLineSummary => handle_plaintext_single_file(
                    rule_file,
                    path.as_path(),
                    writer,
                    &data_test_files,
                    self.verbose,
                ),

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
