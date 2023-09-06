use clap::{Arg, ArgAction, ArgGroup, ArgMatches};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use walkdir::DirEntry;

use validate::validate_path;

use crate::command::Command;
use crate::commands::files::{
    alpabetical, get_files_with_filter, iterate_over, last_modified, read_file_content,
    regular_ordering,
};
use crate::commands::{
    validate, ALPHABETICAL, DIRECTORY, DIRECTORY_ONLY, LAST_MODIFIED, RULES_AND_TEST_FILE,
    RULES_FILE, TEST, TEST_DATA, VERBOSE,
};
use crate::rules::errors::Error;
use crate::rules::eval::eval_rules_file;
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Status::SKIP;
use crate::rules::{NamedStatus, RecordType, Result, Status};
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Test {}

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
                Arg::new("junit")
                    .long("junit")
                    .short('j')
                    .action(ArgAction::SetTrue)
                    .help("Print test results as a junit report"),
            )
            .arg_required_else_help(true)
    }

    fn execute(&self, app: &ArgMatches, writer: &mut Writer, _: &mut Reader) -> Result<i32> {
        let mut exit_code = 0;
        let cmp = if app.get_flag(ALPHABETICAL.0) {
            alpabetical
        } else if app.get_flag(LAST_MODIFIED.0) {
            last_modified
        } else {
            regular_ordering
        };

        let verbose = app.get_flag(VERBOSE.0);

        if app.contains_id(DIRECTORY_ONLY) {
            struct GuardFile {
                prefix: String,
                file: DirEntry,
                test_files: Vec<DirEntry>,
            }
            let dir = app.get_one::<String>(DIRECTORY.0).unwrap();
            validate_path(dir)?;
            let walk = walkdir::WalkDir::new(dir);
            let mut non_guard: Vec<DirEntry> = vec![];
            let mut ordered_guard_files: BTreeMap<String, Vec<GuardFile>> = BTreeMap::new();
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
                        ordered_guard_files
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
                            ordered_guard_files.get_mut(&grand)
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

            for (_, guard_files) in ordered_guard_files {
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
                    let rule_file = File::open(each_rule_file.file.path())?;
                    let content = read_file_content(rule_file)?;
                    let span =
                        crate::rules::parser::Span::new_extra(&content, &each_rule_file.prefix);
                    match crate::rules::parser::rules_file(span) {
                        Err(e) => {
                            writeln!(writer, "Parse Error on ruleset file {e}",)?;
                            exit_code = 1;
                        }
                        Ok(Some(rules)) => {
                            let data_test_files = each_rule_file
                                .test_files
                                .iter()
                                .map(|de| de.path().to_path_buf())
                                .collect::<Vec<PathBuf>>();
                            let test_exit_code =
                                test_with_data(&data_test_files, &rules, verbose, writer)?;
                            exit_code = if exit_code == 0 {
                                test_exit_code
                            } else {
                                exit_code
                            }
                        }
                        Ok(None) => {}
                    }
                    writeln!(writer, "---")?;
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

            let ruleset = vec![path];
            for rules in iterate_over(&ruleset, |content, file| {
                Ok((content, file.to_str().unwrap_or("").to_string()))
            }) {
                match rules {
                    Err(e) => {
                        write!(writer, "Unable to read rule file content {e}")?;
                        exit_code = 1;
                    }
                    Ok((context, path)) => {
                        let span = crate::rules::parser::Span::new_extra(&context, &path);
                        match crate::rules::parser::rules_file(span) {
                            Err(e) => {
                                writeln!(writer, "Parse Error on ruleset file {e}")?;
                                exit_code = 1;
                            }
                            Ok(Some(rules)) => {
                                let curr_exit_code =
                                    test_with_data(&data_test_files, &rules, verbose, writer)?;
                                if curr_exit_code != 0 {
                                    exit_code = curr_exit_code;
                                }
                            }
                            Ok(None) => {}
                        }
                    }
                }
            }
        }

        Ok(exit_code)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TestExpectations {
    rules: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TestSpec {
    name: Option<String>,
    input: serde_yaml::Value,
    expectations: TestExpectations,
}

#[allow(clippy::never_loop)]
fn test_with_data(
    test_data_files: &[PathBuf],
    rules: &RulesFile<'_>,
    verbose: bool,
    writer: &mut Writer,
) -> Result<i32> {
    let mut exit_code = 0;
    let mut test_counter = 1;
    for specs in iterate_over(test_data_files, |data, path| {
        match serde_yaml::from_str::<Vec<TestSpec>>(&data) {
            Ok(spec) => Ok(spec),
            Err(_) => match serde_json::from_str::<Vec<TestSpec>>(&data) {
                Ok(specs) => Ok(specs),
                Err(e) => Err(Error::ParseError(format!(
                    "Unable to process data in file {}, Error {},",
                    path.display(),
                    e
                ))),
            },
        }
    }) {
        match specs {
            Err(e) => {
                writeln!(writer, "Error processing {e}")?;
                exit_code = 1;
            }
            Ok(specs) => {
                for each in specs {
                    writeln!(writer, "Test Case #{test_counter}")?;
                    if each.name.is_some() {
                        writeln!(writer, "Name: {}", each.name.unwrap())?;
                    }

                    let by_result = {
                        let mut by_result = HashMap::new();
                        let root = PathAwareValue::try_from(each.input)?;
                        let mut root_scope =
                            crate::rules::eval_context::root_scope(rules, Rc::new(root.clone()));
                        eval_rules_file(rules, &mut root_scope, None)?; // we never use data file name in the output
                        let top = root_scope.reset_recorder().extract();

                        let by_rules: HashMap<&str, Vec<&Option<RecordType<'_>>>> =
                            top.children.iter().fold(HashMap::new(), |mut acc, rule| {
                                if let Some(RecordType::RuleCheck(NamedStatus { name, .. })) =
                                    rule.container
                                {
                                    acc.entry(name).or_default().push(&rule.container)
                                }
                                acc
                            });

                        for (rule_name, rule) in by_rules {
                            let expected = match each.expectations.rules.get(rule_name) {
                                Some(exp) => Status::try_from(exp.as_str())?,
                                None => {
                                    writeln!(
                                        writer,
                                        "  No Test expectation was set for Rule {rule_name}"
                                    )?;
                                    continue;
                                }
                            };

                            let mut statues: Vec<Status> = Vec::with_capacity(rule.len());
                            let matched = 'matched: loop {
                                let mut all_skipped = 0;

                                for each in rule.iter().copied().flatten() {
                                    if let RecordType::RuleCheck(NamedStatus {
                                        status: got_status,
                                        ..
                                    }) = each
                                    {
                                        match expected {
                                            SKIP => {
                                                if *got_status == SKIP {
                                                    all_skipped += 1;
                                                }
                                            }

                                            rest => {
                                                if *got_status == rest {
                                                    break 'matched Some(expected);
                                                }
                                            }
                                        }
                                        statues.push(*got_status)
                                    }
                                }
                                if expected == SKIP && all_skipped == rule.len() {
                                    break 'matched Some(expected);
                                }
                                break 'matched None;
                            };

                            match matched {
                                Some(status) => {
                                    by_result
                                        .entry(String::from("PASS"))
                                        .or_insert_with(indexmap::IndexSet::new)
                                        .insert(format!("{rule_name}: Expected = {status}"));
                                }

                                None => {
                                    by_result
                                        .entry(String::from("FAIL"))
                                        .or_insert_with(indexmap::IndexSet::new)
                                        .insert(format!(
                                            "{rule_name}: Expected = {expected}, Evaluated = {statues:?}"
                                        ));
                                    exit_code = 7;
                                }
                            }
                        }

                        if verbose {
                            validate::print_verbose_tree(&top, writer);
                        }
                        by_result
                    };
                    print_test_case_report(&by_result, writer);
                    test_counter += 1;
                }
            }
        }
    }
    Ok(exit_code)
}

pub(crate) fn print_test_case_report(
    by_result: &HashMap<String, indexmap::IndexSet<String>>,
    writer: &mut Writer,
) {
    use itertools::Itertools;
    let mut results = by_result.keys().cloned().collect_vec();

    results.sort(); // Deterministic order of results

    for result in &results {
        writeln!(writer, "  {result} Rules:").expect("Unable to write to the output");
        for each_case in by_result.get(result).unwrap() {
            writeln!(writer, "    {}", *each_case).expect("Unable to write to the output");
        }
    }
    writeln!(writer).expect("Unable to write to the output");
}
