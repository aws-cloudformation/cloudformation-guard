use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use clap::{App, Arg, ArgGroup, ArgMatches};
use serde::{Deserialize, Serialize};
use walkdir::DirEntry;

use validate::validate_path;

use crate::command::Command;
use crate::commands::files::{
    alpabetical, get_files_with_filter, iterate_over, last_modified, read_file_content,
    regular_ordering,
};
use crate::commands::tracker::StackTracker;
use crate::commands::{
    validate, ALPHABETICAL, DIRECTORY, DIRECTORY_ONLY, LAST_MODIFIED, PREVIOUS_ENGINE,
    RULES_AND_TEST_FILE, RULES_FILE, TEST, TEST_DATA, VERBOSE,
};
use crate::utils::writer::Writer;
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::eval::eval_rules_file;
use crate::rules::evaluate::RootScope;
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Status::SKIP;
use crate::rules::{Evaluate, NamedStatus, RecordType, Result, Status};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Test {}

impl Test {
    pub fn new() -> Self {
        Test {}
    }
}

impl Command for Test {
    fn name(&self) -> &'static str {
        TEST
    }

    fn command(&self) -> App<'static, 'static> {
        App::new(TEST)
            .about(r#"Built in unit testing capability to validate a Guard rules file against
unit tests specified in YAML format to determine each individual rule's success
or failure testing.
"#)
            .arg(Arg::with_name(RULES_FILE.0)
                .long(RULES_FILE.0)
                .short(RULES_FILE.1)
                .takes_value(true)
                .help("Provide a rules file"))
            .arg(Arg::with_name(TEST_DATA.0)
                .long(TEST_DATA.0)
                .short(TEST_DATA.1)
                .takes_value(true)
                .help("Provide a file or dir for data files in JSON or YAML"))
            .arg(Arg::with_name(DIRECTORY.0)
                .long(DIRECTORY.0)
                .short(DIRECTORY.1)
                .takes_value(true)
                .help("Provide the root directory for rules"))
            .group(ArgGroup::with_name(RULES_AND_TEST_FILE)
                .requires_all(&[RULES_FILE.0, TEST_DATA.0]).conflicts_with(DIRECTORY_ONLY))
            .group(ArgGroup::with_name(DIRECTORY_ONLY)
                .args(&["dir"])
                .requires_all(&[DIRECTORY.0])
                .conflicts_with(RULES_AND_TEST_FILE))
            .arg(Arg::with_name(PREVIOUS_ENGINE.0).long(PREVIOUS_ENGINE.0).short(PREVIOUS_ENGINE.1).takes_value(false)
                .help("Uses the old engine for evaluation. This parameter will allow customers to evaluate old changes before migrating"))
            .arg(Arg::with_name(ALPHABETICAL.0).long(ALPHABETICAL.0).short(ALPHABETICAL.1).help("Sort alphabetically inside a directory").required(false))
            .arg(Arg::with_name(LAST_MODIFIED.0).long(LAST_MODIFIED.0).short(LAST_MODIFIED.1).required(false).conflicts_with(ALPHABETICAL.0)
                .help("Sort by last modified times within a directory"))
            .arg(Arg::with_name(VERBOSE.0).long(VERBOSE.0).short(VERBOSE.1).required(false)
                .help("Verbose logging"))
    }

    fn execute(&self, app: &ArgMatches<'_>, writer: &mut Writer) -> Result<i32> {
        let mut exit_code = 0;
        let cmp = if let Some(_ignored) = app.value_of(ALPHABETICAL.0) {
            alpabetical
        } else if let Some(_ignored) = app.value_of(LAST_MODIFIED.0) {
            last_modified
        } else {
            regular_ordering
        };
        let verbose = app.is_present(VERBOSE.0);
        let new_engine = !app.is_present(PREVIOUS_ENGINE.0);

        if app.is_present(DIRECTORY_ONLY) {
            struct GuardFile {
                prefix: String,
                file: DirEntry,
                test_files: Vec<DirEntry>,
            }
            let dir = app.value_of(DIRECTORY.0).unwrap();
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
                            .or_insert(vec![])
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

            for (_dir, guard_files) in ordered_guard_files {
                for each_rule_file in guard_files {
                    if each_rule_file.test_files.is_empty() {
                        println!(
                            "Guard File {} did not have any tests associated, skipping.",
                            each_rule_file.file.path().display()
                        );
                        println!("---");
                        continue;
                    }
                    println!(
                        "Testing Guard File {}",
                        each_rule_file.file.path().display()
                    );
                    let rule_file = File::open(each_rule_file.file.path())?;
                    let content = read_file_content(rule_file)?;
                    let span =
                        crate::rules::parser::Span::new_extra(&content, &each_rule_file.prefix);
                    match crate::rules::parser::rules_file(span) {
                        Err(e) => {
                            eprintln!("Parse Error on ruleset file {}", e);
                            exit_code = 1;
                        }
                        Ok(rules) => {
                            let data_test_files = each_rule_file
                                .test_files
                                .iter()
                                .map(|de| de.path().to_path_buf())
                                .collect::<Vec<PathBuf>>();
                            let test_exit_code =
                                test_with_data(&data_test_files, &rules, verbose, new_engine)?;
                            exit_code = if exit_code == 0 {
                                test_exit_code
                            } else {
                                exit_code
                            }
                        }
                    }
                    println!("---");
                }
            }
        } else {
            let file = app.value_of(RULES_FILE.0).unwrap();
            let data = app.value_of(TEST_DATA.0).unwrap();

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

            let path = PathBuf::try_from(file)?;

            let rule_file = File::open(path.clone())?;
            if !rule_file.metadata()?.is_file() {
                return Err(Error::new(ErrorKind::IoError(std::io::Error::from(
                    std::io::ErrorKind::InvalidInput,
                ))));
            }

            let ruleset = vec![path];
            for rules in iterate_over(&ruleset, |content, file| {
                Ok((content, file.to_str().unwrap_or("").to_string()))
            }) {
                match rules {
                    Err(e) => {
                        eprintln!("Unable to read rule file content {}", e);
                        exit_code = 1;
                    }
                    Ok((context, path)) => {
                        let span = crate::rules::parser::Span::new_extra(&context, &path);
                        match crate::rules::parser::rules_file(span) {
                            Err(e) => {
                                eprintln!("Parse Error on ruleset file {}", e);
                                exit_code = 1;
                            }
                            Ok(rules) => {
                                let curr_exit_code =
                                    test_with_data(&data_test_files, &rules, verbose, new_engine)?;
                                if curr_exit_code != 0 {
                                    exit_code = curr_exit_code;
                                }
                            }
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
    new_engine: bool,
) -> Result<i32> {
    let mut exit_code = 0;
    let mut test_counter = 1;
    for specs in iterate_over(test_data_files, |data, path| {
        match serde_yaml::from_str::<Vec<TestSpec>>(&data) {
            Ok(spec) => Ok(spec),
            Err(_) => match serde_json::from_str::<Vec<TestSpec>>(&data) {
                Ok(specs) => Ok(specs),
                Err(e) => Err(Error::new(ErrorKind::ParseError(format!(
                    "Unable to process data in file {}, Error {},",
                    path.display(),
                    e
                )))),
            },
        }
    }) {
        match specs {
            Err(e) => {
                eprintln!("Error processing {}", e);
                exit_code = 1;
            }
            Ok(specs) => {
                for each in specs {
                    println!("Test Case #{}", test_counter);
                    if each.name.is_some() {
                        println!("Name: {}", each.name.unwrap());
                    }

                    let by_result = if new_engine {
                        let mut by_result = HashMap::new();
                        let root = PathAwareValue::try_from(each.input)?;
                        let mut root_scope = crate::rules::eval_context::root_scope(rules, &root)?;
                        eval_rules_file(rules, &mut root_scope)?;
                        let top = root_scope.reset_recorder().extract();

                        let by_rules = top.children.iter().fold(HashMap::new(), |mut acc, rule| {
                            if let Some(RecordType::RuleCheck(NamedStatus { name, .. })) =
                                rule.container
                            {
                                acc.entry(name).or_insert(vec![]).push(&rule.container)
                            }
                            acc
                        });

                        for (rule_name, rule) in by_rules {
                            let expected = match each.expectations.rules.get(rule_name) {
                                Some(exp) => Status::try_from(exp.as_str())?,
                                None => {
                                    println!(
                                        "  No Test expectation was set for Rule {}",
                                        rule_name
                                    );
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
                                        .insert(format!("{}: Expected = {}", rule_name, status));
                                }

                                None => {
                                    by_result
                                        .entry(String::from("FAIL"))
                                        .or_insert_with(indexmap::IndexSet::new)
                                        .insert(format!(
                                            "{}: Expected = {}, Evaluated = {:?}",
                                            rule_name, expected, statues
                                        ));
                                    exit_code = 7;
                                }
                            }
                        }

                        if verbose {
                            validate::print_verbose_tree(&top);
                        }
                        by_result
                    } else {
                        let root = PathAwareValue::try_from(each.input)?;
                        let context = RootScope::new(rules, &root)?;
                        let stacker = StackTracker::new(&context);
                        rules.evaluate(&root, &stacker)?;
                        let expectations = each.expectations.rules;
                        let stack = stacker.stack();

                        let mut by_result = HashMap::new();
                        for each in &stack[0].children {
                            match expectations.get(&each.context) {
                                Some(value) => match Status::try_from(value.as_str()) {
                                    Err(e) => {
                                        eprintln!("Incorrect STATUS provided {}", e);
                                        exit_code = 1;
                                    }
                                    Ok(status) => {
                                        let got = each.status.unwrap();
                                        if status != got {
                                            by_result
                                                .entry(String::from("FAILED"))
                                                .or_insert_with(indexmap::IndexSet::new)
                                                .insert(format!(
                                                    "{}: Expected = {}, Evaluated = {}",
                                                    each.context, status, got
                                                ));
                                            exit_code = 7;
                                        } else {
                                            by_result
                                                .entry(String::from("PASS"))
                                                .or_insert_with(indexmap::IndexSet::new)
                                                .insert(format!(
                                                    "{}: Expected = {}, Evaluated = {}",
                                                    each.context, status, got
                                                ));
                                        }
                                        if verbose {
                                            validate::print_context(each, 1);
                                        }
                                    }
                                },
                                None => {
                                    println!(
                                        "  No Test expectation was set for Rule {}",
                                        each.context
                                    )
                                }
                            }
                        }
                        by_result
                    };
                    print_test_case_report(&by_result);
                    test_counter += 1;
                }
            }
        }
    }
    Ok(exit_code)
}

pub(crate) fn print_test_case_report(by_result: &HashMap<String, indexmap::IndexSet<String>>) {
    use itertools::Itertools;
    let mut results = by_result.keys().cloned().collect_vec();

    results.sort(); // Deterministic order of results

    for result in &results {
        println!("  {} Rules:", result);
        for each_case in by_result.get(result).unwrap() {
            println!("    {}", *each_case);
        }
    }
    println!();
}
