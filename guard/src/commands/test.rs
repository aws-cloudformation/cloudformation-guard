use std::convert::TryFrom;
use std::fs::File;
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches};


use crate::command::Command;
use crate::commands::{ALPHABETICAL, LAST_MODIFIED};
use crate::commands::files::{alpabetical, last_modified, regular_ordering, iterate_over, get_files_with_filter};
use crate::rules::{Evaluate, Result, Status};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::evaluate::RootScope;
use crate::rules::exprs::RulesFile;

use std::collections::HashMap;
use crate::rules::path_value::PathAwareValue;
use crate::commands::tracker::{StackTracker};
use serde::{Serialize, Deserialize};
use itertools::Itertools;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Test {}

impl Test {
    pub(crate) fn new() -> Self {
        Test{}
    }
}

impl Command for Test {
    fn name(&self) -> &'static str {
        "test"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("test")
            .about(r#"Built in unit testing capability to validate a Guard rules file against
unit tests specified in YAML format to determine each individual rule's success
or failure testing.
"#)
            .arg(Arg::with_name("rules-file").long("rules-file").short("r").takes_value(true).help("Provide a rules file").required(true))
            .arg(Arg::with_name("test-data").long("test-data").short("t").takes_value(true).help("Provide a file or dir for data files in JSON or YAML").required(true))
            .arg(Arg::with_name("alphabetical").alias("-a").help("Sort alphabetically inside a directory").required(false))
            .arg(Arg::with_name("last-modified").long("last-modified").short("m").required(false).conflicts_with("alphabetical")
                .help("Sort by last modified times within a directory"))
            .arg(Arg::with_name("verbose").long("verbose").short("v").required(false)
                .help("Verbose logging"))
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<i32> {
        let mut exit_code = 0;
        let file = app.value_of("rules-file").unwrap();
        let data = app.value_of("test-data").unwrap();
        let cmp = if let Some(_ignored) = app.value_of(ALPHABETICAL.0) {
            alpabetical
        } else if let Some(_ignored) = app.value_of(LAST_MODIFIED.0) {
            last_modified
        } else {
            regular_ordering
        };
        let verbose = if app.is_present("verbose") { true } else { false };

        let data_test_files = get_files_with_filter(&data, cmp, |entry| {
            entry.file_name().to_str()
                .map(|name|
                    name.ends_with(".json") ||
                    name.ends_with(".yaml") ||
                    name.ends_with(".JSON") ||
                    name.ends_with(".YAML") ||
                    name.ends_with(".yml")  ||
                    name.ends_with(".jsn")
                ).unwrap_or(false)
        })?;

        let path = PathBuf::try_from(file)?;
        let rule_file = File::open(path.clone())?;
        if !rule_file.metadata()?.is_file() {
            return Err(Error::new(ErrorKind::IoError(
                std::io::Error::from(std::io::ErrorKind::InvalidInput)
            )))
        }

        let ruleset = vec![path];
        for rules in iterate_over(&ruleset, |content, file| {
            Ok((content, file.to_str().unwrap_or("").to_string()))
        }) {
            match rules {
                Err(e) => println!("Unable to read rule file content {}", e),
                Ok((context, path)) => {
                    let span = crate::rules::parser::Span::new_extra(&context, &path);
                    match crate::rules::parser::rules_file(span) {
                        Err(e) => println!("Parse Error on ruleset file {}", e),
                        Ok(rules) => {
                            exit_code = test_with_data(&data_test_files, &rules, verbose)?;
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
    rules: HashMap<String, String>
}

#[derive(Serialize, Deserialize, Debug)]
struct TestSpec {
    name: Option<serde_json::Value>,
    input: serde_json::Value,
    expectations: TestExpectations,
}

fn test_with_data(test_data_files: &[PathBuf], rules: &RulesFile<'_>, verbose: bool) -> Result<i32> {
    let mut exit_code = 0;
    let mut test_counter = 1;
    for specs in iterate_over(test_data_files, |data, path| {
        match serde_yaml::from_str::<Vec<TestSpec>>(&data) {
            Ok(spec) => {
                Ok(spec)
            },
            Err(_) => match serde_json::from_str::<Vec<TestSpec>>(&data) {
                Ok(specs) => Ok(specs),
                Err(e) => Err(Error::new (ErrorKind::ParseError(
                    format!("Unable to process data in file {}, Error {},", path.display(), e))))
            }
        }
    }) {
        match specs {
            Err(e) => println!("Error processing {}", e),
            Ok(specs) => {
                for each in specs {
                    let root = PathAwareValue::try_from(each.input)?;
                    let context = RootScope::new(rules, &root);
                    let stacker = StackTracker::new(&context);
                    rules.evaluate(&root, &stacker)?;
                    let expectations = each.expectations.rules;
                    let stack = stacker.stack();

                    println!("Test Case #{}", test_counter);
                    if !each.name.is_none() {
                        println!("Name: {}", each.name.unwrap());
                    }

                    let mut by_result = HashMap::new();
                    for each in &stack[0].children {
                        match expectations.get(&each.context) {
                            Some(value) => {
                                match Status::try_from(value.as_str()) {
                                    Err(e) => println!("Incorrect STATUS provided {}", e),
                                    Ok(status) => {
                                        let got = each.status.unwrap();
                                        if status != got {
                                            by_result.entry(String::from("FAILED")).or_insert(indexmap::IndexSet::new())
                                                .insert(String::from(format!("{}: Expected = {}, Evaluated = {}",
                                                                             each.context, status, got)));
                                            exit_code = 7;
                                        }
                                        else {
                                            by_result.entry(String::from("PASS")).or_insert(indexmap::IndexSet::new())
                                                .insert(String::from(format!("{}: Expected = {}, Evaluated = {}",
                                                                             each.context, status, got)));
                                        }
                                        if verbose {
                                            super::validate::print_context(each, 1);
                                        }
                                    }
                                }
                            },
                            None => {
                                println!("  No Test expectation was set for Rule {}", each.context)
                            }
                        }
                    }
                    print_test_case_report(&by_result);
                    test_counter += 1;
                }
            }
        }
    }
    Ok(exit_code)
}

pub (crate) fn print_test_case_report(by_result: &HashMap<String, indexmap::IndexSet<String>>) {

    let mut results = by_result.keys().map(|elem| elem.clone()).collect_vec();
    results.sort(); // Deterministic order of results

    for result in &results {
        println!("  {} Rules:", result);
        for each_case in by_result.get(result).unwrap() {
            println!("    {}", *each_case);
        }
    }
    println!();
}
