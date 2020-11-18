use clap::{ArgMatches, App, Arg};
use crate::commands::{ALPHABETICAL, LAST_MODIFIED, RULES};
use crate::command::Command;
use crate::errors::Error;

use crate::errors;
use crate::rules::expr::*;
use crate::rules;
use crate::rules::parser::Span;
use crate::rules::{dependency, EvalStatus};

use super::files;
use crate::commands::files::{get_files, alpabetical, last_modified, regular_ordering, read_file_content};
use std::fs::File;
use colored::*;

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::PathBuf;
use std::io::BufReader;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct EvaluateRules {}

impl EvaluateRules {

    pub(crate) fn new() -> EvaluateRules {
        EvaluateRules {}
    }

}

impl Command for EvaluateRules {
    fn name(&self) -> &'static str {
        "evaluate"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("evaluate")
            .about(r#"
             Evaluates rules against the data files to determine
             success or failure. When pointed to a directory it will
             read all rules in the directory file and evaluate them
             against the data files found in the directory. The command
             can also point to a single file and it would work as well
        "#)
            .arg(Arg::with_name("rules").long("rules").short("r").takes_value(true).help("provide a rules file or a directory").required(true))
            .arg(Arg::with_name("data").long("data").short("d").takes_value(true).help("provide a file or dir for data files in JSON or YAML").required(true))
            .arg(Arg::with_name("alphabetical").alias("-a").help("sort alphabetically inside a directory").required(false))
            .arg(Arg::with_name("last-modified").short("-m").required(false).conflicts_with("alphabetical")
                .help("sort by last modified times within a directory"))
    }

    fn execute(&self, app: &ArgMatches) -> Result<(), Error> {
        let file = app.value_of("rules").unwrap();
        let data = app.value_of("data").unwrap();
        let cmp = if let Some(_ignored) = app.value_of(ALPHABETICAL.0) {
            alpabetical
        } else if let Some(_ignored) = app.value_of(LAST_MODIFIED.0) {
            last_modified
        } else {
            regular_ordering
        };
        let files = get_files(file, cmp)?;
        let data_files = get_files(data, cmp)?;
        let mut results = HashMap::with_capacity(files.len());
        let mut file_errors = HashMap::with_capacity(files.len());
        for path in files {
            if let Some(file_name) = path.file_name() {
                if let Some(file_name) = file_name.to_str() {
                    let file_name = file_name.to_string();
                    if let Ok(file) = File::open(path) {
                        let result = read_file_content(file);
                        if let Err(error) = result {
                            let error = format!("Error handling file {}, Error = {}", file_name, error);
                            file_errors.insert(file_name, error);
                            continue;
                        }
                        let content = result?;
                        let result = evaluate_rules(&file_name, &content, &data_files);
                        results.insert(file_name, result);
                    }
                }
            }
        }

        for (name, result) in results {
            if let Err(error) = result {
                println!("Ruleset {}: Rules Parsing Error {}", name.underline(), error);
                continue;
            }

            for (each, rule_evaluations) in result? {
                if let Err(error) = rule_evaluations {
                    println!("Ruleset {}: Rules Evaluation Error {}", name.underline(), error);
                    continue;
                }

                let result = rule_evaluations?;
                let resolutions = result.get_resolved_statuses();
                let overall_status = if let Some(_one) = resolutions.values().find(|status| **status == EvalStatus::FAIL) {
                    "FAILED".red()
                }
                else {
                    "PASSED".green()
                };
                let mut keys: Vec<&String> = resolutions.keys().filter(|s| (*s).starts_with("/") != false)
                    .collect();
                keys.sort();
                let mut longest = 0;
                for each in &keys {
                    if (*each).len() > longest {
                        longest = each.len();
                    }
                }

                let message = format!("Ruleset {}: Overall Status {}", name.underline(), overall_status);
                println!("{}", message.underline());
                for each in keys {
                    let status = resolutions.get(each).unwrap();
                    let status = if status == &EvalStatus::PASS {
                        "PASSED".green()
                    } else {
                        "FAILED".red()
                    };
                    let space = std::iter::repeat(" ").take(longest - each.len() + 4)
                        .collect::<String>();
                    println!("{}{}:{}", each, space, status);
                }
            }
        }
        Ok(())
    }
}


fn evaluate_rules(file_name: &str, content: &str, files: &Vec<PathBuf>)
                  -> Result<HashMap<String, Result<rules::expr::Resolutions, errors::Error>>, errors::Error> {

    let result = super::parse_tree::parse_rule_file(content, file_name)?;
    let mut per_ruleset = HashMap::with_capacity(files.len());
    for each in files {
        let opened = File::open(each);
        if let Ok(file) = opened {
            let reader = BufReader::new(file);
            let context: serde_json::Value = serde_json::from_reader(reader)?;
            let resolutions = result.evaluate(&context);
            per_ruleset.insert(each.to_str().unwrap().to_string(), resolutions);
        }
        else {
            let error = opened.map_err(|e| errors::Error::from(e))
                .err().unwrap();
            per_ruleset.insert(each.to_str().unwrap().to_string(), Err(error));
        }
    }
    Ok(per_ruleset)
}


