use colored::*;

use crate::command::Command;
use crate::commands::{ALPHABETICAL, LAST_MODIFIED, RULES};
use crate::commands::files::{alpabetical, get_files, last_modified, read_file_content, regular_ordering};
use crate::errors;
use crate::errors::{Error, ErrorKind};
use crate::rules;
use crate::rules::EvalStatus;
use crate::rules::expr::*;
use clap::{App, Arg, ArgMatches};
use std::collections::HashMap;
use std::fs::{File, read};
use std::path::PathBuf;
use std::io::BufReader;
use crate::rules::exprs::{EvalContext, RulesFile, QueryResolver, Scope, Path, Resolver, Evaluate, Status};
use crate::rules::values::Value;
use crate::rules::parser2::{from_str2, Span2, rules_file};
use std::convert::TryFrom;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct EvaluateRules {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) struct EvaluationResults<'loc> {
    rules: Option<Result<RulesFile<'loc>>>,
    root_scope: Option<Scope<'loc>>,
    file_name: Option<String>,
    rules_content: Option<String>,
    data_file_evaluations: HashMap<PathBuf, Result<EvalContext<'loc>>>,
}

impl<'loc> EvaluationResults<'loc> {

    fn new() -> EvaluationResults<'loc> {
        EvaluationResults {
            rules: None,
            root_scope: None,
            file_name: None,
            rules_content: None,
            data_file_evaluations: HashMap::new(),
        }
    }
}

impl Command for EvaluateRules {
    fn name(&self) -> &'static str {
        "evaluate"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("evaluate2")
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

    fn execute(&self, app: &ArgMatches) -> Result<()> {
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
        for path in files {
            if let Ok((name, content)) = handle_rules_file(path) {
                let span = Span2::new_extra(&content, &name);
                if let Ok(rules) = rules_file(span) {
                    let mut root  = Scope::new();
                    let root_path = Path::new(&["/"]);
                    root.assignments(&rules.assignments, root_path.clone());
                    let mut resolver = QueryResolver{};

                    for data in &data_files {
                        if let Ok((data_file_name, data_handle)) = open_file(data) {
                            if let Ok(data_root) = read_data(data_handle) {
                                let eval = evaluate_rules(&root, &rules, &resolver, data_root, root_path.clone())?;
                                print_result(&data_file_name, &name, eval);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn print_result(data: &str, rules: &str, context: EvalContext<'_>) {
    println!("Ruleset {}: evaluation against data {}", rules.underline(), data.underline());
    let rule_resolutions = context.rule_resolutions.borrow();
    let mut longest = 0;
    for each in rule_resolutions.keys() {
        if (*each).len() > longest {
            longest = each.len();
        }
    }

    for (rule_name, status) in rule_resolutions.iter() {
        let status = match status {
            Status::PASS => "PASS".green(),
            Status::FAIL => "FAIL".red(),
            Status::SKIP => "SKIP".yellow()
        };
        let space = std::iter::repeat(" ").take(longest - rule_name.len() + 4)
            .collect::<String>();
        println!("{}{}:{}", rule_name, space, status);
    }
}

fn handle_rules_file(file: PathBuf) -> Result<(String, String)> {
    let (file_name, file) = open_file(&file)?;
    let value = read_file_content(file)?;
    Ok((file_name, value))
}

fn parse_rules<'r>(content: &'r str, file_name: &'r str) -> Result<RulesFile<'r>> {
    crate::rules::parser2::rules_file(Span2::new_extra(content, file_name))
}

fn open_file(path: &PathBuf) -> Result<(String, std::fs::File)> {
    if let Some(file_name) = path.file_name() {
        if let Some(file_name) = file_name.to_str() {
            let file_name = file_name.to_string();
            return Ok((file_name, File::open(path)?))
        }
    }
    Err(Error::new(
        ErrorKind::IoError(std::io::Error::from(std::io::ErrorKind::NotFound))))
}

fn evaluate_rules<'a>(
    root: &Scope<'_>,
    rules: &'a RulesFile<'a>,
    resolver: &dyn Resolver,
    data: Value,
    root_path: Path) -> Result<EvalContext<'a>> {

    let mut eval = EvalContext::new(data, rules);
    let mut file_scope = Scope::child(root);
    file_scope.assignment_queries(
        &rules.assignments,
        root_path.clone(),
        &eval.root,
        resolver,
        &eval
    )?;

    for rule in &rules.guard_rules {
        match rule.evaluate(
            resolver,
            &file_scope,
            &eval.root,
            root_path.clone(),
            &eval
        ) {
            Ok(r) => {},
            Err(e) => return Err(e)
        }
    }

    Ok(eval)
}

fn read_data(file: File) -> Result<Value> {
    let context = read_file_content(file)?;
    match serde_json::from_str::<serde_json::Value>(&context) {
        Ok(value) => Value::try_from(value),
        Err(_) => {
            let value = serde_yaml::from_str::<serde_json::Value>(&context)?;
            Value::try_from(value)
        }
    }
}


