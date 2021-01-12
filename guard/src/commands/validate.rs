use std::convert::TryFrom;
use std::fs::File;
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches};
use colored::*;

use crate::command::Command;
use crate::commands::{ALPHABETICAL, LAST_MODIFIED};
use crate::commands::files::{alpabetical, get_files, last_modified, read_file_content, regular_ordering};
use crate::rules::{Evaluate, EvaluationContext, Result, Status, EvaluationType};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::evaluate::RootScope;
use crate::rules::exprs::RulesFile;
use crate::rules::values::Value;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Validate {}

impl Validate {
    pub(crate) fn new() -> Self {
        Validate{}
    }
}

impl Command for Validate {
    fn name(&self) -> &'static str {
        "validate"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("validate")
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

    fn execute(&self, app: &ArgMatches<'_>) -> Result<()> {
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

        for each_rule_file in files {
            match open_file(&each_rule_file) {
                Ok((rule_file_name, file)) => {
                    match read_file_content(file) {
                        Ok(file_content) => {
                            let span = crate::rules::parser::Span::new_extra(&file_content, &rule_file_name);
                            match crate::rules::parser::rules_file(span) {
                                Err(e) => {
                                    println!("Parsing error handling rule file = {}, Error = {}",
                                             rule_file_name.underline(), e);
                                    continue;
                                },

                                Ok(rules) => {
                                    evaluate_against_data_files(&data_files, &rules)?
                                }
                            }
                        },

                        Err(e) => {
                            let msg = format!("Error = {}", e);
                            let msg = msg.red();
                            println!("Unable to process file {} Error = {}", rule_file_name, msg);
                            continue;
                        }
                    }
                },

                Err(e) => {
                    let msg = format!("Unable to open file {}, Error = {}",
                                      each_rule_file.display().to_string().underline(), e);
                    println!("{}", msg);
                    continue;
                }
            }
        }

        Ok(())
    }
}


struct StackContext {
    eval_type: EvaluationType,
    context: String,
    indent: usize,
}

struct Reporter<'r,'loc>{
    root_context: &'r RootScope<'r, 'loc>,
    stack: std::cell::RefCell<Vec<StackContext>>,
}

impl<'r, 'loc> Reporter<'r, 'loc> {
    fn new(root: &'r RootScope<'r, 'loc>) -> Self {
        Reporter {
            root_context: root,
            stack: std::cell::RefCell::new(Vec::new()),
        }
    }
}

const INDENT: &str = "    ";

impl<'r, 'loc> EvaluationContext for Reporter<'r, 'loc> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        self.root_context.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.root_context.rule_status(rule_name)
    }

    fn end_evaluation(&self,
                      eval_type: EvaluationType,
                      context: &str,
                      msg: String,
                      from: Option<Value>,
                      to: Option<Value>,
                      status: Status) {
        let stack = self.stack.borrow_mut().pop();
        match stack {
            Some(stack) => {
                if &stack.context == context && eval_type == stack.eval_type {
                    for idx in 0..stack.indent {
                        print!("{}", INDENT)
                    }
                    println!("{}[{}] Status = {}, Message = {}", eval_type, context.underline(), status, msg);
                    if let Some(value) = &from {
                        print!(" Comparing [{:?}]", value);
                    }
                    if let Some(value) = &to {
                        print!(" with [{:?}]", value);
                    }
                    print!("\n");
                }
            },
            None => {}
        }
        self.root_context.end_evaluation(eval_type, context, msg, from, to, status);
    }

    fn start_evaluation(&self,
                        eval_type: EvaluationType,
                        context: &str) {
        let indent= self.stack.borrow().len();
        self.stack.borrow_mut().push(StackContext {
            eval_type, context: context.to_string(), indent: indent+1
        });
        for idx in 0..indent {
            print!("{}", INDENT)
        }
        println!("Evaluating {}[{}]", eval_type, context);
        self.root_context.start_evaluation(eval_type, context);
    }
}

fn evaluate_against_data_files(data_files: &[PathBuf], rules: &RulesFile<'_>) -> Result<()> {
    for each in data_files {
        match open_file(each) {
            Ok((name, file)) => {
                match read_file_content(file) {
                    Ok(content) => {
                        let root = match serde_json::from_str::<serde_json::Value>(&content) {
                            Ok(value) => Value::try_from(value)?,
                            Err(_) => {
                                let value = serde_yaml::from_str::<serde_json::Value>(&content)?;
                                Value::try_from(value)?
                            }
                        };

                        let root_context = RootScope::new(rules, &root);
                        let reporter = Reporter{ root_context: &root_context, stack: std::cell::RefCell::new(Vec::new()) };
                        rules.evaluate(&root, &reporter)?;
                        root_context.summary_report();
                    },

                    Err(e) => {
                        println!("Unable to process data file = {}, Error = {}", name.underline(), e);
                    }
                }
            },

            Err(e) => {
                println!("Unable to open data file = {}, Error = {}", each.display(), e);
            }
        }

    }
    Ok(())
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
