use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::rules::{EvaluationType, path_value, Status};
use crate::rules::path_value::Path;
use crate::rules::values::CmpOperator;
use std::fmt::Debug;
use std::io::Write;
use std::collections::HashMap;
use std::convert::TryInto;

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct NameInfo<'a> {
    pub(super) rule: &'a str,
    pub(super) path: String,
    pub(super) provided: serde_json::Value,
    pub(super) expected: Option<serde_json::Value>,
    pub(super) comparison: Option<(CmpOperator, bool)>,
    pub(super) message: String
}

pub(super) trait GenericReporter: Debug {
    fn report(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              data_file_name: &str,
              resources: HashMap<String, Vec<NameInfo<'_>>>,
              longest_rule_len: usize) -> crate::rules::Result<()>;
}

#[derive(Debug)]
pub(super) enum StructureType {
    JSON,
    YAML
}

#[derive(Debug)]
pub(super) struct StructuredSummary {
    hierarchy_type: StructureType
}

impl StructuredSummary {
    pub(super) fn new(hierarchy_type: StructureType) -> Self {
        StructuredSummary {
            hierarchy_type
        }
    }
}

#[derive(Debug, Serialize)]
struct DataOutput<'a> {
    data_from: &'a str,
    rules_from: &'a str,
    failed: HashMap<String, Vec<NameInfo<'a>>>
}

impl GenericReporter for StructuredSummary {
    fn report(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              data_file_name: &str,
              resources: HashMap<String, Vec<NameInfo<'_>>>,
              longest_rule_len: usize) -> crate::rules::Result<()> {
        let value = DataOutput {
            rules_from: rules_file_name,
            data_from: data_file_name,
            failed: resources
        };
        match &self.hierarchy_type {
            StructureType::JSON => writeln!(writer, "{}", serde_json::to_string(&value)?),
            StructureType::YAML => writeln!(writer, "{}", serde_yaml::to_string(&value)?),
        };
        Ok(())
    }
}

pub(super) fn extract_name_info<'a>(rule_name: &'a str, each_failing_clause: &StatusContext) -> crate::rules::Result<NameInfo<'a>> {
    let value = each_failing_clause.from.as_ref().unwrap();
    let (path, from): (String, serde_json::Value) = value.try_into()?;
    Ok(NameInfo {
        rule: rule_name,
        path,
        provided: from,
        expected: match &each_failing_clause.to {
            Some(to) => {
                let (_, val): (String, serde_json::Value) = to.try_into()?;
                Some(val)
            },
            None => None,
        },
        comparison: each_failing_clause.comparator.clone(),
        message: each_failing_clause.msg.as_ref().map_or(
            "".to_string(), |e| if !e.contains("DEFAULT") { e.clone() } else { "".to_string() })
    })
}

pub(super) fn colored_string(status: Option<Status>) -> ColoredString {
    let status = match status {
        Some(s) => s,
        None => Status::SKIP,
    };
    match status {
        Status::PASS => "PASS".green(),
        Status::FAIL => "FAIL".red().bold(),
        Status::SKIP => "SKIP".yellow().bold(),
    }
}

pub(super) fn find_all_failing_clauses(context: &StatusContext) -> Vec<&StatusContext> {
    let mut failed = Vec::with_capacity(context.children.len());
    for each in &context.children {
        if each.status.map_or(false, |s| s == Status::FAIL) {
            match each.eval_type {
                EvaluationType::Clause |
                EvaluationType::BlockClause => {
                    failed.push(each);
                    if each.eval_type == EvaluationType::BlockClause {
                        failed.extend(find_all_failing_clauses(each));
                    }
                },

                EvaluationType::Filter |
                EvaluationType::Condition => {
                    continue;
                },

                _ => failed.extend(find_all_failing_clauses(each))
            }
        }
    }
    failed
}

pub(super) fn print_name_info(writer: &mut dyn Write,
                              info: &[NameInfo<'_>],
                              longest_rule_len: usize,
                              rules_file_name: &str) -> crate::rules::Result<()> {
    for each in info {
        let (did_or_didnt, operation, cmp) = match &each.comparison {
            Some((cmp, not)) => {
                if *not {
                    ("did", format!("NOT {}", cmp), Some(cmp))
                } else {
                    ("did not", format!("{}", cmp), Some(cmp))
                }
            },
            None => {
                ("did not", "NONE".to_string(), None)
            }
        };
        // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
        match cmp {
            None => {
                // Block Clause retrieval error
                writeln!(writer, "{rules}/{rule:<pad$}{operation} failed due to retrieval error, stopped at value [{provided}]. Error Message = [{msg}]",
                         rules=rules_file_name,
                         rule=each.rule,
                         pad=longest_rule_len+4,
                         operation=operation,
                         provided=each.provided,
                         msg=each.message.replace("\n", ";"))?;
            },

            Some(cmp) => {
                if cmp.is_unary() {
                    writeln!(writer, "{rules}/{rule:<pad$}{operation} failed at property path {path} on value [{provided}]. Error Message [{msg}]",
                             rules=rules_file_name,
                             rule=each.rule,
                             pad=longest_rule_len+4,
                             operation=operation,
                             provided=each.provided,
                             path=each.path,
                             msg=each.message.replace("\n", ";"))?;
                }
                else {
                    // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
                    writeln!(writer, "{rules}/{rule:<pad$}{operation} failed at property path {path} because provided value [{provided}] {did_or_didnt} match with expected value [{expected}]. Error Message [{msg}]",
                             rules=rules_file_name,
                             rule=each.rule,
                             pad=longest_rule_len+4,
                             operation=operation,
                             provided=each.provided,
                             path=each.path,
                             did_or_didnt=did_or_didnt,
                             expected=match &each.expected { Some(v) => v, None => &serde_json::Value::Null },
                             msg=each.message.replace("\n", ";"))?;
                }
            }

        }
    }

    Ok(())
}

