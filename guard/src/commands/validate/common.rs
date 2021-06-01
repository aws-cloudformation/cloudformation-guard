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
    pub(super) from: serde_json::Value,
    pub(super) to: Option<serde_json::Value>,
    pub(super) comparison: Option<(CmpOperator, bool)>,
    pub(super) message: String
}

pub(super) trait GenericRenderer : Debug {
    fn render(&self,
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

impl GenericRenderer for StructuredSummary {
    fn render(&self,
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
        from,
        to: match &each_failing_clause.to {
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

