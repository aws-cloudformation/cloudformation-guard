use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::rules::{EvaluationType, path_value, Status, RecordType, ClauseCheck, QueryResult, NamedStatus, BlockCheck, TypeBlockCheck};
use crate::rules::path_value::Path;
use crate::rules::values::CmpOperator;
use std::fmt::Debug;
use std::io::Write;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use regex::Regex;
use lazy_static::*;
use crate::rules::eval_context::EventRecord;
use crate::rules::errors::{Error, ErrorKind};

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct Comparison {
    operator: CmpOperator,
    not_operator_exists: bool,
}

impl From<(CmpOperator, bool)> for Comparison {
    fn from(input: (CmpOperator, bool)) -> Self {
        Comparison {
            operator: input.0,
            not_operator_exists: input.1
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct NameInfo<'a> {
    pub(super) rule: &'a str,
    pub(super) path: String,
    pub(super) provided: Option<serde_json::Value>,
    pub(super) expected: Option<serde_json::Value>,
    pub(super) comparison: Option<Comparison>,
    pub(super) message: String,
    pub(super) error: Option<String>
}

impl<'a> Default for NameInfo<'a> {
    fn default() -> Self {
        NameInfo {
            rule: "",
            path: "".to_string(),
            provided: None,
            expected: None,
            comparison: None,
            message: "".to_string(),
            error: None
        }
    }
}

pub(super) trait GenericReporter: Debug {
    fn report(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              data_file_name: &str,
              failed: HashMap<String, Vec<NameInfo<'_>>>,
              passed: HashSet<String>,
              skipped:HashSet<String>,
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
    not_compliant: HashMap<String, Vec<NameInfo<'a>>>,
    not_applicable: HashSet<String>,
    compliant: HashSet<String>,
}

impl GenericReporter for StructuredSummary {
    fn report(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              data_file_name: &str,
              failed: HashMap<String, Vec<NameInfo<'_>>>,
              passed: HashSet<String>,
              skipped: HashSet<String>, longest_rule_len: usize) -> crate::rules::Result<()>
    {
        let value = DataOutput {
            rules_from: rules_file_name,
            data_from: data_file_name,
            not_compliant: failed,
            compliant: passed,
            not_applicable: skipped
        };

        match &self.hierarchy_type {
            StructureType::JSON => writeln!(writer, "{}", serde_json::to_string(&value)?),
            StructureType::YAML => writeln!(writer, "{}", serde_yaml::to_string(&value)?),
        };
        Ok(())
    }
}

lazy_static! {
    static ref PATH_FROM_MSG: Regex = Regex::new(r"path\s+=\s+(?P<path>[^ ]+)").ok().unwrap();
}

pub(super) fn find_failing_clauses<'record, 'value>(
    current: &'record EventRecord<'value>) -> Vec<&'record EventRecord<'value>>
{
    match &current.container {

        Some(RecordType::Filter(_)) |
        Some(RecordType::ClauseValueCheck(ClauseCheck::Success)) => vec![],

        Some(RecordType::ClauseValueCheck(_)) => vec![current],
        Some(RecordType::RuleCheck(NamedStatus{message: Some(_), status: Status::FAIL, ..})) => vec![current],

        _ => {
            let mut acc = Vec::new();
            for child in &current.children {
                acc.extend(find_failing_clauses(child));
            }
            acc
        }
    }
}

pub(super) fn extract_name_info_from_record<'record, 'value>(
    rule_name: &'record str,
    clause: &'record EventRecord<'value>) -> crate::rules::Result<NameInfo<'record>>
{
    Ok(match &clause.container {
        Some(RecordType::RuleCheck(NamedStatus{message: Some(msg), name, ..})) => {
            NameInfo {
                message: msg.clone(),
                rule: *name,
                ..Default::default()
            }
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(missing))) =>
            NameInfo {
                error: missing.message.clone(),
                message: missing.custom_message.as_ref().map_or("".to_string(), |m| m.clone()),
                rule: rule_name,
                ..Default::default()
            },

        Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(missing))) =>
            NameInfo {
                rule: rule_name,
                error: missing.message.clone(),
                message: missing.custom_message.as_ref().map_or("".to_string(), |s| s.clone()),
                path: missing.from.unresolved_traversed_to().map_or("".to_string(), |s| s.self_path().0.clone()),
                ..Default::default()
            },

        Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(check))) => {
            match &check.value.from {
                QueryResult::Resolved(res) => {
                    let (path, provided) :(String, serde_json::Value) = (*res).try_into()?;
                    NameInfo {
                        rule: rule_name,
                        comparison: Some(check.comparison.into()),
                        error: check.value.message.clone(),
                        message: check.value.custom_message.as_ref().map_or("".to_string(), |msg| msg.clone()),
                        provided: Some(provided),
                        path,
                        ..Default::default()
                    }
                },

                QueryResult::UnResolved(unres) => {
                    let (path, provided) :(String, serde_json::Value) = unres.traversed_to.try_into()?;
                    NameInfo {
                        rule: rule_name,
                        comparison: Some(check.comparison.into()),
                        error: Some(check.value.message.as_ref().map_or(unres.reason.as_ref().map_or(
                            "".to_string(), |r| r.clone()), |msg| msg.clone())),
                        message: check.value.custom_message.as_ref().map_or("".to_string(), |msg| msg.clone()),
                        provided: Some(provided),
                        path,
                        ..Default::default()
                    }
                }
            }
        }

        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(check))) => {
            match &check.from {
                QueryResult::Resolved(res) => {
                    let (path, provided) :(String, serde_json::Value) = (*res).try_into()?;
                    let expected: Option<(String, serde_json::Value)> = match &check.to {
                        Some(to) => match to {
                            QueryResult::Resolved(v) => Some((*v).try_into()?),
                            QueryResult::UnResolved(ur) => Some(ur.traversed_to.try_into()?),
                        }
                        None => None,
                    };
                    let expected = match expected {
                        Some((_, ex)) => Some(ex),
                        None => None,
                    };
                    NameInfo {
                        rule: rule_name,
                        comparison: Some(check.comparison.into()),
                        error: check.message.clone(),
                        message: check.custom_message.as_ref().map_or("".to_string(), |msg| msg.clone()),
                        provided: Some(provided),
                        expected,
                        path,
                        ..Default::default()
                    }

                },

                QueryResult::UnResolved(unres) => {
                    let (path, provided) :(String, serde_json::Value) = unres.traversed_to.try_into()?;
                    NameInfo {
                        rule: rule_name,
                        comparison: Some(check.comparison.into()),
                        error: Some(check.message.as_ref().map_or(unres.reason.as_ref().map_or(
                            "".to_string(), |r| r.clone()), |msg| msg.clone())),
                        message: check.custom_message.as_ref().map_or("".to_string(), |msg| msg.clone()),
                        provided: Some(provided),
                        path,
                        ..Default::default()
                    }
                }
            }
        }

        Some(RecordType::ClauseValueCheck(ClauseCheck::NoValueForEmptyCheck(msg))) =>
            NameInfo {
                rule: rule_name,
                comparison: Some(Comparison{not_operator_exists: false, operator: CmpOperator::Empty}),
                message: String::from(msg.as_ref().map_or("", |s| s.as_str())),
                ..Default::default()
            },

        _ => unreachable!()
    })
}

pub(crate) fn extract_event_records<'value>(root_record: EventRecord<'value>)
    -> (Vec<EventRecord<'value>>, Vec<EventRecord<'value>>, Vec<EventRecord<'value>>)
{
    let mut failed = Vec::with_capacity(root_record.children.len());
    let mut skipped = Vec::with_capacity(root_record.children.len());
    let mut passed = Vec::with_capacity(root_record.children.len());
    for each_rule in root_record.children {
        match &each_rule.container {
            Some(RecordType::RuleCheck(NamedStatus{status: Status::FAIL, name, message})) => {
                let mut failed = EventRecord {
                    container: Some(RecordType::RuleCheck(NamedStatus{status: Status::FAIL, name, message: message.clone()})),
                    children: vec![],
                    context: each_rule.context
                };
                //add_failed_children(&mut failed, each_rule.children)
            },

            Some(RecordType::RuleCheck(NamedStatus{status: Status::SKIP, ..})) => {
                skipped.push(each_rule);
            }

            rest => {
                skipped.push(each_rule);
            }
        }
    }
    (failed, skipped, passed)
}

pub(super) fn report_from_events(
    root_record: &EventRecord<'_>,
    writer: &mut dyn Write,
    data_file_name: &str,
    rules_file_name: &str,
    renderer: &dyn GenericReporter,
) -> crate::rules::Result<()> {
    let mut longest_rule_name = 0;
    let mut failed = HashMap::new();
    let mut skipped = HashSet::new();
    let mut success = HashSet::new();
    for each_rule in &root_record.children {
        if let Some(RecordType::RuleCheck(NamedStatus{status, name, message})) = &each_rule.container {
            if name.len() > longest_rule_name {
                longest_rule_name = name.len();
            }
            match status {
                Status::FAIL => {
                    let mut clauses = Vec::new();
                    for each_clause in find_failing_clauses(each_rule) {
                        clauses.push(extract_name_info_from_record(*name, each_clause)?);
                    }
                    failed.insert(name.to_string(), clauses);
                },

                Status::PASS => {
                    success.insert(name.to_string());
                },

                Status::SKIP => {
                    skipped.insert(name.to_string());
                }
            }
        }
    }

    renderer.report(
        writer,
        rules_file_name,
        data_file_name,
        failed,
        success,
        skipped,
        longest_rule_name
    )?;
    Ok(())

}

pub(super) fn extract_name_info<'a>(rule_name: &'a str,
                                    each_failing_clause: &StatusContext) -> crate::rules::Result<NameInfo<'a>> {
    if each_failing_clause.from.is_some() {
        let value = each_failing_clause.from.as_ref().unwrap();
        let (path, from): (String, serde_json::Value) = value.try_into()?;
        Ok(NameInfo {
            rule: rule_name,
            path,
            provided: Some(from),
            expected: match &each_failing_clause.to {
                Some(to) => {
                    let (_, val): (String, serde_json::Value) = to.try_into()?;
                    Some(val)
                },
                None => None,
            },
            comparison: match each_failing_clause.comparator {
                Some(input) => Some(input.into()),
                None => None,
            },
            message: each_failing_clause.msg.as_ref().map_or(
                "".to_string(), |e| if !e.contains("DEFAULT") { e.clone() } else { "".to_string() }),
            error: None
        })
    }
    else {
        //
        // This is crappy, but we are going to extract information from the retrieval error message
        // see path_value.rs for retrieval error messages.
        // TODO merge the query interface to retrieve partial results along with errored one ones and then
        //      change this logic based on the reporting changes. Today we bail out for the first
        //      retrieval error, fast fail semantics
        //

        //
        // No from is how we indicate retrieval errors.
        //
        let (path, error) = each_failing_clause.msg.as_ref().map_or(("".to_string(), "".to_string()), |msg| {
            match PATH_FROM_MSG.captures(msg) {
                Some(cap) => (cap["path"].to_string(), msg.clone()),
                None => ("".to_string(), msg.clone())
            }
        });

        Ok(NameInfo {
            rule: rule_name,
            path,
            error: Some(error),
            ..Default::default()
        })
    }
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

pub(super) fn print_compliant_skipped_info(writer: &mut dyn Write,
                                           passed: &HashSet<String>,
                                           skipped: &HashSet<String>,
                                           rules_file_name: &str,
                                           data_file_name: &str) -> crate::rules::Result<()> {
    if !passed.is_empty() {
        writeln!(writer, "--")?;
    }
    for pass in passed {
        writeln!(writer, "Rule [{}/{}] is compliant for template [{}]", rules_file_name, pass, data_file_name)?;
    }
    if !skipped.is_empty() {
        writeln!(writer, "--")?;
    }
    for skip in skipped {
        writeln!(writer, "Rule [{}/{}] is not applicable for template [{}]", rules_file_name, skip, data_file_name)?;
    }
    Ok(())
}

pub(super) fn print_name_info<R, U, B>(
    writer: &mut dyn Write,
    info: &[NameInfo<'_>],
    longest_rule_len: usize,
    rules_file_name: &str,
    data_file_name: &str,
    retrieval_error: R,
    unary_message: U,
    binary_message: B) -> crate::rules::Result<()>
    where R: Fn(&str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
          U: Fn(&str, &str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
          B: Fn(&str, &str, &str, &NameInfo<'_>) -> crate::rules::Result<String>
{
    for each in info {
        let (cmp, not) = match &each.comparison {
            Some(cmp) => (Some(cmp.operator), cmp.not_operator_exists),
            None => (None, false)
        };
        // CFN = Resource [<name>] was not compliant with [<rule-name>] for property [<path>] because provided value [<value>] did not match expected value [<value>]. Error Message [<msg>]
        // General = Violation of [<rule-name>] for property [<path>] because provided value [<value>] did not match expected value [<value>]. Error Message [<msg>]
        // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
        match each.error {
            Some(_) => {
                // Block Clause retrieval error
                writeln!(writer, "{}", retrieval_error(rules_file_name, data_file_name, each)?)?;
            },

            None => {
                let (cmp, not) = match &each.comparison {
                    Some(cmp) => (cmp.operator, cmp.not_operator_exists),
                    None => {
                        writeln!(writer, "Parameterized Rule {rules}/{rule_name} failed for {data}. Reason {msg}",
                            rules=rules_file_name,
                            data=data_file_name,
                            rule_name=each.rule,
                            msg=each.message.replace('\n', "; ")
                        );
                        continue;
                    }
                };
                if cmp.is_unary() {
                    writeln!(writer, "{}",
                         unary_message(
                             rules_file_name,
                             data_file_name,
                             match cmp {
                                 CmpOperator::Exists => if !not { "did not exist" } else { "existed" },
                                 CmpOperator::Empty => if !not { "was not empty"} else { "was empty" },
                                 CmpOperator::IsList => if !not { "was not a list " } else { "was list" },
                                 CmpOperator::IsMap => if !not { "was not a struct" } else { "was struct" },
                                 CmpOperator::IsString => if !not { "was not a string " } else { "was string" },
                                 _ => unreachable!()
                             },
                             each)?,
                    )?;

                }
                else {
                    // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
                    writeln!(writer, "{}",
                        binary_message(
                            rules_file_name,
                            data_file_name,
                            if not { "did" } else { "did not" },
                            each
                        )?,
                    )?;
                }
            }

        }
    }

    Ok(())
}

