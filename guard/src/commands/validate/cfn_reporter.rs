use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io::Write;

use colored::*;
use lazy_static::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::commands::validate::common::{find_all_failing_clauses, NameInfo, GenericReporter, StructuredSummary, StructureType};
use crate::rules::errors::{Error, ErrorKind};

use super::EvaluationType;
use crate::rules::Status;

lazy_static! {
    static ref CFN_RESOURCES: Regex = Regex::new(r"^/Resources/(?P<name>[^/]+)/(?P<rest>.*$)").ok().unwrap();
}

#[derive(Debug)]
pub(crate) struct CfnReporter<'a> {
    data_file_name: &'a str,
    rules_file_name: &'a str,
    output_format_type: OutputFormatType,
    render: Box<dyn GenericReporter>,
}

impl<'a> CfnReporter<'a> {
    pub(crate) fn new<'r>(data_file_name: &'r str,
                          rules_file_name: &'r str,
                          output_format_type: OutputFormatType) -> CfnReporter<'r> {
        CfnReporter {
            data_file_name,
            rules_file_name,
            output_format_type,
            render: match output_format_type {
                OutputFormatType::SingleLineSummary => Box::new(SingleLineReporter {}) as Box<dyn GenericReporter>,
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON)) as Box<dyn GenericReporter>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML)) as Box<dyn GenericReporter>,
            }
        }
    }
}

impl<'a> Reporter for CfnReporter<'a> {
    fn report(&self,
              writer: &mut dyn Write,
              _status: Option<Status>,
              failed_rules: &[&StatusContext],
              passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize) -> crate::rules::Result<()> {
        let failed = if !failed_rules.is_empty() {
            let mut by_resource_name = HashMap::new();
            for each_failed_rule in failed_rules {
                let failed = find_all_failing_clauses(each_failed_rule);
                for each_failing_clause in failed {
                    match each_failing_clause.eval_type {
                        EvaluationType::Clause |
                        EvaluationType::BlockClause => {
                            if each_failing_clause.from.is_some() {
                                let mut resource_info = super::common::extract_name_info(
                                    &each_failed_rule.context, each_failing_clause)?;
                                let (resource_name, property_path) = match CFN_RESOURCES.captures(&resource_info.path) {
                                    Some(caps) => {
                                        (caps["name"].to_string(), caps["rest"].replace("/", "."))
                                    },
                                    None => return Err(Error::new(ErrorKind::IncompatibleRetrievalError(
                                        "Expecting CFN Template format for errors".to_string()
                                    )))
                                };
                                resource_info.path = property_path;
                                by_resource_name.entry(resource_name).or_insert(Vec::new()).push(resource_info);
                            }
                        },

                        _ => unreachable!()
                    }
                }
            }
            by_resource_name
        } else { HashMap::new() };
        let as_vec = passed_or_skipped.iter().map(|s| *s)
            .collect::<Vec<&StatusContext>>();
        let (skipped, passed): (Vec<&StatusContext>, Vec<&StatusContext>) = as_vec.iter()
            .partition(|status| match status.status { // This uses the dereference deep trait of Rust
                Some(Status::SKIP) => true,
                _ => false
            });
        let skipped = skipped.iter().map(|s| s.context.clone()).collect::<HashSet<String>>();
        let passed = passed.iter().map(|s| s.context.clone()).collect::<HashSet<String>>();
        self.render.report(writer, self.rules_file_name, self.data_file_name, failed, passed, skipped, longest_rule_name)?;
        Ok(())
    }
}

#[derive(Debug)]
struct SingleLineReporter {}

impl super::common::GenericReporter for SingleLineReporter {
    fn report(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              data_file_name: &str,
              by_resource_name: HashMap<String, Vec<NameInfo<'_>>>,
              passed: HashSet<String>,
              skipped: HashSet<String>,
              longest_rule_len: usize) -> crate::rules::Result<()> {

        writeln!(writer, "Evaluation of rules {} for template {}, number of resource failures = {}",
                 rules_file_name, data_file_name, by_resource_name.len())?;
        if !by_resource_name.is_empty() {
            writeln!(writer, "--");
        }
        for (resource, info) in by_resource_name.iter() {
            super::common::print_name_info(
                writer, &info, longest_rule_len, rules_file_name, data_file_name,
                |_, _, info| {
                    Ok(format!("Resource [{}] traversed until [{}] with [{}] for template [{}] wasn't compliant with [{}/{}] due to retrieval error. Error Message [{}]",
                               resource,
                               info.path,
                               info.provided,
                               data_file_name,
                               rules_file_name,
                               info.rule,
                               info.message.replace("\n", ";")
                    ))
                },
                |_, _, op_msg, info| {
                    Ok(format!("Resource [{}] property [{}] with value [{}] {} for template [{}] wasn't compliant with [{}/{}]. Error Message [{}]",
                               resource,
                               info.path,
                               info.provided,
                               op_msg,
                               data_file_name,
                               rules_file_name,
                               info.rule,
                               info.message.replace("\n", ";")
                    ))
                },
                |_, _, msg, info| {
                    Ok(format!("Resource [{}] property [{}] with value [{}] {} match [{}] for template [{}] wasn't compliant with [{}/{}]. Error Message [{}]",
                               resource,
                               info.path,
                               info.provided,
                               msg,
                               info.expected.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
                               data_file_name,
                               rules_file_name,
                               info.rule,
                               info.message.replace("\n", ";")
                    ))
                }

            )?;
        }
        if !passed.is_empty() {
            writeln!(writer, "--");
        }
        for pass in passed {
            writeln!(writer, "Rule [{}/{}] was compliant for template [{}]", rules_file_name, pass, data_file_name);
        }
        if !skipped.is_empty() {
            writeln!(writer, "--");
        }
        for skip in skipped {
            writeln!(writer, "Rule [{}/{}] was not applicable for template [{}]", rules_file_name, skip, data_file_name);
        }
        writeln!(writer, "--");
        Ok(())
    }
}
