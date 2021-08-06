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
use crate::rules::eval_context::EventRecord;

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
            for (idx, each_failed_rule) in failed_rules.iter().enumerate() {
                let failed = find_all_failing_clauses(each_failed_rule);
                for (clause_idx, each_failing_clause) in failed.iter().enumerate() {
                    match each_failing_clause.eval_type {
                        EvaluationType::Clause |
                        EvaluationType::BlockClause => {
                            if each_failing_clause.eval_type == EvaluationType::BlockClause {
                                match &each_failing_clause.msg {
                                    Some(msg) => {
                                        if msg.contains("DEFAULT") {
                                            continue;
                                        }
                                    },

                                    None => {
                                        continue;
                                    }
                                }
                            }
                            let mut resource_info = super::common::extract_name_info(
                                &each_failed_rule.context, each_failing_clause)?;
                            let (resource_name, property_path) = match CFN_RESOURCES.captures(&resource_info.path) {
                                Some(caps) => {
                                    (caps["name"].to_string(), caps["rest"].replace("/", "."))
                                },
                                None =>
                                    (format!("Rule {} Resource {} {}", each_failed_rule.context, idx, clause_idx), "".to_string())

                            };
                            resource_info.path = property_path;
                            by_resource_name.entry(resource_name).or_insert(Vec::new()).push(resource_info);
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

    fn report_eval(&self,
                   write: &mut dyn Write,
                   status: Status,
                   root_record: &EventRecord<'_>) -> crate::rules::Result<()> {
        super::common::report_from_events(root_record, write, self.data_file_name, self.rules_file_name, self.render.as_ref())
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
        //
        // Agreed on text
        // Resource [NewVolume2] property [Properties.Encrypted] in template [template.json] is not compliant with [sg.guard/aws_ec2_volume_checks] because provided value [false] does not match with expected value [true]. Error Message [[EC2-008] : EC2 volumes should be encrypted]
        //
        for (resource, info) in by_resource_name.iter() {
            super::common::print_name_info(
                writer, &info, longest_rule_len, rules_file_name, data_file_name,
                |_, _, info| {
                    Ok(format!("Resource [{}] traversed until [{}] for template [{}] wasn't compliant with [{}/{}] due to retrieval error. Error Message [{}]",
                               resource,
                               info.path,
                               data_file_name,
                               rules_file_name,
                               info.rule,
                               info.message.replace("\n", ";")
                    ))
                },
                |_, _, op_msg, info| {
                    Ok(format!("Resource [{resource}] property [{property}] in template [{template}] is not compliant with [{rules}/{rule}] because needed value at [{provided}] {op_msg}. Error message [{msg}]",
                               resource=resource,
                               property=info.path,
                               provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
                               op_msg=op_msg,
                               template=data_file_name,
                               rules=rules_file_name,
                               rule=info.rule,
                               msg=info.message.replace("\n", ";")
                    ))
                },
                |_, _, msg, info| {
                    Ok(format!("Resource [{resource}] property [{property}] in template [{template}] is not compliant with [{rules}/{rule}] because provided value [{provided}] {op_msg} match with expected value [{expected}]. Error message [{msg}]",
                               resource=resource,
                               property=info.path,
                               provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
                               op_msg=msg,
                               expected=info.expected.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
                               template=data_file_name,
                               rules=rules_file_name,
                               rule=info.rule,
                               msg=info.message.replace("\n", ";")
                    ))
                }

            )?;
        }
        super::common::print_compliant_skipped_info(writer, &passed, &skipped, rules_file_name, data_file_name)?;
        writeln!(writer, "--")?;
        Ok(())
    }
}
