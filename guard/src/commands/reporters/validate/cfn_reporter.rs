use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io::Write;

use fancy_regex::Regex;
use lazy_static::*;

use crate::commands::reporters::validate::common::{
    find_all_failing_clauses, GenericReporter, NameInfo, StructureType, StructuredSummary,
};
use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::errors::Error;

use crate::rules::eval_context::EventRecord;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::EvaluationType;
use crate::rules::Status;

lazy_static! {
    static ref CFN_RESOURCES: Regex = Regex::new(r"^/Resources/(?P<name>[^/]+)/(?P<rest>.*$)")
        .ok()
        .unwrap();
}

#[derive(Debug)]
pub(crate) struct CfnReporter {}

impl Reporter for CfnReporter {
    fn report(
        &self,
        writer: &mut dyn Write,
        _status: Option<Status>,
        failed_rules: &[&StatusContext],
        passed_or_skipped: &[&StatusContext],
        longest_rule_name: usize,
        rules_file: &str,
        data_file: &str,
        _data: &Traversal<'_>,
        output_format_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        let renderer =
            match output_format_type {
                OutputFormatType::SingleLineSummary => {
                    Box::new(SingleLineReporter {}) as Box<dyn GenericReporter>
                }
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON))
                    as Box<dyn GenericReporter>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML))
                    as Box<dyn GenericReporter>,
                OutputFormatType::Junit => unreachable!(),
                OutputFormatType::SARIF => unreachable!(),
            };
        let failed = if !failed_rules.is_empty() {
            let mut by_resource_name = HashMap::new();
            for (idx, each_failed_rule) in failed_rules.iter().enumerate() {
                let failed = find_all_failing_clauses(each_failed_rule);
                for (clause_idx, each_failing_clause) in failed.iter().enumerate() {
                    match each_failing_clause.eval_type {
                        EvaluationType::Clause | EvaluationType::BlockClause => {
                            if each_failing_clause.eval_type == EvaluationType::BlockClause {
                                match &each_failing_clause.msg {
                                    Some(msg) => {
                                        if msg.contains("DEFAULT") {
                                            continue;
                                        }
                                    }

                                    None => {
                                        continue;
                                    }
                                }
                            }
                            let mut resource_info = super::common::extract_name_info(
                                &each_failed_rule.context,
                                each_failing_clause,
                            )?;
                            let (resource_name, property_path) =
                                match CFN_RESOURCES.captures(&resource_info.path) {
                                    Ok(Some(caps)) => {
                                        (caps["name"].to_string(), caps["rest"].replace('/', "."))
                                    }
                                    Ok(None) => (
                                        format!(
                                            "Rule {} Resource {} {}",
                                            each_failed_rule.context, idx, clause_idx
                                        ),
                                        "".to_string(),
                                    ),
                                    Err(e) => return Err(Error::from(Box::new(e))),
                                };
                            resource_info.path = property_path;
                            by_resource_name
                                .entry(resource_name)
                                .or_insert(Vec::new())
                                .push(resource_info);
                        }

                        _ => unreachable!(),
                    }
                }
            }
            by_resource_name
        } else {
            HashMap::new()
        };
        let as_vec = passed_or_skipped.to_vec();
        let (skipped, passed): (Vec<&StatusContext>, Vec<&StatusContext>) =
            as_vec.iter().partition(|status| match status.status {
                // This uses the dereference deep trait of Rust
                Some(Status::SKIP) => true,
                _ => false,
            });
        let skipped = skipped
            .iter()
            .map(|s| s.context.clone())
            .collect::<HashSet<String>>();
        let passed = passed
            .iter()
            .map(|s| s.context.clone())
            .collect::<HashSet<String>>();
        renderer.report(
            writer,
            rules_file,
            data_file,
            failed,
            passed,
            skipped,
            longest_rule_name,
        )?;
        Ok(())
    }

    fn report_eval<'value>(
        &self,
        _write: &mut dyn Write,
        _status: Status,
        _root_record: &EventRecord<'value>,
        _rules_file: &str,
        _data_file: &str,
        _data_file_bytes: &str,
        _data: &Traversal<'value>,
        _output_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        let renderer =
            match _output_type {
                OutputFormatType::SingleLineSummary => {
                    Box::new(SingleLineReporter {}) as Box<dyn GenericReporter>
                }
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON))
                    as Box<dyn GenericReporter>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML))
                    as Box<dyn GenericReporter>,
                OutputFormatType::Junit => unreachable!(),
                OutputFormatType::SARIF => unreachable!(),
            };
        super::common::report_from_events(
            _root_record,
            _write,
            _data_file,
            _rules_file,
            renderer.as_ref(),
        )
    }
}

#[derive(Debug)]
struct SingleLineReporter {}

impl super::common::GenericReporter for SingleLineReporter {
    fn report(
        &self,
        writer: &mut dyn Write,
        rules_file_name: &str,
        data_file_name: &str,
        by_resource_name: HashMap<String, Vec<NameInfo<'_>>>,
        passed: HashSet<String>,
        skipped: HashSet<String>,
        longest_rule_len: usize,
    ) -> crate::rules::Result<()> {
        writeln!(
            writer,
            "Evaluation of rules {} for template {}, number of resource failures = {}",
            rules_file_name,
            data_file_name,
            by_resource_name.len()
        )?;
        if !by_resource_name.is_empty() {
            writeln!(writer, "--")?;
        }
        //
        // Agreed on text
        // Resource [NewVolume2] property [Properties.Encrypted] in template [template.json] is not compliant with [sg.guard/aws_ec2_volume_checks] because provided value [false] does not match with expected value [true]. Error Message [[EC2-008] : EC2 volumes should be encrypted]
        //
        for (resource, info) in by_resource_name.iter() {
            super::common::print_name_info(
                writer,
                info,
                longest_rule_len,
                rules_file_name,
                data_file_name,
                |_, _, info| {
                    Ok(format!("Resource [{}] traversed until [{}] for template [{}] wasn't compliant with [{}] due to retrieval error. Error Message [{}]",
                               resource,
                               info.path,
                               data_file_name,
                               info.rule,
                               info.message.replace('\n', ";")
                    ))
                },
                |_, _, op_msg, info| {
                    Ok(format!("Resource [{resource}] property [{property}] in template [{template}] is not compliant with [{rule}] because needed value at [{provided}] {op_msg}. Error message [{msg}]",
                               resource=resource,
                               property=info.path,
                               provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
                               op_msg=op_msg,
                               template=data_file_name,
                               rule= info.rule,
                               msg=info.message.replace('\n', ";")
                    ))
                },
                |_, _, msg, info| {
                    Ok(format!("Resource [{resource}] property [{property}] in template [{template}] is not compliant with [{rule}] because provided value [{provided}] {op_msg} match with expected value [{expected}]. Error message [{msg}]",
                               resource=resource,
                               property=info.path,
                               provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
                               op_msg=msg,
                               expected=info.expected.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
                               template=data_file_name,
                               rule=info.rule,
                               msg=info.message.replace('\n', ";")
                    ))
                },
            )?;
        }
        super::common::print_compliant_skipped_info(
            writer,
            &passed,
            &skipped,
            rules_file_name,
            data_file_name,
        )?;
        writeln!(writer, "--")?;
        Ok(())
    }
}
