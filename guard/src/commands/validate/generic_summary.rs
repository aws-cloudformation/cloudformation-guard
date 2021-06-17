use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io::Write;

use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::commands::validate::common::find_all_failing_clauses;
use crate::rules::{EvaluationType, Status};

use super::common::*;
use itertools::Itertools;

#[derive(Debug)]
pub(crate) struct GenericSummary<'a> {
    data_file_name: &'a str,
    rules_file_name: &'a str,
    output_format_type: OutputFormatType,
    renderer: Box<dyn GenericReporter + 'a>,
}

impl<'a> GenericSummary<'a> {
    pub(crate) fn new<'r>(data_file_name: &'r str,
                          rules_file_name: &'r str,
                          output_format_type: OutputFormatType) -> GenericSummary<'r> {
        GenericSummary {
            data_file_name,
            rules_file_name,
            output_format_type,
            renderer: match output_format_type {
                OutputFormatType::SingleLineSummary => Box::new(SingleLineSummary{}) as Box<dyn GenericReporter>,
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON)) as Box<dyn GenericReporter>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML)) as Box<dyn GenericReporter>,
            }
        }
    }
}

impl<'a> Reporter for GenericSummary<'a> {
    fn report(&self,
              writer: &mut dyn Write,
              _status: Option<Status>,
              failed_rules: &[&StatusContext],
              passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize) -> crate::rules::Result<()> {
        let failed = if !failed_rules.is_empty() {
            let mut by_rule = HashMap::with_capacity(failed_rules.len());
            for each_failed_rule in failed_rules {
                for each_failed_clause in find_all_failing_clauses(each_failed_rule) {
                    match each_failed_clause.eval_type {
                        EvaluationType::Clause |
                        EvaluationType::BlockClause => {
                            by_rule.entry(each_failed_rule.context.clone())
                                .or_insert(Vec::new())
                                .push(extract_name_info(&each_failed_rule.context, each_failed_clause)?);
                        }

                        _ => {}
                    }
                }
            }
            by_rule
        } else {
            HashMap::new()
        };

        let as_vec = passed_or_skipped.iter().map(|s| *s)
            .collect::<Vec<&StatusContext>>();
        let (skipped, passed): (Vec<&StatusContext>, Vec<&StatusContext>) = as_vec.iter()
            .partition(|status| match status.status { // This uses the dereference deep trait of Rust
                Some(Status::SKIP) => true,
                _ => false
            });
        let skipped = skipped.iter().map(|s| s.context.clone()).collect::<HashSet<String>>();
        let passed = passed.iter().map(|s| s.context.clone()).collect::<HashSet<String>>();
        self.renderer.report(writer, self.rules_file_name, self.data_file_name, failed, passed, skipped, longest_rule_name)?;
        Ok(())
    }
}

#[derive(Debug)]
struct SingleLineSummary{}

fn retrieval_error_message(rules_file: &str, data_file: &str, info: &NameInfo<'_>) -> crate::rules::Result<String> {
    Ok(format!("Property traversed until [{path}] in data [{data}] is not compliant with [{rules}/{rule}] due to retrieval error. Error Message [{msg}]",
       data=data_file,
       rules=rules_file,
       rule=info.rule,
       path=info.path,
       msg=info.message.replace("\n", ";"),
    ))
}

fn unary_error_message(rules_file: &str, data_file: &str, op_msg: &str, info: &NameInfo<'_>) -> crate::rules::Result<String> {
    Ok(format!("Property [{path}] in data [{data}] is not compliant with [{rules}/{rule}] because provided value [{provided}] {op_msg}. Error Message [{msg}]",
        path=info.path,
        provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
        op_msg=op_msg,
        data=data_file,
        rules=rules_file,
        rule=info.rule,
        msg=info.message.replace("\n", ";"),
    ))
}

fn binary_error_message(rules_file: &str, data_file: &str, op_msg: &str, info: &NameInfo<'_>) -> crate::rules::Result<String> {
    Ok(format!("Property [{path}] in data [{data}] is not compliant with [{rules}/{rule}] because provided value [{provided}] {op_msg} match expected value [{expected}]. Error Message [{msg}]",
               path=info.path,
               provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
               op_msg=op_msg,
               data=data_file,
               rules=rules_file,
               rule=info.rule,
               msg=info.message.replace("\n", ";"),
               expected=info.expected.as_ref().map_or(&serde_json::Value::Null, |v| v)
    ))
}

impl GenericReporter for SingleLineSummary {
    fn report(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              data_file_name: &str,
              failed: HashMap<String, Vec<NameInfo<'_>>>,
              passed: HashSet<String>,
              skipped: HashSet<String>, longest_rule_len: usize) -> crate::rules::Result<()>
    {
        writeln!(writer, "Evaluation of rules {} against data {}", rules_file_name, data_file_name)?;
        if !failed.is_empty() {
            writeln!(writer, "--");
        }
        for (_rule, clauses) in failed {
            super::common::print_name_info(
                writer,
                &clauses,
                longest_rule_len,
                rules_file_name,
                data_file_name,
                retrieval_error_message,
                unary_error_message,
                binary_error_message
            )?;
        }
        if !passed.is_empty() {
            writeln!(writer, "--");
        }
        for pass in passed {
            writeln!(writer, "Rule [{}/{}] is compliant for data [{}]", rules_file_name, pass, data_file_name);
        }

        if !skipped.is_empty() {
            writeln!(writer, "--");
        }
        for skip in skipped {
            writeln!(writer, "Rule [{}/{}] is not applicable for data [{}]", rules_file_name, skip, data_file_name);
        }
        writeln!(writer, "--");
        Ok(())
    }
}
