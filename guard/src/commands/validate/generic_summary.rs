use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io::Write;
use std::rc::Rc;

use crate::commands::tracker::StatusContext;
use crate::commands::validate::common::find_all_failing_clauses;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::{EvaluationType, Status};

use super::common::*;
use crate::rules::eval_context::EventRecord;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::values::CmpOperator;

#[derive(Debug)]
pub(crate) struct GenericSummary {}

impl GenericSummary {
    pub(crate) fn new() -> Self {
        GenericSummary {}
    }
}

impl Reporter for GenericSummary {
    fn report(
        &self,
        writer: &mut dyn Write,
        status: Option<Status>,
        failed_rules: &[&StatusContext],
        passed_or_skipped: &[&StatusContext],
        longest_rule_name: usize,
        rules_file: &str,
        data_file: &str,
        data: &Traversal<'_>,
        output_format_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        let renderer =
            match output_format_type {
                OutputFormatType::SingleLineSummary => {
                    Box::new(SingleLineSummary {}) as Box<dyn GenericReporter>
                }
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON))
                    as Box<dyn GenericReporter>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML))
                    as Box<dyn GenericReporter>,
            };
        let failed = if !failed_rules.is_empty() {
            let mut by_rule = HashMap::with_capacity(failed_rules.len());
            for each_failed_rule in failed_rules {
                for each_failed_clause in find_all_failing_clauses(each_failed_rule) {
                    match each_failed_clause.eval_type {
                        EvaluationType::Clause | EvaluationType::BlockClause => {
                            if each_failed_clause.eval_type == EvaluationType::BlockClause {
                                match &each_failed_clause.msg {
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
                            by_rule
                                .entry(each_failed_rule.context.clone())
                                .or_insert(Vec::new())
                                .push(extract_name_info(
                                    &each_failed_rule.context,
                                    each_failed_clause,
                                )?);
                        }

                        _ => {}
                    }
                }
            }
            by_rule
        } else {
            HashMap::new()
        };

        let as_vec = passed_or_skipped
            .iter()
            .map(|s| *s)
            .collect::<Vec<&StatusContext>>();
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
                    Box::new(SingleLineSummary {}) as Box<dyn GenericReporter>
                }
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON))
                    as Box<dyn GenericReporter>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML))
                    as Box<dyn GenericReporter>,
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
struct SingleLineSummary {}

fn retrieval_error_message(
    rules_file: &str,
    data_file: &str,
    info: &NameInfo<'_>,
) -> crate::rules::Result<String> {
    Ok(format!("Property traversed until [{path}] in data [{data}] is not compliant with [{rules}/{rule}] due to retrieval error. Error Message [{msg}]",
       data=data_file,
       rules=rules_file,
       rule=info.rule,
       path=info.path,
       msg=info.error.as_ref().map_or("", |s| s)
    ))
}

fn unary_error_message(
    rules_file: &str,
    data_file: &str,
    op_msg: &str,
    info: &NameInfo<'_>,
) -> crate::rules::Result<String> {
    Ok(format!("Property [{path}] in data [{data}] is not compliant with [{rules}/{rule}] because needed value at [{provided}] {op_msg}. Error Message [{msg}]",
        path=info.path,
        provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
        op_msg=op_msg,
        data=data_file,
        rules=rules_file,
        rule=info.rule,
        msg=info.message.replace("\n", ";"),
    ))
}

fn binary_error_message(
    rules_file: &str,
    data_file: &str,
    op_msg: &str,
    info: &NameInfo<'_>,
) -> crate::rules::Result<String> {
    Ok(format!(
        "Property [{path}] in data [{data}] is not compliant with [{rules}/{rule}] because \
     provided value [{provided}] {op_msg} {cmp_msg} [{expected}]. Error \
     Message [{msg}]",
        path = info.path,
        provided = info
            .provided
            .as_ref()
            .map_or(&serde_json::Value::Null, std::convert::identity),
        op_msg = op_msg,
        data = data_file,
        rules = rules_file,
        rule = info.rule,
        msg = info.message.replace("\n", ";"),
        expected = info
            .expected
            .as_ref()
            .map_or(&serde_json::Value::Null, |v| v),
        cmp_msg = info.comparison.as_ref().map_or("", |c| {
            if c.operator == CmpOperator::In {
                "match expected value in"
            } else {
                "match expected value"
            }
        })
    ))
}

impl GenericReporter for SingleLineSummary {
    fn report(
        &self,
        mut writer: &mut dyn std::io::Write,
        rules_file_name: &str,
        data_file_name: &str,
        failed: HashMap<String, Vec<NameInfo<'_>>>,
        passed: HashSet<String>,
        skipped: HashSet<String>,
        longest_rule_len: usize,
    ) -> crate::rules::Result<()> {
        writeln!(
            writer,
            "Evaluation of rules {} against data {}",
            rules_file_name, data_file_name
        )?;
        if !failed.is_empty() {
            writeln!(writer, "--")?;
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
                binary_error_message,
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
