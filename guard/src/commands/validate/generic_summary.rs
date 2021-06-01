use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;

use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Renderer};
use crate::commands::validate::common::find_all_failing_clauses;
use crate::rules::EvaluationType;

use super::common::*;

#[derive(Debug)]
pub(crate) struct GenericSummary<'a> {
    data_file_name: &'a str,
    rules_file_name: &'a str,
    output_format_type: OutputFormatType,
    renderer: Box<dyn GenericRenderer + 'a>,
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
                OutputFormatType::SingleLineSummary => Box::new(SingleLineSummary{}) as Box<dyn GenericRenderer>,
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON)) as Box<dyn GenericRenderer>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML)) as Box<dyn GenericRenderer>,
            }
        }
    }
}

impl<'a> Renderer for GenericSummary<'a> {
    fn render(&self,
              writer: &mut dyn Write,
              failed_rules: &[&StatusContext],
              _passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize) -> crate::rules::Result<()> {
        if !failed_rules.is_empty() {
            let mut by_rule = HashMap::with_capacity(failed_rules.len());
            for each_failed_rule in failed_rules {
                for each_failed_clause in find_all_failing_clauses(each_failed_rule) {
                    match each_failed_clause.eval_type {
                        EvaluationType::Clause |
                        EvaluationType::BlockClause => {
                            if each_failed_clause.from.is_some() {
                                by_rule.entry(each_failed_rule.context.clone())
                                    .or_insert(Vec::new())
                                    .push(extract_name_info(&each_failed_rule.context, each_failed_clause)?);
                            }
                        }

                        _ => {}
                    }
                }
            }
            self.renderer.render(writer, self.rules_file_name, self.data_file_name, by_rule, longest_rule_name)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SingleLineSummary{}

impl GenericRenderer for SingleLineSummary {
    fn render(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              _data_file_name: &str,
              resources: HashMap<String, Vec<NameInfo<'_>>>,
              longest_rule_len: usize) -> crate::rules::Result<()> {

        writeln!(writer, "{}", "Single Line Summary".underline())?;
        for (_rule, clauses) in resources {
            for info in clauses {
                let (did_or_didnt, operation, cmp) = match &info.comparison {
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
                match cmp {
                    None => {
                        // Block Clause retrieval error
                        writeln!(writer, "{0}/{1:<2$}{3} failed due to retrieval error, stopped at [{4}]. Error = [{5}]",
                                 rules_file_name,
                                 info.rule,
                                 longest_rule_len+4,
                                 operation,
                                 info.from,
                                 info.message.replace("\n", ";"))?;
                    },

                    Some(cmp) => {
                        if cmp.is_unary() {
                            writeln!(writer, "{0}/{1:<2$}{3} failed on value [{4}] at path {5}. Error Message [{6}]",
                                     rules_file_name,
                                     info.rule,
                                     longest_rule_len+4,
                                     operation,
                                     info.from,
                                     info.path,
                                     info.message.replace("\n", ";"))?;
                        }
                        else {
                            writeln!(writer, "{0}/{1:<2$}{3} failed for value [{4}] at path {7} {5} match with [{6}]. Error Message [{8}]",
                                     rules_file_name,
                                     info.rule,
                                     longest_rule_len + 4,
                                     operation,
                                     info.from,
                                     did_or_didnt,
                                     match &info.to { Some(v) => v, None => &serde_json::Value::Null },
                                     info.path,
                                     info.message.replace("\n", ";"))?;
                        }

                    }

                }
            }
        }
        Ok(())
    }
}

