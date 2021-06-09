use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;

use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::commands::validate::common::find_all_failing_clauses;
use crate::rules::{EvaluationType, Status};

use super::common::*;

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
            self.renderer.report(writer, self.rules_file_name, self.data_file_name, by_rule, longest_rule_name)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SingleLineSummary{}

impl GenericReporter for SingleLineSummary {
    fn report(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              data_file_name: &str,
              resources: HashMap<String, Vec<NameInfo<'_>>>,
              longest_rule_len: usize) -> crate::rules::Result<()> {

        writeln!(writer, "Evaluation of rules {} against data {}", rules_file_name, data_file_name)?;
        for (_rule, clauses) in resources {
            super::common::print_name_info(writer, &clauses, longest_rule_len, rules_file_name)?;
        }
        writeln!(writer, "-");
        Ok(())
    }
}

