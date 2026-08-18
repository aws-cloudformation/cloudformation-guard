use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io::Write;

use enumflags2::BitFlags;

use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::{EvaluationType, Status};

use super::common::*;
use super::summary_table::SummaryType;
use crate::rules::eval_context::{simplified_json_from_root, EventRecord};
use crate::rules::path_value::traversal::Traversal;
use crate::rules::values::CmpOperator;

#[derive(Debug)]
pub(crate) struct GenericSummary {
    summary_table: BitFlags<SummaryType>,
}

impl GenericSummary {
    pub(crate) fn new(summary_table: BitFlags<SummaryType>) -> Self {
        GenericSummary { summary_table }
    }
}

impl Reporter for GenericSummary {
    fn report(
        &self,
        writer: &mut dyn Write,
        _: Option<Status>,
        failed_rules: &[&StatusContext],
        passed_or_skipped: &[&StatusContext],
        longest_rule_name: usize,
        rules_file: &str,
        data_file: &str,
        _: &Traversal<'_>,
        output_format_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        let renderer = match output_format_type {
            OutputFormatType::SingleLineSummary => Box::new(SingleLineSummary {
                summary_table: self.summary_table,
            }) as Box<dyn GenericReporter>,
            OutputFormatType::JSON => {
                Box::new(StructuredSummary::new(StructureType::JSON)) as Box<dyn GenericReporter>
            }
            OutputFormatType::YAML => {
                Box::new(StructuredSummary::new(StructureType::YAML)) as Box<dyn GenericReporter>
            }
            OutputFormatType::Junit => unreachable!(),
            OutputFormatType::Sarif => unreachable!(),
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

        let as_vec = passed_or_skipped.to_vec();
        let (skipped, passed): (Vec<&StatusContext>, Vec<&StatusContext>) =
            as_vec.iter().partition(|status| match status.status {
                // This uses the dereference deep trait of Rust
                Some(Status::SKIP) => true,
                _ => false,
            });
        // The StatusContext path carries no record tree, so there is nothing to mine a reason
        // from: every skip here is reported without one. This is the pre-record reporting path;
        // the record-based path in `common::report_from_events` is where reasons come from.
        let skipped = skipped
            .iter()
            .map(|s| (s.context.clone(), None))
            .collect::<SkippedRules>();
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
        writer: &mut dyn Write,
        _status: Status,
        root_record: &EventRecord<'value>,
        rules_file: &str,
        data_file: &str,
        _data_file_bytes: &str,
        _data: &Traversal<'value>,
        output_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        let failure_repord = simplified_json_from_root(root_record)?;

        match output_type {
            OutputFormatType::JSON => serde_json::to_writer_pretty(writer, &failure_repord)?,
            OutputFormatType::YAML => serde_yaml::to_writer(writer, &failure_repord)?,
            OutputFormatType::SingleLineSummary => super::common::report_from_events(
                root_record,
                writer,
                data_file,
                rules_file,
                &(SingleLineSummary {
                    summary_table: self.summary_table,
                }),
            )?,
            OutputFormatType::Sarif => unreachable!(),
            OutputFormatType::Junit => unreachable!(),
        };

        Ok(())
    }
}

#[derive(Debug)]
struct SingleLineSummary {
    summary_table: BitFlags<SummaryType>,
}

impl SingleLineSummary {
    fn is_reportable(
        &self,
        failed: &HashMap<String, Vec<NameInfo<'_>>>,
        passed: &HashSet<String>,
        skipped: &SkippedRules,
    ) -> bool {
        if self.summary_table.is_empty() {
            return false;
        }

        if self.summary_table.contains(SummaryType::FAIL) {
            return !failed.is_empty();
        }

        if self.summary_table.contains(SummaryType::PASS) {
            return !passed.is_empty();
        }

        !skipped.is_empty() && self.summary_table.contains(SummaryType::SKIP)
    }
}

fn retrieval_error_message(
    _: &str,
    data_file: &str,
    info: &NameInfo<'_>,
) -> crate::rules::Result<String> {
    Ok(
        format!("Property traversed until [{path}] in data [{data}] is not compliant with [{rule}] due to retrieval error. Error Message [{msg}]",
                data=data_file,
                rule=info.rule,
                path=info.path,
                msg=info.error.as_ref().map_or("", |s| s)
        ),
    )
}

fn unary_error_message(
    _: &str,
    data_file: &str,
    op_msg: &str,
    info: &NameInfo<'_>,
) -> crate::rules::Result<String> {
    Ok(format!("Property [{path}] in data [{data}] is not compliant with [{rule}] because needed value at [{provided}] {op_msg}. Error Message [{msg}]",
               path=info.path,
               provided=info.provided.as_ref().map_or(&serde_json::Value::Null, std::convert::identity),
               op_msg=op_msg,
               data=data_file,
               rule=info.rule,
               msg=info.message.replace('\n', ";"),
    ))
}

fn binary_error_message(
    _: &str,
    data_file: &str,
    op_msg: &str,
    info: &NameInfo<'_>,
) -> crate::rules::Result<String> {
    Ok(format!(
        "Property [{path}] in data [{data}] is not compliant with [{rule}] because \
     provided value [{provided}] {op_msg} {cmp_msg} [{expected}]. Error \
     Message [{msg}]",
        path = info.path,
        provided = info
            .provided
            .as_ref()
            .map_or(&serde_json::Value::Null, std::convert::identity),
        op_msg = op_msg,
        data = data_file,
        rule = info.rule,
        msg = info.message.replace('\n', ";"),
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

fn print_rules_output(
    writer: &mut dyn Write,
    rules: HashSet<String>,
    descriptor: &str,
    data_file_name: &str,
) -> crate::rules::Result<()> {
    if !rules.is_empty() {
        writeln!(writer, "--")?;
    }
    for rule in rules {
        writeln!(
            writer,
            "Rule [{rule}] is {descriptor} for template [{data_file_name}]"
        )?;
    }

    Ok(())
}

/// Skipped rules, each followed by the evaluator's reason when it recorded one.
///
/// Separate from `print_rules_output` rather than a flag on it: that function also prints the
/// compliant set, which has no reasons, and threading an always-`None` argument through it to
/// serve one caller reads worse than two small functions.
fn print_skipped_rules_output(
    writer: &mut dyn Write,
    rules: SkippedRules,
    data_file_name: &str,
) -> crate::rules::Result<()> {
    if !rules.is_empty() {
        writeln!(writer, "--")?;
    }
    // Sorted so two runs over the same input produce the same output. The map is a HashMap, so
    // iterating it directly would reorder the lines between runs.
    let mut rules = rules.into_iter().collect::<Vec<(String, Option<String>)>>();
    rules.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (rule, reason) in rules {
        writeln!(
            writer,
            "Rule [{rule}] is not applicable for template [{data_file_name}]"
        )?;
        if let Some(reason) = reason {
            writeln!(writer, "  {reason}")?;
        }
    }

    Ok(())
}

impl GenericReporter for SingleLineSummary {
    fn report(
        &self,
        writer: &mut dyn Write,
        rules_file_name: &str,
        data_file_name: &str,
        failed: HashMap<String, Vec<NameInfo<'_>>>,
        passed: HashSet<String>,
        skipped: SkippedRules,
        longest_rule_len: usize,
    ) -> crate::rules::Result<()> {
        if !self.is_reportable(&failed, &passed, &skipped) {
            return Ok(());
        }
        writeln!(
            writer,
            "Evaluation of rules {} against data {}",
            rules_file_name, data_file_name
        )?;
        if self.summary_table.contains(SummaryType::FAIL) {
            if !failed.is_empty() {
                writeln!(writer, "--")?;
            }
            // Sorted by rule name. `failed` is a HashMap, so iterating it directly emitted the
            // failing rules in whatever order the hasher produced -- two runs of the same binary
            // over the same input printed the same findings in different orders. Verified before
            // and after: twelve identical runs produced two distinct outputs on the merge-base as
            // well as here, so this is pre-existing rather than introduced, but it makes report
            // diffing useless and any golden file covering two failing rules flaky.
            //
            // Sorting here rather than changing the map type, because the ordering is a property of
            // the report and every other reporter is free to choose its own.
            let mut failed = failed.into_iter().collect::<Vec<_>>();
            failed.sort_by(|(left, _), (right, _)| left.cmp(right));
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
        }
        if self.summary_table.contains(SummaryType::PASS) {
            print_rules_output(writer, passed, "compliant", data_file_name)?;
        }
        if self.summary_table.contains(SummaryType::SKIP) {
            print_skipped_rules_output(writer, skipped, data_file_name)?;
        }
        writeln!(writer, "--")?;
        Ok(())
    }
}
