use crate::commands::reporters::validate::common::colored_string;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::eval_context::{find_skip_reason, EventRecord};
use crate::rules::parser::get_rule_name;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::RecordType;
use crate::rules::{NamedStatus, Status};
use colored::*;
use enumflags2::{bitflags, BitFlags};
use std::io::Write;

#[bitflags]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialOrd, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum SummaryType {
    PASS = 0b0001,
    FAIL = 0b0010,
    SKIP = 0b0100,
}

#[derive(Debug)]
pub struct SummaryTable<'reporter> {
    summary_type: BitFlags<SummaryType>,
    next: &'reporter dyn Reporter,
}

impl<'a> SummaryTable<'a> {
    pub(crate) fn new(
        summary_type: BitFlags<SummaryType>,
        next: &dyn Reporter,
    ) -> SummaryTable<'_> {
        SummaryTable { summary_type, next }
    }
}

fn print_summary(
    writer: &mut dyn Write,
    rules_file_name: &str,
    longest: usize,
    rules: &indexmap::IndexMap<&str, Status>,
) -> crate::rules::Result<()> {
    for (rule_name, status) in rules.iter() {
        writeln!(
            writer,
            "{filename}/{context:<0$}{status}",
            longest + 4,
            filename = rules_file_name,
            context = get_rule_name(rules_file_name, rule_name),
            status = super::common::colored_string(Some(*status))
        )?;
    }
    Ok(())
}

impl<'r> Reporter for SummaryTable<'r> {
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
        let mut passed = indexmap::IndexMap::with_capacity(_root_record.children.len());
        let mut skipped = indexmap::IndexMap::with_capacity(_root_record.children.len());
        // Why each skipped rule did not apply, for the ones the evaluator can explain. A rule that
        // reports "not applicable" and nothing else is indistinguishable from one that ran and
        // passed, and both exit 0.
        let mut skip_reasons: indexmap::IndexMap<&str, String> = indexmap::IndexMap::new();
        let mut failed = indexmap::IndexMap::with_capacity(_root_record.children.len());
        let mut longest = 0;
        for each_rule in &_root_record.children {
            if let Some(RecordType::RuleCheck(NamedStatus { status, name, .. })) =
                &each_rule.container
            {
                match status {
                    Status::PASS => passed.insert(*name, *status),
                    Status::FAIL => failed.insert(*name, *status),
                    Status::SKIP => {
                        if let Some(reason) = find_skip_reason(each_rule) {
                            skip_reasons.insert(*name, reason);
                        }
                        skipped.insert(*name, *status)
                    }
                };
                let child_rule_name_length = get_rule_name(_rules_file, name).len(); //get_rule_name(_rules_file, name).len();
                if longest < child_rule_name_length {
                    longest = child_rule_name_length
                }
            }
        }

        skipped.retain(|key, _| !(passed.contains_key(key) || failed.contains_key(key)));
        skip_reasons.retain(|key, _| skipped.contains_key(key));

        let mut wrote_header_line = false;
        if self.summary_type.contains(SummaryType::SKIP) && !skipped.is_empty() {
            writeln!(
                _write,
                "{} Status = {}",
                _data_file,
                colored_string(Some(_status))
            )?;
            wrote_header_line = true;
            writeln!(_write, "{}", "SKIP rules".bold())?;
            print_summary(_write, _rules_file, longest, &skipped)?;
            for (rule_name, reason) in skip_reasons.iter() {
                writeln!(
                    _write,
                    "  {rule}: {reason}",
                    rule = get_rule_name(_rules_file, rule_name)
                )?;
            }
        }

        if self.summary_type.contains(SummaryType::PASS) && !passed.is_empty() {
            if !wrote_header_line {
                wrote_header_line = true;
                writeln!(
                    _write,
                    "{} Status = {}",
                    _data_file,
                    colored_string(Some(_status))
                )?;
            }
            writeln!(_write, "{}", "PASS rules".bold())?;
            print_summary(_write, _rules_file, longest, &passed)?;
        }

        if self.summary_type.contains(SummaryType::FAIL) && !failed.is_empty() {
            if !wrote_header_line {
                wrote_header_line = true;
                writeln!(
                    _write,
                    "{} Status = {}",
                    _data_file,
                    colored_string(Some(_status))
                )?;
            }
            writeln!(_write, "{}", "FAILED rules".bold())?;
            print_summary(_write, _rules_file, longest, &failed)?;
        }

        if wrote_header_line {
            writeln!(_write, "---")?;
        }

        self.next.report_eval(
            _write,
            _status,
            _root_record,
            _rules_file,
            _data_file,
            _data_file_bytes,
            _data,
            _output_type,
        )
    }
}
