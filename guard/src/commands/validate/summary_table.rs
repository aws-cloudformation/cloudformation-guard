use crate::commands::tracker::StatusContext;
use crate::commands::validate::common::colored_string;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::eval_context::EventRecord;
use crate::rules::parser::get_rule_name;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::RecordType;
use crate::rules::{NamedStatus, Status};
use colored::*;
use enumflags2::{bitflags, BitFlags};
use itertools::Itertools;
use std::io::Write;

#[bitflags]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialOrd, PartialEq)]
pub(super) enum SummaryType {
    PASS = 0b0001,
    FAIL = 0b0010,
    SKIP = 0b0100,
}

#[derive(Debug)]
pub(super) struct SummaryTable<'reporter> {
    summary_type: BitFlags<SummaryType>,
    next: &'reporter dyn Reporter,
}

impl<'a> SummaryTable<'a> {
    pub(crate) fn new<'r>(
        summary_type: BitFlags<SummaryType>,
        next: &'r dyn Reporter,
    ) -> SummaryTable<'r> {
        SummaryTable { summary_type, next }
    }
}

fn print_partition(
    writer: &mut dyn Write,
    rules_file_name: &str,
    part: &[&StatusContext],
    longest: usize,
) -> crate::rules::Result<()> {
    for container in part {
        writeln!(
            writer,
            "{filename}/{context:<0$}{status}",
            longest + 4,
            filename = rules_file_name,
            context = get_rule_name(rules_file_name, &container.context),
            status = super::common::colored_string(container.status)
        )?;
    }
    Ok(())
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
    fn report(
        &self,
        writer: &mut dyn Write,
        status: Option<Status>,
        failed_rules: &[&StatusContext],
        passed_or_skipped: &[&StatusContext],
        longest_rule_name: usize,
        rules_file_name: &str,
        data_file_name: &str,
        _data: &Traversal<'_>,
        _output_format_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        let as_vec = passed_or_skipped.iter().map(|s| *s).collect_vec();
        let (skipped, passed): (Vec<&StatusContext>, Vec<&StatusContext>) =
            as_vec.iter().partition(|status| match status.status {
                // This uses the dereference deep trait of Rust
                Some(Status::SKIP) => true,
                _ => false,
            });

        let mut wrote_header_line = false;
        if self.summary_type.contains(SummaryType::SKIP) && !skipped.is_empty() {
            writeln!(
                writer,
                "{} Status = {}",
                data_file_name,
                colored_string(status)
            )?;
            wrote_header_line = true;
            writeln!(writer, "{}", "SKIP rules".bold())?;
            print_partition(writer, rules_file_name, &skipped, longest_rule_name)?;
        }

        if self.summary_type.contains(SummaryType::PASS) && !passed.is_empty() {
            writeln!(
                writer,
                "{} Status = {}",
                data_file_name,
                colored_string(status)
            )?;
            wrote_header_line = true;
            writeln!(writer, "{}", "PASS rules".bold())?;
            print_partition(writer, rules_file_name, &passed, longest_rule_name)?;
        }

        if self.summary_type.contains(SummaryType::FAIL) && !failed_rules.is_empty() {
            writeln!(
                writer,
                "{} Status = {}",
                data_file_name,
                colored_string(status)
            )?;
            wrote_header_line = true;
            writeln!(writer, "{}", "FAILED rules".bold())?;
            print_partition(writer, rules_file_name, failed_rules, longest_rule_name)?;
        }

        if wrote_header_line {
            writeln!(writer, "---")?;
        }
        self.next.report(
            writer,
            status,
            failed_rules,
            passed_or_skipped,
            longest_rule_name,
            rules_file_name,
            data_file_name,
            _data,
            _output_format_type,
        )
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
        let mut passed = indexmap::IndexMap::with_capacity(_root_record.children.len());
        let mut skipped = indexmap::IndexMap::with_capacity(_root_record.children.len());
        let mut failed = indexmap::IndexMap::with_capacity(_root_record.children.len());
        let mut longest = 0;
        for each_rule in &_root_record.children {
            if let Some(RecordType::RuleCheck(NamedStatus { status, name, .. })) =
                &each_rule.container
            {
                match status {
                    Status::PASS => passed.insert(*name, *status),
                    Status::FAIL => failed.insert(*name, *status),
                    Status::SKIP => skipped.insert(*name, *status),
                };
                let child_rule_name_length = get_rule_name(_rules_file, name).len(); //get_rule_name(_rules_file, name).len();
                if longest < child_rule_name_length {
                    longest = child_rule_name_length
                }
            }
        }

        skipped.retain(|key, _| !(passed.contains_key(key) || failed.contains_key(key)));

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
