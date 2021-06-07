use crate::commands::validate::Reporter;
use std::io::Write;
use crate::commands::tracker::StatusContext;
use crate::rules::Status;
use colored::*;
use itertools::Itertools;
use enumflags2::{bitflags, BitFlags};

#[bitflags]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialOrd, PartialEq)]
pub(super) enum SummaryType {
    PASS = 0b0001,
    FAIL = 0b0010,
    SKIP = 0b0100,
}


#[derive(Debug)]
pub(super) struct SummaryTable<'r> {
    rules_file_name: &'r str,
    data_file_name: &'r str,
    summary_type: BitFlags<SummaryType>,
}

impl<'a> SummaryTable<'a> {
    pub(crate) fn new<'r>(rules_file_name: &'r str, data_file_name: &'r str, summary_type: BitFlags<SummaryType>) -> SummaryTable<'r> {
        SummaryTable {
            rules_file_name, data_file_name, summary_type
        }
    }
}

fn print_partition(writer: &mut dyn Write,
                   rules_file_name: &str,
                   part: &[&StatusContext],
                   longest: usize) -> crate::rules::Result<()> {
    for container in part {
        writeln!(writer,
                 "{filename}/{context:<0$}{status}",
                 longest+4,
                 filename=rules_file_name,
                 context=container.context,
                 status=super::common::colored_string(container.status)
        )?;
    }
    Ok(())
}


impl<'r> Reporter for SummaryTable<'r> {
    fn report(&self,
              writer: &mut dyn Write,
              failed_rules: &[&StatusContext],
              passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize) -> crate::rules::Result<()> {

        let as_vec = passed_or_skipped.iter().map(|s| *s)
            .collect_vec();
        let (skipped, passed): (Vec<&StatusContext>, Vec<&StatusContext>) = as_vec.iter()
            .partition(|status| match status.status { // This uses the dereference deep trait of Rust
                Some(Status::SKIP) => true,
                _ => false
            });

        if self.summary_type.contains(SummaryType::SKIP) && !skipped.is_empty() {
            writeln!(writer, "{}", "SKIP rules".bold());
            print_partition(writer, self.rules_file_name, &skipped, longest_rule_name)?;

        }

        if self.summary_type.contains(SummaryType::PASS) && !passed.is_empty() {
            writeln!(writer, "{}", "PASS rules".bold());
            print_partition(writer, self.rules_file_name, &passed, longest_rule_name)?;
        }

        if self.summary_type.contains(SummaryType::FAIL) && !failed_rules.is_empty() {
            writeln!(writer, "{}", "FAILED rules".bold());
            print_partition(writer, self.rules_file_name, failed_rules, longest_rule_name)?;
        }

        Ok(())
    }
}