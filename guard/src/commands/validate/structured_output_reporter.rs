use crate::commands::validate::{Reporter, OutputFormatType};
use std::io::Write;
use crate::rules::Status;
use crate::commands::tracker::StatusContext;
use crate::rules::eval_context::EventRecord;

#[derive(Debug)]
pub(crate) struct StructureOutputReporter<'a> {
    data_from: &'a str,
    rules_from: &'a str,
    output_type: OutputFormatType,
}

impl<'a> StructureOutputReporter<'a> {
    pub(crate) fn new<'r>(data: &'r str, rule: &'r str, out: OutputFormatType) -> StructureOutputReporter<'r> {
        StructureOutputReporter {
            data_from: data,
            rules_from: rule,
            output_type: out,
        }
    }
}

impl<'a> Reporter for StructureOutputReporter<'a> {

    fn report(&self,
              writer: &mut dyn Write,
              _status: Option<Status>,
              failed_rules: &[&StatusContext],
              passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize) -> crate::rules::Result<()> {
        Ok(())
    }

    fn report_eval(
        &self,
        write: &mut dyn Write,
        _status: Status,
        root_record: &EventRecord<'_>) -> crate::rules::Result<()> {
        writeln!(
            write,
            "{}",
            super::common::report_structured(
                root_record, self.data_from, self.rules_from, self.output_type
            )?
        )?;
        Ok(())
    }

}
