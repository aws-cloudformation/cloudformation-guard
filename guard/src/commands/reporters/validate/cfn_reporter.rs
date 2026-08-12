use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::io::Write;

use fancy_regex::Regex;
use lazy_static::*;

use crate::commands::reporters::validate::common::{
    GenericReporter, NameInfo, SkippedRules, StructureType, StructuredSummary,
};
use crate::commands::validate::{OutputFormatType, Reporter};

use crate::rules::eval_context::EventRecord;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::Status;

lazy_static! {
    static ref CFN_RESOURCES: Regex = Regex::new(r"^/Resources/(?P<name>[^/]+)/(?P<rest>.*$)")
        .ok()
        .unwrap();
}

#[derive(Debug)]
pub(crate) struct CfnReporter {}

impl Reporter for CfnReporter {
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
                OutputFormatType::Sarif => unreachable!(),
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
        skipped: SkippedRules,
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
        // This reporter does not surface skip reasons, so the names are all it needs.
        let skipped = skipped.into_keys().collect::<HashSet<String>>();
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
