use std::rc::Rc;

use crate::commands::reporters::JunitReporter;
use crate::commands::validate::{parse_rules, DataFile, OutputFormatType, RuleFileInfo};
use crate::commands::{ERROR_STATUS_CODE, FAILURE_STATUS_CODE};
use crate::rules;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::{root_scope, simplified_json_from_root, FileReport};
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Status;
use crate::utils::writer::Writer;
use colored::Colorize;

pub(crate) trait StructuredReporter {
    fn report(&mut self) -> rules::Result<i32>;
}

pub struct StructuredEvaluator<'eval> {
    pub(crate) rule_info: &'eval [RuleFileInfo],
    pub(crate) input_params: Option<PathAwareValue>,
    pub(crate) data: Vec<DataFile>,
    pub(crate) output: OutputFormatType,
    pub(crate) writer: &'eval mut Writer,
    pub(crate) exit_code: i32,
}

impl<'eval> StructuredEvaluator<'eval> {
    pub(crate) fn evaluate(&mut self) -> rules::Result<i32> {
        let rules = self.rule_info.iter().try_fold(
            vec![],
            |mut rules,
             RuleFileInfo { file_name, content }|
             -> rules::Result<Vec<(RulesFile, &str)>> {
                match parse_rules(content, file_name) {
                    Err(e) => {
                        self.writer.write_err(format!(
                            "Parsing error handling rule file = {}, Error = {e}\n---",
                            file_name.underline()
                        ))?;
                        self.exit_code = ERROR_STATUS_CODE;
                    }
                    Ok(Some(rule)) => rules.push((rule, file_name)),
                    Ok(None) => {}
                }
                Ok(rules)
            },
        )?;

        let merged_data = self.data.iter().fold(vec![], |mut res, file| {
            let each = match &self.input_params {
                Some(data) => data.clone().merge(file.path_value.clone()).unwrap(),
                None => file.path_value.clone(),
            };

            let merged_file_data = DataFile {
                path_value: each,
                name: file.name.to_owned(),
                content: String::default(),
            };

            res.push(merged_file_data);
            res
        });

        let mut reporter = match self.output {
            OutputFormatType::Junit => Box::new(JunitReporter {
                data: merged_data,
                rules,
                writer: self.writer,
                exit_code: self.exit_code,
            }) as Box<dyn StructuredReporter>,
            OutputFormatType::JSON | OutputFormatType::YAML => Box::new(CommonStructuredReporter {
                rules,
                data: merged_data,
                writer: self.writer,
                exit_code: self.exit_code,
                output: self.output,
            })
                as Box<dyn StructuredReporter>,
            OutputFormatType::SingleLineSummary => unreachable!(),
        };

        reporter.report()
    }
}

struct CommonStructuredReporter<'reporter> {
    rules: Vec<(RulesFile<'reporter>, &'reporter str)>,
    data: Vec<DataFile>,
    writer: &'reporter mut crate::utils::writer::Writer,
    exit_code: i32,
    output: OutputFormatType,
}

impl<'reporter> StructuredReporter for CommonStructuredReporter<'reporter> {
    fn report(&mut self) -> rules::Result<i32> {
        let mut records = vec![];
        for each in &self.data {
            let mut file_report: FileReport = FileReport {
                name: &each.name,
                ..Default::default()
            };

            for (rule, _) in &self.rules {
                let mut root_scope = root_scope(rule, Rc::new(each.path_value.clone()));

                if let Status::FAIL = eval_rules_file(rule, &mut root_scope, Some(&each.name))? {
                    self.exit_code = FAILURE_STATUS_CODE;
                }

                let root_record = root_scope.reset_recorder().extract();
                let report = simplified_json_from_root(&root_record)?;
                file_report.combine(report);
            }

            records.push(file_report);
        }

        match self.output {
            OutputFormatType::YAML => serde_yaml::to_writer(&mut self.writer, &records)?,
            OutputFormatType::JSON => serde_json::to_writer_pretty(&mut self.writer, &records)?,
            _ => unreachable!(),
        };

        Ok(self.exit_code)
    }
}
