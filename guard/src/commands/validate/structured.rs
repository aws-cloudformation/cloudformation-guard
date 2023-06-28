use std::rc::Rc;

use crate::commands::validate::{parse_rules, DataFile, OutputFormatType, RuleFileInfo};
use crate::rules;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::{root_scope, simplifed_json_from_root, FileReport};
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Status;
use crate::utils::writer::Writer;
use colored::Colorize;

pub struct StructuredEvaluator<'eval> {
    pub(crate) rule_info: &'eval [RuleFileInfo],
    pub(crate) input_params: Option<PathAwareValue>,
    pub(crate) data: Vec<DataFile>,
    pub(crate) output: OutputFormatType,
    pub(crate) writer: &'eval mut Writer,
    pub(crate) exit_code: i32,
}

impl<'eval> StructuredEvaluator<'eval> {
    fn merge_input_params_with_data(&mut self) -> Vec<DataFile> {
        self.data.iter().fold(vec![], |mut res, file| {
            let each = match &self.input_params {
                Some(data) => data.clone().merge(file.path_value.clone()).unwrap(),
                None => file.path_value.clone(),
            };

            let merged_file_data = DataFile {
                path_value: each,
                name: file.name.to_owned(),
                content: "".to_string(), // not used later on
            };

            res.push(merged_file_data);
            res
        })
    }

    fn get_rules(&mut self) -> rules::Result<Vec<RulesFile<'eval>>> {
        self.rule_info.iter().try_fold(
            vec![],
            |mut rules, RuleFileInfo { file_name, content }| -> rules::Result<Vec<RulesFile>> {
                match parse_rules(content, file_name) {
                    Err(e) => {
                        self.writer.write_err(format!(
                            "Parsing error handling rule file = {}, Error = {e}\n---",
                            file_name.underline()
                        ))?;
                        self.exit_code = 5;
                    }
                    Ok(rule) => rules.push(rule),
                }
                Ok(rules)
            },
        )
    }

    pub(crate) fn evaluate(&mut self) -> rules::Result<i32> {
        let rules = self.get_rules()?;
        let merged_data = self.merge_input_params_with_data();

        let mut records = vec![];

        for each in &merged_data {
            let mut file_report: FileReport = FileReport {
                name: &each.name,
                ..Default::default()
            };

            for rule in &rules {
                let mut root_scope = root_scope(rule, Rc::new(each.path_value.clone()))?;

                if let Status::FAIL = eval_rules_file(rule, &mut root_scope, Some(&each.name))? {
                    self.exit_code = 19;
                }

                let root_record = root_scope.reset_recorder().extract();
                let report = simplifed_json_from_root(&root_record)?;
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
