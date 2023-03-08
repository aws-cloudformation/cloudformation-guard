use crate::commands::files::iterate_over;
use crate::commands::validate;
use crate::commands::validate::{DataFile, OutputFormatType};
use crate::rules;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::{root_scope, simplifed_json_from_root};
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Status;
use crate::utils::writer::Writer;
use colored::Colorize;
use std::path::PathBuf;

pub struct StructuredEvaluator<'eval> {
    pub(crate) rule_files: &'eval [PathBuf],
    pub(crate) input_params: Option<PathAwareValue>,
    pub(crate) data: Vec<DataFile>,
    pub(crate) output: OutputFormatType,
    pub(crate) writer: &'eval mut Writer,
    pub(crate) status_code: i32,
}

impl<'eval> StructuredEvaluator<'eval> {
    // parse all rule content, and file names from a list of paths for rules
    // this is needed because we need to guarantee the reference to this data is valid
    fn get_rule_info(&mut self) -> rules::Result<Vec<RuleFileInfo>> {
        iterate_over(self.rule_files, |content, file| {
            Ok((content, validate::get_file_name(file, file)))
        })
        .try_fold(
            vec![],
            |mut res, rule| -> rules::Result<Vec<RuleFileInfo>> {
                match rule {
                    Err(e) => {
                        self.writer
                            .write_err(format!("Unable to read content from file {e}"))?;
                        return Err(e);
                    }
                    Ok((content, file_name)) => res.push(RuleFileInfo { content, file_name }),
                }

                Ok(res)
            },
        )
    }

    fn merge_input_params_with_data(&mut self) -> Vec<PathAwareValue> {
        self.data.iter().fold(vec![], |mut res, file| {
            let each = match &self.input_params {
                Some(data) => data.clone().merge(file.path_value.clone()).unwrap(),
                None => file.path_value.clone(),
            };

            res.push(each);
            res
        })
    }

    fn report(&mut self, rules: Vec<RulesFile>) -> rules::Result<()> {
        let merged_data = self.merge_input_params_with_data();
        let mut records = vec![];

        for rule in &rules {
            for each in &merged_data {
                let mut root_scope = root_scope(rule, each)?;

                if let Status::FAIL = eval_rules_file(rule, &mut root_scope)? {
                    self.status_code = 5;
                }

                let root_record = root_scope.reset_recorder().extract();

                let report = simplifed_json_from_root(&root_record)?;
                records.push(report)
            }
        }

        match self.output {
            OutputFormatType::YAML => serde_yaml::to_writer(&mut self.writer, &records)?,
            OutputFormatType::JSON => serde_json::to_writer_pretty(&mut self.writer, &records)?,
            _ => unreachable!(),
        };

        Ok(())
    }

    pub(crate) fn evaluate(&mut self) -> rules::Result<i32> {
        let info = self.get_rule_info()?;
        let mut rules = vec![];

        for RuleFileInfo { file_name, content } in &info {
            let span = rules::parser::Span::new_extra(content, file_name);

            match rules::parser::rules_file(span) {
                Err(e) => {
                    self.writer.write_err(format!(
                        "Parsing error handling rule file = {}, Error = {e}\n---",
                        file_name.underline()
                    ))?;
                    self.status_code = 5;
                }
                Ok(rule) => rules.push(rule),
            };
        }

        self.report(rules)?;

        Ok(self.status_code)
    }
}

#[derive(Default)]
struct RuleFileInfo {
    content: String,
    file_name: String,
}
