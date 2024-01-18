use std::{collections::HashMap, convert::TryFrom, io::Write, path::PathBuf, rc::Rc};

use serde::{Deserialize, Serialize};

use crate::{
    commands::{files::iterate_over, test::TestSpec, validate::OutputFormatType},
    rules::{
        errors::Error, eval::eval_rules_file, eval_context, exprs::RulesFile,
        path_value::PathAwareValue, NamedStatus, RecordType, Status,
    },
    utils::writer::Writer,
};

pub struct StructuredTestReporter<'reporter> {
    specs: &'reporter [PathBuf],
    output: OutputFormatType,
    writer: &'reporter mut Writer,
    rules: Vec<(String, RulesFile<'reporter>)>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TestResult {
    rule_file: String,
    test_cases: Vec<TestCase>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TestCase {
    name: String,
    passed_rules: Vec<PassedRule>,
    failed_rules: Vec<FailedRule>,
    skipped_rules: Vec<SkippedRule>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PassedRule {
    name: String,
    evaluated: Status,
}

#[derive(Debug, Serialize, Deserialize)]
struct SkippedRule {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FailedRule {
    name: String,
    expected: Status,
    evaluated: Status,
}

impl<'reporter> StructuredTestReporter<'reporter> {
    fn evaluate(&mut self) -> crate::rules::Result<i32> {
        let mut exit_code = 0;
        let mut test_counter = 1;

        // let mut results = vec![];
        for specs in iterate_over(self.specs, |data, path| {
            match serde_yaml::from_str::<Vec<TestSpec>>(&data) {
                Ok(spec) => Ok(spec),
                Err(..) => match serde_json::from_str::<Vec<TestSpec>>(&data) {
                    Ok(spec) => Ok(spec),
                    Err(e) => Err(Error::ParseError(format!(
                        "Unable to process data in file {}, Error {}",
                        path.display(),
                        e
                    ))),
                },
            }
        }) {
            match specs {
                Err(e) => {
                    writeln!(self.writer, "Error processing {e}")?;
                    return Ok(1);
                }
                Ok(spec) => {
                    for (file, rule) in &self.rules {
                        let mut result = TestResult {
                            rule_file: file.to_owned(),
                            test_cases: vec![],
                        };
                        for each in &spec {
                            // let by_result = HashMap::new();
                            let root = PathAwareValue::try_from(&each.input)?;

                            let mut root_scope = eval_context::root_scope(rule, Rc::new(root));

                            eval_rules_file(rule, &mut root_scope, None)?;

                            let top = root_scope.reset_recorder().extract();

                            let by_rules: HashMap<&str, Vec<&Option<RecordType<'_>>>> =
                                top.children.iter().fold(HashMap::new(), |mut acc, rule| {
                                    if let Some(RecordType::RuleCheck(NamedStatus {
                                        name, ..
                                    })) = rule.container
                                    {
                                        acc.entry(name).or_default().push(&rule.container)
                                    }

                                    acc
                                });

                            let mut test_case = TestCase {
                                name: each.name.unwrap_or_default(),
                                ..Default::default()
                            };
                            for (rule_name, r) in by_rules {
                                let expected = match each.expectations.rules.get(rule_name) {
                                    Some(exp) => Status::try_from(exp.as_str())?,
                                    None => {
                                        test_case.skipped_rules.push(SkippedRule {
                                            name: rule_name.to_string(),
                                        });
                                        continue;
                                    }
                                };
                            }

                            result.test_cases.push(test_case);
                        }
                    }
                }
            }
        }

        Ok(exit_code)
    }
}
