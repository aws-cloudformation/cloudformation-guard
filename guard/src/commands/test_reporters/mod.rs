use std::{collections::HashMap, convert::TryFrom, path::PathBuf, rc::Rc};

use crate::commands::test::TestExpectations;
use serde::{Deserialize, Serialize};

use crate::{
    commands::{files::iterate_over, test::TestSpec, validate::OutputFormatType},
    rules::{
        errors::Error, eval::eval_rules_file, eval_context, exprs::RulesFile,
        path_value::PathAwareValue, NamedStatus, RecordType, Status,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ContextAwareRule<'rule> {
    pub rule: RulesFile<'rule>,
    pub name: String,
}

pub struct StructuredTestReporter<'reporter> {
    pub data_test_files: &'reporter [PathBuf],
    pub output: OutputFormatType,
    pub rules: ContextAwareRule<'reporter>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TestResult {
    Ok {
        rule_file: String,
        test_cases: Vec<TestCase>,
    },
    Err {
        rule_file: String,
        error: String,
    },
}

impl TestResult {
    pub fn get_exit_code(&self) -> i32 {
        match self {
            TestResult::Err { .. } => 1,
            TestResult::Ok { test_cases, .. } => {
                match test_cases.iter().any(|test_case| test_case.has_failures()) {
                    true => 7,
                    false => 0,
                }
            }
        }
    }

    fn insert_test_case(&mut self, tc: TestCase) {
        match self {
            TestResult::Err { .. } => unreachable!(),
            TestResult::Ok { test_cases, .. } => test_cases.push(tc),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TestCase {
    name: String,
    passed_rules: Vec<PassedRule>,
    failed_rules: Vec<FailedRule>,
    skipped_rules: Vec<SkippedRule>,
}

impl TestCase {
    fn has_failures(&self) -> bool {
        !self.failed_rules.is_empty()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PassedRule {
    name: String,
    evaluated: Status,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkippedRule {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FailedRule {
    name: String,
    expected: Status,
    evaluated: Vec<Status>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestData {
    name: String,
    path_value: Rc<PathAwareValue>,
    expectations: TestExpectations,
}

impl<'reporter> StructuredTestReporter<'reporter> {
    pub fn evaluate(&mut self) -> TestResult {
        let ContextAwareRule { rule, name: file } = &self.rules;
        let mut result = TestResult::Ok {
            rule_file: file.to_owned(),
            test_cases: vec![],
        };

        for specs in iterate_over(
            self.data_test_files,
            |data, path| match serde_yaml::from_str::<Vec<TestSpec>>(&data) {
                Ok(spec) => Ok(spec),
                Err(..) => match serde_json::from_str::<Vec<TestSpec>>(&data) {
                    Ok(spec) => Ok(spec),
                    Err(e) => Err(Error::ParseError(format!(
                        "Unable to process data in file {}, Error {}",
                        path.display(),
                        e
                    ))),
                },
            },
        ) {
            match specs {
                Err(e) => {
                    return TestResult::Err {
                        rule_file: file.to_owned(),
                        error: e.to_string(),
                    }
                }
                Ok(spec) => {
                    let test_data = match get_test_data(spec) {
                        Ok(res) => res,
                        Err(e) => {
                            return TestResult::Err {
                                rule_file: file.to_owned(),
                                error: e.to_string(),
                            }
                        }
                    };

                    for each in &test_data {
                        let mut root_scope =
                            eval_context::root_scope(rule, Rc::clone(&each.path_value));

                        if let Err(e) = eval_rules_file(rule, &mut root_scope, None) {
                            return TestResult::Err {
                                rule_file: file.to_owned(),
                                error: e.to_string(),
                            };
                        }

                        let top = root_scope.reset_recorder().extract();

                        let by_rules: HashMap<&str, Vec<&Option<RecordType<'_>>>> =
                            top.children.iter().fold(HashMap::new(), |mut acc, rule| {
                                if let Some(RecordType::RuleCheck(NamedStatus { name, .. })) =
                                    rule.container
                                {
                                    acc.entry(name).or_default().push(&rule.container)
                                }

                                acc
                            });

                        let mut test_case = TestCase {
                            name: each.name.to_string(),
                            ..Default::default()
                        };

                        for (rule_name, records) in by_rules {
                            let expected = match each.expectations.rules.get(rule_name) {
                                Some(exp) => match Status::try_from(exp.as_str()) {
                                    Ok(exp) => exp,
                                    Err(e) => {
                                        return TestResult::Err {
                                            rule_file: file.to_owned(),
                                            error: e.to_string(),
                                        }
                                    }
                                },
                                None => {
                                    test_case.skipped_rules.push(SkippedRule {
                                        name: rule_name.to_string(),
                                    });
                                    continue;
                                }
                            };

                            match evaluate_result(records, expected, rule_name) {
                                RecordResult::Pass(test) => test_case.passed_rules.push(test),
                                RecordResult::Fail(test) => test_case.failed_rules.push(test),
                            }
                        }

                        result.insert_test_case(test_case);
                    }
                }
            }
        }

        result
    }
}

enum RecordResult {
    Pass(PassedRule),
    Fail(FailedRule),
}

#[allow(clippy::never_loop)]
fn evaluate_result(
    records: Vec<&Option<RecordType<'_>>>,
    expected: Status,
    rule_name: &str,
) -> RecordResult {
    let mut statuses = Vec::with_capacity(records.len());

    let matched = 'matched: loop {
        let mut all_skipped = 0;

        for each in records.iter().copied().flatten() {
            if let RecordType::RuleCheck(NamedStatus {
                status: got_status, ..
            }) = each
            {
                match expected {
                    Status::SKIP => {
                        if *got_status == Status::SKIP {
                            all_skipped += 1;
                        }
                    }

                    rest => {
                        if *got_status == rest {
                            break 'matched Some(expected);
                        }
                    }
                }
                statuses.push(*got_status)
            }
        }

        if expected == Status::SKIP && all_skipped == records.len() {
            break 'matched Some(expected);
        }

        break 'matched None;
    };

    match matched {
        Some(status) => RecordResult::Pass(PassedRule {
            name: rule_name.to_string(),
            evaluated: status,
        }),

        None => RecordResult::Fail(FailedRule {
            name: rule_name.to_string(),
            evaluated: statuses,
            expected,
        }),
    }
}

fn get_test_data(specs: Vec<TestSpec>) -> crate::rules::Result<Vec<TestData>> {
    specs.into_iter().try_fold(
        vec![],
        |mut acc,
         TestSpec {
             name,
             input,
             expectations,
         }| {
            let root = PathAwareValue::try_from(input)?;
            acc.push(TestData {
                name: name.unwrap_or_default(),
                path_value: Rc::new(root),
                expectations,
            });

            Ok(acc)
        },
    )
}
