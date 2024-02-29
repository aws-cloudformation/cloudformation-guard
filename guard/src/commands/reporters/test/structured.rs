use std::{convert::TryFrom, path::PathBuf, rc::Rc, time::Instant};

use crate::commands::reporters::test::{get_by_rules, get_status_result};
use crate::commands::reporters::{
    FailingTestCase, TestCase as JunitTestCase, TestCaseStatus, TestSuite,
};

use crate::commands::test::TestExpectations;
use crate::commands::{SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE};
use crate::rules::eval_context::Messages;
use serde::{Deserialize, Serialize};

use crate::{
    commands::{files::iterate_over, test::TestSpec, validate::OutputFormatType},
    rules::{
        errors::Error, eval::eval_rules_file, eval_context, exprs::RulesFile,
        path_value::PathAwareValue, Status,
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
pub struct Ok {
    pub rule_file: String,
    pub test_cases: Vec<TestCase>,
    #[serde(skip_serializing)] // NOTE: Only using this for junit
    pub time: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Err {
    pub rule_file: String,
    pub error: String,
    #[serde(skip_serializing)] // NOTE: Only using this for junit
    pub time: u128,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TestResult {
    Ok(Ok),
    Err(Err),
}

impl TestResult {
    pub fn get_exit_code(&self) -> i32 {
        match self {
            TestResult::Err(Err { .. }) => TEST_ERROR_STATUS_CODE,
            TestResult::Ok(Ok { test_cases, .. }) => {
                match test_cases.iter().any(|test_case| test_case.has_failures()) {
                    true => TEST_FAILURE_STATUS_CODE,
                    false => SUCCESS_STATUS_CODE,
                }
            }
        }
    }

    pub fn build_test_suite(&self) -> TestSuite {
        match self {
            TestResult::Err(Err {
                rule_file,
                error,
                time: test_result_time,
            }) => TestSuite::new(
                rule_file.to_string(),
                vec![JunitTestCase {
                    id: None,
                    name: rule_file,
                    time: *test_result_time,
                    status: TestCaseStatus::Error {
                        error: error.to_string(),
                    },
                }],
                *test_result_time,
                1,
                0,
            ),
            TestResult::Ok(Ok {
                rule_file,
                test_cases,
                ..
            }) => {
                let mut failures = 0;
                let mut time = 0;
                let test_cases = test_cases.iter().fold(vec![], |mut acc, tc| {
                    let mut test_cases = tc.build_junit_test_cases();
                    failures += tc.number_of_failures();
                    time += tc.time;
                    acc.append(&mut test_cases);
                    acc
                });

                TestSuite::new(rule_file.to_string(), test_cases, time, 0, failures)
            }
        }
    }

    fn insert_test_case(&mut self, tc: TestCase) {
        match self {
            TestResult::Err(Err { .. }) => unreachable!(),
            TestResult::Ok(result) => {
                result.time += tc.time;
                result.test_cases.push(tc);
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TestCase {
    name: String,
    passed_rules: Vec<PassedRule>,
    failed_rules: Vec<FailedRule>,
    skipped_rules: Vec<SkippedRule>,
    #[serde(skip_serializing)] // NOTE: Only using this for junit
    time: u128,
}

impl TestCase {
    fn has_failures(&self) -> bool {
        !self.failed_rules.is_empty()
    }

    fn number_of_failures(&self) -> usize {
        self.failed_rules.len()
    }

    fn build_junit_test_cases(&self) -> Vec<JunitTestCase> {
        let mut test_cases = vec![];

        for test_case in &self.passed_rules {
            test_cases.push(JunitTestCase {
                id: Some(&self.name),
                status: TestCaseStatus::Pass,
                name: &test_case.name,
                time: self.time,
            })
        }

        for test_case in &self.failed_rules {
            test_cases.push(JunitTestCase {
                id: Some(&self.name),
                status: TestCaseStatus::Fail(FailingTestCase {
                    name: None,
                    messages: vec![Messages {
                        location: None,
                        custom_message: None,
                        error_message: Some(format!(
                            "Expected = {}, Evaluated = [{}]",
                            test_case.expected,
                            test_case
                                .evaluated
                                .iter()
                                .fold(String::new(), |mut acc, status| {
                                    if !acc.is_empty() {
                                        acc.push_str(&format!(", {status}",))
                                    } else {
                                        acc.push_str(&format!("{status}"))
                                    }
                                    acc
                                })
                        )),
                    }],
                }),
                name: &test_case.name,
                time: self.time,
            })
        }

        test_cases
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
    pub fn evaluate(&mut self) -> crate::rules::Result<TestResult> {
        let ContextAwareRule { rule, name: file } = &self.rules;
        let now = Instant::now();
        let mut result = TestResult::Ok(Ok {
            rule_file: file.to_owned(),
            test_cases: vec![],
            time: 0,
        });

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
                    return Ok(TestResult::Err(Err {
                        rule_file: file.to_owned(),
                        error: e.to_string(),
                        time: now.elapsed().as_millis(),
                    }))
                }
                Ok(spec) => {
                    let test_data = get_test_data(spec)?;

                    for each in &test_data {
                        let now = Instant::now();
                        let mut root_scope =
                            eval_context::root_scope(rule, Rc::clone(&each.path_value));

                        eval_rules_file(rule, &mut root_scope, None)?;

                        let top = root_scope.reset_recorder().extract();

                        let by_rules = get_by_rules(&top);
                        let mut test_case = TestCase {
                            name: each.name.to_string(),
                            ..Default::default()
                        };

                        for (rule_name, records) in by_rules {
                            let expected = match each.expectations.rules.get(rule_name) {
                                Some(exp) => match Status::try_from(exp.as_str()) {
                                    Ok(exp) => exp,
                                    Err(e) => {
                                        return Ok(TestResult::Err(Err {
                                            rule_file: file.to_owned(),
                                            error: e.to_string(),
                                            time: now.elapsed().as_millis(),
                                        }))
                                    }
                                },
                                None => {
                                    test_case.skipped_rules.push(SkippedRule {
                                        name: rule_name.to_string(),
                                    });
                                    continue;
                                }
                            };

                            match get_status_result(expected, records) {
                                (Some(status), _) => test_case.passed_rules.push(PassedRule {
                                    name: rule_name.to_string(),
                                    evaluated: status,
                                }),

                                (None, statuses) => test_case.failed_rules.push(FailedRule {
                                    name: rule_name.to_string(),
                                    evaluated: statuses,
                                    expected,
                                }),
                            }
                        }

                        test_case.time = now.elapsed().as_millis();
                        result.insert_test_case(test_case);
                    }
                }
            }
        }

        Ok(result)
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
