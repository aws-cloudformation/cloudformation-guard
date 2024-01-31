use std::{collections::HashMap, convert::TryFrom, path::PathBuf, rc::Rc, time::Instant};

use crate::commands::test::TestExpectations;
use crate::commands::validate::xml::{
    FailingTestCase, TestCase as JunitTestCase, TestCaseStatus, TestSuite,
};
use crate::commands::{SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE};
use crate::rules::eval_context::Messages;
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
pub struct Ok {
    pub rule_file: String,
    pub test_cases: Vec<TestCase>,
    #[serde(skip_serializing)] // NOTE: Only using this for junit
    pub time: u128,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TestResult {
    Ok(Ok),
    Err {
        rule_file: String,
        error: String,
        #[serde(skip_serializing)] // NOTE: Only using this for junit
        time: u128,
    },
}

impl TestResult {
    pub fn get_exit_code(&self) -> i32 {
        match self {
            TestResult::Err { .. } => TEST_ERROR_STATUS_CODE,
            TestResult::Ok(Ok { test_cases, .. }) => {
                match test_cases.iter().any(|test_case| test_case.has_failures()) {
                    true => TEST_FAILURE_STATUS_CODE,
                    false => SUCCESS_STATUS_CODE,
                }
            }
        }
    }

    pub fn build_test_suite(&self) -> TestSuite {
        let mut failures = 0;
        let mut time = 0;

        match self {
            TestResult::Err {
                rule_file: name,
                error,
                time: test_result_time,
            } => TestSuite {
                name: name.to_string(),
                test_cases: vec![JunitTestCase {
                    id: None,
                    name,
                    time: *test_result_time,
                    status: TestCaseStatus::Error {
                        error: error.to_string(),
                    },
                }],
                time: *test_result_time,
                errors: 1,
                failures: 0,
            },
            TestResult::Ok(Ok {
                rule_file: name,
                test_cases,
                ..
            }) => {
                let test_cases = test_cases.iter().fold(vec![], |mut acc, tc| {
                    let mut test_cases = tc.build_junit_test_cases();
                    failures += tc.number_of_failures();
                    time += tc.time;
                    acc.append(&mut test_cases);
                    acc
                });

                TestSuite {
                    name: name.to_string(),
                    test_cases,
                    time,
                    errors: 0,
                    failures,
                }
            }
        }
    }

    fn insert_test_case(&mut self, tc: TestCase) {
        match self {
            TestResult::Err { .. } => unreachable!(),
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
                    return Ok(TestResult::Err {
                        rule_file: file.to_owned(),
                        error: e.to_string(),
                        time: now.elapsed().as_millis(),
                    })
                }
                Ok(spec) => {
                    let test_data = get_test_data(spec)?;

                    for each in &test_data {
                        let now = Instant::now();
                        let mut root_scope =
                            eval_context::root_scope(rule, Rc::clone(&each.path_value));

                        eval_rules_file(rule, &mut root_scope, None)?;

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
                                        return Ok(TestResult::Err {
                                            rule_file: file.to_owned(),
                                            error: e.to_string(),
                                            time: now.elapsed().as_millis(),
                                        })
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

                        test_case.time = now.elapsed().as_millis();
                        result.insert_test_case(test_case);
                    }
                }
            }
        }

        Ok(result)
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
