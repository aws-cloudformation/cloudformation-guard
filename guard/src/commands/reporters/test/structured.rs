use std::{convert::TryFrom, path::PathBuf, rc::Rc, time::Instant};

use crate::commands::reporters::test::{
    get_by_rules, get_status_result, unchecked_expectation_message, unmatched_expectation_names,
    Diagnostics,
};
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
    /// Filled while the cases run and read by the caller, which owns the writer.
    pub diagnostics: Diagnostics,
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
    /// Omitted when empty, so a report over a suite with no unchecked expectation is byte for byte
    /// what it was before this field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unchecked_expectations: Vec<UncheckedExpectation>,
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

        // A skip, not a failure: the run's verdict is the maintainers' to change, and a suite that
        // passes today must keep passing. A case with a `<skipped>` element is counted in `tests`,
        // so a consumer that reads only the counts still sees that something was not checked.
        for unchecked in &self.unchecked_expectations {
            test_cases.push(JunitTestCase {
                id: Some(&self.name),
                status: TestCaseStatus::Skip {
                    reasons: vec![unchecked_expectation_message(&unchecked.name)],
                },
                name: &unchecked.name,
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

/// An expectation naming a rule the file does not define, so it was never consulted.
///
/// Deliberately not folded into `skipped_rules`. That array holds rules the file does define which
/// the test data gave no expectation for; this holds expectations the test data gave which no rule
/// answers. The two are opposite directions of the same mismatch, and a consumer that saw one array
/// could not tell which had happened.
#[derive(Debug, Serialize, Deserialize)]
pub struct UncheckedExpectation {
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
        // Local rather than the field directly: `rule` and `file` borrow `self` for the body of
        // this loop, so the field is filled once at the end instead.
        let mut diagnostics = Diagnostics::new();
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

                        // Not `?`. Propagating discarded the whole structured result, so a rules file
                        // with one unresolvable variable produced no document at all rather than one
                        // saying what went wrong — the same defect the validate path had, in the command
                        // that CI calls to check rules against their own expectations.
                        //
                        // Reported the way this function already reports a spec it cannot parse and an
                        // expectation string it cannot read: as a `TestResult::Err` the caller renders.
                        match eval_rules_file(rule, &mut root_scope, None) {
                            Ok(_) => {}
                            Err(e) => {
                                return Ok(TestResult::Err(Err {
                                    rule_file: file.to_owned(),
                                    error: e.to_string(),
                                    time: now.elapsed().as_millis(),
                                }))
                            }
                        }

                        // Read before `reset_recorder` consumes the scope, as in `validate`.
                        diagnostics.extend(root_scope.deprecations().cloned());

                        let top = root_scope.reset_recorder().extract();

                        let by_rules = get_by_rules(&top);

                        // Decided once and used twice, so the note on stderr and the report cannot
                        // disagree about which expectations went unchecked.
                        let unchecked = unmatched_expectation_names(
                            &each.expectations.rules,
                            &by_rules.keys().copied().collect(),
                        );
                        diagnostics.extend(
                            unchecked
                                .iter()
                                .map(|name| unchecked_expectation_message(name)),
                        );

                        let mut test_case = TestCase {
                            name: each.name.to_string(),
                            unchecked_expectations: unchecked
                                .into_iter()
                                .map(|name| UncheckedExpectation { name })
                                .collect(),
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

        self.diagnostics = diagnostics;

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
