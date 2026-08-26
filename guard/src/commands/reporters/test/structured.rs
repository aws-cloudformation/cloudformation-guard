use std::{convert::TryFrom, path::PathBuf, rc::Rc, time::Instant};

use crate::commands::reporters::test::{
    get_by_rules, get_status_result, unchecked_expectation_message, unmatched_expectation_names,
    Diagnostics,
};
use crate::commands::reporters::{
    FailingTestCase, TestCase as JunitTestCase, TestCaseStatus, TestSuite,
};

use crate::commands::validate::file_name_of;
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
                // A case that could not run, and an unchecked expectation, are both the error code
                // rather than the failure code, and they are asked first so they win over a failure
                // elsewhere in the file. The command's own two codes already draw this line -- an
                // expectation that could not be evaluated is a different answer from an expectation
                // that was not met -- and neither an expectation whose rule produced no verdict nor a
                // case that never ran could be evaluated: there was nothing to compare with.
                //
                // Not a `TestResult::Err`, which is the other way to reach this code. That replaces
                // the whole document with a single error object, so every rule that did get a verdict
                // would vanish from the report over one stale name or one bad case in the test file.
                // The result stays `Ok`, carrying the verdicts alongside what got none.
                if test_cases.iter().any(|test_case| test_case.has_errors()) {
                    TEST_ERROR_STATUS_CODE
                } else if test_cases.iter().any(|test_case| test_case.has_failures()) {
                    TEST_FAILURE_STATUS_CODE
                } else {
                    SUCCESS_STATUS_CODE
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
                // Counted into `errors` rather than `failures`, matching the code the run exits with
                // and the arm above, which reports a rules file that could not be read the same way.
                let mut errors = 0;
                let mut time = 0;
                let test_cases = test_cases.iter().fold(vec![], |mut acc, tc| {
                    let mut test_cases = tc.build_junit_test_cases();
                    failures += tc.number_of_failures();
                    errors += tc.number_of_errors();
                    time += tc.time;
                    acc.append(&mut test_cases);
                    acc
                });

                TestSuite::new(rule_file.to_string(), test_cases, time, errors, failures)
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
    /// What stopped this case, when something did: an `input:` this loader cannot read, an
    /// expectation that is not a status, or an evaluation that failed part way.
    ///
    /// On the case rather than on the whole `TestResult`, which is the distinction this field exists
    /// to make. All three are mistakes in one case of the test file, and answering them with a
    /// `TestResult::Err` replaced the whole document with a single error object -- so every other
    /// case's verdict, already decided, vanished over one bad case. The generic reporter reports
    /// exactly these three per case and keeps the rest, and the two formats have to agree on content.
    ///
    /// Omitted when absent, so a report over a suite where every case ran is byte for byte what it
    /// was before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
    /// A case carrying nothing but the reason it could not run.
    ///
    /// The name is kept even though the case produced no verdict: it is the only thing that says
    /// *which* case the reader has to go and fix, and it is what the junit `<testcase>` is named.
    fn errored(name: String, error: String, time: u128) -> Self {
        TestCase {
            name,
            error: Some(error),
            time,
            ..Default::default()
        }
    }

    fn has_failures(&self) -> bool {
        !self.failed_rules.is_empty()
    }

    fn number_of_failures(&self) -> usize {
        self.failed_rules.len()
    }

    /// Whether anything about this case is an error rather than a verdict: the case itself could not
    /// be run, or an expectation it carries had no rule to be checked against.
    ///
    /// Both answers are `TEST_ERROR_STATUS_CODE`, and both become a junit `status="error"`, so they
    /// are asked together everywhere rather than separately in each of the three places.
    fn has_errors(&self) -> bool {
        self.error.is_some() || !self.unchecked_expectations.is_empty()
    }

    /// Counted the way [`Self::build_junit_test_cases`] emits them: one per unchecked expectation,
    /// plus one for a case that could not run. Derived from the same two fields as `has_errors`, so
    /// the suite's `errors` total cannot disagree with the elements under it.
    fn number_of_errors(&self) -> usize {
        usize::from(self.error.is_some()) + self.unchecked_expectations.len()
    }

    fn build_junit_test_cases(&self) -> Vec<JunitTestCase> {
        let mut test_cases = vec![];

        // The case itself, when it could not run. Named after the case and not after the rules file,
        // which is what the whole-file `TestResult::Err` produced: a suite of one erroring test named
        // after the file, with the decided cases absent from the count entirely, so a CI job read a
        // two-case suite as one test. `id` repeats the name so a consumer grouping the suite by `id`
        // -- every other element here carries the case name in it -- files this with its own case
        // rather than in a nameless bucket.
        if let Some(error) = &self.error {
            test_cases.push(JunitTestCase {
                id: Some(&self.name),
                status: TestCaseStatus::Error {
                    error: error.clone(),
                },
                name: &self.name,
                time: self.time,
            })
        }

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

        // `status="error"` with an `<error>` body, not the `<skipped>` it was. A skipped case counts
        // into `tests` and nothing else, so a consumer watching `failures` and `errors` -- which is
        // what a CI junit step watches -- read a suite where every expectation named a stale rule as
        // entirely green. `errors` is the total this feeds, and it is the one the run's own exit code
        // agrees with.
        for unchecked in &self.unchecked_expectations {
            test_cases.push(JunitTestCase {
                id: Some(&self.name),
                status: TestCaseStatus::Error {
                    error: unchecked.reason.clone(),
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

/// An expectation no rule in the file answered, so it was never consulted.
///
/// Deliberately not folded into `skipped_rules`. That array holds rules the file does define which
/// the test data gave no expectation for; this holds expectations the test data gave which no rule
/// answers. The two are opposite directions of the same mismatch, and a consumer that saw one array
/// could not tell which had happened.
///
/// `reason` is carried in the report rather than left to the reader to infer from the name, because
/// there is more than one reason and they call for different fixes: a name the file does not have
/// wants the test file corrected, while a parameterized rule wants the expectation moved to whatever
/// invokes it. It is also the text the junit `<error>` element uses, so the two cannot disagree.
#[derive(Debug, Serialize, Deserialize)]
pub struct UncheckedExpectation {
    name: String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FailedRule {
    name: String,
    expected: Status,
    evaluated: Vec<Status>,
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

        let specs_by_file =
            iterate_over(
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
            );

        // Zipped with the paths rather than iterated alone. `iterate_over` yields exactly one item
        // per file in slice order, and a test file it could not read has to be reported against that
        // file rather than against the rules file, which is not what went wrong.
        for (test_file, specs) in self.data_test_files.iter().zip(specs_by_file) {
            let specs = match specs {
                // One errored case named after the unreadable file, not a `TestResult::Err`. `test`
                // takes a directory of test data as readily as one file, and returning here
                // discarded every case of every *other* test file over one that would not parse --
                // while the generic reporter reported them and carried on to the next file.
                Err(e) => {
                    result.insert_test_case(TestCase::errored(
                        file_name_of(test_file),
                        e.to_string(),
                        now.elapsed().as_millis(),
                    ));
                    continue;
                }
                Ok(specs) => specs,
            };

            'case: for TestSpec {
                name,
                input,
                expectations,
            } in specs
            {
                let now = Instant::now();
                let name = name.unwrap_or_default();

                // On the case, and this is the sibling call the reason below was not applied to. A
                // case's `input:` that this loader cannot read is a mistake in one case of the test
                // file: propagating it with `?` reached `main`'s catch-all and exited 255,
                // `INTERNAL_FAILURE`, and answering it with a `TestResult::Err` instead still cost
                // every decided case in the file its verdict -- in `json`, `yaml` and `junit` only,
                // because the generic reporter had already been taught to keep them.
                let path_value = match PathAwareValue::try_from(input) {
                    Ok(root) => Rc::new(root),
                    Err(e) => {
                        result.insert_test_case(TestCase::errored(
                            name,
                            e.to_string(),
                            now.elapsed().as_millis(),
                        ));
                        continue;
                    }
                };

                let mut root_scope = eval_context::root_scope(rule, path_value);

                // Recorded on the case rather than returned, for the reason the generic reporter
                // gives: `eval_rules_file` evaluates every rule before returning an error, so the
                // record holds the other rules' verdicts and this case still reports them. That
                // reporter prints the error line and then the verdicts; this is the same answer in a
                // document.
                let eval_error = eval_rules_file(rule, &mut root_scope, None)
                    .err()
                    .map(|e| e.to_string());

                // Read before `reset_recorder` consumes the scope, as in `validate`.
                diagnostics.extend(root_scope.deprecations().cloned());

                let top = root_scope.reset_recorder().extract();

                let by_rules = get_by_rules(&top);

                // Decided once and used three times -- the note on stderr, the report, and the
                // exit code the caller reads off the report -- so they cannot disagree about
                // which expectations went unchecked or why.
                let unchecked = unmatched_expectation_names(
                    &expectations.rules,
                    &by_rules.keys().copied().collect(),
                )
                .into_iter()
                .map(|name| UncheckedExpectation {
                    reason: unchecked_expectation_message(rule, &name),
                    name,
                })
                .collect::<Vec<UncheckedExpectation>>();

                diagnostics.extend(unchecked.iter().map(|each| each.reason.clone()));

                let mut test_case = TestCase {
                    name,
                    error: eval_error,
                    unchecked_expectations: unchecked,
                    ..Default::default()
                };

                for (rule_name, records) in by_rules {
                    let expected = match expectations.rules.get(rule_name) {
                        Some(exp) => match Status::try_from(exp.as_str()) {
                            Ok(exp) => exp,
                            Err(e) => {
                                // The case, and only the case, as in the generic reporter: there
                                // this error leaves `get_by_result` and the caller abandons the
                                // case, so the verdicts collected so far go with it and so does any
                                // evaluation error. One reason per case is reported, and an
                                // expectation that is not a status is the one to act on.
                                result.insert_test_case(TestCase::errored(
                                    test_case.name,
                                    e.to_string(),
                                    now.elapsed().as_millis(),
                                ));
                                continue 'case;
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

        self.diagnostics = diagnostics;

        Ok(result)
    }
}
