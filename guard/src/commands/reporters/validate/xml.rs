use std::time::Instant;

use crate::{
    commands::{
        reporters::{
            get_test_case, validate::structured::StructuredReporter, JunitReport, JunitReporter,
            TestCase, TestCaseStatus, TestSuite,
        },
        ERROR_STATUS_CODE, FAILURE_STATUS_CODE,
    },
    rules::{self, eval_context::FileReport},
};

impl<'reporter> StructuredReporter for JunitReporter<'reporter> {
    fn report(&mut self) -> rules::Result<i32> {
        let now = Instant::now();
        let mut suites = vec![];
        let mut total_errors = 0;
        let mut total_failures = 0;
        let mut tests = 0;

        for each in &self.data {
            let file_report = FileReport {
                name: &each.name,
                ..Default::default()
            };

            let mut failures = 0;
            let mut errors = 0;

            let mut test_cases = self.rules.iter().try_fold(
                vec![],
                |mut test_cases, (rule, name)| -> rules::Result<Vec<TestCase<'_>>> {
                    let tc = get_test_case(each, rule, name)?;

                    if matches!(tc.status, TestCaseStatus::Fail(_)) {
                        failures += 1;
                    } else if matches!(tc.status, TestCaseStatus::Error { .. }) {
                        errors += 1;
                    }

                    tests += 1;
                    test_cases.push(tc);
                    Ok(test_cases)
                },
            )?;

            // A rules file that could not be parsed gets a test case in the `Error` state, named
            // after the file, so `errors` is non-zero and the suite reads as a problem rather than
            // as a green zero-test run. Nothing new was needed for this: `TestCaseStatus::Error`
            // already exists, the loop above already counts it, and that count already escalates
            // the exit code. The variant simply had no way to be constructed on this path, because
            // a file that would not parse never became a test case.
            //
            // One per data file, matching the granularity of the loop above -- a rules file that
            // could not be read was applied to none of them.
            for rule_file_error in self.rule_file_errors {
                test_cases.push(TestCase {
                    id: None,
                    name: &rule_file_error.file_name,
                    time: 0,
                    status: TestCaseStatus::Error {
                        error: rule_file_error.error.clone(),
                    },
                });
                errors += 1;
                tests += 1;
            }

            let suite = TestSuite {
                name: file_report.name.to_string(),
                test_cases,
                time: now.elapsed().as_millis(),
                errors,
                failures,
            };

            total_errors += errors;
            total_failures += failures;

            suites.push(suite);
        }

        if total_errors > 0 {
            self.update_exit_code(ERROR_STATUS_CODE)
        } else if total_failures > 0 {
            self.update_exit_code(FAILURE_STATUS_CODE)
        }

        let report = JunitReport {
            name: "cfn-guard validate report",
            test_suites: suites,
            failures: total_failures,
            errors: total_errors,
            tests,
            duration: now.elapsed().as_millis(),
        };

        report.serialize(self.writer)?;

        Ok(self.exit_code)
    }
}
