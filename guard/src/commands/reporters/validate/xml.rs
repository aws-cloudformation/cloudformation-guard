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

            let test_cases = self.rules.iter().try_fold(
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
