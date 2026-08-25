// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub(crate) mod utils;

#[cfg(test)]
mod test_command_tests {
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    use crate::assert_output_from_file_eq;
    use cfn_guard::commands::{
        ALPHABETICAL, DIRECTORY, LAST_MODIFIED, OUTPUT_FORMAT, RULES_AND_TEST_FILE, RULES_FILE,
        TEST_DATA, VERBOSE,
    };
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
    use cfn_guard::Error;

    use crate::utils::{sanitize_junit_writer, Command, CommandTestRunner, StatusCode};

    #[derive(Default)]
    struct TestCommandTestRunner<'args> {
        test_data: Option<&'args str>,
        rules: Option<&'args str>,
        directory: Option<&'args str>,
        rules_and_test_file: Option<&'args str>,
        output_format: Option<&'args str>,
        directory_only: bool,
        alphabetical: bool,
        last_modified: bool,
        verbose: bool,
    }

    impl<'args> TestCommandTestRunner<'args> {
        fn test_data(&'args mut self, arg: Option<&'args str>) -> &'args mut TestCommandTestRunner {
            self.test_data = arg;
            self
        }

        fn rules(&'args mut self, arg: Option<&'args str>) -> &'args mut TestCommandTestRunner {
            self.rules = arg;
            self
        }

        fn directory(&'args mut self, arg: Option<&'args str>) -> &'args mut TestCommandTestRunner {
            self.directory = arg;
            self
        }

        #[allow(dead_code)]
        fn rules_and_test_file(
            &'args mut self,
            arg: Option<&'args str>,
        ) -> &'args mut TestCommandTestRunner {
            self.rules_and_test_file = arg;
            self
        }

        fn directory_only(&'args mut self) -> &'args mut TestCommandTestRunner {
            self.directory_only = true;
            self
        }

        #[allow(dead_code)]
        fn alphabetical(&'args mut self) -> &'args mut TestCommandTestRunner {
            self.alphabetical = true;
            self
        }

        #[allow(dead_code)]
        fn last_modified(&'args mut self) -> &'args mut TestCommandTestRunner {
            self.last_modified = true;
            self
        }

        fn verbose(&'args mut self) -> &'args mut TestCommandTestRunner {
            self.verbose = true;
            self
        }

        fn output_format(&'args mut self, args: &'args str) -> &'args mut TestCommandTestRunner {
            self.output_format = Some(args);
            self
        }
    }

    impl<'args> CommandTestRunner for TestCommandTestRunner<'args> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![Command::Test.to_string()];

            if self.test_data.is_some() {
                args.push(format!("-{}", TEST_DATA.1));
                args.push(String::from(self.test_data.unwrap()))
            }

            if self.rules.is_some() {
                args.push(format!("-{}", RULES_FILE.1));
                args.push(String::from(self.rules.unwrap()))
            }

            if self.directory.is_some() {
                args.push(format!("-{}", DIRECTORY.1));
                args.push(String::from(self.directory.unwrap()));
            }

            if self.rules_and_test_file.is_some() {
                args.push(format!("-{}", RULES_AND_TEST_FILE));
                args.push(String::from(self.rules_and_test_file.unwrap()));
            }

            if self.alphabetical {
                args.push(format!("-{}", ALPHABETICAL.1));
            }

            if self.last_modified {
                args.push(format!("-{}", LAST_MODIFIED.1));
            }

            if self.verbose {
                args.push(format!("-{}", VERBOSE.1));
            }

            if let Some(output_format) = self.output_format {
                args.push(format!("-{}", OUTPUT_FORMAT.1));
                args.push(String::from(output_format));
            }

            args
        }
    }

    #[rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_data_file_with_shorthand_reference(#[case] file_type: &str) -> Result<(), Error> {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(&format!(
                "resources/test-command/data-dir/s3_bucket_logging_enabled_tests.{}",
                file_type
            )))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            "resources/test-command/output-dir/test_data_file_with_shorthand_reference.out",
            writer
        );

        Ok(())
    }

    #[rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_data_file(#[case] file_type: &str) -> Result<(), Error> {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(&format!(
                "resources/test-command/data-dir/s3_bucket_server_side_encryption_enabled.{}",
                file_type
            )))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            "resources/test-command/output-dir/test_data_file.out",
            writer
        );

        Ok(())
    }

    /// A rule that cannot be evaluated costs its own expectation, not the file's.
    ///
    /// `get_by_result` propagated the evaluation error, so a rules file with one unresolvable variable
    /// printed the case number, the case name, one error line and nothing else — neither of the two
    /// decidable expectations checked or reported, and no report at all in `json` or `junit`.
    ///
    /// Both halves are asserted. The error must still be stated, because the ruleset really is broken; and
    /// the two expectations must still be checked, because `eval_rules_file` evaluates every rule before
    /// returning an error, so their verdicts are in the record and there is nothing to gain by discarding
    /// them.
    ///
    /// `INCORRECT_STATUS_ERROR` is the command's own error code, and it is deliberately not
    /// `TEST_COMMAND_FAILURE`: an expectation that could not be evaluated is a different answer from an
    /// expectation that was not met.
    #[test]
    fn a_rule_that_cannot_be_evaluated_does_not_discard_the_other_expectations() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(
                "resources/test-command/data-dir/a_broken_rule_beside_working_ones_tests.yaml",
            ))
            .rules(Some(
                "resources/test-command/rule-dir/a_broken_rule_beside_working_ones.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "a rule that could not be evaluated is an error, not an unmet expectation"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Could not resolve variable by name nm"),
            "the run must still say what it could not evaluate:\n{}",
            output
        );
        for expectation in [
            "bucket_is_named_expected: Expected = FAIL",
            "producer: Expected = PASS",
        ] {
            assert!(
                output.contains(expectation),
                "and must still report {}:\n{}",
                expectation,
                output
            );
        }
    }

    #[test]
    fn test_parse_error_when_guard_rule_has_syntax_error() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some("resources/test-command/data-dir/test.yaml"))
            .rules(Some("resources/test-command/rule-dir/invalid_rule.guard"))
            .verbose()
            .run(&mut writer, &mut reader);

        let expected_err_msg = String::from(
            r#"Parse Error on ruleset file Parser Error when parsing `Parsing Error Error parsing file resources/test-command/rule-dir/invalid_rule.guard at line 8 at column 46, when handling expecting either a property access "engine.core" or value like "string" or ["this", "that"], fragment  {"Fn::ImportValue":/{"Fn::Sub":"${pSecretKmsKey}"}}
}
`
"#,
        );

        assert_eq!(StatusCode::INCORRECT_STATUS_ERROR, status_code);
        assert_eq!(expected_err_msg, writer.stripped().unwrap());
    }

    #[test]
    fn test_parse_error_when_file_dne() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some("resources/test-command/data-dir/test.yaml"))
            .rules(Some("/resources/test-command/data-dir/invalid_rule.guard"))
            .verbose()
            .run(&mut writer, &mut reader);

        let expected_err_msg = String::from(
            "Error occurred The path `/resources/test-command/data-dir/invalid_rule.guard` does not exist\n",
        );

        assert_eq!(StatusCode::INTERNAL_FAILURE, status_code);
        assert_eq!(expected_err_msg, writer.err_to_stripped().unwrap());
    }

    #[test]
    fn test_data_file_verbose() -> Result<(), Error> {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(
                "resources/test-command/data-dir/s3_bucket_server_side_encryption_enabled.yaml",
            ))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .verbose()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            "resources/test-command/output-dir/test_data_file_verbose.out",
            writer
        );

        Ok(())
    }

    #[test]
    fn test_with_rules_dir_verbose() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from("resources/test-command/dir"))
            .directory_only()
            .verbose()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            "resources/test-command/output-dir/test_data_dir_verbose.out",
            writer
        );
    }

    /// The plaintext directory report writes one section per rules file, terminated by a `---` line.
    /// Returns the section that names `rule_file`.
    fn section_for<'out>(stdout: &'out str, rule_file: &str) -> &'out str {
        stdout
            .split("\n---")
            .find(|section| section.contains(rule_file))
            .unwrap_or_else(|| panic!("no section mentions {} in:\n{}", rule_file, stdout))
    }

    /// The case names a section reported, which is the set of test files that rules file was paired
    /// with.
    fn suite_names_in(section: &str) -> Vec<&str> {
        section
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Name: "))
            .collect()
    }

    /// A test failure was reported as a success, because a shorter rules file stem claimed a longer
    /// one's tests.
    ///
    /// Test files are paired with rules files by prefix, and the first match in sort order won. With
    /// `s3.guard` and `s3_encryption.guard` in one directory, `s3_encryption_tests.yml` starts with
    /// `s3`, so it was attached to `s3.guard` -- whose rules it does not name -- and
    /// `s3_encryption.guard` was reported as having no tests at all.
    ///
    /// The exit code is what makes this a defect rather than untidy output. This fixture's
    /// expectation is not met: run as `test -r s3_encryption.guard -t tests/s3_encryption_tests.yml`
    /// it exits 7, and over the same files `test -d` exited 0. A suite that fails when you point at
    /// it and passes when the directory walker finds it is worse than no suite.
    #[test]
    fn a_shorter_rules_file_stem_does_not_claim_the_longer_ones_tests() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(
                "resources/test-command/prefix-collision-failing-suite",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::TEST_COMMAND_FAILURE,
            status_code,
            "the unmet expectation in s3_encryption_tests.yml must fail the run"
        );

        let stdout = writer.stripped().expect("failed to read stdout");
        assert!(
            !stdout.contains("did not have any tests associated"),
            "each rules file here has a test file of its own:\n{}",
            stdout
        );

        let encryption = section_for(&stdout, "/s3_encryption.guard");
        assert_eq!(
            suite_names_in(encryption),
            vec!["suite for s3 encryption"],
            "s3_encryption.guard must be paired with its own suite only:\n{}",
            encryption
        );
        assert!(
            encryption.contains("s3_encryption_rule: Expected = PASS, Evaluated = [FAIL]"),
            "and must report which expectation was not met:\n{}",
            encryption
        );
        assert_eq!(
            suite_names_in(section_for(&stdout, "/s3.guard")),
            vec!["suite for s3"],
            "s3.guard must keep only its own suite:\n{}",
            stdout
        );
    }

    /// Longest-prefix pairing is not merely turning collisions red.
    ///
    /// The same two-file shape as the failing case, with both expectations met. Both rules files must
    /// run their own suite and neither may be skipped, so the fix cannot be mistaken for one that
    /// fails any directory it cannot pair confidently.
    #[test]
    fn each_rules_file_in_a_prefix_collision_runs_its_own_passing_suite() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(
                "resources/test-command/prefix-collision-both-passing",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);

        let stdout = writer.stripped().expect("failed to read stdout");
        assert!(
            !stdout.contains("did not have any tests associated"),
            "neither rules file may be skipped:\n{}",
            stdout
        );
        assert_eq!(
            suite_names_in(section_for(&stdout, "/s3.guard")),
            vec!["suite for s3"],
            "s3.guard must be paired with its own suite only:\n{}",
            stdout
        );
        assert_eq!(
            suite_names_in(section_for(&stdout, "/s3_encryption.guard")),
            vec!["suite for s3 encryption"],
            "s3_encryption.guard must be paired with its own suite only:\n{}",
            stdout
        );
        assert_eq!(
            stdout.matches("PASS Rules:").count(),
            2,
            "one passing suite per rules file:\n{}",
            stdout
        );
    }

    /// A rules file with no test file of its own is still skipped, and skipping is still not a
    /// failure.
    ///
    /// `orphan.guard` shares no prefix with `paired_tests.yml`, so it has nothing to run. Pairing on
    /// the longest match narrows which rules file a test file lands on; it must not widen what counts
    /// as having no tests, and an unpaired rules file must not fail the run.
    ///
    /// This one passes before the change as well as after. That is what it is for.
    #[test]
    fn a_rules_file_with_no_test_file_is_skipped_without_failing_the_run() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(
                "resources/test-command/rules-file-without-tests",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "a rules file with no tests is not a test failure"
        );

        let stdout = writer.stripped().expect("failed to read stdout");
        assert!(
            stdout.contains(
                "Guard File resources/test-command/rules-file-without-tests/orphan.guard did not have any tests associated, skipping."
            ),
            "the unpaired rules file must still be reported as skipped:\n{}",
            stdout
        );
        assert_eq!(
            suite_names_in(section_for(&stdout, "/paired.guard")),
            vec!["suite for paired"],
            "and the paired one must still run:\n{}",
            stdout
        );
    }

    /// Three stems where each is a prefix of the next.
    ///
    /// `a.guard`, `a_b.guard` and `a_b_c.guard` with a test file apiece. Every one of the three test
    /// file names starts with `a`, so first-match sent all three to `a.guard` and skipped the other
    /// two rules files. Longest-prefix is the rule that separates them: `a_b_tests.yml` matches `a`
    /// and `a_b` but not `a_b_c`, and `a_b_c_tests.yml` matches all three.
    #[test]
    fn a_three_way_prefix_collision_pairs_each_rules_file_with_its_own_tests() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(
                "resources/test-command/prefix-collision-three-way",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);

        let stdout = writer.stripped().expect("failed to read stdout");
        assert!(
            !stdout.contains("did not have any tests associated"),
            "all three rules files have a test file of their own:\n{}",
            stdout
        );
        for (rule_file, suite) in [
            ("/a.guard", "suite for a"),
            ("/a_b.guard", "suite for a_b"),
            ("/a_b_c.guard", "suite for a_b_c"),
        ] {
            assert_eq!(
                suite_names_in(section_for(&stdout, rule_file)),
                vec![suite],
                "{} must be paired with {} and nothing else:\n{}",
                rule_file,
                suite,
                stdout
            );
        }
    }

    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn test_structured_single_report(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/data-dir/s3_bucket_server_side_encryption_enabled.yaml",
            ))
            .rules(Option::from(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .output_format(output)
            .run(&mut writer, &mut reader);

        let writer = if output == "junit" {
            sanitize_junit_writer(writer)
        } else {
            writer
        };

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            format!("resources/test-command/output-dir/structured_single_report_{output}.out")
                .as_str(),
            writer
        );
    }

    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn test_structured_directory_report(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from("resources/test-command/dir"))
            .output_format(output)
            .run(&mut writer, &mut reader);

        let writer = if output == "junit" {
            sanitize_junit_writer(writer)
        } else {
            writer
        };

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            format!("resources/test-command/output-dir/structured_directory_report_{output}.out")
                .as_str(),
            writer
        );
    }

    #[rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_structured_report_with_illegal_args(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from("resources/test-command/dir"))
            .output_format(output)
            .verbose()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INTERNAL_FAILURE, status_code);
    }

    #[test]
    fn test_with_function_expr() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/functions/data/template.yaml",
            ))
            .rules(Some(
                "resources/test-command/functions/rules/json_parse.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!("resources/test-command/output-dir/functions.out", writer);
    }

    #[test]
    fn test_with_failure() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/data-dir/failing_test.yaml",
            ))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::TEST_COMMAND_FAILURE, status_code);
    }

    /// An expectation that names no rule in the file says so.
    ///
    /// It used to be dropped in silence. Expectations are read per evaluated rule, so one whose name
    /// matches nothing is never consulted, and the run exits 0 having checked less than the file
    /// asked for. The fixture asserts FAIL twice on names that do not exist and the run still
    /// succeeds, which is the whole defect: a misspelled rule name turns an assertion into nothing
    /// without ever saying so.
    ///
    /// Still exit 0 here. Failing the run would break suites that pass today, so this reports rather
    /// than enforces; the reporters already print the mirror case for a rule with no expectation.
    ///
    /// Two cases in the fixture and two lines expected, not four.
    #[rstest]
    #[case("")]
    #[case("json")]
    fn an_expectation_naming_no_rule_is_reported(#[case] output: &str) {
        const DATA: &str =
            "resources/test-command/data-dir/expectation_for_a_rule_that_does_not_exist.yaml";
        const RULES: &str =
            "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard";

        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = match output {
            "" => TestCommandTestRunner::default()
                .test_data(Option::from(DATA))
                .rules(Some(RULES))
                .run(&mut writer, &mut reader),
            _ => TestCommandTestRunner::default()
                .test_data(Option::from(DATA))
                .rules(Some(RULES))
                .output_format(output)
                .run(&mut writer, &mut reader),
        };

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "reporting an unchecked expectation must not change the verdict"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let reported: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("is in this file"))
            .collect();

        assert_eq!(
            reported.len(),
            2,
            "expected one line per unmatched name across both cases, got {:?} from stderr {:?}",
            reported,
            stderr
        );
        assert!(
            reported
                .iter()
                .any(|l| l.contains("S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLE ")),
            "the name with a dropped final letter should be reported, got {:?}",
            reported
        );
        assert!(
            reported.iter().any(|l| l.contains("S3_BUCKET_ENCRYPTED")),
            "the plausible-but-wrong name should be reported, got {:?}",
            reported
        );
    }

    /// The deprecation notices reach the command rule authors run.
    ///
    /// `validate` printed them and `test` did not, which is backwards. A notice saying a clause's
    /// answer changes in a later release is addressed to whoever wrote the clause, and they run
    /// `test`; the operator running `validate` in a pipeline usually cannot act on it. So the whole
    /// warn-a-release-ahead approach was invisible to its audience.
    ///
    /// Both assertions matter. Stderr must carry the notices, and stdout must not, because
    /// `--output-format json` is parsed -- which is also why the JSON case asserts the report still
    /// deserializes with the notice present.
    ///
    /// Two notices from three cases, not six: a rule file is evaluated once per case, so the same
    /// notice is produced again for every case, and they are collapsed before being written.
    #[rstest]
    #[case("")]
    #[case("json")]
    fn a_deprecation_notice_reaches_the_test_command(#[case] output: &str) {
        const DATA: &str = "resources/test-command/data-dir/vacuous_and_incomparable_cases.yaml";
        const RULES: &str = "resources/validate/vacuous_and_incomparable_clauses.guard";

        // `stripped` and `err_to_stripped` both consume the writer, so a single run cannot be read
        // for both streams. The command is deterministic over these inputs, so running it once per
        // stream reads the same output twice rather than two different outputs.
        let run = |output: &str| {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            let status_code = match output {
                "" => TestCommandTestRunner::default()
                    .test_data(Option::from(DATA))
                    .rules(Some(RULES))
                    .run(&mut writer, &mut reader),
                _ => TestCommandTestRunner::default()
                    .test_data(Option::from(DATA))
                    .rules(Some(RULES))
                    .output_format(output)
                    .run(&mut writer, &mut reader),
            };

            (status_code, writer)
        };

        let (status_code, out_writer) = run(output);
        let (_, err_writer) = run(output);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "a notice must not change the verdict; both clauses still pass in this release"
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            !stdout.contains("DEPRECATION"),
            "a notice on stdout would land inside the report that consumers parse, got {:?}",
            stdout
        );

        if output == "json" {
            serde_json::from_str::<serde_json::Value>(&stdout)
                .expect("the report on stdout must still parse with a notice on stderr");
        }

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();

        assert_eq!(
            notices.len(),
            2,
            "expected one notice per clause across all three cases, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices
                .iter()
                .any(|n| n.contains("without comparing anything")),
            "the empty-collection clause should say it compared nothing, got {:?}",
            notices
        );
        assert!(
            notices
                .iter()
                .any(|n| n.contains("could not be compared with any element")),
            "the membership clause should say nothing in the list was comparable, got {:?}",
            notices
        );
    }

    /// Two runs of the same command over the same files must produce the same report.
    ///
    /// They did not. Both test reporters iterate the map built by `get_by_rules`, which was a
    /// `HashMap`, so the sequence of rule names inside a result group came from `RandomState` and
    /// was reseeded every process. Ten consecutive runs of this fixture produced ten different
    /// outputs before the fix.
    ///
    /// Nothing in this file could see that, because every other fixture has one rule per result
    /// group, and with one entry hash order and sorted order are the same. So the fixture is the
    /// substance of the test: five rules whose declared order is not alphabetical, listed in a
    /// single group. A golden file over that shape is a live detector -- reverting `get_by_rules`
    /// to a `HashMap` fails it on all but roughly one run in a hundred and twenty per case, and
    /// there are two cases.
    ///
    /// Both reporters are covered because both read the same map: the generic one prints the group
    /// directly, and the structured one fills `passed_rules` in iteration order, which JSON, YAML
    /// and JUnit consumers then see.
    #[rstest]
    #[case("", "five_rules_one_result_group.out")]
    #[case("json", "five_rules_one_result_group_json.out")]
    fn rules_within_a_result_group_are_listed_in_a_fixed_order(
        #[case] output: &str,
        #[case] expected: &str,
    ) {
        const DATA: &str = "resources/test-command/data-dir/five_rules_one_result_group.yaml";
        const RULES: &str = "resources/test-command/rule-dir/five_rules_one_result_group.guard";

        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        // The builder ties its borrow to the whole chain, so the default format cannot be expressed
        // by skipping a setter mid-chain; each case builds its own.
        let status_code = match output {
            "" => TestCommandTestRunner::default()
                .test_data(Option::from(DATA))
                .rules(Some(RULES))
                .run(&mut writer, &mut reader),
            _ => TestCommandTestRunner::default()
                .test_data(Option::from(DATA))
                .rules(Some(RULES))
                .output_format(output)
                .run(&mut writer, &mut reader),
        };

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            format!("resources/test-command/output-dir/{expected}").as_str(),
            writer
        );
    }

    #[test]
    fn test_sarif_output_with_expected_failures() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/data-dir/failing_test.yaml",
            ))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .output_format("sarif")
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INTERNAL_FAILURE, status_code);
    }
}
