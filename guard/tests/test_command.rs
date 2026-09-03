// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub(crate) mod utils;

#[cfg(test)]
mod test_command_tests {
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    use crate::assert_output_from_file_eq;
    use cfn_guard::commands::CfnGuard;
    use cfn_guard::commands::{
        ALPHABETICAL, DIRECTORY, LAST_MODIFIED, OUTPUT_FORMAT, RULES_AND_TEST_FILE, RULES_FILE,
        TEST_DATA, VERBOSE,
    };
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
    use cfn_guard::Error;
    use clap::Parser;

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

    /// A data file whose input carries a YAML shorthand tag (`!Ref`) is read, and its expectations
    /// are checked.
    ///
    /// The second half is new. This paired `s3_bucket_logging_enabled_tests` against
    /// `s3_bucket_server_side_encryption_enabled.guard`, so all five expectations named a rule that
    /// file does not have and none of them was consulted: the recorded output was five cases of
    /// `No Test expectation was set for Rule S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED` and exit 0.
    /// The test proved the file parsed and nothing else, which is half of what its name claims.
    ///
    /// Fixed by pairing the data file with the rules file it was written for rather than by relaxing
    /// the check that caught it. `S3_BUCKET_LOGGING_ENABLED` is in
    /// `resources/validate/rules-dir/s3_bucket_logging_enabled.guard`, and against that the five
    /// expectations -- SKIP, SKIP, PASS, FAIL, SKIP -- are assertions.
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
                "resources/validate/rules-dir/s3_bucket_logging_enabled.guard",
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

    /// A case whose `input:` cannot be read costs its own case, not the file's, and not the exit code
    /// reserved for the tool breaking.
    ///
    /// The sibling of the test above, one call earlier. `get_by_result` converts the case's `input:`
    /// before it evaluates anything, and that conversion was propagated with `?`, so it left the `test`
    /// command entirely and reached `main`'s catch-all: **255**, `INTERNAL_FAILURE`, the code this
    /// repository reserves for the tool itself breaking. Everything about that was wrong. The mistake is
    /// in the test file, which is content, and the same loop already answers `INCORRECT_STATUS_ERROR` for
    /// a test file it cannot parse at all. Every later case in the file went with it -- here the first
    /// case's verdict had already been decided and printed. The structured reporter propagated the same
    /// conversion with the same `?` into the same catch-all, so all four output formats exited 255 on
    /// these bytes rather than two of them disagreeing.
    ///
    /// Five shapes of unreadable `input:` were measured reaching 255 through all four output formats:
    /// a merge key given a scalar, a merge key given a sequence holding a scalar, a quoted `"<<"` given a
    /// scalar, a null key and a sequence key. The first three arrived with the round that taught this
    /// loader to resolve the merge key; the last two were already there.
    ///
    /// This asserts the generic reporter only, which is a `Writer`'s text. The three structured formats
    /// are pinned by
    /// [`a_case_whose_input_cannot_be_read_does_not_discard_the_other_cases_in_structured_formats`],
    /// because asserting one reporter is how the structured half of this went unfixed while its own
    /// comment described the fix.
    #[test]
    fn a_case_whose_input_cannot_be_read_does_not_discard_the_other_cases() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(
                "resources/test-command/data-dir/a_case_whose_input_cannot_be_read_tests.yaml",
            ))
            .rules(Some(
                "resources/test-command/rule-dir/a_case_whose_input_cannot_be_read.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an unreadable input is the test file's mistake, not INTERNAL_FAILURE"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("bucket_is_named_expected: Expected = FAIL"),
            "the decidable case's verdict must still be reported:\n{}",
            output
        );
        assert!(
            output.contains("the merge key"),
            "and the run must still say what it could not read:\n{}",
            output
        );
    }

    /// The same bytes through `json`, `yaml` and `junit`: the decided case keeps its verdict and the
    /// unreadable one is an error of its own.
    ///
    /// The sibling above was asserted and this was not, so the structured reporter kept the defect its
    /// own comment claimed to close. It answered a case's unreadable `input:` with a whole-file
    /// `TestResult::Err`, which replaces the document with a single `{rule_file, error}` object -- so
    /// the first case's `FAIL`, already decided, was absent from all three formats while the
    /// single-line reporter printed it.
    ///
    /// junit is the sharpest of the three and the reason a golden is used rather than a `contains`.
    /// It reported `tests="1" errors="1"` with its one `<testcase>` named after the *rules file*, so a
    /// CI job reading it saw a suite of one erroring test where the file has two cases, one of them
    /// decided. It now reports `tests="2"`: the decided rule as a passing case, and the unreadable
    /// case as `status="error"` named after the case. `errors` stays 1 and the exit code stays
    /// `INCORRECT_STATUS_ERROR`, which is what these formats already agreed with the generic one
    /// about -- content was the only thing they disagreed on.
    ///
    /// Both cases carry a `name:`, so nothing here depends on the empty-string fallback an unnamed
    /// case gets.
    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn a_case_whose_input_cannot_be_read_does_not_discard_the_other_cases_in_structured_formats(
        #[case] output: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(
                "resources/test-command/data-dir/a_case_whose_input_cannot_be_read_tests.yaml",
            ))
            .rules(Some(
                "resources/test-command/rule-dir/a_case_whose_input_cannot_be_read.guard",
            ))
            .output_format(output)
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an unreadable input is the test file's mistake, not INTERNAL_FAILURE"
        );

        let writer = if output == "junit" {
            sanitize_junit_writer(writer)
        } else {
            writer
        };

        assert_output_from_file_eq!(
            format!(
                "resources/test-command/output-dir/a_case_whose_input_cannot_be_read_{output}.out"
            )
            .as_str(),
            writer
        );
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

        // Line 8 of that fixture is `%redshift_clusters.Properties.KmsKeyId == {"Fn::ImportValue":
        // /{"Fn::Sub":"${pSecretKmsKey}"}}`, and the `/` in the middle of it opens a regular
        // expression that never closes before the line ends. So the report names the unterminated
        // regex alongside the alternation it was tried in. It used to name only the alternation,
        // because the regex error was recoverable and its message was discarded.
        let expected_err_msg = String::from(
            r#"Parse Error on ruleset file Parser Error when parsing `Parsing Error Error parsing file resources/test-command/rule-dir/invalid_rule.guard at line 8 at column 46, when handling expecting either a property access "engine.core" or value like "string" or ["this", "that"]/Could not parse regular expression: no closing / before the end of the line, fragment  {"Fn::ImportValue":/{"Fn::Sub":"${pSecretKmsKey}"}}
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
    ///
    /// `rule_file` is a bare file name, matched anchored to the separator in front of it so that a
    /// section naming `s3_encryption.guard` is not returned to a caller asking for `s3.guard`. The
    /// anchor is `MAIN_SEPARATOR` and not `/`, because the report prints the path the walk built: the
    /// directory keeps the separators it was passed on the command line, and each file name under it
    /// is joined on with the platform's own. Every one of these searches was written with a literal
    /// `/` and so found nothing on Windows, where the joined separator is `\`.
    fn section_for<'out>(stdout: &'out str, rule_file: &str) -> &'out str {
        let anchored = format!("{}{}", std::path::MAIN_SEPARATOR, rule_file);

        stdout
            .split("\n---")
            .find(|section| section.contains(&anchored))
            .unwrap_or_else(|| panic!("no section mentions {} in:\n{}", anchored, stdout))
    }

    /// The path the report prints for the file reached by walking from `dir` through `components`.
    ///
    /// Built the way the command builds it -- `dir` verbatim, then each component pushed on -- rather
    /// than written out as one string literal, because a runtime path here has *both* separators. The
    /// directory reaches the report exactly as these tests spell it, with `/`, while every component
    /// the walk joins on is separated by `MAIN_SEPARATOR`, so on Windows the report says
    /// `resources/test-command/orphaned-test-file\tests\s3_tests.yml`. An all-`/` literal and an
    /// all-`\` literal are both wrong against that, and rewriting the separators in the report before
    /// comparing would be normalising the side under test: the report's separators are part of what
    /// these assertions are checking.
    fn reported_path(dir: &str, components: &[&str]) -> String {
        let mut path = std::path::PathBuf::from(dir);
        for component in components {
            path.push(component);
        }

        path.display().to_string()
    }

    /// [`section_for`] requires a separator in front of the name, and nothing else here would notice
    /// if it stopped.
    ///
    /// The anchor is the reason `section_for` takes a bare file name and not a substring, but until
    /// this test existed, loosening it to a plain `contains(file_name)` broke no test -- measured, by
    /// doing exactly that: all six callers stayed green. None of the fixtures can tell the difference,
    /// because substring containment does not actually confuse the collision they are built from.
    /// `s3_encryption.guard` does not *contain* `s3.guard`; prefix extension adds characters after the
    /// stem, and a substring search for `s3.guard` needs `s3` immediately followed by `.guard`.
    ///
    /// The direction that does confuse it is the other one -- a name that *ends with* the name being
    /// searched for. `my_s3.guard` contains `s3.guard`, so an unanchored search returns whichever of
    /// the two sections the walk reported first. That is what this fixture is: two sections in walk
    /// order, the suffix-extended one first, so an unanchored search picks the wrong one and an
    /// anchored search skips it.
    ///
    /// Built as a string rather than as a directory of `.guard` files because the property under test
    /// belongs to the helper, not to the command: what is being pinned is that `section_for` requires a
    /// path-component boundary, and a fixture would make that depend on a real walk agreeing to report
    /// two such names.
    #[test]
    fn section_for_requires_a_separator_in_front_of_the_name() {
        let stdout = format!(
            "Testing Guard File dir{sep}my_s3.guard\n  Name: suffix extension\n---\n\
             Testing Guard File dir{sep}s3.guard\n  Name: the one asked for\n---\n",
            sep = std::path::MAIN_SEPARATOR
        );

        assert_eq!(
            suite_names_in(section_for(&stdout, "s3.guard")),
            vec!["the one asked for"],
            "a name ending in the one searched for must not answer the search:\n{}",
            stdout
        );
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

        let encryption = section_for(&stdout, "s3_encryption.guard");
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
            suite_names_in(section_for(&stdout, "s3.guard")),
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
            suite_names_in(section_for(&stdout, "s3.guard")),
            vec!["suite for s3"],
            "s3.guard must be paired with its own suite only:\n{}",
            stdout
        );
        assert_eq!(
            suite_names_in(section_for(&stdout, "s3_encryption.guard")),
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
        const DIR: &str = "resources/test-command/rules-file-without-tests";

        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(DIR))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "a rules file with no tests is not a test failure"
        );

        let stdout = writer.stripped().expect("failed to read stdout");
        assert!(
            stdout.contains(&format!(
                "Guard File {} did not have any tests associated, skipping.",
                reported_path(DIR, &["orphan.guard"])
            )),
            "the unpaired rules file must still be reported as skipped:\n{}",
            stdout
        );
        assert_eq!(
            suite_names_in(section_for(&stdout, "paired.guard")),
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
            ("a.guard", "suite for a"),
            ("a_b.guard", "suite for a_b"),
            ("a_b_c.guard", "suite for a_b_c"),
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

    /// A test file no rules file claimed is named, instead of being dropped in silence.
    ///
    /// This is what a rules file rename looks like. `s3_bucket.guard` beside `tests/s3_tests.yml`
    /// ran nothing and said only that the rules file had no tests associated, which reads as benign
    /// because a rules file legitimately may have none. The suite that was skipped fails: rename the
    /// file to `s3_bucket_tests.yml` and change nothing else and the run goes from exit 0 to exit 7.
    ///
    /// The exit code is deliberately still 0. A `tests/` directory may hold a yaml or json file that
    /// is not a suite at all and the walker cannot tell by name, so failing would break setups that
    /// work; and the line about the rules file must stay as it was, because it is not wrong.
    #[test]
    fn a_test_file_that_matches_no_rules_file_is_named_rather_than_discarded() {
        const DIR: &str = "resources/test-command/orphaned-test-file";

        // `stripped` and `err_to_stripped` each consume the writer, so one run cannot be read for
        // both streams. The command is deterministic over these files.
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let status_code = TestCommandTestRunner::default()
                .directory(Option::from(DIR))
                .run(&mut writer, &mut reader);

            (status_code, writer)
        };

        let (status_code, err_writer) = run();
        let (_, out_writer) = run();

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "naming the ignored file must not change the verdict"
        );

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains(&format!(
                "{} did not match any rules file, so it was not run",
                reported_path(DIR, &["tests", "s3_tests.yml"])
            )),
            "the ignored test file must be named, path included:\n{}",
            stderr
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            stdout.contains(&format!(
                "Guard File {} did not have any tests associated, skipping.",
                reported_path(DIR, &["s3_bucket.guard"])
            )),
            "and the existing line about the rules file must be unchanged:\n{}",
            stdout
        );
    }

    /// A directory where every test file pairs says nothing, so this does not become noise.
    ///
    /// Two shapes. `dir` is the plain one, every stem matching its own test file. The three-way
    /// collision is the one that matters: whether a file was taken is answered once, where it is
    /// taken, so longest-prefix pairing and this diagnostic cannot disagree. Deciding it a second
    /// time by repeating the prefix test is what would report a paired file as unpaired, and
    /// `a_b_tests.yml` -- which matches two stems and is claimed by one -- is where that would show.
    #[rstest]
    #[case("resources/test-command/dir")]
    #[case("resources/test-command/prefix-collision-three-way")]
    fn a_directory_where_every_test_file_pairs_reports_no_unmatched_file(#[case] dir: &str) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(dir))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            !stderr.contains("did not match any rules file"),
            "every test file in {} is paired, so nothing should be reported:\n{}",
            dir,
            stderr
        );
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

        // A combination the command cannot honour is the caller's mistake, so it carries clap's usage
        // code rather than the code that means cfn-guard fell over.
        assert_eq!(StatusCode::USAGE_ERROR, status_code);
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

    /// An expectation that names no rule in the file says so and fails the run.
    ///
    /// It used to be dropped in silence. Expectations are read per evaluated rule, so one whose name
    /// matches nothing is never consulted, and the run exited 0 having checked less than the file
    /// asked for. The fixture asserts FAIL twice on names that do not exist, which is the whole
    /// defect: a misspelled rule name turns an assertion into nothing without ever saying so.
    ///
    /// `INCORRECT_STATUS_ERROR` and not `TEST_COMMAND_FAILURE`, for the reason this file already
    /// gives where a rule cannot be evaluated: an expectation that could not be evaluated is a
    /// different answer from an expectation that was not met, and an expectation whose rule produced
    /// no verdict was not evaluated -- there was nothing to compare it against. A stale name in a
    /// test file is the same class of authoring defect as an unreadable expectation string, which
    /// this command already answers with the error code.
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
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an expectation with no rule to check it against must fail the run"
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

    /// An unchecked expectation reaches json, yaml and junit, and reddens all three.
    ///
    /// The plaintext reporter said so on stderr and no structured format said it at all. A consumer
    /// reading the report saw a clean suite over a file where nothing had been checked: with every
    /// expectation naming a rule that does not exist, the junit document was `tests="0"
    /// failures="0"` and the run exited 0.
    ///
    /// The junit case is `status="error"` with an `<error>` body, counted into the suite's `errors`.
    /// It was a `<skipped>`, which counts into `tests` and nowhere else -- so a CI step watching
    /// `failures` and `errors`, which is what a junit step watches, saw a suite where every
    /// expectation named a stale rule as entirely green.
    ///
    /// json and yaml carry the reason beside the name. There is more than one reason an expectation
    /// can go unchecked and they call for different fixes, so the name alone would leave a consumer
    /// to guess which one it had.
    ///
    /// Three expectations in the fixture and two unchecked ones per case, listed in sorted order
    /// rather than the order the expectations were read: they come from a `HashMap`.
    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn an_unchecked_expectation_is_reported_in_every_structured_format(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/data-dir/expectation_for_a_rule_that_does_not_exist.yaml",
            ))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .output_format(output)
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an expectation with no rule to check it against must fail the run"
        );

        let writer = if output == "junit" {
            sanitize_junit_writer(writer)
        } else {
            writer
        };

        assert_output_from_file_eq!(
            format!("resources/test-command/output-dir/unchecked_expectation_{output}.out")
                .as_str(),
            writer
        );
    }

    /// The two directions of an expectation/rule mismatch stay in separate arrays.
    ///
    /// `skipped_rules` holds rules the file defines which the test data gave no expectation for.
    /// `unchecked_expectations` holds expectations the test data gave which no rule answers. Reusing
    /// the first for the second would leave a consumer unable to tell which of the two had happened,
    /// so this fixture produces exactly one of each in one case and the report must keep them apart.
    ///
    /// They also differ in verdict, which is the second reason not to merge them: a rule the test
    /// data did not mention is a gap the author can see in the report, while an expectation no rule
    /// answers reads like coverage the author does not have. Only the second fails the run, so this
    /// fixture exits with the error code on account of its one unchecked expectation while its one
    /// unmentioned rule contributes nothing.
    #[test]
    fn an_unchecked_expectation_is_not_confused_with_a_rule_that_has_no_expectation() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/data-dir/a_rule_with_no_expectation_beside_an_unchecked_expectation.yaml",
            ))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .output_format("json")
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "the expectation with no rule fails the run; the rule with no expectation does not"
        );

        assert_output_from_file_eq!(
            "resources/test-command/output-dir/no_expectation_beside_unchecked_expectation_json.out",
            writer
        );
    }

    /// Which of two conditions decides the exit code when a run carries both.
    ///
    /// An unchecked expectation outranks a genuine unmet one, so `both` owes
    /// `INCORRECT_STATUS_ERROR` and not `TEST_COMMAND_FAILURE`. That is deliberate:
    /// `TestResult::get_exit_code` in `guard/src/commands/reporters/test/structured.rs` asks whether
    /// anything could not be evaluated before it asks whether anything failed, because an expectation
    /// whose rule produced no verdict was never evaluated -- there was nothing to compare it against --
    /// which is the same answer as a case that could not run rather than a weaker version of a failure.
    ///
    /// This exists because nothing pinned that decision and the code invites the opposite reading. The
    /// write for an unchecked expectation is the last of three in the generic reporter's per-case loop
    /// and, unlike the write for a failure two lines above it, carries no guard -- so it reads as an
    /// oversight silently clobbering the 7, and the 7 really does disappear. It is not an oversight,
    /// and inverting it is worse than it looks: within one file the reporter still knows *why* the code
    /// was set and can discriminate, but across files only the number survives the merge in
    /// `get_exit_code`, so the same two conditions would answer 7 packed in one file and 1 split across
    /// two. The exit code would become a function of corpus layout.
    ///
    /// A table rather than one case. `both` alone would be satisfied by a change that deleted the
    /// unchecked write, and `unmet_only` and `clean` are what catch that and its opposite.
    ///
    /// The exit code is asserted here and the diagnostic by
    /// [`an_unchecked_expectation_is_named_even_when_a_failure_shares_the_run`], because the two come
    /// from different lines and a change can take either one alone.
    #[rstest]
    #[case::unmet_only("unmet_only", StatusCode::TEST_COMMAND_FAILURE)]
    #[case::unchecked_only("unchecked_only", StatusCode::INCORRECT_STATUS_ERROR)]
    #[case::both("both", StatusCode::INCORRECT_STATUS_ERROR)]
    #[case::clean("clean", StatusCode::SUCCESS)]
    fn an_unchecked_expectation_outranks_an_unmet_one(
        #[case] data: &str,
        #[case] expected_code: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                format!("resources/test-command/exit-code-precedence/{data}.yaml").as_str(),
            ))
            .rules(Some(
                "resources/test-command/exit-code-precedence/precedence.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(
            expected_code, status_code,
            "{}.yaml exited {}, which is not the code this input owes",
            data, status_code
        );
    }

    /// The unchecked expectation is still named when a genuine failure shares the run.
    ///
    /// Asserted separately from the exit code because losing this is the more expensive of the two. The
    /// code that `both.yaml` earns is the same code an unreadable rules file earns, so on its own it
    /// does not tell the author that a rule name went stale; this sentence is the only thing that does,
    /// and it is what found eleven dead assertions in the rules registry. A change could satisfy
    /// [`an_unchecked_expectation_outranks_an_unmet_one`] while dropping the message entirely.
    ///
    /// The unmet expectation is asserted too, on stdout. The precedence decides which condition owns
    /// the exit code, not which one gets reported, and a run that stopped mentioning the failure
    /// because it lost the tie-break would be the same defect pointing the other way.
    #[test]
    fn an_unchecked_expectation_is_named_even_when_a_failure_shares_the_run() {
        // `stripped` and `err_to_stripped` each consume the writer, so one run cannot be read for
        // both streams. The command is deterministic over these files.
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let status_code = TestCommandTestRunner::default()
                .test_data(Option::from(
                    "resources/test-command/exit-code-precedence/both.yaml",
                ))
                .rules(Some(
                    "resources/test-command/exit-code-precedence/precedence.guard",
                ))
                .run(&mut writer, &mut reader);

            (status_code, writer)
        };

        let (status_code, err_writer) = run();
        let (_, out_writer) = run();

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "the expectation that was never evaluated owes the exit code"
        );

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains(
                "No rule named R_TYPO is in this file, so its expectation was not checked"
            ),
            "the unchecked expectation must be named, not just counted in the exit code:\n{}",
            stderr
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            stdout.contains("R_ONE: Expected = PASS, Evaluated = [FAIL]"),
            "and the expectation that was not met must still be reported:\n{}",
            stdout
        );
    }

    /// An expectation for a parameterized rule is not told it names nothing.
    ///
    /// It does name something. `eval_rules_file` walks `guard_rules` only, and a parameterized rule
    /// is evaluated where a clause invokes it, so it is recorded under the invoking rule rather than
    /// under the file and never appears among the rules an expectation can be matched against. The
    /// expectation is as inert as one naming a rule that does not exist -- so it fails the run the
    /// same way -- but `No rule named encryption_is_on is in this file` was false, and the sentence
    /// is now the stated reason for a failing run rather than a note beside a passing one.
    ///
    /// This is why the two cases are separated by what the file declares rather than by what ran.
    /// The other reason is that the fixes differ: this one wants the expectation moved to whatever
    /// invokes the rule, a stale name wants the test file corrected.
    #[test]
    fn an_expectation_for_a_parameterized_rule_says_it_is_parameterized() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/data-dir/expectation_for_a_parameterized_rule.yaml",
            ))
            .rules(Some(
                "resources/test-command/parameterized-rule/encryption.guard",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an expectation a parameterized rule can never answer must fail the run"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains(
                "encryption_is_on is a parameterized rule, which only gets a verdict where a clause invokes it, so its expectation was not checked"
            ),
            "the reason must name the rule and say it is parameterized:\n{}",
            stderr
        );
        assert!(
            !stderr.contains("No rule named encryption_is_on"),
            "and must not claim a rule the file declares is missing from it:\n{}",
            stderr
        );
    }

    /// In directory mode, an expectation for a rule defined in a sibling rules file fails.
    ///
    /// The case that decides whether failing on an unmatched expectation is right at all: if one
    /// test file could be run against several rules files, an expectation naming a sibling file's
    /// rule would be legitimate and failing on it would break working setups.
    ///
    /// It cannot. `OrderedTestDirectory::from` filters the rules files whose stem prefixes the test
    /// file name and then reduces them with `min_by_key`, which yields exactly one claimant, so a
    /// test file is evaluated against one rules file and no other. The fixture proves it from the
    /// outside: `tests/encryption_tests.yml` names `ENCRYPTION_ON` and `LOGGING_ON`, and the run
    /// checks the first while reporting `logging.guard` as having no tests at all -- its rule was
    /// never evaluated against this input, so `LOGGING_ON: PASS` asserted nothing.
    ///
    /// Both halves are asserted. Without the second, a future change that ran each test file against
    /// every rules file in the directory would make this expectation real and the failure wrong, and
    /// nothing here would notice.
    #[test]
    fn an_expectation_for_a_sibling_rules_files_rule_fails() {
        const DIR: &str = "resources/test-command/expectation-for-a-sibling-rule";

        // `stripped` and `err_to_stripped` each consume the writer, so one run cannot be read for
        // both streams. The command is deterministic over these files.
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let status_code = TestCommandTestRunner::default()
                .directory(Option::from(DIR))
                .run(&mut writer, &mut reader);

            (status_code, writer)
        };

        let (status_code, err_writer) = run();
        let (_, out_writer) = run();

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "the expectation for the sibling file's rule was never checked, so the run must say so"
        );

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains(
                "No rule named LOGGING_ON is in this file, so its expectation was not checked"
            ),
            "the unchecked expectation must be named:\n{}",
            stderr
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            stdout.contains("ENCRYPTION_ON: Expected = PASS"),
            "the expectation the paired rules file does answer must still be checked:\n{}",
            stdout
        );
        assert!(
            stdout.contains(&format!(
                "Guard File {} did not have any tests associated, skipping.",
                reported_path(DIR, &["logging.guard"])
            )),
            "and the sibling file must be shown taking no part in the run:\n{}",
            stdout
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

    /// The directory this cell and the structured one below walk.
    ///
    /// Two subdirectories holding a byte-identical `incomparable_membership.guard`, each with its own
    /// paired `tests/` suite, so the walk evaluates both and the only thing telling the two notices
    /// apart is what the locator names the file.
    const SAME_BASENAME_DIR: &str = "resources/test-command/same-basename-rules-dirs";

    /// The rules file both subdirectories hold, so the two locators differ only by their parent.
    const SAME_BASENAME_FILE: &str = "incomparable_membership.guard";

    /// Two rules files reached by walking one directory get two different locators.
    ///
    /// `test -d` located a rules file by `GuardFile::prefix`, the file name with `.guard` or `.ruleset`
    /// stripped, which was the coarsest of the three names this repository gave a rules file: it drops
    /// the directory *and* the extension, so `first/x.guard` and `second/x.guard` both parsed as `x`.
    /// Walking a directory is the invocation aws-guard-rules-registry CI uses, so the collision landed
    /// on the corpus most likely to hit it. Dropping the extension too is what made `prefix` worse than
    /// a basename, and the pair showing that is `ra/x.guard` beside `rb/x.ruleset` -- across
    /// directories, since within one the pairing tie-break leaves `x.ruleset` with no test files and
    /// both walks skip it. The note on the fix site in `test.rs` carries that measurement.
    ///
    /// The count is not the symptom on this path, and is deliberately not asserted.
    /// `handle_plaintext_directory` builds a `GenericReporter` per rules file and each one writes its
    /// own diagnostics set, so the count is 2 before the fix and 2 after -- an assertion on it passes
    /// with the site reverted and would be pure noise in the failure output. What was lost is that the
    /// two lines were the same bytes, leaving the reader unable to locate either clause. So this counts
    /// *distinct* lines, and then requires each locator to name the directory that tells the two files
    /// apart: distinctness alone would be satisfied by two lines differing for any incidental reason.
    ///
    /// `single-line-summary` only, deliberately. The structured formats reach
    /// `handle_structured_directory_report`, which is separate code with its own locator call and its
    /// own cell below, so this one is red for one reason.
    ///
    /// `two_rules_files_sharing_a_basename_get_distinct_locators` in `validate.rs` is the same property
    /// for `validate -r a -r b`, which named a rules file by a third route. The fixture cannot be
    /// shared: this walk requires a `tests/` directory beside each rules file, and the validate-side
    /// pair must not have one.
    #[test]
    fn a_directory_walk_gives_two_rules_files_sharing_a_basename_distinct_locators() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(SAME_BASENAME_DIR))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "naming a file is not a verdict; both suites still pass in this release"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();

        let distinct: std::collections::BTreeSet<&&str> = notices.iter().collect();
        assert_eq!(
            distinct.len(),
            2,
            "the two notices must differ; identical lines mean the locator dropped the only thing \
             that tells these two files apart, got {:?} from stderr {:?}",
            notices,
            stderr
        );

        for parent in ["first", "second"] {
            let located = reported_path(SAME_BASENAME_DIR, &[parent, SAME_BASENAME_FILE]);
            let matched: Vec<&&str> = notices.iter().filter(|n| n.contains(&located)).collect();

            assert_eq!(
                1,
                matched.len(),
                "expected exactly one notice locating the clause at `{}`, got {:?} from {:?}",
                located,
                matched,
                notices
            );
        }
    }

    /// The structured directory walk reports one notice per rules file, not one per directory.
    ///
    /// `handle_structured_directory_report` accumulates into a single `Diagnostics` set for the whole
    /// walk, and that is deliberate: it writes one document covering every rules file, so a notice two
    /// files both produce belongs in it once. What that made is a path where the *count* is a symptom,
    /// unlike the plaintext walk above. While a rules file was located by `GuardFile::prefix`, two
    /// files named `x.guard` in different subdirectories produced byte-identical notices, the set
    /// collapsed them, and `-o json`, `-o yaml` and `-o junit` each reported a single notice for two
    /// separate defective clauses.
    ///
    /// So this asserts the count first, which is what reddens if the locator regresses, and then the
    /// same distinctness and per-directory checks the plaintext cell makes -- a count of two reached by
    /// two identical lines is not what is wanted here either.
    ///
    /// All three structured formats. The count is decided in `handle_structured_directory_report`
    /// before the format is chosen, so covering only json would leave two formats asserting nothing
    /// about a defect they shared. There is no sarif case: `test` rejects `-o sarif` outright.
    ///
    /// Both streams, for the reason `a_deprecation_notice_reaches_the_test_command` gives: stdout is
    /// the document a junit or json consumer parses. The non-empty check on stdout is what stops this
    /// cell from passing over a run that produced no report at all.
    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn a_structured_directory_walk_reports_one_notice_per_rules_file(#[case] output: &str) {
        // `stripped` and `err_to_stripped` each consume the writer, so one run answers for one stream.
        // The command is deterministic over these files, so two runs read the same output twice.
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            let status_code = TestCommandTestRunner::default()
                .directory(Option::from(SAME_BASENAME_DIR))
                .output_format(output)
                .run(&mut writer, &mut reader);

            (status_code, writer)
        };

        let (status_code, out_writer) = run();
        let (_, err_writer) = run();

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "naming a file is not a verdict; both suites still pass in this release"
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            !stdout.contains("DEPRECATION"),
            "a notice on stdout would land inside the report that consumers parse, got {:?}",
            stdout
        );
        assert!(
            !stdout.is_empty(),
            "the report must still be written; an empty stdout means this cell is measuring a run \
             that produced nothing, not a notice per rules file"
        );

        if output == "json" {
            serde_json::from_str::<serde_json::Value>(&stdout)
                .expect("the report on stdout must still parse with the notices on stderr");
        }

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();

        assert_eq!(
            notices.len(),
            2,
            "two defective clauses in two rules files, so two notices; one means the walk's single \
             diagnostics set collapsed them because both files reported the same name. Got {:?} \
             from stderr {:?}",
            notices,
            stderr
        );

        let distinct: std::collections::BTreeSet<&&str> = notices.iter().collect();
        assert_eq!(
            distinct.len(),
            2,
            "the two notices must differ; two identical lines reaching a set would not have counted \
             two, so this also pins that the count above was not met by a duplicate, got {:?}",
            notices
        );

        for parent in ["first", "second"] {
            let located = reported_path(SAME_BASENAME_DIR, &[parent, SAME_BASENAME_FILE]);
            let matched: Vec<&&str> = notices.iter().filter(|n| n.contains(&located)).collect();

            assert_eq!(
                1,
                matched.len(),
                "expected exactly one notice locating the clause at `{}`, got {:?} from {:?}",
                located,
                matched,
                notices
            );
        }
    }

    /// The directory for the two cells below.
    ///
    /// Two subdirectories holding a byte-identical comment-only `declares_nothing.guard` -- a file that
    /// declares no rules at all -- each with a `tests/` suite expecting a rule. Comment-only rather than
    /// `let x = 1`: an assignment parses to `Ok(Some(RulesFile))` with zero rules and takes the arm that
    /// pushes a per-file report entry, so nothing is lost there. Only a file parsing to `Ok(None)` takes
    /// `report_expectations_against_no_rules`, which is the site under test.
    const NO_RULES_DIR: &str = "resources/test-command/no-rules-same-basename-dirs";

    /// The rules file both subdirectories hold.
    const NO_RULES_FILE: &str = "declares_nothing.guard";

    /// The rule name both suites expect and neither file declares.
    const NO_RULES_EXPECTATION: &str = "some_rule";

    /// Two rules files that declare nothing get two distinct records, walking one directory.
    ///
    /// `report_expectations_against_no_rules` named the file with `file_name_of`, the basename, and this
    /// is the arm where that costs the most: `Ok(None)` pushes no `TestResult`, so the structured
    /// document is `[]` and holds no `rule_file` field to recover the name from. The sentence is the
    /// whole record of what was dropped.
    ///
    /// The plaintext walk keeps one diagnostics set per rules file, so the count is 2 either way and is
    /// not asserted here, for the reason the deprecation-notice cell above gives. What the basename cost
    /// on this channel is that the two lines were the same bytes.
    ///
    /// Its structured sibling below is the same fix site, not a second one -- both walks call the one
    /// function -- so a revert reddens both. They are separate cells because the two channels lose
    /// different things: this one loses the ability to tell two records apart, that one loses a record.
    #[test]
    fn two_rules_files_declaring_nothing_get_distinct_records_in_a_directory_walk() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(NO_RULES_DIR))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an expectation that could not be evaluated is an error, and both files dropped one"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let reports: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("declares no rules, so the expectation for"))
            .collect();

        let distinct: std::collections::BTreeSet<&&str> = reports.iter().collect();
        assert_eq!(
            distinct.len(),
            2,
            "the two records must differ; identical lines mean the name dropped the only thing that \
             tells these two files apart, and this sentence is the only record either file gets. Got \
             {:?} from stderr {:?}",
            reports,
            stderr
        );

        for parent in ["first", "second"] {
            let located = reported_path(NO_RULES_DIR, &[parent, NO_RULES_FILE]);
            let matched: Vec<&&str> = reports.iter().filter(|r| r.contains(&located)).collect();

            assert_eq!(
                1,
                matched.len(),
                "expected exactly one record naming `{}`, got {:?} from {:?}",
                located,
                matched,
                reports
            );
        }
    }

    /// The structured walk reports both files that declared no rules, not one.
    ///
    /// This is the channel where the basename lost a record outright rather than making one illegible.
    /// `handle_structured_directory_report` keeps a single `Diagnostics` set across the walk, and
    /// `Ok(None)` contributes no `TestResult`, so two files that both declared nothing produced one
    /// stderr line and a document of `[]`. Two dropped expectations, one record between them, naming
    /// neither directory, and nothing anywhere else in the run to recover the second from.
    ///
    /// The count is asserted first, and the document is asserted to be exactly `[]` rather than merely
    /// non-empty: `[]` is what makes the stderr line the only record, and if that stops being true this
    /// cell is measuring something else and should be re-read rather than trusted.
    ///
    /// All three structured formats. The count is decided before the format is chosen, so covering only
    /// json would leave two formats asserting nothing about a defect they shared.
    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn a_structured_directory_walk_reports_every_file_that_declared_no_rules(#[case] output: &str) {
        // `stripped` and `err_to_stripped` each consume the writer, so one run answers for one stream.
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            let status_code = TestCommandTestRunner::default()
                .directory(Option::from(NO_RULES_DIR))
                .output_format(output)
                .run(&mut writer, &mut reader);

            (status_code, writer)
        };

        let (status_code, out_writer) = run();
        let (_, err_writer) = run();

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an expectation that could not be evaluated is an error, and both files dropped one"
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        if output == "json" {
            assert_eq!(
                stdout.trim(),
                "[]",
                "the premise of this cell is that the report carries no entry for either file, so the \
                 stderr record is the only one. A non-empty document means that premise no longer \
                 holds and the assertion below is measuring something else. Got {:?}",
                stdout
            );
        }
        assert!(
            !stdout.contains("declares no rules"),
            "the record belongs on stderr, not inside the document consumers parse, got {:?}",
            stdout
        );

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        let reports: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("declares no rules, so the expectation for"))
            .collect();

        assert_eq!(
            reports.len(),
            2,
            "two files each dropped an expectation for `{}`, so two records; one means the walk's \
             single diagnostics set collapsed them because both files reported the same name, and the \
             document carries nothing to recover the other from. Got {:?} from stderr {:?}",
            NO_RULES_EXPECTATION,
            reports,
            stderr
        );

        let distinct: std::collections::BTreeSet<&&str> = reports.iter().collect();
        assert_eq!(
            distinct.len(),
            2,
            "and they must differ, so the count above was not met by a duplicate, got {:?}",
            reports
        );

        for parent in ["first", "second"] {
            let located = reported_path(NO_RULES_DIR, &[parent, NO_RULES_FILE]);
            let matched: Vec<&&str> = reports.iter().filter(|r| r.contains(&located)).collect();

            assert_eq!(
                1,
                matched.len(),
                "expected exactly one record naming `{}`, got {:?} from {:?}",
                located,
                matched,
                reports
            );
        }
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

    /// `test` requires `--rules-file` and `--test-data` together, and says so instead of panicking.
    ///
    /// The `RULES_AND_TEST_FILE` group carried `requires_all` but had never been given any members, and
    /// a clap group with no members can never be present, so the requirement never fired. `execute`
    /// then did `self.test_data.as_ref().unwrap()` and the process panicked at exit 101.
    /// `arg_required_else_help` hid it, because it only covers `cfn-guard test` with no arguments at
    /// all.
    #[rstest]
    #[case::only_a_rules_file(vec!["test", "-r", "some-rules.guard"])]
    #[case::only_a_test_data_file(vec!["test", "-t", "some-tests.yaml"])]
    fn test_requires_a_rules_file_and_a_test_data_file_together(#[case] args: Vec<&str>) {
        let error =
            CfnGuard::try_parse_from(args).expect_err("one of the pair on its own must not parse");

        assert_eq!(StatusCode::USAGE_ERROR, error.exit_code());
    }

    /// `--dir` conflicts with `--rules-file` and `--test-data`, rather than silently winning.
    ///
    /// The same empty group is why. `execute` reads `self.directory` first, so
    /// `test -d dir -r other.guard` ran the directory and never looked at `-r`: byte-identical output
    /// to `test -d dir`, exit 0, no diagnostic. The caller asked for two things and got one, and
    /// nothing said so -- while the doc comments on all three fields claimed the conflict existed and
    /// `TestBuilder::try_build` enforced half of it for library callers.
    #[rstest]
    #[case::directory_and_both(vec!["test", "-d", "some-dir", "-r", "r.guard", "-t", "t.yaml"])]
    #[case::directory_and_rules(vec!["test", "-d", "some-dir", "-r", "r.guard"])]
    #[case::directory_and_test_data(vec!["test", "-d", "some-dir", "-t", "t.yaml"])]
    fn a_directory_conflicts_with_a_rules_file_and_a_test_data_file(#[case] args: Vec<&str>) {
        let error = CfnGuard::try_parse_from(args)
            .expect_err("--dir beside --rules-file or --test-data must not parse");

        assert_eq!(StatusCode::USAGE_ERROR, error.exit_code());
    }

    /// A directory handed to `--rules-file` is reported as a rules file that could not be read.
    ///
    /// It exited 255 with "I/O error when reading invalid input parameter": no path named, and "input
    /// parameter" is `validate`'s `--input-params`, a flag `test` does not have. 255 is the code
    /// `guard/README.md` gives to cfn-guard itself failing.
    ///
    /// `INCORRECT_STATUS_ERROR` is 1, which that table defines for `test` as "an expectation could not
    /// be evaluated, or a rules or test file could not be read".
    #[test]
    fn a_directory_given_to_rules_file_is_reported_as_unreadable() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some("resources/test-command/data-dir/test.yaml"))
            .rules(Some("resources/test-command/dir"))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INCORRECT_STATUS_ERROR, status_code);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains("is not a rules file") && stderr.contains("--dir"),
            "the message must name the path and point at --dir, got: {}",
            stderr
        );
    }

    /// A rules file that declares no rules reports every expectation it could not check.
    ///
    /// This was the third of three ways an expectation goes unchecked, and the only one that said
    /// nothing: `parse_rules` returns `Ok(None)` for an empty, comment-only or whitespace-only file, and
    /// the run ended before any expectation was looked at -- exit 0, no output. The suite asserted a
    /// verdict, nothing verified it, and CI read success. The other two exit
    /// `INCORRECT_STATUS_ERROR` and name the rule.
    #[rstest]
    #[case::an_empty_file("resources/validate/blank-rule.guard")]
    #[case::a_comment_only_file("resources/validate/comments.guard")]
    fn a_rules_file_declaring_no_rules_reports_its_unchecked_expectations(#[case] rules: &str) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = TestCommandTestRunner::default()
            .test_data(Some("resources/test-command/data-dir/test.yaml"))
            .rules(Some(rules))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INCORRECT_STATUS_ERROR, status_code);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains("declares no rules, so the expectation for"),
            "every unchecked expectation must be named, got: {}",
            stderr
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

        // Rejected by clap now, not at `execute`: `sarif` is no longer among `-o`'s possible values,
        // because `test` has no SARIF reporter and `--help` was advertising the one value that could
        // only ever fail. `USAGE_ERROR` rather than `INTERNAL_FAILURE` either way -- naming an output
        // format the command does not have is the caller's mistake, not cfn-guard breaking.
        assert_eq!(StatusCode::USAGE_ERROR, status_code);
    }

    /// Every output format `test` has a reporter for.
    ///
    /// Named in one place because the two tests below run all of them over one input. A table that
    /// lists three of the four is how the two halves of this command drifted apart, twice.
    const EVERY_OUTPUT_FORMAT: [&str; 4] = ["single-line-summary", "json", "yaml", "junit"];

    /// What each output format made of one invocation: its name, the code the run exited with, and its
    /// stderr.
    type PerFormat = Vec<(&'static str, i32, String)>;

    /// Asserts every format gave the same exit code and the same stderr, and returns the pair they
    /// agreed on so the caller can then say what it should have been.
    ///
    /// Compared against the first format rather than every pair: agreement is transitive, so N-1
    /// comparisons decide it, and a failure names the two formats that differ either way.
    ///
    /// Every message here passes its values positionally. This crate is edition 2018, where
    /// `assert!(cond, "{value}")` hands the string to `panic!` unformatted and the braces reach the
    /// output literally -- so an inline-captured message reads as `{format} disagrees` on the run that
    /// needed it most. `assert_eq!` routes through `format_args!` and does interpolate, which is worse
    /// than if neither did: the two macros would disagree for the same written message.
    fn the_formats_agree(results: &PerFormat, input: &str) -> (i32, String) {
        let (first_format, first_code, first_stderr) =
            results.first().expect("no output format was run");

        for (format, code, stderr) in results {
            assert_eq!(
                first_code, code,
                "{}: {} exits {} where {} exits {}, on the same input",
                input, first_format, first_code, format, code
            );
            assert_eq!(
                first_stderr, stderr,
                "{}: {} and {} report different diagnostics for the same input",
                input, first_format, format
            );
        }

        (*first_code, first_stderr.clone())
    }

    fn every_format_over_one_rules_file(rules: &str, test_data: &str) -> PerFormat {
        EVERY_OUTPUT_FORMAT
            .iter()
            .map(|&format| {
                let mut reader = Reader::default();
                let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                    .expect("Failed to create writer.");
                let status_code = TestCommandTestRunner::default()
                    .test_data(Some(test_data))
                    .rules(Some(rules))
                    .output_format(format)
                    .run(&mut writer, &mut reader);

                (
                    format,
                    status_code,
                    writer.err_to_stripped().expect("failed to read stderr"),
                )
            })
            .collect()
    }

    fn every_format_over_a_directory(dir: &str) -> PerFormat {
        EVERY_OUTPUT_FORMAT
            .iter()
            .map(|&format| {
                let mut reader = Reader::default();
                let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                    .expect("Failed to create writer.");
                let status_code = TestCommandTestRunner::default()
                    .directory(Some(dir))
                    .output_format(format)
                    .run(&mut writer, &mut reader);

                (
                    format,
                    status_code,
                    writer.err_to_stripped().expect("failed to read stderr"),
                )
            })
            .collect()
    }

    /// One rules file and one test data file: all four output formats exit with the same code and put
    /// the same diagnostics on stderr.
    ///
    /// This asserts the invariant rather than an instance of it, and the reason is that two rounds of
    /// instance assertions each missed the half the other was about.
    /// [`a_case_whose_input_cannot_be_read_does_not_discard_the_other_cases`] pinned the generic
    /// reporter, its structured sibling went unfixed, and the sibling test that closed that gap pinned
    /// the structured reporter -- so when the generic reporter later lost a diagnostic the structured
    /// one kept, nothing failed. "The structured format reports X" cannot catch a disagreement; only
    /// "the formats report the same thing" can, and it catches it in whichever direction it appears.
    ///
    /// The exit code and stderr are the right two things to compare because they are the only outputs
    /// that do not depend on the format. The report itself is legitimately four different documents.
    /// `write_diagnostics` writes to stderr from code both reporters share, so the same input owes the
    /// same sentences there; and one input has one verdict, so it owes one number.
    ///
    /// Two defects this would have caught, one per column. A rules file the command could not read or
    /// parse exited 0 through `json`, `yaml` and `junit` and 1 through `single-line-summary`, because
    /// `handle_structured_single_report` assigned its exit code only in the arm where the rules file
    /// parsed -- so a CI job gating on the code read a ruleset that never loaded as a pass, while the
    /// junit document beside it said `errors="1"`. And a case carrying both a bad expectation string
    /// and an expectation naming a rule that does not exist lost the second diagnostic in
    /// `single-line-summary` alone, because the generic reporter computed it after the loop that
    /// abandons such a case.
    ///
    /// What this does not cover: the content of the reports, which
    /// [`test_structured_single_report`] and the golden files own; `sarif`, which `test` rejects at the
    /// parser; and the ordering of stderr against stdout, which is not fixed because they are separate
    /// streams. It also cannot see a disagreement over an input shape absent from the table -- the
    /// nine cases here are the shapes the two reporters take different branches on, not a proof of
    /// agreement over all inputs.
    #[rstest]
    #[case::everything_passes(
        "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        "resources/test-command/data-dir/s3_bucket_server_side_encryption_enabled.yaml",
        StatusCode::SUCCESS
    )]
    #[case::an_expectation_that_was_not_met(
        "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        "resources/test-command/data-dir/failing_test.yaml",
        StatusCode::TEST_COMMAND_FAILURE
    )]
    #[case::a_rules_file_that_will_not_parse(
        "resources/test-command/rule-dir/invalid_rule.guard",
        "resources/test-command/data-dir/test.yaml",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::a_rules_file_that_cannot_be_read(
        "resources/test-command/format-agreement/not_utf8.guard",
        "resources/test-command/data-dir/test.yaml",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::a_rules_file_that_declares_no_rules(
        "resources/validate/blank-rule.guard",
        "resources/test-command/data-dir/test.yaml",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::a_bad_expectation_beside_a_stale_rule_name(
        "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        "resources/test-command/format-agreement/a_bad_expectation_beside_a_stale_rule_name.yaml",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::a_stale_rule_name_alone(
        "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        "resources/test-command/data-dir/expectation_for_a_rule_that_does_not_exist.yaml",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::an_expectation_for_a_parameterized_rule(
        "resources/test-command/parameterized-rule/encryption.guard",
        "resources/test-command/data-dir/expectation_for_a_parameterized_rule.yaml",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::a_case_whose_input_cannot_be_read(
        "resources/test-command/rule-dir/a_case_whose_input_cannot_be_read.guard",
        "resources/test-command/data-dir/a_case_whose_input_cannot_be_read_tests.yaml",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    fn every_output_format_agrees_over_one_rules_file(
        #[case] rules: &str,
        #[case] test_data: &str,
        #[case] expected_code: i32,
    ) {
        let results = every_format_over_one_rules_file(rules, test_data);
        let (code, _) = the_formats_agree(&results, test_data);

        // Agreeing on the wrong number is still agreement, so the number is named too.
        assert_eq!(
            expected_code, code,
            "{}: every format agreed on {}, which is not the code this input owes",
            test_data, code
        );
    }

    /// The same invariant over a directory walk, which is a separate pair of handlers.
    ///
    /// Not folded into the table above, because `handle_plaintext_directory` and
    /// `handle_structured_directory_report` are different code from the single-file pair and held three
    /// disagreements of their own. A rules file that would not parse exited 7 here and 1 in the three
    /// structured formats -- `guard/README.md` gives 7 to an expectation that was not met and 1 to one
    /// that could not be evaluated, and a file that will not parse is the second. A rules file that
    /// could not be read was worse: the plaintext walk propagated it to `main`'s catch-all for 255,
    /// the code reserved for cfn-guard itself breaking, and abandoned every later rules file in the
    /// directory. And a walk whose first file failed an expectation and whose second could not evaluate
    /// one exited 7 rather than 1, because the plaintext merge kept whatever it already had instead of
    /// letting an error outrank a failure.
    ///
    /// The last of those is why the fixtures are named `a_` and `b_`: the walk is sorted by file name,
    /// so the failure has to be reached before the error for the merge to be the thing under test.
    #[rstest]
    #[case::everything_passes("resources/test-command/dir", StatusCode::SUCCESS)]
    #[case::a_rules_file_that_will_not_parse(
        "resources/test-command/format-agreement/a-rules-file-that-will-not-parse",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::a_rules_file_that_cannot_be_read(
        "resources/test-command/format-agreement/an-unreadable-rules-file",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    #[case::a_failure_reached_before_an_error(
        "resources/test-command/format-agreement/a-failure-before-an-error",
        StatusCode::INCORRECT_STATUS_ERROR
    )]
    fn every_output_format_agrees_over_a_directory(#[case] dir: &str, #[case] expected_code: i32) {
        let results = every_format_over_a_directory(dir);
        let (code, _) = the_formats_agree(&results, dir);

        assert_eq!(
            expected_code, code,
            "{}: every format agreed on {}, which is not the code this input owes",
            dir, code
        );
    }

    /// A rules file that cannot be read does not end the directory walk in any output format.
    ///
    /// The other half of the 255 above, and the half an exit code cannot express: propagating with `?`
    /// left the walk entirely, so `b_readable.guard` -- which sorts after the unreadable file and
    /// passes -- was never reached, and its suite went unrun in silence under `single-line-summary`
    /// while all three structured formats reported it. Asserted per format rather than once, because a
    /// return to propagating would show in exactly one of them.
    #[test]
    fn an_unreadable_rules_file_does_not_end_a_directory_walk() {
        const DIR: &str = "resources/test-command/format-agreement/an-unreadable-rules-file";

        for format in EVERY_OUTPUT_FORMAT {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            TestCommandTestRunner::default()
                .directory(Some(DIR))
                .output_format(format)
                .run(&mut writer, &mut reader);

            let stdout = writer.stripped().expect("failed to read stdout");
            assert!(
                stdout.contains("b_readable"),
                "{} stopped at the unreadable rules file instead of going on to the next one:\n{}",
                format,
                stdout
            );
        }
    }
}
