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

    use crate::utils::{
        capture_both_streams, sanitize_junit_writer, Command, CommandTestRunner, StatusCode,
    };

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
    /// scalar, a null key and a sequence key. Spec files are read through the libyaml loader, which
    /// leaves a node it refuses in the document as an unreadable value, so each of the four it refuses
    /// costs its own case and nothing else; a loader that refused such a node while reading the document
    /// would cost the whole file, the first case's verdict included, which is the answer this test is
    /// written to reject. The quoted `"<<"` is an ordinary key to a YAML reader and its case runs. The
    /// fixture holds all five, plus the conversion-time shape (a scalar tagged `!!int` whose payload is
    /// not an integer), which is per-case on any reading, plus a sequence tagged `!!If`, whose refusal
    /// goes through the spec loader's policy like every other refused node's rather than refusing the
    /// whole document.
    ///
    /// This asserts the generic reporter only, which is a `Writer`'s text. The three structured formats
    /// are pinned by
    /// [`a_case_whose_input_cannot_be_read_does_not_discard_the_other_cases_in_structured_formats`],
    /// because a test that asserts one reporter pins nothing about the other three, whatever its
    /// comment says they do.
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
        assert_eq!(
            8,
            output.matches("Test Case #").count(),
            "every case is reported, the unreadable ones as errors:\n{}",
            output
        );
        assert!(
            output.contains(
                "Name: a bucket named something other than expected\n  PASS Rules:\n    \
                 bucket_is_named_expected: Expected = FAIL"
            ),
            "the decidable case's verdict must still be reported:\n{}",
            output
        );
        assert!(
            output.contains(
                "Name: an input whose quoted merge key is given a scalar\n  PASS Rules:\n    \
                 bucket_is_named_expected: Expected = PASS"
            ),
            "the quoted merge key is an ordinary key and its case runs:\n{}",
            output
        );
        for refusal in [
            "the merge key `<<` at L:24,C:9 must be given a mapping",
            "the merge key `<<` at L:37,C:25 must be given a mapping",
            "L:64,C:5, where the key is null",
            "L:77,C:7, where the key is a sequence",
            "not-a-number",
            "does not read the tag `!!If` at L:107,C:11",
        ] {
            assert_eq!(
                1,
                output.matches(refusal).count(),
                "each unreadable input is reported once, as its own case's error ({refusal}):\n{}",
                output
            );
        }
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
        // regex alongside the alternation it was tried in: the regex error is recoverable, and its
        // message is kept rather than discarded.
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
    /// run their own suite and neither may be skipped, so longest-prefix pairing cannot be mistaken for
    /// a rule that fails any directory it cannot pair confidently.
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
    /// This one passes under longest-match pairing and under plain prefix pairing alike. That is what it
    /// is for.
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
    /// Expectations are read per evaluated rule, so one whose name matches nothing is never consulted;
    /// without this report the run would exit 0 having checked less than the file asked for. The
    /// fixture asserts FAIL twice on names that do not exist, which is the whole defect: a misspelled
    /// rule name would turn an assertion into nothing without ever saying so.
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

    /// A refusal settled beside a gate's error is named by `test` when the expectation on the gated rule is
    /// unmet. `test` prints per-rule statuses and no messages, and the refused-read line that used to name
    /// such a refusal is not written for this shape, so the unmet line carries the rule's sentence as its
    /// reason: the gated rule failed closed on the converter's error, and the refusal follows it whole.
    ///
    /// Fails when the unmet lines carry no reason, or when the reason lacks the refused map's path.
    #[test]
    fn an_unmet_expectation_on_a_gated_rule_names_the_refusal_settled_beside_the_error() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let _ = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/gate.yaml",
            ))
            .rules(Some(
                "resources/validate/gate_failing_closed_beside_a_settled_refusal.guard",
            ))
            .run(&mut writer, &mut reader);
        let stdout = writer.stripped().expect("failed to read stdout");
        let unmet: Vec<&str> = stdout
            .lines()
            .filter(|line| line.contains("Expected = PASS, Evaluated = [FAIL]"))
            .collect();
        assert!(
            unmet.len() == 2
                && unmet.iter().all(|line| {
                    line.contains(", Reason = ")
                        && line.contains("; the condition also met: ")
                        && line.contains("/Resources/M/Tags")
                }),
            "both unmet lines carry the reason with the refusal and its path:\n{}",
            stdout
        );
    }

    /// The structured reports of `test` carry the reason of an unmet expectation on a gated rule as the plain
    /// report does (`an_unmet_expectation_on_a_gated_rule_names_the_refusal_settled_beside_the_error`): the
    /// rule's sentence with the refusal joined to it, in the failed rule's `reason` for `json` and `yaml` and
    /// after `Reason = ` in the failure text of `junit`, once for each of the two gated rules.
    ///
    /// Fails when a report carries no reason (a count of 0), when one of the two rules lacks it (a
    /// count of 1), or when the refusal's path is missing from the text.
    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn a_structured_report_of_an_unmet_expectation_on_a_gated_rule_carries_the_reason(
        #[case] output: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let _ = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/gate.yaml",
            ))
            .rules(Some(
                "resources/validate/gate_failing_closed_beside_a_settled_refusal.guard",
            ))
            .output_format(output)
            .run(&mut writer, &mut reader);
        let stdout = writer.stripped().expect("failed to read stdout");
        assert_eq!(
            2,
            stdout.matches("; the condition also met: ").count(),
            "each of the two gated rules carries the refusal joined to its sentence in the {output} report:\n{stdout}"
        );
        assert!(
            stdout.matches("/Resources/M/Tags").count() >= 2,
            "and the refusal's path, at least once for each:\n{}",
            stdout
        );
    }

    /// The reason an unmet expectation carries is written through the console's one pipeline: the sentence
    /// collapsed on its line breaks alone, then its controls escaped, so a tab in the value the converter's
    /// error quotes reads as the two characters `\t` and a no-break space (not a control, not a line break)
    /// stays what it is. Folding every run of whitespace into a space before escaping, as the first form of
    /// this line did, printed both as a plain space.
    #[test]
    fn the_reason_of_an_unmet_expectation_is_escaped_as_the_console_escapes_it() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let _ = TestCommandTestRunner::default()
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/tab-and-no-break-space.yaml",
            ))
            .rules(Some(
                "resources/validate/gate_converter_error_on_a_long_value_beside_a_settled_refusal.guard",
            ))
            .run(&mut writer, &mut reader);
        let stdout = writer.stripped().expect("failed to read stdout");
        let reasons: Vec<&str> = stdout
            .lines()
            .filter(|line| line.contains(", Reason = "))
            .collect();
        assert!(
            reasons.len() == 2
                && reasons
                    .iter()
                    .all(|line| line.contains("a\\tb\u{a0}c") && !line.contains('\t')),
            "both unmet lines carry the reason with the tab escaped and the no-break space kept:\n{}",
            stdout
        );
    }

    /// The reason of an unmet expectation is bounded where the format is read by a person and carried whole
    /// where it is read by a program: the plain reporter prints the console's form (the plain head cut at
    /// the recorded-message bound, the one-word 910-character value dropped whole, the ellipsis before the
    /// join), and `json`, `yaml` and `junit` carry the raw sentence, the whole value in each of the two
    /// unmet rules' reasons.
    ///
    /// Fails when the plain line carries the long value (a run of 321 letters) or no cut, or when a
    /// structured report cuts the value (fewer than two whole runs of 900).
    #[rstest]
    #[case(None)]
    #[case(Some("json"))]
    #[case(Some("yaml"))]
    #[case(Some("junit"))]
    fn the_reason_is_cut_in_the_plain_report_and_whole_in_the_structured_ones(
        #[case] output: Option<&str>,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let mut runner = TestCommandTestRunner::default();
        let runner = runner
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/long-value.yaml",
            ))
            .rules(Some(
                "resources/validate/gate_converter_error_on_a_long_value_beside_a_settled_refusal.guard",
            ));
        let _ = match output {
            Some(format) => runner.output_format(format).run(&mut writer, &mut reader),
            None => runner.run(&mut writer, &mut reader),
        };
        let stdout = writer.stripped().expect("failed to read stdout");
        let whole = "x".repeat(900);
        match output {
            None => assert!(
                !stdout.contains(&"x".repeat(321))
                    && stdout
                        .matches("not a number...; the condition also met: ")
                        .count()
                        == 2,
                "the plain reasons are cut at the console bound, the value dropped whole:\n{}",
                stdout
            ),
            Some(_) => assert_eq!(
                2,
                stdout.matches(&whole).count(),
                "the structured reasons carry the whole value, once for each unmet rule:\n{stdout}"
            ),
        }
    }

    /// A rule whose sentence has a REFUSAL for its head and a second refusal joined to it keeps its `Reason`
    /// under `test`, as one with a plain head does: the reporters key on whether the sentence joined refusals
    /// (`Messages::parts`, carried whatever the head's kind), not on the head being plain. Both gated rules of
    /// the rules file fail closed on a refusal with the other map's refusal beside it; each unmet line names
    /// both refused maps, in the plain reporter and in `json`.
    ///
    /// Fails when an unmet line carries no reason (the head being a refusal dropped the parts), or
    /// when a reason names only one of the two maps.
    #[rstest]
    #[case(None)]
    #[case(Some("json"))]
    fn an_unmet_expectation_on_a_rule_with_a_refusal_head_keeps_its_reason(
        #[case] output: Option<&str>,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let mut runner = TestCommandTestRunner::default();
        let runner = runner
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/two-refusals.yaml",
            ))
            .rules(Some(
                "resources/validate/gate_failing_closed_on_a_refusal_beside_a_second_refusal.guard",
            ));
        let _ = match output {
            Some(format) => runner.output_format(format).run(&mut writer, &mut reader),
            None => runner.run(&mut writer, &mut reader),
        };
        let stdout = writer.stripped().expect("failed to read stdout");
        let both_maps =
            |text: &str| text.contains("/Resources/M1/Tags") && text.contains("/Resources/M2/Tags");
        let reasons: Vec<&str> = match output {
            None => stdout
                .lines()
                .filter(|line| line.contains(", Reason = "))
                .collect(),
            Some(_) => stdout
                .lines()
                .filter(|line| line.contains("\"reason\""))
                .collect(),
        };
        assert!(
            reasons.len() == 2 && reasons.iter().all(|line| both_maps(line)),
            "both unmet rules carry a reason naming both refused maps:\n{}",
            stdout
        );
    }

    /// A FAIL expectation MET on a rule that failed closed on two refusals still says why, in every output:
    /// the met line of the plain report reads `<rule>: Expected = FAIL, Reason = <sentence>`, `json` and
    /// `yaml` carry `reason` on the passed rule, and `junit` writes the sentence as the passed case's
    /// `<system-out>` text. Both gated rules of the rules file fail closed on one map's refusal with the
    /// other map's beside it, so each reason names both refused maps, and names each once: two refusals
    /// joined by one `; the condition also met: `, never a third.
    ///
    /// Fails when a met FAIL line carries no reason, when a reason names one map only or carries two
    /// joiners (a refusal told twice), when the plain line takes the unmet shape (`Evaluated =`), or when
    /// the junit case is written as a failure.
    #[rstest]
    #[case(None)]
    #[case(Some("json"))]
    #[case(Some("yaml"))]
    #[case(Some("junit"))]
    fn a_met_fail_expectation_on_a_rule_that_failed_closed_on_two_refusals_says_why(
        #[case] output: Option<&str>,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let mut runner = TestCommandTestRunner::default();
        let runner = runner
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/two-refusals-expected-fail.yaml",
            ))
            .rules(Some(
                "resources/validate/gate_failing_closed_on_a_refusal_beside_a_second_refusal.guard",
            ));
        let _ = match output {
            Some(format) => runner.output_format(format).run(&mut writer, &mut reader),
            None => runner.run(&mut writer, &mut reader),
        };
        let stdout = writer.stripped().expect("failed to read stdout");
        let names_each_once = |text: &str| {
            text.contains("/Resources/M1/Tags")
                && text.contains("/Resources/M2/Tags")
                && text.matches("; the condition also met: ").count() == 1
        };
        let reason_marker = match output {
            None => "Expected = FAIL, Reason = ",
            Some("json") => "\"reason\": ",
            Some("yaml") => "reason: ",
            Some(_) => "<system-out>Reason = ",
        };
        let reasons: Vec<&str> = stdout
            .lines()
            .filter(|line| line.contains(reason_marker))
            .collect();
        let no_other_shape = match output {
            None => !stdout.contains("Evaluated ="),
            Some("junit") => {
                !stdout.contains("<failure") && stdout.matches("status=\"pass\"").count() == 2
            }
            Some(_) => !stdout.contains("\"expected\"") && !stdout.contains("expected: "),
        };
        assert!(
            reasons.len() == 2 && reasons.iter().all(|line| names_each_once(line)) && no_other_shape,
            "both met FAIL lines carry a reason naming each refused map once, in the met shape:\n{}",
            stdout
        );
    }

    /// A rule that failed closed on ONE refusal, with nothing joined to its sentence, carries that sentence
    /// as its reason: an unmet PASS expectation on a rule whose `when` holds one filter read over a scalar
    /// `Tags` (refused) and whose body never runs names the refused map exactly once after `Reason = ` in
    /// the plain report, under `reason` in `json` and `yaml`, and after `Reason = ` in the junit failure
    /// text, with no `; the condition also met: ` joiner, since there is no second refusal to join. The
    /// two-refusal fixture is not this shape: its gates have a block body whose read of the empty selection
    /// is refused too, so the sentence there joins two refusals.
    ///
    /// Fails when the unmet line carries no reason (the reporters keyed on a joined sentence only), when
    /// the reason names the map twice or not at all, or when it carries a joiner.
    #[rstest]
    #[case(None)]
    #[case(Some("json"))]
    #[case(Some("yaml"))]
    #[case(Some("junit"))]
    fn an_unmet_expectation_on_a_rule_that_failed_closed_on_one_refusal_carries_its_sentence(
        #[case] output: Option<&str>,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let mut runner = TestCommandTestRunner::default();
        let runner = runner
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/one-refusal.yaml",
            ))
            .rules(Some(
                "resources/test-command/refusal-beside-a-gates-error/one-refusal.guard",
            ));
        let _ = match output {
            Some(format) => runner.output_format(format).run(&mut writer, &mut reader),
            None => runner.run(&mut writer, &mut reader),
        };
        let stdout = writer.stripped().expect("failed to read stdout");
        let reason_marker = match output {
            None => ", Reason = ",
            Some("json") => "\"reason\": ",
            Some("yaml") => "reason: ",
            Some(_) => ", Reason = ",
        };
        let reasons: Vec<&str> = stdout
            .lines()
            .filter(|line| line.contains(reason_marker))
            .collect();
        assert!(
            reasons.len() == 1
                && reasons.iter().all(|line| {
                    line.matches("/Resources/M1/Tags").count() == 1
                        && !line.contains("the condition also met")
                }),
            "the unmet line carries the rule's own refusal sentence, naming the map once, with nothing joined:\n{}",
            stdout
        );
    }

    /// Where no refusal decided a rule, no reason is written, and the output is what it was before a
    /// passed rule could carry one: a rule evaluated PASS under a met expectation, and a rule that failed
    /// on a plain comparison (a key the document lacks) under a call with an author's `<< >>` text, met by a
    /// FAIL expectation. The plain lines read `passes: Expected = PASS` and `author_body: Expected = FAIL`
    /// with nothing after; the `json` records are the two-field objects pinned here, with no `reason` key.
    /// The `json` check is on the quoted key, since the report's `rule_file` names the fixture file and
    /// that name holds the word.
    ///
    /// Fails when either line gains a `Reason`, when the author's text is written as one, or when a
    /// `"reason"` key (null or otherwise) appears in the `json`.
    #[rstest]
    #[case(None)]
    #[case(Some("json"))]
    fn a_passed_rule_and_a_plain_failure_under_an_author_text_carry_no_reason(
        #[case] output: Option<&str>,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let mut runner = TestCommandTestRunner::default();
        let runner = runner
            .test_data(Option::from(
                "resources/test-command/refusal-beside-a-gates-error/no-reason-controls.yaml",
            ))
            .rules(Some(
                "resources/test-command/refusal-beside-a-gates-error/no-reason-controls.guard",
            ));
        let _ = match output {
            Some(format) => runner.output_format(format).run(&mut writer, &mut reader),
            None => runner.run(&mut writer, &mut reader),
        };
        let stdout = writer.stripped().expect("failed to read stdout");
        match output {
            None => assert!(
                stdout.contains("passes: Expected = PASS\n")
                    && stdout.contains("author_body: Expected = FAIL\n")
                    && !stdout.contains("Reason")
                    && !stdout.contains("the author says so"),
                "both met lines end at the status, with no reason and no author text:\n{}",
                stdout
            ),
            Some(_) => assert!(
                stdout.contains(
                    "        {\n          \"name\": \"passes\",\n          \"evaluated\": \"PASS\"\n        }"
                ) && stdout.contains(
                    "        {\n          \"name\": \"author_body\",\n          \"evaluated\": \"FAIL\"\n        }"
                ) && !stdout.contains("\"reason\""),
                "both passed records are the two-field objects, with no reason key:\n{}",
                stdout
            ),
        }
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
    /// One notice from three cases, not three: a rule file is evaluated once per case, so the same
    /// notice is produced again for every case, and they are collapsed before being written.
    #[rstest]
    #[case("")]
    #[case("json")]
    fn a_deprecation_notice_reaches_the_test_command(#[case] output: &str) {
        const DATA: &str = "resources/test-command/data-dir/incomparable_membership_cases.yaml";
        const RULES: &str = "resources/validate/incomparable_membership_clause.guard";

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
            "a notice must not change the verdict; the clause still passes in this release"
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
            1,
            "expected one notice for the one warning clause across all three cases, got {:?} from \
             stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices[0].contains("could not be compared with any element"),
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
    /// both walks skip it. The note on the locator in `test.rs` carries that measurement.
    ///
    /// The count is not the symptom on this path, and is deliberately not asserted.
    /// `handle_plaintext_directory` builds a `GenericReporter` per rules file and each one writes its
    /// own diagnostics set, so the count is 2 whichever name locates the file -- an assertion on it
    /// passes with `prefix` as the locator and would be pure noise in the failure output. What was lost
    /// is that the two lines were the same bytes, leaving the reader unable to locate either clause. So
    /// this counts *distinct* lines, and then requires each locator to name the directory that tells
    /// the two files apart: distinctness alone would be satisfied by two lines differing for any
    /// incidental reason.
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
    /// Its structured sibling below exercises the same site, not a second one -- both walks call the
    /// one function -- so a basename locator reddens both. They are separate cells because the two
    /// channels lose different things: this one loses the ability to tell two records apart, that one
    /// loses a record.
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

    /// The directory for the two cells below.
    ///
    /// Two subdirectories holding a byte-identical `names_absent_rule.guard` that declares
    /// `present_rule`, each paired with a suite expecting `absent_rule`. Both directories therefore
    /// drop one expectation, and `unchecked_expectation_message` describes it as being "in this file"
    /// -- a phrase with no referent once two files say it.
    const UNCHECKED_SIBLING_DIR: &str = "resources/test-command/unchecked-expectation-sibling-dirs";

    /// The rules file both subdirectories hold.
    const UNCHECKED_SIBLING_FILE: &str = "names_absent_rule.guard";

    /// The fragment every one of these records ends with, whichever of the sentences produced it.
    const UNCHECKED_SUFFIX: &str = "so its expectation was not checked";

    /// Two sibling records for an unchecked expectation are distinguishable in the default format.
    ///
    /// This is the format a caller gets without asking for one, and it is the format where the identity
    /// of the affected rules file is recoverable from nowhere else. The report on stdout carries no
    /// unchecked-expectation entry at all -- measured, zero records pairing the expectation with a file
    /// -- so the two stderr lines are the whole account of what was dropped. While the sentence said
    /// only "this file", those two lines were byte-identical and a reader could not tell which
    /// directory either belonged to.
    ///
    /// Distinctness, not count. `handle_plaintext_directory` builds a `GenericReporter` and a
    /// diagnostics set per rules file, so the count is 2 whether or not the sentence names the file: a
    /// count assertion passes with a sentence that says only "this file" and would be satisfied by the
    /// very duplication this cell exists to reject. Against that sentence this cell reddens on the
    /// distinctness assertion with two identical lines.
    ///
    /// Then each record is required to name its own directory, so distinctness means "the file is
    /// identified" rather than "the two lines happen to differ".
    #[test]
    fn sibling_unchecked_expectation_records_are_distinguishable_in_the_default_format() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = TestCommandTestRunner::default()
            .directory(Option::from(UNCHECKED_SIBLING_DIR))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an expectation that was never compared against anything is an error, and both \
             directories dropped one"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let records: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains(UNCHECKED_SUFFIX))
            .collect();

        let distinct: std::collections::BTreeSet<&&str> = records.iter().collect();
        assert_eq!(
            distinct.len(),
            2,
            "the two records must differ. Identical lines mean neither names the file it is about, \
             and in this format nothing else does either. Got {:?} from stderr {:?}",
            records,
            stderr
        );

        for parent in ["first", "second"] {
            let located = reported_path(UNCHECKED_SIBLING_DIR, &[parent, UNCHECKED_SIBLING_FILE]);
            let matched: Vec<&&str> = records.iter().filter(|r| r.contains(&located)).collect();

            assert_eq!(
                1,
                matched.len(),
                "expected exactly one record naming `{}`, got {:?} from {:?}",
                located,
                matched,
                records
            );
        }
    }

    /// The premise the cell above rests on: this format's report holds no unchecked-expectation entry.
    ///
    /// Separate so the two failures cannot be confused. If the report grows such an entry the identity
    /// becomes recoverable from stdout and the argument for naming the file on stderr weakens -- that is
    /// a change of circumstances, not a regression in the naming, and it should not redden a cell about
    /// distinctness.
    ///
    /// The structured formats are the contrast and are asserted here too, because the claim is
    /// comparative: they carry the record *and* the rules file in the document, and this format carries
    /// neither.
    #[test]
    fn the_default_format_reports_no_unchecked_expectation_entry_on_stdout() {
        let run = |output: Option<&str>| {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            match output {
                None => TestCommandTestRunner::default()
                    .directory(Option::from(UNCHECKED_SIBLING_DIR))
                    .run(&mut writer, &mut reader),
                Some(fmt) => TestCommandTestRunner::default()
                    .directory(Option::from(UNCHECKED_SIBLING_DIR))
                    .output_format(fmt)
                    .run(&mut writer, &mut reader),
            };

            writer.stripped().expect("failed to read stdout")
        };

        let default_stdout = run(None);
        assert!(
            !default_stdout.contains(UNCHECKED_SUFFIX),
            "the default format's report carries no unchecked-expectation record; if it now does, the \
             sibling-distinctness cell above is no longer the only account of the dropped expectation \
             and should be re-read. Got {:?}",
            default_stdout
        );

        for fmt in ["json", "yaml"] {
            let structured_stdout = run(Some(fmt));
            assert!(
                structured_stdout.contains(UNCHECKED_SUFFIX),
                "-o {} must carry the record in its document, which is what makes the default format \
                 the one that needs the name on stderr. Got {:?}",
                fmt,
                structured_stdout
            );
            assert!(
                structured_stdout.contains(UNCHECKED_SIBLING_FILE),
                "-o {} must also name the rules file in its document, so the record there is \
                 attributable without the stderr line. Got {:?}",
                fmt,
                structured_stdout
            );
        }
    }

    /// Two runs of the same command over the same files must produce the same report.
    ///
    /// They did not. Both test reporters iterate the map built by `get_by_rules`, which was a
    /// `HashMap`, so the sequence of rule names inside a result group came from `RandomState` and
    /// was reseeded every process: over a `HashMap`, ten consecutive runs of this fixture give ten
    /// different outputs.
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

    /// A rules file that declares no rules reports a case it could not read, as well as the
    /// expectations it could.
    ///
    /// The no-rules path looped over each case's expectations and nothing else, so a case the
    /// command could not read -- here a `name` that is a sequence -- was silent there: it has no
    /// expectations to name when its `expectations:` is what could not be read, and a file whose
    /// cases were all unreadable exited 0 beside a comment-only rules file. The same case beside a
    /// rules file that declares rules is reported as that case's error, so the no-rules path says the
    /// same thing. The ordinary case in the fixture is the control: its expectation is still named.
    #[test]
    fn a_rules_file_declaring_no_rules_reports_a_case_it_could_not_read() {
        let (status_code, _, stderr) = run_spec(
            "resources/validate/comments.guard",
            "resources/test-command/spec-shape/unreadable_name_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stderr
        );
        assert!(
            stderr.contains("Unable to process a test case in test file")
                && stderr.contains("unreadable_name_tests.yaml")
                && stderr.contains("`name` must be a string"),
            "the unreadable case is reported with its file and the reason:\n{}",
            stderr
        );
        assert!(
            stderr.contains("declares no rules, so the expectation for"),
            "the expectation the file did read is still named:\n{}",
            stderr
        );
    }

    /// A rules file that declares no rules reports a case whose `input:` the loader refused, even
    /// when the case expects nothing.
    ///
    /// A refused node inside `input:` is not an unreadable case: the input is passed through as the
    /// loader left it and converted by whoever reads the case, which is where the refusal surfaces.
    /// The no-rules path read only the case's fields and its expectations, so a case with a null key
    /// in its input and an empty `rules:` beside a comment-only rules file exited 0 with nothing
    /// printed, where beside a rules file that declares rules it is an errored case at exit 1. The
    /// input is converted on this path too now, and the refusal is reported as the case's error.
    #[test]
    fn a_rules_file_declaring_no_rules_reports_a_case_whose_input_the_loader_refused() {
        let (status_code, _, stderr) = run_spec(
            "resources/validate/comments.guard",
            "resources/test-command/spec-shape/refused_input_with_no_expectations_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stderr
        );
        assert!(
            stderr.contains("Unable to process a test case in test file")
                && stderr.contains("refused_input_with_no_expectations_tests.yaml")
                && stderr.contains("where the key is null"),
            "the refused input is reported as the case's error, with the loader's reason:\n{}",
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

    /// Runs one spec file against one rules file under `single-line-summary` and returns the exit
    /// code with everything written to stdout and to stderr, so a failing assertion can show the
    /// verdicts and the diagnostics.
    ///
    /// One run, both streams, through `capture_both_streams` in the shared test utilities: the
    /// command writes to two files and each is read back through public API. Running the command
    /// twice, once per stream, would double the cost of the specs that spend the alias expansion
    /// budget.
    fn run_spec(rules: &str, test_data: &str) -> (i32, String, String) {
        run_spec_in(rules, test_data, "single-line-summary")
    }

    fn run_spec_in(rules: &str, test_data: &str, output: &str) -> (i32, String, String) {
        capture_both_streams(|writer, reader| {
            TestCommandTestRunner::default()
                .test_data(Some(test_data))
                .rules(Some(rules))
                .output_format(output)
                .run(writer, reader)
        })
    }

    /// Every output format of `test` writes the moved-reading warning to stderr, once.
    ///
    /// A key filter argument the map answers where the enclosing scope would have answered differently
    /// is a warning the evaluator records; the test reporters drain it beside the deprecations. Pinned
    /// per format so a reporter that stops reading the warnings turns its own row red, and so the
    /// warning stays on stderr and out of the document a pipeline parses. Two resources under one call
    /// are one line: the first map is shown and the other counted.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    #[case::yaml("yaml")]
    #[case::junit("junit")]
    fn every_output_format_writes_the_moved_reading_warning_once(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/moved-reading-warning/rules.guard",
            "resources/test-command/moved-reading-warning/tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: the case passes on the maps' own values:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        assert_eq!(
            1,
            stderr.lines().filter(|l| l.starts_with("Warning:")).count(),
            "{}: one call site, one warning, got:\n{}",
            format,
            stderr
        );
        assert!(
            stderr.contains("1 more map") && !stderr.contains("DEPRECATION"),
            "{}: the second map is counted into the line and nothing fell back, got:\n{}",
            format,
            stderr
        );
        assert!(
            !stdout.contains("Warning:"),
            "{}: the warning is not part of the report on stdout:\n{}",
            format,
            stdout
        );
    }

    /// Two cases reaching one call site are one warning line, worded for a case and not for a data file.
    ///
    /// `test` evaluates each case in a scope of its own, so the moved reading is recorded once per case
    /// with that case's positions in its text; a drain that removed repeats by exact text printed one
    /// line per case for one call, against the one-line-per-call promise the warning makes. The drains
    /// now take the warnings with their call-site keys and keep the first line per site across the
    /// cases. The command reads no data file, so the line must not say "in this data file": the first
    /// case holds two maps, so the printed line carries the count and its wording for a case's input.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    #[case::yaml("yaml")]
    #[case::junit("junit")]
    fn two_cases_reaching_one_call_site_are_one_warning_line(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/moved-reading-warning/rules.guard",
            "resources/test-command/moved-reading-warning/two_cases_tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: both cases pass on the maps' own values:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        assert_eq!(
            1,
            stderr.lines().filter(|l| l.starts_with("Warning:")).count(),
            "{}: one call site across two cases is one warning line, got:\n{}",
            format,
            stderr
        );
        assert!(
            stderr.contains("2 more maps")
                && stderr.contains("across 2 cases in this file")
                && stderr.contains("in case `first case, two maps` of `")
                && stderr.contains("two_cases_tests.yaml`")
                && !stderr.contains("data file"),
            "{}: the line names the first case and the spec file it was drawn from, not a data file \
             the command never read, and counts the maps of both cases (two in the first, one in the \
             second), got:\n{}",
            format,
            stderr
        );
    }

    /// The one line a spec file gets counts every case of the file that recorded the site, not only the
    /// case it names.
    ///
    /// The line is kept once per call site and argument per spec file, with the first case's text. Its
    /// count was that case's own ("N more maps ... in this case"), so when the first case recorded the
    /// site and passed, and a later case recorded it and failed on the moved reading, the failing case
    /// was neither named nor counted: the reader was told of a case that passed and nothing of the one
    /// that did not. The count now covers the maps of every case in the file that recorded the site,
    /// worded "across K cases in this file", on the single-line output and on the structured ones alike.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    fn the_count_covers_every_case_of_the_spec_file_that_recorded_the_site(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/moved-reading-warning/rules.guard",
            "resources/test-command/moved-reading-warning/two_cases_second_fails_tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: the first case passes and the second fails as it expects:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "{}: one call site in one spec file is one line, got:\n{}",
            format,
            stderr
        );
        assert!(
            warnings[0].contains("in case `first case, passes` of `")
                && warnings[0].contains("1 more map")
                && warnings[0].contains("across 2 cases in this file")
                && !warnings[0].contains("in this case"),
            "{}: the line names the first case and counts the second case's map as well, worded for \
             the file: {}",
            format,
            warnings[0]
        );
    }

    /// The one line a spec file gets names the case that drew it, whichever case comes first.
    ///
    /// The command reads a case's inline input and no data file, and the scope was built with no name,
    /// so the line cited map positions `[L:x,C:y]` that belong to no file the reader could open, and
    /// which of a spec's cases they belonged to depended on the order of the cases. The scope is now
    /// built for the case, and the line reads "in case `<name>` of `<spec file>`". The same two cases in
    /// either order: the printed line names the first, and its count covers the maps of both cases
    /// (three in all, so "2 more maps across 2 cases in this file") whichever order they come in.
    #[rstest]
    #[case::two_maps_first("two_cases_tests.yaml", "first case, two maps")]
    #[case::one_map_first("two_cases_swapped_tests.yaml", "one map, first")]
    fn the_line_a_spec_file_gets_names_the_case_that_drew_it(
        #[case] spec: &str,
        #[case] first_case: &str,
    ) {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/moved-reading-warning/rules.guard",
            &format!("resources/test-command/moved-reading-warning/{spec}"),
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: both cases pass on the maps' own values:\n{}\n{}",
            spec,
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "{}: one call site, one line, got:\n{}",
            spec,
            stderr
        );
        assert!(
            warnings[0].contains(&format!("in case `{first_case}` of `"))
                && warnings[0].contains(&format!("{spec}`")),
            "{}: the line names the case it was drawn from and the spec file: {}",
            spec,
            warnings[0]
        );
        assert!(
            warnings[0].contains("2 more maps")
                && warnings[0].contains("across 2 cases in this file"),
            "{}: the count covers both cases' maps, three in all, whichever case came first: {}",
            spec,
            warnings[0]
        );
    }

    /// Two cases named alike are two cases in the file's one line.
    ///
    /// A spec file may repeat a case name (`docs/UNIT_TESTING.md`: ordinary, and published suites do
    /// it). The file's one line for a call site counted its cases by their label, which two cases named
    /// alike share, so the second such case was folded into the first: the count never reached "across
    /// 2 cases", and the later case's own line, its own "in this case" count, stood in place of the
    /// first case's. A case is counted by its position in its file: the first case's line stands, and
    /// the second case's map is counted into it ("2 more maps across 2 cases in this file").
    ///
    /// Each reporter numbers a case by its place in its file on its own, so the line is read on the
    /// single-line output and on json: a structured reporter that handed every case the same number
    /// would fold the two cases into one and print the second case's own line instead.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    fn two_cases_named_alike_are_two_cases_in_the_files_line(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/moved-reading-warning/rules.guard",
            "resources/test-command/moved-reading-warning/two_cases_named_alike_tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: both cases pass on the maps' own values:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "{}: one call site in one spec file is one line, got:\n{}",
            format,
            stderr
        );
        assert!(
            warnings[0].contains("in case `x` of `")
                && warnings[0].contains("2 more maps")
                && warnings[0].contains("across 2 cases in this file")
                && !warnings[0].contains("in this case"),
            "{}: the first case's line, counting the second case's map as a second case: {}",
            format,
            warnings[0]
        );
    }

    /// Three cases, the first and the third named alike, are three in the file's one line.
    ///
    /// Counted by label, x, y, x read as two cases: the third's map was folded into the first's and
    /// the line said "across 2 cases". Counted by position it says "across 3 cases", with every map of
    /// the three (two, one and one: "3 more maps"), and it is the first case's line, on the single-line
    /// output and on json alike.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    fn three_cases_two_named_alike_are_three_cases_in_the_files_line(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/moved-reading-warning/rules.guard",
            "resources/test-command/moved-reading-warning/three_cases_two_named_alike_tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: all three cases pass on the maps' own values:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "{}: one call site in one spec file is one line, got:\n{}",
            format,
            stderr
        );
        assert!(
            warnings[0].contains("in case `x` of `")
                && warnings[0].contains("3 more maps")
                && warnings[0].contains("across 3 cases in this file"),
            "{}: the first case's line, counting all three cases and their four maps: {}",
            format,
            warnings[0]
        );
    }

    /// Two spec files reaching one call site are one line each, naming the file.
    ///
    /// The per-site collapse keeps one line per call across the cases of one spec file; across spec
    /// files it kept the first file's line and swallowed every later file's, so a run over a directory
    /// of specs said nothing about the second file's maps. The collapse is keyed by the site and the
    /// spec file: one line per file, each naming its file and its own count.
    #[test]
    fn two_spec_files_reaching_one_call_site_are_one_line_each() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/moved-reading-warning/rules.guard",
            "resources/test-command/moved-reading-warning/two-specs",
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files' cases pass on the maps' own values:\n{}\n{}",
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            2,
            warnings.len(),
            "two spec files, one line each for the one call, got:\n{}",
            stderr
        );
        let line_for = |file: &str| {
            warnings
                .iter()
                .find(|w| w.contains(&format!("{file}`")))
                .unwrap_or_else(|| panic!("no line names {}:\n{}", file, stderr))
        };
        let a = line_for("a_tests.yaml");
        let b = line_for("b_tests.yaml");
        assert!(
            a.contains("in case `one map in file a` of `") && !a.contains("more map"),
            "file a's line names its case and counts no second map: {}",
            a
        );
        assert!(
            b.contains("in case `two maps in file b` of `") && b.contains("1 more map"),
            "file b's line names its case and counts its own second map: {}",
            b
        );
    }

    /// An unnamed case is numbered by its position in its own spec file, on every output format.
    ///
    /// The scope a case is built with names an unnamed case by number. The structured reporter passed
    /// the case's position in its file, as the scope's doc promises; the single-line reporter passed
    /// the counter it prints as `Test Case #N`, which runs across every spec file of the run, so over a
    /// directory whose second file opens with an unnamed case the warning said "case 3 of `b_tests.yaml`"
    /// under single-line-summary and "case 1" under json, and could name a case the file does not have.
    /// Both reporters now pass the position in the file; the run-wide counter is the header's alone.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    fn an_unnamed_case_is_numbered_within_its_own_spec_file(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/moved-reading-warning/rules.guard",
            "resources/test-command/moved-reading-warning/two-specs-unnamed",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: every case passes on the maps' own values:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        let b = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .find(|l| l.contains("b_tests.yaml`"))
            .unwrap_or_else(|| panic!("{}: no line names b_tests.yaml:\n{}", format, stderr));
        assert!(
            b.contains("in case 1 of `"),
            "{}: the unnamed case is the first of its file, whatever the run counted before it: {}",
            format,
            b
        );
    }

    /// The warning for a capture nothing can bind names the case and the spec file under `test`.
    ///
    /// The command reads no data file, and the warning read the data file's name alone, so under `test`
    /// it said the capture was found "on this template" where the moved-reading warning beside it names
    /// "case `<name>` of `<spec file>`". Both warnings now name the input the same way.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    fn an_unbound_capture_warning_names_the_case_and_the_spec_file(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/unsupported-capture-warning/rules.guard",
            "resources/test-command/unsupported-capture-warning/one_case_tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: the case expects the refusal's FAIL:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "{}: one capture in one case is one line, got:\n{}",
            format,
            stderr
        );
        assert!(
            warnings[0].contains("the capture `nm`")
                && warnings[0].contains("not a list in case `the one case` of `")
                && warnings[0].contains("one_case_tests.yaml`.")
                && !warnings[0].contains("on this template"),
            "{}: the line names the case and the spec file, not a template the command never read: {}",
            format,
            warnings[0]
        );
    }

    /// Two cases of one spec file refusing one capture are one line, counted in the capture's words.
    ///
    /// The capture's warning rode the moved-reading warning's key, so the collapse across the cases of
    /// one spec file re-rendered its line with that warning's count: "1 more map under this call read a
    /// differing value for this argument across 2 cases in this file", about a capture that has no maps
    /// and no argument. The capture is its own kind of warning, and the count across cases speaks of the
    /// cases that refuse it.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    fn two_cases_refusing_one_capture_are_one_line_counted_in_cases(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/unsupported-capture-warning/rules.guard",
            "resources/test-command/unsupported-capture-warning/two_cases_tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: both cases expect the refusal's FAIL:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "{}: one capture across two cases of one spec file is one line, got:\n{}",
            format,
            stderr
        );
        assert!(
            warnings[0].contains("not a list in case `first case` of `")
                && warnings[0]
                    .ends_with("The same capture is refused in 1 more case of this file; only the first is shown.")
                && !warnings[0].contains("more map")
                && !warnings[0].contains("differing value"),
            "{}: the line names the first case and counts the second as a case that refuses the \
             capture, never as a map that read a differing value: {}",
            format,
            warnings[0]
        );
    }

    /// Two cases of one spec file reaching one clause site with an unraised refused read are one line,
    /// RENDERED from both cases: the clause as written, the verdict both cases reached (one phrase, no
    /// per-way count), each case's refusal text (the twin's text names the refused map at its position in
    /// the spec file, so two cases are two texts even over the same input), and the case count in place
    /// of the one case's name.
    ///
    /// The evaluator keeps the clause as written as the head it re-renders the site's line from, and the
    /// command's collapse across the cases of one spec file renders the multi-case line from that head
    /// with what every case's scope counted (the evaluations under each verdict, the refusal texts met),
    /// through the evaluator's own line builder, so the line carries the `Warning:` prefix, the verdict
    /// and the refusals, and a later case's text or verdict is named rather than reduced to a count.
    /// Built on the bare head it would print the clause alone, a line with no prefix read as failure
    /// text; built as the first case's line with a count appended, it would leave a second case's
    /// refusal unsaid.
    #[rstest]
    #[case::single_line_summary("single-line-summary")]
    #[case::json("json")]
    fn two_cases_reaching_one_unraised_refusal_site_are_one_prefixed_line(#[case] format: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/unraised-refusal-warning/rules.guard",
            "resources/test-command/unraised-refusal-warning/two_cases_tests.yaml",
            format,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: both cases expect the PASS the absence decides:\n{}\n{}",
            format,
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "{}: one clause site across two cases of one spec file is one prefixed line, got:\n{}",
            format,
            stderr
        );
        // The clause as the author wrote it (`Properties.Owner == %names`, the form a reader greps the
        // rules file for), never the record tree's `Properties.Owner EQUALS  %names`.
        // Both cases reach the one site with the same verdict and the same refusal shape (the same
        // function `M`, the same map-shaped tags), so the line names one verdict with no per-way count
        // and the two cases of the spec file in place of the one case's name; the two refusal texts are
        // two, each naming the refused map at its own position in the spec file, both numbered.
        assert!(
            warnings[0].contains("Properties.Owner == %names")
                && !warnings[0].contains("EQUALS")
                && warnings[0].contains("was decided by a value the document lacks")
                && !warnings[0].contains("on 2 evaluations")
                && warnings[0]
                    .contains("the 2 refused reads among its other values were not raised by it")
                && warnings[0].contains("they are reported here instead: (1) ")
                && warnings[0].contains(" (2) ")
                && warnings[0]
                    .matches("a name bound outside the predicate")
                    .count()
                    == 2
                && warnings[0].contains("in 2 cases of `")
                && !warnings[0].contains("more case"),
            "{}: the line names the clause as written, its verdict and the refusal, rendered across the \
             two cases: {}",
            format,
            warnings[0]
        );
        let bare: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Properties.Owner"))
            .collect();
        assert!(
            bare.is_empty(),
            "{}: no line starts with the bare clause (a prefix-less line is read as failure text): {:?}",
            format,
            bare
        );
        // A positioned line, as every warning the `Notices` contract keeps: the clause's position in the
        // rules file and the input it was found in (the case and its spec file under `test`), so two
        // rules of one clause spelling print two distinct lines.
        assert!(
            warnings[0].contains("The clause is at Location[file:")
                && warnings[0].contains("rules.guard")
                && warnings[0].contains("two_cases_tests.yaml"),
            "{}: the line ends with the clause's position and names the spec file: {}",
            format,
            warnings[0]
        );
    }

    /// Two cases of one spec file whose refused reads are DIFFERENT texts (two functions at two paths,
    /// each with map-shaped tags, one per case) are one line naming BOTH texts, numbered in case order,
    /// with the count of refused reads: the fold renders the line from every text the cases met, so the
    /// second case's refusal is named; appended as a case count to the first case's line, it would be a
    /// number.
    #[test]
    fn two_cases_with_different_refused_reads_are_one_line_naming_both() {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/unraised-refusal-warning/rules.guard",
            "resources/test-command/unraised-refusal-warning/two_texts_tests.yaml",
            "single-line-summary",
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both cases expect the PASS the absence decides:\n{}\n{}",
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            1,
            warnings.len(),
            "one clause site across two cases is one prefixed line, got:\n{}",
            stderr
        );
        assert!(
            warnings[0]
                .contains("the 2 refused reads among its other values were not raised by it")
                && warnings[0].contains("they are reported here instead: (1) ")
                && warnings[0].contains(" (2) ")
                && warnings[0]
                    .matches("a name bound outside the predicate")
                    .count()
                    == 2
                && warnings[0].contains("in 2 cases of `")
                && !warnings[0].contains("more case"),
            "the line counts two refused reads and names both texts in case order: {}",
            warnings[0]
        );
    }

    /// Two rules of ONE clause spelling in one rules file reach two sites, and the two lines they write
    /// are distinct: each ends with its own clause's position, so a reader can tell which rule's clause
    /// left the refused read unraised; without the position the two lines would be byte-identical.
    #[test]
    fn two_rules_of_one_clause_spelling_print_two_distinct_unraised_refusal_lines() {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/unraised-refusal-warning/two_rules.guard",
            "resources/test-command/unraised-refusal-warning/one_case_tests.yaml",
            "single-line-summary",
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both rules PASS by the absence:\n{}\n{}",
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            2,
            warnings.len(),
            "two clause sites, two lines, got:\n{}",
            stderr
        );
        assert_ne!(
            warnings[0], warnings[1],
            "the two lines differ (each ends with its own position):\n{}",
            stderr
        );
        assert!(
            warnings
                .iter()
                .all(|line| line.contains("The clause is at Location[file:")
                    && line.contains("line:")),
            "each line ends with its clause's position:\n{}",
            stderr
        );
    }

    /// Two spec files refusing one capture are one line each, naming the file.
    ///
    /// The collapse is keyed by the spec file for this warning as for the moved reading, so a run over
    /// a directory of specs names each file's case rather than the first file's alone, and a file with
    /// one refusing case carries no count.
    #[test]
    fn two_spec_files_refusing_one_capture_are_one_line_each() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/unsupported-capture-warning/rules.guard",
            "resources/test-command/unsupported-capture-warning/two-specs",
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files' cases expect the refusal's FAIL:\n{}\n{}",
            stdout,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            2,
            warnings.len(),
            "two spec files, one line each for the one capture, got:\n{}",
            stderr
        );
        for (file, case) in [
            ("a_tests.yaml", "the case in file a"),
            ("b_tests.yaml", "the case in file b"),
        ] {
            let line = warnings
                .iter()
                .find(|w| w.contains(&format!("{file}`.")))
                .unwrap_or_else(|| panic!("no line names {}:\n{}", file, stderr));
            assert!(
                line.contains(&format!("not a list in case `{case}` of `"))
                    && !line.contains("more case")
                    && !line.contains("on this template"),
                "{}: the line names its own case and file and counts no further case: {}",
                file,
                line
            );
        }
    }

    /// An integer wider than `i64` keeps its digits in a spec's `input:`, as it does in a data file
    /// given to `validate`.
    ///
    /// The spec's `input:` was read by serde, which has no integer wider than `u64`: a JSON spec fell
    /// through to `serde_json`, which parsed the literal as a float, so two distinct integers compared
    /// equal and `is_float` passed; a YAML spec was refused outright with "invalid number". Both now
    /// read through the loader `validate` uses, which keeps the digits as text. The second case in each
    /// file is the control: an ordinary integer is still an integer.
    #[rstest]
    #[case("big_tests.json")]
    #[case("big_tests.yaml")]
    fn an_integer_past_i64_keeps_its_digits_in_a_spec(#[case] spec: &str) {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/integer-past-i64/rules.guard",
            &format!("resources/test-command/integer-past-i64/{spec}"),
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{} must give the verdicts validate gives:\n{}",
            spec,
            stdout
        );
    }

    /// A float literal too small to represent keeps its text in a spec's `input:`, as it does in a
    /// data file given to `validate`.
    ///
    /// `1e-400` parses to `0.0` and the serde value the spec was read into kept no source text, so
    /// `A == 0` passed under `test` where `validate` refuses the comparison and reads the literal as a
    /// string. The second case in each file is the control: a genuine `0.0` is a float that equals 0
    /// on every route.
    #[rstest]
    #[case("under_tests.yaml")]
    #[case("under_tests.json")]
    fn a_float_that_underflowed_keeps_its_text_in_a_spec(#[case] spec: &str) {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/float-underflow/rules.guard",
            &format!("resources/test-command/float-underflow/{spec}"),
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{} must give the verdicts validate gives:\n{}",
            spec,
            stdout
        );
    }

    /// A quoted `"<<"` in a spec's `input:` is the ordinary key YAML says it is, as it is in a data file
    /// given to `validate`; a plain `<<` still merges.
    ///
    /// YAML resolves the merge key from a plain scalar only. The serde value the spec was read into
    /// keeps no scalar style, so the quoted key was merged too: it vanished and its contents were
    /// hoisted, and both rules reported FAIL where `validate` reported PASS on the same bytes. The
    /// second case is the control, and the reason the first could not be fixed by not merging at all.
    #[test]
    fn a_quoted_merge_key_is_a_literal_key_in_a_spec() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/quoted-merge-key/rules.guard",
            "resources/test-command/quoted-merge-key/quoted_merge_key_tests.yaml",
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the quoted key must stay literal and the plain one must merge:\n{}",
            stdout
        );
    }

    /// A field written twice in one case refuses the file and names both positions.
    ///
    /// The common way to get there is a second case pasted without its leading `- `: that is one
    /// mapping with two `name`, `input` and `expectations` keys. Reading the last value would run only
    /// the pasted case and lose the first one at exit 0. The serde derive this replaced refused the
    /// shape ("duplicate field"), so the refusal is kept, and the message says where both are.
    #[test]
    fn a_field_written_twice_in_a_case_fails_that_case_naming_both_positions() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/duplicated_case_field_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        // The exact lines: the case is reported as a case, with one message and one "Parser Error
        // when parsing" prefix rather than a parse error quoting another parse error, and the file
        // is not refused around it.
        let expected =
            "Test Case #1\nError processing Parser Error when parsing ``name` is written \
                        twice in one test case, at L:4,C:3 and again at L:10,C:3. A case pasted \
                        without its leading `- ` reads as one case with two of every field`\n";
        assert_eq!(expected, stdout);
        assert_eq!(
            1,
            stdout.matches("Parser Error when parsing").count(),
            "the error prefix must appear once:\n{}",
            stdout
        );
    }

    /// A spec in YAML flow style with a mistake is refused with libyaml's position, and nothing from
    /// a JSON reader.
    ///
    /// Flow style begins with `[` as a JSON array does, and a JSON reader stops at the first unquoted
    /// key, "key must be a string at line 1 column 3", which is valid YAML and not the mistake. libyaml
    /// stops at the value missing its comma, `B` at column 26, and that is the one position shown; the
    /// JSON reader's would follow only if it had read at least as far.
    #[test]
    fn a_flow_style_spec_with_a_mistake_is_refused_at_libyamls_position_alone() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/flow_style_missing_comma_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("did not find expected ',' or '}' at L:1,C:26")
                && !stdout.contains("JSON"),
            "libyaml's position, and nothing from the JSON reader, which stopped at valid YAML:\n{}",
            stdout
        );
    }

    /// The repeated field is named whichever field comes first in the case, and the case still has no
    /// name to report.
    ///
    /// The scan over a case's fields stopped at the first field written twice. With `name` written
    /// first that was `name`, and the scan had not reached the second `name` when it stopped, so it
    /// knew of one and reported the case under it. With `input` written first it stopped at `input`,
    /// before either `name`, and the case kept the first name as if it had one: the refusal named
    /// `input`, and the reporter headed it with a name the author had given to half a case. The scan
    /// goes on to the end now, so a case with two names has none whichever field repeats first.
    #[test]
    fn a_field_written_twice_is_named_whichever_field_it_is_and_the_case_has_no_name() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/duplicated_case_field_input_first_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        let expected =
            "Test Case #1\nError processing Parser Error when parsing ``input` is written \
                        twice in one test case, at L:5,C:3 and again at L:11,C:3. A case pasted \
                        without its leading `- ` reads as one case with two of every field`\n";
        assert_eq!(expected, stdout);
    }

    /// A case mapping the loader cannot read refuses the file with the loader's reason, not with
    /// "an unreadable value" alone.
    ///
    /// A null key beside a case's fields has no text, so the loader marks the whole case unreadable.
    /// The file is refused, because a case that is not a mapping has no `input:` to run, and the
    /// refusal has to carry the loader's message: it says where the key is and that it is null, so
    /// the author knows what to quote.
    #[test]
    fn a_case_mapping_the_loader_cannot_read_refuses_the_file_with_the_loaders_reason() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/null_key_in_a_case_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("`a test case` must be a mapping")
                && stdout.contains("where the key is null"),
            "the refusal must say which field and why the loader could not read it:\n{}",
            stdout
        );
        assert_eq!(
            1,
            stdout.matches("Parser Error when parsing").count(),
            "the error prefix must appear once:\n{}",
            stdout
        );
    }

    /// A key written twice inside a case's `input:` resolves last-wins with a warning on stderr, the
    /// way the same document resolves under `validate`.
    ///
    /// `serde_yaml` refused the document outright; the loader keeps the last value, as `validate` does,
    /// and `validate` says so on stderr. The warning has to reach this command too, or the spec would
    /// prove a rule against a document that `validate` reads with a warning the author never saw.
    #[test]
    fn a_key_written_twice_inside_the_input_warns_and_keeps_the_last_value() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/duplicated_input_key_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert!(
            stderr.contains("Warning: duplicate key /A in test file")
                && stderr.contains("duplicated_input_key_tests.yaml")
                && stderr.contains("first at L:6,C:5 and again at L:7,C:5")
                && stderr.contains("The last value is the one evaluated."),
            "the warning validate prints must reach stderr here too:\n{}",
            stderr
        );
    }

    /// An anchored key beside an alias of it inside a case's `input:` is a key written twice: the last
    /// value stands, and the warning reaches stderr naming the two lines the key was written at, the
    /// alias at its own line, as it does under `validate`. The loader records this pair beside its
    /// merge collisions, and the case's conversion reads them, so the pair that `validate` warns on
    /// warns here as the plain pair above does. The alias's line is the alias's own position, not the
    /// anchor's repeated ("first at L:6,C:5 and again at L:6,C:5"), one line named twice, which is
    /// what the copy an alias pushes would give, since it carries no position of its own.
    #[test]
    fn an_aliased_key_inside_the_input_warns_and_keeps_the_last_value() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/aliased_input_key_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert_eq!(
            1,
            stderr
                .matches("Warning: duplicate key /A in test file")
                .count(),
            "one warning for the one extra entry:\n{}",
            stderr
        );
        assert!(
            stderr.contains("aliased_input_key_tests.yaml")
                && stderr.contains("first at L:6,C:5 and again at L:7,C:5")
                && stderr.contains("The last value is the one evaluated."),
            "the warning validate prints must reach stderr here too:\n{}",
            stderr
        );
    }

    /// A spec file that holds no document has no cases, and is not an error.
    ///
    /// A comment-only placeholder and a lone `---` both load as nothing. serde read them as an empty
    /// list of cases and the run exited 0; the loader reports "no document", which is turned back into
    /// zero cases here rather than into a refusal of a file a rule author has not written yet.
    #[rstest]
    #[case("comment_only_tests.yaml")]
    #[case("document_marker_only_tests.yaml")]
    fn a_spec_file_holding_no_document_has_no_cases(#[case] spec: &str) {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            &format!("resources/test-command/spec-shape/{spec}"),
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert!(
            stdout.is_empty(),
            "{} has no cases, so nothing should be reported:\n{}",
            spec,
            stdout
        );
    }

    /// `rules:` with nothing after it is an empty set of expectations, as serde read it.
    #[test]
    fn an_empty_rules_block_is_an_empty_set_of_expectations() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/null_rules_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert!(
            stdout.contains("Test Case #1"),
            "the case must run with nothing to check:\n{}",
            stdout
        );
    }

    /// An input declared once with an anchor and reused through aliases runs every case that names it.
    ///
    /// Spec files are read with the loader `validate` reads a data file with, and both resolve
    /// aliases within the same budget: sharing one input between cases is how suites are written, and
    /// the document a case shares is one `validate` reads the same way. The fixture reuses the
    /// base input whole in one case and through `<<: *base` with an override in another, and the
    /// override's rule is expected to FAIL, so the merge has to have kept the case's own key for the
    /// spec to exit 0.
    #[test]
    fn an_input_shared_through_an_alias_runs_every_case_that_names_it() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/aliases/rules.guard",
            "resources/test-command/aliases/shared_input_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert!(
            stdout.contains("Test Case #3"),
            "all three cases must run, the aliased ones included:\n{}",
            stdout
        );
    }

    /// An alias chain whose copies would pass the expansion budget fails the case that holds it,
    /// naming the budget and the alias that crossed it, and the case before it keeps its verdict.
    ///
    /// Resolving an alias copies the anchored node, so six anchors that each alias the one before
    /// them ten times is a million-fold expansion of ten scalars. The copies are counted against a
    /// budget for the case, and the message says which alias crossed it so the author can see
    /// where the growth is. The alias is one node of one case's `input:`, so the spec loader leaves
    /// an unreadable value in its place rather than refusing the file, and the first case runs.
    #[test]
    fn an_alias_chain_past_the_expansion_budget_fails_its_case_naming_the_budget() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/aliases/rules.guard",
            "resources/test-command/aliases/alias_budget_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("through aliases") && stdout.contains("`*e`"),
            "the error must name the budget and the alias that crossed it:\n{}",
            stdout
        );
        // The budget is spent per case, and the message has to say so: told "in one document", an
        // author went looking for aliases in the other cases.
        assert!(
            stdout.contains("in one test case (one item of the root sequence)")
                && !stdout.contains("in one document"),
            "the error must say the budget is one case's:\n{}",
            stdout
        );
        assert!(
            stdout.contains("Test Case #2") && stdout.contains("a_is_one: Expected = PASS"),
            "the case before the chain keeps its verdict, so the file was not refused:\n{}",
            stdout
        );
    }

    /// A resource's type reached through an alias runs against the rule as it does when the same
    /// document is a template under `validate` or data under the library entry point.
    ///
    /// The fixture is the one document every route is pinned on: `validate`'s pin is
    /// `a_yaml_template_with_an_alias_resolves_it_as_the_other_routes_do` in `tests/validate.rs`, and
    /// the entry point's sits beside `commands::helper`. The second case writes the type out and
    /// expects the rule to fail, so the spec exits 0 only if the alias reached the rule whole.
    #[test]
    fn a_type_reached_through_an_alias_runs_as_it_does_on_every_route() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/aliases/type_through_an_alias.guard",
            "resources/test-command/aliases/type_through_an_alias_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert!(
            stdout.contains("Test Case #2") && stdout.contains("a_type_is_x: Expected = PASS"),
            "both cases run and the aliased type reaches the rule:\n{}",
            stdout
        );
    }

    /// However many cases a spec file has, what it copies through aliases in all is bounded: a ceiling
    /// over the whole document that no case resets.
    ///
    /// The per-case budget made the number of cases the multiplier. The fixture anchors a chain in
    /// its first case and aliases the chain's fifth level nine times in each of twelve more cases;
    /// each of those copies 999,999 nodes, inside one case's budget, so twelve cases were twelve
    /// million nodes from a few hundred bytes each. The ceiling is a thousand nodes for each event of
    /// the file other than aliases and never below one case's budget, so for a file of a few hundred
    /// such events it is one case's budget in all: the chain charges 123,440 nodes, the first flood case
    /// fits seven copies, and every alias after that is refused naming the ceiling. The twelve flood
    /// cases fail and the chain case keeps its verdict;
    /// `a_spec_loader_holds_the_whole_document_under_a_ceiling_that_no_item_resets` in the loader's
    /// tests pins the counts.
    #[test]
    fn a_flood_of_cases_aliasing_one_chain_is_refused_at_the_documents_ceiling() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/aliases/rules.guard",
            "resources/test-command/aliases/flood_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert_eq!(
            12,
            stdout.matches("across the whole document").count(),
            "every flood case is refused naming the ceiling:\n{}",
            stdout
        );
        assert_eq!(
            (1, 1),
            (
                stdout.matches("a_is_one: Expected = PASS\n").count(),
                stdout.matches("b_is_two: Expected = PASS\n").count()
            ),
            "the chain case keeps its verdicts and no flood case reaches a verdict:\n{}",
            stdout
        );
        assert!(
            stdout.contains("Test Case #13"),
            "every case is reported, the refused ones with their error:\n{}",
            stdout
        );
    }

    /// A `!!int` whose payload is not an integer fails its case with the key or merge refusal those
    /// shapes always had, position and advice included, and the case before it keeps its verdict.
    ///
    /// The loader marks a tagged scalar it cannot read, and the mark is not forwarded as the refusal
    /// itself when it stands where a key or a merge source should be: forwarded, `<<: !!int abc` would
    /// be reported as "abc" with no position and no word about the merge key, and `!!int abc` as a key
    /// would lose the key refusal's position and its advice. Only the loader's own refusals -- an alias
    /// it could not resolve, a mapping it could not model -- are forwarded that way.
    #[rstest]
    #[case(
        "merge_key_given_a_tagged_integer_tests.yaml",
        "the merge key `<<` at L:15,C:9 must be given a mapping"
    )]
    #[case(
        "tagged_integer_as_a_key_tests.yaml",
        "L:15,C:5, where the key is an unreadable value, !!int abc. Quote it to make it a string"
    )]
    fn a_tagged_scalar_that_is_not_its_type_fails_its_case_with_the_key_or_merge_refusal(
        #[case] spec: &str,
        #[case] reason: &str,
    ) {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            &format!("resources/test-command/spec-shape/{spec}"),
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}: {}",
            spec,
            stdout
        );
        assert!(
            stdout.contains(reason),
            "{}: the case reports the key or merge refusal with its position:\n{}",
            spec,
            stdout
        );
        assert!(
            stdout.contains("Test Case #2") && stdout.contains("a_is_one: Expected = PASS"),
            "{}: the case before it keeps its verdict:\n{}",
            spec,
            stdout
        );
    }

    /// An alias whose copy would nest past the loader's bound refuses the whole file, as the same
    /// nesting written inline does, and no case is reported.
    ///
    /// The bound is a property of the document rather than of one case: a value nested past it is
    /// the thing the bound exists to keep from ever being built, whichever node asked for it. The
    /// spec loader otherwise marks an alias it refuses and fails only that case, and for a while it
    /// did so here too, so an alias that landed too deep cost one case where inline nesting cost the
    /// file; docs/UNIT_TESTING.md says the file, and the command now agrees. The spec is written at
    /// test time, because a hundred brackets are counted more reliably by `repeat` than by hand.
    #[test]
    fn an_alias_whose_copy_nests_past_the_bound_refuses_the_file() {
        let dir =
            std::env::temp_dir().join(format!("cfn-guard-alias-depth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let spec = dir.join("alias_depth_tests.yaml");
        // The anchored sequence is 100 deep. Under the sequence of cases, the case, `input` and 28
        // nested mappings its copy's deepest container would land at level 131; the same alias under
        // 25 mappings lands at 128 and loads.
        let mut text = String::from(
            "- name: a case before the deep alias\n  input:\n    A: 1\n  expectations:\n    rules:\n      \
             a_is_one: PASS\n- name: an alias whose copy lands past the bound\n  input:\n    deep: &deep ",
        );
        text.push_str(&format!("{}x{}\n", "[".repeat(100), "]".repeat(100)));
        for level in 0..28 {
            text.push_str(&format!("{}m{level}:\n", "  ".repeat(level + 2)));
        }
        text.push_str(&format!("{}leaf: *deep\n", "  ".repeat(30)));
        text.push_str("  expectations:\n    rules:\n      a_is_one: PASS\n");
        std::fs::write(&spec, text).expect("the spec is written");
        let spec_path = spec.to_str().expect("a UTF-8 path").to_string();

        let (status_code, stdout, _) =
            run_spec("resources/test-command/spec-shape/rules.guard", &spec_path);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("nested at most") && stdout.contains("`*deep`"),
            "the refusal names the bound and the alias:\n{}",
            stdout
        );
        assert!(
            !stdout.contains("Test Case #"),
            "no case of a refused file is reported:\n{}",
            stdout
        );
    }

    /// An alias to a name that no node before it anchors fails its case, naming the alias, and the
    /// case that declares the anchor afterwards still runs.
    ///
    /// YAML has no forward references, and libyaml leaves the check to whoever composes the
    /// document, so without this the alias would have been resolved to nothing in silence.
    #[test]
    fn an_alias_to_an_anchor_declared_later_fails_its_case_naming_the_alias() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/aliases/rules.guard",
            "resources/test-command/aliases/undeclared_anchor_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("`*later`") && stdout.contains("declares"),
            "the error must name the alias:\n{}",
            stdout
        );
        assert!(
            stdout.contains("Test Case #2") && stdout.contains("a_is_one: Expected = PASS"),
            "the case declaring the anchor keeps its verdict, so the file was not refused:\n{}",
            stdout
        );
    }

    /// A merge of a misspelled anchor fails its case naming the alias, as a bare alias does, and
    /// not with a complaint about the merge key.
    ///
    /// `<<: *base` is how a shared input is usually reused, so a misspelled anchor name arrives at
    /// the merge key. The alias is marked unreadable, and the refusal the case reports is the alias's
    /// own. Reading that mark as a value that is not a mapping would report "must be given a mapping,
    /// or a sequence of mappings", which hides the typo.
    #[test]
    fn a_merge_of_a_misspelled_anchor_fails_its_case_naming_the_alias() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/aliases/rules.guard",
            "resources/test-command/aliases/merge_of_a_misspelled_anchor_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("`*bsae`") && stdout.contains("declares"),
            "the error must name the alias:\n{}",
            stdout
        );
        assert!(
            !stdout.contains("must be given a mapping"),
            "the merge error must not stand in for the alias's refusal:\n{}",
            stdout
        );
        assert!(
            stdout.contains("Test Case #1") && stdout.contains("a_is_one: Expected = PASS"),
            "the case declaring the anchor keeps its verdict:\n{}",
            stdout
        );
    }

    /// A merge whose alias crosses the expansion budget fails its case naming the alias and the
    /// budget, not the merge key, and the case before it keeps its verdict.
    ///
    /// The budget is spent per case, so the fixture spends it inside one: the base holds a
    /// 111,111-node chain and the case merges the base seven times in one merge sequence. 234,551
    /// nodes are charged before the first merge (the aliases that build the chain and the alias of
    /// the chain inside the base; recording an anchor is not charged), each merge copies 111,113, six
    /// fit and the seventh crosses. The budget message is the one that says where the growth is, so
    /// the merge key's own refusal must not stand in for it. The same base anchored in one case and
    /// merged from others loads, one copy per case, and
    /// [`an_input_aliased_by_a_hundred_cases_loads_in_every_case`] pins it.
    #[test]
    fn a_merge_past_the_expansion_budget_fails_its_case_naming_the_budget() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/aliases/rules.guard",
            "resources/test-command/aliases/merge_past_the_budget_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("through aliases")
                && stdout.contains("`*m`")
                && stdout.contains("1000000"),
            "the error must name the budget and the alias that crossed it:\n{}",
            stdout
        );
        assert!(
            !stdout.contains("must be given a mapping"),
            "the merge error must not stand in for the budget refusal:\n{}",
            stdout
        );
        assert_eq!(
            1,
            stdout.matches("a_is_one: Expected = PASS").count(),
            "the case before the merges keeps its verdict:\n{}",
            stdout
        );
    }

    /// A 64 KiB scalar aliased past the byte budget fails the case that holds the alias, naming the
    /// byte budget, and the case before it keeps its verdict.
    ///
    /// A scalar is one node whatever its length, so the node budget alone let a long string be copied
    /// without limit. Each alias is one copy and recording the anchor is none; with a 64 MiB budget
    /// 1,024 aliases of a 64 KiB scalar fill it exactly and the 1,025th is the copy that crosses it.
    /// The spec is written at test time, because a fixture of a thousand aliases says nothing a loop
    /// does not.
    #[test]
    fn a_scalar_aliased_past_the_byte_budget_fails_its_case_naming_the_budget() {
        let dir =
            std::env::temp_dir().join(format!("cfn-guard-byte-budget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let spec = dir.join("byte_budget_tests.yaml");
        let aliases = std::iter::repeat("*big")
            .take(1025)
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            &spec,
            format!(
                "- name: a case before the copies\n  input:\n    A: 1\n  expectations:\n    rules:\n      \
                 a_is_one: PASS\n- name: a 64 KiB scalar aliased past the byte budget\n  input:\n    \
                 A: 1\n    big: &big {}\n    copies: [{aliases}]\n  expectations:\n    rules:\n      \
                 a_is_one: PASS\n",
                "x".repeat(64 * 1024)
            ),
        )
        .expect("the spec is written");
        let spec_path = spec.to_str().expect("a UTF-8 path").to_string();

        let (status_code, stdout, _) =
            run_spec("resources/test-command/aliases/rules.guard", &spec_path);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("67108864 bytes") && stdout.contains("`*big`"),
            "the error must name the byte budget and the alias that crossed it:\n{}",
            stdout
        );
        assert!(
            stdout.contains("Test Case #2") && stdout.contains("a_is_one: Expected = PASS"),
            "the case before the copies keeps its verdict:\n{}",
            stdout
        );
    }

    /// An alias standing where a key should be fails its case with the alias's own refusal, not
    /// with the refusal of a key that is not a string.
    ///
    /// The loader marks an alias it cannot resolve unreadable, and a mapping whose key carries that
    /// mark is not refused as a mapping with a non-string key: "non string type detected for key in
    /// a map ... Quote it to make it a string" would put the alias's message in the middle of advice
    /// that does not apply, since quoting `*later` makes a key named `*later`. The case reports the
    /// alias's refusal, and the case before it keeps its verdict.
    #[test]
    fn an_alias_used_as_a_key_fails_its_case_naming_the_alias() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/aliases/rules.guard",
            "resources/test-command/aliases/alias_as_a_key_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("`*later`") && stdout.contains("declares"),
            "the error must name the alias:\n{}",
            stdout
        );
        assert!(
            !stdout.contains("non string type") && !stdout.contains("Quote it to make it a string"),
            "the non-string-key refusal must not stand in for the alias's:\n{}",
            stdout
        );
        assert!(
            stdout.contains("Test Case #1") && stdout.contains("a_is_one: Expected = PASS"),
            "the case before the alias keeps its verdict:\n{}",
            stdout
        );
    }

    /// An input anchored in one case and aliased by ninety-nine more loads in every case.
    ///
    /// The copies an alias makes are counted against a budget per case, so each case costs one copy
    /// of the shared input, 9,908 nodes, however many cases alias it; counted over the whole file,
    /// the first case's 9,797 copies inside the input and ninety-nine aliases of it would be 990,689
    /// nodes, and the next case would cross the budget, so which case failed would depend on how many
    /// came before it. The chain in `alias_budget_tests.yaml`, which spends the budget inside one case,
    /// is refused there, which
    /// [`an_alias_chain_past_the_expansion_budget_fails_its_case_naming_the_budget`] pins.
    ///
    /// The second file is the same hundred cases in flow style with short names, in about two thirds
    /// of the bytes. The ceiling over the whole document is set by the file's events other than
    /// aliases, which the two layouts share, so both load; a ceiling of 100 nodes for each byte would
    /// stand at the 1,000,000 floor for the flow file and refuse its hundredth case while accepting
    /// the block-style twin.
    #[rstest]
    #[case::block_style("shared_input_across_a_hundred_cases_tests.yaml")]
    #[case::flow_style("shared_input_across_a_hundred_cases_flow_tests.yaml")]
    fn an_input_aliased_by_a_hundred_cases_loads_in_every_case(#[case] spec: &str) {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/aliases/rules.guard",
            &format!("resources/test-command/aliases/{spec}"),
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{spec}:\n{}\n{}",
            stdout,
            stderr
        );
        // A met expectation is reported as `rule: Expected = PASS` and nothing more; an unmet one
        // goes on with `, Evaluated = ...`.
        assert_eq!(
            100,
            stdout.matches("a_is_one: Expected = PASS\n").count(),
            "every one of the hundred cases runs against the shared input:\n{}",
            stdout
        );
        assert!(
            !stdout.contains("through aliases") && !stdout.contains("Evaluated ="),
            "no case may be refused by the budget or fail:\n{}",
            stdout
        );
    }

    /// An unreadable node where the document or a case should be refuses the file, naming what was
    /// expected and carrying the loader's reason.
    ///
    /// These are the two places a refused node leaves nothing to run: the document itself, which is
    /// the sequence of cases, and a case, which is the mapping that holds a case's fields -- an
    /// alias standing for the whole case, an unreadable key beside its fields, which makes the
    /// mapping unreadable, or the case mapping itself tagged with an intrinsic's name under `!!`.
    /// With nesting past the loader's bound and a second document in the file, they are the shapes
    /// docs/UNIT_TESTING.md lists as costing the whole file; pinned so that the list and the command
    /// cannot drift apart. A refused node inside a case's fields costs only that case, which the
    /// test after this one pins. Each row names the loader's reason the message has to carry: for an
    /// alias, the alias and that no node declares it; for a tag, the tag.
    #[rstest]
    #[case(
        "alias_as_the_document_tests.yaml",
        "expected a sequence of test cases",
        &["`*nope`", "declares"]
    )]
    #[case(
        "alias_as_a_case_tests.yaml",
        "`a test case` must be a mapping",
        &["`*nope`", "declares"]
    )]
    #[case(
        "alias_as_a_key_in_a_case_tests.yaml",
        "`a test case` must be a mapping",
        &["`*nope`", "declares"]
    )]
    #[case(
        "type_tagged_container_as_a_case_tests.yaml",
        "`a test case` must be a mapping, found an unreadable value at L:12,C:3",
        &["does not read the tag `!!Equals` at L:12,C:3"]
    )]
    fn an_unreadable_document_or_case_refuses_the_file_naming_what_was_expected(
        #[case] spec: &str,
        #[case] field: &str,
        #[case] reasons: &[&str],
    ) {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            &format!("resources/test-command/spec-shape/{spec}"),
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}: {}",
            spec,
            stdout
        );
        assert!(
            stdout.contains(field) && reasons.iter().all(|reason| stdout.contains(reason)),
            "{}: the refusal must name the field and carry the loader's reason {:?}:\n{}",
            spec,
            reasons,
            stdout
        );
        assert!(
            !stdout.contains("Test Case #"),
            "{}: no case of a refused file is reported:\n{}",
            spec,
            stdout
        );
    }

    /// A tagged leading-zero integer in a case's field says why it could not be read and offers no
    /// integer to write in its place.
    ///
    /// The loader's reason for `!!int 0755` carries both: the sentence naming the two readings, and
    /// the integers to write instead, 493 or 755. A `name` is text and a status is PASS, FAIL or
    /// SKIP, so no integer can fix either field; the field message carries the why and leaves the
    /// integers out, where it once carried both and told the author to write 493 into a status.
    #[rstest]
    #[case("leading_zero_name_tests.yaml")]
    #[case("leading_zero_status_tests.yaml")]
    fn a_tagged_leading_zero_integer_in_a_field_says_why_but_offers_no_integer(#[case] spec: &str) {
        let (_, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            &format!("resources/test-command/spec-shape/{spec}"),
        );

        assert!(
            stdout.contains("a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2"),
            "{}: the field message carries the reason:\n{}",
            spec,
            stdout
        );
        assert!(
            !stdout.contains("write ") && !stdout.contains("493"),
            "{}: the field message offers no integer to write:\n{}",
            spec,
            stdout
        );
    }

    /// A container tagged with an intrinsic's name under `!!` as the whole document refuses the file
    /// the same way, carrying the tag's refusal.
    ///
    /// The spec loader marks the container unreadable like any other refused node rather than refusing
    /// the document itself for the tag, which would leave the file refused with the tag's message and
    /// no mention of what was expected. So the tag costs what the node's place costs: the file here,
    /// where the node is the document, and in a tagged case mapping (the
    /// `type_tagged_container_as_a_case` row of the test above); one case when the node is a case's
    /// field (the `type_tagged_container_as_*` rows of the test after this one). Pinned so the
    /// file-level message keeps both halves, what was expected and why the node could not be read.
    #[test]
    fn a_type_tagged_container_as_the_document_refuses_the_file_naming_the_tag() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/type_tagged_container_as_the_document_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "an unreadable spec file is the file's mistake, not INTERNAL_FAILURE:\n{}",
            stdout
        );
        assert!(
            stdout.contains(
                "expected a sequence of test cases, found an unreadable value at L:4,C:1: cfn-guard \
                 does not read the tag `!!If` at L:4,C:1. An intrinsic function is written with one \
                 `!`, as `!If`."
            ),
            "the refusal must name what was expected and carry the tag's refusal:\n{}",
            stdout
        );
        assert!(
            !stdout.contains("Test Case #"),
            "no case of a refused file is reported:\n{}",
            stdout
        );
    }

    /// An unreadable node in one of a case's fields -- its `name`, its `expectations`, the `rules`
    /// under them, or a rule's expected status -- fails that case with the field's name and the
    /// loader's reason, and the other cases keep their verdicts.
    ///
    /// Every field is per case, not `input:` alone: a refused node in another field that went through
    /// the shape check would refuse the whole file, so one case's mistake would cost every case's
    /// verdict, and which case it was would depend on the order of the file through the budget. A case
    /// mapping that reads is a case, and a field the command cannot read is that case's error, as an
    /// `input:` it cannot convert is; docs/UNIT_TESTING.md lists what costs the file.
    #[rstest]
    #[case(
        "alias_as_a_name_tests.yaml",
        "`name` must be a string",
        &["`*nope`", "declares"]
    )]
    #[case(
        "alias_as_the_expectations_tests.yaml",
        "`expectations` must be a mapping",
        &["`*nope`", "declares"]
    )]
    #[case(
        "alias_as_the_rules_tests.yaml",
        "`rules` must be a mapping",
        &["`*nope`", "declares"]
    )]
    #[case(
        "alias_as_a_status_tests.yaml",
        "`a_is_one` must be a status",
        &["`*nope`", "declares"]
    )]
    #[case(
        "type_tagged_container_as_the_expectations_tests.yaml",
        "`expectations` must be a mapping, found an unreadable value at L:15,C:17",
        &["does not read the tag `!!Equals` at L:15,C:17"]
    )]
    #[case(
        "type_tagged_container_as_a_status_tests.yaml",
        "`a_is_one` must be a status, found an unreadable value at L:17,C:17",
        &["does not read the tag `!!If` at L:17,C:17"]
    )]
    // A tagged scalar refused for a reason carries the reason's why after its position: the field
    // says the scalar is not its type, and the reason is what says why, since `!!int 0o755` beside it
    // reads. The reason's fix, an integer to write, is not carried: no integer belongs in a name or
    // a status (`a_tagged_leading_zero_integer_in_a_field_says_why_but_offers_no_integer` pins that).
    #[case(
        "leading_zero_name_tests.yaml",
        "`name` must be a string, found a tagged scalar that is not its type, `!!int 0755`, at L:12,C:9",
        &["at L:12,C:9: a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2"]
    )]
    #[case(
        "leading_zero_status_tests.yaml",
        "`a_is_one` must be a status, found a tagged scalar that is not its type, `!!int 0755`, at L:17,C:17",
        &["at L:17,C:17: a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2"]
    )]
    fn an_unreadable_node_in_a_cases_field_fails_that_case_naming_the_field(
        #[case] spec: &str,
        #[case] field: &str,
        #[case] reasons: &[&str],
    ) {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            &format!("resources/test-command/spec-shape/{spec}"),
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}: {}",
            spec,
            stdout
        );
        assert!(
            stdout.contains(field) && reasons.iter().all(|reason| stdout.contains(reason)),
            "{}: the case's error must name the field and carry the loader's reason {:?}:\n{}",
            spec,
            reasons,
            stdout
        );
        assert!(
            stdout.contains("Test Case #1")
                && stdout.contains("a_is_one: Expected = PASS")
                && stdout.contains("Test Case #2"),
            "{}: the ordinary case keeps its verdict and the broken case is reported:\n{}",
            spec,
            stdout
        );
        assert!(
            !stdout.contains("Unable to process data in file"),
            "{}: the file is not refused:\n{}",
            spec,
            stdout
        );
        // The broken case carries the expectations it did read (the `name` fixture's second case
        // still expects `a_is_one: PASS`), and the reporter answers it with its error alone: one
        // verdict line in the whole report, the ordinary case's.
        assert_eq!(
            1,
            stdout.matches("a_is_one: Expected = PASS").count(),
            "{}: the unreadable case's expectations are not evaluated:\n{}",
            spec,
            stdout
        );
    }

    /// A case missing both its `input` and its `expectations` is told about its `input` first.
    ///
    /// That is the order the serde reader had, and the order the command kept until a rewrite of the
    /// case reader read the expectations before checking for the input, so that a case with only a
    /// `name:` was told about its `expectations` instead. Neither field is more missing than the
    /// other; the pin is that the message does not move again.
    #[test]
    fn a_case_with_only_a_name_is_missing_its_input_before_its_expectations() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/only_a_name_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("missing field `input` in the test case at L:3,C:3")
                && !stdout.contains("missing field `expectations`"),
            "the missing input is named, and the missing expectations are not:\n{}",
            stdout
        );
    }

    /// The structured reporters answer an unreadable case with its error alone, evaluating none of
    /// the expectations it carries.
    ///
    /// An unreadable case keeps the expectations it did read, for the no-rules path; the fixture's
    /// second case has an unreadable `name` and an ordinary `a_is_one: PASS`. In the report that case
    /// is an errored case with no passed and no failed rules, and the one verdict in the document is
    /// the ordinary case's.
    #[rstest]
    #[case("json")]
    #[case("yaml")]
    fn a_structured_report_evaluates_none_of_an_unreadable_cases_expectations(
        #[case] output: &str,
    ) {
        let (status_code, stdout, _) = run_spec_in(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/alias_as_a_name_tests.yaml",
            output,
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("`name` must be a string"),
            "{output}: the unreadable case is an errored case:\n{}",
            stdout
        );
        assert_eq!(
            1,
            stdout.matches("\"evaluated\"").count() + stdout.matches("evaluated: ").count(),
            "{output}: one verdict in the document, the ordinary case's:\n{}",
            stdout
        );
    }

    /// A case name that is not a string keeps the spelling the file has.
    ///
    /// The loader has resolved the scalar by the time this command sees it, and for a while the name
    /// was rendered from the value the way a mapping key is: `1.50` became `1.5`, `1e3` became
    /// `1000.0`, `0x1F` became `31` and `True` became `true`. Names are JUnit ids and the `name` of a
    /// JSON or YAML report, so that renamed cases a dashboard groups by and merged two that differed.
    /// The loader keeps each number's and boolean's spelling beside the document, and the name is
    /// reported from it, as `serde_yaml` reported it.
    #[test]
    fn a_non_string_case_name_keeps_its_spelling() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/numeric_name_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        for spelled in [
            "Name: 1.0\n",
            "Name: 1.50\n",
            "Name: 1e3\n",
            "Name: 0x1F\n",
            "Name: 2024\n",
            "Name: True\n",
        ] {
            assert!(
                stdout.contains(spelled),
                "{:?} must appear, spelled as the file has it:\n{}",
                spelled,
                stdout
            );
        }
        for rendered in [
            "Name: 1.5\n",
            "Name: 1000.0\n",
            "Name: 31\n",
            "Name: true\n",
        ] {
            assert!(
                !stdout.contains(rendered),
                "{:?} is a rendering of the value, not the file's spelling:\n{}",
                rendered,
                stdout
            );
        }
        assert!(
            stderr.is_empty(),
            "six distinct names draw no duplicate-name warning:\n{}",
            stderr
        );
    }

    /// Two cases named alike that differ in both input and expectations run with no warning.
    ///
    /// A name repeated over different inputs with different expectations is how a suite groups the
    /// cases that exercise one scenario under one label, and published suites do it. A repeated
    /// input or a repeated set of expectations is the shape of a pasted case, which is what the
    /// warning is for.
    #[test]
    fn two_cases_named_alike_over_different_inputs_and_expectations_draw_no_warning() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/alike_names.guard",
            "resources/test-command/spec-shape/alike_names_over_different_inputs_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert_eq!(
            2,
            stdout.matches("Test Case #").count(),
            "both cases run:\n{}",
            stdout
        );
        assert_eq!(
            "", stderr,
            "a name grouping two cases that differ in input and expectations draws no warning"
        );
    }

    /// Two cases named alike draw the warning when they repeat the input, and not when they agree
    /// only on the expectations.
    ///
    /// One input under two sets of expectations is the shape of a case pasted and not finished, and
    /// the warning names the file and both positions. Two inputs under one set of expectations is
    /// how published suites group the cases that exercise one scenario: a suite with one rule has
    /// three verdicts to choose from, so cases agreeing on them is ordinary. Measured over the
    /// rules registry's 191 paired suites, warning on a repeated set of expectations named 39 of
    /// them, every pair holding different inputs; warning on a repeated input names none. Both cases
    /// run either way.
    #[rstest]
    #[case::the_input(
        "alike_names_sharing_the_input_tests.yaml",
        Some(("L:4,C:9", "L:12,C:9"))
    )]
    #[case::the_expectations("alike_names_sharing_the_expectations_tests.yaml", None)]
    fn two_cases_named_alike_warn_only_when_they_share_the_input(
        #[case] fixture: &str,
        #[case] positions: Option<(&str, &str)>,
    ) {
        let test_file = format!("resources/test-command/spec-shape/{fixture}");
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/alike_names.guard",
            &test_file,
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert_eq!(
            2,
            stdout.matches("Test Case #").count(),
            "both cases run:\n{}",
            stdout
        );
        let expected = match positions {
            Some((first, again)) => format!(
                "Warning: two test cases in test file {test_file} are named `a pasted case`, at \
                 {first} and again at {again}. Reports tell cases apart by name; rename one.\n"
            ),
            None => String::new(),
        };
        assert_eq!(expected, stderr);
    }

    /// Two cases in one file that share a name, and repeat each other's input and expectations, both
    /// run, and the command warns on stderr naming the file and both positions.
    ///
    /// Reports and JUnit ids tell cases apart by name, so two cases with one name are one entry to a
    /// dashboard. An unquoted `1.5` and a quoted `"1.5"` spell the same name, which is the pair the
    /// fixture holds, the second a paste of the first; the third case has a name of its own and is
    /// not mentioned.
    #[test]
    fn two_cases_named_alike_run_with_a_warning_naming_both_positions() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/duplicated_case_name_tests.yaml",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert_eq!(
            3,
            stdout.matches("Test Case #").count(),
            "all three cases run:\n{}",
            stdout
        );
        let expected = "Warning: two test cases in test file \
                        resources/test-command/spec-shape/duplicated_case_name_tests.yaml are named \
                        `1.5`, at L:4,C:9 and again at L:11,C:9. Reports tell cases apart by name; \
                        rename one.\n";
        assert_eq!(expected, stderr);
    }

    /// A JSON spec whose string holds a raw U+0085, U+2028 or U+2029 reads the character, where the
    /// YAML reader on its own folds it as a line break.
    ///
    /// JSON permits the three unescaped. The YAML reader treats each as a line break and folds it
    /// inside a double-quoted scalar: `"a<NEL>b"` read as `a b`, and `"a <LS> b"` as `a<LS>b`, and
    /// the load succeeded, so a rule comparing the string answered against a value the file does not
    /// hold. The character is escaped before the loader reads the text. The spec and the rule are
    /// written at test time, because the fixture tree is kept free of raw control bytes.
    #[rstest]
    #[case::a_next_line('\u{0085}', "a\u{0085}b", "/^a[^ ]b$/")]
    #[case::a_line_separator('\u{2028}', "a \u{2028} b", "/^a . b$/")]
    #[case::a_paragraph_separator('\u{2029}', "a \u{2029} b", "/^a . b$/")]
    fn a_json_spec_with_a_raw_line_break_in_a_string_reads_the_character(
        #[case] raw: char,
        #[case] label: &str,
        #[case] pattern: &str,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "cfn-guard-raw-break-{:04X}-{}",
            raw as u32,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let rules = dir.join("label_is_kept.guard");
        std::fs::write(
            &rules,
            format!("rule label_is_kept {{ Label == {pattern} }}\n"),
        )
        .expect("the rules file is written");
        let spec = dir.join("raw_break_tests.json");
        std::fs::write(
            &spec,
            format!(
                "[{{\"name\": \"a raw U+{:04X} inside a string\", \"input\": {{\"A\": 1, \
                 \"Label\": \"{label}\"}}, \"expectations\": {{\"rules\": {{\"label_is_kept\": \
                 \"PASS\"}}}}}}]\n",
                raw as u32
            ),
        )
        .expect("the spec is written");
        let rules_path = rules.to_str().expect("a UTF-8 path").to_string();
        let spec_path = spec.to_str().expect("a UTF-8 path").to_string();

        let (status_code, stdout, stderr) = run_spec(&rules_path, &spec_path);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the string must hold the character, not a folded line break:\n{}\n{}",
            stdout,
            stderr
        );
    }

    /// A rule named twice under `rules:` refuses the file with a message about expectations, not the
    /// pasted-case message a duplicated case field gets.
    ///
    /// Two expectations for one rule cannot both be checked. serde's `HashMap` kept the last one in
    /// silence, so a copied `a_is_one: PASS` line could hide the expectation the author meant. The
    /// refusal is kept and worded for what it is; the exact line is pinned.
    #[test]
    fn a_rule_expected_twice_in_one_case_fails_that_case_with_its_own_message() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/spec-shape/rules.guard",
            "resources/test-command/spec-shape/duplicated_expectation_tests.yaml",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        let expected = "Test Case #1\nName: a rule expected twice\nError processing Parser Error when \
                        parsing ``a_is_one` is expected twice in one test case, at L:8,C:7 and again \
                        at L:9,C:7. A rule has one expectation per case; delete one, or split the \
                        case in two`\n";
        assert_eq!(expected, stdout);
    }

    /// A JSON spec whose string holds a surrogate-pair escape is read, and the two halves become the
    /// one character they encode.
    ///
    /// Python's `json.dumps` writes every character outside the BMP that way by default. The YAML
    /// loader refuses a lone surrogate escape inside a double-quoted scalar, which is correct for YAML
    /// and wrong for JSON, where the pair is the only way to write the character. The pair is decoded
    /// before the loader sees valid JSON text.
    #[test]
    fn a_json_spec_with_a_surrogate_pair_escape_is_read() {
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/spec-shape/surrogate_pair.guard",
            "resources/test-command/spec-shape/surrogate_pair_tests.json",
        );

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
    }

    /// A JSON spec written in a shape libyaml's scanner does not accept is rewritten the way a YAML
    /// emitter would write it, and read.
    ///
    /// JSON is read as the YAML it is, and two shapes of valid JSON fall outside what libyaml's
    /// scanner accepts: a member name past its simple-key limit, and a line break between a member
    /// name and its colon. Both read before the YAML loader took over, so refusing them, even with a
    /// message naming the limit, was a regression on files every JSON tool writes. The long name is
    /// read as an explicit key and the break as a space, and the case runs.
    #[rstest]
    #[case::a_member_name_past_the_limit("long_member_name_tests.json")]
    #[case::a_line_break_before_the_colon("newline_before_colon_tests.json")]
    fn a_json_spec_libyaml_cannot_scan_is_rewritten_and_read(#[case] spec: &str) {
        let path = format!("resources/test-command/json-limits/{spec}");
        let (status_code, stdout, stderr) =
            run_spec("resources/test-command/json-limits/rules.guard", &path);

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert!(
            stdout.contains("a_is_one: Expected = PASS") && !stdout.contains("valid JSON"),
            "the case runs against the document as written:\n{}",
            stdout
        );
    }

    /// A spec that is neither JSON nor YAML is refused with the YAML reader's message and the line
    /// and column it stopped at, under one error prefix.
    ///
    /// A document with a missing comma between two members is not valid JSON, so the check that
    /// recognizes valid JSON the YAML reader cannot read does not apply, and what the author gets is
    /// libyaml's message with its position, on the line of the missing comma. The JSON reader's own
    /// refusal would follow only if it had read at least as far; on `{"A": 1 "B": 2}` libyaml stops
    /// after the member that follows the gap and the JSON reader at its opening quote, so nothing of
    /// the JSON reader's is shown. The spec file's name is wrapped around the message once, so it
    /// reads like every other refused spec and not like a parse error quoting another parse error.
    #[test]
    fn a_json_spec_that_is_not_json_is_refused_naming_the_line_and_column() {
        let (status_code, stdout, _) = run_spec(
            "resources/test-command/json-limits/rules.guard",
            "resources/test-command/json-limits/missing_comma_tests.json",
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}",
            stdout
        );
        assert!(
            stdout.contains("missing_comma_tests.json")
                && stdout.contains("did not find expected ',' or '}' at L:4,C:")
                && !stdout.contains("JSON"),
            "the refusal names the file and libyaml's position on the fourth line, and nothing from \
             a JSON reader that stopped earlier:\n{}",
            stdout
        );
        assert_eq!(
            1,
            stdout.matches("Parser Error when parsing").count(),
            "the error prefix must appear once:\n{}",
            stdout
        );
    }

    /// The third shape: a raw U+007F-U+009F character inside a string, which JSON permits unescaped
    /// and libyaml's reader refuses as a control character. It is rewritten as its `\u` escape, as
    /// the raw line breaks are, and read as the character; the rule that holds only when the string
    /// is intact passes. The spec is written at test time, because the fixture tree is kept free of
    /// raw control bytes.
    #[test]
    fn a_json_spec_with_a_raw_control_character_in_a_string_reads_the_character() {
        let dir =
            std::env::temp_dir().join(format!("cfn-guard-raw-control-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let spec = dir.join("raw_control_character_tests.json");
        std::fs::write(
            &spec,
            "[{\"name\": \"a raw U+0080 inside a string\", \"input\": {\"A\": 1, \"Label\": \
             \"a\u{0080}b\"}, \"expectations\": {\"rules\": {\"a_is_one\": \"PASS\", \
             \"label_is_intact\": \"PASS\"}}}]\n",
        )
        .expect("the spec is written");
        let spec_path = spec.to_str().expect("a UTF-8 path").to_string();

        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/json-limits/label_is_intact.guard",
            &spec_path,
        );
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        assert!(
            stdout.contains("label_is_intact: Expected = PASS") && !stdout.contains("valid JSON"),
            "the string holds the character and the case runs:\n{}",
            stdout
        );
    }

    /// A spec whose document the loader itself cannot read costs the file, in every output format:
    /// exit 1, a message naming the file and the bound, and no verdict for the other cases. Never 255.
    ///
    /// The sibling fixture `a_case_whose_input_cannot_be_read_tests.yaml` holds the shapes that fail
    /// one case and keep the others. What still costs the file is a refusal of the document rather
    /// than of a node in it: here an `input:` nested past the loader's bound of 128 levels, where the
    /// sequence of cases and the case mapping are the first two. Pinned so that a later change cannot
    /// quietly turn it back into `INTERNAL_FAILURE`, and so that the two together say exactly which
    /// shapes keep their siblings and which do not. The spec is written at test time, because 127
    /// brackets are counted more reliably by `repeat` than by hand.
    #[test]
    fn a_spec_whose_document_the_loader_refuses_costs_the_file_in_every_format() {
        let dir = std::env::temp_dir().join(format!("cfn-guard-too-deep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the temp dir is writable");
        let spec = dir.join("too_deep_tests.yaml");
        std::fs::write(
            &spec,
            format!(
                "- name: a bucket named something other than expected\n  input:\n    Resources:\n      \
                 BucketA:\n        Type: AWS::S3::Bucket\n        Properties:\n          BucketName: \
                 wrong\n  expectations:\n    rules:\n      bucket_is_named_expected: FAIL\n- name: an \
                 input nested past the bound\n  input: {}x{}\n  expectations:\n    rules:\n      \
                 bucket_is_named_expected: SKIP\n",
                "[".repeat(127),
                "]".repeat(127)
            ),
        )
        .expect("the spec is written");
        let spec_path = spec.to_str().expect("a UTF-8 path").to_string();

        for format in EVERY_OUTPUT_FORMAT {
            let (status_code, stdout, _) = run_spec_in(
                "resources/test-command/rule-dir/a_case_whose_input_cannot_be_read.guard",
                &spec_path,
                format,
            );

            assert_eq!(
                StatusCode::INCORRECT_STATUS_ERROR,
                status_code,
                "{}: an unreadable spec file is the file's mistake, not INTERNAL_FAILURE:\n{}",
                format,
                stdout
            );
            assert!(
                stdout.contains("nested at most") && stdout.contains("too_deep_tests.yaml"),
                "{}: the message must name the bound and the file:\n{}",
                format,
                stdout
            );
            assert!(
                !stdout.contains("a bucket named something other than expected"),
                "{}: no case of a refused file is reported:\n{}",
                format,
                stdout
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plain mapping key the loader will not commit to a number is looked up by its source text in a
    /// spec's `input:`, as it is in a data file given to `validate`.
    ///
    /// A float literal that underflows to zero (`1e-400`), an integer wider than `u64`, one wider than
    /// `u128` and one below `i64::MIN` all keep their text on both routes. The spec was read by serde,
    /// which rendered the underflow key as `0.0` and the beyond-`u128` key as the float's text, and
    /// refused the file outright for the two in between, so `Mappings.M."1e-400" exists` PASSed under
    /// `validate` and FAILed here. Both read through one loader now, and the expectations are the
    /// verdicts `validate` gives the same document, measured. `u64::MAX` is the control: it rendered
    /// identically on both routes before and still does.
    #[test]
    fn wide_numeric_keys_are_looked_up_by_their_text_in_a_spec() {
        let (status_code, stdout, _) = run_spec(
            "resources/validate/loader-parity/wide-numeric-keys.guard",
            "resources/test-command/loader-parity/wide-numeric-keys/tests.yaml",
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "every key must be looked up by the text validate keeps:\n{}",
            stdout
        );
    }

    /// Every YAML spelling of a non-finite float stays the text the document wrote in a spec's
    /// `input:`, as it does in a data file given to `validate`.
    ///
    /// The loader keeps a non-finite float out of the value model as its literal text, so `.Inf`,
    /// `.INF`, `.NaN`, `.NAN`, `+.inf` and `-.Inf` are those strings. The spec was read by serde, which
    /// resolved each to a float that was then re-spelled `.inf` or `.nan`, so `A == ".Inf"` PASSed
    /// under `validate` and FAILed here while `A == ".inf"` did the reverse. The expectations are the
    /// verdicts `validate` gives the same document, measured; `.inf` itself is the control, the one
    /// spelling the two routes already agreed on.
    #[test]
    fn non_finite_float_spellings_keep_their_text_in_a_spec() {
        let (status_code, stdout, _) = run_spec(
            "resources/validate/loader-parity/non-finite-spellings.guard",
            "resources/test-command/loader-parity/non-finite-spellings/tests.yaml",
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "every spelling must stay the text the document wrote:\n{}",
            stdout
        );
    }

    /// A plain `0b101` is the string "0b101" in a spec's `input:`, as it is in a data file given to
    /// `validate`, while `0x1F` is the integer 31 on both.
    ///
    /// YAML 1.2 core resolves hexadecimal and `0o` octal integers and has no binary form, so the
    /// loader leaves `0b101` as text. The spec was read by serde, which accepts the `0b` prefix, so
    /// `V == 5` PASSed here and was a refused comparison under `validate`. The expectations are the
    /// verdicts `validate` gives the same document, measured; the hexadecimal key is the control.
    #[test]
    fn a_binary_looking_literal_is_a_string_in_a_spec() {
        let (status_code, stdout, _) = run_spec(
            "resources/validate/loader-parity/binary-literal.guard",
            "resources/test-command/loader-parity/binary-literal/tests.yaml",
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "0b101 must be a string and 0x1F an integer, as under validate:\n{}",
            stdout
        );
    }

    /// Two keys that differ as YAML scalars but read as one name (`1` beside `"1"`, `true` beside
    /// `"true"`) resolve last-wins in a spec's `input:`, as they do in a data file given to `validate`.
    ///
    /// Both routes read through one loader, whose map is keyed on name and position, so the pair
    /// survives to the conversion and collapses there the way every other repeated key does. The
    /// expectations are the verdicts `validate` gives the same document, measured. `validate` also
    /// prints a duplicate-key warning for each pair; what this pins is the verdict.
    #[test]
    fn keys_that_read_as_one_name_resolve_last_wins_in_a_spec() {
        let (status_code, stdout, _) = run_spec(
            "resources/validate/loader-parity/keys-that-read-alike.guard",
            "resources/test-command/loader-parity/keys-that-read-alike/tests.yaml",
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the last value must win on both routes:\n{}",
            stdout
        );
    }

    /// A merge source whose two keys read as one name (`1` and `"1"`) under an explicit `"1"` has one
    /// reading in a spec's `input:`, `explicit`, as it does in a data file given to `validate`. The
    /// merged `"1"` is a same-key override of the explicit `"1"` and silent; the merged integer `1` is
    /// a key of another kind that reads as it, a collision, which `validate` reports once on stderr
    /// and the serde conversion refuses. The value is the same on every route that produces one, and
    /// the merge key is folded.
    #[test]
    fn a_shadowed_merge_source_that_reads_as_one_name_has_one_reading_in_a_spec() {
        let (status_code, stdout, _) = run_spec(
            "resources/validate/loader-parity/shadowed-merge-key.guard",
            "resources/test-command/loader-parity/shadowed-merge-key/tests.yaml",
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the explicit key must be the one reading:\n{}",
            stdout
        );
    }

    /// A merge source with two keys that read as one name keeps the last value in a spec's `input:`,
    /// as it does in a data file; two sources keep the earlier source's value; a same-kind override
    /// keeps the explicit value and its gated rule SKIPs. One route each of the three-route pins on the
    /// collision shapes; the spec's table is the one the other two routes are held to.
    #[rstest]
    #[case::merge_collision_one_source("merge-collision-one-source")]
    #[case::merge_collision_two_sources("merge-collision-two-sources")]
    #[case::merge_same_key_override("merge-same-key-override")]
    fn a_merge_collision_shape_has_one_reading_in_a_spec(#[case] shape: &str) {
        let (status_code, stdout, _) = run_spec(
            &format!("resources/validate/loader-parity/{shape}.guard"),
            &format!("resources/test-command/loader-parity/{shape}/tests.yaml"),
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}: the spec's expectations must hold:\n{}",
            shape,
            stdout
        );
    }

    /// Each case of each loader-parity spec carries exactly the document its data-file fixture holds,
    /// as the whole of its `input:`, and names every rule of the shared rules file in its expectations.
    ///
    /// The three-route pins only prove parity if the three routes read the same bytes. The data file
    /// is the one copy; the spec cannot `include_str!` it, so this checks the spec against it by text,
    /// anchored at both ends: the case must contain `  input:` on its own line, then the fixture's
    /// lines each indented four spaces, then `  expectations:` on its own line, so nothing can sit
    /// before, inside or after the fixture under `input:`, and a first line nested one level deeper
    /// does not match. Every case is checked, split on the `- name:` lines, so a second case cannot
    /// slip in unverified. The names under each case's `rules:` must equal the `rule <name>`
    /// declarations. A spec that drifted from its fixture, or quietly dropped a rule, fails here rather
    /// than passing a weaker pin.
    #[rstest]
    #[case::wide_numeric_keys("wide-numeric-keys")]
    #[case::non_finite_spellings("non-finite-spellings")]
    #[case::binary_literal("binary-literal")]
    #[case::keys_that_read_alike("keys-that-read-alike")]
    #[case::shadowed_merge_key("shadowed-merge-key")]
    #[case::merge_collision_one_source("merge-collision-one-source")]
    #[case::merge_collision_two_sources("merge-collision-two-sources")]
    #[case::merge_same_key_override("merge-same-key-override")]
    fn a_loader_parity_spec_carries_its_fixture_and_covers_every_rule(#[case] shape: &str) {
        let fixture =
            std::fs::read_to_string(format!("resources/validate/loader-parity/{shape}.yaml"))
                .expect("the data-file fixture is readable");
        let rules =
            std::fs::read_to_string(format!("resources/validate/loader-parity/{shape}.guard"))
                .expect("the shared rules file is readable");
        let spec = std::fs::read_to_string(format!(
            "resources/test-command/loader-parity/{shape}/tests.yaml"
        ))
        .expect("the spec is readable");

        let indented = fixture.lines().fold(String::new(), |mut text, line| {
            text.push_str("    ");
            text.push_str(line);
            text.push('\n');
            text
        });
        let anchored = format!("  input:\n{indented}  expectations:\n");

        let declared: std::collections::BTreeSet<&str> = rules
            .lines()
            .filter_map(|line| line.strip_prefix("rule "))
            .filter_map(|rest| rest.split_whitespace().next())
            .collect();
        assert!(
            !declared.is_empty(),
            "{}: the rules file declares no rules",
            shape
        );

        // One case per `- name:` line, through the parser the three readers share.
        let cases = crate::utils::loader_parity_spec::loader_parity_spec_cases(&spec);
        assert!(!cases.is_empty(), "{}: the spec holds no case", shape);

        for (index, case) in cases.iter().enumerate() {
            assert!(
                case.text.contains(&anchored),
                "{} case {}: `input:` must be exactly the fixture indented four spaces, between \
                 `  input:` and `  expectations:`; fixture:\n{}\ncase:\n{}",
                shape,
                index + 1,
                fixture,
                case.text
            );

            let expected: std::collections::BTreeSet<&str> =
                case.expectations.keys().map(String::as_str).collect();
            assert_eq!(
                declared,
                expected,
                "{} case {}: the expectations must name every rule and nothing else",
                shape,
                index + 1
            );
        }
    }

    /// One filter site, two cases whose matching resource has a different logical id: the notice names
    /// a different map in each case, so the texts differ, and a collection that deduplicated by text
    /// printed two lines for one filter. The test command keeps the once-per-site reading across cases
    /// by `(kind, site)`: one line, the first case's. Red before that: two lines.
    ///
    /// The filter is `testBasic !exists` over `Resources.*[ Metadata exists ].Metadata`. Each case's
    /// instance holds one authentication block, which carries the key and is no member, so the
    /// instance's `Metadata` map loses its selection and is named. The role's `Metadata` holds one
    /// sub-map that lacks the key, a map one object to the slot (never walked, no notice), so the
    /// selection is the role's map and the key read below it passes: both cases expect PASS, which an
    /// engine selecting the instance's map whole (FAIL on the key it holds, as cfn-guard 3.2.1 did,
    /// observed on its binary) or keeping its block (FAIL on the key the block carries) would not meet.
    #[rstest]
    #[case("")]
    #[case("json")]
    fn a_site_notice_is_written_once_across_cases_that_name_different_maps(#[case] output: &str) {
        const DATA: &str = "resources/test-command/data-dir/metadata_projection_two_ids_cases.yaml";
        const RULES: &str = "resources/validate/filter_through_a_metadata_projection.guard";

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

        let (status_code, _) = run(output);
        let (_, err_writer) = run(output);
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both cases expect PASS over the role's one-member map"
        );

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(
            1,
            notices.len(),
            "one line for one filter site across two cases, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices[0].contains("/Resources/EC2A/Metadata"),
            "the first case's text is the one kept, got {:?}",
            notices[0]
        );
    }

    /// A single-map filter over a map that is one object is judged by the test command and announced
    /// by nothing.
    ///
    /// The cases are the two shapes a published registry rule's own tests carry for a resource whose
    /// `Metadata` map holds a scalar `Type` beside its authentication block, and they expect the
    /// published rule's own verdicts: FAIL over the block that defines a password, PASS over the one
    /// that does not. The filter through the variable tests the one map itself, as `[*]` does, so the
    /// expectations hold, the command succeeds, and no notice is written on either stream. The JSON
    /// report has to parse.
    ///
    /// The second pair of cases is the same two shapes with the scalar `Type` entry left out. A map
    /// with no scalar entry whose own key the predicate names (and none of its map-valued entries
    /// holds) is one object too, so the filter tests the map itself and the expectations are the same
    /// FAIL and PASS, with no notice.
    #[rstest]
    #[case::with_a_type_entry("", "resources/test-command/data-dir/single_map_binding_cases.yaml")]
    #[case::with_a_type_entry_json(
        "json",
        "resources/test-command/data-dir/single_map_binding_cases.yaml"
    )]
    #[case::without_a_type_entry(
        "",
        "resources/test-command/data-dir/single_map_binding_without_type_cases.yaml"
    )]
    #[case::without_a_type_entry_json(
        "json",
        "resources/test-command/data-dir/single_map_binding_without_type_cases.yaml"
    )]
    fn a_single_map_binding_of_one_object_is_judged_by_the_test_command_without_a_notice(
        #[case] output: &str,
        #[case] data: &str,
    ) {
        const RULES: &str = "resources/validate/filter_through_a_single_map_binding.guard";

        let run = |output: &str| {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            let status_code = match output {
                "" => TestCommandTestRunner::default()
                    .test_data(Option::from(data))
                    .rules(Some(RULES))
                    .run(&mut writer, &mut reader),
                _ => TestCommandTestRunner::default()
                    .test_data(Option::from(data))
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
            "{data}: the cases expect FAIL and PASS, the verdicts the filter gives once it tests the map itself"
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            !stdout.contains("DEPRECATION"),
            "no selection was lost, so nothing is announced on stdout, got {:?}",
            stdout
        );
        if output == "json" {
            serde_json::from_str::<serde_json::Value>(&stdout)
                .expect("the report on stdout must parse");
        }

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            !stderr.contains("DEPRECATION"),
            "no selection was lost, so nothing is announced on stderr, got {:?}",
            stderr
        );
    }

    /// The bound-map filter notice reaches the test command, once, on stderr.
    ///
    /// The cases are two instances, each with an authentication block under its `Metadata`, beside a
    /// role whose `Metadata` holds one `cfn_nag` sub-map, and the rules file filters
    /// `Resources.*[ Metadata exists ].Metadata` through a variable with `testBasic !exists`. The maps
    /// have no scalar entry and the predicate names no key a map holds itself. The instance's map holds
    /// one sub-map that carries the key, so the filter keeps the walk over it: the authentication block
    /// is no member, and the selection the predicate held on the map by absence is lost. The role's map
    /// holds one sub-map that lacks the key, one object to the slot, selected whole and never walked. So
    /// the selection is the role's map, the key read below it passes, and both cases expect PASS, which
    /// is the verdict the engine gives, so the command succeeds. The rules file is evaluated once per
    /// case and the same filter loses a selection each time, so two notices are produced and collapsed
    /// to one before they are written. Not on stdout, where the report that consumers parse lives; the
    /// JSON report has to parse with the notice beside it.
    /// The single-map registry shape, which is one object and draws no notice, is in the cases of
    /// `a_single_map_binding_of_one_object_is_judged_by_the_test_command_without_a_notice`.
    #[rstest]
    #[case("")]
    #[case("json")]
    fn a_single_map_binding_notice_reaches_the_test_command(#[case] output: &str) {
        const DATA: &str = "resources/test-command/data-dir/metadata_projection_two_ids_cases.yaml";
        const RULES: &str = "resources/validate/filter_through_a_metadata_projection.guard";

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
            "both cases expect PASS and the notice must not move that"
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
            1,
            notices.len(),
            "expected one notice across both cases, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices[0].contains("`let blocks = Resources.*[ Metadata exists ].Metadata`"),
            "the notice names the binding, got {:?}",
            notices[0]
        );
    }

    /// The `!!` tag warning lines on a run's stderr, in the order they were written.
    fn tag_warnings(stderr: &str) -> Vec<&str> {
        stderr
            .lines()
            .filter(|line| line.starts_with("Warning: cfn-guard does not read the YAML tag"))
            .collect()
    }

    /// The positions of the `!!python/str` tags in a fixture, as the loader writes them (`L:n,C:m`,
    /// both one-based), in document order. Read from the file rather than written into the test, so
    /// that a fixture whose padding moves a tag does not fail the test in a way that has to be traced
    /// back to the padding. The tests that use it need the second tag on a two-digit line, which is
    /// what makes a text sort and the document disagree; they check that too.
    fn tag_positions(fixture: &str) -> Vec<String> {
        let text = std::fs::read_to_string(fixture).expect("the fixture is readable");
        // Comment lines are skipped: the fixtures' comments name the tag too.
        let positions: Vec<String> = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with('#'))
            .filter_map(|(index, line)| {
                line.find("!!python/str")
                    .map(|column| format!("L:{},C:{}", index + 1, column + 1))
            })
            .collect();
        assert_eq!(
            2,
            positions.len(),
            "{fixture}: two tagged lines, got {positions:?}"
        );
        assert!(
            positions[0].as_bytes()[3] == b',' && positions[1].as_bytes()[4] == b',',
            "{}: the first tag must sit on a one-digit line and the second on a two-digit line, so \
             that a text sort would put them the wrong way round, got {:?}",
            fixture,
            positions
        );
        positions
    }

    /// Checks that `warnings` holds one `!!python/str` line per position in `positions`, in that
    /// order, each naming `spec`.
    fn assert_tag_warnings_in_order(
        context: &str,
        warnings: &[&str],
        positions: &[String],
        spec: &str,
    ) {
        assert_eq!(
            positions.len(),
            warnings.len(),
            "{context}: one warning per tagged node, got:\n{}",
            warnings.join("\n")
        );
        for (index, position) in positions.iter().enumerate() {
            let expected =
                format!("`!!python/str` at {position} in test file {spec}; the node is read as if");
            assert!(
                warnings[index].contains(&expected),
                "{context}: warning {} must be the one at {position}, document order:\n{}",
                index + 1,
                warnings.join("\n")
            );
        }
    }

    /// Two `!!` tags in a spec file are warned about in document order, as `validate` warns about the
    /// same tags in a data file.
    ///
    /// `two_tags_tests.yaml` tags its case names on a one-digit and a two-digit line. The warnings
    /// went through the reporter's sorted diagnostics, so they came out by text, and `L:10` sorts
    /// before `L:2`: a reader fixing the file top to bottom was sent to the second tag first. Both
    /// lines name the test file and its position, and the file still loads and passes.
    #[test]
    fn tag_warnings_for_a_spec_file_come_in_document_order() {
        const SPEC: &str = "resources/test-command/foreign-tags/two_tags_tests.yaml";
        let (status_code, stdout, stderr) =
            run_spec("resources/test-command/foreign-tags/rules.guard", SPEC);

        assert_eq!(StatusCode::SUCCESS, status_code, "{}", stdout);
        assert_tag_warnings_in_order("loads", &tag_warnings(&stderr), &tag_positions(SPEC), SPEC);
    }

    /// A spec file the loader refuses is still warned about for the `!!` tags it read before the
    /// refusal, under every output format.
    ///
    /// `two_tags_then_a_refusal_tests.yaml` is `two_tags_tests.yaml` with a flow sequence left open
    /// on its last line. The loader read past both tags before it refused the document, and `validate`
    /// prints the tags a refused data file carried; `test` rendered the same two lines and then
    /// dropped them on the refusal, so the author of a file that was both tagged and broken saw the
    /// refusal alone, and fixing it brought two warnings they had not been told about. The refusal
    /// is reported as before, at exit 1, and the two lines come in document order beside it.
    #[rstest]
    #[case("single-line-summary")]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn tag_warnings_for_a_refused_spec_file_are_still_printed(#[case] output: &str) {
        const SPEC: &str = "resources/test-command/foreign-tags/two_tags_then_a_refusal_tests.yaml";
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/foreign-tags/rules.guard",
            SPEC,
            output,
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{output}: the refusal keeps its exit code:\n{}",
            stdout
        );
        assert!(
            stdout.contains("did not find expected node content"),
            "{output}: the refusal must still be reported:\n{}",
            stdout
        );
        assert_tag_warnings_in_order(output, &tag_warnings(&stderr), &tag_positions(SPEC), SPEC);
    }

    /// The same refused, tagged spec beside a rules file that declares no rules is warned about the
    /// same way, by the path that reports expectations against no rules.
    ///
    /// That path reads the spec files itself, through the same helper the reporters use to note the
    /// tags. The refusal is reported on stderr as that path reports it, at exit 1, after the two tag
    /// lines, which come in document order: the refusal names the file and the position the loader
    /// stopped at, so it is a positioned line of that file and follows the file's tags rather than
    /// landing in the sorted set among lines about other files.
    #[test]
    fn tag_warnings_for_a_refused_spec_beside_a_rules_file_declaring_nothing() {
        const SPEC: &str = "resources/test-command/foreign-tags/two_tags_then_a_refusal_tests.yaml";
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/foreign-tags/declares_nothing.guard",
            SPEC,
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}\n{}",
            stdout,
            stderr
        );
        let lines: Vec<&str> = stderr.lines().collect();
        let refusal = lines
            .iter()
            .position(|line| {
                line.starts_with("Unable to process a test file:")
                    && line.contains("did not find expected node content")
            })
            .unwrap_or_else(|| {
                panic!(
                    "the refusal must be reported on stderr by this path:\n{}",
                    stderr
                )
            });
        assert_tag_warnings_in_order(
            "no rules",
            &tag_warnings(&stderr),
            &tag_positions(SPEC),
            SPEC,
        );
        assert_eq!(
            2, refusal,
            "the two tag lines come first and the refusal right after them:\n{}",
            stderr
        );
    }

    /// A directory of two rules files declaring nothing, the first beside a tagged spec the loader
    /// refuses and the second beside a spec whose case lacks `input:`, reports the first file's two tag
    /// lines, then its refusal, then the second file's case line, under the plaintext and the
    /// structured walk.
    ///
    /// The structured walk keeps one collection for the whole directory, and the refusal went into its
    /// sorted set while the tag lines and the case line went into the ordered one, so the refusal came
    /// out after the second file's case line. It names the file and the position the loader stopped
    /// at, so it is a positioned line of the first file and belongs between that file's tags and the
    /// next file's lines.
    #[rstest]
    #[case("single-line-summary")]
    #[case("json")]
    fn a_refusal_beside_a_rules_file_declaring_nothing_keeps_its_place_in_a_directory_walk(
        #[case] output: &str,
    ) {
        const DIR: &str = "resources/test-command/foreign-tags-no-rules-dir";
        let (status_code, stdout, stderr) = capture_both_streams(|writer, reader| {
            TestCommandTestRunner::default()
                .directory(Option::from(DIR))
                .output_format(output)
                .run(writer, reader)
        });

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{output}:\n{}\n{}",
            stdout,
            stderr
        );
        let a_spec = reported_path(DIR, &["tests", "a_nothing_tests.yaml"]);
        let b_spec = reported_path(DIR, &["tests", "b_nothing_tests.yaml"]);
        let positioned: Vec<&str> = stderr
            .lines()
            .filter(|line| {
                line.starts_with("Warning: cfn-guard does not read the YAML tag")
                    || line.starts_with("Unable to process a test file:")
                    || line.starts_with("Unable to process a test case in test file")
            })
            .collect();
        assert_eq!(
            4,
            positioned.len(),
            "{output}: two tag lines, one refusal and one case line, got:\n{}",
            stderr
        );
        for (index, position) in tag_positions(&a_spec).iter().enumerate() {
            assert!(
                positioned[index].contains(&format!("at {position} in test file {a_spec}")),
                "{output}: line {} is the first file's tag at {position}:\n{}",
                index + 1,
                stderr
            );
        }
        assert!(
            positioned[2].starts_with("Unable to process a test file:")
                && positioned[2].contains(&a_spec),
            "{output}: the first file's refusal comes right after its tag lines:\n{}",
            stderr
        );
        assert!(
            positioned[3].contains(&b_spec) && positioned[3].contains("missing field `input`"),
            "{output}: the second file's case line comes last:\n{}",
            stderr
        );
    }

    /// A directory walk over two rules files whose spec files each carry two `!!` tags warns file by
    /// file, each file in document order, under the plaintext and the structured walk.
    ///
    /// The structured walk keeps one collection of notices for the whole directory and every rules
    /// file's reporter writes into it, so the order has to survive that: `a_tagged_tests.yaml`'s two
    /// lines, then `b_tagged_tests.yaml`'s. A text sort would interleave them by position instead.
    #[rstest]
    #[case("single-line-summary")]
    #[case("json")]
    fn tag_warnings_in_a_directory_walk_come_file_by_file_in_document_order(#[case] output: &str) {
        const DIR: &str = "resources/test-command/foreign-tags-dir";
        let (status_code, stdout, stderr) = capture_both_streams(|writer, reader| {
            TestCommandTestRunner::default()
                .directory(Option::from(DIR))
                .output_format(output)
                .run(writer, reader)
        });

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{output}:\n{}\n{}",
            stdout,
            stderr
        );
        let warnings = tag_warnings(&stderr);
        let mut expected = vec![];
        for spec in [
            reported_path(DIR, &["tests", "a_tagged_tests.yaml"]),
            reported_path(DIR, &["tests", "b_tagged_tests.yaml"]),
        ] {
            for position in tag_positions(&spec) {
                expected.push(format!(
                    "`!!python/str` at {position} in test file {spec}; the node is read as if"
                ));
            }
        }
        assert_eq!(
            expected.len(),
            warnings.len(),
            "{output}: one warning per tagged node across both files, got:\n{}",
            stderr
        );
        for (index, needle) in expected.iter().enumerate() {
            assert!(
                warnings[index].contains(needle),
                "{output}: warning {} must be {needle}, file by file in document order:\n{}",
                index + 1,
                stderr
            );
        }
    }

    /// Duplicate-key warnings from two cases of one spec come in document order, like the tag lines.
    ///
    /// Each case of `duplicated_keys_in_two_cases_tests.yaml` writes `A` twice inside its `input:`,
    /// the first pair on one-digit lines and the second on two-digit lines. The warnings went
    /// through the sorted set, so the second case's line, `first at L:14`, came out before the first
    /// case's `first at L:4`. They carry positions and are read top to bottom, so they take the
    /// ordered path the tag lines take.
    #[test]
    fn duplicate_key_warnings_come_in_document_order() {
        const SPEC: &str =
            "resources/test-command/foreign-tags/duplicated_keys_in_two_cases_tests.yaml";
        let (status_code, stdout, stderr) =
            run_spec("resources/test-command/foreign-tags/rules.guard", SPEC);

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("Warning: duplicate key /A in test file"))
            .collect();
        let expected = [
            "first at L:4,C:5 and again at L:5,C:5",
            "first at L:14,C:5 and again at L:15,C:5",
        ];
        assert_eq!(
            expected.len(),
            warnings.len(),
            "one warning per duplicated key, got:\n{}",
            stderr
        );
        for (index, needle) in expected.iter().enumerate() {
            assert!(
                warnings[index].contains(needle),
                "warning {} must be the one {needle}, document order:\n{}",
                index + 1,
                stderr
            );
        }
    }

    /// Duplicate-case-name warnings for two pairs of cases come in document order, like the tag lines.
    ///
    /// `alike_names_in_two_pairs_tests.yaml` holds a pair named `b` and then a pair named `a`, each
    /// pair over one input. Sorted by text, the warning for `a` came first; the document has `b`
    /// first, and so does a reader renaming the cases top to bottom.
    #[test]
    fn duplicate_case_name_warnings_come_in_document_order() {
        const SPEC: &str =
            "resources/test-command/foreign-tags/alike_names_in_two_pairs_tests.yaml";
        let (status_code, stdout, stderr) =
            run_spec("resources/test-command/foreign-tags/rules.guard", SPEC);

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("Warning: two test cases in test file"))
            .collect();
        let expected = [
            "are named `b`, at L:2,C:9 and again at L:8,C:9",
            "are named `a`, at L:14,C:9 and again at L:20,C:9",
        ];
        assert_eq!(
            expected.len(),
            warnings.len(),
            "one warning per pair, got:\n{}",
            stderr
        );
        for (index, needle) in expected.iter().enumerate() {
            assert!(
                warnings[index].contains(needle),
                "warning {} must be the one that {needle}, document order:\n{}",
                index + 1,
                stderr
            );
        }
    }

    /// The lines for two unreadable cases beside a rules file that declares nothing come in document
    /// order, like the other positioned lines that path writes.
    ///
    /// `two_cases_without_input_tests.yaml` holds two cases that both lack `input:`, on a one-digit
    /// and a two-digit line. The path that reports expectations against no rules put each case's
    /// line in the sorted set, so the second case's `L:12` came out before the first case's `L:2`
    /// while the tag lines just above them had already been taught document order. The reporters
    /// put the same refusal in the report, case by case, so only this path was affected.
    #[test]
    fn unreadable_case_lines_beside_a_rules_file_declaring_nothing_come_in_document_order() {
        const SPEC: &str = "resources/test-command/foreign-tags/two_cases_without_input_tests.yaml";
        let (status_code, stdout, stderr) = run_spec(
            "resources/test-command/foreign-tags/declares_nothing.guard",
            SPEC,
        );

        assert_eq!(
            StatusCode::INCORRECT_STATUS_ERROR,
            status_code,
            "{}\n{}",
            stdout,
            stderr
        );
        let lines: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("Unable to process a test case in test file"))
            .collect();
        let expected = [
            "missing field `input` in the test case at L:2,C:3",
            "missing field `input` in the test case at L:12,C:3",
        ];
        assert_eq!(
            expected.len(),
            lines.len(),
            "one line per unreadable case, got:\n{}",
            stderr
        );
        for (index, needle) in expected.iter().enumerate() {
            assert!(
                lines[index].contains(needle),
                "line {} must be the one {needle}, document order:\n{}",
                index + 1,
                stderr
            );
        }
    }

    /// The evaluator's notices reach stderr in one order in every output: the deprecation notices, then
    /// the warnings in the order the evaluator recorded them, which is the order `validate` writes
    /// them in.
    ///
    /// `warnings-order/rules.guard` has two key filters whose function argument is read from the map
    /// being filtered where the enclosing scope holds a different value, at line 3 and at line 13, each
    /// a warning, and between them a filter after a scalar key, which is a deprecation notice. (A
    /// `this[ ... ]` inside a block that selects nothing is refused at the clause on this tree and writes
    /// nothing to stderr, so the warning the evaluator still writes is the one used.) Each
    /// warning ends with its clause's position, and sorted by text "line:13" comes before "line:3", so
    /// a store or a bucket sorted by text printed the later clause first: the scope's own set was
    /// sorted, and the reporters fed the evaluator's warnings to the sorted bucket as well, so every
    /// output printed 13 then 3 while the author reads the file top down. The warnings now keep the
    /// evaluator's order through the scope and through a bucket of their own, written after the
    /// deprecation notices as `validate` writes them: the deprecation notice, then line 3, then line
    /// 13, three lines, in both outputs.
    #[rstest::rstest]
    #[case::single_line("single-line-summary")]
    #[case::json("json")]
    fn the_evaluators_notices_keep_one_order_in_every_output(#[case] output: &str) {
        let (status_code, stdout, stderr) = run_spec_in(
            "resources/test-command/warnings-order/rules.guard",
            "resources/test-command/warnings-order/tests/two_argument_warnings_tests.yaml",
            output,
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{output}: every expectation holds:\n{stdout}\n{stderr}"
        );
        let order: Vec<String> = stderr
            .lines()
            .filter_map(|line| {
                if line.starts_with("DEPRECATION: the filter `[ this == 'x' ]` follows the key") {
                    Some("deprecation".to_string())
                } else if line
                    .starts_with("Warning: the function argument `Wanted` in a map key filter")
                {
                    line.rsplit_once("line:").map(|(_, tail)| {
                        format!("warning at line {}", tail.replace(", column:43].", ""))
                    })
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            vec![
                "deprecation".to_string(),
                "warning at line 3".to_string(),
                "warning at line 13".to_string(),
            ],
            order,
            "{output}: the deprecation notice first, then the warnings in the order the clauses were \
             evaluated, line 3 then line 13, not in text order:\n{stderr}"
        );
    }

    /// The positioned lines of one file are grouped by kind, each kind in document order: every tag
    /// line, then the alike-name lines, then the duplicate-key lines case by case.
    ///
    /// `mixed_kinds_tests.yaml` writes a key twice in its first case (L:4 and L:5) and tags its second
    /// case's name on L:20. The tag line is written first although it sits later in the file: that is
    /// the order `validate` writes the same lines in for a data file, every tag line as the file is
    /// read and the duplicate-key lines after them, and the test command matches it rather than
    /// interleaving the kinds by position. This pins the grouping, so that a change to strict position
    /// order has a red to turn green.
    #[test]
    fn positioned_warnings_are_grouped_by_kind_each_kind_in_document_order() {
        const SPEC: &str = "resources/test-command/foreign-tags/mixed_kinds_tests.yaml";
        let (status_code, stdout, stderr) =
            run_spec("resources/test-command/foreign-tags/rules.guard", SPEC);

        assert_eq!(StatusCode::SUCCESS, status_code, "{}\n{}", stdout, stderr);
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("Warning: "))
            .collect();
        assert_eq!(
            2,
            warnings.len(),
            "one tag line and one duplicate-key line, got:\n{}",
            stderr
        );
        assert!(
            warnings[0].contains("does not read the YAML tag `!!python/str` at L:20,C:9"),
            "the tag line comes first, its kind being written first:\n{}",
            stderr
        );
        assert!(
            warnings[1].contains("duplicate key /A")
                && warnings[1].contains("first at L:4,C:5 and again at L:5,C:5"),
            "the duplicate-key line comes second although it sits earlier in the file:\n{}",
            stderr
        );
    }
}
