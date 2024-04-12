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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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

    #[test]
    fn test_parse_error_when_guard_rule_has_syntax_error() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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

    #[rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    fn test_structured_single_report(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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

    #[test]
    fn test_sarif_output_with_expected_failures() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer");
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
