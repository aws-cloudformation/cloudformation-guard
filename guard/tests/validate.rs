// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod validate_tests {
    use std::fs::File;
    use std::io::{stderr, stdout, Read};

    use indoc::indoc;
    use rstest::rstest;
    use strip_ansi_escapes;

    use cfn_guard;
    use cfn_guard::commands::validate::Validate;
    use cfn_guard::commands::{
        ALPHABETICAL, DATA, INPUT_PARAMETERS, LAST_MODIFIED, OUTPUT_FORMAT, PAYLOAD,
        PREVIOUS_ENGINE, PRINT_JSON, RULES, SHOW_CLAUSE_FAILURES, SHOW_SUMMARY, VALIDATE, VERBOSE,
    };
    use cfn_guard::utils::reader::ReadBuffer::{File as ReadFile, Stdin};
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::WriteBuffer::Stderr;
    use cfn_guard::utils::writer::{WriteBuffer::Stdout, WriteBuffer::Vec as WBVec, Writer};

    use crate::utils::{
        compare_write_buffer_with_file, compare_write_buffer_with_string,
        get_full_path_for_resource_file, CommandTestRunner, StatusCode,
    };
    use crate::{assert_output_from_file_eq, assert_output_from_str_eq};

    #[derive(Default)]
    struct ValidateTestRunner<'args> {
        data: Vec<&'args str>,
        rules: Vec<&'args str>,
        show_summary: Vec<&'args str>,
        input_parameters: Vec<&'args str>,
        output_format: Option<&'args str>,
        previous_engine: bool,
        show_clause_failures: bool,
        alphabetical: bool,
        last_modified: bool,
        verbose: bool,
        print_json: bool,
        payload: Option<&'args str>,
    }

    impl<'args> ValidateTestRunner<'args> {
        fn data(&'args mut self, args: Vec<&'args str>) -> &'args mut ValidateTestRunner {
            self.data = args;
            self
        }

        fn rules(&'args mut self, args: Vec<&'args str>) -> &'args mut ValidateTestRunner {
            self.rules = args;
            self
        }

        fn show_summary(&'args mut self, args: Vec<&'args str>) -> &'args mut ValidateTestRunner {
            self.show_summary = args;
            self
        }

        fn input_parameters(
            &'args mut self,
            args: Vec<&'args str>,
        ) -> &'args mut ValidateTestRunner {
            self.input_parameters = args;
            self
        }

        fn output_format(
            &'args mut self,
            arg: Option<&'args str>,
        ) -> &'args mut ValidateTestRunner {
            self.output_format = arg;
            self
        }

        fn payload(&'args mut self, arg: Option<&'args str>) -> &'args mut ValidateTestRunner {
            if !self.data.is_empty() || !self.rules.is_empty() {
                panic!("data argument conflicts with the payload argument")
            }

            self.payload = arg;
            self
        }

        fn previous_engine(&'args mut self, arg: bool) -> &'args mut ValidateTestRunner {
            self.previous_engine = arg;
            self
        }

        fn show_clause_failures(&'args mut self, arg: bool) -> &'args mut ValidateTestRunner {
            self.show_clause_failures = arg;
            self
        }

        fn alphabetical(&'args mut self, arg: bool) -> &'args mut ValidateTestRunner {
            if self.last_modified {
                panic!("alphabetical and last modified are conflicting")
            }

            self.alphabetical = arg;
            self
        }

        fn last_modified(&'args mut self, arg: bool) -> &'args mut ValidateTestRunner {
            if self.alphabetical {
                panic!("alphabetical and last modified are conflicting")
            }

            self.last_modified = arg;
            self
        }

        fn verbose(&'args mut self, arg: bool) -> &'args mut ValidateTestRunner {
            self.verbose = arg;
            self
        }

        fn print_json(&'args mut self, arg: bool) -> &'args mut ValidateTestRunner {
            self.print_json = arg;
            self
        }
    }

    impl<'args> CommandTestRunner for ValidateTestRunner<'args> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![String::from(VALIDATE)];

            if !self.data.is_empty() {
                args.push(format!("-{}", DATA.1));

                for data_arg in &self.data {
                    args.push(get_path_for_resource_file(data_arg));
                }
            }

            if !self.rules.is_empty() {
                args.push(format!("-{}", RULES.1));

                for rule_arg in &self.rules {
                    args.push(get_path_for_resource_file(rule_arg));
                }
            }

            if !self.input_parameters.is_empty() {
                args.push(format!("-{}", INPUT_PARAMETERS.1));

                for input_param_arg in &self.input_parameters {
                    args.push(get_path_for_resource_file(input_param_arg));
                }
            }

            if !self.show_summary.is_empty() {
                args.push(format!("-{}", SHOW_SUMMARY.1));
                args.push(self.show_summary.join(","));
            }

            if let Some(output_format) = self.output_format {
                args.push(format!("-{}", OUTPUT_FORMAT.1));
                args.push(String::from(output_format));
            }

            if self.previous_engine {
                args.push(format!("-{}", PREVIOUS_ENGINE.1));
            }

            if self.show_clause_failures {
                args.push(format!("-{}", SHOW_CLAUSE_FAILURES.1));
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

            if self.print_json {
                args.push(format!("-{}", PRINT_JSON.1));
            }

            if let Some(payload) = self.payload {
                args.push(format!("-{}", PAYLOAD.1));
                args.push(payload.to_string());
            }

            args
        }
    }

    fn get_path_for_resource_file(file: &str) -> String {
        get_full_path_for_resource_file(&format!("resources/validate/{}", file))
    }

    #[rstest::rstest]
    #[case(
        vec!["data-dir/s3-public-read-prohibited-template-compliant.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard"],
        StatusCode::SUCCESS
    )]
    #[case(
        vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard"],
        StatusCode::PARSING_ERROR
    )]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["malformed-rule.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["malformed-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["blank-rule.guard"], StatusCode::PARSING_ERROR)]
    #[case(
        vec!["s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["s3_bucket_server_side_encryption_enabled_2.guard", "blank-rule.guard"],
        StatusCode::PARSING_ERROR
    )]
    #[case(vec!["blank-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(
        vec!["blank-template.yaml", "s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["s3_bucket_server_side_encryption_enabled_2.guard"],
        StatusCode::INTERNAL_FAILURE
    )]
    #[case(vec!["dne.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"], vec!["dne.guard"], StatusCode::INTERNAL_FAILURE)]
    fn test_single_data_file_single_rules_file_status(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(Stdout(stdout()), Stderr(stderr()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_compliant() {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), Stderr(stderr()));
        let status_code = ValidateTestRunner::default()
            .data(vec![
                "data-dir/s3-public-read-prohibited-template-compliant.yaml",
            ])
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let expected_output = indoc! {
            r#"s3-public-read-prohibited-template-compliant.yaml Status = PASS
               PASS rules
               s3_bucket_public_read_prohibited.guard/S3_BUCKET_PUBLIC_READ_PROHIBITED    PASS
               ---
               "#
        };

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_str_eq!(expected_output, writer)
    }

    #[rstest::rstest]
    #[case(
        vec!["data-dir/s3-public-read-prohibited-template-compliant.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard"],
        "resources/validate/output-dir/test_single_data_file_single_rules_file_verbose_compliant.out",
        StatusCode::SUCCESS
    )]
    #[case(
        vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard"],
        "resources/validate/output-dir/test_single_data_file_single_rules_file_verbose_non_compliant.out",
        StatusCode::PARSING_ERROR
    )]
    fn test_single_data_file_single_rules_file_verbose(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] expected_output: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut writer = Writer::new(WBVec(vec![]), Stderr(stderr()));
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .show_summary(vec!["all"])
            .verbose(true)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_file_eq!(expected_output, writer)
    }

    #[rstest::rstest]
    #[case(
        vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard"],
        "resources/validate/output-dir/test_single_data_file_single_rules_file_verbose.out",
        StatusCode::PARSING_ERROR
    )]
    #[case(
        vec!["data-dir/advanced_regex_negative_lookbehind_non_compliant.yaml"],
        vec!["rules-dir/advanced_regex_negative_lookbehind_rule.guard"],
        "resources/validate/output-dir/advanced_regex_negative_lookbehind_non_compliant.out",
        StatusCode::PARSING_ERROR
    )]
    #[case(
        vec!["data-dir/advanced_regex_negative_lookbehind_compliant.yaml"],
        vec!["rules-dir/advanced_regex_negative_lookbehind_rule.guard"],
        "resources/validate/output-dir/advanced_regex_negative_lookbehind_compliant.out",
        StatusCode::SUCCESS
    )]
    fn test_single_data_file_single_rules_file(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] expected_output: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), Stderr(stderr()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_file_eq!(expected_output, writer)
    }

    #[rstest::rstest]
    #[case(
    vec!["data-dir/s3-server-side-encryption-template-compliant.yaml", "data-dir/s3-public-read-prohibited-template-compliant.yaml"],
    vec!["rules-dir/s3_bucket_public_read_prohibited.guard"]
    )]
    #[case(
    vec!["data-dir/s3-public-read-prohibited-template-compliant.yaml"],
    vec!["rules-dir/s3_bucket_public_read_prohibited.guard", "rules-dir/s3_bucket_public_read_prohibited.guard"]
    )]
    fn test_different_combinations_of_rules_and_data(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
    ) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(Stdout(stdout()), Stderr(stderr()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[rstest::rstest]
    #[case(vec!["data-dir/"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])]
    #[case(vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"], vec!["rules-dir/"])]
    #[case(vec!["data-dir/"], vec!["rules-dir/"])]
    #[case(
        vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml", "data-dir/s3-public-read-prohibited-template-compliant.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard"]
    )]
    #[case(
        vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard", "rules-dir/s3_bucket_server_side_encryption_enabled.guard"]
    )]
    #[case(
        vec!["data-dir/", "s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["rules-dir/s3_bucket_public_read_prohibited.guard"]
    )]
    #[case(
        vec!["s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["rules-dir/", "s3_bucket_server_side_encryption_enabled_2.guard"]
    )]
    #[case(vec!["data-dir/"], vec!["rules-dir/", "s3_bucket_server_side_encryption_enabled_2.guard"])]
    #[case(vec!["data-dir/", "s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["rules-dir/"])]
    #[case(
        vec!["data-dir/", "s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["rules-dir/", "s3_bucket_server_side_encryption_enabled_2.guard"]
    )]
    fn test_combinations_of_rules_and_data_non_compliant(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
    ) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(Stdout(stdout()), Stderr(stderr()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[rstest::rstest]
    #[case(
        vec!["db_resource.yaml"],
        vec!["db_param_port_rule.guard"],
        vec!["input-parameters-dir/db_params.yaml"], 
        StatusCode::PARSING_ERROR
    )]
    #[case(
        vec!["db_resource.yaml"],
        vec!["db_param_port_rule.guard"],
        vec!["input-parameters-dir/db_params.yaml", "input-parameters-dir/db_metadata.yaml"],
        StatusCode::SUCCESS
    )]
    #[case(
        vec!["db_resource.yaml"],
        vec!["db_param_port_rule.guard"],
        vec!["input-parameters-dir/"],
        StatusCode::SUCCESS
    )]
    #[case(
        vec!["db_resource.yaml"],
        vec!["db_param_port_rule.guard"],
        vec!["input-parameters-dir/malformed-template.yaml"],
        StatusCode::INTERNAL_FAILURE
    )]
    #[case(
        vec!["db_resource.yaml"],
        vec!["db_param_port_rule.guard"],
        vec!["input-parameters-dir/blank-template.yaml"],
        StatusCode::INTERNAL_FAILURE
    )]
    #[case(
        vec!["db_resource.yaml"],
        vec!["db_param_port_rule.guard"],
        vec!["input-parameters-dir/blank-template.yaml", "input-parameters-dir/db_params.yaml"],
        StatusCode::INTERNAL_FAILURE
    )]
    fn test_combinations_of_rules_data_and_input_params_files(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] input_params_arg: Vec<&str>,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(Stdout(stdout()), Stderr(stderr()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .input_parameters(input_params_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
    }

    #[test]
    fn test_payload() {
        let file = File::open(
            "resources/validate/data-dir/s3-server-side-encryption-template-compliant.yaml",
        )
        .expect("failed to find mocked file ");
        let mut reader = Reader::new(ReadFile(file));
        let mut writer = Writer::new(Stdout(stdout()), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .run(&mut writer, &mut reader);

        let s = writer.err_to_stripped().unwrap();

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_payload_verbose() {
        let file = File::open(
            "resources/validate/data-dir/s3-server-side-encryption-template-compliant.yaml",
        )
        .expect("failed to find mocked file ");
        let mut reader = Reader::new(ReadFile(file));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose(true)
            .run(&mut writer, &mut reader);

        let mut file =
            File::open("resources/validate/output-dir/payload_verbose_success.out").unwrap();
        let result = writer.stripped().unwrap();
        let mut expected = String::new();

        file.read_to_string(&mut expected).unwrap();

        assert_eq!(expected, result);
        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_payload_verbose_fail() {
        let file = File::open(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        )
        .expect("failed to find mocked file ");
        let mut reader = Reader::new(ReadFile(file));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose(true)
            .run(&mut writer, &mut reader);

        let mut file =
            File::open("resources/validate/output-dir/payload_verbose_non_compliant.out").unwrap();
        let result = writer.stripped().unwrap();
        let mut expected = String::new();

        file.read_to_string(&mut expected).unwrap();

        assert_eq!(result, expected);
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_payload_verbose_fail2() {
        let file = File::open(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        )
        .expect("failed to find mocked file ");
        let mut reader = Reader::new(ReadFile(file));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose(true)
            .previous_engine(true)
            .print_json(true)
            .run(&mut writer, &mut reader);

        let result = writer.stripped().unwrap();
        let mut file =
            File::open("resources/validate/output-dir/payload_verbose_json_non_compliant.out")
                .unwrap();
        let mut expect = String::new();
        file.read_to_string(&mut expect).unwrap();

        assert_eq!(expect, result);
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_payload_verbose_yaml_compliant() {
        let file = File::open(
            "resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        )
        .expect("failed to find mocked file ");
        let mut reader = Reader::new(ReadFile(file));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose(true)
            .output_format(Some("yaml"))
            .run(&mut writer, &mut reader);
        let result = writer.stripped().unwrap();

        let mut file =
            File::open("resources/validate/output-dir/payload_verbose_yaml_compliant.out").unwrap();
        let mut expect = String::new();
        file.read_to_string(&mut expect).unwrap();

        assert_eq!(expect, result);
        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_payload_json_fail() {
        let file = File::open(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        )
        .expect("failed to find mocked file ");
        let mut reader = Reader::new(ReadFile(file));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .previous_engine(true)
            .print_json(true)
            .run(&mut writer, &mut reader);

        let expected = indoc! {"
        STDIN Status = FAIL
        FAILED rules
        s3_bucket_public_read_prohibited.guard/S3_BUCKET_PUBLIC_READ_PROHIBITED    FAIL
        ---
        "
        };

        let result = writer.stripped().unwrap();

        assert_eq!(expected, result);
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }
}
