// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod validate_tests {
    use std::fmt::format;
    use std::fs::File;
    use std::io::{stderr, stdout, Cursor, Read};

    use indoc::indoc;
    use rstest::rstest;
    use strip_ansi_escapes;

    use cfn_guard;
    use cfn_guard::commands::validate::Validate;
    use cfn_guard::commands::{
        ALPHABETICAL, DATA, INPUT_PARAMETERS, LAST_MODIFIED, OUTPUT_FORMAT, PAYLOAD,
        PREVIOUS_ENGINE, PRINT_JSON, RULES, SHOW_CLAUSE_FAILURES, SHOW_SUMMARY, STRUCTURED,
        VALIDATE, VERBOSE,
    };
    use cfn_guard::utils::reader::ReadBuffer::{Cursor as ReadCursor, File as ReadFile, Stdin};
    use cfn_guard::utils::reader::{ReadBuffer, Reader};
    use cfn_guard::utils::writer::WriteBuffer::Stderr;
    use cfn_guard::utils::writer::{WriteBuffer::Stdout, WriteBuffer::Vec as WBVec, Writer};

    use crate::utils::{
        compare_write_buffer_with_file, compare_write_buffer_with_string,
        get_full_path_for_resource_file, CommandTestRunner, StatusCode,
    };
    use crate::{assert_output_from_file_eq, assert_output_from_str_eq, utils};

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
        payload: bool,
        structured: bool,
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

        fn payload(&'args mut self) -> &'args mut ValidateTestRunner {
            self.payload = true;
            self
        }

        fn previous_engine(&'args mut self) -> &'args mut ValidateTestRunner {
            self.previous_engine = true;
            self
        }

        fn show_clause_failures(&'args mut self) -> &'args mut ValidateTestRunner {
            self.show_clause_failures = true;
            self
        }

        fn alphabetical(&'args mut self) -> &'args mut ValidateTestRunner {
            self.alphabetical = true;
            self
        }

        fn last_modified(&'args mut self) -> &'args mut ValidateTestRunner {
            self.last_modified = true;
            self
        }

        fn verbose(&'args mut self) -> &'args mut ValidateTestRunner {
            self.verbose = true;
            self
        }

        fn print_json(&'args mut self) -> &'args mut ValidateTestRunner {
            self.print_json = true;
            self
        }

        fn structured(&'args mut self) -> &'args mut ValidateTestRunner {
            self.structured = true;
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

            if self.payload {
                args.push(format!("-{}", PAYLOAD.1));
            }

            if self.structured {
                args.push(format!("-{}", STRUCTURED.1));
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
            .verbose()
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
    fn test_rules_with_data_from_stdin_yaml() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-server-side-encryption-template-compliant.yaml",
        );
        let mut writer = Writer::new(Stdout(stdout()), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_rules_with_data_from_stdin_yaml_verbose() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-server-side-encryption-template-compliant.yaml",
        );
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!(
            "resources/validate/output-dir/payload_verbose_success.out",
            writer
        );
        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_rules_with_data_from_stdin_fail() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!(
            "resources/validate/output-dir/payload_verbose_non_compliant.out",
            writer
        );
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_rules_with_data_from_stdin_verbose_previous_engine_json_fail() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose()
            .previous_engine()
            .print_json()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        assert_output_from_file_eq!(
            "resources/validate/output-dir/payload_verbose_json_non_compliant.out",
            writer
        )
    }

    #[test]
    fn test_payload_verbose_yaml_compliant() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose()
            .output_format(Some("yaml"))
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!(
            "resources/validate/output-dir/payload_verbose_yaml_compliant.out",
            writer
        );
        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_rules_with_data_from_stdin_prev_engine_fail() {
        let file = File::open(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        )
        .expect("failed to find mocked file ");
        let mut reader = Reader::new(ReadFile(file));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .previous_engine()
            .print_json()
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

    #[test]
    fn test_with_payload_flag() {
        let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"TestInstance\"" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    const COMPLIANT_PAYLOAD: &str = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"TestInstance\"" ]}"#;

    #[test]
    fn test_with_payload_flag_prev_engine_show_summary_all() {
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(
            COMPLIANT_PAYLOAD.as_bytes(),
        ))));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .payload()
            .previous_engine()
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let result = writer.stripped().unwrap();
        let expected = indoc! {
            r#"
            DATA_STDIN[1] Status = PASS
            PASS rules
            RULES_STDIN[1]/default    PASS
            ---
            DATA_STDIN[2] Status = PASS
            PASS rules
            RULES_STDIN[1]/default    PASS
            ---
            DATA_STDIN[1] Status = PASS
            PASS rules
            RULES_STDIN[2]/default    PASS
            ---
            DATA_STDIN[2] Status = PASS
            PASS rules
            RULES_STDIN[2]/default    PASS
            ---
            "#
        };

        assert_eq!(expected, result);
        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_with_payload_flag_show_summary_all() {
        let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"TestInstance\"" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .payload()
            .previous_engine()
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let result = writer.stripped().unwrap();
        let expected = indoc! {
            r#"
            DATA_STDIN[1] Status = PASS
            PASS rules
            RULES_STDIN[1]/default    PASS
            ---
            DATA_STDIN[2] Status = PASS
            PASS rules
            RULES_STDIN[1]/default    PASS
            ---
            DATA_STDIN[1] Status = PASS
            PASS rules
            RULES_STDIN[2]/default    PASS
            ---
            DATA_STDIN[2] Status = PASS
            PASS rules
            RULES_STDIN[2]/default    PASS
            ---
            "#
        };

        assert_eq!(expected, result);
        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_with_payload_flag_fail() {
        let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"SomeRandomString\"" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        let result = writer.stripped().unwrap();
        let expected = indoc! {
            r#"
            DATA_STDIN[1] Status = FAIL
            FAILED rules
            RULES_STDIN[2]/default    FAIL
            ---
            Evaluating data DATA_STDIN[1] against rules RULES_STDIN[2]
            Number of non-compliant resources 0
            DATA_STDIN[2] Status = FAIL
            FAILED rules
            RULES_STDIN[2]/default    FAIL
            ---
            Evaluating data DATA_STDIN[2] against rules RULES_STDIN[2]
            Number of non-compliant resources 0
            "#
        };

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        assert_eq!(expected, result);
    }

    #[test]
    fn test_with_payload_flag_fail_verbose_prev_engine() {
        let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"SomeRandomString\"" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .payload()
            .previous_engine()
            .verbose()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!(
            "resources/validate/output-dir/payload_flag_fail_verbose_prev_engine.out",
            writer
        );
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_rules_with_data_from_stdin_fail_prev_engine_show_clause_failures() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .show_summary(vec!["none", "all", "pass", "fail", "skip"])
            .verbose()
            .previous_engine()
            .show_clause_failures()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!(
            "resources/validate/output-dir/payload_verbose_show_failure.out",
            writer
        );
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_structured_output() {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/rules-dir"])
            .data(vec![
                "/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(vec!["none"])
            .output_format(Option::from("json"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!("resources/validate/output-dir/structured.json", writer);
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_structured_output_yaml() {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/rules-dir"])
            .data(vec![
                "/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(vec!["none"])
            .output_format(Option::from("yaml"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!("resources/validate/output-dir/structured.yaml", writer);
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_structured_output_payload() {
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(
            COMPLIANT_PAYLOAD.as_bytes(),
        ))));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .payload()
            .show_summary(vec!["none"])
            .output_format(Option::from("json"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!(
            "resources/validate/output-dir/structured-payload.json",
            writer
        );
        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[rstest::rstest]
    #[case("json", "all")]
    #[case("single-line-summary", "none")]
    fn test_structured_output_with_show_summary(#[case] output: &str, #[case] show_summary: &str) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/rules-dir"])
            .data(vec![
                "/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(vec![show_summary])
            .output_format(Option::from(output))
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INTERNAL_FAILURE, status_code);
    }

    #[rstest::rstest]
    #[case("regex_replace.guard")]
    #[case("substring.guard")]
    #[case("json_parse.guard")]
    #[case("string_manipulation.guard")]
    #[case("url_decode.guard")]
    #[case("join.guard")]
    #[case("count.guard")]
    fn test_validate_with_fn_expr_success(#[case] rule: &str) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec![&format!("/functions/rules/{rule}")])
            .data(vec!["/functions/data/template.yaml"])
            .verbose()
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }
}
