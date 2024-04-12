// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub(crate) mod utils;
#[cfg(test)]
mod validate_tests {
    use indoc::indoc;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;

    use cfn_guard::commands::{
        ALPHABETICAL, DATA, INPUT_PARAMETERS, LAST_MODIFIED, OUTPUT_FORMAT, PAYLOAD, PRINT_JSON,
        RULES, SHOW_SUMMARY, STRUCTURED, VERBOSE,
    };
    use cfn_guard::utils::reader::ReadBuffer::Cursor as ReadCursor;
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};

    use crate::utils::{
        get_full_path_for_resource_file, sanitize_junit_writer, sanitize_sarif_writer, Command,
        CommandTestRunner, StatusCode,
    };
    use crate::{assert_output_from_file_eq, assert_output_from_str_eq, utils};
    #[derive(Default)]
    struct ValidateTestRunner<'args> {
        data: Vec<&'args str>,
        rules: Vec<&'args str>,
        show_summary: Vec<&'args str>,
        input_parameters: Vec<&'args str>,
        output_format: Option<&'args str>,
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

        #[allow(dead_code)]
        fn alphabetical(&'args mut self) -> &'args mut ValidateTestRunner {
            self.alphabetical = true;
            self
        }

        #[allow(dead_code)]
        fn last_modified(&'args mut self) -> &'args mut ValidateTestRunner {
            self.last_modified = true;
            self
        }

        fn verbose(&'args mut self) -> &'args mut ValidateTestRunner {
            self.verbose = true;
            self
        }

        #[allow(dead_code)]
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
            let mut args = vec![Command::Validate.to_string()];

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

    const COMPLIANT_PAYLOAD: &str = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"TestInstance\"" ]}"#;

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
        StatusCode::VALIDATION_ERROR
    )]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["malformed-rule.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["malformed-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["blank-rule.guard"], StatusCode::SUCCESS)]
    #[case(
        vec!["s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["s3_bucket_server_side_encryption_enabled_2.guard", "blank-rule.guard"],
        StatusCode::VALIDATION_ERROR
    )]
    #[case(vec!["blank-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(
        vec!["blank-template.yaml", "s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["dne.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"], vec!["dne.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["blank.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["comments.guard"], StatusCode::SUCCESS)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["comments.guard"], StatusCode::SUCCESS)]
    fn test_single_data_file_single_rules_file_status(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::default();
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
    }

    #[rstest::rstest]
    #[case("SSEAlgorithm: {{CRASH}}")]
    #[case("~:")]
    #[case("[1, 2, 3]: foo")]
    #[case("1: foo")]
    #[case("1.0: foo")]
    fn test_graceful_handling_when_yaml_file_has_non_string_type_key(#[case] input: &str) {
        let bytes = input.as_bytes();
        let mut reader = Reader::new(ReadCursor(Cursor::new(bytes.to_vec())));
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["s3_bucket_server_side_encryption_enabled_2.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INTERNAL_FAILURE, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_compliant() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![]));
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
        StatusCode::VALIDATION_ERROR
    )]
    #[case(
        vec!["template_where_resources_isnt_root.json"],
        vec!["workshop.guard"],
        "resources/validate/output-dir/failing_template_without_resources_at_root.out",
        StatusCode::VALIDATION_ERROR
    )]
    #[case(
        vec!["failing_template_with_slash_in_key.yaml"],
        vec!["rules-dir/s3_bucket_server_side_encryption_enabled.guard"],
        "resources/validate/output-dir/failing_template_with_slash_in_key.out",
        StatusCode::VALIDATION_ERROR
    )]
    fn test_single_data_file_single_rules_file_verbose(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] expected_output: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut writer = Writer::new(WBVec(vec![]));
        let mut reader = Reader::default();
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
        StatusCode::VALIDATION_ERROR
    )]
    #[case(
        vec!["data-dir/advanced_regex_negative_lookbehind_non_compliant.yaml"],
        vec!["rules-dir/advanced_regex_negative_lookbehind_rule.guard"],
        "resources/validate/output-dir/advanced_regex_negative_lookbehind_non_compliant.out",
        StatusCode::VALIDATION_ERROR
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
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![]));
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
        let mut reader = Reader::default();
        let mut writer = Writer::default();
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
        let mut reader = Reader::default();
        let mut writer = Writer::default();
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    #[test]
    fn test_updated_summary_output() {
        let mut writer = Writer::new(WBVec(vec![]));
        let mut reader = Reader::default();
        let status_code = ValidateTestRunner::default()
            .data(vec!["data-dir"])
            .rules(vec!["rules-dir"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        assert_output_from_file_eq!(
            "resources/validate/output-dir/rules_dir_against_data_dir.out",
            writer
        )
    }

    #[rstest::rstest]
    #[case(
        vec!["db_resource.yaml"],
        vec!["db_param_port_rule.guard"],
        vec!["input-parameters-dir/db_params.yaml"],
        StatusCode::VALIDATION_ERROR
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
        let mut reader = Reader::default();
        let mut writer = Writer::default();
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
        let mut writer = Writer::default();
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
        let mut writer = Writer::new(WBVec(vec![]));
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
        let mut writer = Writer::new(WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose()
            .run(&mut writer, &mut reader);

        assert_output_from_file_eq!(
            "resources/validate/output-dir/payload_verbose_non_compliant.out",
            writer
        );
        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    #[test]
    fn test_payload_verbose_yaml_compliant() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let mut writer = Writer::new(WBVec(vec![]));
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
    fn test_with_payload_flag() {
        let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"TestInstance\"" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::default();
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_with_payload_failing_type_block() {
        let payload = r#"{"data": [ "{}" ], "rules" : [ "d1z::Y\n\t\tm<0m<03333333" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::default();
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INTERNAL_FAILURE, status_code);
    }

    #[test]
    fn test_with_payload_flag_fail() {
        let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"SomeRandomString\"" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::new(WBVec(vec![]));
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

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        assert_eq!(expected, result);
    }

    #[rstest::rstest]
    #[case("yaml")]
    #[case("json")]
    #[case("junit")]
    #[case("sarif")]
    fn test_structured_output(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/rules-dir"])
            .data(vec![
                "/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(vec!["none"])
            .output_format(Option::from(output))
            .structured()
            .run(&mut writer, &mut reader);

        let writer = if output == "junit" {
            sanitize_junit_writer(writer)
        } else if output == "sarif" {
            sanitize_sarif_writer(writer)
        } else {
            writer
        };

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        assert_output_from_file_eq!(
            &format!("resources/validate/output-dir/structured.{output}"),
            writer
        );
    }

    #[test]
    fn test_structured_output_payload() {
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(
            COMPLIANT_PAYLOAD.as_bytes(),
        ))));
        let mut writer = Writer::new(WBVec(vec![]));

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
    #[case("json", "pass")]
    #[case("json", "fail")]
    #[case("json", "skip")]
    #[case("yaml", "all")]
    #[case("yaml", "pass")]
    #[case("yaml", "fail")]
    #[case("yaml", "skip")]
    #[case("junit", "all")]
    #[case("junit", "pass")]
    #[case("junit", "fail")]
    #[case("junit", "skip")]
    #[case("sarif", "all")]
    #[case("sarif", "pass")]
    #[case("sarif", "fail")]
    #[case("sarif", "skip")]
    #[case("single-line-summary", "none")]
    #[case("single-line-summary", "all")]
    #[case("single-line-summary", "skip")]
    #[case("single-line-summary", "pass")]
    fn test_structured_output_with_show_summary(#[case] output: &str, #[case] show_summary: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

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
    #[case("junit")]
    #[case("sarif")]
    fn test_structured_outputs_fail_without_structured_flag(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::default();
        let status_code = ValidateTestRunner::default()
            .rules(vec!["/rules-dir"])
            .data(vec![
                "/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(vec!["none"])
            .output_format(Option::from(output))
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
    #[case("converters.guard")]
    #[case("complex_rules.guard")]
    fn test_validate_with_fn_expr_success(#[case] rule: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec![&format!("/functions/rules/{rule}")])
            .data(vec!["/functions/data/template.yaml"])
            .verbose()
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    #[test]
    fn test_validate_with_failing_count_and_compare_output() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/count_with_message.guard"])
            .data(vec!["/functions/data/template.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        assert_output_from_file_eq!(
            "resources/validate/functions/output/failing_count_show_summary_all.out",
            writer
        );
    }

    #[test]
    fn test_validate_with_failing_complex_rule() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/failing_complex_rule.guard"])
            .data(vec!["/functions/data/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        assert_output_from_file_eq!(
            "resources/validate/functions/output/failing_complex_rule.out",
            writer
        );
    }

    #[test]
    fn test_validate_with_failing_join_and_compare_output() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![]));

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/join_with_message.guard"])
            .data(vec!["/functions/data/template.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        assert_output_from_file_eq!(
            "resources/validate/functions/output/failing_join_show_summary_all.out",
            writer
        );
    }

    #[rstest::rstest]
    #[case("single-line-summary", vec!["pass", "fail"])]
    #[case("single-line-summary", vec!["skip", "fail"])]
    #[case("single-line-summary", vec!["skip", "pass"])]
    fn test_validate_with_show_summary_combinations(
        #[case] output: &str,
        #[case] show_summary: Vec<&str>,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/rules-dir"])
            .data(vec![
                "/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(show_summary)
            .output_format(Option::from(output))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }
}
