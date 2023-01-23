// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod validate_command_tests {
    use std::io::stdout;

    use indoc::indoc;
    use rstest::rstest;
    use strip_ansi_escapes;

    use cfn_guard;
    use cfn_guard::commands::validate::Validate;
    use cfn_guard::commands::{
        ALPHABETICAL, DATA, INPUT_PARAMETERS, LAST_MODIFIED, OUTPUT_FORMAT, PAYLOAD,
        PREVIOUS_ENGINE, PRINT_JSON, RULES, SHOW_CLAUSE_FAILURES, SHOW_SUMMARY, VALIDATE, VERBOSE,
    };
    use cfn_guard::utils::writer::{WriteBuffer::Stdout, WriteBuffer::Vec as WBVec, Writer};

    use crate::utils::{
        compare_write_buffer_with_file, compare_write_buffer_with_string,
        get_full_path_for_resource_file, CommandTestRunner,
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
            if self.payload.is_some() {
                panic!("data argument conflicts with the payload argument")
            }

            self.data = args;
            self
        }

        fn rules(&'args mut self, args: Vec<&'args str>) -> &'args mut ValidateTestRunner {
            if self.payload.is_some() {
                panic!("data argument conflicts with the payload argument")
            }

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
    #[case(vec!["data-dir/s3-public-read-prohibited-template-compliant.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], 0)]
    #[case(vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], 5)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["malformed-rule.guard"], -1)]
    #[case(vec!["malformed-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], -1)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["blank-rule.guard"], 5)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard", "blank-rule.guard"], 5 )]
    #[case(vec!["blank-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], -1)]
    #[case(vec!["blank-template.yaml", "s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], -1)]
    #[case(vec!["dne.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], -1)]
    #[case(vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"], vec!["dne.guard"], -1)]
    fn test_single_data_file_single_rules_file(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] expected_status_code: i32,
    ) {
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer);

        assert_eq!(expected_status_code, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_compliant_verbose() {
        let mut writer = Writer::new(WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .data(vec![
                "data-dir/s3-public-read-prohibited-template-compliant.yaml",
            ])
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer);

        let expected_output = indoc! {
            r#"s3-public-read-prohibited-template-compliant.yaml Status = PASS
               PASS rules
               s3_bucket_public_read_prohibited.guard/S3_BUCKET_PUBLIC_READ_PROHIBITED    PASS
               ---
               "#
        };

        assert_eq!(0, status_code);
        assert_output_from_str_eq!(expected_output, writer)
    }

    #[test]
    fn test_single_data_file_single_rules_file_verbose() {
        let mut writer = Writer::new(WBVec(vec![]));
        let status_code = ValidateTestRunner::default()
            .data(vec![
                "data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer);

        assert_eq!(5, status_code);
        assert_output_from_file_eq!(
            "resources/validate/output-dir/test_single_data_file_single_rules_file_verbose.out",
            writer
        )
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
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer);

        assert_eq!(0, status_code);
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
    #[case(vec!["data-dir/", "s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["rules-dir/", "s3_bucket_server_side_encryption_enabled_2.guard"])]
    #[case(vec!["data-dir/"], vec!["rules-dir/", "s3_bucket_server_side_encryption_enabled_2.guard"])]
    #[case(vec!["data-dir/", "s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["rules-dir/"])]
    #[case(vec!["data-dir/", "s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["rules-dir/", "s3_bucket_server_side_encryption_enabled_2.guard"])]
    fn test_combinations_of_rules_and_data_non_compliant(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
    ) {
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .run(&mut writer);

        assert_eq!(5, status_code);
    }

    #[rstest::rstest]
    #[case(vec!["db_resource.yaml"], vec!["db_param_port_rule.guard"], vec!["input-parameters-dir/db_params.yaml"], 5)]
    #[case(vec!["db_resource.yaml"], vec!["db_param_port_rule.guard"], vec!["input-parameters-dir/db_params.yaml", "input-parameters-dir/db_metadata.yaml"], 0)]
    #[case(vec!["db_resource.yaml"], vec!["db_param_port_rule.guard"], vec!["input-parameters-dir/"], 0)]
    #[case(vec!["db_resource.yaml"], vec!["db_param_port_rule.guard"], vec!["input-parameters-dir/malformed-template.yaml"], -1)]
    #[case(vec!["db_resource.yaml"], vec!["db_param_port_rule.guard"], vec!["input-parameters-dir/blank-template.yaml"], -1)]
    #[case(vec!["db_resource.yaml"], vec!["db_param_port_rule.guard"], vec!["input-parameters-dir/blank-template.yaml", "input-parameters-dir/db_params.yaml"], -1)]
    fn test_combinations_of_rules_data_and_input_params_files(
        #[case] data_arg: Vec<&str>,
        #[case] rules_arg: Vec<&str>,
        #[case] input_params_arg: Vec<&str>,
        #[case] expected_status_code: i32,
    ) {
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = ValidateTestRunner::default()
            .data(data_arg)
            .rules(rules_arg)
            .input_parameters(input_params_arg)
            .run(&mut writer);

        assert_eq!(expected_status_code, status_code);
    }
}
