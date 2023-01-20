// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod validate_command_tests {
    use std::io::stdout;
    use cfn_guard;
    use cfn_guard::commands::validate::Validate;
    use cfn_guard::commands::{DATA, INPUT_PARAMETERS, RULES, VALIDATE, SHOW_SUMMARY};
    use cfn_guard::utils::writer::{Writer, WriteBuffer::Stdout, WriteBuffer::Vec as WBVec};
    use indoc::indoc;
    use crate::{assert_output_from_file_eq, assert_output_from_str_eq};
    use crate::utils::{get_full_path_for_resource_file, cfn_guard_test_command};


    #[test]
    fn test_single_data_file_single_rules_file_compliant() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(0, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_compliant_verbose() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let show_summary_arg = "all";

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let show_summary_option = format!("-{}", SHOW_SUMMARY.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg,
                        &show_summary_option, &show_summary_arg];

        let mut writer = Writer::new(WBVec(vec![]));
        let status_code = cfn_guard_test_command(
            args,
            &mut writer
        );

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
    fn test_single_data_file_single_rules_file() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_verbose() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let show_summary_arg = "all";

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let show_summary_option = format!("-{}", SHOW_SUMMARY.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg,
                        &show_summary_option, &show_summary_arg];

        let mut writer = Writer::new(WBVec(vec![]));
        let status_code = cfn_guard_test_command(
            args,
            &mut writer
        );

        assert_eq!(5, status_code);
        assert_output_from_file_eq!(
            "resources/validate/output-dir/test_single_data_file_single_rules_file_verbose.out",
            writer
        )
    }

    #[test]
    fn test_data_dir_single_rules_file() {
        let data_arg = get_full_path_for_resource_file("resources/validate/data-dir/");
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_single_data_file_rules_dir() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg = get_full_path_for_resource_file("resources/validate/rules-dir/");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_data_dir_rules_dir() {
        let data_arg = get_full_path_for_resource_file("resources/validate/data-dir/");
        let rules_arg = get_full_path_for_resource_file("resources/validate/rules-dir/");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_multiple_data_files_single_rules_file() {
        let data_arg1 = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let data_arg2 = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_single_data_file_multiple_rules_files() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg1 = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let rules_arg2 = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_data_file_and_dir_single_rules_file() {
        let data_arg1 = get_full_path_for_resource_file(
            "resources/validate/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let data_arg2 = get_full_path_for_resource_file("resources/validate/data-dir/");
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_single_data_file_rules_file_and_dir() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg1 = get_full_path_for_resource_file("resources/validate/rules-dir/");
        let rules_arg2 = get_full_path_for_resource_file(
            "resources/validate/s3_bucket_server_side_encryption_enabled_2.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_data_dir_rules_file_and_dir() {
        let data_arg = get_full_path_for_resource_file("resources/validate/data-dir/");
        let rules_arg1 = get_full_path_for_resource_file("resources/validate/rules-dir/");
        let rules_arg2 = get_full_path_for_resource_file(
            "resources/validate/s3_bucket_server_side_encryption_enabled_2.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_data_file_and_dir_rules_dir() {
        let data_arg1 = get_full_path_for_resource_file(
            "resources/validate/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let data_arg2 = get_full_path_for_resource_file("resources/validate/data-dir/");
        let rules_arg = get_full_path_for_resource_file("resources/validate/rules-dir/");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_data_file_and_dir_rules_file_and_dir() {
        let data_arg1 = get_full_path_for_resource_file(
            "resources/validate/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let data_arg2 = get_full_path_for_resource_file("resources/validate/data-dir/");
        let rules_arg1 = get_full_path_for_resource_file("resources/validate/rules-dir/");
        let rules_arg2 = get_full_path_for_resource_file(
            "resources/validate/s3_bucket_server_side_encryption_enabled_2.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_single_input_parameters_file() {
        let data_arg = get_full_path_for_resource_file("resources/validate/db_resource.yaml");
        let input_parameters_arg =
            get_full_path_for_resource_file("resources/validate/input-parameters-dir/db_params.yaml");
        let rules_arg =
            get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_multiple_input_parameters_files() {
        let data_arg = get_full_path_for_resource_file("resources/validate/db_resource.yaml");
        let input_parameters_arg1 =
            get_full_path_for_resource_file("resources/validate/input-parameters-dir/db_params.yaml");
        let input_parameters_arg2 = get_full_path_for_resource_file(
            "resources/validate/input-parameters-dir/db_metadata.yaml",
        );
        let rules_arg =
            get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg1,
            &input_parameters_option,
            &input_parameters_arg2,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(0, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_input_parameters_dir() {
        let data_arg = get_full_path_for_resource_file("resources/validate/db_resource.yaml");
        let input_parameters_arg =
            get_full_path_for_resource_file("resources/validate/input-parameters-dir/");
        let rules_arg =
            get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(0, status_code);
    }

    #[test]
    fn test_single_data_file_malformed_rules_file() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg = get_full_path_for_resource_file("resources/validate/malformed-rule.guard");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        // -1 status code equates to Error being thrown
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(-1, status_code);
    }

    #[test]
    fn test_malformed_data_file_single_rules_file() {
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/malformed-template.yaml"
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/s3_bucket_server_side_encryption_enabled_2.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        // -1 status code equates to Error being thrown
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(-1, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_malformed_input_parameters_file() {
        let data_arg = get_full_path_for_resource_file("resources/validate/db_resource.yaml");
        let input_parameters_arg =
            get_full_path_for_resource_file("resources/validate/malformed-template.yaml");
        let rules_arg =
            get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];

        // -1 status code equates to Error being thrown
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(-1, status_code);
    }

    #[test]
    fn test_single_data_file_blank_rules_file() {
        // The parsing exits with status code 5 = FAIL for allowing other rules to get evaluated even when one of them fails to get parsed
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/blank-rule.guard"
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_single_data_file_blank_and_valid_rules_file() {
        // The parsing exits with status code 5 = FAIL for allowing other rules to get evaluated even when one of them fails to get parsed
        let data_arg = get_full_path_for_resource_file(
            "resources/validate/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg1 = get_full_path_for_resource_file("resources/validate/blank-rule.guard");
        let rules_arg2 = get_full_path_for_resource_file(
            "resources/validate/s3_bucket_server_side_encryption_enabled_2.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(5, status_code);
    }

    #[test]
    fn test_blank_data_file_single_rules_file() {
        let data_arg = get_full_path_for_resource_file("resources/validate/blank-template.yaml");
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/s3_bucket_server_side_encryption_enabled_2.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];

        // -1 status code equates to Error being thrown
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(-1, status_code);
    }

    #[test]
    fn test_blank_and_valid_data_file_single_rules_file() {
        let data_arg1 = get_full_path_for_resource_file("resources/validate/blank-template.yaml");
        let data_arg2 = get_full_path_for_resource_file(
            "resources/validate/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/s3_bucket_server_side_encryption_enabled_2.guard",
        );

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];

        // -1 status code equates to Error being thrown
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(-1, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_blank_input_parameters_file() {
        let data_arg = get_full_path_for_resource_file("resources/validate/db_resource.yaml");
        let input_parameters_arg =
            get_full_path_for_resource_file("resources/validate/blank-template.yaml");
        let rules_arg =
            get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];

        // -1 status code equates to Error being thrown
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(-1, status_code);
    }

    #[test]
    fn test_single_data_file_single_rules_file_blank_and_valid_input_parameters_file() {
        let data_arg = get_full_path_for_resource_file("resources/validate/db_resource.yaml");
        let input_parameters_arg1 =
            get_full_path_for_resource_file("resources/validate/blank-template.yaml");
        let input_parameters_arg2 =
            get_full_path_for_resource_file("resources/validate/input-parameters-dir/db_params.yaml");
        let rules_arg =
            get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard");

        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg1,
            &input_parameters_option,
            &input_parameters_arg2,
        ];

        // -1 status code equates to Error being thrown
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(-1, status_code);
    }

    #[test]
    fn test_single_data_file_single_rule_file_when_either_data_or_rule_file_dne() {
        for arg in vec![
            (
                get_full_path_for_resource_file("fake_file.yaml"),
                get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard"),
            ),
            (
                get_full_path_for_resource_file("resources/validate/db_resource.yaml"),
                get_full_path_for_resource_file("fake_file.guard"),
            ),
        ] {
            let data_option = &format!("-{}", DATA.1);
            let rules_option = &format!("-{}", RULES.1);
            let args = vec![VALIDATE, data_option, &arg.0, rules_option, &arg.1];

            // -1 status code equates to Error being thrown
            let mut writer = Writer::new(Stdout(stdout()));
            let status_code = cfn_guard_test_command(args, &mut writer);
            assert_eq!(-1, status_code);
        }
    }
}
