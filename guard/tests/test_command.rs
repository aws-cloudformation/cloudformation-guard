// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod test_command_tests {
    use std::io::stdout;
    use cfn_guard::commands::{RULES, TEST, TEST_DATA};
    use cfn_guard::Error;
    use rstest::rstest;
    use cfn_guard::utils::writer::WriteBuffer::Stdout;
    use cfn_guard::utils::writer::Writer;
    use crate::utils::{get_full_path_for_resource_file, cfn_guard_test_command};

    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_test_data_file_with_shorthand_reference(#[case] file_type: &str) -> Result<(), Error> {
        let test_data_arg = get_full_path_for_resource_file(&format!(
            "resources/test-command/data-dir/s3_bucket_logging_enabled_tests.{}",
            file_type
        ));
        let rule_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_logging_enabled.guard",
        );
        let data_option = format!("-{}", TEST_DATA.1);
        let rules_option = format!("-{}", RULES.1);

        let args = vec![TEST, &data_option, &test_data_arg, &rules_option, &rule_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(0, status_code);

        Ok(())
    }

    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_test_data_file(#[case] file_type: &str) -> Result<(), Error> {
        let test_data_arg = get_full_path_for_resource_file(&format!(
            "resources/test-command/data-dir/s3_bucket_server_side_encryption_enabled.{}",
            file_type
        ));
        let rule_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        );
        let data_option = format!("-{}", TEST_DATA.1);
        let rules_option = format!("-{}", RULES.1);

        let args = vec![TEST, &data_option, &test_data_arg, &rules_option, &rule_arg];

        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = cfn_guard_test_command(args, &mut writer);
        assert_eq!(0, status_code);

        Ok(())
    }
}
