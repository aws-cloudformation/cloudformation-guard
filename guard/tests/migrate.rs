// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod migrate_tests {
    use std::io::stdout;

    use rstest::rstest;

    use crate::assert_output_from_file_eq;
    use cfn_guard::commands::{MIGRATE, OUTPUT, RULES};
    use cfn_guard::utils::writer::{WriteBuffer::Stdout, WriteBuffer::Vec as WBVec, Writer};
    use cfn_guard::Error;

    use crate::utils::{get_full_path_for_resource_file, CommandTestRunner, StatusCode};

    #[derive(Default)]
    struct MigrateTestRunner<'args> {
        rules: Option<&'args str>,
        output: Option<&'args str>,
    }

    impl<'args> MigrateTestRunner<'args> {
        fn rules(&'args mut self, arg: Option<&'args str>) -> &'args mut MigrateTestRunner {
            self.rules = arg;
            self
        }

        fn output(&'args mut self, arg: Option<&'args str>) -> &'args mut MigrateTestRunner {
            self.output = arg;
            self
        }
    }

    impl<'args> CommandTestRunner for MigrateTestRunner<'args> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![String::from(MIGRATE)];

            if self.rules.is_some() {
                args.push(format!("-{}", RULES.1));
                args.push(get_full_path_for_resource_file(self.rules.unwrap()));
            }

            if self.output.is_some() {
                args.push(format!("-{}", OUTPUT.1));
                args.push(get_full_path_for_resource_file(self.output.unwrap()))
            }

            args
        }
    }

    #[rstest::rstest]
    #[case(
        Some("resources/migrate/rules-dir/rule_1dot0.guard"),
        "resources/migrate/output-dir/test_migrate_rule.guard",
        StatusCode::SUCCESS
    )]
    fn test_migrate_rule(
        #[case] rules_arg: Option<&str>,
        #[case] expected_output_file_path: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut writer = Writer::new(WBVec(vec![]));
        let status_code = MigrateTestRunner::default()
            .rules(rules_arg)
            .run(&mut writer);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_file_eq!(expected_output_file_path, writer)
    }
}
