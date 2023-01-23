// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod test_command_tests {
    use crate::utils::{
        cfn_guard_test_command, get_full_path_for_resource_file, CommandTestRunner,
    };
    use cfn_guard::commands::{
        ALPHABETICAL, DIRECTORY, LAST_MODIFIED, PREVIOUS_ENGINE, RULES, RULES_AND_TEST_FILE,
        RULES_FILE, TEST, TEST_DATA, VERBOSE,
    };
    use cfn_guard::utils::writer::WriteBuffer::Stdout;
    use cfn_guard::utils::writer::Writer;
    use cfn_guard::Error;
    use rstest::rstest;
    use std::io::stdout;

    #[derive(Default)]
    struct TestCommandTestRunner<'args> {
        test_data: Option<&'args str>,
        rules: Option<&'args str>,
        directory: Option<&'args str>,
        rules_and_test_file: Option<&'args str>,
        directory_only: bool,
        previous_engine: bool,
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

        fn rules_and_test_file(
            &'args mut self,
            arg: Option<&'args str>,
        ) -> &'args mut TestCommandTestRunner {
            if self.directory_only {
                panic!("cannot have rules_and_test_file flag present if directory_only is set to true!")
            }

            self.rules_and_test_file = arg;
            self
        }

        fn directory_only(&'args mut self, arg: bool) -> &'args mut TestCommandTestRunner {
            if self.rules_and_test_file.is_some() && arg {
                panic!("cannot have directory_only set to true if rules_and_test_file is present!")
            }

            self.directory_only = arg;
            self
        }

        fn previous_engine(&'args mut self, arg: bool) -> &'args mut TestCommandTestRunner {
            self.previous_engine = arg;
            self
        }

        fn alphabetical(&'args mut self, arg: bool) -> &'args mut TestCommandTestRunner {
            if self.last_modified {
                panic!("alphabetical and last modified are conflicting")
            }

            self.alphabetical = arg;
            self
        }

        fn last_modified(&'args mut self, arg: bool) -> &'args mut TestCommandTestRunner {
            if self.alphabetical {
                panic!("alphabetical and last modified are conflicting")
            }

            self.last_modified = arg;
            self
        }

        fn verbose(&'args mut self, arg: bool) -> &'args mut TestCommandTestRunner {
            self.verbose = arg;
            self
        }
    }

    impl<'args> CommandTestRunner for TestCommandTestRunner<'args> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![String::from(TEST)];

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

            if self.directory_only {}

            if self.previous_engine {
                args.push(format!("-{}", PREVIOUS_ENGINE.1));
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
            args
        }
    }

    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_test_data_file_with_shorthand_reference(#[case] file_type: &str) -> Result<(), Error> {
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(&format!(
                "resources/test-command/data-dir/s3_bucket_logging_enabled_tests.{}",
                file_type
            )))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .run(&mut writer);

        assert_eq!(0, status_code);

        Ok(())
    }

    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_test_data_file(#[case] file_type: &str) -> Result<(), Error> {
        let mut writer = Writer::new(Stdout(stdout()));
        let status_code = TestCommandTestRunner::default()
            .test_data(Some(&format!(
                "resources/test-command/data-dir/s3_bucket_server_side_encryption_enabled.{}",
                file_type
            )))
            .rules(Some(
                "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
            ))
            .run(&mut writer);

        assert_eq!(0, status_code);

        Ok(())
    }
}
