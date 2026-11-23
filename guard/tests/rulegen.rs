// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub(crate) mod utils;

#[cfg(test)]
mod rulegen_tests {
    use crate::assert_output_from_file_eq;
    use cfn_guard::commands::{OUTPUT, TEMPLATE};
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
    use pretty_assertions::assert_eq;

    use crate::utils::{get_full_path_for_resource_file, Command, CommandTestRunner, StatusCode};

    // The round trip -- rules generated from every template under `resources` evaluate PASS against
    // the template they came from, and are exactly the rules the template calls for -- is
    // `src/rules/rulegen_round_trip_tests.rs`. It reads each template through the loader `rulegen`
    // reads with, which is crate-private, so it cannot be here; what is here is only what needs the
    // command's argument parsing.

    #[derive(Default)]
    struct RulegenTestRunner<'args> {
        template: Option<&'args str>,
        output: Option<&'args str>,
    }

    impl<'args> RulegenTestRunner<'args> {
        fn template(&'args mut self, arg: Option<&'args str>) -> &'args mut RulegenTestRunner {
            self.template = arg;
            self
        }

        #[allow(dead_code)]
        fn output(&'args mut self, arg: Option<&'args str>) -> &'args mut RulegenTestRunner {
            self.output = arg;
            self
        }
    }

    impl<'args> CommandTestRunner for RulegenTestRunner<'args> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![Command::Rulegen.to_string()];

            if self.template.is_some() {
                args.push(format!("-{}", TEMPLATE.1));
                args.push(get_full_path_for_resource_file(self.template.unwrap()));
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
        Some("resources/rulegen/data-dir/s3-public-read-prohibited-template-compliant.json"),
        "resources/rulegen/output-dir/test_rulegen_from_template.out",
        StatusCode::SUCCESS
    )]
    #[case(
        Some("resources/rulegen/data-dir/s3-public-read-prohibited-template-compliant.yaml"),
        "resources/rulegen/output-dir/test_rulegen_from_template.out",
        StatusCode::SUCCESS
    )]
    fn test_rulegen_from_template(
        #[case] template_arg: Option<&str>,
        #[case] expected_output_file_path: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = RulegenTestRunner::default()
            .template(template_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_file_eq!(expected_output_file_path, writer)
    }

    /// A JSON template that is not JSON is refused with the JSON reader's line and column.
    ///
    /// `rulegen` reads its template through the loader `validate` uses, so the same missing comma
    /// gets the same refusal: libyaml's text and position, which describe the stop in YAML's terms,
    /// and the JSON reader's line and column after them, since that reader read as far. The exit code
    /// is the one a template that cannot be read already had.
    #[test]
    fn a_json_template_missing_a_comma_is_refused_with_the_json_readers_position() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = RulegenTestRunner::default()
            .template(Some(
                "resources/rulegen/data-dir/missing-comma-template.json",
            ))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            err.contains("Unable to read the template")
                && err.contains("missing-comma-template.json")
                && err.contains("did not find expected ',' or '}' at L:5,C:7")
                && err.contains("Read as JSON as well, the text fails with")
                && err.contains("line 5 column 7"),
            "the refusal names the template, libyaml's position and the JSON reader's:\n{}",
            err
        );
    }
}
