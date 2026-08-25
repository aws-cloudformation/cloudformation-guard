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
    // A rule whose only check compares against a reference that resolved to no values must
    // not reach a successful exit. It used to: the comparison reported SKIP, the file status
    // was SKIP, and the process exited 0 having enforced nothing. Exit code rather than
    // reported status is the assertion that matters here, because 0 is what a CI gate reads,
    // and SKIP and PASS are indistinguishable from outside the process.
    // These fixtures sit at the resources/validate root rather than in data-dir/ and
    // rules-dir/, because test_updated_summary_output evaluates every rules file in
    // rules-dir/ against every data file in data-dir/ and compares the result to a
    // checked-in golden output.
    #[case(
        vec!["bucket-with-no-kms-keys-template.yaml"],
        vec!["denied_names_from_empty_reference.guard"],
        StatusCode::VALIDATION_ERROR
    )]
    // The same comparison with the possibly-empty reference declared as a `when` guard. The
    // condition fails, the rule does not apply, and exiting 0 is correct. Without this row
    // the case above is also satisfied by failing every ruleset that mentions an empty
    // reference, which would leave no way to express a permissibly-empty denylist.
    #[case(
        vec!["bucket-with-no-kms-keys-template.yaml"],
        vec!["denied_names_guarded_by_not_empty.guard"],
        StatusCode::SUCCESS
    )]
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

    /// A data file with no document in it -- nothing but comments -- used to abort the process at
    /// `guard/src/rules/libyaml/event.rs` with `not implemented`, exit 101. An empty file and a
    /// whitespace-only file were already reported as empty, so this asserts the message as well as
    /// the exit code: the requirement is that a file holding no document is reported the same way
    /// one holding no bytes is, not merely that it fails somehow.
    #[rstest::rstest]
    #[case::a_single_comment_line("# just a comment\n")]
    #[case::a_comment_with_no_trailing_newline("# just a comment")]
    #[case::comments_separated_by_blank_lines("\n# a\n\n#  b\n")]
    #[case::a_fully_commented_out_template(
        "# Resources:\n#   B:\n#     Properties:\n#       Encrypted: true\n"
    )]
    fn test_a_data_file_with_no_document_is_reported_as_empty(#[case] input: &str) {
        let bytes = input.as_bytes();
        let mut reader = Reader::new(ReadCursor(Cursor::new(bytes.to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["s3_bucket_server_side_encryption_enabled_2.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::INTERNAL_FAILURE, status_code);
        assert_eq!(
            "Error occurred Parser Error when parsing `Unable to parse a template from data file: STDIN is empty`\n",
            writer.err_to_stripped().expect("failed to read stderr")
        );
    }

    /// A gate written `== true` has to fire for every spelling YAML makes boolean, because when it
    /// does not fire the body never runs and the process exits 0 having checked nothing. Against a
    /// bucket with `Encrypted: false`, `PublicAccess: true` exited 19 and caught the violation
    /// while `PublicAccess: True` and `TRUE` exited 0 and left it unchecked. `yes` and `on` exited
    /// 19, so the loader was reading a YAML 1.1 vocabulary with the capitalised spellings missing
    /// out of it.
    ///
    /// The false spellings are here for the same reason the true ones are. Without them the true
    /// half is also satisfied by reading every spelling as true, which would fire the gate on
    /// `PublicAccess: false` and fail a compliant template. Exit code is the assertion that
    /// matters, because 0 is what a CI gate reads and a gate that never fires is indistinguishable
    /// in the output from one that correctly did not apply.
    #[rstest::rstest]
    #[case::lowercase_true("true", StatusCode::VALIDATION_ERROR)]
    #[case::capitalized_true("True", StatusCode::VALIDATION_ERROR)]
    #[case::uppercase_true("TRUE", StatusCode::VALIDATION_ERROR)]
    #[case::lowercase_yes("yes", StatusCode::VALIDATION_ERROR)]
    #[case::capitalized_yes("Yes", StatusCode::VALIDATION_ERROR)]
    #[case::uppercase_yes("YES", StatusCode::VALIDATION_ERROR)]
    #[case::lowercase_on("on", StatusCode::VALIDATION_ERROR)]
    #[case::capitalized_on("On", StatusCode::VALIDATION_ERROR)]
    #[case::uppercase_on("ON", StatusCode::VALIDATION_ERROR)]
    #[case::lowercase_y("y", StatusCode::VALIDATION_ERROR)]
    #[case::uppercase_y("Y", StatusCode::VALIDATION_ERROR)]
    #[case::lowercase_false("false", StatusCode::SUCCESS)]
    #[case::capitalized_false("False", StatusCode::SUCCESS)]
    #[case::uppercase_false("FALSE", StatusCode::SUCCESS)]
    #[case::lowercase_no("no", StatusCode::SUCCESS)]
    #[case::capitalized_no("No", StatusCode::SUCCESS)]
    #[case::uppercase_no("NO", StatusCode::SUCCESS)]
    #[case::lowercase_off("off", StatusCode::SUCCESS)]
    #[case::capitalized_off("Off", StatusCode::SUCCESS)]
    #[case::uppercase_off("OFF", StatusCode::SUCCESS)]
    #[case::lowercase_n("n", StatusCode::SUCCESS)]
    #[case::uppercase_n("N", StatusCode::SUCCESS)]
    fn test_a_gate_on_a_boolean_fires_for_every_spelling_yaml_makes_boolean(
        #[case] spelling: &str,
        #[case] expected_status_code: i32,
    ) {
        let data = format!(
            indoc! {r#"
                Resources:
                  B:
                    Type: "AWS::S3::Bucket"
                    Properties:
                      PublicAccess: {}
                      Encrypted: false
            "#},
            spelling
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(data.into_bytes())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["public_access_gate_on_encryption.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
    }

    /// The control for the case above, and the reason the set is the 22 spellings rather than
    /// anything that looks like one. A scalar YAML resolves to a string stays a string and stays
    /// incomparable to a boolean, so widening the boolean set does not quietly answer comparisons
    /// that have no answer. Asserting the reported reason and not only the exit code is what
    /// separates this from a clause that failed on the merits.
    #[rstest::rstest]
    #[case::mixed_case_true("tRuE")]
    #[case::a_word_outside_the_set("enabled")]
    fn test_a_non_boolean_string_is_still_not_comparable_to_a_boolean(#[case] spelling: &str) {
        let data = format!(
            indoc! {r#"
                Resources:
                  B:
                    Type: "AWS::S3::Bucket"
                    Properties:
                      PublicAccess: {}
            "#},
            spelling
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(data.into_bytes())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["public_access_equals_true.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("PathAwareValues are not comparable String, bool"),
            "{} was compared to a boolean without reporting the type mismatch:\n{}",
            spelling,
            output
        );
    }

    /// A duplicated key took the last value and said nothing, on any channel. A reviewer reading a
    /// template top-down sees the first value and the tool judges the last, so the document can
    /// present one posture and be evaluated on another with no diagnostic to notice it by.
    ///
    /// The diagnostic names the path and both lines, because a warning that only says a key was
    /// duplicated does not tell anyone which of several thousand lines to look at. It fires once per
    /// duplicated key rather than once per document, which the two-duplicate case below pins.
    #[rstest::rstest]
    #[case::yaml(
        "Resources:\n  B:\n    Properties:\n      Encrypted: false\n      Encrypted: true\n",
        "L:3,C:6",
        "L:4,C:6"
    )]
    #[case::json(
        "{\"Resources\":{\"B\":{\"Properties\":{\"Encrypted\":false,\"Encrypted\":true}}}}",
        "L:0,C:33",
        "L:0,C:51"
    )]
    fn test_a_duplicate_key_is_reported_with_its_path(
        #[case] input: &str,
        #[case] first: &str,
        #[case] repeated: &str,
    ) {
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            format!(
                "Warning: duplicate key /Resources/B/Properties/Encrypted in data file STDIN, \
                 first at {first} and again at {repeated}. The last value is the one evaluated.\n"
            ),
            stderr
        );
    }

    /// The control, and the one that matters more than the positive case. A key name appearing in
    /// two different mappings is ordinary and legal -- nearly every template repeats a property name
    /// across its resources -- so a diagnostic that fired on that would fire on almost everything.
    /// Nothing at all may be written to stderr here.
    #[test]
    fn test_a_key_repeated_across_two_mappings_is_not_reported() {
        let input = indoc! {r#"
            Resources:
              A:
                Properties:
                  Encrypted: true
              B:
                Properties:
                  Encrypted: true
        "#};
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_eq!(
            "",
            writer.err_to_stripped().expect("failed to read stderr"),
            "a key name used in two separate mappings was reported as a duplicate"
        );
    }

    /// Reporting the duplicate must not change the verdict. Which value wins is unchanged, and it is
    /// asserted from both directions so that the exit code alone shows the winner: last-wins means
    /// `false` then `true` passes and `true` then `false` fails. Deciding to reject a duplicate key
    /// outright, which the YAML 1.2 spec allows, would break every template that carries one today
    /// and is a separate change from saying so.
    #[rstest::rstest]
    #[case::last_value_true("false", "true", StatusCode::SUCCESS)]
    #[case::last_value_false("true", "false", StatusCode::VALIDATION_ERROR)]
    fn test_reporting_a_duplicate_key_leaves_the_winning_value_alone(
        #[case] first: &str,
        #[case] second: &str,
        #[case] expected_status_code: i32,
    ) {
        let input = format!(
            indoc! {r#"
                Resources:
                  B:
                    Properties:
                      Encrypted: {}
                      Encrypted: {}
            "#},
            first, second
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.into_bytes())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            expected_status_code, status_code,
            "Encrypted declared {} then {} did not resolve to {}",
            first, second, second
        );
    }

    /// Two different duplicated keys in one document produce two warnings, not one for the document.
    #[test]
    fn test_each_duplicated_key_is_reported_once() {
        let input = indoc! {r#"
            Resources:
              B:
                Properties:
                  Encrypted: false
                  Encrypted: true
                  Public: false
                  Public: true
        "#};
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            2,
            stderr.lines().count(),
            "two duplicated keys reported as:\n{}",
            stderr
        );
        assert!(
            stderr.contains("/Resources/B/Properties/Encrypted")
                && stderr.contains("/Resources/B/Properties/Public"),
            "both duplicated keys should be named:\n{}",
            stderr
        );
    }

    /// A clause that fails because its reference resolved to nothing must say so in the output.
    ///
    /// Exit code alone is not enough, and asserting only the exit code is how this was missed: the
    /// run correctly returned 19 while the console said "Number of non-compliant resources 0" and
    /// the structured output carried `"checks": []` with a null error_message. The explanation was
    /// built, recorded, and discarded by the reporter, so an operator got a failure with no stated
    /// reason -- and docs/CLAUSES.md promised one.
    ///
    /// Both output paths are asserted because they discard messages independently. The structured
    /// reporter walks the record tree, and the console reporter additionally organises findings by
    /// resource, which a clause with nothing to compare cannot be attributed to.
    ///
    /// Parameterized over the data shape as well, because the console reporter is really two: with a
    /// `/Resources` key the CloudFormation-aware one renders the finding, and without one it delegates
    /// to the generic reporter. Only the first was covered here, which is how the generic reporter
    /// kept discarding the explanation after this test started passing -- it collected findings from
    /// `ClauseValueCheck` records only, and a comparison that never ran against a value records its
    /// explanation on the enclosing block instead.
    #[rstest::rstest]
    #[case(
        None,
        "bucket-with-no-kms-keys-template.yaml",
        "denied_names_from_empty_reference.guard"
    )]
    #[case(
        Some("json"),
        "bucket-with-no-kms-keys-template.yaml",
        "denied_names_from_empty_reference.guard"
    )]
    #[case(
        None,
        "flat-document-with-empty-filter.yaml",
        "denied_names_from_empty_reference_flat.guard"
    )]
    #[case(
        Some("json"),
        "flat-document-with-empty-filter.yaml",
        "denied_names_from_empty_reference_flat.guard"
    )]
    fn empty_reference_failure_explains_itself_in_the_output(
        #[case] output_format: Option<&str>,
        #[case] data_file: &str,
        #[case] rules_file: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let mut runner = ValidateTestRunner::default();
        let runner = runner.data(vec![data_file]).rules(vec![rules_file]);
        let status_code = match output_format {
            Some(format) => runner
                .output_format(Some(format))
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader),
            None => runner
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader),
        };

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the clause must still fail; this test is about the explanation, not the verdict"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("resolved to no values"),
            "the {} output for {} did not explain that the reference resolved to no values.\n{}",
            output_format.unwrap_or("console"),
            data_file,
            output
        );
        assert!(
            output.contains("!empty"),
            "the explanation should name the `!empty` guard as the remedy, got:\n{}",
            output
        );
    }

    /// A clause the evaluator cannot answer must not discard the rest of the file.
    ///
    /// `EMPTY` on an integer returned an error, and an error from one rule propagates out of
    /// `eval_rules_file` and aborts the run. So a rules file whose first rule had already reported a
    /// genuine violation exited 255 with nothing printed, instead of 19 with the finding. A gate
    /// keyed on "nonzero" still fails, but one keyed on 19, or one parsing the report, loses the
    /// finding entirely -- and the more rules a file has, the more it loses.
    ///
    /// Asserted on the output as well as the exit code, because the exit code alone was never the
    /// whole problem: the run has to say which rule failed, and an aborted run says nothing at all.
    #[test]
    fn an_incompatible_type_does_not_discard_other_rules() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["volume-with-a-region.yaml"])
            .rules(vec!["empty_on_a_scalar_with_an_unrelated_rule.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the file must report its violations rather than aborting; 255 here means an error \
             escaped one rule and took every other rule's verdict with it"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("unrelated_violation"),
            "the unrelated rule's failure was not reported, which is what the abort used to \
             discard:\n{}",
            output
        );
        assert!(
            output.contains("empty_on_a_scalar"),
            "the unanswerable clause should report its own failure too, not vanish:\n{}",
            output
        );
        assert!(
            output.contains("EMPTY"),
            "the report should name the operation that could not be performed so the author can \
             find the clause:\n{}",
            output
        );
    }

    /// A gate that cannot be evaluated fails its rule instead of disarming the body.
    ///
    /// This is the shape a reviewer found against the first version of the incompatible-type fix, and
    /// it is the failure mode this whole branch exists to remove: `!EMPTY` on a boolean has no answer,
    /// the rule was therefore treated as not applicable, and the violation inside it went unreported
    /// with exit 0. On the merge-base the same file exits 19, because `!EMPTY` on a boolean was
    /// unconditionally true there -- so the gate opened and the body ran. Fixing the boolean clause
    /// without fixing the gate turned a bug that over-reported into one that under-reported.
    ///
    /// Why a status could not express this: `eval_rule` collapses both FAIL and SKIP on a condition to
    /// a rule-level SKIP, since "the condition did not match" is the ordinary gating idiom and must
    /// stay a skip. So an unevaluatable condition travels as an error and is caught at the rule
    /// boundary, which is what makes the rule fail rather than the file abort.
    ///
    /// Asserted on the output as well as the exit code, and on the unrelated rule too: failing closed
    /// is only correct if it does not also take the rest of the file down.
    #[test]
    fn an_unevaluatable_gate_fails_the_rule_closed() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["unevaluatable-gate-template.yaml"])
            .rules(vec!["unevaluatable_gate_guarding_a_violation.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR, status_code,
            "an unevaluatable gate must not report success; exit 0 here means the guarded body was \
             silently skipped"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("guarded"),
            "the rule with the unevaluatable gate should be reported as failing:\n{}",
            output
        );
        assert!(
            output.contains("unrelated_violation"),
            "failing the rule closed must not discard the rest of the file:\n{}",
            output
        );
        assert!(
            output.contains("could not be evaluated"),
            "the report should say the rule failed because its condition could not be evaluated, \
             rather than leaving the reader to guess:\n{}",
            output
        );
        assert!(
            !output.contains("Parameterized Rule"),
            "this rule takes no parameters; the rule-level failure line used to announce every such \
             failure as a parameterized rule, which was true only of the callers that reached it \
             before this branch:\n{}",
            output
        );
    }

    /// An undecidable condition one level in does not silence the rule it gates.
    ///
    /// The single-condition form is `an_unevaluatable_gate_fails_the_rule_closed`. This is the same
    /// hazard reached across a parameterized-rule boundary, and that path was open while the direct
    /// one was closed: the nested `when` converted the undecidable answer to `Status::FAIL`, one
    /// level out a FAIL on a condition is indistinguishable from a condition that was decided and
    /// did not match, and `eval_rule` maps that to a rule-level SKIP. Measured before the fix:
    ///
    ///     merge-base  exit 19   the gate opened, because `!EMPTY` on a boolean was always true
    ///     this branch  exit  0  the rule was reported not applicable, `MustBeTrue` unchecked
    ///
    /// Reported by a reviewer, whose diagnosis named the mechanism exactly. The fix keeps the error
    /// for a gate instead of converting it, so the enclosing condition site fails its own rule
    /// closed; an assertion still answers FAIL, which is what stops one undecidable clause from
    /// aborting the whole file.
    #[test]
    fn an_undecidable_nested_gate_does_not_silence_the_outer_rule() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["unevaluatable-gate-template.yaml"])
            .rules(vec!["undecidable_nested_gate.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "exit 0 here means the guarded check was dropped because a condition two levels down \
             could not be answered"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("guarded"),
            "the rule whose gate could not be decided must be named as failing:\n{}",
            output
        );
        assert!(
            !output.contains("SKIP rules"),
            "the rule must not be reported as not applicable:\n{}",
            output
        );
        assert!(
            output.contains("could not be evaluated"),
            "the console must say why the rule failed. The evaluator recorded the explanation and \
             the JSON reporter always printed it, while the console printed `Number of non-compliant \
             resources 0` and nothing else -- exit 19 with no account of the reason:\n{}",
            output
        );
    }

    /// The named-rule spelling of the same gate, where the exit code cannot detect the defect.
    ///
    /// `inner_gate` is a plain rule, so it is also a top-level rule, and its own undecidable
    /// condition fails it as an assertion. That failure exits the file 19 no matter what happens to
    /// `guarded`, so a test that checks only the exit code passes while the guarded rule is silently
    /// dropped. This asserts on `guarded`.
    ///
    /// The cause was the rule-status cache, keyed on the rule name alone: `inner_gate` was evaluated
    /// once as an assertion, and the gate reference read that cached FAIL instead of re-evaluating
    /// with gate semantics. Keying on `(rule, role)` makes the reference ask its own question, and the
    /// undecidable answer then reaches the enclosing condition as an error rather than as a status.
    ///
    /// Measured: the merge-base reports `guarded` FAIL, this branch reported SKIP before the fix.
    #[test]
    fn an_undecidable_named_gate_does_not_silence_the_outer_rule() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["unevaluatable-gate-template.yaml"])
            .rules(vec!["undecidable_nested_gate_named.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            !output.contains("SKIP rules"),
            "`guarded` must not be reported as not applicable; its gate could not be decided, which \
             is not the same as a gate that did not match:\n{}",
            output
        );
        assert!(
            output.contains("guarded"),
            "`guarded` must be named as failing:\n{}",
            output
        );
        assert!(
            output.contains("could not be evaluated"),
            "the console must say why, not only that:\n{}",
            output
        );
    }

    /// Two keys spelled the same way in one template must compare equal, and must not compare
    /// unequal.
    ///
    /// `f64::from_str` accepts `nan`, `inf` and `infinity`, so `Threshold: nan` loaded as
    /// `Float(NaN)` -- while YAML's own spellings for those values, `.nan` and `.inf`, were already
    /// loading as strings. `Float(NaN)` is not equal to itself, and `PathAwareValue` asserts `Eq`
    /// while hashing its own contents, so `Threshold == Ceiling` failed on two identical scalars
    /// and the negation of it passed. A rule of the form "these two fields must differ" was
    /// satisfied by two fields that do not.
    ///
    /// Measured on the merge-base: the equality exits 19 and the negation exits 0, both backwards.
    /// The finite pair in `identical_scalars_compare_equal.guard` is the control -- it shares the
    /// clause shape and was always right, so it fails if the fix breaks ordinary floats.
    #[test]
    fn identical_scalars_do_not_compare_unequal() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["non-finite-scalars-template.yaml"])
            .rules(vec!["identical_scalars_compare_equal.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "two keys holding the same scalar must compare equal"
        );

        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["non-finite-scalars-template.yaml"])
            .rules(vec!["identical_scalars_are_not_unequal.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "two keys holding the same scalar must not satisfy a clause asserting they differ"
        );
    }

    /// Two skip reasons in one junit report stay two reasons.
    ///
    /// `serialize_text_events` wrote one text event per reason, and XML concatenates adjacent text
    /// events, so the output was `...nothing to checkbucket_named: no AWS::S3::Bucket...`. A reviewer
    /// found it with a direct serializer probe and noted why the CLI fixtures had not: some evaluator
    /// reasons happen to end in whitespace, which supplies an accidental separator, and every existing
    /// fixture had only one rule to explain.
    ///
    /// Asserted by splitting the element body on the delimiter, so the test fails if the separator is
    /// dropped again rather than merely checking that both rule names appear somewhere.
    #[test]
    fn junit_keeps_multiple_skip_reasons_separate() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["no-volumes-template.yaml"])
            .rules(vec!["two_type_blocks_that_do_not_apply.guard"])
            .output_format(Some("junit"))
            .show_summary(vec!["none"])
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        let body = output
            .split("<skipped>")
            .nth(1)
            .and_then(|rest| rest.split("</skipped>").next())
            .expect("junit emitted no <skipped> element");

        let reasons: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            reasons.len(),
            2,
            "expected one line per inapplicable rule, got {:?} from body {:?}",
            reasons,
            body
        );
        assert!(
            reasons.iter().all(|r| r.contains(": ")),
            "each line should name its rule and its reason, got {:?}",
            reasons
        );
    }

    /// A comparison whose left-hand variable resolved to nothing fails closed.
    ///
    /// An earlier commit on this branch closed this on the right-hand side and left the left open,
    /// so `%x == 'abc'`,
    /// `%x != 'abc'` and `%x > 5` all exited 0 when `%x` held no values. A rule whose only check is one
    /// of those reported compliance having compared nothing, which is the same bypass the right-hand
    /// fix removed.
    ///
    /// Scoped to a lone variable on purpose, and the negative half of that is asserted by
    /// `an_empty_filtered_query_still_skips`: a filtered query that matches nothing must stay a SKIP,
    /// because that is what lets one ruleset run against templates that do not all contain the
    /// resource being checked.
    #[test]
    fn an_empty_variable_on_the_left_fails_closed() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["flat-document-for-empty-lhs.yaml"])
            .rules(vec!["empty_variable_on_the_left.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a comparison that compared nothing must not report success"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("left_side_is_empty"),
            "the clause with the empty left-hand side should be reported:\n{}",
            output
        );
        assert!(
            output.contains("unrelated_violation"),
            "failing closed must not discard the rest of the file:\n{}",
            output
        );
        assert!(
            output.contains("resolved to no values"),
            "the report should say the left-hand side resolved to no values:\n{}",
            output
        );
    }

    /// The counterpart, and the reason the fix above is scoped to a lone variable: a filtered query
    /// that matches nothing is not applicable, not a failure.
    ///
    /// This is the idiom that lets one ruleset run over templates that do not all contain the resource
    /// type being checked, documented in `docs/QUERY_AND_FILTERING.md`. Failing it would fail every
    /// template that omits the type, which is why the empty-left-hand-side fix distinguishes the two
    /// shapes instead of treating every empty selection alike.
    #[test]
    fn an_empty_filtered_query_still_skips() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["no-volumes-template.yaml"])
            .rules(vec!["large_volumes_encrypted_type_block.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "a filtered query that matched nothing must not fail the rule"
        );
    }

    /// Two clauses that pass today, and will not in a later release, say so on stderr without changing
    /// this run's answer.
    ///
    /// Both are spec violations rather than judgment calls. `QUERY_AND_FILTERING.md` lists `Tags: []`
    /// beside a missing key and an empty map as retrieval errors and states that all retrieval errors
    /// are failures; the other two do fail, so a comparison against an empty collection passing is the
    /// outlier. And `CLAUSES.md` says a comparison across kinds that are not both numeric "cannot be
    /// decided, and the clause fails rather than guessing", which `!=` honours and `NOT IN` does not.
    ///
    /// Neither is changed yet, for different reasons: the empty-collection answer is #720's to change,
    /// and `NOT IN` cannot change until five rules in aws-guard-rules-registry stop relying on the
    /// current reading -- failing closed there makes a filter select fewer resources and turns a
    /// reported violation into a pass. So the notice goes out a release ahead of the change.
    ///
    /// On stderr, not in the report: the report on stdout is what pipelines parse, and a notice about a
    /// future release is not part of this run's result. This also keeps every golden file untouched.
    ///
    /// The assertion covers the verdict as well as the notices, because a deprecation notice that moves
    /// a verdict is not a notice.
    #[test]
    fn clauses_whose_answer_changes_later_warn_now() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["vacuous-and-incomparable-template.yaml"])
            .rules(vec!["vacuous_and_incomparable_clauses.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the notices must not change the verdict; both clauses still pass in this release"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(
            notices.len(),
            2,
            "expected one notice per clause, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices
                .iter()
                .any(|n| n.contains("without comparing anything")),
            "the empty-collection clause should say it compared nothing, got {:?}",
            notices
        );
        assert!(
            notices
                .iter()
                .any(|n| n.contains("could not be compared with any element")),
            "the membership clause should say nothing in the list was comparable, got {:?}",
            notices
        );
    }

    /// The counterpart: clauses that are not changing stay silent.
    ///
    /// A deprecation notice is only useful if it is rare. The cases here are the ones most likely to be
    /// mistaken for the ones above -- a filtered query that matched nothing, a `some` clause over the
    /// same empty collection whose answer is already FAIL and is not changing, and ordinary comparisons
    /// that decide normally.
    #[test]
    fn clauses_whose_answer_is_unchanged_stay_quiet() {
        for (label, rules_file, data_file) in [
            (
                "a filtered query that matched nothing",
                "large_volumes_encrypted_type_block.guard",
                "no-volumes-template.yaml",
            ),
            (
                "ordinary comparisons that decide",
                "denied_names_guarded_by_not_empty.guard",
                "bucket-with-no-kms-keys-template.yaml",
            ),
        ] {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            ValidateTestRunner::default()
                .data(vec![data_file])
                .rules(vec![rules_file])
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader);

            let stderr = writer.err_to_stripped().expect("failed to read stderr");
            assert!(
                !stderr.contains("DEPRECATION"),
                "{} should emit no notice, got: {}",
                label,
                stderr
            );
        }
    }

    /// The report lists failing rules in a fixed order.
    ///
    /// The failing set arrives at the console reporter as a `HashMap`, so iterating it directly
    /// emitted the findings in whatever order the hasher produced. Twenty runs of the merge-base
    /// binary over this fixture produced five distinct reports, and `--show-summary all` produced
    /// six. Structured output was already stable, since it is built from ordered collections.
    ///
    /// That makes report diffing across runs useless and any golden file covering two or more
    /// failing rules flaky. It is pre-existing rather than introduced here -- confirmed by running
    /// the merge-base binary -- but it also had to be fixed before a differential over output could
    /// mean anything, since there was no stable baseline to compare against.
    ///
    /// Asserting sortedness rather than looping. A loop inside one process is close to vacuous: the
    /// report is built once, so re-reading it re-reads the same map in the same order, and whether
    /// two `HashMap`s in one process disagree depends on how `RandomState` seeds each instance.
    /// Sortedness is the property that makes the order stable, and it is checkable in a single run.
    /// The count is asserted too, so an extraction that silently found nothing cannot pass.
    #[test]
    fn the_report_orders_failing_rules_deterministically() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["regional-metadata-template.yaml"])
            .rules(vec!["three-failing-rules.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        // The fixture names its rules out of alphabetical order on purpose, so declaration order and
        // sorted order differ and the assertion cannot pass by coincidence.
        let reported = output
            .lines()
            .filter_map(|line| {
                line.split("is not compliant with [")
                    .nth(1)
                    .and_then(|rest| rest.split(']').next())
                    .map(str::to_string)
            })
            .collect::<Vec<String>>();

        assert_eq!(
            reported.len(),
            3,
            "expected all three failing rules in the report, got {:?} from:\n{}",
            reported,
            output
        );
        let mut sorted = reported.clone();
        sorted.sort();
        assert_eq!(
            reported, sorted,
            "failing rules were reported in an unsorted order, which means the order came from a \
             HashMap and varies between runs"
        );
    }

    /// The report lists compliant rules in a fixed order too.
    ///
    /// Companion to the test above, and the same defect one section further down the same function:
    /// the failing and skipped sections were sorted, but `print_rules_output` still iterated the
    /// compliant set, a `HashSet`, directly. Twenty runs over this fixture produced nineteen
    /// distinct orderings of the compliant lines while the failing lines produced exactly one, so
    /// the invariant the sibling test establishes did not hold for a report that had any passing
    /// rules at all -- which is most of them.
    ///
    /// `--show-summary pass` rather than `all`: with `all` the console section is suppressed
    /// entirely for this input, so the compliant lines never reach the writer and the assertion
    /// would pass vacuously.
    #[test]
    fn the_report_orders_compliant_rules_deterministically() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["regional-metadata-template.yaml"])
            .rules(vec!["seven-compliant-rules.guard"])
            .show_summary(vec!["pass"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        // The fixture declares its rules out of alphabetical order (g, c, f, a, e, b, d), so neither
        // declaration order nor sorted order can be reached by coincidence.
        let reported = output
            .lines()
            .filter_map(|line| {
                line.split("Rule [")
                    .nth(1)
                    .and_then(|rest| rest.split(']').next())
                    .map(str::to_string)
            })
            .collect::<Vec<String>>();

        assert_eq!(
            reported.len(),
            7,
            "expected all seven compliant rules in the report, got {:?} from:\n{}",
            reported,
            output
        );
        let mut sorted = reported.clone();
        sorted.sort();
        assert_eq!(
            reported, sorted,
            "compliant rules were reported in an unsorted order, which means the order came from a \
             HashSet and varies between runs"
        );
    }

    /// A failure message comparing against many values shows a few and says how many there were.
    ///
    /// The reporter computed its cut-off as `max(values.len(), 5)`, which is never below the number
    /// of values, so the loop that was meant to stop early never did and the branch reporting a
    /// `Total` was unreachable. A rule comparing against a denylist of five hundred entries printed
    /// all five hundred, in every failure message, for every resource. The dead branch is what gives
    /// the intent away -- it exists to say how many there were when not all are shown.
    ///
    /// The right-hand side has to resolve to many *separate* values to reach this at all. A literal
    /// list is one value however long it is, which is why the fixture compares against a variable
    /// over nine resources rather than against `['a', 'b', ...]`. An earlier version of this test
    /// used the literal and proved nothing.
    #[test]
    fn a_long_in_comparison_is_truncated_with_a_total() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["many-allowed-values-template.yaml"])
            .rules(vec!["volume-type-in-allowed-names.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the volume type is not among the allowed names, so the rule must fail"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Total"),
            "a truncated comparison should report how many values there were:\n{}",
            output
        );
        // Scoped to the ComparedWith line rather than the whole output. The report echoes the
        // offending template, and the fixture's nine topic names all appear there, so a search over
        // everything would find the withheld values in the code snippet and prove nothing.
        let compared_with = output
            .lines()
            .find(|line| line.contains("ComparedWith"))
            .unwrap_or_else(|| panic!("no ComparedWith line in the report:\n{}", output));

        // Five shown, four withheld. Both halves are asserted: a reporter that printed no values at
        // all would satisfy the withheld check on its own.
        for shown in ["n0", "n4"] {
            assert!(
                compared_with.contains(shown),
                "expected {} among the values shown, got: {}",
                shown,
                compared_with
            );
        }
        for withheld in ["n5", "n8"] {
            assert!(
                !compared_with.contains(withheld),
                "{} should have been withheld by the cut-off, got: {}",
                withheld,
                compared_with
            );
        }
    }

    /// A condition that could not be decided has to say so, and a condition that was merely false
    /// must not.
    ///
    /// This is the quietest wrong answer left in the evaluator, and the reason the discrimination
    /// matters. `when ... Size > 10` against a template carrying `Size: "50"` cannot be decided, so
    /// the condition does not pass, so the rule is reported as not applicable and its unencrypted
    /// volume is never checked. Exit 0. A template with `Size: 50` fails the same rule.
    ///
    /// The rule still does not enforce, and it cannot be made to from here: on a condition, both
    /// FAIL and SKIP drop the block being guarded, so telling "could not decide" from "decided
    /// false" at the point it matters needs a status meaning "could not tell", which `Status` does
    /// not have. What is available is saying so, which turns a silent non-check into a visible one.
    /// When that third state exists, this test is where the stronger behaviour gets asserted.
    ///
    /// The false-condition case is asserted alongside because the discriminator is the whole
    /// mechanism: only an undecidable comparison records an explanation, so a rule that legitimately
    /// does not apply stays quiet. Without that, every inapplicable rule in a large ruleset would
    /// grow a line of output and the signal would be worthless.
    #[rstest::rstest]
    #[case(None, "volume-size-as-string-template.yaml", true)]
    #[case(Some("json"), "volume-size-as-string-template.yaml", true)]
    #[case(None, "volume-under-gate-threshold-template.yaml", false)]
    #[case(Some("json"), "volume-under-gate-threshold-template.yaml", false)]
    fn an_undecidable_condition_says_so_in_the_output(
        #[case] output_format: Option<&str>,
        #[case] data_file: &str,
        #[case] expect_explanation: bool,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let mut runner = ValidateTestRunner::default();
        let runner = runner
            .data(vec![data_file])
            .rules(vec!["large_volumes_encrypted_gate.guard"]);
        let status_code = match output_format {
            Some(format) => runner
                .output_format(Some(format))
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader),
            None => runner
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader),
        };

        // Both templates exit 0, which is the point: the exit code cannot tell them apart.
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "an inapplicable rule exits 0 whichever reason applied"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let explained = output.contains("could not be decided");
        assert_eq!(
            explained,
            expect_explanation,
            "the {} output for {} {} an explanation; got:\n{}",
            output_format.unwrap_or("console"),
            data_file,
            if expect_explanation {
                "should have carried"
            } else {
                "should not have carried"
            },
            output
        );
    }

    /// A rule that skipped has to say why, in both the console and the structured output.
    ///
    /// This is the case `every_recorded_explanation_has_a_rendering_path` refused earlier in this
    /// branch. A message was written onto the skip record and it went nowhere: a skipped rule
    /// reached the reporters as a bare name, so the explanation was constructed and discarded --
    /// the same defect that had five other message-bearing record variants rendering nothing.
    /// Making it reachable meant the skip set had to carry reasons, which changed the shape of
    /// `FileReport` and of the `GenericReporter::report` signature.
    ///
    /// Both skip causes are asserted, because telling them apart is the whole value. "No volumes
    /// in the template" is the ordinary reason for a rule not to apply. "Every volume was exempted
    /// by the condition" is the one worth a second look, since a rule that never fires looks
    /// exactly like a rule that passes -- both report SKIP and exit 0.
    #[rstest::rstest]
    #[case(
        None,
        "volume-below-threshold-template.yaml",
        "was exempted by the type block"
    )]
    #[case(
        Some("json"),
        "volume-below-threshold-template.yaml",
        "was exempted by the type block"
    )]
    #[case(None, "no-volumes-template.yaml", "no AWS::EC2::Volume in the input")]
    #[case(
        Some("json"),
        "no-volumes-template.yaml",
        "no AWS::EC2::Volume in the input"
    )]
    fn a_skipped_type_block_explains_itself_in_the_output(
        #[case] output_format: Option<&str>,
        #[case] data_file: &str,
        #[case] expected: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let mut runner = ValidateTestRunner::default();
        let runner = runner
            .data(vec![data_file])
            .rules(vec!["large_volumes_encrypted_type_block.guard"]);
        let status_code = match output_format {
            Some(format) => runner
                .output_format(Some(format))
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader),
            None => runner
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader),
        };

        assert_eq!(
            StatusCode::SUCCESS, status_code,
            "a rule that does not apply exits 0; this test is about the explanation, not the verdict"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains(expected),
            "the {} output for {} did not explain why the rule was skipped; wanted {:?} in:\n{}",
            output_format.unwrap_or("console"),
            data_file,
            expected,
            output
        );
    }

    /// The specific reason a rule did not apply survives the block's own summary.
    ///
    /// `find_skip_reason` searches a record's children before its own message, and names this test as
    /// what pins that. The test did not exist -- the fixture pair did, built for it and left unused, so
    /// the claim read as covered while nothing held the order in place.
    ///
    /// The order is what matters. A type block attaches a summary to its own SKIP, so taking `own`
    /// first stops the recursion and the deeper explanation is built, recorded, and never read. Here
    /// the deeper one is the useful one: `Size: "50"` is a string, so the gate's comparison against 10
    /// cannot be decided, and "a condition could not be decided" is a different thing for an author to
    /// read than "every volume was exempted".
    ///
    /// Asserting the absence of the block summary is what makes this a test of the ordering rather
    /// than of the message: with `own` taken first, the summary is what would appear.
    #[test]
    fn a_specific_skip_reason_is_not_shadowed_by_the_block_summary() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["volume-size-as-string-template.yaml"])
            .rules(vec!["large_volumes_encrypted_type_block.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS, status_code,
            "an undecidable type-block condition still reports SKIP and exits 0; this test is about \
             which explanation reaches the output"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("could not be decided"),
            "the console must give the specific reason the condition failed:\n{}",
            output
        );
        assert!(
            output.contains("not comparable"),
            "and it must name the mismatch, since that is what tells the author to look at the \
             template rather than the rule:\n{}",
            output
        );
        assert!(
            !output.contains("was exempted by the type block"),
            "the block's own summary must not be what surfaces -- that is the shadowing this \
             ordering exists to prevent:\n{}",
            output
        );
    }

    /// A finding under `Resources` that names no CloudFormation resource is reported, not a panic.
    ///
    /// The console reporter organises findings by resource, and reached `unreachable!()` when a path
    /// under `/Resources` did not resolve to one. That is not a broken invariant -- guard validates
    /// plain YAML and JSON as well as templates, so `Resources.Nested.inner.key` is an ordinary query
    /// against a document where `Nested` has no `Type`. It took the process down at exit 101 on a
    /// document whose only fault was not being CloudFormation, and the finding was lost with it.
    ///
    /// The fallback already existed for the sibling case: hand back an `InternalError` and let
    /// `report_eval` delegate to the next reporter, which makes no assumption about the shape. Both
    /// depths are covered, because the reporter takes a different branch either side of two path
    /// separators.
    #[test]
    fn a_finding_outside_a_cloudformation_resource_is_reported_not_a_panic() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["non-resource-nesting-template.yaml"])
            .rules(vec!["nested_non_resource_clause.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the clauses fail, so the run reports 19; 101 is the panic this test exists for"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("nested_values_are_right"),
            "the failing rule must still be named once the reporter falls back:\n{}",
            output
        );
    }

    /// Every shape the console reporter cannot organise by resource falls back instead of crashing.
    ///
    /// The first fix here covered one of four `unreachable!()` on this path, and review found the other
    /// three. All four had the same cause: the reporter assumed every finding sits under a resolvable
    /// CloudFormation resource, and reached for a panic when one did not.
    ///
    /// The range that fed it was `range("/Resources"..)` with no upper bound, wrong in both directions
    /// and silently so in one of them:
    ///
    /// - After `Resources`: `Rules` and `Transform` are real CloudFormation sections and both sort
    ///   after it, so a SAM template with a failing clause under either died at exit 101.
    /// - Before `Resources`: `Outputs` was dropped from the aggregation entirely, and the file then
    ///   printed "Number of non-compliant resources 0" while exiting 19. A failing gate with nothing to
    ///   act on is worse than a crash, because it reads as a report.
    ///
    /// The other two are values of the wrong type on an otherwise ordinary resource -- a `Type` that is
    /// a map, and an `aws:cdk:path` that is a number -- where the sibling arm already returned `None`.
    ///
    /// Each case asserts the finding is *named*, not merely that the run exited 19, because exiting 19
    /// with nothing printed is the defect in the `Outputs` row.
    #[rstest::rstest]
    #[case::section_sorting_after_resources(
        "transform-section-template.yaml",
        "rules_section_assertion.guard",
        "/Rules/RegionCheck"
    )]
    #[case::section_sorting_before_resources(
        "outputs-section-template.yaml",
        "outputs_value_is_right.guard",
        "/Outputs/a/b/c"
    )]
    #[case::resource_type_is_not_a_string(
        "non-string-type-template.yaml",
        "nested_key_is_right.guard",
        "/Resources/Nested/key"
    )]
    #[case::cdk_path_is_not_a_string(
        "non-string-cdk-path-template.yaml",
        "bucket_name_is_right.guard",
        "/Resources/Bucket/Properties/BucketName"
    )]
    fn a_finding_the_cfn_reporter_cannot_place_is_still_reported(
        #[case] data_file: &str,
        #[case] rules_file: &str,
        #[case] expected_path: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec![data_file])
            .rules(vec![rules_file])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{} fails its rule, so the run reports 19; 101 is the panic these cases exist for",
            data_file
        );

        let output = writer.stripped().expect("failed to read the writer");
        // The property path rather than a phrase, because the two outcomes are both correct and word
        // things differently. The first three demote the file to the generic reporter, which prints
        // "Property [...] is not compliant with"; the last one stays with the console reporter -- a
        // non-string CDK path is now just a resource without a CDK path -- and keeps the detailed
        // per-resource report. Either way the path has to appear, and "Number of non-compliant
        // resources 0" contains no path at all.
        assert!(
            output.contains(expected_path),
            "the finding for {} must name {}, not be counted as zero:\n{}",
            data_file,
            expected_path,
            output
        );
    }

    /// A unary operator on a numeric literal is reported, not a panic.
    ///
    /// `let numeric = 5` followed by `%numeric empty` is a clause the operator cannot answer, so it
    /// fails -- and building the *report* for that failure hit `QueryResult::Literal(_) =>
    /// unreachable!()`, taking the process down at exit 101. String and list literals never reached it,
    /// because the operator answers those; the arm is only reachable once the clause has already decided
    /// to fail.
    ///
    /// This is an integration test rather than a unit test on purpose. The panic is in the
    /// report-building path, which `eval_rules_file` alone does not enter -- a unit test asserting the
    /// rule's status passes whether or not the bug is present, which is how the first version of this
    /// test came out green against the unfixed code. Both output modes are covered because the reporter
    /// is what reaches the arm.
    /// The second data file is not interchangeable with the first, and that is the point. Fixing the
    /// `eval_context` arm made a *further* `unreachable!()` reachable in `reporters/validate/common.rs`,
    /// which had been shadowed by it -- a reachability triage had listed those arms as "not reproduced"
    /// for exactly that reason. `flat-document-for-empty-lhs.yaml` reaches the second one and
    /// `numeric-literal-unary-template.yaml` does not, so both are needed to hold both layers.
    #[rstest::rstest]
    #[case::console(None, "numeric-literal-unary-template.yaml")]
    #[case::structured_json(Some("json"), "numeric-literal-unary-template.yaml")]
    #[case::console_reaching_the_shadowed_arm(None, "flat-document-for-empty-lhs.yaml")]
    #[case::json_reaching_the_shadowed_arm(Some("json"), "flat-document-for-empty-lhs.yaml")]
    fn a_unary_operator_on_a_numeric_literal_is_reported_not_a_panic(
        #[case] output_format: Option<&str>,
        #[case] data_file: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let mut runner = ValidateTestRunner::default();
        let runner = runner
            .data(vec![data_file])
            .rules(vec!["unary_on_a_numeric_literal.guard"]);
        let status_code = match output_format {
            Some(format) => runner
                .output_format(Some(format))
                .structured()
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader),
            None => runner
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader),
        };

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the clause fails, so the run reports 19; 101 is the panic this test exists for"
        );
    }

    /// The Terraform reporter reports findings it cannot place, rather than aborting or dropping them.
    ///
    /// `tf.rs` carried the same four defects as `cfn.rs`, unfixed, and nothing exercised any of them
    /// because the fixture corpus had no plan document at all. This adds one.
    ///
    /// The extraction regex only matches `/resource_changes/<x>/change/after/<...>`, so every other part
    /// of a plan reached an abort: `type`, `address`, `name` and `change.actions` are everyday fields and
    /// all four took the process down at exit 101. `terraform_version` is a real top-level key of a plan
    /// and sorts *after* `resource_changes`, so the unbounded range admitted it and it panicked too.
    /// `format_version` sorts *before*, so it was excluded from the aggregation and the file reported
    /// "Number of non-compliant resources 0" while exiting 19.
    ///
    /// `TfAware` also had no `InternalError` fallback -- `CfnAware` has had one all along -- so there was
    /// nothing for a declining reporter to fall back to. That is added here.
    ///
    /// The control matters: `change.after.acl` is the one path the regex does match, so it always worked
    /// and must keep its detailed per-resource rendering rather than being demoted with the rest.
    #[rstest::rstest]
    #[case::top_level_keys_either_side_of_the_range(
        "tf_plan_top_level_keys.guard",
        "/terraform_version"
    )]
    #[case::resource_change_fields_outside_change_after(
        "tf_resource_change_fields.guard",
        "/resource_changes/0/type"
    )]
    #[case::control_inside_change_after(
        "tf_change_after_control.guard",
        "/resource_changes/0/change/after/acl"
    )]
    fn a_terraform_finding_the_reporter_cannot_place_is_still_reported(
        #[case] rules_file: &str,
        #[case] expected_path: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["terraform-plan.json"])
            .rules(vec![rules_file])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR, status_code,
            "{} fails against the plan, so the run reports 19; 101 is the abort these cases exist for",
            rules_file
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains(expected_path),
            "the finding for {} must name {}, not be counted as zero:\n{}",
            rules_file,
            expected_path,
            output
        );
    }

    /// A rule that cannot be evaluated does not discard the junit report.
    ///
    /// `get_test_case` propagated the evaluation error, so a junit run against a rules file with one
    /// unresolvable variable emitted no XML at all. For a CI format that means the job reports nothing
    /// rather than reporting a problem — the report is the entire interface.
    ///
    /// Everything needed was already present: `TestCaseStatus::Error` exists, `xml.rs` counts it into the
    /// suite's `errors`, and that total sets the exit code. Only the `?` was in the way.
    ///
    /// The exit code changes for this case, from 255 to `ERROR_STATUS_CODE`. That is deliberate: 5 is what
    /// this reporter already assigns to a test case in the `Error` state, so an evaluation error and a
    /// rendering error now agree, and the distinction that matters to a consumer — not 19, so not a
    /// policy failure — is kept either way.
    #[test]
    fn a_rule_that_cannot_be_evaluated_does_not_discard_the_junit_report() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["five-non-compliant-buckets-template.yaml"])
            .rules(vec!["a_broken_rule_beside_working_ones.guard"])
            .output_format(Some("junit"))
            .structured()
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a test case in the error state sets the reporter's own error code, not 19"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("<?xml") && output.contains("errors=\"1\""),
            "the report must be emitted and must count the error:\n{}",
            output
        );
        assert!(
            output.contains("Could not resolve variable by name nm"),
            "and must name the cause:\n{}",
            output
        );
    }

    /// The same for the JSON, YAML and SARIF path, which shares one evaluator.
    ///
    /// `CommonStructuredReporter` propagated too, so the document a machine reads was replaced by a
    /// single error line for a file whose other rules had findings. Here the error is still returned
    /// after the document is written, so the exit code is unchanged and the document is gained.
    #[test]
    fn a_rule_that_cannot_be_evaluated_does_not_discard_the_structured_document() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["five-non-compliant-buckets-template.yaml"])
            .rules(vec!["a_broken_rule_beside_working_ones.guard"])
            .output_format(Some("json"))
            .structured()
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INTERNAL_FAILURE,
            status_code,
            "the exit code for this path is unchanged; only the document is new"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("every_bucket_is_named_expected"),
            "the rules that could be evaluated must still be in the document:\n{}",
            output
        );
    }

    /// A failing `IN` comparison against a Terraform plan is rendered, not a panic.
    ///
    /// `binary_error_in_msg` in `tf.rs` was `todo!()`, and an everyday rule reaches it: `IN` on any
    /// `resource_changes[*].change.after.<field>` that fails renders through there, so it took the
    /// process down at exit 101 with the report cut off mid-line. The trait's default writes nothing
    /// instead, which would have left the finding unnamed — the panic and the silence are the same
    /// defect in different clothes.
    ///
    /// The `Total` half is the other reason this needs a six-resource plan: the cut-off can only be
    /// crossed when the compared-with side has more than five elements, and `terraform-plan.json` has one
    /// resource change, so nothing in the corpus could reach it.
    #[test]
    fn a_failing_in_comparison_against_a_plan_is_rendered_not_a_panic() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["terraform-plan-many-resources.json"])
            .rules(vec!["tf_acl_in_tags.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "no acl is among the tags, so the rule fails; 101 is the panic this case exists for"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Operator        = IN"),
            "the failing IN comparison must be rendered:\n{}",
            output
        );

        let compared_with = output
            .lines()
            .find(|line| line.contains("ComparedWith"))
            .unwrap_or_else(|| panic!("no ComparedWith line in the report:\n{}", output));
        assert_eq!(
            compared_with.matches('"').count() / 2,
            5,
            "the reporter shows five of the values and no more, got: {}",
            compared_with
        );
        assert!(
            output.contains("Total           = 6"),
            "and says how many there were in total:\n{}",
            output
        );
    }

    /// Terraform resource changes are reported in a fixed order.
    ///
    /// The companion to `resources_are_reported_in_a_fixed_order`: `tf.rs` had the same per-process
    /// `HashMap` iteration and was fixed in the same commit, but no plan fixture had more than one
    /// resource change, so nothing exercised it. With the `HashMap` restored, three runs of one binary
    /// against this fixture produce three different orders.
    #[test]
    fn terraform_resources_are_reported_in_a_fixed_order() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["terraform-plan-many-resources.json"])
            .rules(vec!["tf_acl_in_tags.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        let reported: Vec<&str> = output
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Resource = "))
            .map(|rest| rest.trim_end_matches(" {"))
            .collect();

        assert_eq!(
            reported,
            vec!["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"],
            "all six resource changes must be reported, in a fixed order:\n{}",
            output
        );
    }

    /// One rule that cannot be evaluated does not cost the file its report.
    ///
    /// `eval_rules_file` returned on the first rule that errored, after closing the *file's* record with
    /// a rule-check payload. So the record was both mislabelled and truncated, every rule after the
    /// broken one went unevaluated, and the run printed a single error line: five real findings from a
    /// third rule, discarded because a second rule read a variable that does not exist in it.
    ///
    /// The exit code is deliberately unchanged. A variable that resolves nowhere is a broken ruleset
    /// rather than a non-compliant template, and 255 rather than 19 is what says so; the fix is that
    /// there is now a report to read beside it.
    #[test]
    fn a_rule_that_cannot_be_evaluated_does_not_discard_the_other_rules_findings() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["five-non-compliant-buckets-template.yaml"])
            .rules(vec!["a_broken_rule_beside_working_ones.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::INTERNAL_FAILURE, status_code,
            "a ruleset that cannot be evaluated stays distinguishable from a non-compliant template"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let reported = output
            .lines()
            .filter(|l| l.starts_with("Resource = "))
            .count();
        assert_eq!(
            reported, 5,
            "the rules that could be evaluated must still report their findings:\n{}",
            output
        );
        assert!(
            output.contains("Could not resolve variable by name nm"),
            "and the rule that could not be evaluated must still say why:\n{}",
            output
        );
    }

    /// A failing clause that belongs to no resource still says why.
    ///
    /// `let numeric = 5` then `%numeric empty`: the operand is a literal, so the finding has no path and
    /// no resource to be filed under. The evaluator records "Attempting EMPTY operation on type int that
    /// does not support it" and the JSON reporter prints it; the console reporter dropped it, so the run
    /// exited 19 reporting `Number of non-compliant resources 0` and no reason at all.
    ///
    /// The third variant of one defect. The block-attributed and rule-attributed variants were fixed
    /// earlier on this branch; a clause whose path is empty was the case left, and it is pre-existing —
    /// the merge-base behaves the same way.
    ///
    /// Whether a clause is rendered is a property of its *rule*, not of the clause: the per-resource loop
    /// matches a rule to a resource through its findings' paths and then renders all of it, so one placed
    /// clause carries its pathless siblings into the output. Deciding this at the clause instead prints
    /// such a sibling a second time, with the whole document as its "value traversed to" —
    /// `test_validate_with_failing_join_and_compare_output` is the fixture that catches it, and it does.
    ///
    /// The data file matters only in that it has to reach a resource-grouping reporter — the rule never
    /// looks at the data at all. Those reporters are the ones with buckets to walk, and therefore the ones
    /// that had nowhere to put a finding belonging to no resource.
    ///
    /// Both of them, which is why this is two cases. The collector lives in `common.rs` and `tf.rs` calls
    /// it on the same terms as `cfn.rs`, so a Terraform plan reaches the same code by a different route.
    /// Every defect this branch fixed in `cfn.rs` was present in `tf.rs` too and unnoticed there, because
    /// the fixture corpus had no plan document reaching any of them — an untested second caller of shared
    /// code is how that happened, and one fixture is what stops it happening again.
    #[rstest::rstest]
    #[case::cloudformation("numeric-literal-unary-template.yaml")]
    #[case::terraform("terraform-plan.json")]
    fn a_failing_clause_that_belongs_to_no_resource_still_says_why(#[case] data_file: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec![data_file])
            .rules(vec!["unary_on_a_numeric_literal.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`empty` has no answer for a number, so the clause fails"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Findings that belong to no resource:"),
            "a finding that belongs to no resource is reported in its own section:\n{}",
            output
        );
        assert!(
            !output.contains("Could not be evaluated:"),
            "and under its own heading — this clause was evaluated, it just has nowhere to be shown:\n{}",
            output
        );
        assert!(
            output.contains("EMPTY operation on type int"),
            "and the reason the evaluator recorded reaches the console, not only the JSON:\n{}",
            output
        );
    }

    /// A block whose query fails at the document root is still reported.
    ///
    /// Of the four ways a block report is built, `MissingBlockValue` is the one that sets `unresolved`, and
    /// when the query fails at the root the value it traversed to has an empty path. So the per-resource
    /// output had no bucket for it, and the collector that handles blocks skipped it because that collector
    /// required `unresolved` to be absent. The run exited 19 with "Number of non-compliant resources 0" and
    /// nothing else -- the everyday shape of the defect this section exists for, in block syntax, and it
    /// took the author's own message down with it.
    ///
    /// The gate is now what the reporter actually rendered rather than what a path predicts it will.
    #[test]
    fn a_block_query_that_fails_at_the_document_root_still_says_why() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["one-bucket-no-parameters-template.yaml"])
            .rules(vec!["block_query_at_the_document_root.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the block's query resolves to nothing, so the rule fails"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Parameters"),
            "a run that exits 19 has to say which query it could not resolve:\n{}",
            output
        );
    }

    /// A pathless clause beside a placed one is reported, and the placed one is not reported twice.
    ///
    /// Both halves matter and they pull against each other. `pprint_clauses` gates each clause individually
    /// on membership of the resource's set, so a clause over a literal is skipped there even though its rule
    /// renders; a rule-level "was anything placed?" gate then hid it from the unattributed section as well,
    /// and it appeared nowhere while the JSON carried its reason. Deciding per clause instead reintroduces a
    /// different fault -- the evaluator emits two reports for one comparison it resolved one way and could
    /// not resolve another, so the unresolved twin gets printed beside the entry already on screen. That is
    /// what `test_validate_with_failing_join_and_compare_output` catches.
    ///
    /// The rendered-context set separates them: the twin shares a context with what was shown, a genuinely
    /// unreported sibling does not.
    #[test]
    fn a_pathless_clause_beside_a_placed_one_is_reported_once() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["numeric-literal-unary-template.yaml"])
            .rules(vec!["a_pathless_clause_beside_a_placed_one.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Resource = One"),
            "the clause with a path is still rendered under its resource:\n{}",
            output
        );
        assert!(
            output.contains("EMPTY operation on type int"),
            "and the clause without one is reported rather than dropped:\n{}",
            output
        );
        assert_eq!(
            output.matches("EMPTY operation on type int").count(),
            1,
            "exactly once:\n{}",
            output
        );
    }

    /// Two clauses whose rendered text is identical are both reported.
    ///
    /// One is inside a resource block and resolves to a value with a path; the other is at document scope
    /// and has none. They are separate report nodes and both fail. The rendered set was keyed on the
    /// trimmed context string, so the placed clause made the pathless one's text count as already shown
    /// and it was dropped from the console with no section printed at all, while the JSON carried its
    /// reason. Exit 19 either way, so nothing was misreported -- a real finding was simply missing.
    ///
    /// The two messages are what separate the findings: one names the property missing under
    /// `/Resources/S3Bucket/Properties`, the other the one missing at the document root.
    #[test]
    fn two_clauses_that_share_a_context_are_both_reported() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["bucket-with-no-kms-keys-template.yaml"])
            .rules(vec!["two_clauses_that_share_a_context.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Resource = S3Bucket"),
            "the clause with a path is still rendered under its resource:\n{}",
            output
        );
        assert!(
            output.contains("Findings that belong to no resource:"),
            "and the one without a path is reported rather than dropped:\n{}",
            output
        );
        assert!(
            output.contains("[Properties.Tags] is missing"),
            "with the reason that belongs to it, which is the root query and not the resource one:\n{}",
            output
        );
    }

    /// One comparison the evaluator reported twice is still printed once.
    ///
    /// This is the case the rendered set was added for, and the reason the test above cannot simply be
    /// satisfied by asking whether a clause has a path. For `"a,b" == join(%collection, ",")` the
    /// evaluator records two clause reports under one context: an `UnResolved` one for the literal on the
    /// left, whose path is the unlocated root, and an `InResolved` one for the comparison that ran, whose
    /// path is under `/Resources/`. The second is placed and rendered; the first is not placed, and
    /// printing it would restate a finding already on screen.
    ///
    /// Asserted on the same fixture `test_validate_with_failing_join_and_compare_output` compares against
    /// a golden file, so the two pin the same behaviour from both directions.
    #[test]
    fn one_comparison_reported_twice_is_printed_once() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/join_with_message.guard"])
            .data(vec!["/functions/data/template.yaml"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            output
                .matches("a,b EQUALS  join(%collection, \",\")")
                .count(),
            1,
            "the twin shares a context with the entry already on screen and is not repeated:\n{}",
            output
        );
        assert!(
            !output.contains("Findings that belong to no resource:"),
            "so the section has nothing to say here:\n{}",
            output
        );
    }

    /// Resources are reported in a fixed order.
    ///
    /// The reporter aggregated them into a `std::collections::HashMap` and iterated that to write the
    /// output. Rust seeds that hasher per process, so the `Resource = ...` blocks came out in a
    /// different order on every run: five distinct outputs from ten runs of one binary against a
    /// three-resource template. Output that changes without the input changing cannot be diffed in CI,
    /// and it made a differential over the fixture corpus report changes that were only noise.
    ///
    /// Asserted as "in name order" rather than "the same twice", because two runs inside one test
    /// process may draw the same order by chance and prove nothing. Five resources make an accidental
    /// alphabetical order one arrangement in a hundred and twenty.
    #[test]
    fn resources_are_reported_in_a_fixed_order() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["five-non-compliant-buckets-template.yaml"])
            .rules(vec!["every_bucket_is_named_expected.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        let reported: Vec<&str> = output
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Resource = "))
            .map(|rest| rest.trim_end_matches(" {"))
            .collect();

        assert_eq!(
            reported,
            vec!["Alpha", "Bravo", "Charlie", "Delta", "Echo"],
            "all five resources must be reported, in a fixed order:\n{}",
            output
        );
    }

    /// A Terraform finding that belongs to no resource change is still explained.
    ///
    /// `single_line` groups findings by resource change. A clause that failed *because it had nothing
    /// to compare* points at no path, so it lands in no group and the loop cannot render it: the run
    /// exited 19, printed "Number of non-compliant resources 0", and gave no reason anywhere. `cfn.rs`
    /// grew a section for exactly this and `tf.rs` did not.
    ///
    /// Nothing reached it before, which is why it went unnoticed -- a capture that selected nothing was
    /// an unresolved-variable error that ended the run before any reporter saw it. Scoping captures to
    /// the block that declares them turns that into a clause failure, so this shape now arrives here.
    #[test]
    fn a_terraform_finding_that_belongs_to_no_resource_change_is_still_explained() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["terraform-plan.json"])
            .rules(vec!["public_bucket_is_not_named_a.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the capture selects nothing against a plan, which fails the clause reading it"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Could not be evaluated:") && output.contains("%nm"),
            "the run exits 19 and must say why, rather than counting zero resources and stopping:\n{}",
            output
        );
    }

    /// A repeated document key does not misalign the keys from the values.
    ///
    /// `values` is an `IndexMap` and dedups; `keys` was a `Vec` that did not. The two therefore ended up
    /// different lengths, and `eval_context` pairs them *positionally* --
    /// `map.keys.iter().zip(map.values.values())` -- so every entry after the duplicate was bound to the
    /// wrong key and the last key was dropped altogether.
    ///
    /// On this template, where `A` is declared twice and `C` is the only public bucket, the capture bound
    /// "A" -- a bucket whose `Public` is false. A rule that reports the wrong logical id sends someone to
    /// the wrong resource.
    ///
    /// An integration test with a YAML fixture, not a unit test: the relaxed-JSON parser behind
    /// `PathAwareValue::try_from(&str)` collapses a repeated key before a map is built, so a unit test
    /// written against a string passes whether or not the bug is present. The first version of this test
    /// was written that way and came out green against the unfixed code.
    ///
    /// The `not_named_a` case is the one that fails without the fix; `names_c` states the positive.
    #[rstest::rstest]
    #[case::names_c("which_bucket_is_public.guard", StatusCode::SUCCESS)]
    #[case::not_named_a("public_bucket_is_not_named_a.guard", StatusCode::VALIDATION_ERROR)]
    fn a_repeated_document_key_does_not_misalign_the_capture(
        #[case] rules_file: &str,
        #[case] expected: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["duplicate-logical-id-template.yaml"])
            .rules(vec![rules_file])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            expected, status_code,
            "{} against a template whose logical id A is declared twice",
            rules_file
        );
    }

    /// The same explanation has to reach junit, which is the format a pipeline gates on.
    ///
    /// It did not. `TestCaseStatus::Skip` was a unit variant, so the reason the evaluator had already
    /// recorded had nowhere to go, and the element came out as `<testcase status="skip"/>`. A
    /// consumer parsing junit saw a rule silently not apply -- the failure mode this branch exists to
    /// remove, one output format further out than the reporters it started with.
    ///
    /// Asserted on the contents of the `<skipped>` element rather than on the whole document, so the
    /// reason has to arrive somewhere a junit consumer actually reads. A substring assertion over the
    /// document would also pass if the text leaked into an attribute of the wrong element.
    #[test]
    fn a_skipped_rule_explains_itself_in_junit_output() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["no-volumes-template.yaml"])
            .rules(vec!["large_volumes_encrypted_type_block.guard"])
            .output_format(Some("junit"))
            .show_summary(vec!["none"])
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "a rule that does not apply exits 0; this test is about the explanation"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let inside_skipped = output
            .split("<skipped>")
            .nth(1)
            .and_then(|rest| rest.split("</skipped>").next());

        match inside_skipped {
            None => panic!(
                "junit emitted no <skipped> element for a rule that did not apply:\n{}",
                output
            ),
            Some(body) => assert!(
                body.contains("no AWS::EC2::Volume in the input"),
                "the <skipped> element did not carry the reason; body was {:?} in:\n{}",
                body,
                output
            ),
        }
    }

    /// The counterpart: a run with nothing wrong must not print the section.
    ///
    /// Without this, the assertion above is satisfied by a reporter that prints the explanation
    /// unconditionally.
    #[test]
    fn a_clean_run_does_not_print_an_unevaluated_clause_section() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["bucket-with-no-kms-keys-template.yaml"])
            .rules(vec!["denied_names_guarded_by_not_empty.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            !output.contains("Clauses that could not be evaluated"),
            "a guarded, skipped clause is not an unevaluated failure, got:\n{}",
            output
        );
    }

    #[test]
    fn test_single_data_file_single_rules_file_compliant() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
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

    /// A type block whose query cannot be resolved must not take the process down with it.
    ///
    /// Introduced by #432, "fixing panic in evaluator when query from typeblock is unresolved",
    /// which replaced `QueryResult::UnResolved(_) => unreachable!()` -- a real panic on this fuzzed
    /// input -- with a recorded failure and an `Err`. The assertion was `INTERNAL_FAILURE` because
    /// that is what an `Err` escaping `execute` produces, so the exit code was the observable proof
    /// that the panic was gone.
    ///
    /// The no-panic property is the point of that fix and it still holds. What changed is the
    /// representation: an unresolvable slot is now not-applicable rather than an error, because an
    /// `Err` from one rule aborts the whole rules file and takes the verdicts of unrelated rules
    /// with it -- see `an_unresolved_type_block_query_skips_without_aborting_the_file`. This input
    /// is a garbage rule (`d1z::Y` with a clause `m < ...`) against an empty document, so the
    /// retrieval of `m` fails closed and the run reports a violation instead of an internal error.
    ///
    /// The assertion is deliberately not `SUCCESS`. That would mean the fuzzed rule had been quietly
    /// accepted, which is the failure mode this whole branch exists to remove.
    ///
    /// It is now `PARSING_ERROR` rather than `VALIDATION_ERROR`, and the reason is in the payload:
    /// the clause is `m<0m<03333333`, where the literal `0` runs straight into `m`. That used to
    /// split into two clauses -- `m < 0` and `m < 03333333` -- because a bare identifier is a valid
    /// clause, so the fuzzer's garbage parsed and then evaluated to a violation. A digit running into
    /// a letter is never two clauses, and `reject_trailing_identifier` now says so, which is how
    /// `Size == 1e5` stopped meaning `Size == 1` and a reference to a rule called `e5`.
    ///
    /// Rejecting garbage at parse time serves this test's intent better than evaluating it: both exit
    /// non-zero, and only one of them pretends the rule was understood.
    #[test]
    fn test_with_payload_failing_type_block() {
        let payload = r#"{"data": [ "{}" ], "rules" : [ "d1z::Y\n\t\tm<0m<03333333" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::default();
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    #[test]
    fn test_with_payload_flag_fail() {
        let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"SomeRandomString\"" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        let result = writer.stripped().unwrap();
        // This expectation used to be "Number of non-compliant resources 0", twice, for a rule that
        // really does fail: `Parameters.InstanceName` is "TestInstance" and the rule demands
        // "SomeRandomString". The console reporter aggregates by CloudFormation resource and
        // `/Parameters/InstanceName` is not under one, so the finding was dropped and the file was
        // described by a count that did not include it -- exiting 19 with nothing to act on. The test
        // pinned that, which is why it survived.
        //
        // The finding is now named, by the reporter that can name it.
        let expected = indoc! {
            r#"
            DATA_STDIN[1] Status = FAIL
            FAILED rules
            RULES_STDIN[2]/default    FAIL
            ---
            Evaluation of rules RULES_STDIN[2] against data DATA_STDIN[1]
            --
            Property [/Parameters/InstanceName] in data [DATA_STDIN[1]] is not compliant with [RULES_STDIN[2]/default] because provided value ["TestInstance"] did not match expected value ["SomeRandomString"]. Error Message []
            --
            DATA_STDIN[2] Status = FAIL
            FAILED rules
            RULES_STDIN[2]/default    FAIL
            ---
            Evaluation of rules RULES_STDIN[2] against data DATA_STDIN[2]
            --
            Property [/Parameters/InstanceName] in data [DATA_STDIN[2]] is not compliant with [RULES_STDIN[2]/default] because provided value ["TestInstance"] did not match expected value ["SomeRandomString"]. Error Message []
            --
            "#
        };

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        assert_eq!(expected, result);
    }

    #[rstest::rstest]
    #[case("yaml")]
    #[case("json")]
    #[case("junit")]
    #[case::sarif("sarif")]
    fn test_structured_output(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

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
    #[case("now.guard")]
    #[case("parse_epoch.guard")]
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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

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

    /// An embedded string `json_parse` cannot read fails the clause, and does not abort the run.
    ///
    /// `embedded_json_the_parser_rejects.yaml` carries a duplicate key, which JSON readers generally
    /// accept and `serde_yaml` rejects, and a mapping keyed by a number. Both errors propagated
    /// unchanged, and neither class is unevaluatable, so the run exited 255 while the `REAL_VIOLATION`
    /// rule in the same file reported its finding.
    #[test]
    fn an_embedded_string_the_parser_rejects_fails_the_clause_rather_than_the_run() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "/functions/rules/embedded_json_the_parser_rejects.guard",
            ])
            .data(vec![
                "/functions/data/embedded_json_the_parser_rejects.yaml",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    /// A scalar function argument the data could not supply fails the clause, and does not abort the run.
    ///
    /// `bad_function_arguments.yaml` feeds a negative offset and a non-numeric offset to `substring`, a
    /// number to `join`'s delimiter and a number to `regex_replace`'s pattern. All four were reported as
    /// `ParseError`, the class the evaluator reserves for a malformed rules file, which is not
    /// unevaluatable, so the run aborted and exited 255. The rules file is well formed, and the
    /// `REAL_VIOLATION` rule in the same file reports its finding either way -- so a template author
    /// could turn their own violation from exit 19 into exit 255 with a `-1` in the right field.
    #[test]
    fn a_bad_function_argument_from_the_data_fails_the_clause_rather_than_the_run() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/bad_function_arguments.guard"])
            .data(vec!["/functions/data/bad_function_arguments.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    /// A `count` over a query that named something absent does not answer 0, so a misspelled path in a
    /// rule cannot pass.
    ///
    /// `count_unresolved.guard` counts `Collectionz`, one letter off the `Collection` the data carries,
    /// and asserts the count is 0. That used to be satisfied and the run exited 0 while the correctly
    /// spelled rule found three entries. The verdict is the assertion: SUCCESS before, VALIDATION_ERROR
    /// after.
    #[test]
    fn a_count_of_an_unresolved_selection_does_not_pass_the_rule() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/count_unresolved.guard"])
            .data(vec!["/functions/data/template.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    /// The control for the test above: a collection that is present and empty still counts 0, so the
    /// rule passes. Both cases used to arrive as an unresolved result, and this is the one that has to
    /// keep its answer.
    #[test]
    fn a_count_of_an_empty_collection_is_still_zero() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/count_empty_collection.guard"])
            .data(vec!["/functions/data/empty_collection.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    /// A `regex_replace` whose pattern does not match returns the input, so the clause around it still
    /// compares the real value and this rule fails.
    ///
    /// It used to return `""`. An empty string is a value and it compares, so the `!=` in
    /// `regex_replace_no_match.guard` was satisfied and the run exited 0 -- a rule that normalises an
    /// optional prefix before checking a name reported a pass on the name it was written to catch. The
    /// verdict is the assertion here, not the text: SUCCESS before, VALIDATION_ERROR after.
    #[test]
    fn a_regex_replace_that_matches_nothing_does_not_pass_the_rule() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/regex_replace_no_match.guard"])
            .data(vec!["/functions/data/template.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    #[test]
    fn test_validate_with_failing_complex_rule() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

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
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

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
