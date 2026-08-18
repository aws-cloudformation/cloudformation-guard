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
    #[rstest::rstest]
    #[case(None)]
    #[case(Some("json"))]
    fn empty_reference_failure_explains_itself_in_the_output(#[case] output_format: Option<&str>) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let mut runner = ValidateTestRunner::default();
        let runner = runner
            .data(vec!["bucket-with-no-kms-keys-template.yaml"])
            .rules(vec!["denied_names_from_empty_reference.guard"]);
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
            "output ({:?}) did not explain that the reference resolved to no values.\n{}",
            output_format.unwrap_or("console"),
            output
        );
        assert!(
            output.contains("!empty"),
            "the explanation should name the `!empty` guard as the remedy, got:\n{}",
            output
        );
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
    #[test]
    fn test_with_payload_failing_type_block() {
        let payload = r#"{"data": [ "{}" ], "rules" : [ "d1z::Y\n\t\tm<0m<03333333" ]}"#;
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer = Writer::default();
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
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
