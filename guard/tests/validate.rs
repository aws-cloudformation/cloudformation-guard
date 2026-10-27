// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub(crate) mod utils;
#[cfg(test)]
mod validate_tests {
    use indoc::indoc;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;

    use cfn_guard::commands::CfnGuard;
    use cfn_guard::commands::{
        ALPHABETICAL, DATA, INPUT_PARAMETERS, LAST_MODIFIED, OUTPUT_FORMAT, PAYLOAD, PRINT_JSON,
        RULES, SHOW_SUMMARY, STRUCTURED, VERBOSE,
    };
    use cfn_guard::utils::reader::ReadBuffer::Cursor as ReadCursor;
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
    use clap::Parser;

    use crate::utils::{
        capture_both_streams, get_full_path_for_resource_file, sanitize_junit_writer,
        sanitize_sarif_writer, Command, CommandTestRunner, StatusCode,
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

    /// One rules text over one document through the payload form of `validate` with
    /// `--show-summary all`: the exit code and the stripped stdout. The null-entry tests share it, so
    /// their cells differ only in what they assert, never in how the run is made.
    fn run_payload(rule: &str, document: &str) -> (i32, String) {
        let payload = format!(
            r#"{{"data": [{}], "rules": [{}]}}"#,
            serde_json::to_string(document).unwrap(),
            serde_json::to_string(rule).unwrap()
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .payload()
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);
        (
            status_code,
            writer.stripped().expect("failed to read stdout"),
        )
    }

    /// `run_payload` with the summary off (`--show-summary none`): the console output is the findings
    /// alone, so a line that carries a record's sentence is a finding's and never the summary's quote of
    /// the same record. `output_format` is the `-o` value, `None` for the console; `Some("json")` gives
    /// the same run's report, whose `error_message` strings are the records' sentences as recorded.
    fn run_payload_without_summary(
        rule: &str,
        document: &str,
        output_format: Option<&str>,
    ) -> (i32, String) {
        let payload = format!(
            r#"{{"data": [{}], "rules": [{}]}}"#,
            serde_json::to_string(document).unwrap(),
            serde_json::to_string(rule).unwrap()
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .payload()
            .output_format(output_format)
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);
        (
            status_code,
            writer.stripped().expect("failed to read stdout"),
        )
    }

    /// The status the summary printed for `rule`, read from the rule's own line.
    ///
    /// A summary line is the rules file's path, `/`, the rule's name, whitespace, and the status, and
    /// nothing else. Matching the line is what makes the answer about that rule: `contains("main")`
    /// is satisfied by the name inside another rule's line, a path, or a message, so a check that a
    /// rule was reported as passing could be met by a file that never ran it.
    fn rule_status_line(output: &str, rule: &str) -> Option<String> {
        let suffix = format!("/{}", rule);
        output.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next()) {
                (Some(path), Some(status), None) if path.ends_with(&suffix) => {
                    Some(status.to_string())
                }
                _ => None,
            }
        })
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
    // `malformed-rule.guard` parses; every clause reads `%s3_buckets_server_side_encryption_2` and
    // nothing declares it with a `let`. That is the rules author's mistake, so it is `PARSING_ERROR`
    // -- the name this repository gives 5 -- and not `INTERNAL_FAILURE`, which is -1 and means
    // cfn-guard broke. This case asserted -1, so it encoded the defect rather than the requirement:
    // forgetting a `let` is a common mistake, and being told the tool is broken sends the author
    // looking in the wrong place.
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["malformed-rule.guard"], StatusCode::PARSING_ERROR)]
    // The four cases below name a data file whose *content* cannot be read -- malformed, or holding
    // no document. That is the user's input, so they are `PARSING_ERROR` for the same reason the
    // undeclared-variable case above is: 5 is not 19, so a gate still tells it from a violation, and
    // unlike -1 it does not claim cfn-guard broke. The two `dne` cases keep -1, because a path that
    // does not exist is a different failure and validate, test and parse-tree already agree on it.
    #[case(vec!["malformed-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::PARSING_ERROR)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["blank-rule.guard"], StatusCode::SUCCESS)]
    #[case(
        vec!["s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["s3_bucket_server_side_encryption_enabled_2.guard", "blank-rule.guard"],
        StatusCode::VALIDATION_ERROR
    )]
    #[case(vec!["blank-template.yaml"], vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::PARSING_ERROR)]
    #[case(
        vec!["blank-template.yaml", "s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["s3_bucket_server_side_encryption_enabled_2.guard"], StatusCode::PARSING_ERROR)]
    #[case(vec!["dne.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["data-dir/s3-public-read-prohibited-template-non-compliant.yaml"], vec!["dne.guard"], StatusCode::INTERNAL_FAILURE)]
    #[case(vec!["blank.yaml"], vec!["rules-dir/s3_bucket_public_read_prohibited.guard"], StatusCode::PARSING_ERROR)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["comments.guard"], StatusCode::SUCCESS)]
    #[case(vec!["s3-server-side-encryption-template-non-compliant-2.yaml"], vec!["comments.guard"], StatusCode::SUCCESS)]
    // A rule whose only check compares against a reference that resolved to no values must
    // not reach a successful exit: a SKIP from the comparison, carried up as the file status
    // and out as exit 0, would enforce nothing. Exit code rather than reported status is the
    // assertion that matters here, because 0 is what a CI gate reads, and SKIP and PASS are
    // indistinguishable from outside the process.
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
    // A type block written for a CloudFormation module, `My::Org::Mod::MODULE { .. }`, selects the
    // resources whose `Type` is that full string. The parser keeps the `::MODULE` suffix in the name,
    // so the block's `Type ==` filter looks for `My::Org::Mod::MODULE` and not for `My::Org::Mod`: a
    // violating module resource is selected and the rule exits 19 rather than 0 as SKIP.
    #[case(
        vec!["module-type-template.yaml"],
        vec!["module_type_block.guard"],
        StatusCode::VALIDATION_ERROR
    )]
    // The control for the row above: the same block does not select a resource of the bare type.
    #[case(
        vec!["bare-type-template.yaml"],
        vec!["module_type_block.guard"],
        StatusCode::SUCCESS
    )]
    // A built-in function written as a bare clause is refused when the file is parsed, whether or not
    // the clause would have run. This file puts the clause behind a `when` the template does not
    // satisfy: a refusal at evaluation time would never reach it, and the file would exit 0 as SKIP
    // with the mistake unreported.
    #[case(
        vec!["s3-server-side-encryption-template-non-compliant-2.yaml"],
        vec!["builtin_function_behind_an_unmatched_when.guard"],
        StatusCode::PARSING_ERROR
    )]
    // A quoted key that begins with `%`, written `."%foo"` or `["%foo"]`, is the key it spells. Both
    // parse to a different part than the variable reference `%foo`; read as that reference, the run
    // would look for a variable named `foo` and exit 5 ("Could not resolve variable by name foo
    // across scopes").
    #[case(
        vec!["quoted-keys-template.json"],
        vec!["quoted_key_starting_with_a_percent_sign.guard"],
        StatusCode::SUCCESS
    )]
    // Two controls: a quoted key that does not start with `%` was always a key, and `%foo` is still a
    // variable, interpolated into the key it names.
    #[case(
        vec!["quoted-keys-template.json"],
        vec!["quoted_key_with_a_space.guard"],
        StatusCode::SUCCESS
    )]
    #[case(
        vec!["quoted-keys-template.json"],
        vec!["variable_interpolated_key.guard"],
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

    /// A rules file whose first three bytes are the UTF-8 byte order mark exits the way the same file
    /// without them does. The mark is a character no terminal shows, so a parse error at "line 1 at
    /// column 1" would name a fragment that reads identically to the one that parses.
    /// `byte-order-mark.guard` is the three bytes followed by `rule r { Resources exists }`;
    /// `comments.guard` is the control that passes against the same template without a mark.
    #[test]
    fn a_rules_file_starting_with_a_byte_order_mark_is_read_like_one_without() {
        for rules in ["byte-order-mark.guard", "comments.guard"] {
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .data(vec![
                    "s3-server-side-encryption-template-non-compliant-2.yaml",
                ])
                .rules(vec![rules])
                .run(&mut writer, &mut Reader::default());
            assert_eq!(
                StatusCode::SUCCESS,
                status_code,
                "{rules}: {}",
                writer.err_to_stripped().expect("failed to read stderr")
            );
        }
    }

    /// A byte order mark that is not at the start of the file stays an error, and the error names it.
    /// The position is the mark's own, so an author can find a character no editor displays.
    #[test]
    fn a_byte_order_mark_inside_a_rules_file_is_named_in_the_error() {
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .data(vec![
                "s3-server-side-encryption-template-non-compliant-2.yaml",
            ])
            .rules(vec!["byte-order-mark-mid-file.guard"])
            .run(&mut writer, &mut Reader::default());
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains("byte order mark") && stderr.contains("line 2 at column 1"),
            "the message must name the mark and where it is, got: {}",
            stderr
        );
    }

    /// `1: foo` and `1.0: foo` are not errors: a scalar key becomes the text CloudFormation would give
    /// it, because a template is converted to JSON before deployment and JSON has no key but a string.
    /// `a_scalar_key_becomes_the_text_cloudformation_would_give_it` pins the text each one produces.
    /// The cases here are the set with no text to produce: a null key, a sequence key, and a document
    /// that does not parse at all.
    #[rstest::rstest]
    #[case("SSEAlgorithm: {{CRASH}}")]
    #[case("~:")]
    #[case("[1, 2, 3]: foo")]
    fn test_graceful_handling_when_yaml_file_has_non_string_type_key(#[case] input: &str) {
        let bytes = input.as_bytes();
        let mut reader = Reader::new(ReadCursor(Cursor::new(bytes.to_vec())));
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["s3_bucket_server_side_encryption_enabled_2.guard"])
            .run(&mut writer, &mut reader);

        // `PARSING_ERROR`, not `INTERNAL_FAILURE`. A key cfn-guard cannot model is the template
        // author's mistake, and -1 is the code this repository reserves for cfn-guard breaking.
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
    }

    /// A data file with no document in it -- nothing but comments -- is reported as empty, the way an
    /// empty file and a whitespace-only file are. This asserts the message as well as the exit code:
    /// the requirement is that a file holding no document is reported the same way one holding no
    /// bytes is, not merely that it fails somehow.
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

        // The code and the message both move, together. An empty data file is the user's input, so
        // it is `PARSING_ERROR` rather than `INTERNAL_FAILURE`; and once `validate` has decided the
        // failure is not internal, `main`'s "Error occurred" prefix -- its vocabulary for an
        // unexpected failure -- no longer describes it, so the command reports it itself.
        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        assert_eq!(
            "Parser Error when parsing `Unable to parse a template from data file: STDIN is empty`\n",
            writer.err_to_stripped().expect("failed to read stderr")
        );
    }

    /// A data file the user named is read whatever it is called.
    ///
    /// `--data` fed every argument through `walk_dir` and then through the extension filter, and
    /// `walkdir` on a plain file yields that one file, so a file named as an argument was filtered
    /// as though a walk had discovered it. A name outside the five recognised suffixes was dropped,
    /// the run had no data left, `evaluate_against_data_input` iterated an empty list and returned
    /// PASS, and the process exited 0 having written nothing to any channel. A template that
    /// violates the rule reported compliance because of what it was called.
    ///
    /// Exit code is the assertion that matters, because 0 is what a CI gate reads. The output checks
    /// are here so that a run exiting 19 for an unrelated reason cannot satisfy this.
    #[test]
    fn an_explicitly_named_data_file_is_read_whatever_its_extension() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["unsupported-extension-template.txt"])
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the template violates the rule, and naming the file is the user asking for it to be read"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("unsupported-extension-template.txt"),
            "the file that was read is named in the report:\n{}",
            output
        );
        assert!(
            output.contains("encrypted_is_true"),
            "and the rule it violated is reported:\n{}",
            output
        );
    }

    /// A directory walk evaluates the data files it recognises and passes over the rest.
    ///
    /// The counterpart to the test above. The extension filter is a discovery heuristic and it still
    /// governs directory arguments, which is what `--data`'s help text documents and what the
    /// `dummy.txt` fixtures in data-dir/ and rules-dir/ exist to pin. Without this half, reading an
    /// explicitly named file whatever its extension is also satisfied by reading every file a walk
    /// finds, which would try to load every README and lockfile sitting in a data directory.
    ///
    /// `mixed-extension-dir/README.md` is deliberately not loadable as YAML, so a walk that stopped
    /// skipping it would fail this test outright rather than merely add a line to the output.
    #[test]
    fn a_directory_walk_evaluates_the_templates_and_passes_over_unrelated_files() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["mixed-extension-dir"])
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both templates in the directory violate the rule"
        );

        assert_output_from_str_eq!(
            indoc! {r#"
                template.json Status = FAIL
                FAILED rules
                encrypted_is_true.guard/encrypted_is_true    FAIL
                ---
                Evaluation of rules encrypted_is_true.guard against data template.json
                --
                Property [/Resources/B/Properties/Encrypted] in data [template.json] is not compliant with [encrypted_is_true] because provided value [false] did not match expected value [true]. Error Message []
                --
                template.yaml Status = FAIL
                FAILED rules
                encrypted_is_true.guard/encrypted_is_true    FAIL
                ---
                Evaluation of rules encrypted_is_true.guard against data template.yaml
                --
                Property [/Resources/B/Properties/Encrypted] in data [template.yaml] is not compliant with [encrypted_is_true] because provided value [false] did not match expected value [true]. Error Message []
                --
            "#},
            writer
        );
    }

    /// A file whose extension is recognised but whose content will not load still fails loudly.
    ///
    /// Reading explicitly-named files widened what reaches the loader, so the loud path has to stay
    /// loud: a data file that cannot be parsed aborts the run with the parse error rather than being
    /// treated as absent. This pins the message as well as the exit code, because a run that failed
    /// for some other reason would satisfy the code on its own.
    #[test]
    fn a_recognised_extension_with_unloadable_content_still_fails_loudly() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["malformed-template.yaml"])
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a data file that will not load aborts the run, as the user's mistake rather than ours"
        );

        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            err.contains("Error encountered while parsing data file"),
            "and says on stderr that it could not parse the file:\n{}",
            err
        );
        assert!(
            err.contains("malformed-template.yaml"),
            "naming the file it could not parse:\n{}",
            err
        );
        assert!(
            err.contains(" at L:") && !err.contains("data beginning with"),
            "and says where the parser stopped, in place of the excerpt of the file:\n{}",
            err
        );
    }

    /// A YAML template with a syntax error names the line and the column of the error, and prints no
    /// excerpt of the file.
    ///
    /// The loader's message names what the parser expected and where it stopped, the way the loader
    /// reports every other position. An excerpt of the file's first hundred bytes would add nothing
    /// to it: for an error on the fifth line of a template it shows the comment at the top and nothing
    /// near the mistake.
    #[test]
    fn a_yaml_template_with_a_syntax_error_names_its_line_and_column_without_an_excerpt() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["syntax-error-on-the-fifth-line-template.yaml"])
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            err.contains("syntax-error-on-the-fifth-line-template.yaml")
                && err.contains("mapping values are not allowed in this context at L:5,C:17")
                && !err.contains("data beginning with"),
            "the refusal names the file, the line and the column, and shows no excerpt:\n{}",
            err
        );
    }

    /// A JSON template that is not JSON is refused with libyaml's position, and the JSON reader's
    /// line and column follow when that reader read as far.
    ///
    /// JSON is read through the YAML loader, which describes a missing comma between two members as
    /// "did not find expected ',' or '}'" in a flow mapping, at the member that follows the gap. The
    /// JSON reader stops at the same member, so its line and column are appended for the author who
    /// wrote JSON, labeled as the JSON reader's.
    #[test]
    fn a_json_template_missing_a_comma_is_refused_with_the_json_readers_position() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["missing-comma-template.json"])
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            err.contains("missing-comma-template.json")
                && err.contains("did not find expected ',' or '}' at L:5,C:7")
                && err.contains("Read as JSON as well, the text fails with")
                && err.contains("line 5 column 7"),
            "the refusal names the file, libyaml's position and the JSON reader's:\n{}",
            err
        );
    }

    /// A template in YAML flow style with a mistake is refused with libyaml's position, and nothing
    /// from a JSON reader.
    ///
    /// Flow style begins with `{` as a JSON object does, and a JSON reader stops at the first unquoted
    /// key, which is valid YAML and not the mistake. libyaml stops where the closing brace is missing,
    /// at the end of the text, and that is the one position shown, with no excerpt of the file.
    #[test]
    fn a_flow_style_template_with_a_mistake_is_refused_at_libyamls_position_alone() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["flow-style-missing-brace-template.yaml"])
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            err.contains("flow-style-missing-brace-template.yaml")
                && err.contains("did not find expected ',' or '}' at L:2,C:1")
                && !err.contains("JSON")
                && !err.contains("data beginning with"),
            "libyaml's position, nothing from the JSON reader, and no excerpt:\n{}",
            err
        );
    }

    /// A run that evaluated no data at all says so on stderr.
    ///
    /// A directory holding nothing a walk recognises leaves the run with an empty data list, and an
    /// empty list yields no findings, no output and exit 0 -- indistinguishable from a run in which
    /// every file complied. The notice names each file passed over and states that nothing was
    /// checked.
    ///
    /// The exit code is still 0. Whether a run that checked nothing should fail is a separate
    /// question, because changing it moves the result for everyone pointing `--data` at a directory
    /// of mixed content. Asserting 0 here records that the current answer is deliberate rather than
    /// overlooked, so that changing it has to change this test too.
    #[test]
    fn a_run_that_evaluates_no_data_says_so() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["only-unrelated-files-dir"])
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "a run that evaluated nothing exits 0; the notice goes to stderr, not the exit code"
        );

        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            err.contains("no data files were evaluated"),
            "a run that checked nothing has to say so:\n{}",
            err
        );
        assert!(
            err.contains("README.md"),
            "and name what it passed over, so the reader can tell why:\n{}",
            err
        );
    }

    /// A gate written `== true` has to fire for every spelling YAML makes boolean, because when it
    /// does not fire the body never runs and the process exits 0 having checked nothing. Against a
    /// bucket with `Encrypted: false`, `PublicAccess: true` exited 19 and caught the violation
    /// while `PublicAccess: True` and `TRUE` exited 0 and left it unchecked.
    ///
    /// The set is the YAML 1.2 core schema's six spellings, which is also what
    /// `rules::parser::parse_bool` accepts for a literal written in a rule. YAML 1.1's `yes`, `on`,
    /// `y` and their false counterparts are strings here, and they live in
    /// `test_a_non_boolean_string_is_still_not_comparable_to_a_boolean` below, which asserts the
    /// reported reason. They cannot sit here even with the expectation set to SUCCESS: `no` and
    /// `off` exit 0 because the comparison is *undecidable*, not because the gate evaluated *false*,
    /// so a case asserting only the exit code would pass for a reason it does not name.
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
    #[case::lowercase_false("false", StatusCode::SUCCESS)]
    #[case::capitalized_false("False", StatusCode::SUCCESS)]
    #[case::uppercase_false("FALSE", StatusCode::SUCCESS)]
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

    /// The control for the case above, and the reason the set is six spellings rather than anything
    /// that looks like one. A scalar YAML resolves to a string stays a string and stays incomparable
    /// to a boolean, so the boolean set does not quietly answer comparisons that have no answer.
    /// Asserting the reported reason and not only the exit code is what separates this from a clause
    /// that failed on the merits -- which is exactly the distinction the YAML 1.1 spellings need,
    /// since `PublicAccess: no` makes this clause undecidable rather than deciding it false, and
    /// both exit 0.
    #[rstest::rstest]
    #[case::mixed_case_true("tRuE")]
    #[case::a_word_outside_the_set("enabled")]
    #[case::yaml_1_1_yes("yes")]
    #[case::yaml_1_1_yes_uppercase("YES")]
    #[case::yaml_1_1_on("on")]
    #[case::yaml_1_1_y("y")]
    #[case::yaml_1_1_no("no")]
    #[case::yaml_1_1_off("off")]
    #[case::yaml_1_1_n("n")]
    #[case::yaml_1_1_n_uppercase("N")]
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

    /// Run one rules file against one data file with `--show-summary all` and return the summary's
    /// verdict for every rule named in `expected`, as `(rule, got, wanted)` disagreements, together
    /// with the exit code and the output.
    ///
    /// The summary prints one `<rules file>/<rule>  <STATUS>` line per rule, the status column padded
    /// to align, so a rule's verdict is read from its own line -- the two whitespace-separated
    /// tokens -- rather than inferred from the exit code, which can only say whether *some* rule
    /// failed.
    struct Run {
        status_code: i32,
        stdout: String,
        /// Where the evaluator's notices go.
        stderr: String,
        /// One `<rule>: wanted <status>, got <status>` line per expected rule whose summary line
        /// disagrees or is missing.
        disagreed: Vec<String>,
    }

    /// One `validate --show-summary all` of `rules` against `data`, with both channels captured, so a
    /// notice on stderr is observable beside the verdicts on stdout. Each rule's verdict is read from
    /// its own summary line through `rule_status_line`.
    fn rule_verdicts(data: &str, rules: &str, expected: &[(&str, &str)]) -> Run {
        let (status_code, output, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![data])
                .rules(vec![rules])
                .show_summary(vec!["all"])
                .run(writer, reader)
        });

        let disagreed = expected
            .iter()
            .filter_map(|(rule, status)| {
                let got = rule_status_line(&output, rule);
                (got.as_deref() != Some(*status)).then(|| {
                    format!(
                        "{}: wanted {}, got {}",
                        rule,
                        status,
                        got.unwrap_or_default()
                    )
                })
            })
            .collect();
        Run {
            status_code,
            stdout: output,
            stderr,
            disagreed,
        }
    }

    /// `.*`, `[ filter ]` and `[ keys ... ]` after a `%var` key evaluate as they do after a literal
    /// key, and the two rules files here are the same three clauses in the two spellings.
    ///
    /// The interpolated file exited 19 with every rule reported as a block failure carrying
    /// "variable interpolation is not supported", which is the wrong channel twice over: a shape the
    /// evaluator cannot walk is a problem with the rule, not a violation in the template, and exit 19
    /// is what a CI gate reads as a violation. Each rule's verdict is read from its summary line and
    /// has to be the literal spelling's; the refusal text is asserted absent so that a future
    /// refusal cannot hide behind a verdict it happens to share.
    ///
    /// `[ x == 1 ]` after the key is a filter over one map that names the map's own key and selects
    /// nothing: the misreading `a_key_filter_over_a_member_is_refused` pins, refused at the clause in
    /// both spellings, so both files fail that rule and exit 19 for that reason alone. The refusal
    /// is read from each file's report, since the verdict could be shared by a refusal on the wrong
    /// channel.
    #[rstest::rstest]
    #[case::interpolated_key(
        "tags_by_interpolated_key.guard",
        &[
            ("all_values_after_interpolated_key", "PASS"),
            ("filter_after_interpolated_key", "FAIL"),
            ("key_filter_after_interpolated_key", "PASS"),
        ]
    )]
    #[case::literal_key(
        "tags_by_literal_key.guard",
        &[
            ("all_values_after_literal_key", "PASS"),
            ("filter_after_literal_key", "FAIL"),
            ("key_filter_after_literal_key", "PASS"),
        ]
    )]
    fn a_part_after_an_interpolated_key_evaluates_as_after_a_literal_one(
        #[case] rules: &str,
        #[case] expected: &[(&str, &str)],
    ) {
        let Run {
            status_code,
            stdout: output,
            disagreed,
            ..
        } = rule_verdicts("tags-by-key-template.yaml", rules, expected);

        assert!(
            !output.contains("variable interpolation is not supported"),
            "{} was refused rather than evaluated:\n{}",
            rules,
            output
        );
        assert!(
            disagreed.is_empty(),
            "{}: {} rules disagree:\n  {}\n{}",
            rules,
            disagreed.len(),
            disagreed.join("\n  "),
            output
        );
        // The one failing rule is the filter over one map naming the map's own key, refused in the
        // report with the spellings that test the map's property and the key they stand for; a FAIL
        // reached any other way would be a different defect sharing the verdict.
        assert!(
            output.contains("selected nothing among the map's own entries")
                && output.contains("`Key` is `x`, a key of the map itself. Write")
                && output.contains("Write `X[*] { Key == value }` or `X[*].Key == value`"),
            "{}: the failing rule is not the refused filter:\n{}",
            rules,
            output
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{}:\n{}",
            rules,
            output
        );
    }

    /// A filter directly after a part that names a collection selects among its entries; directly
    /// after a part that names one value, it tests that value.
    ///
    /// The indexed file is the spellings that select among entries -- an index, `this`, a chained
    /// filter, a numeric key, the entry a key filter selected -- beside the ones that are closed: a
    /// filter over a scalar named by a key, and a capture where nothing binds it. The wildcard file
    /// holds each one's `[*]`, `.*` or literal-key counterpart, and each pair has to agree verdict for
    /// verdict. Verdicts are read per rule from the summary lines, since both files hold rules that
    /// are meant to fail and the exit code says only that.
    #[rstest::rstest]
    #[case::indexed_this_and_chained(
        "rules_indexed_then_filtered.guard",
        &[
            ("index_then_filter", "PASS"),
            ("index_then_filter_then_key", "PASS"),
            ("index_then_filter_rejects", "SKIP"),
            ("numeric_key_then_filter", "PASS"),
            ("filter_then_filter", "PASS"),
            ("this_over_the_collection", "FAIL"),
            // Both `this[ f ]` clauses over a member map name a key of the member and select
            // nothing: the misreading `a_this_filter_over_a_member_is_refused` pins, refused at the
            // clause rather than left to SKIP.
            ("this_over_a_member", "FAIL"),
            ("this_in_a_wildcard_block_over_members", "FAIL"),
            ("index_then_filter_on_a_scalar", "PASS"),
            ("index_then_filter_rejects_a_scalar", "SKIP"),
            ("key_then_filter_on_a_scalar", "FAIL"),
            ("key_filter_then_filter_on_scalar_entries", "SKIP"),
            ("key_filter_then_filter_on_the_selected_entry", "PASS"),
            ("key_filter_then_filter_rejects_the_selected_entry", "SKIP"),
            ("key_filter_matching_two_keys_then_filter", "PASS"),
            ("negated_rule_reference_in_a_filter", "SKIP"),
        ]
    )]
    #[case::wildcard_and_literal_key_controls(
        "rules_wildcard_then_filtered.guard",
        &[
            ("wildcard_then_filter", "PASS"),
            ("wildcard_then_filter_then_key", "PASS"),
            ("wildcard_then_filter_rejects", "SKIP"),
            ("key_over_the_collection", "FAIL"),
            // The key spelling of the misreading the indexed file's `this_over_a_member` pins: a
            // filter over one map that names the map's own key and selects nothing, refused at the
            // clause rather than left to SKIP (`a_key_filter_over_a_member_is_refused`).
            ("key_over_a_member", "FAIL"),
            ("the_members_property_in_a_wildcard_block", "FAIL"),
            ("wildcard_then_filter_on_a_scalar", "PASS"),
            ("wildcard_then_filter_rejects_a_scalar", "SKIP"),
            ("dot_wildcard_then_filter_on_a_scalar", "PASS"),
            ("dot_wildcard_then_filter_rejects_a_scalar", "SKIP"),
            ("dot_wildcard_then_filter_on_scalar_entries", "FAIL"),
            ("capture_after_a_key", "PASS"),
            ("rule_reference_in_a_filter", "PASS"),
            ("negated_rule_reference_as_a_gate", "PASS"),
        ]
    )]
    // Over a list `this` names the collection in hand as a key does, so a capture after it binds
    // the selected member and the clause after it reads that member; the key spelling over the same
    // list is each rule's control, and the file decides its verdict at 19 rather than stopping at 5.
    #[case::capture_after_this_over_a_list(
        "rules_capture_after_this_over_a_list.guard",
        &[
            ("capture_after_this_over_a_list", "PASS"),
            ("capture_after_this_over_a_list_tests_the_bound_member", "FAIL"),
            ("capture_after_a_key_over_the_same_list", "PASS"),
            ("capture_after_a_key_over_the_same_list_tests_the_bound_member", "FAIL"),
        ]
    )]
    fn a_filter_selects_among_a_collection_and_tests_a_member(
        #[case] rules: &str,
        #[case] expected: &[(&str, &str)],
    ) {
        let Run {
            status_code,
            stdout: output,
            disagreed,
            ..
        } = rule_verdicts("rules-indexed-then-filtered-template.yaml", rules, expected);

        assert!(
            !output.contains("applies a filter directly"),
            "{} was refused rather than evaluated:\n{}",
            rules,
            output
        );
        assert!(
            disagreed.is_empty(),
            "{}: {} rules disagree:\n  {}\n{}",
            rules,
            disagreed.len(),
            disagreed.join("\n  "),
            output
        );
        // Both files hold a rule that is meant to fail, so the file verdict is a failure either way.
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{}:\n{}",
            rules,
            output
        );
    }

    /// The capture refusal names the capture, so the author is told which name went unbound rather
    /// than later being told it cannot be resolved. After an index, as after `this`, the value the
    /// template puts there decides whether the position binds -- `Rules[0]` binds when it is a list
    /// -- so the refusal is a verdict on the clause, which fails, and the run goes on at 19 rather
    /// than stopping at 5 and dropping every other rule's verdict.
    #[test]
    fn a_capture_after_a_part_that_names_one_value_is_refused_by_name() {
        let Run {
            status_code,
            stdout,
            stderr,
            disagreed,
        } = rule_verdicts(
            "rules-indexed-then-filtered-template.yaml",
            "rules_capture_after_an_index.guard",
            &[("capture_after_an_index", "FAIL")],
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a capture declared where the template's value binds nothing fails its clause and the run \
             goes on:\n{}\n{}",
            stdout,
            stderr
        );
        assert!(
            disagreed.is_empty(),
            "the clause is held and the rule fails:\n  {}\n{}",
            disagreed.join("\n  "),
            stdout
        );
        assert!(
            !stdout.contains("Types or variable assignments are incompatible"),
            "the refusal is the template's, not reported as a rules-file incompatibility:\n{}",
            stdout
        );
        assert!(
            stdout.contains("declares the capture `nm` after a part that names one value"),
            "the refusal does not name the capture:\n{}\n{}",
            stdout,
            stderr
        );
    }

    /// A capture after `this` binds over a list and is held at the clause over a map, and the same
    /// rules file decides which on each template rather than stopping on one of them.
    ///
    /// Over the template whose `Rules` is a list, the capture binds and the rule passes beside its
    /// key-spelling control. Over the template whose `Rules` is an intrinsic -- `!If`, which the
    /// loader keeps as a map with one `Fn::If` entry -- there is nothing to bind: the clause fails,
    /// naming the capture and the kind of value found, the key spelling over the same map is simply
    /// evaluated, and the third rule is still reported, so the file exits 19. A refusal that stopped
    /// the run at 5 here would make one template's shape decide whether any other rule in the file is
    /// heard from.
    #[rstest::rstest]
    #[case::rules_is_a_list(
        "rules-indexed-then-filtered-template.yaml",
        StatusCode::SUCCESS,
        "PASS",
        false
    )]
    #[case::rules_is_a_map_under_fn_if(
        "rules-under-fn-if-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "FAIL",
        true
    )]
    fn a_capture_after_this_binds_over_a_list_and_is_held_at_the_clause_over_a_map(
        #[case] template: &str,
        #[case] expected_code: i32,
        #[case] capture_verdict: &str,
        #[case] refused: bool,
    ) {
        let Run {
            status_code,
            stdout,
            stderr,
            disagreed,
        } = rule_verdicts(
            template,
            "rules_capture_after_this.guard",
            &[
                ("CAPTURE_AFTER_THIS_OVER_RULES", capture_verdict),
                ("OTHER_RULE_STILL_REPORTED", "PASS"),
            ],
        );

        assert_eq!(
            expected_code, status_code,
            "{}: the run decides at the clause and goes on:\n{}\n{}",
            template, stdout, stderr
        );
        assert!(
            disagreed.is_empty(),
            "{}: {} rules disagree:\n  {}\n{}",
            template,
            disagreed.len(),
            disagreed.join("\n  "),
            stdout
        );
        assert_eq!(
            refused,
            stdout.contains(
                "declares the capture `r` after `this`, which is not supported over a map"
            ),
            "{}: the refusal names the capture and the kind only where nothing binds:\n{}",
            template,
            stdout
        );
        // The key spelling over the same value is evaluated, whatever it decides: it has a summary
        // line, and the only refusal in the report is the one after `this`, so the key spelling
        // raised none of its own.
        assert!(
            rule_status_line(&stdout, "CONTROL_CAPTURE_AFTER_THE_KEY").is_some(),
            "{}: the key spelling was not evaluated:\n{}",
            template,
            stdout
        );
        assert_eq!(
            usize::from(refused),
            stdout.matches("declares the capture").count(),
            "{}: a refusal other than the one after `this` was reported:\n{}",
            template,
            stdout
        );
    }

    /// The evaluator's notices reach stderr. A filter after a key that holds a scalar announces its
    /// refusal there, naming the path. A `this[ f ]` inside a block that selects nothing while asking
    /// about a key `this` has is refused at the clause (`a_this_filter_over_a_member_is_refused`), not
    /// explained there as a warning, so the indexed file's two such clauses write no warning, and the
    /// control file, which has neither, writes nothing.
    #[rstest::rstest]
    #[case::a_scalar_under_a_key("rules_indexed_then_filtered.guard", true)]
    #[case::neither("rules_wildcard_then_filtered.guard", false)]
    fn the_evaluators_notices_reach_stderr(#[case] rules: &str, #[case] expected: bool) {
        let stderr = rule_verdicts("rules-indexed-then-filtered-template.yaml", rules, &[]).stderr;

        let deprecation = "DEPRECATION:";
        assert_eq!(
            expected,
            stderr.contains(deprecation),
            "{}: stderr was:\n{}",
            rules,
            stderr
        );
        assert!(
            !stderr.contains("Warning:"),
            "{}: a `this[ f ]` over a member is refused, not warned about:\n{}",
            rules,
            stderr
        );
        if expected {
            // `key_then_filter_on_a_scalar` is the one clause filtering after a key that holds a
            // scalar, and it is the only notice the file produces.
            assert_eq!(
                1,
                stderr
                    .lines()
                    .filter(|l| l.starts_with(deprecation))
                    .count(),
                "one notice line in the file:\n{}",
                stderr
            );
            assert_eq!(
                1,
                stderr
                    .lines()
                    .filter(|l| {
                        l.starts_with(deprecation) && l.contains("/Resources/B1/Properties/Scalar")
                    })
                    .count(),
                "one deprecation line naming the scalar's path:\n{}",
                stderr
            );
        }
    }

    /// A `this[ f ]` over a member map whose own key the predicate names selects nothing and is
    /// refused: every such clause fails, the file exits 19, the refusal in the report names the two
    /// spellings that test the member, and nothing goes to stderr.
    ///
    /// `Rules[0] { this[ Action == 'allow' ] exists }` reads as "the first rule, when its action is
    /// allow", and it is not that: inside the block `this` is the rule, a map, so the filter selects
    /// among the rule's own entries, and `Action == 'allow'` holds on none of them. Before this the
    /// clause was not applicable, the file exited 0, and the explanation went to stderr as a warning,
    /// which a CI gate reading the exit code never saw. The template-side refusal is held at the
    /// clause, so the rule beside the five misreadings is still decided and the file is still reported.
    ///
    /// The spellings are asserted per refused rule, on the explanation line under that rule's own
    /// entry in the "Could not be evaluated" section, not on the output as a whole: one rule carrying
    /// both spellings would satisfy a whole-output check while another lost them.
    #[test]
    fn a_this_filter_over_a_member_is_refused() {
        const REFUSED: [&str; 5] = [
            "this_over_a_member",
            "this_over_a_member_negated",
            "this_in_a_wildcard_block_over_members",
            "this_over_a_resource_whose_type_the_predicate_names",
            "this_over_properties_with_a_long_key",
        ];
        let Run {
            status_code,
            stdout,
            stderr,
            disagreed,
        } = rule_verdicts(
            "this-filter-over-a-member-template.yaml",
            "this_filter_over_a_member.guard",
            &[
                ("this_over_a_member", "FAIL"),
                ("this_over_a_member_negated", "FAIL"),
                ("this_in_a_wildcard_block_over_members", "FAIL"),
                (
                    "this_over_a_resource_whose_type_the_predicate_names",
                    "FAIL",
                ),
                ("this_over_properties_with_a_long_key", "FAIL"),
                ("beside_them_and_decided", "PASS"),
            ],
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a refused clause is a failed clause, which a gate reads from the exit code:\n{}\n{}",
            stdout,
            stderr
        );
        assert!(
            disagreed.is_empty(),
            "{} rules disagree:\n  {}\n{}",
            disagreed.len(),
            disagreed.join("\n  "),
            stdout
        );

        // Per rule: the first explanation line under `  <rule>: ...` in the "Could not be evaluated"
        // section carries the lead sentence and both spellings.
        let lines: Vec<&str> = stdout.lines().collect();
        for rule in REFUSED {
            let header = format!("  {}: ", rule);
            let explanation = lines
                .iter()
                .position(|line| line.starts_with(&header))
                .and_then(|at| lines.get(at + 1))
                .unwrap_or_else(|| {
                    panic!(
                        "{}: no entry under \"Could not be evaluated\":\n{}",
                        rule, stdout
                    )
                });
            assert!(
                explanation.contains("`this[ ... ]` selected nothing among the member's own entries")
                    && explanation.contains("Write `{ Key == value }` in the block")
                    && explanation.contains("`X[*] { Key == value }`")
                    && explanation.contains("`X[*].Key == value`")
                    && explanation.contains("with `X` the member's query")
                    && explanation.contains("a key of the member"),
                "{}: its explanation line does not carry the refusal with the in-block spelling, both collection spellings and the definitions:\n{}\n\n{}",
                rule,
                explanation,
                stdout
            );
        }
        assert!(
            !stderr.contains("Warning:") && !stderr.contains("DEPRECATION:"),
            "the refusal is the report's, not a notice:\n{}",
            stderr
        );
    }

    /// The key spelling of the misreading above: `Resources.B1[ Type == 'AWS::S3::Bucket' ] exists`
    /// reads as "B1, when it is a bucket", and it is not that. `B1` is one map, so the filter selects
    /// among `B1`'s own entries, and `Type == ...` holds on none of them. Before this the clause was
    /// not applicable and the file exited 0 with nothing on either channel, so a rules file that
    /// checked nothing passed a gate. Now every such clause fails, the file exits 19, the refusal in
    /// the report names the two spellings that test the map and read one map and a list of them alike,
    /// with the query as written and the key read printed once after them, and nothing goes to stderr. The template-side refusal is held at the clause, so the rules beside the
    /// misreadings are still decided: the filter over the collection at the root and over a list,
    /// and the predicate naming a key the map lacks, keep their verdicts.
    #[test]
    fn a_key_filter_over_a_member_is_refused() {
        let Run {
            status_code,
            stdout,
            stderr,
            disagreed,
        } = rule_verdicts(
            "rules-indexed-then-filtered-template.yaml",
            "key_filter_over_a_member.guard",
            &[
                ("key_over_a_member", "FAIL"),
                ("key_over_a_member_negated", "FAIL"),
                ("key_over_a_map_of_scalars", "FAIL"),
                ("key_over_a_member_inside_a_block", "FAIL"),
                ("long_key_over_a_member", "FAIL"),
                ("the_predicate_names_a_key_the_member_lacks", "SKIP"),
                ("key_over_the_collection", "PASS"),
                ("key_over_a_list", "PASS"),
                ("beside_them_and_decided", "PASS"),
            ],
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a refused clause is a failed clause, which a gate reads from the exit code:\n{}\n{}",
            stdout,
            stderr
        );
        assert!(
            disagreed.is_empty(),
            "{} rules disagree:\n  {}\n{}",
            disagreed.len(),
            disagreed.join("\n  "),
            stdout
        );
        // The spellings and what `X` and `Key` stand for are read here, on the console summary, where
        // the author reads them, and not only in the JSON report. The key's definition comes first, the
        // spellings carry placeholders and the query is printed once after them.
        assert!(
            stdout.contains("The filter selected nothing among the map's own entries")
                && stdout.contains("`Key` is `Type`, a key of the map itself. Write")
                && stdout.contains("Write `X[*] { Key == value }` or `X[*].Key == value`")
                && stdout.contains("where `X` is `Resources.B1`, at path"),
            "the report does not carry the refusal with the key, both spellings and the definition of `X`:\n{}",
            stdout
        );
        assert!(
            stdout.contains("where `X` is `B1`, at path"),
            "inside a block the query is named relative to the block:\n{}",
            stdout
        );
        assert!(
            stdout.contains("`Key` is `Name`, a key of the map itself. Write")
                && stdout.contains("where `X` is `Resources.B1.Properties.Tags`, at path"),
            "the definitions survive the console clip for the longer query:\n{}",
            stdout
        );
        // The longest key a template is likely to name: a text that repeated the key in every spelling
        // would end the console clip inside them, with the definition of `X` cut off.
        assert!(
            stdout.contains(
                "`Key` is `ServerSideEncryptionConfiguration`, a key of the map itself. Write"
            ) && stdout
                .contains("where `X` is `Resources.B1.Properties.BucketEncryption`, at path"),
            "the spellings and the definitions survive the console clip for a long key:\n{}",
            stdout
        );
        assert!(
            !stderr.contains("Warning:") && !stderr.contains("DEPRECATION:"),
            "the refusal is the report's, not a notice:\n{}",
            stderr
        );
    }

    /// The evaluator's notices reach stderr in one order on every path: the deprecation notices, then
    /// the warnings in the order the evaluator recorded them.
    ///
    /// `two_argument_warnings.guard` has two key filters whose function argument is read from the map
    /// being filtered where the enclosing scope holds a different value, at line 3 and at line 13, each
    /// a warning, and between them a filter after a scalar key, which is a deprecation notice. (A
    /// `this[ ... ]` inside a block that selects nothing is not a warning on this tree: it is refused at
    /// the clause and writes nothing to stderr, so the warning the evaluator still writes is the one
    /// used.) Each warning ends with its clause's position, and sorted by text "line:13" comes before
    /// "line:3", so a store or a bucket sorted by text printed the later clause first, on every path:
    /// the scope's own set was sorted, so the single-line output printed 13 then 3 and the structured
    /// reporters, fed from that set, printed the same. A reader fixing the file works top down, which
    /// is the order the evaluator reached the clauses in. The single-line path writes the scope's
    /// deprecations and then its warnings; the structured path collects both kinds from every data
    /// file into one set of notices and writes them once, and it keeps to the same order: the
    /// deprecation notice, then line 3, then line 13, three lines, on the single-line path, with
    /// `-o json`, and with `--structured`.
    #[rstest::rstest]
    #[case::single_line(None, false)]
    #[case::json(Some("json"), false)]
    #[case::structured_json(Some("json"), true)]
    fn the_evaluators_notices_keep_one_order_on_every_path(
        #[case] output: Option<&str>,
        #[case] structured: bool,
    ) {
        let (status_code, stdout, stderr) = utils::capture_both_streams(|writer, reader| {
            let mut runner = ValidateTestRunner::default();
            let configured = runner
                .data(vec!["two-argument-warnings-template.yaml"])
                .rules(vec!["two_argument_warnings.guard"])
                .show_summary(vec!["none"])
                .output_format(output);
            let configured = if structured {
                configured.structured()
            } else {
                configured
            };
            configured.run(writer, reader)
        });
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{output:?} structured={structured}: the filter after a scalar key fails, the two key \
             filters pass:\n{stdout}\n{stderr}"
        );

        let order: Vec<String> = stderr
            .lines()
            .filter_map(|line| {
                if line.starts_with("DEPRECATION: the filter `[ this == 'x' ]` follows the key") {
                    Some("deprecation".to_string())
                } else if line
                    .starts_with("Warning: the function argument `Wanted` in a map key filter")
                {
                    line.rsplit_once("line:").map(|(_, tail)| {
                        format!("warning at line {}", tail.replace(", column:43].", ""))
                    })
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            vec![
                "deprecation".to_string(),
                "warning at line 3".to_string(),
                "warning at line 13".to_string(),
            ],
            order,
            "{output:?} structured={structured}: the deprecation notice first, then the warnings in \
             the order the clauses were evaluated, line 3 then line 13, not in text order:\n{stderr}"
        );
    }

    /// A duplicated key takes the last value. A reader going through a template top-down sees the
    /// first value and the tool judges the last, so without a diagnostic the document could present
    /// one posture and be evaluated on another with nothing to notice it by.
    ///
    /// The diagnostic names the path and both lines, because a warning that only says a key was
    /// duplicated does not tell anyone which of several thousand lines to look at. It fires once per
    /// duplicated key rather than once per document, which the two-duplicate case below pins.
    #[rstest::rstest]
    #[case::yaml(
        "Resources:\n  B:\n    Properties:\n      Encrypted: false\n      Encrypted: true\n",
        "L:4,C:7",
        "L:5,C:7"
    )]
    #[case::json(
        "{\"Resources\":{\"B\":{\"Properties\":{\"Encrypted\":false,\"Encrypted\":true}}}}",
        "L:1,C:34",
        "L:1,C:52"
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
        // The explanation has to reach its last sentence, which is the one that says what the `!empty`
        // guard would do. That guard is not a *remedy*, and the message must not offer it as one: the
        // gate's own `!empty` check fails when the reference is empty, so the block is skipped and the
        // comparison never runs. An author taking it as advice would replace a check that is failing
        // with a check that does not run, at exit 0. The message is also the longest one the console
        // section prints, so asserting the tail here is what catches the truncation cap being outgrown.
        assert!(
            output.contains("skips the clause rather than satisfying it"),
            "the explanation should say what the `!empty` guard does rather than offer it as the \
             remedy, and should not be cut off before saying it, got:\n{}",
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
            "the unrelated rule's failure must be reported; an abort on the other rule would \
             discard it:\n{}",
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
    /// This is the failure mode the gate rule exists to remove: `!EMPTY` on a boolean has no answer,
    /// and a rule treated as not applicable on that account would leave the violation inside it
    /// unreported with exit 0. With `!EMPTY` on a boolean unconditionally true, the same file exits 19:
    /// the gate opens and the body runs. Fixing the boolean clause without fixing the gate would turn a
    /// bug that over-reports into one that under-reports.
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
            "this rule takes no parameters, so the rule-level failure line must not announce it as a \
             parameterized rule:\n{}",
            output
        );
    }

    /// An undecidable condition one level in does not silence the rule it gates.
    ///
    /// The single-condition form is `an_unevaluatable_gate_fails_the_rule_closed`. This is the same
    /// hazard reached across a parameterized-rule boundary, and closing the direct path alone leaves
    /// this one open: a nested `when` that converted the undecidable answer to `Status::FAIL` would
    /// hand the level above a FAIL on a condition, which is indistinguishable from a condition that
    /// was decided and did not match, and `eval_rule` maps that to a rule-level SKIP -- exit 0, the
    /// rule reported not applicable, `MustBeTrue` unchecked. With `!EMPTY` on a boolean
    /// unconditionally true instead, the gate opens and the file exits 19 on the body.
    ///
    /// The error for a gate is kept instead of converted, so the enclosing condition site fails its
    /// own rule closed; an assertion still answers FAIL, which is what stops one undecidable clause
    /// from aborting the whole file.
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
    /// The hazard is the rule-status cache: keyed on the rule name alone, it would hold the answer
    /// `inner_gate` gave as an assertion, and the gate reference would read that cached FAIL instead
    /// of re-evaluating with gate semantics, so `guarded` would read SKIP. Keying on `(rule, role)`
    /// makes the reference ask its own question, and the undecidable answer then reaches the
    /// enclosing condition as an error rather than as a status, so `guarded` reads FAIL.
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

    /// A gate whose comparison had no answer does not silence the rule it guards.
    ///
    /// The same hazard as `an_unevaluatable_gate_fails_the_rule_closed`, reached through the other
    /// error kind, and that one was closed while this one was open. `!EMPTY` on a boolean raises
    /// `IncompatibleError`, which `is_unevaluatable` recognises, so the gate keeps the error and the
    /// enclosing rule fails closed. A `NOT IN` whose regex exhausted its backtracking budget never
    /// becomes an `Error`: `is_one_of` promotes it to `Membership::Unanswerable`, `binary_operation`
    /// records it at its `NotComparable` arm as a per-value `Status::FAIL`, and one level out a FAIL
    /// on a condition is what a condition that was decided and did not match looks like. `eval_rule`
    /// maps that to a rule-level SKIP, so the file exits 0 having enforced nothing.
    ///
    /// Measured on `undecided-membership-gate-template.yaml`, all three `NOT IN` spellings:
    ///
    ///     rule guarded when Cat NOT IN [[/re/]]    exit 0   SKIP, body never ran
    ///     rule guarded when Cat NOT IN [/re/]      exit 0   SKIP
    ///     rule guarded when Cat[*] NOT IN [/re/]   exit 0   SKIP
    ///     rule guarded when Enabled !EMPTY         exit 19  control, already failed closed
    ///     rule direct { MustBeTrue == true }       exit 19  control, the body is a real violation
    ///
    /// Asserts the reported violation rather than only the exit code, for the reason
    /// `an_undecidable_nested_gate_does_not_silence_the_outer_rule` gives: `unrelated_violation`
    /// exits this file 19 whatever happens to `guarded`, so a test reading the exit code alone passes
    /// while the guarded body is still being dropped.
    #[test]
    fn an_undecided_membership_gate_fails_the_rule_closed() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["undecided-membership-gate-template.yaml"])
            .rules(vec!["undecided_membership_gate_guarding_a_violation.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a gate whose comparison had no answer must not report success; exit 0 here means the \
             guarded body was silently skipped"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("guarded"),
            "the rule whose gate could not be decided must be named as failing:\n{}",
            output
        );
        assert!(
            !output.contains("SKIP rules"),
            "the rule must not be reported as not applicable; a comparison with no answer is not a \
             condition that was decided and did not match:\n{}",
            output
        );
        assert!(
            output.contains("unrelated_violation"),
            "failing the rule closed must not discard the rest of the file:\n{}",
            output
        );
        assert!(
            output.contains("could not be evaluated"),
            "the console must say why the rule failed rather than leaving the reader to guess:\n{}",
            output
        );
    }

    /// The same undecidable comparison as a filter predicate, where the absorption is different and
    /// the exit code is the same.
    ///
    /// A `when` condition that fails makes the rule inapplicable. A filter predicate that fails
    /// selects nothing, and an assertion over an empty selection SKIPs. Both roles carry
    /// `ClauseRole::Gate`, so both reach the same repair, and both exited 0 with the body unchecked.
    ///
    /// This is also the canary for the direction the repair must not take. Five
    /// aws-guard-rules-registry rules depend on `NOT IN` inside a filter predicate answering "not a
    /// member" for a `!Ref`-shaped value, because failing closed there would make the filter select
    /// fewer resources and turn a reported violation into a pass. They are untouched, and mechanically
    /// so: a kind mismatch is discarded by `is_one_of`'s `Err(_) => {}` before any comparison result
    /// exists, while only a promoted `RegexError` becomes the `NotComparable` this repair reads.
    /// `.github/scripts/check-registry-corpus.sh` holds that corpus to its known state.
    #[test]
    fn an_undecided_membership_filter_fails_the_clause_closed() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["undecided-membership-gate-template.yaml"])
            .rules(vec![
                "undecided_membership_filter_guarding_a_violation.guard",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a filter predicate whose comparison had no answer must not select nothing and pass; \
             exit 0 here means the body was never compared"
        );

        let output = writer.stripped().expect("failed to read the writer");
        // `unrelated_violation` exits this file 19 on its own, and at baseline `guarded` appeared in
        // the SKIP list -- so the exit code and a bare `contains("guarded")` were both satisfied while
        // the body went unchecked. The SKIP assertion is the one that can fail here.
        assert!(
            !output.contains("SKIP rules"),
            "`guarded` must not be reported as not applicable; its filter predicate could not be \
             decided, which is not the same as a filter that selected nothing:\n{}",
            output
        );
        assert!(
            output.contains("guarded"),
            "the rule whose filter could not be decided must be named as failing:\n{}",
            output
        );
        assert!(
            output.contains("unrelated_violation"),
            "failing the clause closed must not discard the rest of the file:\n{}",
            output
        );
    }

    /// A map-key filter whose regex ran out of budget fails the clause closed instead of crashing.
    ///
    /// The `[ keys <op> ... ]` path is `real_binary_operation`, and it reached none of the machinery the
    /// other spellings of this question use: `each_lhs_compare` matched `Error::NotComparable` and
    /// propagated everything else, so a `RegexError` left the evaluator unclassified and `main` exited
    /// 255 -- `INTERNAL_FAILURE`, the code this repository uses for the tool itself breaking.
    ///
    /// **The exit code is the assertion that matters, and a verdict-only test would have passed while
    /// the tool was crashing.** The crash printed the entire report first, `k_eq_regex` included, and
    /// only then emitted "Error occurred ..." and exited 255. So `contains("k_eq_regex")` was satisfied,
    /// the rule was already listed as FAILED, and every string in the report read normally. Measured by
    /// key length, all four comparators alike:
    ///
    /// ```text
    /// 10 -> 19    17 -> 19    18 -> 255    19 -> 255    30 -> 255
    /// ```
    ///
    /// Eighteen characters is where `(?!x)((a+)+)b` gives up on this path, which makes the threshold a
    /// property of the template rather than of the rule: one more byte in a map key turned a verdict
    /// into a crash.
    #[test]
    fn an_undecided_map_key_filter_does_not_crash_the_run() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["undecided-map-key-template.json"])
            .rules(vec!["undecided_map_key_filter.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a map-key comparison that could not be answered must fail the clause, not the tool; \
             {} here is INTERNAL_FAILURE and says cfn-guard broke rather than that the template did",
            StatusCode::INTERNAL_FAILURE
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            !output.contains("Error occurred"),
            "the run must not report an unclassified error after printing its report:\n{}",
            output
        );
        assert!(
            output.contains("k_eq_regex"),
            "the rule holding the undecidable key comparison must be named:\n{}",
            output
        );
        assert!(
            output.contains("unrelated_violation"),
            "failing the clause closed must not discard the rest of the file:\n{}",
            output
        );
        // The reason travels with the record. `report_value` bound the pair and dropped it, so an
        // eighteen-character key was rendered as "did not match expected value" -- a claim that the
        // comparison was made and answered no, about a comparison that was abandoned.
        assert!(
            output.contains("The regular expression could not be evaluated against the value"),
            "the report must say the comparison had no answer rather than that the key did not \
             match:\n{}",
            output
        );
    }

    /// An assertion raised on a refusal's reason prints the refusal whole, and says the run goes on.
    ///
    /// The two strict-role raises (`some ... NOT IN %x` beside a refusal's marker a capture holds;
    /// `X IN %x` with the marker alone) are recorded as the refusal they carry, so the console prints the
    /// sentence whole, its remedy and its path included, where it holds every other recorded message to
    /// 320 characters, and the record's sentence says the clause fails and the run continues, which it
    /// does: the exit is the validation failure, not an internal one, and no line says "bailing". The
    /// fixtures' predicate is long enough for the sentence, which writes the query before the wildcard
    /// out twice, to pass that bound, so a record read as a plain error would print it cut before its
    /// path.
    ///
    /// Which record the summary prints differs by shape. `X IN %x` with the marker alone compares
    /// nothing, so its block record is the one line and carries the raise's sentence. `some ... NOT IN %x`
    /// has a pair record for the marker's value beneath its block record, and the summary prints the pair
    /// record in the block's place (the refusal whole, at the value's path); the raise's sentence lives in
    /// the block record, which the summary does not list when a pair record speaks for the clause. The
    /// refused walk that minted the marker sits under an `or` a sibling disjunct decided, and the summary
    /// lists nothing beneath a passing disjunction, so no other record prints the sentence.
    #[rstest::rstest]
    #[case::some_not_in("strict_raise_some_not_in_a_refused_capture.guard", false)]
    #[case::marker_only_in("strict_raise_in_a_marker_only_capture.guard", true)]
    fn an_asserted_refusal_raise_prints_the_refusal_whole_and_the_run_continues(
        #[case] rules: &str,
        #[case] prints_the_raise_sentence: bool,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["strict-raise-refusal-template.json"])
            .rules(vec![rules])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{}: the asserted raise fails the rule and the run goes on to its exit code:\n{}",
            rules,
            output
        );
        assert!(
            output.contains("then no kept entry holds a key the predicate names")
                && output.contains("path /Cfg/A/Sub"),
            "{}: the refusal is printed whole, its path included (a plain recorded message is cut at 320 \
             characters, before the path):\n{}",
            rules,
            output
        );
        assert!(
            !output.contains("bailing"),
            "{}: no record says the clause bails:\n{}",
            rules,
            output
        );
        assert_eq!(
            prints_the_raise_sentence,
            output.contains("the clause is raised and the run continues"),
            "{}: the raise's sentence is printed where the block record is the clause's one line, and \
             not where a pair record speaks for the clause:\n{}",
            rules,
            output
        );
    }

    /// An every-entry block whose body FAILs at the leaf on a refusal, asserted, prints the refusal once
    /// and writes no refused-read line for it.
    ///
    /// The strict raise beside a refused read becomes a FAIL at the comparison's own leaf; under
    /// `match_all` that FAIL is the block's own and the rule's, so the leaf's record, flagged as the
    /// refusal it carries, is the report: the console prints the refusal's sentence exactly once (the
    /// record's one line for it), and the fold writes no "reported here instead" line, since a line
    /// saying the read was not raised would be false of a refusal the failing rule shows. The premise the
    /// no-line rule rests on is that the failing block PRINTS the leaf's refusal; this cell is that
    /// premise, read on the console.
    #[test]
    fn a_strict_leaf_fail_under_an_every_entry_block_prints_the_refusal_once_and_no_line() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["strict-leaf-fail-under-match-all-template.json"])
            .rules(vec!["strict_leaf_fail_under_match_all.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the block fails on the leaf FAIL and the sibling's failure, and the run goes on to its exit \
             code:\n{}",
            output
        );
        assert_eq!(
            1,
            output
                .matches("then no kept entry holds a key the predicate names")
                .count(),
            "the leaf's refusal is printed exactly once, by its own record:\n{}",
            output
        );
        assert!(
            !output.contains("reported here instead"),
            "no refused-read line is written for a refusal the failing block shows:\n{}",
            output
        );
    }

    /// A `when` gate raised beside a refusal AND a key filter's budget marker prints the remedy whole.
    ///
    /// The raise's text is the refusal first and the budget marker's reason after it, numbered; read by
    /// text alone the record is nobody's refusal (the marker's part is registered by no one), and the
    /// console would cut it at the bound it holds every plain recorded message to, before the remedy.
    /// The raise carries the refusal's token beside its text, since the comparison met a refused read,
    /// so the record is flagged and printed whole: the remedy, the path and the budget's sentence.
    #[test]
    fn a_gate_raised_beside_a_refusal_and_a_budget_marker_prints_the_remedy_whole() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["refusal-beside-a-budget-marker-template.json"])
            .rules(vec![
                "gate_raised_beside_a_refusal_and_a_budget_marker.guard",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the gate fails closed and the run goes on to its exit code:\n{}",
            output
        );
        // Read on EVERY line that carries the numbered raise, not anywhere in the output: a path
        // falling before the 320th character would keep a `contains` over the whole output green with
        // the record's flag lost, and the cut's own marker (`...[N more characters cut]`) is what the
        // flag keeps off that line. A candidate line is picked by the number AND the refusal
        // sentence's OPENING, which precedes the 320-character cut, so a cut copy is a candidate too (a
        // bare "(1) " also matches `gate(1)` or an earlier numbered message; the remedy, the path and
        // the second part come AFTER the cut, so picking by any of them would drop exactly the cut copy
        // the check exists to catch). There has to be at least one candidate, and every candidate is
        // held to the four conditions: the remedy sentence, the path, the budget part numbered second,
        // and no cut marker. `whole_raise_lines` is the filter and the loop as one function, so the
        // planted control below runs through the same code as the output.
        const THE_OPENING: &str = "then no kept entry holds a key the predicate names";
        fn whole_raise_lines(output: &str) -> Result<usize, String> {
            let candidates: Vec<&str> = output
                .lines()
                .filter(|line| line.contains("(1) ") && line.contains(THE_OPENING))
                .collect();
            if candidates.is_empty() {
                return Err("no line carries the numbered raise with its opening".to_string());
            }
            for line in &candidates {
                let whole = line.contains("Write `")
                    && line.contains("path /Cfg/A/Sub")
                    && line.contains("(2) ")
                    && !line.contains("...[");
                if !whole {
                    return Err(format!("a candidate line is not the whole raise: {line}"));
                }
            }
            Ok(candidates.len())
        }
        // The control: one whole line and one cut copy (the opening kept, the remedy and everything
        // after it replaced by the cut marker) read RED through the same filter and loop. A check that
        // passed this control would be passing a record that lost its flag behind a whole copy.
        // Each planted line breaks exactly ONE of the four conditions, so deleting any one condition
        // (or turning the chain into `||`) turns the matching control green and the cell red.
        let whole = format!(
            "    Message = (1) `[*]` {THE_OPENING}. `Key` is `Kind`, a key of the map itself. Write `X[*] {{ Key == value }}`, where `X` is `Cfg`, at path /Cfg/A/Sub (2) the budget's reason\n"
        );
        let cut_early = format!(
            "    Message = (1) `[*]` {THE_OPENING}. `Key` is `Kind`, a key of the map itself. Wr...[180 more characters cut]\n"
        );
        let cut_late = format!(
            "    Message = (1) `[*]` {THE_OPENING}. `Key` is `Kind`, a key of the map itself. Write `X[*] {{ Key == value }}`, where `X` is `Cfg`, at path /Cfg/A/Sub (2) the bud...[40 more characters cut]\n"
        );
        let no_remedy = format!(
            "    Message = (1) `[*]` {THE_OPENING}. `Key` is `Kind`, a key of the map itself, at path /Cfg/A/Sub (2) the budget's reason\n"
        );
        let no_path = format!(
            "    Message = (1) `[*]` {THE_OPENING}. `Key` is `Kind`, a key of the map itself. Write `X[*] {{ Key == value }}`, where `X` is `Cfg` (2) the budget's reason\n"
        );
        let no_second_part = format!(
            "    Message = (1) `[*]` {THE_OPENING}. `Key` is `Kind`, a key of the map itself. Write `X[*] {{ Key == value }}`, where `X` is `Cfg`, at path /Cfg/A/Sub\n"
        );
        assert!(
            whole_raise_lines(&whole).is_ok(),
            "the control's whole line alone has to read green"
        );
        assert!(
            whole_raise_lines(&format!("{whole}{cut_early}")).is_err(),
            "the control (a whole line beside a cut copy) has to read red"
        );
        for (what, planted) in [
            ("a copy cut early", &cut_early),
            (
                "a copy that holds the remedy, the path and the second part and is cut later",
                &cut_late,
            ),
            ("a line without the remedy", &no_remedy),
            ("a line without the path", &no_path),
            ("a line without the second numbered part", &no_second_part),
        ] {
            assert!(
                whole_raise_lines(planted).is_err(),
                "the control ({}) has to read red alone: {}",
                what,
                planted
            );
        }
        if let Err(why) = whole_raise_lines(&output) {
            panic!(
                "the refusal is printed whole on every line that carries it, numbered first, its remedy \
                 and path included, the budget marker's reason following it numbered second on the same \
                 line, and no cut marker on that line (a plain recorded message is cut at 320 characters, \
                 before the remedy and the path): {why}\n{}",
                output
            );
        }
        assert!(
            !output.contains("bailing"),
            "the run continues, never bails:\n{}",
            output
        );
    }

    /// One rules file over one document, in the console form (`--show-summary all`) or in the named
    /// output format (`--show-summary none`): the exit code and the stripped stdout. The refused-read
    /// cells share it, so their cases differ only in what they assert.
    fn run_one(data_file: &str, rules_file: &str, output_format: Option<&str>) -> (i32, String) {
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
        (
            status_code,
            writer.stripped().expect("failed to read the writer"),
        )
    }

    /// A rule that fails closed on a plain error names that error, and names a refusal settled beside
    /// it once, bare, in the rule's own sentence.
    ///
    /// `M` is a one-object map holding an intrinsic beside the compared entry (a refused selection), and
    /// the sibling whose body raises a converter's error (`parse_int` on a word) is either `L`, a list
    /// (the first template), or `N`, a second one-object selection (the second template). In the
    /// ASSERTION role (`rule check { .. }`) both shapes print two checks: the converter error's clause
    /// record and the refusal's sentence, once each (the list shape completes the loop over the values
    /// and folds the refusal after it; the one-object shape exits the block with the refusal settled,
    /// and the sentence at `M`'s path is carried by the block's own exit record, the one written when the
    /// body's read of the empty selection was refused, not by the settled per-value record, which has no
    /// message). Behind a `when` GATE (a
    /// parameterized rule the condition calls, `some` and every-value blocks alike) the error exits the
    /// block, the rule fails closed on it, and the run prints the condition's sentence naming the error,
    /// followed by the refusal the block had settled, bare and at the refused map's path ("; the
    /// condition also met: .."): the refusal did not decide the verdict, so it follows the error and the
    /// block-exit sentence stays out (known issue 25 in `docs/KNOWN_ISSUES.md`). Each of the four cases
    /// (two templates, the console and `-o json`) reads the gated rule's output for the error and the
    /// condition's sentence twice each (the file holds two gated rules), the block-exit sentence none
    /// and the refused map's path once, and the asserted rule's output for the error once, the refusal
    /// once at that path and no condition sentence. The reading is the rule's sentence on stdout: no
    /// refused-read line is written for this shape, and a `Warning:` line would go to stderr, which this
    /// runner's writer leaves on the process.
    #[rstest::rstest]
    #[case(
        "refused-map-beside-a-list-template.json",
        "list sibling",
        None,
        "console"
    )]
    #[case(
        "refused-map-beside-a-list-template.json",
        "list sibling",
        Some("json"),
        "json"
    )]
    #[case(
        "refused-map-beside-a-one-object-template.json",
        "one-object sibling",
        None,
        "console"
    )]
    #[case(
        "refused-map-beside-a-one-object-template.json",
        "one-object sibling",
        Some("json"),
        "json"
    )]
    fn a_gate_failing_closed_on_a_plain_error_names_a_refusal_settled_beside_it_in_the_rules_sentence(
        #[case] data_file: &str,
        #[case] shape: &str,
        #[case] format: Option<&str>,
        #[case] label: &str,
    ) {
        const THE_CONVERTERS_ERROR: &str = "failed to convert a string: prod into an integer";
        const THE_CONDITIONS_SENTENCE: &str =
            "The rule's condition could not be evaluated, so the rule fails rather than being treated as not applicable";
        const THE_REFUSAL: &str =
            "The block's body read the empty selection a one-object filter left";
        // The refused map's own path: a gate that named the refusal would print it, and the assertion's
        // refusal sentence ends with it.
        const THE_REFUSED_MAPS_PATH: &str = "/Resources/M/Tags";
        let (gate_status, gate_output) = run_one(
            data_file,
            "gate_failing_closed_beside_a_settled_refusal.guard",
            format,
        );
        assert_eq!(
                    StatusCode::VALIDATION_ERROR,
                    gate_status,
                    "({shape}, {label}) both gated rules fail closed on the converter's error:\n{gate_output}"
                );
        assert_eq!(
                    (2, 2, 0),
                    (
                        gate_output.matches(THE_CONDITIONS_SENTENCE).count(),
                        gate_output.matches(THE_CONVERTERS_ERROR).count(),
                        gate_output.matches(THE_REFUSAL).count(),
                    ),
                    "({shape}, {label}) each gated rule prints the condition's sentence naming the \
                     converter's error once, and not the block-exit refusal sentence (the verdict's \
                     sentence names the error that decided):\n{gate_output}"
                );
        // The refusal settled beside the error is appended once to EACH gated rule's sentence
        // ("; the condition also met: .."), which names the refused map's path. The file holds two
        // gated rules (`some` and every-value), and both settle `M` before the error, so the path
        // appears once per rule: twice in all, in the console and in the JSON alike, and nowhere
        // else (no refused-read line, no per-clause copy).
        assert_eq!(
            2,
            gate_output.matches(THE_REFUSED_MAPS_PATH).count(),
            "({shape}, {label}) the refusal settled beside the error names the refused \
             map's path once in each gated rule's sentence:\n{gate_output}"
        );

        let (assert_status, assert_output) = run_one(
            data_file,
            "assertion_failing_beside_a_settled_refusal.guard",
            format,
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            assert_status,
            "({shape}, {label}) the asserted rule fails:\n{assert_output}"
        );
        assert_eq!(
                    (1, 1, 0, true),
                    (
                        assert_output.matches(THE_CONVERTERS_ERROR).count(),
                        assert_output.matches(THE_REFUSAL).count(),
                        assert_output.matches(THE_CONDITIONS_SENTENCE).count(),
                        // The line (console) or the error message (json) that carries the refusal
                        // also names the refused map's path.
                        assert_output
                            .lines()
                            .filter(|line| line.contains(THE_REFUSAL))
                            .all(|line| line.contains(THE_REFUSED_MAPS_PATH))
                    ),
                    "({shape}, {label}) the asserted rule prints the converter's error once and the \
                     refusal once at the refused map's path, and no condition sentence:\n{assert_output}"
                );
    }

    /// Each part of a rule's joined sentence is bounded by its own kind, at the console alone. The gate fails
    /// closed on a converter's error that quotes a 639-character template value (a 626-character run of one
    /// letter after a few words), and a refusal settled beside it is joined to the sentence ("; the condition
    /// also met: .."). The CONSOLE cuts the plain half at the recorded-message bound before the join: the cut
    /// falls at whitespace, the run is one word, so the value is dropped whole from "not a number" on, with
    /// the ellipsis before the join, and the refusal half is printed whole, its path included. The
    /// structured output (`-o json`) carries every part whole: the quoted value in full and the refusal
    /// whole, since the report model cuts nothing.
    ///
    /// Fails when the console prints 321 or more of the value's characters (the plain half left
    /// the plain bound), has no cut marker before the join, or cuts the refusal; or when the
    /// json output lacks the whole value (the model cut the head) or the refusal's path.
    #[rstest::rstest]
    #[case(None, "console")]
    #[case(Some("json"), "json")]
    fn a_plain_half_is_cut_and_a_joined_refusal_is_whole(
        #[case] format: Option<&str>,
        #[case] label: &str,
    ) {
        const THE_REFUSED_MAPS_PATH: &str = "/Resources/M/Tags";
        const THE_JOIN: &str = "; the condition also met: ";
        let (status, output) = run_one(
            "refused-map-beside-a-long-value-template.json",
            "gate_converter_error_on_a_long_value_beside_a_settled_refusal.guard",
            format,
        );
        assert!(
            output.contains("failed to convert a string: not a number"),
            "({}) the converter's error quotes the value (the control: the gate reached `parse_int` \
             on it, and did not raise the other map's refusal alone):\n{}",
            label,
            output
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status,
            "({}) the gated rules fail closed on the converter's error:\n{}",
            label,
            output
        );
        match format {
            None => assert!(
                !output.contains(&"x".repeat(321))
                    && output.contains(&format!("not a number...{THE_JOIN}")),
                "({}) the console cuts the plain half at the plain bound, at whitespace, so the quoted value \
                 (one word) is dropped whole and the ellipsis stands before the join:\n{}",
                label,
                output
            ),
            Some(_) => assert!(
                output.contains(&"x".repeat(626)),
                "({}) the structured output carries the quoted template value whole (the report model \
                 cuts nothing):\n{}",
                label,
                output
            ),
        }
        let joins: Vec<&str> = output.split(THE_JOIN).skip(1).collect();
        assert!(
            !joins.is_empty(),
            "({}) a refusal is joined to the rule's sentence:\n{}",
            label,
            output
        );
        for after in joins {
            // The refusal half, up to the end of its line (console) or string (json).
            let refusal = after.split(['\n', '"']).next().unwrap_or_default();
            assert!(
                refusal.contains(THE_REFUSED_MAPS_PATH) && !refusal.contains("..."),
                "({}) the joined refusal is whole, path included: {}",
                label,
                refusal
            );
        }
    }

    /// A refusal the evaluator met is never silent in any output format. The gate shape of known issue 25
    /// (a gate failing closed on a converter's error with a refusal settled beside it) joins the refusal to
    /// the rule's sentence, and `-o sarif`, which prints no rule-level sentence of its own, takes the rule's
    /// record as the result's text where no check speaks for the rule: the refused map's path appears once
    /// per gated rule (the file holds two), twice in the document.
    ///
    /// Fails when the path is absent from the SARIF document (the refusal is silent there,
    /// since the console's warning line is no longer written for this shape).
    #[rstest::rstest]
    #[case("refused-map-beside-a-list-template.json", "list sibling")]
    #[case("refused-map-beside-a-one-object-template.json", "one-object sibling")]
    fn a_refusal_settled_beside_a_gates_error_is_in_the_sarif_report(
        #[case] data_file: &str,
        #[case] shape: &str,
    ) {
        const THE_REFUSED_MAPS_PATH: &str = "/Resources/M/Tags";
        // Not `run_one`: `-o sarif` is refused without `--structured` ("the structured flag must be set
        // when output is set to sarif"), so the run returned the usage error's code and printed no
        // document.
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status = ValidateTestRunner::default()
            .data(vec![data_file])
            .rules(vec!["gate_failing_closed_beside_a_settled_refusal.guard"])
            .show_summary(vec!["none"])
            .output_format(Some("sarif"))
            .structured()
            .run(&mut writer, &mut reader);
        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status,
            "({}) the gated rules fail closed:\n{}",
            shape,
            output
        );
        assert_eq!(
            2,
            output.matches(THE_REFUSED_MAPS_PATH).count(),
            "({}) the refusal settled beside the error is named once per gated rule in the SARIF results:\n{}",
            shape,
            output
        );
    }

    /// A resource keyed by three hundred right-to-left overrides keeps the console's line under its bound.
    ///
    /// The left-hand refused marker is compared with a key the document lacks under that resource; the
    /// record leads with the absence, whose reason names the key and its path. Both are escaped first
    /// (`\u{202e}` for each override) and bounded on the PRINTED width with the leaf kept, so the line the
    /// console prints holds the refusal's remedy and no raw override, where a bound on the source
    /// characters printed eight times the bound of escapes and pushed the remedy past the console's
    /// whole-line bound.
    #[test]
    fn a_resource_key_of_bidi_controls_keeps_the_console_line_under_its_bound() {
        let key = "\u{202e}".repeat(300);
        let data = format!(
            concat!(
                "{{ \"Cfg\": {{ \"Mode\": {{ \"Ref\": \"ModeParam\" }}, \"Fallback\": {{ \"Kind\": \"k\" }}, ",
                "\"A\": {{ \"Kind\": \"k\", \"Sub\": {{ \"R1_the_own_key_of_the_sub_map_whose_name_is_long_enough_to_carry_the_refusal_past_the_bound\": {{ \"Ref\": \"P\" }}, \"P\": {{ \"Kind\": \"k\" }}, \"Q\": {{ \"Kind\": \"k\" }} }} }}, ",
                "\"B\": {{ \"Kind\": \"k\", \"Sub\": {{ \"R1_the_own_key_of_the_sub_map_whose_name_is_long_enough_to_carry_the_refusal_past_the_bound\": {{ \"Ref\": \"P\" }}, \"P\": {{ \"Kind\": \"k\" }}, \"Q\": {{ \"Kind\": \"k\" }} }} }} }}, ",
                "\"Resources\": {{ \"R{}x\": {{ \"Type\": \"AWS::S3::Bucket\", \"Properties\": {{ \"Name\": \"n\" }} }} }} }}"
            ),
            key
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(data.into_bytes())));
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "left_refusal_beside_an_absent_key_under_a_bidi_resource.guard",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the clause fails on the absence beside the refusal:\n{}",
            output
        );
        // Two console lines carry the remedy: the strict raise's block record (the refusal alone, the
        // path of its own key) and the pair record that leads with the absence under the overrides' key
        // and ends with the refusal. The second is the one the key reaches; every line is read for the
        // bound and the whole output for a raw override.
        let carrying: Vec<&str> = output
            .lines()
            .filter(|line| line.contains("then no kept entry holds a key the predicate names"))
            .collect();
        assert!(
            !carrying.is_empty(),
            "no console line carries the refusal's remedy:\n{}",
            output
        );
        assert!(
            carrying.iter().all(|line| line.chars().count() < 4096),
            "every line carrying the remedy is under the console's whole-line bound:\n{}",
            output
        );
        assert!(
            !output.contains('\u{202e}'),
            "no raw override reaches the console:\n{}",
            output
        );
        assert!(
            carrying.iter().any(|line| {
                line.contains("\\u{202e}")
                    && line.contains("more characters cut")
                    && line.contains("x/Properties")
            }),
            "one line names the path with the overrides as escapes, the key cut and its leaf kept, and \
             ends with the refusal:\n{}",
            output
        );
    }

    /// Two data files reaching one clause site with an unraised refused read are two distinct `Warning:`
    /// lines, each naming the clause as the author wrote it (`Properties.Owner == %names`, never the
    /// record tree's `EQUALS` form), ending with the clause's position, and naming its own data file: the
    /// warning's key under `validate` is the site and the data file, so a reader can tell which file's
    /// evaluation left the read unraised, where one line for the two would name neither.
    #[test]
    fn two_data_files_reaching_one_unraised_refusal_site_print_two_lines_naming_each_file() {
        let (status_code, stdout, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![
                    "unraised-refusal-first-template.json",
                    "unraised-refusal-second-template.json",
                ])
                .rules(vec!["unraised_refusal_two_data_files.guard"])
                .show_summary(vec!["all"])
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files PASS by the absence:\n{stdout}\n{stderr}"
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("Warning:") && line.contains("reported here instead"))
            .collect();
        assert_eq!(
            2,
            warnings.len(),
            "one clause site over two data files is two lines, got:\n{stderr}"
        );
        assert_ne!(
            warnings[0], warnings[1],
            "the two lines differ (each names its own file):\n{stderr}"
        );
        for line in &warnings {
            assert!(
                line.contains("Properties.Owner == %names")
                    && !line.contains("EQUALS")
                    && line.contains("The clause is at Location[file:")
                    && line.contains(" in data file "),
                "the line names the clause as written, its position and a data file: {}",
                line
            );
        }
        for file in [
            "unraised-refusal-first-template.json",
            "unraised-refusal-second-template.json",
        ] {
            assert_eq!(
                1,
                warnings.iter().filter(|line| line.contains(file)).count(),
                "exactly one line names {file}:\n{stderr}"
            );
        }
    }

    /// An error that stops the run is still named on stdout here, beside the rule it stopped in.
    ///
    /// `validate` reports the record tree before it applies `?` to the error `eval_rules_file` returns,
    /// so the rule is printed as FAIL and the "Could not be evaluated" section names the cause; a caller
    /// that applied `?` first would print nothing on stdout for the same files. Two spellings, because
    /// the cause reaches stdout through two different records. In
    /// `%nosuch == 1 or Resources exists` the disjunct's own record carries the access clause's
    /// "bailing" sentence, and every reporter renders that in place of the disjunction's message
    /// (measured: a sentence recorded on the disjunction's early-return path reached none of the
    /// console, json, yaml and structured outputs, so that record keeps `message: None`). In
    /// `%nosuch.Foo { Type exists }` the block clause's query raises before any child record exists,
    /// so the `BlockGuardCheck` record's own sentence is the only account of what went wrong, and it
    /// is the one asserted here.
    ///
    /// The exit code is `PARSING_ERROR`, the code for a name the rules file never declares,
    /// and it is asserted so a change that turns either file into a verdict is seen.
    #[rstest::rstest]
    #[case::in_an_or(
        "undeclared_name_in_an_or.guard",
        "Could not resolve variable by name nosuch across scopes` when handling clause, bailing"
    )]
    #[case::in_a_block_query(
        "undeclared_name_in_a_block_query.guard",
        "The block's query raised an error that is not about the data, so the run stops: There was \
         no variable or value object to resolve. Error = `Could not resolve variable by name nosuch \
         across scopes`"
    )]
    fn an_undeclared_name_in_an_or_is_named_on_stdout(#[case] rules: &str, #[case] reason: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["db_resource.yaml"])
            .rules(vec![rules])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "{} names a variable no `let` declares, which exits 5",
            rules
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("FAILED rules") && output.contains("/r    FAIL"),
            "{}: the rule the error stopped in must be printed as FAIL on stdout:\n{}",
            rules,
            output
        );
        assert!(
            output.contains("Could not be evaluated:") && output.contains(reason),
            "{}: the cause must be named under \"Could not be evaluated\"; expected {:?} in:\n{}",
            rules,
            reason,
            output
        );
    }

    /// The membership spellings of that filter carry the reason too.
    ///
    /// `real_binary_operation` splits by comparator: `==` and `!=` reach `report_all_values` and so
    /// `report_value`, while `IN` and `NOT IN` reach `report_by_lhs`. Both sites carry the reason, as
    /// every other site recording a refusal does. A `report_by_lhs` that left `message: None` would
    /// report a comparison that never finished, for the two membership operators only, as one that
    /// finished and answered.
    ///
    /// `NOT IN` is the worse of the two and the reason the wording is asserted rather than only the
    /// presence of a message. Without the reason it renders as "provided value [...] did match
    /// expected value in [...]", an affirmative claim that the comparison succeeded, about a
    /// comparison the engine abandoned; `IN` renders the mirror. With `message: None` at the
    /// membership site, the four spellings over the same eighteen-character key render:
    ///
    /// ```text
    /// keys ==     -> due to retrieval error. Error Message [The regular expression could not be ...]
    /// keys !=     -> due to retrieval error. Error Message [The regular expression could not be ...]
    /// keys in     -> did not match expected value in [...]. Error Message []
    /// keys not in -> did match     expected value in [...]. Error Message []
    /// ```
    ///
    /// An undecidable key filter fails closed wherever its selection is read as a clause's own query: a
    /// `when` gate fails its rule (it reported SKIP at exit 0 with the body unchecked), a comparison on
    /// either side fails, and a `some` binding keeps the marker so `empty` over it fails (it bound
    /// nothing and passed). Inside a filter predicate the marker fails the enclosing clause closed in
    /// either polarity, whether the filter is evaluated there or bound outside and read through a `let`:
    /// a positive predicate does not deselect every entry (which would let `empty` over the selection
    /// pass at exit 0 where the predicate-free spelling fails), and a negated one does not hold and
    /// select every entry. A decided list beside them keeps a predicate decided. The file exits with the
    /// validation failure code and the two decided rules beside them keep PASS. The block form of the
    /// selection fails
    /// closed as a gate too, referenced from a `when` plainly or under `not`, or called as a
    /// parameterized rule plainly or under `not`; those gate bodies hold on the template, so an opened
    /// gate would read PASS and a gate closed on a decided no would read SKIP. The `_absent_property`
    /// rows are that decided no, a block over a property the template lacks, on each of the same gate
    /// paths: asserted it fails, the plain gates read their rule not applicable, and the negated gates
    /// open their bodies and pass, so a marker check widened to any unresolved value shows up here as an
    /// optional property failing a gate closed.
    #[test]
    fn an_undecidable_selection_fails_closed_downstream() {
        let Run {
            status_code,
            stdout,
            disagreed,
            ..
        } = rule_verdicts(
            "/in-over-enumerating-query/undecidable_selection_downstream.yaml",
            "/in-over-enumerating-query/undecidable_selection_downstream.guard",
            &[
                ("gate_over_a_missing_rhs", "FAIL"),
                ("gate_over_a_spent_regex", "FAIL"),
                ("predicate_over_a_missing_rhs", "FAIL"),
                ("predicate_positive_not_empty", "FAIL"),
                ("predicate_positive_exists", "FAIL"),
                ("predicate_negated_empty", "FAIL"),
                ("predicate_negated_not_exists", "FAIL"),
                ("predicate_with_a_present_list", "PASS"),
                ("rhs_over_a_missing_rhs", "FAIL"),
                ("let_carried_into_a_predicate_exists", "FAIL"),
                ("let_carried_into_a_predicate_not_exists", "FAIL"),
                ("let_carried_into_a_predicate_in", "FAIL"),
                ("some_binding_is_not_empty", "FAIL"),
                ("some_binding_is_compared", "FAIL"),
                ("decided_beside_them", "PASS"),
                ("decided_beside_them_too", "PASS"),
                ("block_over_a_missing_rhs", "FAIL"),
                ("block_gate_over_a_missing_rhs", "FAIL"),
                ("block_negated_gate_over_a_missing_rhs", "FAIL"),
                ("block_parameterized_gate_over_a_missing_rhs", "FAIL"),
                (
                    "block_negated_parameterized_gate_over_a_missing_rhs",
                    "FAIL",
                ),
                ("block_over_an_absent_property", "FAIL"),
                ("block_gate_over_an_absent_property", "SKIP"),
                ("block_negated_gate_over_an_absent_property", "PASS"),
                ("block_parameterized_gate_over_an_absent_property", "SKIP"),
                (
                    "block_negated_parameterized_gate_over_an_absent_property",
                    "PASS",
                ),
            ],
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "an undecidable selection fails the file closed:\n{}",
            stdout
        );
        assert!(
            disagreed.is_empty(),
            "{} rules disagree:\n  {}\n{}",
            disagreed.len(),
            disagreed.join("\n  "),
            stdout
        );
    }

    /// Inside a filter predicate an entry whose key filter cannot be decided fails the file closed and
    /// is named with the filter's reason, and a decided sibling's own violation is named beside it, in
    /// either order of the entries; a template with two undecidable entries names both. The filter
    /// loops do not end the selection at the first entry's raise: ending it there would leave the
    /// sibling's violation named nowhere and make which entry is named depend on the order.
    #[test]
    fn an_undecidable_entry_inside_a_predicate_names_its_decided_siblings() {
        for (data, undecidable) in [
            (
                "/in-over-enumerating-query/undecidable_entry_in_a_predicate_a_then_c.yaml",
                &["/Resources/C/Properties/M/Tags"][..],
            ),
            (
                "/in-over-enumerating-query/undecidable_entry_in_a_predicate_c_then_a.yaml",
                &["/Resources/C/Properties/M/Tags"],
            ),
            (
                "/in-over-enumerating-query/undecidable_entry_in_a_predicate_two_undecidable.yaml",
                &[
                    "/Resources/C/Properties/M/Tags",
                    "/Resources/D/Properties/M/Tags",
                ],
            ),
        ] {
            let Run {
                status_code,
                stdout,
                disagreed,
                ..
            } = rule_verdicts(
                data,
                "/in-over-enumerating-query/undecidable_entry_in_a_predicate.guard",
                &[
                    ("r", "FAIL"),
                    ("capture_read_alone", "FAIL"),
                    ("gate_decided_by_some", "FAIL"),
                ],
            );
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{}: an undecidable entry fails the file closed:\n{}",
                data,
                stdout
            );
            assert!(
                disagreed.is_empty(),
                "{}: {} rules disagree:\n  {}\n{}",
                data,
                disagreed.len(),
                disagreed.join("\n  "),
                stdout
            );
            assert!(
                stdout.contains("/Resources/A/Type"),
                "{}: the decided violation at A is named:\n{}",
                data,
                stdout
            );
            for path in undecidable {
                assert!(
                    stdout.contains(path),
                    "{}: the undecidable entry {} is named with its reason:\n{}",
                    data,
                    path,
                    stdout
                );
            }
        }
    }

    /// The exit code is 19 with the reason named and 19 without it, because the clause fails closed
    /// either way. So a status-only assertion cannot see this, and neither can one that greps the whole
    /// output for the reason while a `==` rule sits in the same file supplying it. The fixture holds
    /// only membership rules against the pattern for that second reason.
    #[test]
    fn an_undecided_map_key_membership_filter_says_why() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["undecided-map-key-template.json"])
            .rules(vec!["undecided_map_key_membership.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the membership spellings already failed closed and must keep doing so; this change is \
             about what the report says, not about the verdict"
        );

        let output = writer.stripped().expect("failed to read the writer");
        for rule in ["k_in_regex", "k_not_in_regex"] {
            assert!(
                output.contains(rule),
                "{} must be named in the report:\n{}",
                rule,
                output
            );
        }
        // Scoped to the membership renderings, and then split by which key they are about, because the
        // interesting property is per value rather than per clause. "expected value in" is what only
        // the `IN`/`NOT IN` rendering says; the string-against-string failure in
        // `unrelated_violation` reads "did not match expected value [...]" with no `in`, and its empty
        // reason slot is correct -- that comparison was made and answered no.
        //
        // Three renderings, not two. `k_in_regex` fails on both keys, `k_not_in_regex` only on the long
        // one: `other` is decidedly outside the denylist, so `NOT IN` passes for it. That asymmetry is
        // what makes this worth splitting -- two of the three comparisons had no answer and one did.
        const UNDECIDABLE_KEY: &str = "aaaaaaaaaaaaaaaaaa";
        const REASON: &str = "The regular expression could not be evaluated against the value";

        let membership_lines = output
            .lines()
            .filter(|line| line.contains("expected value in"))
            .collect::<Vec<_>>();
        assert_eq!(
            3,
            membership_lines.len(),
            "expected two renderings from `IN` and one from `NOT IN`; got {:#?}",
            membership_lines
        );

        let (undecidable, decided): (Vec<&str>, Vec<&str>) = membership_lines
            .iter()
            .partition(|line| line.contains(UNDECIDABLE_KEY));
        assert_eq!(
            2,
            undecidable.len(),
            "both spellings must report the key the pattern could not be evaluated against; got {:#?}",
            undecidable
        );
        for line in &undecidable {
            assert!(
                line.contains(REASON),
                "a membership comparison that had no answer must say so rather than claim the value \
                 did or did not match: {}",
                line
            );
        }

        // The other half of the property, and the reason this is not a blanket "every membership line
        // carries a reason". A comparison that WAS answered must keep its empty slot, so a repair that
        // attached one clause's reason to every value it reports would fail here.
        assert_eq!(
            1,
            decided.len(),
            "expected exactly one decided membership rendering; got {:#?}",
            decided
        );
        assert!(
            !decided[0].contains(REASON),
            "a comparison that was answered must not borrow another value's refusal: {}",
            decided[0]
        );

        // Four, from two sources. The two undecided key comparisons each carry the reason on their
        // membership rendering (one under `IN`, one under `NOT IN`); fewer means only one of the two
        // operators was repaired. And each rule's filter, left undecided for its one map, records that
        // map as a value that could not be decided, "traversed until [/Cfg] ... due to retrieval
        // error", with the same reason: that is the clause's own verdict about the map, failed closed
        // while any sibling map would still be decided, and it is the record a reader of the summary
        // looks at first. The decided comparison and the unrelated rule carry no reason, asserted
        // above, so a count beyond four would be the reason leaking onto a value that was answered.
        assert_eq!(
            4,
            output.matches(REASON).count(),
            "the two undecided comparisons and the two undecided maps report the reason, and nothing \
             else does:\n{}",
            output
        );
        assert_eq!(
            2,
            output.matches("traversed until [/Cfg]").count(),
            "each rule records the map whose selection could not be decided, once:\n{}",
            output
        );
        assert!(
            output.contains("backtracking"),
            "the reason must carry fancy_regex's own text, not `RegexError`'s wrapper wording, which \
             claims a parse error for a pattern that parsed:\n{}",
            output
        );
    }

    /// A key filter's `==` and `!=` against a list are reported in the equality wording, one line per
    /// failing key, and the `in` spelling of the same list in the membership wording.
    ///
    /// A list on the right of a key filter is a set, so `keys == ["nope"]` is decided as membership, but
    /// the evaluator records the written operator and not the widened one: a summary reading "did not
    /// match expected value in [...]" for a rule no line of which contains `in`, with the verbose tree
    /// and the structured reports naming `IN`, would describe a clause the author did not write. The
    /// record is one per key, in the membership shape: `==` reads "is not equal to any of [...]", `!=`
    /// names the element the key was equal to, and `in` keeps the membership sentence. One per key and
    /// not one per list value: per-value records each stamped with the key's one verdict would report,
    /// for a `!=` against `["aaaaaaaaaaaaaaaaaa", "other"]`, the key `other` as equal to
    /// `aaaaaaaaaaaaaaaaaa`, which is false, and a `==` against a long allowlist would report one line
    /// per entry for every key. Every rule fails on both keys of `Cfg`, so each yields one line per
    /// key, whatever the length of its list.
    #[test]
    fn a_key_filter_equality_against_a_list_keeps_the_equality_wording_one_line_per_key() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["undecided-map-key-template.json"])
            .rules(vec!["key_filter_equality_wording.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "no key is `nope` or `nah` and both keys are denied, so every rule fails"
        );

        let output = writer.stripped().expect("failed to read the writer");
        // The per-key comparison lines only; each rule also prints one clause-level line saying the
        // selection was empty, which names neither wording.
        let lines_of = |rule: &str| {
            output
                .lines()
                .filter(|line| {
                    line.contains(&format!("[{}]", rule)) && line.contains("provided value")
                })
                .collect::<Vec<_>>()
        };

        for (rule, expected) in [
            ("k_eq_one_element", r#"is not equal to any of [["nope"]]"#),
            (
                "k_eq_two_element",
                r#"is not equal to any of [["nope","nah"]]"#,
            ),
        ] {
            let lines = lines_of(rule);
            assert_eq!(
                2,
                lines.len(),
                "{}: one `==` line per key of Cfg, whatever the length of the list; got {:#?}",
                rule,
                lines
            );
            for line in &lines {
                assert!(
                    line.contains(expected) && !line.contains("expected value in"),
                    "{}: a written `==` is reported in the equality wording against the set: {}",
                    rule,
                    line
                );
            }
        }

        let denied = lines_of("k_not_eq_two_element");
        assert_eq!(
            2,
            denied.len(),
            "one `!=` line per key of Cfg; got {:#?}",
            denied
        );
        for key in ["aaaaaaaaaaaaaaaaaa", "other"] {
            let line = denied
                .iter()
                .find(|line| line.contains(&format!("provided value [\"{}\"]", key)))
                .unwrap_or_else(|| panic!("no `!=` line for the key {}; got {:#?}", key, denied));
            assert!(
                line.contains(&format!(
                    r#"is equal to ["{}"], one of [["aaaaaaaaaaaaaaaaaa","other"]]"#,
                    key
                )),
                "a written `!=` names the element the key was equal to, and only that one: {}",
                line
            );
        }

        let membership_lines = lines_of("k_in_one_element");
        assert_eq!(
            2,
            membership_lines.len(),
            "one `in` line per key of Cfg; got {:#?}",
            membership_lines
        );
        for line in &membership_lines {
            assert!(
                line.contains(r#"did not match expected value in [["nope"]]"#),
                "a written `in` keeps the membership wording against the set: {}",
                line
            );
        }

        // A pairing the comparator refuses, a key of more than one character against a char range,
        // has no answer under either polarity, and the line says so rather than claiming the key did
        // or did not match. The record carries the written operator, so this is what pins that a
        // reason outranks the operator in every renderer.
        for rule in ["k_eq_refused", "k_not_eq_refused"] {
            let lines = lines_of(rule);
            assert_eq!(
                2,
                lines.len(),
                "{}: one refused line per key of Cfg; got {:#?}",
                rule,
                lines
            );
            for line in &lines {
                assert!(
                    line.contains("could not be compared with expected value in")
                        && !line.contains("match expected value"),
                    "{}: a refused pairing says the comparison could not be made: {}",
                    rule,
                    line
                );
            }
        }
    }

    /// A refused membership does not claim a match happened; a decided one keeps saying it did.
    ///
    /// `report_by_lhs` carries the refusal reason now, so the reporters can tell the two apart, and the
    /// lead sentence is conditional on it. Before that they could not: every membership failure read
    /// "provided value [...] did match expected value in [...]", which is an assertion that the
    /// comparison ran and answered.
    ///
    /// Both rules in the fixture fail, and the pair is the point. For `k_decided` the sentence is
    /// CORRECT -- the denylist names both keys, so the value really did match -- and a blanket rewording
    /// would have replaced a true sentence for the common case in order to fix the refused one. So this
    /// asserts the new wording on one rule and the old wording on the other, in the same report. A
    /// change that reworded membership failures unconditionally passes the first half and fails the
    /// second.
    ///
    /// The pair's fixture is `guard/resources/validate/membership_lead_sentence.guard`. Two live
    /// renderers build the lead sentence, this reporter's and `eval_context.rs`'s `InComparison` arm;
    /// `SingleLineReporter` in `cfn_reporter.rs` is unreachable, so a third copy of the sentence there
    /// is not a third renderer.
    #[test]
    fn a_refused_membership_does_not_claim_a_match_happened() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["undecided-map-key-template.json"])
            .rules(vec!["membership_lead_sentence.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both rules fail whatever the sentence says; this is about the sentence, not the verdict"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let refused = output
            .lines()
            .find(|l| l.contains("k_refused") && l.contains("expected value in"))
            .unwrap_or_else(|| panic!("no membership rendering for k_refused:\n{}", output));
        let decided = output
            .lines()
            .find(|l| l.contains("k_decided") && l.contains("expected value in"))
            .unwrap_or_else(|| panic!("no membership rendering for k_decided:\n{}", output));

        assert!(
            refused.contains("could not be compared with expected value in"),
            "a comparison that never ran must not be reported as one that did: {}",
            refused
        );
        assert!(
            !refused.contains("did match") && !refused.contains("did not match"),
            "the refused rendering must not assert a match either way: {}",
            refused
        );

        assert!(
            decided.contains("did match expected value in"),
            "a decided membership failure must keep saying the value matched, because it did: {}",
            decided
        );
        assert!(
            !decided.contains("could not be compared"),
            "a comparison that was answered must not borrow the refused wording: {}",
            decided
        );
    }

    /// The same distinction on the structured reporter, which had no cell asserting its sentence.
    ///
    /// Two sites build this sentence. `membership_verdict` in `generic_summary.rs` serves the console
    /// and is covered by the test above. The `ClauseCheck::InComparison` arm in `eval_context.rs`
    /// serves `-o json`, `--structured`, the FFI and the Lambda, and this cell is its first assertion.
    ///
    /// That arm was not wholly uncovered, and saying so precisely matters because two mutations of it
    /// give different answers. Neutralizing it entirely -- both branches emitting the pre-fix sentence
    /// -- reddens `non_verbose_run_checks_reports_an_undecided_map_key_comparison`, because dropping the
    /// `. Error = [...]` suffix takes the reason with it. But a NARROW mutant that reverts only the lead
    /// words while still appending the reason left the suite at 3142 / 0 / 0, fully green. So the reason
    /// was asserted and the sentence was not, and a change reintroducing "was not present in" for a
    /// comparison that never ran would have shipped undetected. The narrow mutant is what this cell
    /// exists to catch.
    ///
    /// `Resources` in the template is load-bearing. Without it `CfnAware` hands the file to
    /// `generic_summary` and the report never enters the arm under test, which is why the console
    /// fixture -- which has no `Resources` -- cannot cover this site whatever it asserts. A separate
    /// fixture rather than a widened one, because the console cell pins `membership_lines.len() == 3`
    /// on its own file.
    ///
    /// The counts are measured rather than chosen. `k_refused` fails on the one key the pattern could
    /// not be evaluated against, so its sentence appears once; `k_decided` fails on both keys, so the
    /// decided sentence appears twice. Pinning both numbers is what makes the narrow mutant fail here:
    /// it moves them to 0 and 3 rather than merely rewording something inside a large report.
    #[test]
    fn a_refused_membership_in_structured_output_does_not_claim_a_match_happened() {
        const REFUSED: &str = "could not be compared with";
        const DECIDED: &str = "was not present in";

        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["cfn-map-key-membership-template.json"])
            .rules(vec!["membership_lead_sentence_structured.guard"])
            .output_format(Some("json"))
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both rules fail whatever the sentence says; this cell is about the sentence, not the verdict"
        );

        let output = writer.stripped().expect("failed to read the writer");

        assert_eq!(
            1,
            output.matches(REFUSED).count(),
            "the refused comparison must say it could not be compared, exactly once -- 0 means the \
             lead sentence reverted to claiming an answer:\n{}",
            output
        );
        assert_eq!(
            2,
            output.matches(DECIDED).count(),
            "the decided rule's two keys must keep the original sentence -- 3 means the refused case \
             borrowed it:\n{}",
            output
        );
        assert!(
            output.contains("could not be evaluated"),
            "the reason must still travel with the sentence on this surface, which is the only record \
             the FFI and Lambda callers get:\n{}",
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
    /// With `nan` loading as a float, the equality exits 19 and the negation exits 0, both backwards.
    /// The finite pair in `identical_scalars_compare_equal.guard` is the control -- it shares the
    /// clause shape and is right under either loading, so it fails if string loading breaks ordinary
    /// floats.
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
    /// One text event per reason from `serialize_text_events` would run the reasons together, because
    /// XML concatenates adjacent text events: `...nothing to checkbucket_named: no AWS::S3::Bucket...`.
    /// A direct serializer probe shows it where the CLI fixtures do not: some evaluator reasons happen
    /// to end in whitespace, which supplies an accidental separator, and every other fixture has only
    /// one rule to explain.
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
    /// A variable that resolved to nothing fails the comparison on either side it appears on. Closed
    /// on the right-hand side alone, `%x == 'abc'`, `%x != 'abc'` and `%x > 5` would all exit 0 when
    /// `%x` held no values, and a rule whose only check is one of those would report compliance
    /// having compared nothing, the same bypass the right-hand side refuses.
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

    /// The counterpart, and the reason failing closed on an empty left-hand side is scoped to a lone
    /// variable: a filtered query that matches nothing is not applicable, not a failure.
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

    /// A `let`'s spelling must not change what a filter over it selects.
    ///
    /// `let direct = Outer.Nested` and `let projected = Wrapper.*[ .. ].Nested` bind the same map, so
    /// reading either with `%v[ Type == 'Match' ]` has to select the same entry. It did not.
    /// `query_projects` answered `true` for `projected` because *some* part of its query projected,
    /// which consumed the slot `access_query` reserves in a variable-rooted query and left the filter
    /// testing the whole `Nested` map as one subject rather than its entries. The predicate matched
    /// nothing, and an assertion over an empty selection is not applicable -- so the projected
    /// spelling reported SKIP at exit 0 on the violation the direct spelling reported at exit 19.
    ///
    /// The silent direction is why this is a test rather than a note. The spelling that goes quiet is
    /// the one an author reaches for whenever the binding is filtered by resource type, which is the
    /// commonest shape in `aws-guard-rules-registry`; the corpus escapes it today only because every
    /// reader there is a bare one-part `%name`, for which the slot index falls past the end of the
    /// query and the value passes through untouched. That is a co-occurrence gap, not a barrier, and
    /// it closes the moment someone writes a multi-part reader over such a binding.
    ///
    /// Both rules are asserted, by the path each names rather than by comparing whole output. Naming
    /// the paths keeps the assertion independent of the absolute fixture path, and asserting both
    /// keeps a fix from satisfying this test by silencing the side that already worked.
    #[test]
    fn a_bindings_spelling_does_not_change_what_a_filter_over_it_selects() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["same-map-two-binding-spellings.yaml"])
            .rules(vec!["filter_over_a_projected_binding.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both spellings name a violating value, so the run must report a violation"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("/Outer/Nested/Entry/Value"),
            "the direct binding's violation should be reported:\n{}",
            output
        );
        assert!(
            output.contains("/Wrapper/Only/Nested/Entry/Value"),
            "the projected binding holds the same map, so its violation should be reported too:\n{}",
            output
        );
    }

    /// The same pair over a map whose entries are all scalars, where the two spellings once disagreed
    /// in the opposite direction from the test above.
    ///
    /// `Config` is `{ Status: Enabled }`, and two facts differ from `Nested`. A filter cannot apply to
    /// a scalar entry, and `Status` IS a key of `Config`. A map with a scalar entry is one object, so
    /// the filter tests the map itself: `Status == 'Enabled'` holds on it, the map is selected, and
    /// the body's `.Status == 'no-such-value-zzz'` fails as a plain comparison against "Enabled" at
    /// the key's own path. Nothing is refused (no "`Key` is `Status`, a key of the map itself"
    /// sentence, no "Could not be evaluated" section) and nothing is announced.
    ///
    /// Both sides exit 19 here, so the message text carries the whole signal. One expected message
    /// is asserted for both rules and for the author's own `[*]` spelling of the same filter
    /// (`control_star_spelling`), each with its own rule name and the key's path, so what is pinned is
    /// that the three spellings agree. If the engine later changes what it reports for a comparison
    /// against a scalar, the assertions fail together and a maintainer updates all three, where
    /// asserting only the projected side would let a change to the direct side pass unnoticed.
    #[test]
    fn a_bindings_spelling_does_not_change_a_filter_over_scalar_entries() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["same-map-two-binding-spellings.yaml"])
            .rules(vec!["filter_over_a_projected_binding.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "every clause names a value that is absent or mistyped, so the run must report violations"
        );

        let output = writer.stripped().expect("failed to read the writer");
        for (rule, path) in [
            (
                "filter_over_a_direct_scalar_entry_binding",
                "/Outer/Config/Status",
            ),
            (
                "filter_over_a_projected_scalar_entry_binding",
                "/Wrapper/Only/Config/Status",
            ),
            ("control_star_spelling", "/Outer/Config/Status"),
        ] {
            // The comparison's own failure. The line also names the data file by its absolute
            // path, which the test does not know, so the three parts that identify the finding are
            // read from one line.
            let property = format!("Property [{}] in data [", path);
            let rule_part = format!("is not compliant with [{}] because ", rule);
            let comparison =
                "provided value [\"Enabled\"] did not match expected value [\"no-such-value-zzz\"]";
            let found = output.lines().any(|line| {
                line.contains(&property) && line.contains(&rule_part) && line.contains(comparison)
            });
            assert!(
                found,
                "{} should fail on the comparison with \"Enabled\" at {}, as its counterparts do; wanted {:?}, {:?} and {:?} on one line of:\n{}",
                rule,
                path,
                property,
                rule_part,
                comparison,
                output
            );
        }
        // The map is one object: nothing is refused for its own key, so neither sentence of the
        // refusal and no "Could not be evaluated" section is written for these rules.
        for refusal in [
            "The filter selected nothing among the map's own entries",
            "a key of the map itself",
            "Could not be evaluated",
        ] {
            assert!(
                !output.contains(refusal),
                "a filter over a map whose entries are all scalars tests the map itself and is not refused; found {:?} in:\n{}",
                refusal,
                output
            );
        }
    }

    /// The console's "Could not be evaluated" section bounds a line by the kind of message the record
    /// carries, never by its words. The three rules fail their condition and reach the section through
    /// the same rule arm; what differs is what the evaluator embedded. The refusal is the evaluator's own
    /// sentence, 704 characters at the tip this was cut over, and is printed whole, remedy and path
    /// included. The converter's message carries the 2048-character template string it could not
    /// convert, and the JSON parser's message carries the 2150-character string that is not JSON, so
    /// each of those lines is held to the recorded-message cap and the string is gone from it.
    ///
    /// Measured at the parent of this change: the section read the error's wrapper to pick the bound,
    /// every unevaluatable clause displays that wrapper, and the converter's line came out whole at
    /// 2277 characters, about seven times the cap written for exactly that value.
    #[test]
    fn the_console_bounds_an_explanation_by_its_kind_and_not_its_words() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["refusal-beside-a-two-kilobyte-value.yaml"])
            .rules(vec!["refusal_and_value_carrying_text.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both conditions fail closed, so the run reports violations"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let lines: Vec<&str> = output.lines().collect();
        // The section prints each rule's heading on one line and its explanation on the next.
        let explanation_under = |heading: &str| -> &str {
            let at = lines
                .iter()
                .position(|line| line.trim() == heading)
                .unwrap_or_else(|| panic!("no {:?} heading in:\n{}", heading, output));
            lines[at + 1].trim()
        };

        let refused = explanation_under("rule refusal_longer_than_the_cap");
        assert!(
            refused.chars().count() > 320,
            "the refusal runs past the cap by construction; got {} characters: {}",
            refused.chars().count(),
            refused
        );
        assert!(
            refused.contains("where `X` is `Resources.*.Properties.Configuration.Settings.Tags`")
                && refused
                    .contains("at path /Resources/Big/Properties/Configuration/Settings/Tags"),
            "the remedy and the path sit past the cap and are printed: {}",
            refused
        );
        assert!(
            refused.ends_with('`') && !refused.contains("..."),
            "a refusal is whole, not cut: {}",
            refused
        );

        let cut = explanation_under("rule value_carrying_text_is_cut");
        assert!(
            cut.ends_with("...") && cut.contains("failed to convert a string:"),
            "the converter's line is cut at the cap, after the sentence and before the value: {}",
            cut
        );
        assert!(
            cut.chars().count() <= 320 + 3,
            "{} characters against a cap of 320 plus the ellipsis: {}",
            cut.chars().count(),
            cut
        );
        assert!(
            !cut.contains("0123456789abcdef0123456789abcdef"),
            "the template value is dropped whole: {}",
            cut
        );

        // The parser's message over the 2150-character string that is not JSON is the other sentence a
        // template value reaches this section through, and it is bounded the same way.
        let parsed = explanation_under("rule parser_text_is_cut");
        assert!(
            parsed.ends_with("...") && parsed.contains("failed to parse"),
            "the parser's line is cut at the cap, after the sentence and before the value: {}",
            parsed
        );
        assert!(
            parsed.chars().count() <= 320 + 3,
            "{} characters against a cap of 320 plus the ellipsis: {}",
            parsed.chars().count(),
            parsed
        );
        assert!(
            !parsed.contains("9876543210fedcba9876543210fedcba"),
            "the string that is not JSON is dropped whole: {}",
            parsed
        );
    }

    /// The list-valued half, which needs its own case because the reserved slot behaves differently
    /// over a list than over a map: `[*]` on a map is a documented pass-through, so consuming the slot
    /// and walking it can coincide, while on a list it enumerates, so the two readings differ for
    /// every tail rather than only for a filter.
    ///
    /// Three tails, each measured to disagree at the tip, and all three at exit 19 on both sides --
    /// so the exit code is not the signal and the message text is. `%direct` and `%projected` hold the
    /// same list, so each pair is asserted to produce the same message with only the path differing:
    ///
    /// - `%v[0]`: the filtered spelling reported `PathAwareValues are not comparable map, String`,
    ///   having applied the index to the list and compared the element it found, where the direct
    ///   spelling enumerated first and reported the index against a map. Both now report the former,
    ///   and the needles below say so; see the note under the index pair for why that is the owed
    ///   answer and not merely the newer one.
    /// - `%v.Status`: the filtered spelling reported the key against the whole array, the direct
    ///   spelling against each entry.
    /// - `%v[ keys == /Status/ ]`: the filtered spelling reported
    ///   `Map Filter for keys was not a struct array`, where the direct spelling tested each entry's
    ///   keys.
    ///
    /// THOSE THREE PAIRS DO NOT HOLD A PROJECTING BINDING, and the fixture is named for one. Both
    /// `%direct` and `%filtered` end their query with a `Key`, and the last act is the whole of what
    /// `query_projects` reads, so both are judged not to project and both walk the reserved slot. The
    /// pairs are a real control on a shared answer, but the invariant stated below could not fire
    /// through them -- which is why the fixture read as covering a projected list binding while
    /// covering the other one, and why the divergence it exists to catch survived here.
    ///
    /// So a fourth pair was added, and it is the one the file's name claims. `Outer.Groups` is
    /// `[[{Key: Name, Value: alpha}]]`; `%indexed` is `Outer.Groups[0]` and `%enumerated` is
    /// `Outer.Groups[*]`, which leave the same inner list in hand and are judged differently, because
    /// `part_projects` counts an expansion and not an index. Its tail writes the author's own `[*]`,
    /// where `access_query` retags rather than inserting and so leaves no reserved slot to consume.
    /// Two rules carry the identity premise, asserted rather than assumed.
    ///
    /// Asserted as agreement between the two spellings rather than against a particular verdict. The
    /// engine may answer these however it likes; it has to answer them the same way, because the two
    /// variables hold the same list. Both sides of each pair are named so that a fix cannot pass by
    /// breaking the side that already worked.
    ///
    /// One tail is left open on purpose and named in the fixture: `%indexed.Value` against
    /// `%enumerated.Value`, where slot 1 IS the reserved slot and `binding_enumerated` decides. The
    /// deviant side there is the indexed binding, measured against a literal oracle that `QueryPart::Key`
    /// makes sound, and closing it is a change to `part_projects` that moves every `let v = Q[0]`.
    #[test]
    fn a_bindings_spelling_does_not_change_what_a_descent_into_it_traverses() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["same-map-two-binding-spellings.yaml"])
            .rules(vec!["descent_into_a_projected_list_binding.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "every clause names a value that is absent or mistyped, so the run must report violations"
        );

        let output = writer.stripped().expect("failed to read the writer");

        // The index pair's oracle is the literal spelling of the same descent,
        // `Outer.Tags[0] == 'no-such-value-zzz'`, which reports `PathAwareValues are not comparable
        // map, String` and cannot take the reserved-slot path at all. Both binding spellings answer
        // as it does: `access_query` records whether it inserted slot 1, and an index consumes that
        // slot instead of walking it in front of the list and enumerating the map *inside* the list
        // first, which would report `Attempting to retrieve from index 0 but type is not an array`.
        // Two spellings agreeing on that message would satisfy the agreement this test asks for while
        // agreeing on an answer the language does not give, and `%g[0]` and `Outer.Tags[0]` over this
        // fixture sit at exit 19 apiece and differ in nothing but this message, so nothing that
        // compares exit codes could see the disagreement.
        //
        // The four needles below the index pair are the control: the index pair answers as its
        // oracle does, and the other descents over a binding keep their own messages.
        for (rule, path, expected) in [
            (
                "index_into_a_direct_binding",
                "/Outer/Tags/0",
                "PathAwareValues are not comparable map, String",
            ),
            (
                "index_into_a_filtered_binding",
                "/Wrapper/Only/Tags/0",
                "PathAwareValues are not comparable map, String",
            ),
            (
                "key_descent_over_a_direct_binding",
                "/Outer/Tags/0",
                "Could not find key Status inside struct at path /Outer/Tags/0",
            ),
            (
                "key_descent_over_a_filtered_binding",
                "/Wrapper/Only/Tags/0",
                "Could not find key Status inside struct at path /Wrapper/Only/Tags/0",
            ),
        ] {
            // Path and message asserted on the one line that names this rule. The index pair's message
            // no longer embeds the path it traversed to, and the path is half of what this test is for,
            // so a single `contains` over the whole output would no longer tie the two together -- the
            // data file's absolute path sits between them.
            //
            // Still `contains` rather than whole-output comparison, for the reason the rest of this file
            // is: the text a comparison would have to match embeds an absolute prefix baked in at compile
            // time. `utils.rs`'s `replace_path_with_filenames` builds its pattern from
            // `fancy_regex::escape(env!("CARGO_MANIFEST_DIR"))` and `sanitize_path` is the only thing
            // between the run's output and the expected file, so the prefix that gets stripped is
            // whatever `CARGO_MANIFEST_DIR` held when this test binary was *built*, not where it runs.
            // Nothing here keys on a home directory and nothing keys on a symlink. That matters because a
            // reader who believes it does concludes whole-output comparison works on any other machine
            // and switches to it -- and it still fails, because `env!` bakes at compile time and the
            // baked prefix travels with the binary.
            //
            // This file's own total is unexplained, and the `contains` is not what explains it. It reports
            // 231 passed / 0 failed in some checkouts and 214 / 17 in others. Two candidate mechanisms
            // were tested and both are disproved: path spelling -- the same worktree invoked through its
            // real path and through a symlink that reaches it gives 231/0 both times -- and a shared
            // `CARGO_TARGET_DIR` serving a stale baked prefix, where cargo recompiled, re-baked, and
            // still gave 231/0. The split is environmental with the cause unidentified. Do not supply a
            // third mechanism here. Inventing a plausible one is what put a developer's home directory
            // into this comment.
            let marker = format!("is not compliant with [{}]", rule);
            let line = output
                .lines()
                .find(|line| line.contains(&marker))
                .unwrap_or_else(|| panic!("nothing reports {} at all in:\n{}", rule, output));
            let traversed = format!("Property traversed until [{}]", path);
            assert!(
                line.contains(&traversed) && line.contains(expected),
                "{} should traverse the list the same way its counterpart does; wanted {:?} and {:?} \
                 on:\n{}",
                rule,
                traversed,
                expected,
                line
            );
        }

        for rule in [
            "key_filter_over_a_direct_binding",
            "key_filter_over_a_filtered_binding",
        ] {
            let needle = format!(
                "[{}] because provided value [\"Key\"] did not match expected value [\"/Status/\"]",
                rule
            );
            assert!(
                output.contains(&needle),
                "{} should test each entry's keys rather than the list itself; wanted {:?} in:\n{}",
                rule,
                needle,
                output
            );
        }

        // The pair the fixture is named for, and the only pair in it where the two bindings sit on
        // opposite sides of `query_projects`. Both rules fail on both sides of the repair, so the
        // exit code is not the signal here either: `authored_wildcard_over_an_enumerated_binding`
        // reported `Attempting to retrieve from key Value but type is not an struct type` at
        // `/Outer/Groups/0` -- the key applied to the list, because the projecting binding's judgment
        // consumed the author's own `[*]` and left the query with nothing to run after its root --
        // where the indexed spelling reported the comparison against `alpha` one level down. Both now
        // report the latter.
        //
        // Asserted as the same path and the same message for both spellings, not as a chosen verdict,
        // and both sides are named so that agreement cannot be reached by breaking the side that
        // already worked.
        for rule in [
            "authored_wildcard_over_an_indexed_binding",
            "authored_wildcard_over_an_enumerated_binding",
        ] {
            let needle = "Property [/Outer/Groups/0/0/Value] in data";
            let marker = format!(
                "[{}] because provided value [\"alpha\"] did not match expected value \
                 [\"no-such-value-zzz\"]",
                rule
            );
            let line = output
                .lines()
                .find(|line| line.contains(&marker))
                .unwrap_or_else(|| {
                    panic!(
                        "nothing reports {} with the owed message in:\n{}",
                        rule, output
                    )
                });
            assert!(
                line.contains(needle),
                "{} must reach the map inside the list, at /Outer/Groups/0/0/Value, whichever way \
                 the binding was spelled; got:\n{}",
                rule,
                line
            );
        }

        // And the identity premise. Without it a change to what either binding HOLDS would read as
        // the pair having reached agreement.
        for rule in [
            "the_indexed_binding_holds_a_list",
            "the_enumerated_binding_holds_a_list",
        ] {
            let needle = format!("Rule [{}] is compliant", rule);
            assert!(
                output.contains(&needle),
                "{} is the premise that the two bindings hold the same list; wanted {:?} in:\n{}",
                rule,
                needle,
                output
            );
        }
    }

    /// A clause that passes today, and will not in a later release, says so on stderr without changing
    /// this run's answer.
    ///
    /// It is a spec violation rather than a judgment call. `CLAUSES.md` says a comparison across kinds
    /// that are not both numeric "cannot be decided, and the clause fails rather than guessing", which
    /// `!=` honours and `NOT IN` does not. It is not changed yet because `NOT IN` cannot change until five
    /// rules in aws-guard-rules-registry stop relying on the current reading -- failing closed there
    /// makes a filter select fewer resources and turns a reported violation into a pass. So the notice
    /// goes out a release ahead of the change.
    ///
    /// A comparison over an empty collection, which `QUERY_AND_FILTERING.md` lists beside a missing key
    /// as a retrieval error, fails and carries no notice, so it is not a clause of this fixture;
    /// `an_empty_collection_fails_the_comparison_in_the_output` covers that failure.
    ///
    /// On stderr, not in the report: the report on stdout is what pipelines parse, and a notice about a
    /// future release is not part of this run's result. This also keeps every golden file untouched.
    ///
    /// The assertion covers the verdict as well as the notice, because a deprecation notice that moves
    /// a verdict is not a notice. And it binds the notice to the clause it is about, by the property
    /// name only that clause reads.
    #[test]
    fn clauses_whose_answer_changes_later_warn_now() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["incomparable-membership-template.yaml"])
            .rules(vec!["incomparable_membership_clause.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the notice must not change the verdict; the clause still passes in this release"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(
            notices.len(),
            1,
            "expected one notice for the one warning clause, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        // The clause context is in the line -- the notice reads `Name not IN  [10,50,100] passed
        // because ...` -- so the notice is required to name its own clause as well as to carry the
        // membership wording.
        assert!(
            notices[0].contains("could not be compared with any element")
                && notices[0].contains("Name"),
            "the incomparable-membership notice must be about `Name`, the clause whose value no \
             element of the list could be compared with; got {:?}",
            notices[0]
        );
    }

    /// A comparison over a collection that is present and empty fails, and the report says why.
    ///
    /// `QUERY_AND_FILTERING.md` lists `Tags: []` beside a missing key and an empty map as retrieval
    /// errors and states that all retrieval errors are failures. The other two always failed; this one
    /// passed, because the ordering operators and `==` against a scalar compare a list's elements and
    /// an empty list has none, so the clause passed on a comparison that never ran. A release's
    /// deprecation notice announced that a clause which passed without comparing anything would fail,
    /// which is this fixture's shape: every value the query selected is an empty collection, so the
    /// whole clause compared nothing. The per-value case, an empty list beside a populated sibling,
    /// goes further than the notice announced and is recorded in `docs/KNOWN_ISSUES.md`.
    ///
    /// Per value, so the finding carries the empty collection's own path and lands under its resource,
    /// and with the reason in the `Error` slot so a reader is told why a comparison with nothing to
    /// compare failed rather than passed. `IN` fails the same way: an empty list is not read as a
    /// subset of any set, because an empty collection is the same retrieval error on every binary
    /// operator. Nothing reaches stderr: there is no later change left to announce.
    #[test]
    fn an_empty_collection_fails_the_comparison_in_the_output() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["empty-collections-template.yaml"])
            .rules(vec!["empty_collection_comparisons.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "an empty collection fails `<=` and `==`, so the file fails"
        );

        let output = writer.stripped().expect("failed to read stdout");
        // The summary pads rule names to a common width, so each verdict is read off the line that
        // names the rule rather than matched with its padding.
        let verdict_of = |rule: &str| -> String {
            let needle = format!("empty_collection_comparisons.guard/{rule}");
            output
                .lines()
                .find(|line| line.contains(&needle))
                .map(|line| line.trim_end().rsplit(' ').next().unwrap_or("").to_string())
                .unwrap_or_else(|| panic!("the summary must list {}; got:\n{}", rule, output))
        };
        assert_eq!("FAIL", verdict_of("ports_in_range"), "got:\n{}", output);
        assert_eq!(
            "FAIL",
            verdict_of("security_group_named"),
            "got:\n{}",
            output
        );
        assert_eq!("FAIL", verdict_of("ports_allowed"), "got:\n{}", output);

        for expected in [
            "Resource = Instance {",
            "PropertyPath    = /Resources/Instance/Properties/Ports[",
            "PropertyPath    = /Resources/Instance/Properties/SecurityGroupIds[",
            "Value           = []",
            "The value is an empty collection, so there was nothing to compare",
        ] {
            assert!(
                output.contains(expected),
                "the report must carry {:?}; got:\n{}",
                expected,
                output
            );
        }

        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        ValidateTestRunner::default()
            .data(vec!["empty-collections-template.yaml"])
            .rules(vec!["empty_collection_comparisons.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            !stderr.contains("DEPRECATION"),
            "the empty-collection comparison fails now, so there is no notice left to print; got {:?}",
            stderr
        );
    }

    /// An empty collection in a `when` condition leaves the rule not applicable, with the reason named.
    ///
    /// Two rules over the same empty `Ports`: `ports_guarded` puts `Ports !empty` beside the comparison,
    /// and `ports_guarded_alone` has the comparison alone. Both are not applicable, the file exits 0, and
    /// the not-applicable summary explains each with the empty collection. Neither says the rule failed.
    /// Two shapes that would: a recorded reason that says "the rule fails closed" explains the SKIP
    /// decided by the `!empty` conjunct with a sentence announcing a FAIL; an unguarded gate that fails
    /// its rule closed sends `Ports: []` and a missing `Ports` on the same gate different ways, and fails
    /// a template whose other resources are compliant on one empty list. The
    /// record states only the fact -- an empty collection, nothing to compare, the condition not
    /// satisfied -- and the skip-reason finder's "did not apply because one of its conditions was not
    /// met" is the sentence that names the outcome.
    #[test]
    fn an_empty_collection_in_a_condition_leaves_the_rule_not_applicable() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["empty-collections-template.yaml"])
            .rules(vec!["empty_collection_in_a_guarded_condition.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "neither rule applies to a document whose `Ports` is empty, so the file passes"
        );

        let output = writer.stripped().expect("failed to read stdout");
        for rule in ["ports_guarded", "ports_guarded_alone"] {
            let needle = format!("{rule}:");
            let skip_reason = output
                .lines()
                .find(|line| line.trim_start().starts_with(&needle))
                .unwrap_or_else(|| {
                    panic!(
                        "the summary must explain the skipped rule {}; got:\n{}",
                        rule, output
                    )
                });
            for expected in [
                "did not apply because one of its conditions was not met",
                "The value is an empty collection, so there was nothing to compare",
                "not satisfied",
            ] {
                assert!(
                    skip_reason.contains(expected),
                    "the skip reason for {} must carry {:?}; got:\n{}",
                    rule,
                    expected,
                    skip_reason
                );
            }
            assert!(
                !skip_reason.contains("fails closed")
                    && !skip_reason.contains("fails rather than")
                    && !skip_reason.contains("could not be decided"),
                "a rule that was not applicable must not be explained as failing or undecided; got:\n{}",
                skip_reason
            );
        }
        assert!(
            !output.contains("could not be evaluated") && !output.contains("FAILED rules"),
            "no rule failed, so nothing in the output may say so; got:\n{}",
            output
        );
    }

    /// A comparison whose two sides both resolve to an empty collection fails, and every reporter says so.
    ///
    /// With a left-hand empty list and a right-hand value to show beside it, the failure is filed per
    /// value. With the right-hand side also empty there is no pair at all, and the first version of this
    /// fix filed a per-value check with no right-hand value, which the console and the structured
    /// reporters both dropped: the run exited 19 with `Number of non-compliant resources 0` and
    /// `"checks": []`. The clause now reaches the block-level compared-nothing explanation instead, which
    /// the reporters already render, so the reason survives in the console summary and in `-o json`.
    #[rstest::rstest]
    #[case::console(None)]
    #[case::json(Some("json"))]
    fn an_empty_collection_on_both_sides_explains_itself_in_every_reporter(
        #[case] output: Option<&str>,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = match output {
            Some(format) => ValidateTestRunner::default()
                .data(vec!["empty-collections-template.yaml"])
                .rules(vec!["empty_collections_on_both_sides.guard"])
                .structured()
                .output_format(Some(format))
                .run(&mut writer, &mut reader),
            None => ValidateTestRunner::default()
                .data(vec!["empty-collections-template.yaml"])
                .rules(vec!["empty_collections_on_both_sides.guard"])
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader),
        };

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "nothing was compared, so the clause fails"
        );

        let stdout = writer.stripped().expect("failed to read stdout");
        if output.is_some() {
            serde_json::from_str::<serde_json::Value>(&stdout).expect("the json report must parse");
            assert!(
                !stdout.contains(r#""checks": []"#),
                "the failing rule must carry a check, not an empty list; got:\n{}",
                stdout
            );
        }
        assert!(
            stdout.contains("compared nothing")
                && stdout.contains("produced no pair of values to compare"),
            "the report must say why the clause failed; got:\n{}",
            stdout
        );
    }

    /// A `NOT IN` condition that fails gets no notice, however quiet the run it leaves behind.
    ///
    /// This asserted the opposite until the premise under it was checked, and the premise is worth keeping
    /// because it is genuinely tempting. The condition here fails, a failing condition skips its rule, and
    /// the file exits 0 with an empty report while the body it dropped would have failed. Silent green --
    /// so the notice looks like the author's only sight of the clause, and suppressing it looks like losing
    /// the one warning that mattered.
    ///
    /// What that misses is what the notice claims. It says a future release fails closed where this one
    /// passes, and this condition does not pass, so the change does not move it. That is measurable rather
    /// than arguable: `!=` fails closed today, and a condition reaching `NotComparable` skips its rule at
    /// exit 0 exactly as this one does. Before and after are both green, so a notice here warns about a
    /// non-event -- and it cost two false sentences to print, since the body written for it said "Nothing
    /// in the report says so" while the report names this clause whenever a later clause in the same rule
    /// fails, and said the pair "currently reads as not a member" even where the pair already errors out.
    ///
    /// An integration test rather than only a unit one, because the unit helper reads
    /// `RootScope::deprecations` directly and cannot see the two things that make this shape look like a
    /// defect: the exit code, and the empty report.
    ///
    /// `clauses_whose_answer_changes_later_warn_now` is the positive half, on a clause that does pass. This
    /// asserting an absence is only meaningful beside it -- on its own it would be satisfied by a build that
    /// never emits this notice at all.
    ///
    /// Which is why that positive half now runs here too, as the third run below, rather than being left as
    /// a cross-reference in this comment. A reference is not a control: the two tests are separate binaries'
    /// worth of state as far as a reader is concerned, and nothing made the absence fail when the notice
    /// stopped being emitted anywhere. The control is the same fixture pair
    /// `clauses_whose_answer_changes_later_warn_now` uses, driven through the same `ValidateTestRunner` and
    /// the same stderr drain, so what it proves is precisely what this test needs: the path from the
    /// scope's recorded notices to a `DEPRECATION` line on stderr was live in this process. It does not
    /// prove that the absorbed condition reached the predicate, and nothing over an absence can.
    #[test]
    fn a_notice_stays_away_from_the_failure_a_when_condition_absorbs() {
        // The same run twice, because `Writer::stripped` and `Writer::err_to_stripped` each consume the
        // writer, so one run answers for one stream. Both are asserted: the report says nothing about the
        // clause, and neither does stderr.
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["absorbed-incomparable-template.yaml"])
            .rules(vec!["absorbed_incomparable_condition.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "a failing condition still skips its rule; the verdict is the same whether or not a notice is written"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            !output.contains("ports_not_denied") && !output.contains("Encrypted"),
            "the report stays silent on a skipped rule; got {:?}",
            output
        );

        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["absorbed-incomparable-template.yaml"])
            .rules(vec!["absorbed_incomparable_condition.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both runs are the same run; a differing exit code means the fixture is not deterministic"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert!(
            notices.is_empty(),
            "the condition failed, so the coming change leaves it where it is and there is nothing for \
             this notice to announce; got {:?} from stderr {:?}",
            notices,
            stderr
        );

        // The positive half, in this process. Without it the assertion above is satisfied by a build in
        // which no clause anywhere reaches stderr with a notice, which is the state it looks like it rules
        // out and does not.
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["incomparable-membership-template.yaml"])
            .rules(vec!["incomparable_membership_clause.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the control's clauses pass in this release; a differing exit code means the control is \
             broken rather than the absence above"
        );

        let control_stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            control_stderr.contains("could not be compared with any element"),
            "a clause that does pass on an incomparability must reach stderr with this notice, or the \
             empty `notices` above is not evidence about the absorbed condition -- it is evidence that \
             nothing emits this notice at all; got {:?}",
            control_stderr
        );
    }

    /// The notices reach `--structured` too, which is the mode a pipeline actually runs.
    ///
    /// `clauses_whose_answer_changes_later_warn_now` covers the single-line path, and that was the only
    /// path covered. The structured evaluator builds its own `RootScope` per rules file and went from
    /// `eval_rules_file` straight to `reset_recorder` without ever reading `deprecations()`, so every
    /// notice was discarded -- silently, since a discarded notice leaves no trace anywhere. The run
    /// exited 0 with an empty stderr and a report saying the template complied, which is also what a
    /// template with nothing to warn about produces.
    ///
    /// That voided the whole warn-a-release-ahead approach for the audience it was built for. The notice
    /// exists to tell a rule author that a later release fails closed where this one passes; `--structured`
    /// is the machine-readable mode CI runs, so the pipeline that will break was the one place the warning
    /// never appeared.
    ///
    /// All four structured formats, not just json. `-o junit` reaches a different reporter --
    /// `JunitReporter`, whose scope lives inside `get_test_case` -- and dropped the notices by its own
    /// route rather than by the one the other three share. Covering only json would have left the defect
    /// in place for a junit test reporter, which is the most CI-shaped consumer of the four.
    ///
    /// Both streams are asserted, for the reason the single-line test gives: the notice belongs on stderr
    /// because stdout is parsed, and the json case is parsed here to prove the document survived.
    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("sarif")]
    #[case("junit")]
    fn a_deprecation_notice_reaches_the_structured_reporters(#[case] output: &str) {
        // `stripped` and `err_to_stripped` each consume the writer, so one run answers for one stream.
        // The command is deterministic over these inputs, so two runs read the same output twice.
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            let status_code = ValidateTestRunner::default()
                .data(vec!["incomparable-membership-template.yaml"])
                .rules(vec!["incomparable_membership_clause.guard"])
                .structured()
                .output_format(Some(output))
                .run(&mut writer, &mut reader);

            (status_code, writer)
        };

        let (status_code, out_writer) = run();
        let (_, err_writer) = run();

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the notice must not change the verdict; the clause still passes in this release"
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            !stdout.contains("DEPRECATION"),
            "a notice on stdout would land inside the document consumers parse, got {:?}",
            stdout
        );
        assert!(
            !stdout.is_empty(),
            "the structured document must still be written; an empty stdout means this cell is \
             measuring a run that produced no report at all, not a notice reaching stderr"
        );

        if output == "json" || output == "sarif" {
            serde_json::from_str::<serde_json::Value>(&stdout)
                .expect("the document on stdout must still parse with a notice on stderr");
        }

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();

        assert_eq!(
            notices.len(),
            1,
            "expected one notice for the one warning clause, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices[0].contains("could not be compared with any element"),
            "the membership clause must say nothing in the list was comparable, got {:?}",
            notices
        );
    }

    /// Two rules files that differ only by directory get two different locators.
    ///
    /// The notice ends with the clause's source position so that a reader can go to the clause, and
    /// each notice is meant to name a distinct rules file and line. Before this fix it did not: both call
    /// sites built the name with `get_file_name(file, file)`, and `strip_prefix` against itself yields
    /// the empty path, so the function fell through to `file_name()` and every rules file was known by
    /// its basename alone. Two files named `incomparable_membership.guard` in different directories
    /// produced two byte-identical notices.
    ///
    /// The count is not the symptom *on this path*, so this counts distinct lines and separately
    /// requires each locator to name the directory that tells the two files apart. What was lost is
    /// that the two notices were the same two characters, and the reader could locate neither clause.
    ///
    /// "On this path" is the qualifier that decides it, and the mechanism is recorded on the shared
    /// `Notices` set in `reporters/validate/structured.rs`. In short: the
    /// single-line path this cell runs keeps one set per rules file across that file's data files, and
    /// this cell runs two rules files over one data file, so each rules file's notice is in a set of its
    /// own and both come out; all four structured formats hold one set across the whole document and
    /// dedupe two byte-identical notices to one. So the count is a symptom there and not here.
    ///
    /// The single-line path rather than `--structured`, deliberately: this fixes the locator, and
    /// asserting it through the structured path would make this cell depend on the notices reaching
    /// that path at all, which is a different defect with its own cell above. Red for one reason each.
    #[test]
    fn two_rules_files_sharing_a_basename_get_distinct_locators() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["incomparable-membership-template.yaml"])
            .rules(vec![
                "same-basename-rules-dirs/first/incomparable_membership.guard",
                "same-basename-rules-dirs/second/incomparable_membership.guard",
            ])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "naming a file is not a verdict; both clauses still pass in this release"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();

        assert_eq!(
            notices.len(),
            2,
            "one notice per rules file, since each gets its own scope; got {:?} from stderr {:?}",
            notices,
            stderr
        );

        let distinct: std::collections::BTreeSet<&&str> = notices.iter().collect();
        assert_eq!(
            distinct.len(),
            2,
            "the two notices must differ; identical lines mean the locator dropped the only thing \
             that tells these two files apart, got {:?}",
            notices
        );

        // And they differ by the directory, not by something incidental. Requiring each notice to
        // carry its own parent and not the other's is what makes the assertion above mean "the
        // locator distinguishes them" rather than "the two lines happen to be unequal". The locator
        // renders the path with the platform's separator, so the expected tail is built with `join`
        // rather than written with a slash.
        for parent in ["first", "second"] {
            let tail = std::path::Path::new(parent)
                .join("incomparable_membership.guard")
                .display()
                .to_string();
            let matched: Vec<&&str> = notices.iter().filter(|n| n.contains(&tail)).collect();

            assert_eq!(
                1,
                matched.len(),
                "expected exactly one notice locating the clause in `{}`, got {:?} from {:?}",
                parent,
                matched,
                notices
            );
        }
    }

    /// A notice recorded before the rules file failed still leaves through the junit reporter.
    ///
    /// `-o junit` is the one structured format whose deprecation set lives inside `get_test_case`, and
    /// that function returns early when `eval_rules_file` hands back an error. `eval_rules_file`
    /// evaluates every rule before returning, so a clause that reached a notice has already recorded
    /// it -- and the early return dropped the scope without reading it, losing the notice for the one
    /// input where the author most needs everything the run had to say.
    ///
    /// The `Ok` arm a few lines further down does the same read, and
    /// `a_deprecation_notice_reaches_the_structured_reporters` covers that one over a fixture where
    /// nothing errors. This cell is about the other arm, which is why the fixture has to fail and why
    /// `status="error"` on stdout is asserted: without it the cell would be satisfied by the `Ok` arm
    /// and would say nothing about the early return. The resolver error is asserted too, so the reason
    /// the arm was taken is pinned rather than assumed from the status alone.
    ///
    /// Junit only, and the other three structured formats would be actively misleading here. They go
    /// through `CommonStructuredReporter`, which does not return early on an eval error -- it stashes it in
    /// `first_error` and carries on to its own drain (`first_error = Some(e)` stashes,
    /// `deprecations.absorb_deprecations` accumulates into the `Notices` set, `for notice in
    /// deprecations.iter()` writes it out; all three in `CommonStructuredReporter::report`).
    /// So a json, yaml or sarif case over this same fixture reaches the `Ok`-arm equivalent, passes with
    /// the junit drain removed, and would eventually go red for something else entirely.
    ///
    /// Two mechanisms, so one pointer was always going to be short. The `first_error` half is the
    /// `let mut first_error = None` and the `first_error = Some(e)` stash; the drain half is the
    /// `absorb_deprecations` call and the `deprecations.iter()` write loop. The three named above are the
    /// set worth citing because the word the citation hangs on is "drain", and they cover a stash plus
    /// both ends of it. Names rather than line numbers: a `file:line` into another file goes stale
    /// silently, because a comment inserted above the cited line moves every number below it and no test
    /// catches it, so such a citation is re-derived against the tree being written or not made at all.
    ///
    /// One notice, not two. `notice_then_error.guard` has one clause that warns, so a count is exact
    /// here rather than a floor -- the run either carried the notice past the early return or it did
    /// not.
    ///
    /// The exit code is `PARSING_ERROR`: a reference no `let` declares is the rules author's mistake,
    /// not cfn-guard falling over. Asserted because a notice that moved the verdict is not a notice.
    #[test]
    fn a_notice_recorded_before_an_error_reaches_the_junit_report() {
        // `stripped` and `err_to_stripped` each consume the writer, so one run answers for one stream.
        // The command is deterministic over these inputs.
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            let status_code = ValidateTestRunner::default()
                .data(vec!["incomparable-membership-template.yaml"])
                .rules(vec!["notice_then_error.guard"])
                .structured()
                .output_format(Some("junit"))
                .run(&mut writer, &mut reader);

            (status_code, writer)
        };

        let (status_code, out_writer) = run();
        let (_, err_writer) = run();

        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "an undeclared reference is the rules author's mistake, and the notice must not move it"
        );

        let stdout = out_writer.stripped().expect("failed to read stdout");
        assert!(
            stdout.contains(r#"status="error""#),
            "this cell is about the arm `eval_rules_file` errors out of; a test case in any other \
             state means the run left through the `Ok` arm and the assertion below proves nothing \
             about the early return. Got {:?}",
            stdout
        );
        assert!(
            stdout.contains("Could not resolve variable by name undeclared_name"),
            "and the error must be the unresolved reference, so the arm was taken for the reason \
             this fixture is built on. Got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION"),
            "a notice on stdout would land inside the document a junit reporter parses, got {:?}",
            stdout
        );

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();

        assert_eq!(
            notices.len(),
            1,
            "the file has one warning clause, and it was evaluated before the rule that failed, so \
             the notice must survive the early return; got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices[0].contains("could not be compared with any element"),
            "and it must be the membership notice the warning clause produces, got {:?}",
            notices
        );
    }

    /// The counterpart: clauses that are not changing stay silent.
    ///
    /// A deprecation notice is only useful if it is rare. The cases here are the ones most likely to be
    /// mistaken for the ones above -- a filtered query that matched nothing, a `some` clause over the
    /// same empty collection whose answer is already FAIL and is not changing, and ordinary comparisons
    /// that decide normally.
    ///
    /// # Why the last row is a fixture that does warn
    ///
    /// Every row but the last asserts an absence, and until the control was added this test held nothing
    /// else -- not even the exit code. So it could not fail for the property it names: a build in which no
    /// clause anywhere reached stderr with a notice satisfied all of it, and that build is the regression
    /// this test is the counterpart to. Measured: silencing `incomparable_membership` at its source left
    /// this test green while reddening every test that expects a notice.
    ///
    /// The control is the fixture pair `clauses_whose_answer_changes_later_warn_now` uses, so the same
    /// command, reporter and stderr drain carry it, and the row's expectation is the only difference
    /// between it and the two quiet rows. The exit code is asserted on every row for the same reason --
    /// a run that failed to start produces no stderr either, and an absence over an empty stream is not
    /// a fact about the clause.
    #[test]
    fn clauses_whose_answer_is_unchanged_stay_quiet() {
        for (label, rules_file, data_file, expect_notice) in [
            (
                "a filtered query that matched nothing",
                "large_volumes_encrypted_type_block.guard",
                "no-volumes-template.yaml",
                false,
            ),
            (
                "ordinary comparisons that decide",
                "denied_names_guarded_by_not_empty.guard",
                "bucket-with-no-kms-keys-template.yaml",
                false,
            ),
            // The control. Same command, same drain, opposite expectation.
            (
                "a clause whose answer does change, which must still warn",
                "incomparable_membership_clause.guard",
                "incomparable-membership-template.yaml",
                true,
            ),
        ] {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");

            let status_code = ValidateTestRunner::default()
                .data(vec![data_file])
                .rules(vec![rules_file])
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader);

            assert_eq!(
                StatusCode::SUCCESS,
                status_code,
                "{} must run to completion; a run that did not start produces no stderr either, and \
                 the assertion below would read that as silence",
                label
            );

            let stderr = writer.err_to_stripped().expect("failed to read stderr");
            assert_eq!(
                expect_notice,
                stderr.contains("DEPRECATION"),
                "{} should {} a notice, got: {}",
                label,
                match expect_notice {
                    true => "emit",
                    false => "emit no",
                },
                stderr
            );

            // The channel by name, and not merely a `DEPRECATION` line. The quiet rows above assert
            // that no notice of any kind arrives, so a control that only proves *some* notice reaches
            // stderr would leave them satisfied by any other line carrying the word. Naming the notice
            // is what makes this channel going quiet fail here. There is one channel now: the
            // empty-collection notice this fixture also carried is retired, that comparison fails.
            if expect_notice {
                let text = "could not be compared with any element";
                assert!(
                    stderr.contains(text),
                    "{} must carry the notice reading {:?}; without it the quiet rows above are \
                     satisfied by that channel being dead rather than by their clauses. Got: {}",
                    label,
                    text,
                    stderr
                );
            }
        }
    }

    /// The report lists failing rules in a fixed order.
    ///
    /// The failing set arrives at the console reporter as a `HashMap`, so iterating it directly
    /// emits the findings in whatever order the hasher produces: twenty runs of a binary that does so
    /// over this fixture produce five distinct reports, and `--show-summary all` produces six.
    /// Structured output is stable either way, since it is built from ordered collections.
    ///
    /// That makes report diffing across runs useless and any golden file covering two or more
    /// failing rules flaky, and a differential over output cannot mean anything without a stable
    /// baseline to compare against.
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
    /// over nine resources rather than against `['a', 'b', ...]`. A test comparing against the
    /// literal would prove nothing.
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

    /// A rule that did not apply explains itself when one of its comparisons reported something, and
    /// stays quiet when none did.
    ///
    /// This is the quietest wrong answer left in the evaluator, and the reason the discrimination
    /// matters. `when ... Size > 10` against a template carrying `Size: "50"` refuses to compare a
    /// string with an integer, so the condition does not pass, so the rule is reported as not
    /// applicable and its unencrypted volume is never checked. Exit 0. A template with `Size: 50`
    /// fails the same rule.
    ///
    /// The probe is the new half of the sentence rather than the old one, and the old one had to go.
    /// It read "one of its conditions could not be decided", which is false here: a refusal to compare
    /// kinds is a decided answer under the reading `Unanswerable` draws, and `NOT IN` relies on it. It
    /// was also false in the other direction -- a comparison the engine abandoned cannot produce a SKIP
    /// at all, because `undecided_gate` raises on one -- so the sentence was wrong about both of the
    /// cases that reach it. `own_skip_reason` says which measurements established that.
    ///
    /// This rule does not enforce, and the reason is a precondition, not an impossibility. Telling
    /// "could not decide" from "decided false" does not need a status meaning "could not tell", which
    /// `Status` does not have: an `Err` is that third value and `undecided_gate` fails such a rule
    /// closed with it. What keeps this case quiet is that closing the kind-mismatch
    /// half would move the aws-guard-rules-registry rules that depend on the current reading -- tracked
    /// in `docs/KNOWN_ISSUES.md`. When those change, this test is where the stronger behaviour gets
    /// asserted.
    ///
    /// The quiet case is asserted alongside because the discriminator is the whole mechanism: only a
    /// comparison that recorded an explanation produces a line, so a rule that legitimately does not
    /// apply stays silent. Without that, every inapplicable rule in a large ruleset would grow a line
    /// of output and the signal would be worthless.
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
        let explained = output.contains("a comparison it made reported");
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
    /// refuses on kinds, and a line naming that refusal is a different thing for an author to read
    /// than "every volume was exempted".
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
            output.contains("a comparison it made reported"),
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
    /// Four arms on this path can meet a finding that sits under no resolvable CloudFormation
    /// resource. Each falls back instead of panicking, and the four cases below pin one arm each.
    /// An `unreachable!()` at any of the four would panic, because the assumption it encodes --
    /// that every finding sits under a resolvable resource -- does not hold.
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
        // things differently. The first three demote the file to `generic_summary::GenericSummary`,
        // which prints "Property [...] is not compliant with"; the last one stays with
        // `cfn::CfnAware` -- a non-string CDK path is now just a resource without a CDK path -- and
        // keeps its detailed per-resource report. Either way the path has to appear, and "Number of
        // non-compliant resources 0" contains no path at all.
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
    ///
    /// The exit code is 5, not 19. `5` is a value written in the rules file, so `%numeric empty` is the
    /// author's mistake rather than a fact about the template: `Error::unanswerable` raises
    /// `IncompatibleError` for a literal, the run stops once the file is evaluated, and `validate` maps
    /// that error to `ERROR_STATUS_CODE` with the message on stderr. The report is still built before
    /// the error is applied (`evaluate_against_data_input` reports first), so the two `unreachable!()`
    /// arms are still reached and 101 is still what a regression would look like.
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
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

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
            StatusCode::PARSING_ERROR,
            status_code,
            "`empty` on a literal is the rules file's mistake, so the run reports 5; 101 is the panic \
             this test exists for"
        );

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains("Error handling rule file")
                && stderr.contains("EMPTY operation on type int"),
            "stderr names the clause the rules file got wrong:\n{}",
            stderr
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

    /// A rules file that will not parse must be visible in the document, not only in the exit code.
    ///
    /// `StructuredEvaluator::evaluate` wrote the parse error to stderr, set the exit code, and dropped
    /// the file from `rules`. No reporter ever saw it, so stdout carried what a clean run carries:
    /// three empty verdict lists in json and yaml, `tests="0" failures="0" errors="0"` in junit, an
    /// empty `results` array in sarif. The all-pass sarif document and the parse-error sarif document
    /// were identical.
    ///
    /// Exit 5 is not a sufficient defence, because the CI steps that consume these files run
    /// regardless of exit status -- a junit test reporter, or `upload-sarif` under `if: always()`. A
    /// junit file reading zero tests renders as a green run, and uploading an empty sarif `results`
    /// array resolves the alerts the previous run raised. So a typo in a rules file read as "all
    /// policies now pass".
    ///
    /// Each format says it in its own vocabulary, and none of them reuses a verdict: `errors` in
    /// junit, a `rule_file_errors` field in json and yaml, and `invocations[].executionSuccessful`
    /// with a `toolConfigurationNotifications` entry in sarif. Reusing `status: SKIP` or one of the
    /// three verdict lists is what the defect already did.
    #[rstest::rstest]
    #[case("json", "rule_file_errors")]
    #[case("yaml", "rule_file_errors")]
    #[case("junit", "errors=\"1\"")]
    #[case::sarif("sarif", "\"executionSuccessful\": false")]
    fn a_rules_file_that_cannot_be_parsed_is_reported_in_the_document(
        #[case] output: &str,
        #[case] expected_marker: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec![
                "s3-server-side-encryption-template-non-compliant-2.yaml",
            ])
            .rules(vec!["unparsable-rule.guard"])
            .output_format(Some(output))
            .structured()
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "the exit code for a rules-file parse error is unchanged; only the document is new"
        );

        let out = writer.stripped().expect("failed to read the writer");

        assert!(
            out.contains(expected_marker),
            "{} must carry {} so a consumer can tell this from a clean run:\n{}",
            output,
            expected_marker,
            out
        );
        assert!(
            out.contains("unparsable-rule.guard"),
            "{} must name the rules file that could not be read:\n{}",
            output,
            out
        );
        assert!(
            out.contains("Unable to find a closing >> tag for message")
                || out.contains("Unable to find a closing &gt;&gt; tag for message"),
            "{} must carry the parser's reason, not just the fact of failure:\n{}",
            output,
            out
        );

        // The verdict vocabulary is not borrowed to say this. A rules file that failed to parse is
        // not a rule that skipped, and it is not a finding about the template either.
        if output == "sarif" {
            assert!(
                out.contains("\"results\": []"),
                "a tool failure is not a finding about the code under analysis:\n{}",
                out
            );
        }
    }

    /// The same for the JSON, YAML and SARIF path, which shares one evaluator.
    ///
    /// `CommonStructuredReporter` propagated too, so the document a machine reads was replaced by a
    /// single error line for a file whose other rules had findings. The error is still returned after
    /// the document is written, so the document is gained either way.
    ///
    /// This asserted `INTERNAL_FAILURE`, described as "unchanged". It was unchanged *by that commit*,
    /// which is not the same as correct, and it left this path disagreeing with `-o junit` on the same
    /// input: `JunitReporter` folds the error into the suite's `errors` total and reaches
    /// `PARSING_ERROR`, while json, yaml and sarif returned `Err` and exited -1. Now all four formats
    /// give one answer.
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
            StatusCode::PARSING_ERROR,
            status_code,
            "the structured formats must agree with -o junit on one rules file"
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
    /// The companion to `resources_are_reported_in_a_fixed_order`: `tf.rs` has the same per-process
    /// `HashMap` to order, and a plan fixture with one resource change cannot exercise it. With the
    /// `HashMap` iterated directly, three runs of one binary against this fixture produce three
    /// different orders.
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
    /// A variable that resolves nowhere is a broken ruleset rather than a non-compliant template, and
    /// the exit code has to keep saying so. This asserted `INTERNAL_FAILURE` for that, on the reasoning
    /// that "255 rather than 19 is what says so" -- true as far as it went, and the wrong half of the
    /// distinction. `PARSING_ERROR` is also not 19, and unlike 255 it does not additionally claim
    /// cfn-guard broke: 5 is the code this repository gives a ruleset it cannot use, and -1 is the one
    /// it gives itself. The requirement that commit was protecting is unchanged and still asserted
    /// below; only the code that expresses it moves.
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
            StatusCode::PARSING_ERROR, status_code,
            "a ruleset that cannot be evaluated stays distinguishable from a non-compliant template"
        );
        assert_ne!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "and must not be reported as the template merely failing a rule"
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
    /// The run now exits 5 rather than 19: a literal under `empty` is the rules file's mistake, so the
    /// clause raises `IncompatibleError` and `validate` maps it to `ERROR_STATUS_CODE` with the message
    /// on stderr, which is where the reason is asserted. The report is built before the error is applied,
    /// so the console still prints the pathless finding under its own section, naming the clause; but
    /// the error is returned rather than recorded, so the section carries the reporter's fallback
    /// sentence ("was not empty") and not the evaluator's reason, and the only rules text that reaches
    /// the pathless-clause reporter is a literal, which now stops the run. The reporter therefore has no
    /// vehicle that exercises its reason text at exit 19. A template-sourced pathless value, if one
    /// exists, would be the test to write; until then this is the pin.
    ///
    /// The third variant of one defect, the console reporter dropping a reason the evaluator recorded,
    /// beside the block-attributed and rule-attributed variants: here the clause's path is empty.
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
    /// it on the same terms as `cfn.rs`, so a Terraform plan reaches the same code by a different route,
    /// and a defect in that code reaches `tf.rs` too. Without a plan document in the fixture corpus it
    /// would go unnoticed there — an untested second caller of shared code is how a defect hides, and
    /// one fixture is what keeps it from hiding.
    #[rstest::rstest]
    #[case::cloudformation("numeric-literal-unary-template.yaml")]
    #[case::terraform("terraform-plan.json")]
    fn a_failing_clause_that_belongs_to_no_resource_still_says_why(#[case] data_file: &str) {
        let (status_code, output, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![data_file])
                .rules(vec!["unary_on_a_numeric_literal.guard"])
                .show_summary(vec!["all"])
                .run(writer, reader)
        });

        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "`empty` has no answer for a number the rules file wrote, so the run stops at 5"
        );

        assert!(
            stderr.contains("Error handling rule file")
                && stderr.contains("EMPTY operation on type int"),
            "stderr names the clause the rules file got wrong:\n{}",
            stderr
        );
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
            output.contains("%numeric EMPTY"),
            "and the clause is named there, even though its reason now travels on stderr:\n{}",
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
        assert!(
            output.contains("parameters_are_constrained:"),
            "and which rule asked for it, since the entry names the file and line but not the rule:\n{}",
            output
        );
    }

    /// Two rules spelling the same failing block clause are told apart.
    ///
    /// The section labelled a clause entry with its rule and a block entry with nothing, so a block whose
    /// context is the same text as another's produced the same line twice: two rules reported FAIL in the
    /// summary and one entry, repeated, in the detail. Across the fixture cross product it also left seven
    /// (rules file, rule) pairs reporting FAIL with the rule named nowhere below the summary at all, because
    /// a block entry's context is `GuardAccessClause#block ...` or `GuardBlockAccessClause#Location[...]`,
    /// which names the rules file and the line but never the rule.
    ///
    /// Labelled rather than deduplicated, for the reason the clause path already gives: that two rules
    /// failed is the fact the reader is here for, and collapsing the repeat would hide it.
    #[test]
    fn two_rules_sharing_a_block_clause_are_told_apart() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["bucket-with-no-kms-keys-template.yaml"])
            .rules(vec!["two_rules_that_share_a_block_clause.guard"])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the denylist resolves to no values, so both rules fail"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("first_reader_of_the_denylist: GuardAccessClause#block"),
            "each entry names the rule it came from:\n{}",
            output
        );
        assert!(
            output.contains("second_reader_of_the_denylist: GuardAccessClause#block"),
            "including the second, whose clause text is the first's:\n{}",
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
        let (status_code, output, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec!["numeric-literal-unary-template.yaml"])
                .rules(vec!["a_pathless_clause_beside_a_placed_one.guard"])
                .show_summary(vec!["none"])
                .run(writer, reader)
        });

        // 5, not 19: the pathless clause is `%numeric empty` over a literal, which is the rules file's
        // mistake and stops the run (see `a_failing_clause_that_belongs_to_no_resource_still_says_why`).
        // The report is built first, so what the console rendered is still on stdout.
        assert_eq!(StatusCode::PARSING_ERROR, status_code);

        assert!(
            stderr.contains("Error handling rule file")
                && stderr.contains("EMPTY operation on type int"),
            "stderr names the clause the rules file got wrong:\n{}",
            stderr
        );
        assert!(
            output.contains("Resource = One"),
            "the clause with a path is still rendered under its resource:\n{}",
            output
        );
        assert!(
            output.contains("%numeric EMPTY"),
            "and the clause without one is reported rather than dropped (its reason is on stderr):\n{}",
            output
        );
        assert_eq!(
            output.matches("%numeric EMPTY").count(),
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

    /// A present null compared with a literal decides; an absent key still fails both polarities.
    ///
    /// `PubliclyAccessible:` with no value is a present null, and `!= true` over it decides rather than
    /// failing as a refusal ("not comparable null, bool", which would fail both polarities). A null is
    /// not `true`, so `!=` passes and `==` fails as an inequality. The verdict carries no notice -- a
    /// reading rather than a deprecation -- and this is the row that names it. The two controls on
    /// `Other`, which has no such key, fail under both operators: an absent key is a retrieval failure,
    /// not a null, and the null arms never see it.
    ///
    /// Neither stream may carry a notice: the move ships as a documented behavior change, not as a
    /// deprecation.
    #[rstest::rstest]
    #[case::present_null_ne_passes("present_null_ne_literal.guard", StatusCode::SUCCESS)]
    #[case::present_null_eq_fails("present_null_eq_literal.guard", StatusCode::VALIDATION_ERROR)]
    #[case::absent_key_ne_fails("absent_key_ne_literal.guard", StatusCode::VALIDATION_ERROR)]
    #[case::absent_key_eq_fails("absent_key_eq_literal.guard", StatusCode::VALIDATION_ERROR)]
    fn a_present_null_decides_a_literal_comparison_and_an_absent_key_still_fails(
        #[case] rules_file: &str,
        #[case] expected: i32,
    ) {
        let (status_code, stdout, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec!["present-null-template.yaml"])
                .rules(vec![rules_file])
                .show_summary(vec!["all"])
                .run(writer, reader)
        });

        assert_eq!(
            expected, status_code,
            "{} over present-null-template.yaml",
            rules_file
        );

        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "{}: a present null compared with a literal is a decided comparison and prints no \
             notice:\nstdout: {}\nstderr: {}",
            rules_file,
            stdout,
            stderr
        );
    }

    /// A failing comparison on a captured key names the key's own path in the structured report.
    ///
    /// `validate` loads a template through the libyaml route, and that constructor pathed a map key to
    /// the mapping holding it: `Resources[ nm | Properties.Public == true ]` then `some %nm == "A"`
    /// reported `from.path` as `/Resources`, while `test` and `run_checks`, which load through serde,
    /// reported `/Resources/C` for the same template and rule. `/Resources` is every resource at once
    /// and names none of them. The structured JSON reporter writes the path exactly as the value
    /// carries it, which is why this reads `-o json` back rather than the console rendering, where the
    /// line and column beside the path made the loss easy to miss.
    #[test]
    fn a_failing_captured_key_reports_its_own_path() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["duplicate-logical-id-template.yaml"])
            .rules(vec!["public_bucket_is_not_named_a.guard"])
            .show_summary(vec!["none"])
            .output_format(Some("json"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the capture binds C, the only public bucket, and the clause asks for A"
        );

        let stdout = writer.stripped().expect("failed to read the writer");
        let document: serde_json::Value =
            serde_json::from_str(&stdout).expect("the json report must parse");

        // Every `from.path` in the document, in document order.
        fn from_paths(value: &serde_json::Value, found: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(members) => {
                    if let Some(serde_json::Value::Object(from)) = members.get("from") {
                        if let Some(serde_json::Value::String(path)) = from.get("path") {
                            found.push(path.clone());
                        }
                    }
                    members
                        .values()
                        .for_each(|member| from_paths(member, found));
                }
                serde_json::Value::Array(items) => {
                    items.iter().for_each(|item| from_paths(item, found))
                }
                _ => {}
            }
        }
        let mut paths = vec![];
        from_paths(&document, &mut paths);

        assert_eq!(
            paths,
            vec!["/Resources/C".to_string()],
            "the one failing check compares the captured key C, and its path must name C rather \
             than the mapping that holds it:\n{}",
            stdout
        );
    }

    /// The same explanation has to reach junit, which is the format a pipeline gates on.
    ///
    /// It did not. `TestCaseStatus::Skip` was a unit variant, so the reason the evaluator had already
    /// recorded had nowhere to go, and the element came out as `<testcase status="skip"/>`. A
    /// consumer parsing junit saw a rule silently not apply -- the same silent skip the console and
    /// structured reporters refuse, one output format further out.
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

    /// The console reporter files a finding under the resource named by the segment after
    /// `/Resources/`, and nothing deeper.
    ///
    /// Its path tree is keyed on pointers now: a `/` inside a key is spelled `~1`, so the resource a
    /// finding belongs to is one segment and never has to be guessed. Before, the key was the value's
    /// path string, in which a key `A/B` and a nested `A.B` were the same text, and the reporter peeled
    /// candidate names off it from the longest down, taking the first that resolved to a node with a
    /// `Type`. That guess had three consequences, and these cases pin the new answer to each:
    ///
    /// - a nested property map with its own `Type` key (a CodeBuild `Environment` here) resolved
    ///   first and was printed as a resource named `Build/Properties/Environment` with the inner
    ///   `Type`; the finding now prints under `Build` with the project's `Type`;
    /// - a resource named `A/B` beside a resource `A` with a child `B`: both rules' findings were
    ///   filed under one key and printed under `A/B`, including the one about `A.B`; they now
    ///   separate, `A/B` under `A/B` and `A.B` under `A`, in either order of the keys;
    /// - a document that groups typed items under `Resources.Group.Item` is not CloudFormation and
    ///   printed `Group/Item` as a resource; now no resource resolves and the file goes to the next
    ///   reporter, as every other non-CloudFormation shape does.
    ///
    /// The verdict is the same in every case; what moved is the attribution. The expected outputs were
    /// written from the binary and read against the parent's.
    #[rstest::rstest]
    #[case::a_nested_map_with_a_type_key_is_filed_under_its_resource(
        "nested-map-with-type-key-template.yaml",
        "codebuild_compute_type_is_small.guard",
        "resources/validate/output-dir/nested-map-with-type-key-template.out"
    )]
    #[case::a_slash_named_resource_and_a_nested_key_file_apart(
        "slash-named-resource-beside-nested-template.yaml",
        "every_type_is_outer.guard",
        "resources/validate/output-dir/slash-named-resource-beside-nested-template.out"
    )]
    #[case::a_grouped_document_goes_to_the_next_reporter(
        "grouped-resources-document.yaml",
        "grouped_item_size_is_small.guard",
        "resources/validate/output-dir/grouped-resources-document.out"
    )]
    fn a_finding_is_filed_under_the_segment_after_resources(
        #[case] data_file: &str,
        #[case] rules_file: &str,
        #[case] expected_output: &str,
    ) {
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let mut reader = Reader::default();
        let status_code = ValidateTestRunner::default()
            .data(vec![data_file])
            .rules(vec![rules_file])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
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

    /// `--verbose` with a machine-readable `--output-format` is refused, because the two write to one
    /// stdout.
    ///
    /// This asserted SUCCESS against a fixture, and the fixture was the defect: it held a YAML
    /// document with the verbose tree appended straight onto it, so the recorded expected output of
    /// this test was a stream that no YAML parser accepts. With `-o json` the join is worse still --
    /// the closing brace and the tree's first line share a line.
    ///
    /// Refusing rather than rerouting the tree to stderr, because refusing is what the rest of the
    /// tool already does with this combination: `test` rejects "an output_type of JSON, YAML, or JUnit
    /// while the verbose flag is set", clap rejects `-z -v`, and `ValidateBuilder::try_build` rejects
    /// `structured && verbose`. This was the one spelling of the combination nothing guarded.
    #[test]
    fn verbose_is_refused_with_a_machine_readable_output_format() {
        let mut reader = utils::get_reader(
            "resources/validate/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .verbose()
            .output_format(Some("yaml"))
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::USAGE_ERROR, status_code);
        assert_eq!(
            "Error occurred Cannot provide an output format of YAML while the verbose flag is set, \
             because the verbose tree and the report share stdout\n",
            writer.err_to_stripped().expect("failed to read stderr")
        );
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
    /// It is `PARSING_ERROR` rather than `VALIDATION_ERROR`, and the reason is in the payload: the
    /// clause is `m<0m<03333333`, where the literal `0` runs straight into `m`. A bare identifier is a
    /// valid clause, so without `reject_trailing_identifier` that would split into two clauses -- `m <
    /// 0` and `m < 03333333` -- and the fuzzer's garbage would parse and then evaluate to a violation.
    /// A digit running into a letter is never two clauses, and `reject_trailing_identifier` says so,
    /// which is also why `Size == 1e5` does not mean `Size == 1` and a reference to a rule called `e5`.
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
        // The second rule really does fail: `Parameters.InstanceName` is "TestInstance" and the rule
        // demands "SomeRandomString". The console reporter aggregates by CloudFormation resource and
        // `/Parameters/InstanceName` is not under one, so the finding is named by the reporter that can
        // name it; dropped from a resource count instead, the file would be described by "Number of
        // non-compliant resources 0" and exit 19 with nothing to act on.
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

    /// A bare `Resources:` is one more spelling of "no resources", and the file exits 0 for all of them.
    ///
    /// `{}`, `Resources: {}` and a bare `Resources:` (null in YAML) each describe a template with
    /// nothing to check, and a rule that selects from the population has nothing to say about any of
    /// them: the selection is empty, the rule is not applicable, the run exits 0 and prints nothing.
    /// That has to hold for every spelling of the selection a rules file reaches for -- a filter or a
    /// key filter directly on the key, after `.*`, or after `[*]` -- because they are one query to an
    /// author. A null document that exited 19 under the wildcard spellings, with "Filter on value type
    /// that was not a struct or array null" as the reason, or under the key-filter spellings, with "Map
    /// Filter for keys was not a struct null", while the other two documents exited 0 under every
    /// spelling, would hand a CI gate reading the exit code a failure on a template that had nothing
    /// in it.
    ///
    /// Eighteen runs, one per (query, document) pair, each its own payload so each exit code is its own
    /// measurement; stdout and stderr are both asserted empty, so a run that exits 0 while printing a
    /// violation would still be seen.
    #[test]
    fn every_spelling_of_no_resources_exits_zero_under_every_spelling_of_the_selection() {
        let queries = [
            "rule r { Resources[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b' }",
            "rule r { Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b' }",
            "rule r { Resources[*][ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b' }",
            "rule r { Resources[ keys == /^Bucket/ ].Properties.BucketName == 'b' }",
            "rule r { Resources.*[ keys == /^Bucket/ ].Properties.BucketName == 'b' }",
            "rule r { Resources[*][ keys == /^Bucket/ ].Properties.BucketName == 'b' }",
        ];
        let documents = [r#"{}"#, r#"{"Resources":{}}"#, r#"{"Resources":null}"#];
        for rule in queries {
            for document in documents {
                let payload = format!(
                    r#"{{"data": [{}], "rules": [{}]}}"#,
                    serde_json::to_string(document).unwrap(),
                    serde_json::to_string(rule).unwrap()
                );
                // Two runs because no public accessor returns both streams at once (`stripped` and
                // `err_to_stripped` each consume the writer; the crate-only pair stays crate-only), and
                // the shared `capture_both_streams` hands the run a default reader, where this payload
                // comes through the reader. The payload is tiny, so the second run costs nothing.
                let run = || {
                    let mut reader =
                        Reader::new(ReadCursor(Cursor::new(payload.clone().into_bytes())));
                    let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                        .expect("Failed to create writer.");
                    let status_code = ValidateTestRunner::default()
                        .payload()
                        .run(&mut writer, &mut reader);
                    assert_eq!(
                        StatusCode::SUCCESS,
                        status_code,
                        "{} over {}: nothing to select from, so the rule is not applicable",
                        rule,
                        document
                    );
                    writer
                };
                let out = run().stripped().expect("failed to read stdout");
                let err = run().err_to_stripped().expect("failed to read stderr");
                // Arguments spelled out: under edition 2018 a lone literal handed to `assert!` is the
                // panic payload verbatim and its placeholders are not filled.
                assert!(
                    out.is_empty() && err.is_empty(),
                    "{} over {}: a run with nothing to check prints nothing:\nstdout:\n{}\nstderr:\n{}",
                    rule,
                    document,
                    out,
                    err
                );
            }
        }
    }

    /// A null entry beside a resource fails a filter's assertion the same way under every spelling of the
    /// filter, and the same empty resource spelled `B: {}` passes under every spelling.
    ///
    /// `Resources: { A: { Type: X, Properties: {} }, B: }` holds a bare `B:`, a null entry, beside a
    /// resource; `%r[ Properties.Tags empty ] !empty` through `let r = Resources`, the literal
    /// `Resources[ ... ]`, `Resources[*][ ... ]` and `Resources.*[ ... ]` are four spellings of one
    /// filter over it, and each has a list twin, `[ { Type: X, Properties: {} }, null ]`. The predicate
    /// holds on the null member by absence, the member is selected, and `!empty` fails on it: exit 19,
    /// "Property [/Resources/B] ... needed value at [null] was empty" (the list twin names `/Resources/1`).
    /// An enumerating spelling that refused the null entry as a value a filter cannot run over, a
    /// retrieval error "Filter on value type that was not a struct or array null /Resources/B", while
    /// the literal failed it by evaluation, would draw two failure texts from one document and one
    /// filter. The same document with `B: {}` is the control: the empty map holds the absence
    /// check, the selection is `A` and the empty map, and `!empty` passes at exit 0 under all four, in
    /// the map and in the list. Sixteen runs, one per (spelling, document) pair; the verdict and the
    /// text are asserted together so a spelling that fails by refusal rather than by evaluation is
    /// seen.
    #[test]
    fn a_null_entry_fails_a_filter_the_same_way_under_every_spelling() {
        let spellings = [
            "let r = Resources\nrule r { %r[ Properties.Tags empty ] !empty }",
            "rule r { Resources[ Properties.Tags empty ] !empty }",
            "rule r { Resources[*][ Properties.Tags empty ] !empty }",
            "rule r { Resources.*[ Properties.Tags empty ] !empty }",
        ];
        let failing = [
            (
                r#"{"Resources": {"A": {"Type": "X", "Properties": {}}, "B": null}}"#,
                "/Resources/B",
            ),
            (
                r#"{"Resources": [{"Type": "X", "Properties": {}}, null]}"#,
                "/Resources/1",
            ),
        ];
        let passing = [
            r#"{"Resources": {"A": {"Type": "X", "Properties": {}}, "B": {}}}"#,
            r#"{"Resources": [{"Type": "X", "Properties": {}}, {}]}"#,
        ];
        for rule in spellings {
            for (document, path) in failing {
                let (status_code, out) = run_payload(rule, document);
                assert_eq!(
                    StatusCode::VALIDATION_ERROR,
                    status_code,
                    "{} over {}: the null member fails the assertion",
                    rule,
                    document
                );
                let expected = format!("Property [{}]", path);
                assert!(
                    out.contains(&expected) && out.contains("needed value at [null] was empty"),
                    "{} over {}: the failure names the null member and the empty needed value:\n{}",
                    rule,
                    document,
                    out
                );
                assert!(
                    !out.contains("retrieval error") && !out.contains("was not a struct or array"),
                    "{} over {}: the null member is not a value the filter cannot run over:\n{}",
                    rule,
                    document,
                    out
                );
            }
            for document in passing {
                let (status_code, out) = run_payload(rule, document);
                assert_eq!(
                    StatusCode::SUCCESS,
                    status_code,
                    "{} over {}: the empty map holds the absence check and the assertion passes:\n{}",
                    rule,
                    document,
                    out
                );
            }
        }
    }

    /// The exit codes a null entry beside a bucket draws under every spelling of a filter.
    ///
    /// Over `Resources: { A: <bucket>, B: }` (a bare `B:`, a null entry) and its list twin
    /// `[ <bucket>, null ]`, a value check that reads a key of the selection,
    /// `[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists`, passes at exit 0 under the variable,
    /// the literal, the `[*]`, the `.*` and the type-block spellings: the null fails the predicate and is
    /// dropped, the bucket decides. An absence check that asserts on the selection,
    /// `[ Tags !exists ] !empty`, fails at the validation code under the variable, the literal, `[*]` and
    /// `.*` spellings, naming the null member by its path ("needed value at [null] was empty"). Over the
    /// map, `Resources[*][ Type == 'AWS::S3::Bucket' ] empty` fails and `!empty` passes: the bucket is
    /// selected. What the released binaries drew for the same inputs is recorded in docs/CLAUSES.md
    /// (the paragraph on a filter through a variable, under "Behavior change in 3.2") and in the fixture
    /// README under `resources/validate/wildcard-filter-release-verdicts/`; this test pins the current
    /// answers so a move away from them is deliberate. The two documents here are the JSON spelling
    /// (`"B": null`, a `null` element) of the fixtures `bucket_beside_a_null_entry.yaml` and
    /// `bucket_beside_a_null_element_list.yaml`, whose YAML bare key the fixture table reads through the
    /// files; the two spellings are pinned side by side so the loader's null reading is seen from both.
    #[test]
    fn a_null_entry_beside_a_bucket_draws_the_pinned_exit_code_under_every_spelling() {
        let value_checks = [
            "let r = Resources\nrule r { %r[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists }",
            "rule r { Resources[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists }",
            "rule r { Resources[*][ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists }",
            "rule r { Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists }",
            "rule r { AWS::S3::Bucket { Properties.BucketName exists } }",
        ];
        let absence_checks = [
            "let r = Resources\nrule r { %r[ Tags !exists ] !empty }",
            "rule r { Resources[ Tags !exists ] !empty }",
            "rule r { Resources[*][ Tags !exists ] !empty }",
            "rule r { Resources.*[ Tags !exists ] !empty }",
        ];
        let map = r#"{"Resources": {"A": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "a"}}, "B": null}}"#;
        let list = r#"{"Resources": [{"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "a"}}, null]}"#;
        for (document, path) in [(map, "/Resources/B"), (list, "/Resources/1")] {
            for rule in value_checks {
                let (status_code, out) = run_payload(rule, document);
                assert_eq!(
                    StatusCode::SUCCESS,
                    status_code,
                    "{} over {}: the null fails the value check and is dropped, the bucket passes:\n{}",
                    rule,
                    document,
                    out
                );
                assert_eq!(
                    Some("PASS".to_string()),
                    rule_status_line(&out, "r"),
                    "{} over {}: the rule's own summary line reads PASS, not SKIP:\n{}",
                    rule,
                    document,
                    out
                );
            }
            for rule in absence_checks {
                let (status_code, out) = run_payload(rule, document);
                assert_eq!(
                    StatusCode::VALIDATION_ERROR,
                    status_code,
                    "{} over {}: the absence check selects the null member and the assertion fails on it:\n{}",
                    rule,
                    document,
                    out
                );
                assert_eq!(
                    Some("FAIL".to_string()),
                    rule_status_line(&out, "r"),
                    "{} over {}: the rule's own summary line reads FAIL:\n{}",
                    rule,
                    document,
                    out
                );
                let expected = format!("Property [{}]", path);
                assert!(
                    out.contains(&expected) && out.contains("needed value at [null] was empty"),
                    "{} over {}: the failure names the null member and the empty needed value:\n{}",
                    rule,
                    document,
                    out
                );
            }
        }
        let (status_code, out) = run_payload(
            "rule r { Resources[*][ Type == 'AWS::S3::Bucket' ] empty }",
            map,
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the bucket beside the null is selected, so `empty` fails:\n{}",
            out
        );
        let (status_code, out) = run_payload(
            "rule r { Resources[*][ Type == 'AWS::S3::Bucket' ] !empty }",
            map,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the bucket beside the null is selected, so `!empty` passes:\n{}",
            out
        );
    }

    /// The document of the two console cells below: `Cfg[ x | Kind == 'k' ]` captures the keys of the
    /// entries holding `Kind: k`, and the refused walk adds the own-key refusal's marker to the capture, so
    /// `%x` holds keys and a REFUSAL's marker; `Cfg` lacks `Missing`, and `Cfg.Mode.Ref` is among no key.
    const CAPTURED_KEYS_AND_A_REFUSAL: &str = r#"{"Cfg": {"Mode": {"Ref": "ModeParam"}, "Fallback": {"Kind": "k"}, "A": {"Kind": "k", "Sub": {"R1": {"Ref": "P"}, "P": {"Kind": "k"}, "Q": {"Kind": "k"}}}, "B": {"Kind": "k", "Sub": {"R1": {"Ref": "P"}, "P": {"Kind": "k"}, "Q": {"Kind": "k"}}}}}"#;
    const REFUSED_WALK_INTO_X: &str =
        "Cfg[*][ x | Mode exists or Kind == 'k' ].Sub[*][ s | R1 !exists ] !empty or Cfg.Fallback exists";
    const THE_OWN_KEY_REFUSAL: &str = "then no kept entry holds a key the predicate names";

    /// A refused read beside a value the document lacks prints whole on the console, in the absent value's
    /// own record: `Cfg.Missing == %x` asserted with the keys and the refusal's marker in `%x` fails on the
    /// absence at the validation code, and the console's finding leads with the retrieval's own reason
    /// ("Could not find key Missing") and carries the refusal after it, uncut: its key sentence, its remedy
    /// and its path, the last of them past the bound the console holds every other message to, all in the
    /// output.
    #[test]
    fn a_refused_read_beside_an_absent_value_prints_whole_in_the_console_finding() {
        let rules = format!(
            "rule r {{ Cfg[ x | Kind == 'k' ] !empty  {REFUSED_WALK_INTO_X}  Cfg.Missing == %x }}"
        );
        let (status_code, out) = run_payload(&rules, CAPTURED_KEYS_AND_A_REFUSAL);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`Cfg` lacks `Missing`, so the assertion fails on the absence:\n{}",
            out
        );
        assert!(
            out.contains("Could not find key Missing")
                && out.contains(THE_OWN_KEY_REFUSAL)
                && out.contains("t path /Cfg"),
            "the console finding names the absent key and carries the refusal whole, its path included:\n{}",
            out
        );
    }

    /// The template values a refusal's comparison finding quotes are bounded: the console prints a
    /// refusal's finding whole, up to 4096 characters, because the refusal's sentence is the evaluator's
    /// own and its template parts are each cut at 256 characters with a marker, and the value a query
    /// traversed to, or a value a comparison decided, is a template part like the rest. The document is
    /// a template (a `Resources` key). Where the sentence is read depends on the record: for a decided
    /// comparison the console prints the clause under its resource with the sentence on an `Error =`
    /// line; for a value the document lacks the console prints a `RequiredPropertyError` block whose
    /// `Reason` is the retrieval's own reason and omits the record's message (the released rendering), so
    /// that record's sentence is read from `-o json`, where `messages.error_message` carries it; over a
    /// plain document the summary prints the record's own message, which quotes no value.
    /// `Cfg.Missing == %x` asserted with the keys and the refusal's marker in `%x`, over a `Cfg` holding a
    /// 3000-character string, reports the retrieval's reason, the refusal's key sentence, its remedy and
    /// its path whole, the `Cfg` value cut with the marker naming how much was cut, and the sentence
    /// under the 4096-character bound; unbounded, the sentence carried the 3000 characters of the
    /// document whole. The same bound holds for the two values a decided comparison quotes: `Tags IN %x`
    /// over `Tags: []` with a 3000-character key among the captured keys beside the refusal's marker
    /// records the empty collection against each right-hand value with the refusal in every record (an
    /// empty left-hand collection is a decided failure whatever the right-hand value), and the console
    /// line for the long key carries the refusal whole and the key cut and marked, under the bound. The
    /// control, the first clause over the small `Cfg`, reports the value whole and no marker.
    #[test]
    fn a_refusals_finding_cuts_the_value_the_query_traversed_to() {
        const CUT_MARKER_TAIL: &str = " more characters cut]";
        const THE_REFUSALS_PATH: &str = "t path /Resources/R/Properties/Cfg";
        // The `Cfg` of the two cells above, placed under a resource's `Properties` beside an empty `Tags`.
        let template = |cfg: &str| {
            format!(
                r#"{{"Resources": {{"R": {{"Type": "AWS::S3::Bucket", "Properties": {{"Tags": [], "Cfg": {cfg}}}}}}}}}"#
            )
        };
        let cfg = CAPTURED_KEYS_AND_A_REFUSAL
            .strip_prefix(r#"{"Cfg": "#)
            .and_then(|rest| rest.strip_suffix('}'))
            .expect("the shared document is one `Cfg` map");
        let walk = REFUSED_WALK_INTO_X.replace("Cfg", "Resources.R.Properties.Cfg");
        let rules = |clause: &str| {
            format!(
                "rule r {{ Resources.R.Properties.Cfg[ x | Kind == 'k' ] !empty  {walk}  {clause} }}"
            )
        };
        // The lines that carry the evaluator's sentence with the refusal in it: the `Error =` line of the
        // resource's finding. The summary's own line for the same record quotes the record's message,
        // which carries no template value, and the reporter's `ComparedWith` line quotes the compared
        // value as released without the refusal; neither is the sentence under test.
        let findings = |out: &str, sentence: &str| -> Vec<String> {
            out.lines()
                .filter(|line| line.contains(THE_OWN_KEY_REFUSAL) && line.contains(sentence))
                .map(str::to_string)
                .collect()
        };

        // The same run through `-o json`: the report's every `error_message` string, wherever the
        // record sits in the tree, so the assertion reads the sentence a machine consumer would.
        let run_payload_json = |rule: &str, document: &str| -> (i32, Vec<String>, String) {
            fn error_messages(value: &serde_json::Value, out: &mut Vec<String>) {
                match value {
                    serde_json::Value::Object(map) => {
                        for (key, value) in map {
                            match (key.as_str(), value) {
                                ("error_message", serde_json::Value::String(text)) => {
                                    out.push(text.clone())
                                }
                                _ => error_messages(value, out),
                            }
                        }
                    }
                    serde_json::Value::Array(items) => {
                        items.iter().for_each(|item| error_messages(item, out))
                    }
                    _ => {}
                }
            }
            let payload = format!(
                r#"{{"data": [{}], "rules": [{}]}}"#,
                serde_json::to_string(document).unwrap(),
                serde_json::to_string(rule).unwrap()
            );
            let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .payload()
                .output_format(Some("json"))
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader);
            let out = writer.stripped().expect("failed to read stdout");
            let report: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
                panic!(
                    "the structured output is one JSON document ({}):\n{}",
                    e, out
                )
            });
            let mut messages = Vec::new();
            error_messages(&report, &mut messages);
            (status_code, messages, out)
        };

        // The value the query traversed to: `Cfg.Missing` over a `Cfg` holding a 3000-character string.
        // Read from `-o json`: the console's `RequiredPropertyError` block for a value the document lacks
        // prints the retrieval's reason and omits the record's message, as released.
        const TRAVERSED: &str = "Value traversed to";
        let pad = "y".repeat(3000);
        let padded = cfg.replacen(
            r#""Fallback": {"Kind": "k"}"#,
            &format!(r#""Fallback": {{"Kind": "k", "Pad": "{pad}"}}"#),
            1,
        );
        assert!(
            padded.contains(&pad),
            "the fixture gained the 3000-character string under `Cfg.Fallback.Pad`"
        );
        let absent = rules("Resources.R.Properties.Cfg.Missing == %x");
        let (status_code, messages, out) = run_payload_json(&absent, &template(&padded));
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`Cfg` lacks `Missing`, so the assertion fails on the absence:\n{}",
            out
        );
        let sentences: Vec<&String> = messages
            .iter()
            .filter(|text| text.contains(THE_OWN_KEY_REFUSAL) && text.contains(TRAVERSED))
            .collect();
        assert!(
            !sentences.is_empty(),
            "the absent value's record carries the evaluator's sentence with the refusal:\n{}",
            out
        );
        for sentence in &sentences {
            assert!(
                sentence.contains("Could not find key Missing")
                    && sentence.contains(THE_REFUSALS_PATH),
                "the sentence names the absent key and carries the refusal whole, its path included:\n{}",
                sentence
            );
            assert!(
                !sentence.contains(&pad) && sentence.contains(CUT_MARKER_TAIL),
                "the value the query traversed to is cut at the template-part bound with the marker, \
                 never printed whole:\n{}",
                sentence
            );
            assert!(
                sentence.chars().count() < 4096,
                "the sentence stays under the console's refusal bound ({} characters):\n{}",
                sentence.chars().count(),
                sentence
            );
        }
        assert!(
            messages
                .iter()
                .filter(|text| text.contains(THE_OWN_KEY_REFUSAL))
                .all(|text| !text.contains(&pad)),
            "no recorded sentence that carries the refusal carries the 3000-character string:\n{}",
            out
        );

        // The two values a decided comparison quotes: an empty left-hand collection beside the
        // refusal's marker and a 3000-character key among the captured keys.
        const COMPARED: &str = "not compliant as property value";
        let long_key = "z".repeat(3000);
        let long_key_captured = cfg.replacen(
            r#""Fallback": {"Kind": "k"}"#,
            &format!(r#""Fallback": {{"Kind": "k"}}, "{long_key}": {{"Kind": "k"}}"#),
            1,
        );
        assert!(
            long_key_captured.contains(&long_key),
            "the fixture gained the 3000-character key under `Cfg`"
        );
        let (status_code, out) = run_payload(
            &rules("Resources.R.Properties.Tags IN %x"),
            &template(&long_key_captured),
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the empty `Tags` is a decided failure against every captured key:\n{}",
            out
        );
        let lines = findings(&out, COMPARED);
        assert!(
            !lines.is_empty() && lines.iter().all(|line| line.contains(THE_REFUSALS_PATH)),
            "every compared-value finding of the clause carries the refusal whole, its path included:\n{}",
            out
        );
        assert!(
            lines.iter().all(|line| !line.contains(&long_key))
                && lines.iter().any(|line| line.contains(CUT_MARKER_TAIL)),
            "the long right-hand key is cut at the template-part bound with the marker in the refusal's \
             finding, never printed whole there:\n{}",
            out
        );
        assert!(
            lines.iter().all(|line| line.chars().count() < 4096),
            "every finding stays under the console's refusal bound:\n{}",
            out
        );
        assert!(
            out.lines()
                .filter(|line| line.contains(THE_OWN_KEY_REFUSAL))
                .all(|line| !line.contains(&long_key)),
            "no line that carries the refusal carries the 3000-character key:\n{}",
            out
        );

        // The control: the small `Cfg` is reported whole, with no marker.
        let (status_code, messages, out) = run_payload_json(&absent, &template(cfg));
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the control fails on the absence:\n{}",
            out
        );
        let sentences: Vec<&String> = messages
            .iter()
            .filter(|text| text.contains(THE_OWN_KEY_REFUSAL) && text.contains(TRAVERSED))
            .collect();
        assert!(
            !sentences.is_empty()
                && sentences
                    .iter()
                    .all(|text| text.contains("ModeParam") && !text.contains(CUT_MARKER_TAIL)),
            "a small value is reported whole, with no cut marker:\n{}",
            out
        );
    }

    /// A refused read beside a value no listed entry accepted under a positive `IN` prints whole on the
    /// console, in that value's record: `Cfg.Mode.Ref IN %x` asserted with the keys and the refusal's marker
    /// in `%x`, `Ref` among no key, fails on the marker's pair at the validation code, and the console's
    /// finding for `Ref` carries the refusal uncut, its path included.
    #[test]
    fn a_refused_read_beside_an_unmatched_value_under_in_prints_whole_in_the_console_finding() {
        let rules = format!(
            "rule r {{ Cfg[ x | Kind == 'k' ] !empty  {REFUSED_WALK_INTO_X}  Cfg.Mode.Ref IN %x }}"
        );
        let (status_code, out) = run_payload(&rules, CAPTURED_KEYS_AND_A_REFUSAL);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`Ref` is among no key, so the assertion fails on the marker's pair:\n{}",
            out
        );
        assert!(
            out.contains(THE_OWN_KEY_REFUSAL) && out.contains("t path /Cfg"),
            "the console finding carries the refusal whole, its path included:\n{}",
            out
        );
    }

    /// A refused read beside a value a template lacks reaches the console in the resource's own finding:
    /// over a CloudFormation template the console prints each failing clause under its resource as a
    /// `Check = ... {` block holding a `RequiredPropertyError`, whose `Reason` line is the retrieval's own
    /// reason, and that block printed nothing of the record's sentence, so the refusal beside the absence
    /// reached a reader only on stderr and in the structured output. `Resources.R.Properties.Cfg.Missing
    /// == %x` asserted with the keys and the refusal's marker in `%x` now prints the record's sentence,
    /// the refusal in it, on an `Error =` line right before the `RequiredPropertyError` block, as a decided
    /// comparison's finding prints its sentence; the retrieval's reason leads that sentence, so the block
    /// prints no `Reason =` line restating it. The control, the same assertion with `%x` a plain list,
    /// prints the block as released, the `Check =` line followed by the `RequiredPropertyError` block,
    /// and no `Error =` line: a missing property with no refusal beside it says what it said.
    #[test]
    fn a_refusal_beside_a_missing_template_value_prints_on_an_error_line() {
        const THE_REFUSALS_PATH: &str = "t path /Resources/R/Properties/Cfg";
        let cfg = CAPTURED_KEYS_AND_A_REFUSAL
            .strip_prefix(r#"{"Cfg": "#)
            .and_then(|rest| rest.strip_suffix('}'))
            .expect("the shared document is one `Cfg` map");
        let template = format!(
            r#"{{"Resources": {{"R": {{"Type": "AWS::S3::Bucket", "Properties": {{"Cfg": {cfg}}}}}}}}}"#
        );
        // The line before the `RequiredPropertyError {` line of the resource's finding, trimmed.
        let line_before_the_block = |out: &str| -> String {
            let lines: Vec<&str> = out.lines().collect();
            let at = lines
                .iter()
                .position(|line| line.trim() == "RequiredPropertyError {")
                .unwrap_or_else(|| {
                    panic!(
                        "the resource's finding holds a `RequiredPropertyError` block:\n{}",
                        out
                    )
                });
            assert!(
                at > 0,
                "the block is not the first line of the output:\n{}",
                out
            );
            lines[at - 1].trim().to_string()
        };

        let walk = REFUSED_WALK_INTO_X.replace("Cfg", "Resources.R.Properties.Cfg");
        let rules = format!(
            "rule r {{ Resources.R.Properties.Cfg[ x | Kind == 'k' ] !empty  {walk}  \
             Resources.R.Properties.Cfg.Missing == %x }}"
        );
        let (status_code, out) = run_payload(&rules, &template);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`Cfg` lacks `Missing`, so the assertion fails on the absence:\n{}",
            out
        );
        let before = line_before_the_block(&out);
        assert!(
            before.starts_with("Error") && before.contains(" = "),
            "the record's sentence is printed on an `Error =` line right before the block:\n{}",
            out
        );
        assert!(
            before.contains("Value traversed to")
                && before.contains("Could not find key Missing")
                && before.contains(THE_OWN_KEY_REFUSAL)
                && before.contains(THE_REFUSALS_PATH),
            "the `Error =` line carries the sentence with the absent key, the refusal and its path:\n{}",
            before
        );
        // The retrieval's own reason is on the `Error =` line, as the lead of the record's message, so the
        // block prints no `Reason =` line restating it: the reason is printed once.
        assert!(
            !out.contains("Reason = Could not find key Missing"),
            "the `Error =` line already carries the retrieval's reason, so the block prints no `Reason` \
             line:\n{}",
            out
        );

        // The control: no refusal beside the absence, the block as released, no `Error =` line.
        let control = "rule r { let x = ['a', 'b']  Resources.R.Properties.Cfg.Missing == %x }";
        let (status_code, out) = run_payload(control, &template);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the control fails on the absence:\n{}",
            out
        );
        let before = line_before_the_block(&out);
        assert!(
            before.starts_with("Check =") && before.ends_with('{'),
            "with no refusal the `Check =` line is followed by the block, as released:\n{}",
            out
        );
        assert!(
            !out
                .lines()
                .any(|line| line.trim().starts_with("Error") && line.contains("Value traversed to")),
            "with no refusal no `Error =` line carries the record's sentence:\n{}",
            out
        );
        assert!(
            out.contains("Reason = Could not find key Missing"),
            "the control's block keeps the retrieval's own reason:\n{}",
            out
        );
    }

    /// A refusal's sentence is printed once per console finding, whichever record carries it.
    ///
    /// Two records carry an asserted `IN` against a capture holding a refusal's marker. With the marker
    /// ALONE in `%x` (no earlier clause binds `x`) the clause compares nothing and is raised on the
    /// refusal's reason: its record is the clause's block record, which names no value and so belongs
    /// to no resource, and the console prints it under its `Could not be evaluated:` heading, the
    /// sentence once, whole and as recorded, with the record's word that the clause is raised and the
    /// run continues. That case is a pin of what the console prints for the shape, unchanged here. With
    /// listed keys beside the marker and a value no key accepts (`Ref` is among no key) the clause fails
    /// on its statuses and the marker's pair keeps its record, a right-hand value the evaluator could
    /// not read, printed under the resource as a `Check = { }` block: the sentence's head on its `Error =`
    /// line and the refusal, the unresolved value's reason, on its `Reason =` line, each bounded on its
    /// own. Written as recorded, the `Error =` line quoted the refusal (`Error = [...]`) and the
    /// `Reason =` line repeated it, so the resource's finding carried the refusal's key sentence, remedy
    /// and path twice, each up to the console's refusal bound. The summary is off so that every line
    /// carrying the sentence is a finding's; the key pairs' own findings carry no refusal.
    #[rstest::rstest]
    #[case::marker_alone(false)]
    #[case::listed_keys_beside_the_marker(true)]
    fn an_asserted_in_against_a_refusals_marker_prints_the_refusal_once(
        #[case] keys_beside_the_marker: bool,
    ) {
        const THE_REFUSALS_PATH: &str = "t path /Resources/R/Properties/Cfg";
        let cfg = CAPTURED_KEYS_AND_A_REFUSAL
            .strip_prefix(r#"{"Cfg": "#)
            .and_then(|rest| rest.strip_suffix('}'))
            .expect("the shared document is one `Cfg` map");
        let template = format!(
            r#"{{"Resources": {{"R": {{"Type": "AWS::S3::Bucket", "Properties": {{"Cfg": {cfg}}}}}}}}}"#
        );
        let walk = REFUSED_WALK_INTO_X.replace("Cfg", "Resources.R.Properties.Cfg");
        let bind = match keys_beside_the_marker {
            true => "Resources.R.Properties.Cfg[ x | Kind == 'k' ] !empty  ",
            false => "",
        };
        let rules = format!("rule r {{ {bind}{walk}  Resources.R.Properties.Cfg.Mode.Ref IN %x }}");

        // `run_payload` prints the summary, whose line for a failing rule quotes the record's message;
        // with the summary off the lines that carry the sentence are the findings' alone. The same
        // payload through `-o json` gives the record's sentence as recorded, which the console line is
        // compared with.
        let run = |output_format: Option<&str>| -> (i32, String) {
            run_payload_without_summary(&rules, &template, output_format)
        };
        let (status_code, out) = run(None);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "keys beside the marker {}: the assertion fails and the run goes on to its exit code:\n{}",
            keys_beside_the_marker,
            out
        );

        let carrying: Vec<&str> = out
            .lines()
            .filter(|line| line.contains(THE_OWN_KEY_REFUSAL))
            .collect();
        assert_eq!(
            1,
            carrying.len(),
            "keys beside the marker {}: the refusal's sentence is on exactly one line of the console \
             output (an empty output fails this too):\n{}",
            keys_beside_the_marker,
            out
        );
        let line = carrying[0];
        assert!(
            line.contains(THE_REFUSALS_PATH),
            "keys beside the marker {}: the one line carries the refusal whole, its path included:\n{}",
            keys_beside_the_marker,
            line
        );
        if keys_beside_the_marker {
            // The marker's pair, under the resource: the sentence's head on the `Error =` line of the
            // `Check = { }` block, and the refusal, the unresolved value's reason, on its one `Reason =`
            // line.
            let resource_block: Vec<&str> = out
                .lines()
                .skip_while(|l| !l.starts_with("Resource = R "))
                .skip(1)
                .take_while(|l| *l != "}")
                .collect();
            assert!(
                resource_block.iter().any(|l| *l == line),
                "the refusal is in the resource's own block:\n{}",
                out
            );
            assert!(
                line.trim_start().starts_with("Reason = "),
                "the refusal is the finding's `Reason =` line:\n{}",
                line
            );
            assert_eq!(
                vec![
                    "Error = Check was not compliant as the value to compare to could not be read."
                ],
                resource_block
                    .iter()
                    .filter(|l| l.trim_start().starts_with("Error = "))
                    .map(|l| l.trim_start())
                    .collect::<Vec<_>>(),
                "the finding's one `Error =` line is the sentence's head:\n{}",
                out
            );
            assert_eq!(
                1,
                resource_block
                    .iter()
                    .filter(|l| l.trim_start().starts_with("Reason = "))
                    .count(),
                "one `Reason =` line under the finding:\n{}",
                out
            );
        } else {
            // The clause's block record: it names no value, so the per-resource output has nowhere to
            // put it, and the console prints it under its `Could not be evaluated:` heading, the rule
            // and the clause's context on a line indented by two and the record's sentence, whole, on
            // the line after it indented by four. The sentence is the record's as `-o json` carries it:
            // the unevaluatable error's display around the refusal, then the record's word that the
            // clause is raised and the run continues.
            let (json_status, json) = run(Some("json"));
            assert_eq!(StatusCode::VALIDATION_ERROR, json_status, "{}", json);
            let report: serde_json::Value = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("one JSON document ({}):\n{}", e, json));
            fn error_messages(value: &serde_json::Value, out: &mut Vec<String>) {
                match value {
                    serde_json::Value::Object(map) => {
                        for (key, value) in map {
                            match (key.as_str(), value) {
                                ("error_message", serde_json::Value::String(text)) => {
                                    out.push(text.clone())
                                }
                                _ => error_messages(value, out),
                            }
                        }
                    }
                    serde_json::Value::Array(items) => {
                        items.iter().for_each(|item| error_messages(item, out))
                    }
                    _ => {}
                }
            }
            let mut recorded = Vec::new();
            error_messages(&report, &mut recorded);
            let recorded: Vec<&String> = recorded
                .iter()
                .filter(|text| text.contains(THE_OWN_KEY_REFUSAL))
                .collect();
            assert_eq!(
                1,
                recorded.len(),
                "one recorded sentence carries the refusal, the raised clause's block record:\n{}",
                json
            );
            let recorded = recorded[0];
            assert!(
                recorded.starts_with("Error Clause could not be evaluated against the incoming context `")
                    && recorded.ends_with(
                        "` when handling clause; the clause is raised and the run continues"
                    )
                    && recorded.contains(THE_REFUSALS_PATH),
                "the record's sentence is the unevaluatable error's display around the refusal, its \
                 path included, and says the clause is raised and the run continues:\n{}",
                recorded
            );

            let lines: Vec<&str> = out.lines().collect();
            let heading = lines
                .iter()
                .position(|l| *l == "Could not be evaluated:")
                .unwrap_or_else(|| {
                    panic!(
                        "the console prints the `Could not be evaluated:` heading for a record \
                         naming no value:\n{}",
                        out
                    )
                });
            assert_eq!(
                Some(&format!("    {recorded}").as_str()),
                lines.get(heading + 2),
                "the record's sentence, whole and as recorded, is the entry's second line under the \
                 heading, indented by four:\n{}",
                out
            );
            assert!(
                lines
                    .get(heading + 1)
                    .is_some_and(|l| l.starts_with("  r: GuardAccessClause#block ")),
                "the entry's first line names the rule and the clause's context, indented by two:\n{}",
                out
            );
            assert_eq!(
                lines[heading + 2],
                line,
                "and that line is the one line of the output carrying the refusal"
            );
        }
    }

    /// A refused marker compared against a value a long template string lacks prints its refusal once on
    /// the console, on the `Reason =` line, whatever the console's bound keeps of the record's sentence.
    /// `%x != Resources.R.Properties.Cfg.Mode.Ref.Missing` with the refusal's marker alone in `%x` and
    /// `Cfg.Mode.Ref` a 5000-character string: the record is the marker's beside the absent key, its
    /// reason the refusal and its message the absence's lead (the retrieval's reason over the long
    /// string, bounded by the evaluator) followed by the refusal. The console prints the head and the
    /// lead on the `Error =` line, bounded, and the refusal on the `Reason =` line: exactly one console
    /// line carries the refusal, its path included, and that line is the `Reason =` line; an empty
    /// output fails. The summary is off so every line carrying the sentence is a finding's.
    #[test]
    fn a_refused_marker_against_a_long_strings_missing_key_prints_the_refusal_once() {
        const THE_REFUSALS_PATH: &str = "t path /Resources/R/Properties/Cfg";
        let long = "y".repeat(5000);
        let cfg = CAPTURED_KEYS_AND_A_REFUSAL
            .strip_prefix(r#"{"Cfg": "#)
            .and_then(|rest| rest.strip_suffix('}'))
            .expect("the shared document is one `Cfg` map")
            .replacen("\"ModeParam\"", &format!("\"{long}\""), 1);
        assert!(
            cfg.contains(&long),
            "the fixture's `Cfg.Mode.Ref` is the 5000-character string"
        );
        let template = format!(
            r#"{{"Resources": {{"R": {{"Type": "AWS::S3::Bucket", "Properties": {{"Cfg": {cfg}}}}}}}}}"#
        );
        let walk = REFUSED_WALK_INTO_X.replace("Cfg", "Resources.R.Properties.Cfg");
        let rules =
            format!("rule r {{ {walk}  %x != Resources.R.Properties.Cfg.Mode.Ref.Missing }}");

        let (status_code, out) = run_payload_without_summary(&rules, &template, None);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the marker's pair fails the assertion and the run goes on to its exit code:\n{}",
            out
        );
        let carrying: Vec<&str> = out
            .lines()
            .filter(|line| line.contains(THE_OWN_KEY_REFUSAL))
            .collect();
        assert_eq!(
            1,
            carrying.len(),
            "the refusal is on exactly one line of the console output (zero fails this too):\n{}",
            out
        );
        assert!(
            carrying[0].trim_start().starts_with("Reason = ")
                && carrying[0].contains(THE_REFUSALS_PATH),
            "the one line is the `Reason =` line and carries the refusal whole, its path included:\n{}",
            carrying[0]
        );
        assert!(
            out.lines().any(|line| {
                line.trim_start().starts_with(
                    "Error = Check was not compliant as the value to compare from could not be read."
                )
            }),
            "the `Error =` line is the sentence's head, the lead after it:\n{}",
            out
        );
    }

    /// The short-lead sibling of the cell above: `%x != Resources.R.Properties.Cfg.Mode.Ref.Missing` with
    /// the refusal's marker alone in `%x` and `Cfg.Mode.Ref` the fixture's short string. The layout is
    /// decided from the record, not from the lead's length, so it is the long-lead cell's: the head and
    /// the lead on the `Error =` line, the refusal once on the `Reason =` line. Decided from what a
    /// bounded line still carried, the block put the refusal on the `Error =` line here and on the
    /// `Reason =` line there, and printed it on both when the two readings disagreed.
    #[test]
    fn a_refused_marker_against_a_short_strings_missing_key_prints_the_refusal_on_the_reason_line()
    {
        const THE_REFUSALS_PATH: &str = "t path /Resources/R/Properties/Cfg";
        let cfg = CAPTURED_KEYS_AND_A_REFUSAL
            .strip_prefix(r#"{"Cfg": "#)
            .and_then(|rest| rest.strip_suffix('}'))
            .expect("the shared document is one `Cfg` map");
        let template = format!(
            r#"{{"Resources": {{"R": {{"Type": "AWS::S3::Bucket", "Properties": {{"Cfg": {cfg}}}}}}}}}"#
        );
        let walk = REFUSED_WALK_INTO_X.replace("Cfg", "Resources.R.Properties.Cfg");
        let rules =
            format!("rule r {{ {walk}  %x != Resources.R.Properties.Cfg.Mode.Ref.Missing }}");

        let (status_code, out) = run_payload_without_summary(&rules, &template, None);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the marker's pair fails the assertion and the run goes on to its exit code:\n{}",
            out
        );
        let carrying: Vec<&str> = out
            .lines()
            .filter(|line| line.contains(THE_OWN_KEY_REFUSAL))
            .collect();
        assert_eq!(
            1,
            carrying.len(),
            "the refusal is on exactly one line of the console output:\n{}",
            out
        );
        assert!(
            carrying[0].trim_start().starts_with("Reason = ")
                && carrying[0].contains(THE_REFUSALS_PATH),
            "the one line is the `Reason =` line and carries the refusal whole, its path included:\n{}",
            carrying[0]
        );
        let error_lines: Vec<&str> = out
            .lines()
            .filter(|line| line.trim_start().starts_with("Error = "))
            .collect();
        assert!(
            error_lines.len() == 1
                && error_lines[0].trim_start().starts_with(
                    "Error = Check was not compliant as the value to compare from could not be read."
                )
                && error_lines[0].contains("Missing")
                && !error_lines[0].contains(THE_OWN_KEY_REFUSAL),
            "the one `Error =` line is the sentence's head and the absence's lead, the refusal not on \
             it:\n{}",
            out
        );
    }

    /// The control for the two cells above: the same absent key compared against a plain list, no
    /// refusal anywhere, prints its `RequiredPropertyError` block as released, the retrieval's reason on
    /// the `Reason =` line and no `Error =` line, so a record that is no refusal's keeps its one line.
    #[test]
    fn an_absent_key_of_a_string_with_no_refusal_beside_it_keeps_its_reason_line() {
        let cfg = CAPTURED_KEYS_AND_A_REFUSAL
            .strip_prefix(r#"{"Cfg": "#)
            .and_then(|rest| rest.strip_suffix('}'))
            .expect("the shared document is one `Cfg` map");
        let template = format!(
            r#"{{"Resources": {{"R": {{"Type": "AWS::S3::Bucket", "Properties": {{"Cfg": {cfg}}}}}}}}}"#
        );
        let rules =
            "rule r { let x = ['a', 'b']  %x != Resources.R.Properties.Cfg.Mode.Ref.Missing }";

        let (status_code, out) = run_payload_without_summary(rules, &template, None);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the absence fails the assertion:\n{}",
            out
        );
        assert!(
            out.lines()
                .any(|line| line.trim_start().starts_with("Reason = ")),
            "a record that is no refusal's prints its reason on the `Reason =` line:\n{}",
            out
        );
        assert!(
            !out.lines()
                .any(|line| line.trim_start().starts_with("Error = ")),
            "and prints no `Error =` line:\n{}",
            out
        );
        assert!(
            !out.contains(THE_OWN_KEY_REFUSAL),
            "no refusal is printed, there being none:\n{}",
            out
        );
    }

    /// The fixture README's Cells table, read from its text: each `| ... |` row whose first column is a
    /// rules file gives (rules file, document, now) from its first, second and last columns; the
    /// header, separator and rule lines, and the Notices rows (their rules file in backticks), are
    /// passed over. The README and a doctored copy of it go through this one reader.
    fn wildcard_filter_cells_table(readme: &str) -> Vec<(&str, &str, &str)> {
        readme
            .lines()
            .map(str::trim)
            .filter_map(|line| {
                let columns: Vec<&str> = line
                    .strip_prefix('|')?
                    .strip_suffix('|')?
                    .split('|')
                    .map(str::trim)
                    .collect();
                match columns.as_slice() {
                    [rule, document, .., now] if rule.ends_with(".guard") => {
                        Some((*rule, *document, *now))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// The fixtures under `resources/validate/wildcard-filter-release-verdicts/` are the probe rules and
    /// documents behind the release-history sentences of docs/CLAUSES.md (the behavior-change callouts
    /// on a filter after `[*]` and the paragraph on a filter through a variable), docs/KNOWN_ISSUES.md
    /// item 11 and the README's 3.2 bullets. Their README tabulates, per (rules file, document) cell, the
    /// verdict read on binaries built from the release commits and the current engine's verdict; this test
    /// reads that table's rows and asserts, for every cell, the current engine's exit code and the
    /// summary's status for the one rule `r`, so the `now` column is what the README says it is and a
    /// move away from it is deliberate. The release columns are recorded there, not asserted here.
    #[test]
    fn the_wildcard_filter_fixtures_draw_the_pinned_current_verdicts() {
        const DIR: &str = "wildcard-filter-release-verdicts";
        // The Cells table holds this many data rows. The count is pinned because the two readers tell
        // the Cells table from the Notices table by the backticks around the rules file, so a row that
        // gains or loses its backticks moves between the tables with every cell still passing; the
        // count moving by one is what shows it. A cell added on purpose moves the const with it.
        const CELLS_TABLE_ROWS: usize = 69;
        // The cells are the README's own Cells table, read here and never copied: each `| ... |` row
        // whose first column is a rules file gives (rules file, document, now) from its first, second
        // and last columns; the header and rule lines are passed over. The row count is pinned below,
        // so a row the README gains or loses is a cell this test gains or loses on purpose, and what
        // the README says is asserted is what is asserted.
        let readme_path = get_path_for_resource_file(&format!("{}/README.md", DIR));
        let readme = std::fs::read_to_string(&readme_path)
            .unwrap_or_else(|e| panic!("{} is readable: {}", readme_path, e));
        let cells = wildcard_filter_cells_table(&readme);
        // Every table row that names a rules file is read. A row the reader cannot parse into columns (one
        // written without its closing `|`) would otherwise drop out silently, and the set equality below
        // notices a drop only when the dropped row alone named one of its two files.
        let rows_naming_a_rules_file = readme
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.strip_prefix('|')
                    .and_then(|rest| rest.split('|').next())
                    .map(|first| first.trim().ends_with(".guard"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            cells.len(),
            rows_naming_a_rules_file,
            "every table row naming a rules file is read: {} rows, {} parsed",
            rows_naming_a_rules_file,
            cells.len()
        );
        assert_eq!(
            cells.len(),
            CELLS_TABLE_ROWS,
            "the Cells table holds {} rows, {} read: a row was added to or dropped from the table, \
             or moved between the Cells and Notices tables by the backticks around its rules file; \
             a cell added on purpose moves CELLS_TABLE_ROWS with it",
            CELLS_TABLE_ROWS,
            cells.len()
        );
        // The misread the count exists to catch, shown caught: a Notices row whose rules file loses its
        // backticks reads as a Cells row, and the count moves by one. The first Notices row is found by
        // its shape, never by its text, and the same reader parses the doctored copy.
        let notices_row = readme
            .lines()
            .find(|line| {
                line.trim()
                    .strip_prefix('|')
                    .and_then(|rest| rest.split('|').next())
                    .map(|first| {
                        let first = first.trim();
                        first.starts_with('`') && first.ends_with(".guard`")
                    })
                    .unwrap_or(false)
            })
            .expect("the README has a Notices row with a backticked rules file");
        let doctored_readme = readme.replacen(notices_row, &notices_row.replacen('`', "", 2), 1);
        assert_ne!(
            doctored_readme, readme,
            "the doctored copy differs from the README: the Notices row lost its backticks"
        );
        let doctored = wildcard_filter_cells_table(&doctored_readme);
        assert_eq!(
            doctored.len(),
            CELLS_TABLE_ROWS + 1,
            "the misread the count catches: a Notices row whose rules file lost its backticks \
             reads as a Cells row, and the count moves by one"
        );
        // The table and the directory name the same files, both ways, so a fixture the README forgot
        // or a row naming a file the directory lacks fails by name, and a reader that matched no row
        // fails on the first fixture. The count is pinned above, because a row moving between the
        // tables by its backticks keeps naming files the directory holds and would move silently; the
        // files are still the thing the table is about.
        let dir_path = get_path_for_resource_file(DIR);
        let mut fixtures: Vec<String> = std::fs::read_dir(&dir_path)
            .unwrap_or_else(|e| panic!("{} is listable: {}", dir_path, e))
            .map(|entry| {
                entry
                    .expect("a directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".guard") || name.ends_with(".yaml"))
            .collect();
        fixtures.sort();
        assert!(
            !fixtures.is_empty(),
            "{} holds the rules and documents the README tabulates",
            dir_path
        );
        let named: std::collections::BTreeSet<&str> = cells
            .iter()
            .flat_map(|(rule, document, _)| [*rule, *document])
            .collect();
        for fixture in &fixtures {
            assert!(
                named.contains(fixture.as_str()),
                "fixture {} has no row in the README's Cells table",
                fixture
            );
        }
        for (rule, document, _) in &cells {
            for file in [rule, document] {
                assert!(
                    fixtures.iter().any(|fixture| fixture == file),
                    "the Cells table row {} over {} names {}, a file the directory lacks",
                    rule,
                    document,
                    file
                );
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for (rule, document, _) in &cells {
            assert!(
                seen.insert((*rule, *document)),
                "the Cells table lists {} over {} twice",
                rule,
                document
            );
        }
        for (rule, document, status) in cells {
            let code = match status {
                "PASS" | "SKIP" => StatusCode::SUCCESS,
                "FAIL" => StatusCode::VALIDATION_ERROR,
                other => panic!("unknown status {} in the fixture table", other),
            };
            let rule_path = format!("{}/{}", DIR, rule);
            let document_path = format!("{}/{}", DIR, document);
            let mut reader = Reader::default();
            let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .data(vec![document_path.as_str()])
                .rules(vec![rule_path.as_str()])
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader);
            let out = writer.stripped().expect("failed to read stdout");
            assert_eq!(
                code, status_code,
                "{} over {}: the exit code the fixture README records as the current one:\n{}",
                rule, document, out
            );
            assert_eq!(
                Some(status.to_string()),
                rule_status_line(&out, "r"),
                "{} over {}: the summary's status for rule r:\n{}",
                rule,
                document,
                out
            );
        }
    }

    /// The fixture README's Notices table, read from its text: each `| ... |` row of exactly three
    /// columns whose first column is a rules file in backticks gives (rules file, document, fires);
    /// every other row is passed over, and a notice column other than `yes` or `no` is a panic. The
    /// README and a doctored copy of it go through this one reader.
    fn wildcard_filter_notices_table(readme: &str) -> Vec<(&str, &str, bool)> {
        readme
            .lines()
            .map(str::trim)
            .filter_map(|line| {
                let columns: Vec<&str> = line
                    .strip_prefix('|')?
                    .strip_suffix('|')?
                    .split('|')
                    .map(str::trim)
                    .collect();
                match columns.as_slice() {
                    [rule, document, fires]
                        if rule.starts_with('`') && rule.ends_with(".guard`") =>
                    {
                        let fires = match *fires {
                            "yes" => true,
                            "no" => false,
                            other => {
                                panic!("unknown notice column {} in the fixture README", other)
                            }
                        };
                        Some((rule.trim_matches('`'), *document, fires))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// The fixture README's Notices table records, per cell, whether the `[*]` member notice goes out on
    /// stderr; each listed cell is run with both channels captured and the notice's presence or absence
    /// asserted, so a cell pins WHETHER the notice fires beside the verdict the Cells table pins (a
    /// verdict that did not move is told from a selection that did). A row is `| `<rules file>` |
    /// <document> | yes or no |`, the rules file in backticks so the Cells reader above passes the row
    /// over. The row count is pinned, because the backticks are all that tells the two tables apart and
    /// a row that gains or loses them would move between the readers silently; a cell added on purpose
    /// moves the const with it.
    #[test]
    fn the_wildcard_filter_fixtures_pin_whether_the_member_notice_fires() {
        const DIR: &str = "wildcard-filter-release-verdicts";
        const NOTICE: &str = "the filter after `[*]` at ";
        // The Notices table holds this many data rows; see the doc comment above for why it is pinned.
        const NOTICES_TABLE_ROWS: usize = 13;
        let readme_path = get_path_for_resource_file(&format!("{}/README.md", DIR));
        let readme = std::fs::read_to_string(&readme_path)
            .unwrap_or_else(|e| panic!("{} is readable: {}", readme_path, e));
        let cells = wildcard_filter_notices_table(&readme);
        assert!(
            !cells.is_empty(),
            "the README's Notices table lists at least one cell"
        );
        // Every Notices row is read, as the Cells reader above asserts for its table: a row this reader
        // cannot parse into columns would otherwise drop out silently.
        let rows_naming_a_rules_file = readme
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.strip_prefix('|')
                    .and_then(|rest| rest.split('|').next())
                    .map(|first| {
                        let first = first.trim();
                        first.starts_with('`') && first.ends_with(".guard`")
                    })
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            cells.len(),
            rows_naming_a_rules_file,
            "every Notices row naming a rules file is read: {} rows, {} parsed",
            rows_naming_a_rules_file,
            cells.len()
        );
        assert_eq!(
            cells.len(),
            NOTICES_TABLE_ROWS,
            "the Notices table holds {} rows, {} read: a row was added to or dropped from the \
             table, or moved between the Cells and Notices tables by the backticks around its \
             rules file; a cell added on purpose moves NOTICES_TABLE_ROWS with it",
            NOTICES_TABLE_ROWS,
            cells.len()
        );
        // The misread the count exists to catch, shown caught: a Cells row rewritten into this table's
        // shape (its rules file in backticks, its release columns cut to the one notice column) reads
        // as a Notices row, and the count moves by one. The first Cells row is found by its shape, never
        // by its text, and the same reader parses the doctored copy.
        let cells_row = readme
            .lines()
            .find(|line| {
                line.trim()
                    .strip_prefix('|')
                    .and_then(|rest| rest.split('|').next())
                    .map(|first| first.trim().ends_with(".guard"))
                    .unwrap_or(false)
            })
            .expect("the README has a Cells row with an unbackticked rules file");
        let mut columns = cells_row.trim().trim_matches('|').split('|').map(str::trim);
        let (rule, document) = (
            columns.next().expect("the Cells row has a rules file"),
            columns.next().expect("the Cells row has a document"),
        );
        let doctored_row = format!("| `{}` | {} | no |", rule, document);
        let doctored_readme = readme.replacen(cells_row, &doctored_row, 1);
        assert_ne!(
            doctored_readme, readme,
            "the doctored copy differs from the README: the Cells row took the Notices shape"
        );
        let doctored = wildcard_filter_notices_table(&doctored_readme);
        assert_eq!(
            doctored.len(),
            NOTICES_TABLE_ROWS + 1,
            "the misread the count catches: a Cells row rewritten into the Notices shape, its \
             rules file in backticks, reads as a Notices row, and the count moves by one"
        );
        for (rule, document, fires) in cells {
            let rule_path = format!("{}/{}", DIR, rule);
            let document_path = format!("{}/{}", DIR, document);
            let (_, _, stderr) = capture_both_streams(|writer, reader| {
                ValidateTestRunner::default()
                    .data(vec![document_path.as_str()])
                    .rules(vec![rule_path.as_str()])
                    .show_summary(vec!["all"])
                    .run(writer, reader)
            });
            assert_eq!(
                fires,
                stderr.contains(NOTICE),
                "{} over {}: the fixture README records whether the member notice fires; stderr:\n{}",
                rule,
                document,
                stderr
            );
        }
    }

    /// A filter over a bare `Tags:` exits as the same filter over a resource with no `Tags` key.
    ///
    /// YAML reads a bare `Tags:` as null, and that is one spelling of "no tags", so
    /// `Resources.B.Properties.Tags[ Key == 'Env' ] exists` has to give it the answer the missing key
    /// gets: the collection is not there, the clause fails closed, the run exits 19, and the report
    /// names the property as missing. A null that read as an empty selection instead would make the
    /// clause not applicable and the file exit 0 with nothing reported while the file with no `Tags`
    /// key exited 19, and a gate reading the exit code would let the null spelling through. The
    /// explicit "no tags", `Tags: []`, is a collection that holds nothing, and under this direct
    /// spelling it is the ruled empty-collection reading: the filter selects nothing, the clause is not
    /// applicable, and the file exits 0 with nothing printed, which the third run measures. That is
    /// the reading the base already gave it; it is pinned here as decided, not as history. (Under a
    /// wildcard, `Tags[*][ f ]` or `Tags.*[ f ]`, the same `[]` is enumerated below the population and
    /// stays unresolved, so `exists` fails there; the evaluator's unit tests hold that split.)
    ///
    /// One run per document rather than one payload holding them all: a payload's exit code is the
    /// worst of its documents, so the absent-key document would have carried the null one to 19 on its
    /// own and the exit code would have measured nothing. The absent-key run is the control, and the
    /// message shape is asserted on both so the two readings are seen to be the same reading.
    #[test]
    fn a_filter_over_a_null_collection_exits_as_over_an_absent_one() {
        const RULE: &str = "rule r { Resources.B.Properties.Tags[ Key == 'Env' ] exists }";
        let run = |document: &str| {
            let payload = format!(
                r#"{{"data": [{}], "rules": [{}]}}"#,
                serde_json::to_string(document).unwrap(),
                serde_json::to_string(RULE).unwrap()
            );
            let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
            let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .payload()
                .run(&mut writer, &mut reader);
            (
                status_code,
                writer.stripped().expect("failed to read the writer"),
            )
        };

        let (absent_status, absent_output) =
            run(r#"{"Resources":{"B":{"Type":"X","Properties":{}}}}"#);
        let (null_status, null_output) =
            run(r#"{"Resources":{"B":{"Type":"X","Properties":{"Tags":null}}}}"#);
        let (empty_status, empty_output) =
            run(r#"{"Resources":{"B":{"Type":"X","Properties":{"Tags":[]}}}}"#);

        assert_eq!(
            StatusCode::SUCCESS,
            empty_status,
            "`Tags: []` is a collection with nothing to select, so the clause is not applicable:\n{}",
            empty_output
        );
        assert!(
            empty_output.is_empty(),
            "`Tags: []`: a run with nothing to check prints nothing:\n{}",
            empty_output
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            absent_status,
            "control: the collection the filter needs is absent, so the clause fails closed:\n{}",
            absent_output
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            null_status,
            "a bare `Tags:` is the absent collection spelled with its key, so it exits the same:\n{}",
            null_output
        );
        for (spelling, output) in [
            ("no `Tags` key", absent_output.as_str()),
            ("a bare `Tags:`", null_output.as_str()),
        ] {
            assert!(
                output.contains("RULES_STDIN[1]/r    FAIL")
                    && output.contains("Number of non-compliant resources 1")
                    && output.contains("RequiredPropertyError")
                    && output
                        .contains("Check =  Resources.B.Properties.Tags (filter-clauses) EXISTS"),
                "over {}: the clause is reported as a required property the data lacks:\n{}",
                spelling,
                output
            );
        }
        // A key filter over the same null names itself as a key filter, under every spelling of the
        // wildcard before it: the wording says what the filter was, not what it was not.
        for (spelling, rule) in [
            (
                "direct",
                "rule r { Resources.B.Properties.Tags[ keys == 'x' ] exists }",
            ),
            (
                "`.*` then",
                "rule r { Resources.B.Properties.Tags.*[ keys == 'x' ] exists }",
            ),
            (
                "`[*]` then",
                "rule r { Resources.B.Properties.Tags[*][ keys == 'x' ] exists }",
            ),
        ] {
            let payload = format!(
                r#"{{"data": [{}], "rules": [{}]}}"#,
                serde_json::to_string(
                    r#"{"Resources":{"B":{"Type":"X","Properties":{"Tags":null}}}}"#
                )
                .unwrap(),
                serde_json::to_string(rule).unwrap()
            );
            let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
            let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .payload()
                .run(&mut writer, &mut reader);
            let output = writer.stripped().expect("failed to read the writer");
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{} key filter over a bare `Tags:`: the collection is not there, so the clause fails closed:\n{}",
                spelling,
                output
            );
            assert!(
                output.contains("Reason = Map Filter for keys was not a struct null /Resources/B/Properties/Tags"),
                "{} key filter over a bare `Tags:`: the reason names a key filter over a null:\n{}",
                spelling,
                output
            );
        }

        // The two reasons differ, as they should: one names the key that is not there, the other the
        // null that stands where the collection should be, so the reader can tell the spellings apart.
        assert!(
            absent_output.contains("Reason = Could not find key Tags inside struct"),
            "over no `Tags` key: the reason names the missing key:\n{}",
            absent_output
        );
        // The path and the type name are what the reader needs; the sentence around them is the
        // retrieval's own wording and is not pinned here.
        assert!(
            null_output.contains("Reason = ")
                && null_output.contains(" null /Resources/B/Properties/Tags"),
            "over a bare `Tags:`: the reason names the null and its path:\n{}",
            null_output
        );

        // Below the population, a null met by `[*]` with a KEY next is handed on, and the key names
        // itself as the part that failed, even when a filter follows that key further along. The IAM
        // shape: a `Statement` written bare, read as `Statement[*].Condition[ keys == 'x' ]`. A `[*]`
        // arm that stopped at the null because a filter lay somewhere ahead would name a filter over a
        // value that was not a struct or array, when the part that met the null is the key `Condition`
        // and the filter is a key filter two parts on.
        let statement_rule =
            "rule r { Resources.B.Properties.Statement[*].Condition[ keys == 'x' ] exists }";
        let payload = format!(
            r#"{{"data": [{}], "rules": [{}]}}"#,
            serde_json::to_string(
                r#"{"Resources":{"B":{"Type":"X","Properties":{"Statement":null}}}}"#
            )
            .unwrap(),
            serde_json::to_string(statement_rule).unwrap()
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);
        let statement_output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`[*]` then a key over a bare `Statement:`: the key is not there, so the clause fails closed:\n{}",
            statement_output
        );
        assert!(
            statement_output.contains("Reason = Attempting to retrieve from key Condition")
                && !statement_output.contains("Filter on value type"),
            "`[*]` then a key over a bare `Statement:`: the reason names the key that met the null, not a filter:\n{}",
            statement_output
        );
    }

    /// A filter after `.*` over a `Properties` map that mixes a string with maps enumerates the maps,
    /// so a compliant template exits 0 and a template that imports a value exits 19 with the importing
    /// entry named, and neither is refused. A refusal would instead name the compliant template's
    /// `BucketName` and tell the importing one to remove that entry.
    #[test]
    fn a_dot_wildcard_filter_over_a_properties_map_with_a_scalar_entry_exits_by_what_it_selects() {
        const RULE: &str =
            "rule no_imports { Resources.*.Properties.*[ \"Fn::ImportValue\" exists ] empty }";
        let run = |document: &str| {
            let payload = format!(
                r#"{{"data": [{}], "rules": [{}]}}"#,
                serde_json::to_string(document).unwrap(),
                serde_json::to_string(RULE).unwrap()
            );
            let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
            let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .payload()
                .run(&mut writer, &mut reader);
            (
                status_code,
                writer.stripped().expect("failed to read the writer"),
            )
        };
        let (compliant_status, compliant_output) = run(
            r#"{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"b","BucketEncryption":{"ServerSideEncryptionConfiguration":[]},"Tags":[{"Key":"Env","Value":"prod"}]}}}}"#,
        );
        let (importing_status, importing_output) = run(
            r#"{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"b","BucketEncryption":{"Fn::ImportValue":"SharedEncryptionConfig"}}}}}"#,
        );
        assert_eq!(
            StatusCode::SUCCESS,
            compliant_status,
            "a compliant bucket: nothing imports a value, so `empty` passes and the file exits 0:\n{}",
            compliant_output
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            importing_status,
            "a bucket importing its encryption: the importing map is selected, so `empty` fails:\n{}",
            importing_output
        );
        for (spelling, output) in [
            ("the compliant bucket", compliant_output.as_str()),
            ("the importing bucket", importing_output.as_str()),
        ] {
            assert!(
                !output.contains("refused in both polarities")
                    && !output.contains("Fix or remove the entry"),
                "{}: the filter is evaluated, not refused:\n{}",
                spelling,
                output
            );
        }
        assert!(
            importing_output.contains("/Resources/Bucket/Properties/BucketEncryption"),
            "the importing bucket: the failing clause names the entry that imports:\n{}",
            importing_output
        );
    }

    /// A filter after `[*]` over map-shaped tags, `Tags: { Env: dev }`, under a predicate written for
    /// `{ Key, Value }` pairs, is decided by the tags' `{ Key, Value }` list twin, so it exits by the
    /// tag's value as the list-shaped twin does, 19 for `dev` and 0 for `prod`, with no refusal. Read as
    /// one object, the map-shaped `dev` template would exit 0: no `Key` is found, nothing is selected,
    /// and the clause is not applicable; refused outright, it would exit 19 whatever the value, with the
    /// refusal naming `Key`.
    #[test]
    fn a_bracket_wildcard_filter_over_map_shaped_tags_exits_by_the_value_as_over_list_tags() {
        const RULE: &str =
            "rule prod_tag { Resources.*.Properties.Tags[*][ Key == 'Env' ].Value == 'prod' }";
        let run = |document: &str| {
            let payload = format!(
                r#"{{"data": [{}], "rules": [{}]}}"#,
                serde_json::to_string(document).unwrap(),
                serde_json::to_string(RULE).unwrap()
            );
            let mut reader = Reader::new(ReadCursor(Cursor::new(payload.into_bytes())));
            let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .payload()
                .run(&mut writer, &mut reader);
            (
                status_code,
                writer.stripped().expect("failed to read the writer"),
            )
        };
        let (map_dev_status, map_dev_output) = run(
            r#"{"Resources":{"Fn":{"Type":"AWS::Serverless::Function","Properties":{"Handler":"index.handler","Tags":{"Env":"dev"}}}}}"#,
        );
        let (map_prod_status, map_prod_output) = run(
            r#"{"Resources":{"Fn":{"Type":"AWS::Serverless::Function","Properties":{"Handler":"index.handler","Tags":{"Env":"prod"}}}}}"#,
        );
        let (list_dev_status, list_dev_output) = run(
            r#"{"Resources":{"Fn":{"Type":"AWS::Lambda::Function","Properties":{"Handler":"index.handler","Tags":[{"Key":"Env","Value":"dev"}]}}}}"#,
        );
        let (list_prod_status, list_prod_output) = run(
            r#"{"Resources":{"Fn":{"Type":"AWS::Lambda::Function","Properties":{"Handler":"index.handler","Tags":[{"Key":"Env","Value":"prod"}]}}}}"#,
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            map_dev_status,
            "map-shaped tags `dev`: the twin pair's value fails the clause and the file exits 19:\n{}",
            map_dev_output
        );
        assert_eq!(
            StatusCode::SUCCESS,
            map_prod_status,
            "map-shaped tags `prod`: the twin pair's value passes the clause and the file exits 0:\n{}",
            map_prod_output
        );
        for (spelling, output) in [
            ("map-shaped tags `dev`", map_dev_output.as_str()),
            ("map-shaped tags `prod`", map_prod_output.as_str()),
        ] {
            assert!(
                !output.contains("read one object that has no `Key`")
                    && !output.contains("refused in both polarities"),
                "{}: the filter is decided by the twin, not refused:\n{}",
                spelling,
                output
            );
        }
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            list_dev_status,
            "list-shaped tags `dev`: the value fails the clause:\n{}",
            list_dev_output
        );
        assert_eq!(
            StatusCode::SUCCESS,
            list_prod_status,
            "list-shaped tags `prod`: the value passes the clause and the file exits 0:\n{}",
            list_prod_output
        );
        for (spelling, output) in [
            ("list-shaped tags `dev`", list_dev_output.as_str()),
            ("list-shaped tags `prod`", list_prod_output.as_str()),
        ] {
            assert!(
                !output.contains("refused in both polarities"),
                "{}: the filter is evaluated, not refused:\n{}",
                spelling,
                output
            );
        }
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

    /// The junit `<failure message>` names every failing rule, not whichever one came last.
    ///
    /// `test_case.name` was assigned once per message rather than accumulated, so the attribute held
    /// whichever rule was visited last while the element body held every rule's messages. Against
    /// `three-failing-rules.guard` the attribute read `b_second` for a body containing all three
    /// rules' violations, so a reader who trusted it attributed `c_third`'s and `a_first`'s failures to
    /// `b_second`.
    ///
    /// `test_structured_output`'s golden cannot catch this and needed no update for the fix: every
    /// rules file in the golden directory declares at most one rule, and last-rule-wins is always
    /// right when there is one rule to win. This fixture declares three, named out of declaration
    /// order, so neither sorted order nor last-wins can pass by coincidence.
    ///
    /// Full per-message attribution is not what this establishes -- one attribute cannot label four
    /// messages individually. That belongs to junit reporting one test case per rule instead of one per
    /// rules file, which is a separate defect.
    #[test]
    fn the_junit_failure_message_names_every_failing_rule() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["regional-metadata-template.yaml"])
            .rules(vec!["three-failing-rules.guard"])
            .output_format(Option::from("junit"))
            .structured()
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains(r#"<failure message="c_third, a_first, b_second">"#),
            "the attribute must name all three failing rules in the order they are reported:\n{}",
            output
        );
    }

    /// junit separates the messages inside one `<failure>` instead of running them together.
    ///
    /// `serialize_text_events` wrote one XML text event per message, and adjacent text events
    /// concatenate with nothing between them. A custom message ending `...must be Enabled` followed by
    /// `Check was not compliant...` came out as the non-word `must be EnabledCheck`, and the committed
    /// junit golden carried `].Check` five times over. With several failing rules in one test case
    /// there was no boundary a consumer could split on either, so which message belonged to which rule
    /// was not recoverable from the document.
    ///
    /// The sibling `Skipped` arm already joined its reasons for exactly this reason, with a comment
    /// saying so. Only the `Failure` arm was left.
    ///
    /// Not fixed here, and measured as unchanged: junit orders the pair custom-then-error while sarif
    /// orders it error-then-custom, so the two still render the same finding's text differently. There
    /// is no correctness argument for either order, so picking one would churn a golden for nothing.
    #[test]
    fn junit_separates_the_messages_inside_one_failure() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir"])
            .data(vec![
                "data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(vec!["none"])
            .output_format(Option::from("junit"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("].\nCheck was not compliant"),
            "consecutive messages must be separated:\n{}",
            output
        );
        assert!(
            !output.contains("].Check was not compliant"),
            "and must not run together, which is what produced `].Check`:\n{}",
            output
        );
        // The messages are joined, not merely emitted one after another, so an empty custom message --
        // which is `Some("")` for most clauses rather than `None` -- must not become a blank line or a
        // newline straight after the opening tag.
        assert!(
            !output.contains("\">\nCheck was not compliant"),
            "a dropped empty message must not leave a newline after the <failure> tag:\n{}",
            output
        );
        assert!(
            !output.contains("].\n\nCheck was not compliant"),
            "nor a blank line between two error messages:\n{}",
            output
        );
    }

    /// sarif omits `region` for a finding whose position it does not have, rather than reporting
    /// line 1.
    ///
    /// The reporter read a missing position as `(0, 0)` and then raised both numbers to 1, because the
    /// schema puts `"minimum": 1` on `startLine` and `startColumn`. That converts "unknown" into
    /// "line 1, column 1", which a code-scanning consumer renders as a real position and annotates the
    /// first line of the template.
    ///
    /// `region` is optional: it is not in `physicalLocation`'s required set, whose only constraint is
    /// an `anyOf` demanding `address` or `artifactLocation`. So omitting it is well formed and says
    /// "somewhere in this artifact", which is what is known.
    ///
    /// `no-resources-template.yaml` puts `Resources` well down the file behind a header, so line 1 is
    /// demonstrably not where the finding is. Positions the reporter does have are unaffected, which
    /// `test_structured_output`'s golden covers -- it still carries `startLine` 4 and 13.
    #[test]
    fn sarif_omits_the_region_it_does_not_have_rather_than_reporting_line_one() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["denied_names_from_empty_reference.guard"])
            .data(vec!["bucket-with-no-kms-keys-template.yaml"])
            .show_summary(vec!["none"])
            .output_format(Option::from("sarif"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("\"results\": [") && !output.contains("\"results\": []"),
            "the case has to produce a result for the region assertion to mean anything:\n{}",
            output
        );
        assert!(
            !output.contains("\"startLine\": 1"),
            "a position the reporter does not have must be omitted, not reported as line 1:\n{}",
            output
        );
        assert!(
            !output.contains("\"startColumn\": 1"),
            "and a column it does not have must not be reported as column 1:\n{}",
            output
        );
    }

    /// Every sarif `artifactLocation.uri` is a resolvable `file://` URI.
    ///
    /// This has its own test because `test_structured_output` cannot have one: `sanitize_sarif_writer`
    /// rewrites every `"uri"` in the document to `"some/path"` before comparing, which is why all
    /// eight sites in the committed golden read that. The sanitiser is defensible -- the path depends
    /// on where the repository is checked out -- but it leaves the URI with no coverage at all rather
    /// than with correct coverage, and the value it was hiding was wrong.
    ///
    /// `validate` canonicalises every data-file path, so `report.name` is always absolute. Removing
    /// its leading `/` produced a relative reference with no `uriBaseId` to resolve it against, which
    /// named nothing at a code-scanning consumer's repository root.
    ///
    /// The rootedness check below runs on every platform; the `file://` spelling check does not, and
    /// the split is deliberate.
    ///
    /// The test runs on Windows too, so the leak it exists to catch has coverage there. The rootedness
    /// check asserts the property and not an approximation of it: checks of the shape
    /// `!contains("\"uri\": \"local/")`, and the same for `home/` and `github/`, name three directory
    /// names a stripped absolute path happens to start with on particular machines, and a checkout
    /// under `/opt/build` would satisfy all three while carrying exactly the defect. An artifact
    /// location must be rooted, which is checkable without naming any directory and without assuming
    /// a separator, and reads the same question on both platforms: a POSIX path that lost its leading
    /// `/`, and a Windows path that lost its root name, are both `is_absolute() == false`.
    ///
    /// The `file://` check stays POSIX-only because the product genuinely emits something else on
    /// Windows: `sanitize_path` returns any path not starting with `/` unchanged, so a Windows artifact
    /// location is a bare `\\?\C:\...` with no scheme at all. That is very likely its own defect -- an
    /// `artifactLocation.uri` that is not a URI -- but it is a defect in shipped code on a platform
    /// this suite cannot exercise, so it is named here rather than guessed at. Gating one assertion is
    /// not the same as skipping the test: the rootedness check is a real assertion that a rooted path
    /// passes and a stripped one fails, on Windows as much as here.
    #[test]
    fn sarif_artifact_locations_are_resolvable_file_uris() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir"])
            .data(vec![
                "data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
            ])
            .show_summary(vec!["none"])
            .output_format(Option::from("sarif"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let output = writer.stripped().expect("failed to read the writer");

        let uris = artifact_location_uris(&output);
        assert!(
            !uris.is_empty(),
            "a run reporting no artifact location would satisfy the loop below without checking \
             anything:\n{}",
            output
        );

        for uri in &uris {
            let path = uri.strip_prefix("file://").unwrap_or(uri);
            assert!(
                std::path::Path::new(path).is_absolute(),
                "an artifact location that is not rooted resolves against whatever base the consumer \
                 happens to use, which is the defect this pins; got {} among {} location(s) in\n{}",
                uri,
                uris.len(),
                output
            );
        }

        if !cfg!(windows) {
            let expected = format!(
                "\"uri\": \"file://{}\"",
                get_full_path_for_resource_file(
                    "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml"
                )
            );

            assert!(
                output.contains(&expected),
                "every artifact location must be a file:// URI naming the real file; expected to find\n\
                 {}\nin\n{}",
                expected,
                output
            );
        }
    }

    /// Every artifact location a SARIF run reports, in document order.
    ///
    /// Keyed on the `uri` member itself rather than on its parents, because the document spells the
    /// same member two ways -- `artifacts[].location.uri` and
    /// `results[].locations[].physicalLocation.artifactLocation.uri` -- and the driver's own two URIs
    /// are `downloadUri` and `informationUri`, which are different member names. So every `uri` in the
    /// document is an artifact location and none of the driver's metadata is picked up by accident.
    ///
    /// Parsed rather than scanned for a `"uri": "..."` substring: a percent-encoded path can contain
    /// `%22`, and a scan would also have to decide what to do about the escaping that JSON applies to a
    /// Windows path's backslashes. `serde_json` already answers both, and is a dependency of this crate
    /// rather than something added for this.
    fn artifact_location_uris(sarif: &str) -> Vec<String> {
        fn collect(value: &serde_json::Value, found: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(members) => {
                    for (name, member) in members {
                        match (name.as_str(), member.as_str()) {
                            ("uri", Some(uri)) => found.push(uri.to_string()),
                            _ => collect(member, found),
                        }
                    }
                }
                serde_json::Value::Array(items) => {
                    items.iter().for_each(|item| collect(item, found))
                }
                _ => {}
            }
        }

        let document: serde_json::Value =
            serde_json::from_str(sarif).expect("the sarif output must be JSON");

        let mut found = vec![];
        collect(&document, &mut found);

        found
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

        // `USAGE_ERROR`, not `INTERNAL_FAILURE`. Every case here is a combination of flags the command
        // cannot honour, which is the caller's mistake; asserting 255 asserted that cfn-guard had
        // fallen over. clap's own conflicts -- `-P -r`, `-z -v` -- already answered 2 for the same
        // class of mistake, so the two layers disagreed about the same kind of error.
        assert_eq!(StatusCode::USAGE_ERROR, status_code);
    }

    /// `--rules` with no values after it is a usage error, not a panic.
    ///
    /// `--rules` is a member of the required `<--rules|--payload>` group, so a bare `--rules`
    /// *satisfied* that group while leaving the list empty; `execute` then matched neither the rules
    /// branch nor the payload branch and reached its `unreachable!()`, exit 101. `num_args=1..` is what
    /// closes it, and this asserts through `try_parse_from` because the failure is clap's to report --
    /// the builder in this file cannot emit `--rules` with no values, which is why nothing here caught
    /// it.
    ///
    /// The three spellings matter separately: a trailing `--rules`, and `--rules` followed by another
    /// flag, which clap does not consume as a value.
    #[rstest::rstest]
    #[case::nothing_after_it(vec!["validate", "--rules"])]
    #[case::followed_by_another_flag(vec!["validate", "--rules", "--data"])]
    #[case::followed_by_a_flag_with_a_value(vec!["validate", "-r", "-d", "some-template.yaml"])]
    fn rules_with_no_values_is_a_usage_error(#[case] args: Vec<&str>) {
        let error =
            CfnGuard::try_parse_from(args).expect_err("--rules with no values must not parse");

        assert_eq!(StatusCode::USAGE_ERROR, error.exit_code());
    }

    /// A machine-readable `--output-format` puts exactly one document on stdout, so a failing run is
    /// still parseable.
    ///
    /// `--show-summary` defaults to `fail` and the summary table shares stdout with the report, so
    /// `-o json` emitted clean JSON while everything passed and a table welded to the front of the
    /// JSON as soon as a rule failed -- invalid exactly when a consumer needs to read it. The default
    /// is now `none` when the format is machine-readable.
    ///
    /// Asserted by parsing, not by comparing to a fixture: the requirement is that the bytes are a
    /// document, and a fixture would have recorded the corruption just as happily.
    #[rstest::rstest]
    #[case::json_without_structured(vec!["json"], false)]
    #[case::yaml_without_structured(vec!["yaml"], false)]
    #[case::json_with_structured(vec!["json"], true)]
    #[case::yaml_with_structured(vec!["yaml"], true)]
    fn a_failing_run_puts_one_parseable_document_on_stdout(
        #[case] output: Vec<&str>,
        #[case] structured: bool,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = match structured {
            true => ValidateTestRunner::default()
                .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
                .data(vec![
                    "data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
                ])
                .output_format(Some(output[0]))
                .structured()
                .run(&mut writer, &mut reader),
            false => ValidateTestRunner::default()
                .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
                .data(vec![
                    "data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
                ])
                .output_format(Some(output[0]))
                .run(&mut writer, &mut reader),
        };

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let document = writer.stripped().expect("failed to read stdout");
        assert!(
            !document.trim().is_empty(),
            "a failing run must still write its report"
        );

        match output[0] {
            "json" => {
                serde_json::from_str::<serde_json::Value>(&document).unwrap_or_else(|e| {
                    panic!("stdout is not valid JSON: {}\n{}", e, document);
                });
            }
            _ => {
                serde_yaml::from_str::<serde_yaml::Value>(&document).unwrap_or_else(|e| {
                    panic!("stdout is not valid YAML: {}\n{}", e, document);
                });
            }
        }
    }

    /// `--structured` no longer needs `-S none` spelled out beside it.
    ///
    /// `validate_construct` rejected `structured && !summary_type.is_empty()`, and `--show-summary`'s
    /// own default of `fail` is not empty, so every `-z` invocation that did not say `-S none` failed
    /// with a complaint about a flag the caller never passed. The `-z` help text lists
    /// `show-summary: all/fail/pass/skip` among its conflicts without saying that `fail` is the
    /// default, so following the help produced the error.
    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    #[case("junit")]
    #[case("sarif")]
    fn structured_does_not_require_show_summary_none_to_be_spelled_out(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .rules(vec!["rules-dir/s3_bucket_public_read_prohibited.guard"])
            .data(vec![
                "data-dir/s3-public-read-prohibited-template-compliant.yaml",
            ])
            .output_format(Option::from(output))
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert!(
            !writer
                .stripped()
                .expect("failed to read stdout")
                .trim()
                .is_empty(),
            "the structured report must be written"
        );
    }

    /// A `--rules` argument that yields no rules file says so, rather than reporting success.
    ///
    /// The `--data` side has had `report_no_data_evaluated` and its doc comment states the hazard: a
    /// run that checked nothing prints nothing and exits 0, which is what a run in which everything
    /// complied also does. The rules side had no counterpart, so `--rules some-dir-with-no-rules`
    /// applied no policy and reported success -- a green build for rules nobody ran.
    ///
    /// The exit code is deliberately left at 0, as it is on the data side; moving it is a separate
    /// argument. What is asserted is that the run is no longer silent.
    #[test]
    fn a_rules_directory_holding_no_rules_files_says_nothing_was_checked() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .rules(vec!["data-dir"])
            .data(vec![
                "data-dir/s3-public-read-prohibited-template-compliant.yaml",
            ])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains("no rules files were evaluated"),
            "a run that applied no rule must say so, got: {}",
            stderr
        );
        assert!(
            stderr.contains("dummy.txt was not evaluated because its extension is not one of"),
            "the files the walk passed over must be named, got: {}",
            stderr
        );
    }

    /// A `--payload` whose `rules` or `data` list is empty says nothing was checked.
    ///
    /// The payload branch reached neither `report_no_data_evaluated` nor its new rules-side
    /// counterpart, so `{"rules":[],"data":["{}"]}` parsed, evaluated nothing and exited 0. That is
    /// the same false green as above, arrived at through the one input most likely to be machine-built
    /// and least likely to be read by a person.
    #[rstest::rstest]
    #[case::no_rules(
        r#"{"rules":[],"data":["{\"Resources\":{}}"]}"#,
        "no rules files were evaluated"
    )]
    #[case::no_data(
        r#"{"rules":["rule M { Resources !empty }"],"data":[]}"#,
        "no data files were evaluated"
    )]
    fn a_payload_with_an_empty_list_says_nothing_was_checked(
        #[case] payload: &str,
        #[case] expected: &str,
    ) {
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(payload.as_bytes()))));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains(expected),
            "expected {:?} on stderr, got: {}",
            expected,
            stderr
        );
    }

    /// `--payload` read from stdin that will not parse names the flag, the stream and the shape.
    ///
    /// The message was serde's bare text -- `EOF while parsing a value at line 1 column 0` for no
    /// stdin at all -- which names none of the three even though `deserialize_payload` knows all
    /// three. "line 1 column 0" is least helpful in the case it is most likely to describe: a CI step
    /// with nothing piped in.
    ///
    /// `PARSING_ERROR`, not `INTERNAL_FAILURE`. `deserialize_payload` raises
    /// `Error::ParseError`, and `execute` classifies every one of those as the caller's input rather
    /// than as cfn-guard breaking -- the payload deserializer is one of the producers that
    /// classification was written to cover. This case asserted -1 only because, when it was written,
    /// the error reached `main`'s catch-all, which is the code this repository reserves for an
    /// unexpected failure and would here have told a CI author with nothing piped in that the tool
    /// was at fault.
    #[rstest::rstest]
    #[case::empty_stdin("")]
    #[case::not_json("not json")]
    fn a_payload_that_will_not_parse_says_where_it_came_from(#[case] input: &str) {
        let mut reader = Reader::new(ReadCursor(Cursor::new(Vec::from(input.as_bytes()))));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .payload()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains("--payload")
                && stderr.contains("stdin")
                && stderr.contains("\"rules\""),
            "the message must name the flag, the stream and the expected shape, got: {}",
            stderr
        );
        // The code and the message have to agree about whose mistake this is, and they are set in
        // two different places -- the code by `execute`'s classification, the prefix by whether
        // `main` ever sees the error. `test_a_data_file_with_no_document_is_reported_as_empty` pins
        // the same pairing for an unreadable data file; this pins it for the payload.
        assert!(
            !stderr.contains("Error occurred"),
            "an input cfn-guard cannot read must not be reported in main's vocabulary for an \
             unexpected failure, got: {}",
            stderr
        );
    }

    /// `--input-parameters` is merged into a `--payload` run whichever reporter runs.
    ///
    /// The structured path passed `input_params: extra_data` and the plain path passed `&None`, so
    /// `validate -P -i params.yaml` returned opposite verdicts depending only on whether `-z` was
    /// given -- PASS structured, FAIL not -- and nothing said that a file the caller named had not
    /// been read. Both paths now merge, which is what `--input-parameters` documents.
    ///
    /// The two runs are compared to each other rather than to a recorded verdict: the defect was that
    /// they disagreed, so agreement is the property worth pinning.
    #[test]
    fn input_parameters_reach_a_payload_run_whichever_reporter_runs() {
        const PAYLOAD: &str = r#"{"rules":["rule MAIN { Parameters.Env == \"prod\" }"],"data":["{\"Resources\":{\"V\":{}}}"]}"#;

        let mut plain_reader = Reader::new(ReadCursor(Cursor::new(Vec::from(PAYLOAD.as_bytes()))));
        let mut plain_writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let plain = ValidateTestRunner::default()
            .payload()
            .input_parameters(vec!["payload-input-parameters/prod-env.yaml"])
            .show_summary(vec!["none"])
            .run(&mut plain_writer, &mut plain_reader);

        let mut structured_reader =
            Reader::new(ReadCursor(Cursor::new(Vec::from(PAYLOAD.as_bytes()))));
        let mut structured_writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let structured = ValidateTestRunner::default()
            .payload()
            .input_parameters(vec!["payload-input-parameters/prod-env.yaml"])
            .output_format(Some("json"))
            .structured()
            .run(&mut structured_writer, &mut structured_reader);

        assert_eq!(
            structured, plain,
            "the same rules, data and --input-parameters must reach the same verdict \
             whether or not --structured is passed"
        );
        assert_eq!(
            StatusCode::SUCCESS,
            plain,
            "the parameter file supplies Parameters.Env, so the rule passes"
        );
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

        // See above: a usage mistake now carries a usage code.
        assert_eq!(StatusCode::USAGE_ERROR, status_code);
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

    /// Which side of a comparison an unevaluatable error comes from does not change the exit code.
    ///
    /// A clause whose own query could not produce a value fails closed and the run exits 19. The same
    /// error reached through the right-hand side recorded the clause as failing and then propagated the
    /// error anyway, so the run aborted with "Error occurred" and exited 255 -- the tool-failure code, on
    /// a template that is only non-compliant. Both spellings of the right-hand side did it, a variable
    /// bound to the conversion and the conversion written inline, and
    /// `unevaluatable_right_hand_side.guard` has one rule for each alongside the left-hand control.
    #[test]
    fn an_unevaluatable_right_hand_side_fails_the_clause_rather_than_the_run() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/unevaluatable_right_hand_side.guard"])
            .data(vec!["/functions/data/unevaluatable_right_hand_side.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    /// A value the conversion could not represent is not reported as a number.
    ///
    /// `numbers_that_do_not_fit.guard` asserts that a budget of `1.0e40` *is* 9223372036854775807, and
    /// that an overflowing `"1e400"` is greater than `1.0e300`. Both passed at exit 0: `parse_int` cast
    /// the float with `as`, which clamps to `i64::MAX`, and `parse::<f64>()` answers infinity for a
    /// literal that does not fit. Each rule names the wrong answer it was given, so the assertion here is
    /// the verdict: SUCCESS before, VALIDATION_ERROR after.
    #[test]
    fn numbers_too_large_to_convert_do_not_compare_equal() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/numbers_that_do_not_fit.guard"])
            .data(vec!["/functions/data/numbers_that_do_not_fit.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
    }

    /// The control for the test above: two ordinary floats that do fit still convert and still compare,
    /// so truncation toward zero is unaffected. This rule asserts 5 differs from 12, which holds.
    #[test]
    fn numbers_that_fit_still_convert_and_compare() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/functions/rules/numbers_that_fit.guard"])
            .data(vec!["/functions/data/numbers_that_fit.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
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

    /// An embedded string whose two keys read as one name fails the clause the same way, and does not
    /// abort the run.
    ///
    /// `{1: "a", "1": "b"}` is two keys to the parser and one name to the value model, so the
    /// conversion refuses it naming the key; the refusal is a `ParseError` from the conversion, and
    /// `json_parse` maps it to `IncompatibleError` naming the property, the class the evaluator treats
    /// as a clause failure, as it does the parser's own refusal in the case above. `{"1": "a", "1":
    /// "b"}` is two string keys whose resolved values are equal, which the parser refuses first.
    /// Measured on the CLI: both rules FAIL with the refusal as their message, the control rule and the
    /// unrelated bucket rule beside them PASS, and the file exits 19, not 255. Red with the mapping
    /// removed (the conversion's `ParseError` passed through aborts the run at 255); green with it.
    /// This is the rule-level half of the unit tests on `Value::try_from_json`; `json_parse` is the one
    /// production route through that conversion.
    #[test]
    fn json_parse_on_two_keys_that_read_as_one_name_fails_the_clause_rather_than_the_run() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .data(vec![
                "functions/data/embedded_json_with_keys_that_read_alike.yaml",
            ])
            .rules(vec![
                "functions/rules/embedded_json_with_keys_that_read_alike.guard",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);
        let out = writer.stripped().expect("failed to read stdout");

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code, "{}", out);
        assert_eq!(
            verdicts_of(&[
                ("KEYS_THAT_READ_ALIKE", "FAIL"),
                ("EQUAL_VALUED_DUPLICATE", "FAIL"),
                ("PLAIN", "PASS"),
                ("BUCKET_NAMED", "PASS"),
            ]),
            summary_verdicts(&out),
            "the two refusals fail their rules, the other rules are evaluated:\n{}",
            out
        );
        assert!(
            out.contains(
                "failed to convert the parsed string at /Resources/Service/Properties/KeysThatReadAlike"
            ) && out.contains("read as the key `1`"),
            "the collision must be named by property and key:\n{}",
            out
        );
        assert!(
            out.contains(
                "failed to parse the string at /Resources/Service/Properties/EqualValuedDuplicate"
            ) && out.contains("duplicate entry"),
            "the equal-valued duplicate must be the parser's own refusal:\n{}",
            out
        );
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
    /// and asserts the count is 0. Counting an unresolved selection as 0 would satisfy it and exit 0
    /// while the correctly spelled rule finds three entries. The verdict is the assertion:
    /// VALIDATION_ERROR.
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

    /// The control for the test above: a collection that is present and empty counts 0, so the rule
    /// passes. An empty collection is not an unresolved selection, and this is the case that keeps
    /// its answer.
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
    /// Returning `""` instead would not fail it. An empty string is a value and it compares, so the
    /// `!=` in `regex_replace_no_match.guard` would be satisfied and the run would exit 0 -- a rule
    /// that normalises an optional prefix before checking a name would report a pass on the name it
    /// was written to catch. The verdict is the assertion here, not the text: VALIDATION_ERROR.
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

    /// A failing count or join over two buckets is reported at the path the buckets share.
    ///
    /// Both answers describe the two buckets together, so they sit at `/Resources`, not at whichever
    /// bucket the template lists first; before, the console report named BucketA as the one
    /// non-compliant resource for a number that counted both, and BucketB when the two were listed the
    /// other way round. The console reporter organizes findings by resource and has no place for one
    /// at `/Resources`, so by its own rule the file is rendered by the next reporter, which prints each
    /// finding against that path; there is no "Number of non-compliant resources" line in that
    /// rendering, and the two failing clauses stay two findings. The json document carries
    /// `"path": "/Resources"` for both, and the sarif document two results with no `region`. The
    /// count's members are the buckets themselves, whose parent `/Resources` is, so that finding
    /// carries the first bucket's position in its message text; the join's members sit three levels
    /// below `/Resources`, so that finding has the neutral position.
    #[rstest::rstest]
    #[case::console(None)]
    #[case::json(Some("json"))]
    #[case::sarif(Some("sarif"))]
    fn an_aggregate_over_two_buckets_is_reported_at_the_shared_path(#[case] output: Option<&str>) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        // Each branch builds its own runner: the builder methods borrow the runner for the struct's
        // lifetime, so a chain cannot be split across statements.
        let status_code = match output {
            None => ValidateTestRunner::default()
                .rules(vec!["/functions/rules/aggregate_over_two_buckets.guard"])
                .data(vec!["/functions/data/two_buckets.yaml"])
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader),
            Some(format) => ValidateTestRunner::default()
                .rules(vec!["/functions/rules/aggregate_over_two_buckets.guard"])
                .data(vec!["/functions/data/two_buckets.yaml"])
                .show_summary(vec!["none"])
                .output_format(Some(format))
                .structured()
                .run(&mut writer, &mut reader),
        };

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);

        let (golden, writer) = match output {
            None => ("aggregate_over_two_buckets.out", writer),
            Some("sarif") => (
                "aggregate_over_two_buckets.sarif",
                sanitize_sarif_writer(writer),
            ),
            Some(_) => ("aggregate_over_two_buckets.json", writer),
        };
        assert_output_from_file_eq!(
            &format!("resources/validate/functions/output/{golden}"),
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

    /// `IN` against a right-hand query that enumerates a collection is membership, and the written-out
    /// list is the oracle: `IN Mappings.Allowed.Types[*]` owes the verdicts `IN ["gp2", "gp3"]` gives.
    ///
    /// The query-vs-query arm asks membership, not substring containment of every resolved right-hand
    /// string: `[*]` resolves an allowlist to one string per entry, and reading each entry as a
    /// haystack would put `gp` and `""` "in" `["gp2", "gp3"]` at exit 0 while the literal spelling
    /// fails them, and would make the `NOT IN` mirror deny `s` against a denylist of `["ssh"]` at exit
    /// 19 while `NOT IN ["ssh"]` passes it. The `%allowed` spelling binds the same enumeration and
    /// answers the same way.
    ///
    /// The shape is read off the whole query, not its last part: `Entries[*].Name` ends by descending a
    /// key and still hands back one name per entry, so it is the same allowlist one key further in and
    /// owes the same verdicts. When the enumeration is not the query's last part and a result is itself
    /// a list -- `Resources.*[ Type == 'Custom::Policy' ].Properties.AllowedTypes` resolves to the one
    /// list each policy holds -- that list's members join the set, so the wildcard spelling and the
    /// named spelling `Resources.Policy.Properties.AllowedTypes` agree in both polarities;
    /// `Mappings.Regions.*.Types` and `Parameters.*.AllowedValues` are the same shape when every
    /// enumerated member carries the key, as every region and every parameter in the fixtures does. A
    /// member without it leaves the query partly unresolved and the clause fails for that reason, as
    /// any `IN` over an unresolved right-hand side does; that behavior is not this test's subject. The
    /// author's own `[*]` after a `let` counts as an enumeration they wrote: `let entries =
    /// Mappings.Allowed.Entries` then `%entries[*].Name` is the inline `Entries[*].Name` through a
    /// binding and answers as it does, with one key after the wildcard, two (`%nested[*].Sub.Name`), or
    /// a filter (`%entries[*][ Kind == 'volume' ].Name`). The shape is what the retrieval did, reported by
    /// the retrieval itself: the reader's own slot in `%entries.Name` walked the list the binding holds,
    /// so `%entries.Name` and `%entries[*].Name` agree; over one map (`let p = Parameters.Allowed`,
    /// `%p.Default`) it passed the map through and the query names one string; and in front of an index
    /// (`%t[0]`, `%e[0].Name`) it was consumed, so those name one value as the inline index does. A
    /// function that
    /// maps its input value by value (`to_lower`) hands back as many values as the argument it maps
    /// over did, so its results enumerate when THAT argument does, inline or bound with `let`; its
    /// other arguments do not count (`regex_replace(Default, Patterns[*], "")` is one string), and
    /// `join` folds its inputs into one string, which stays a haystack.
    ///
    /// A list on the left is a subset question against the entry set, as it is against the literal:
    /// every element allowed passes and one stranger fails. When the enumeration is not the last part
    /// and the results are lists, the two polarities are fail-closed and asymmetric: `IN` holds when the
    /// list is a subset of some single result, not of their pool, so `Pair IN Mappings.Combos.*.Pair`
    /// admits `[s1, g1]`, a pair it names, and refuses `[s1, g2]`, assembled from two; `NOT IN` denies
    /// when any element is a member of the union of the results, as the pairing loop and the named
    /// spelling do, so `Protocols: [ssh, tcp]` against a policy's `DeniedTypes: [ssh]` is denied in the
    /// filtered spelling as in the named one. `IN Mappings.Pairs.List[*]` over the same pairs agrees on
    /// those two and parts on a permuted or partial pair, which is pinned rather than implied: `[g1, s1]`
    /// and `[s1]` are subsets of one result and so admitted by `Combos.*.Pair`, while `Pairs.List[*]`
    /// and the written-out list of pairs match whole pairs only and refuse them, and `[22, 80] NOT IN
    /// Mappings.DenyGroups.*` passes as `NOT IN [[22], [3389]]` does. An interpolated key
    /// (`Mappings.Names.%env`) enumerates
    /// when the variable it names enumerated, holds a list of keys, or is a filter's capture; a literal
    /// bound to one key, or an indexed interpolation, names one value, as the literal key does.
    /// A literal on the left (`%needle`) is one membership question against the same set, and its
    /// failure is reported as the query-vs-query spelling's is. A call passed as a parameterized rule's
    /// argument (`check(to_lower(Upper[*]))`) keeps the call's shape inside the rule.
    ///
    /// The empty-left cells: `[] IN Types[*]` PASSES and `[] NOT IN Denied[*]` FAILS, exactly as
    /// `[] IN ["gp2", "gp3"]` and `[] NOT IN ["ssh"]` do beside them, because the empty list is
    /// vacuously a subset of a set. Agreement with the literal oracle is the only claim these four rows
    /// make. Whether an empty collection should pass `IN` at all is the empty-collection vacuous-PASS
    /// defect, a separate question left untouched here for every spelling.
    ///
    /// The controls that must not move: the same query without `[*]` resolves to one list and was
    /// already membership; a query naming one authored string (`Parameters.Allowed.Default`) keeps
    /// containment, which is what `Name IN Haystack` means; and the literal spellings beside each
    /// query spelling give the expected column today.
    ///
    /// `PASSES` and `FAILS` are the exit codes the cases name, short enough for each case to stay on one
    /// line: a rule that fails exits `VALIDATION_ERROR`, one that passes exits `SUCCESS`.
    const FAILS: i32 = StatusCode::VALIDATION_ERROR;
    const PASSES: i32 = StatusCode::SUCCESS;

    #[rstest::rstest]
    // A scalar on the left against `Types[*]`, the written-out list's verdicts.
    #[case("allowed_types_wildcard.guard", "volume_gp.yaml", FAILS)]
    #[case("allowed_types_wildcard.guard", "volume_empty.yaml", FAILS)]
    #[case("allowed_types_wildcard.guard", "volume_gp2.yaml", PASSES)]
    #[case("allowed_types_wildcard.guard", "volume_io1.yaml", FAILS)]
    #[case("allowed_types_variable_wildcard.guard", "volume_gp.yaml", FAILS)]
    #[case("allowed_types_variable_wildcard.guard", "volume_gp2.yaml", PASSES)]
    // The enumeration one key further in, and through a value-by-value function.
    #[case("allowed_types_entries_name.guard", "volume_gp.yaml", FAILS)]
    #[case("allowed_types_entries_name.guard", "volume_empty.yaml", FAILS)]
    #[case("allowed_types_entries_name.guard", "volume_gp2.yaml", PASSES)]
    #[case("allowed_types_to_lower.guard", "volume_gp.yaml", FAILS)]
    #[case("allowed_types_to_lower.guard", "volume_gp2.yaml", PASSES)]
    #[case("allowed_types_let_to_lower.guard", "volume_gp.yaml", FAILS)]
    #[case("allowed_types_let_to_lower.guard", "volume_gp2.yaml", PASSES)]
    // The author's own `[*]` after a `let`: `let entries = Mappings.Allowed.Entries` then
    // `%entries[*].Name` is `Entries[*].Name` spelled through a binding, and agrees with it in both
    // polarities, with a scalar and a list on the left, with two keys after the wildcard, and with a
    // filter after it. `g` is a strict substring of `gp2` and `s` of `ssh`: the cells containment
    // admitted and denied.
    #[case("allowed_types_entries_name.guard", "volume_g.yaml", FAILS)]
    #[case("let_entries_name.guard", "volume_gp.yaml", FAILS)]
    #[case("let_entries_name.guard", "volume_g.yaml", FAILS)]
    #[case("let_entries_name.guard", "volume_gp2.yaml", PASSES)]
    #[case("denied_name.guard", "protocol_s.yaml", PASSES)]
    #[case("denied_name.guard", "protocol_ssh.yaml", FAILS)]
    #[case("let_denied_name.guard", "protocol_s.yaml", PASSES)]
    #[case("let_denied_name.guard", "protocol_ssh.yaml", FAILS)]
    #[case("lists_entries_name.guard", "one_allowed.yaml", PASSES)]
    #[case("lists_entries_name.guard", "one_stranger.yaml", FAILS)]
    #[case("lists_let_entries_name.guard", "one_allowed.yaml", PASSES)]
    #[case("lists_let_entries_name.guard", "one_stranger.yaml", FAILS)]
    // A projection of scalar results is the written-out list of them: `[gp2, gp3]` against the names
    // `gp2`, `gp3` is a subset, as `IN ["gp2", "gp3"]` is, in the inline, the `%entries[*].Name` and the
    // `%entries.Name` spellings alike.
    #[case("lists_entries_name.guard", "two_allowed.yaml", PASSES)]
    #[case("lists_let_entries_name.guard", "two_allowed.yaml", PASSES)]
    #[case("denied_lists_name.guard", "only_tcp.yaml", PASSES)]
    #[case("denied_lists_name.guard", "ssh_and_tcp.yaml", FAILS)]
    #[case("denied_lists_let_name.guard", "only_tcp.yaml", PASSES)]
    #[case("denied_lists_let_name.guard", "ssh_and_tcp.yaml", FAILS)]
    #[case("nested_sub_name.guard", "volume_gp.yaml", FAILS)]
    #[case("nested_sub_name.guard", "volume_gp2.yaml", PASSES)]
    #[case("let_nested_sub_name.guard", "volume_gp.yaml", FAILS)]
    #[case("let_nested_sub_name.guard", "volume_gp2.yaml", PASSES)]
    #[case("entries_kind_name.guard", "volume_gp.yaml", FAILS)]
    #[case("entries_kind_name.guard", "volume_gp2.yaml", PASSES)]
    #[case("let_entries_kind_name.guard", "volume_gp.yaml", FAILS)]
    #[case("let_entries_kind_name.guard", "volume_gp2.yaml", PASSES)]
    // The reader's own slot: `%entries.Name` with no `[*]` walks the list the binding holds one member
    // at a time, so it is the same allowlist as `%entries[*].Name` and answers as it does, scalar and
    // list on the left, both polarities. A binding to one map (`let p = Parameters.Allowed`) keeps the
    // named reading, so `%p.Default` is still one haystack; and the inline `Entries.Name` without `[*]`
    // does not resolve over a list and fails as it did.
    #[case("let_entries_dot_name.guard", "volume_gp.yaml", FAILS)]
    #[case("let_entries_dot_name.guard", "volume_empty.yaml", FAILS)]
    #[case("let_entries_dot_name.guard", "volume_g.yaml", FAILS)]
    #[case("let_entries_dot_name.guard", "volume_gp2.yaml", PASSES)]
    #[case("let_denied_dot_name.guard", "protocol_s.yaml", PASSES)]
    #[case("let_denied_dot_name.guard", "protocol_ssh.yaml", FAILS)]
    #[case("lists_let_entries_dot_name.guard", "one_allowed.yaml", PASSES)]
    #[case("lists_let_entries_dot_name.guard", "one_stranger.yaml", FAILS)]
    #[case("lists_let_entries_dot_name.guard", "two_allowed.yaml", PASSES)]
    #[case("let_param_default.guard", "name_substring.yaml", PASSES)]
    #[case("let_param_default.guard", "name_other.yaml", FAILS)]
    #[case("entries_dot_name.guard", "volume_gp.yaml", FAILS)]
    #[case("entries_dot_name.guard", "volume_gp2.yaml", FAILS)]
    // A call passed as a parameterized rule's argument keeps its shape: `check(to_lower(Upper[*]))`
    // answers as the inline `IN to_lower(Upper[*])` does.
    #[case("check_to_lower.guard", "volume_gp.yaml", FAILS)]
    #[case("check_to_lower.guard", "volume_gp2.yaml", PASSES)]
    // A list on the left of an enumeration that is not the last part, against list-valued results, is
    // fail-closed in both polarities and deliberately asymmetric. `IN` holds when the list is a SUBSET of
    // some single result: an allowlist of pairs admits a pair it names and refuses one assembled from
    // two. `NOT IN` denies when ANY element is a member of the union of the results, as the pairing loop
    // and the named spelling do, so a denylist is never opened by a list that shares one element with a
    // denied one: `[s1, g2]` is out of `IN` and out of `NOT IN` alike. `Pairs.List[*]` enumerates the
    // same pairs as its last part and answers alike (the rows after the `action_*` ones).
    #[case("pair_in_combos.guard", "pair_s1g1.yaml", PASSES)]
    #[case("pair_in_combos.guard", "pair_s1g2.yaml", FAILS)]
    #[case("pair_in_combos.guard", "pair_g1s1.yaml", PASSES)]
    #[case("pair_in_combos.guard", "pair_s1.yaml", PASSES)]
    #[case("pair_not_in_combos.guard", "pair_s1g1.yaml", FAILS)]
    #[case("pair_not_in_combos.guard", "pair_s1g2.yaml", FAILS)]
    #[case("pair_not_in_combos.guard", "pair_g1s1.yaml", FAILS)]
    #[case("pair_not_in_combos.guard", "pair_s1.yaml", FAILS)]
    // The denylist the asymmetry protects, in the filtered and the named spelling: `[gp2, io1]` holds
    // the denied `gp2` and is denied by both, `[io1]` by neither; and the allowlist side, where
    // `[gp2, gp3]` is a subset of the one policy's list and `[gp2, io1]` is not.
    #[case("denied_lists_filtered.guard", "plists_gp2_io1.yaml", FAILS)]
    #[case("denied_lists_filtered.guard", "plists_io1.yaml", PASSES)]
    #[case("denied_lists_named.guard", "plists_gp2_io1.yaml", FAILS)]
    #[case("denied_lists_named.guard", "plists_io1.yaml", PASSES)]
    #[case("allowed_lists_filtered.guard", "plists_gp2_gp3.yaml", PASSES)]
    #[case("allowed_lists_filtered.guard", "plists_gp2_io1.yaml", FAILS)]
    // An interpolated key that names one key names one value: `Mappings.Names.%env` with `env` bound to
    // `prod` is the haystack `Mappings.Names.prod` is, so `bucket` is contained in `production-bucket`.
    #[case("name_in_env.guard", "name_substring.yaml", PASSES)]
    #[case("name_in_env.guard", "name_other.yaml", FAILS)]
    // The shape is what the retrieval did, not what the parse tree looks like. A `let` bound to a list
    // and indexed (`%t[0]`, `%t[-1]`, `%e[0].Name`) names one value, because the walk consumed the
    // reserved slot in front of the index, exactly as the inline index does; `bucket` is contained in
    // `production-bucket` and in `big-bucket`. An interpolation over a list of two keys
    // (`Mappings.Names.%envs`) expanded over both and is a set, in both polarities; indexed to one key
    // (`%envs[0]`) it names one value again. A call passed as a parameterized rule's argument is read
    // with the caller's resolver, so `check(to_lower(%allowed))` is the inline call's membership.
    #[case("let_types_index.guard", "types_index.yaml", PASSES)]
    #[case("types_index.guard", "types_index.yaml", PASSES)]
    #[case("let_types_last.guard", "types_index.yaml", PASSES)]
    #[case("types_last.guard", "types_index.yaml", PASSES)]
    #[case("let_entries_index_name.guard", "types_index.yaml", PASSES)]
    #[case("entries_index_name.guard", "types_index.yaml", PASSES)]
    #[case("let_envs_names.guard", "types_index.yaml", FAILS)]
    #[case("let_envs_names.guard", "types_index_full.yaml", PASSES)]
    #[case("let_envs_names_not.guard", "types_index.yaml", PASSES)]
    #[case("let_envs_names_not.guard", "types_index_full.yaml", FAILS)]
    #[case("let_envs_index.guard", "types_index.yaml", PASSES)]
    // An interpolation enumerates when the variable it names did, not when it denoted more than one
    // key: `let envs = Mappings.Allowed.KeyList1[*]` over a one-key list is the same set as over two, so
    // `Mappings.Names.%envs` is membership in the one name (`bucket` is out, `production-bucket` in),
    // and so is `let envs = ["prod"]`, a list of one key. `let env = "prod"` names one key and keeps
    // containment (`name_in_env` above), and `%envs[0]` consumed the index (`let_envs_index`).
    #[case("let_envs_one_wildcard.guard", "types_index.yaml", FAILS)]
    #[case("let_envs_one_wildcard.guard", "types_index_full.yaml", PASSES)]
    #[case("let_envs_one_wildcard_not.guard", "types_index.yaml", PASSES)]
    #[case("let_envs_one_wildcard_not.guard", "types_index_full.yaml", FAILS)]
    #[case("let_envs_one_literal.guard", "types_index.yaml", FAILS)]
    #[case("let_envs_one_literal.guard", "types_index_full.yaml", PASSES)]
    #[case("check_to_lower_var.guard", "volume_gp.yaml", FAILS)]
    #[case("check_to_lower_var.guard", "volume_gp2.yaml", PASSES)]
    // An author's `[*]` handed a scalar or a single object passes the one value on and is still the one
    // entry of the set the author named: `Types[*]` over a scalar `Types: gp2` refuses `gp` and `""` as
    // it does over `[gp2]`, `Protocols[*]` over a scalar denylist admits `s`, and the array-or-single
    // idiom `Statement[*].Action` answers the same over a list and over one object, in both polarities.
    #[case("allowed_types_wildcard.guard", "types_scalar_gp.yaml", FAILS)]
    #[case("allowed_types_wildcard.guard", "types_scalar_empty.yaml", FAILS)]
    #[case("allowed_types_wildcard.guard", "types_scalar_gp2.yaml", PASSES)]
    #[case("allowed_single_map_name.guard", "allowed_map_gp.yaml", FAILS)]
    #[case("allowed_single_map_name.guard", "allowed_map_gp2.yaml", PASSES)]
    #[case("denied_protocols_wildcard.guard", "protocol_scalar_s.yaml", PASSES)]
    #[case("denied_protocols_wildcard.guard", "protocol_scalar_ssh.yaml", FAILS)]
    #[case("action_in_statements.guard", "statement_single.yaml", FAILS)]
    #[case("action_in_statements.guard", "statement_list.yaml", FAILS)]
    #[case("action_in_statements.guard", "statement_single_eq.yaml", PASSES)]
    #[case("action_not_in_statements.guard", "statement_single.yaml", PASSES)]
    #[case("action_not_in_statements.guard", "statement_list.yaml", PASSES)]
    #[case("action_not_in_statements.guard", "statement_single_eq.yaml", FAILS)]
    // The same pairs enumerated as the query's last part (`Pairs.List[*]`) match whole pairs only, as
    // the written-out list of pairs does, so `[g1, s1]` and `[s1]` are out and `[s1, g2]` collides with
    // nothing.
    #[case("pair_in_pairs.guard", "pair_s1g1.yaml", PASSES)]
    #[case("pair_in_pairs.guard", "pair_s1g2.yaml", FAILS)]
    #[case("pair_in_pairs.guard", "pair_g1s1.yaml", FAILS)]
    #[case("pair_in_pairs.guard", "pair_s1.yaml", FAILS)]
    #[case("pair_not_in_pairs.guard", "pair_s1g1.yaml", FAILS)]
    #[case("pair_not_in_pairs.guard", "pair_s1g2.yaml", PASSES)]
    #[case("pair_not_in_pairs.guard", "pair_g1s1.yaml", PASSES)]
    #[case("pair_not_in_pairs.guard", "pair_s1.yaml", PASSES)]
    // A `let` keeps its query's part. `let pairs = Mappings.Pairs.List[*]` then `IN %pairs` matches whole
    // pairs as `Pairs.List[*]` does, so the permuted `[g1, s1]` is out; `let pairs = Mappings.Combos.*
    // .Pair` then `IN %pairs` is the per-result subset reading `Combos.*.Pair` has, so `[g1, s1]` is in;
    // `let denies = Mappings.Denies[*]` then `NOT IN %denies` matches whole entries, so `[1, 2]` collides
    // with nothing in `[[1, 3]]`. The three bindings are what separate the two shapes through a `let`.
    #[case("let_pairs_wildcard.guard", "pair_s1g1.yaml", PASSES)]
    #[case("let_pairs_wildcard.guard", "pair_g1s1.yaml", FAILS)]
    #[case("let_pairs_wildcard.guard", "pair_s1.yaml", FAILS)]
    #[case("let_combos_pairs.guard", "pair_s1g1.yaml", PASSES)]
    #[case("let_combos_pairs.guard", "pair_g1s1.yaml", PASSES)]
    #[case("let_combos_pairs.guard", "pair_s1g2.yaml", FAILS)]
    #[case("let_denies_wildcard.guard", "pair_denies.yaml", PASSES)]
    // A list on the left against lists the last part enumerated reads exactly as the written-out list of
    // lists: `[22, 80] NOT IN Mappings.DenyGroups.*` over `{ssh: [22], rdp: [3389]}` passes, as `NOT IN
    // [[22], [3389]]` passes it; `[80] IN Mappings.AllowGroups.*` over `{web: [80, 443], db: [5432]}`
    // fails, as `[80] IN [[80, 443], [5432]]` fails; and `Nest: [1, [9]] NOT IN Mappings.DenyNestedNine[*]`
    // over `[[9]]` is denied for the entry `[9]` it holds while `[1, [8]]` is not, as `NOT IN [[9]]`
    // answers.
    #[case("denied_port_groups_list.guard", "ports_22_80.yaml", PASSES)]
    #[case("denied_port_groups_list.guard", "ports_80_443.yaml", PASSES)]
    #[case("allowed_port_groups_list.guard", "allow_groups_80.yaml", FAILS)]
    #[case("allowed_port_groups_list.guard", "allow_groups_80_5432.yaml", FAILS)]
    #[case("denied_nested_nine_wildcard.guard", "nest_1_9.yaml", FAILS)]
    #[case("denied_nested_nine_wildcard.guard", "nest_1_8.yaml", PASSES)]
    // A left-hand value no entry can be compared with is refused, not read as "not a member": an
    // `InstanceType` of `!Ref TypeParam` (a map) and a `FromPort` of `22` against enumerated strings fail
    // both polarities, as the pairing loop failed them, so a denylist is not opened by a kind mismatch.
    // A value some entry CAN be compared with is decided: `80` against `[22, "ssh"]` is not a member, so
    // `NOT IN` passes it.
    #[case("denied_instance_types_wildcard.guard", "instance_ref.yaml", FAILS)]
    #[case("allowed_instance_types_wildcard.guard", "instance_ref.yaml", FAILS)]
    #[case("denied_from_ports_wildcard.guard", "from_port_22.yaml", FAILS)]
    #[case("allowed_from_ports_wildcard.guard", "from_port_22.yaml", FAILS)]
    #[case("denied_from_ports_wildcard.guard", "from_port_80_mixed.yaml", PASSES)]
    #[case("allowed_from_ports_wildcard.guard", "from_port_80_mixed.yaml", FAILS)]
    // A map against int entries is a miss in both readings, as it is against the written-out `[22,
    // 3389]`: `NOT IN` passes and `IN` fails, and nothing moved.
    #[case("denied_from_ports_wildcard.guard", "from_port_ref.yaml", PASSES)]
    #[case("allowed_from_ports_wildcard.guard", "from_port_ref.yaml", FAILS)]
    // `some` over several left-hand values is one verdict per value in both spellings: ports `22` and
    // `8080` against `[22, 443]` pass `some ... IN Ports[*]` and `some ... IN Ports` alike on the `22`;
    // without `some` both fail on the `8080`.
    #[case("some_port_in_ports_wildcard.guard", "ports_22_8080.yaml", PASSES)]
    #[case("some_port_in_ports.guard", "ports_22_8080.yaml", PASSES)]
    #[case("port_in_ports_wildcard.guard", "ports_22_8080.yaml", FAILS)]
    #[case("port_in_ports.guard", "ports_22_8080.yaml", FAILS)]
    // An interpolation over a capture enumerates: `Resources.%buckets.Properties.BucketName` after
    // `Resources[ buckets | Type == 'AWS::S3::Bucket' ]` is the set of bucket names, as the inline
    // `Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName` is, so `bucket` is out of both and
    // `production-bucket` in. The capture keeps that shape when it is passed on: as a parameterized
    // rule's argument (`names_hold(%buckets)`, then `Resources.%names...` in the body) and through a
    // `let` alias (`let names = %buckets`), both answer as the capture read directly does.
    #[case(
        "name_in_captured_bucket_names.guard",
        "buckets_name_bucket.yaml",
        FAILS
    )]
    #[case(
        "name_in_captured_bucket_names.guard",
        "buckets_name_full.yaml",
        PASSES
    )]
    #[case(
        "name_in_captured_bucket_names_param.guard",
        "buckets_name_bucket.yaml",
        FAILS
    )]
    #[case(
        "name_in_captured_bucket_names_param.guard",
        "buckets_name_full.yaml",
        PASSES
    )]
    #[case(
        "name_in_captured_bucket_names_let.guard",
        "buckets_name_bucket.yaml",
        FAILS
    )]
    #[case(
        "name_in_captured_bucket_names_let.guard",
        "buckets_name_full.yaml",
        PASSES
    )]
    // A capture made in a parameterized rule's own `when` condition enumerates an interpolation in
    // that rule's body the same way, whether or not the caller's body binds a `let` of the same name:
    // the called rule reads its own capture, and the shape questions the interpolation asks are
    // answered about that capture, not about the caller's binding.
    #[case(
        "name_in_captured_bucket_names_param_when.guard",
        "buckets_name_bucket.yaml",
        FAILS
    )]
    #[case(
        "name_in_captured_bucket_names_param_when.guard",
        "buckets_name_full.yaml",
        PASSES
    )]
    #[case(
        "name_in_captured_bucket_names_param_when_let.guard",
        "buckets_name_bucket.yaml",
        FAILS
    )]
    #[case(
        "name_in_captured_bucket_names_param_when_let.guard",
        "buckets_name_full.yaml",
        PASSES
    )]
    // The same capture passed on to a nested call as a bare `%buckets` argument enumerates inside the
    // called rule as it does in the rule that made it: the argument's shape and whether it lists keys
    // are answered by the scope that holds the capture, not by the rule that made the outer call.
    #[case(
        "name_in_captured_bucket_names_param_when_nested.guard",
        "buckets_name_bucket.yaml",
        FAILS
    )]
    #[case(
        "name_in_captured_bucket_names_param_when_nested.guard",
        "buckets_name_full.yaml",
        PASSES
    )]
    // The same capture read bare as the right-hand side is one entry set: `Prefix IN %buckets` after
    // `Resources[ buckets | Type == 'AWS::S3::Bucket' ]` holds for a prefix that IS a captured key and
    // fails for one that is not, a prefix of a key included, whatever the caller's body has bound and
    // read under the name before the call. The caller here binds an enumerating `let buckets =
    // Resources.*.Type` and reads it first; answered from that `let`, the key `BktOne` is no resource
    // type and the row that names it fails, so the control tells the capture's keys from the `let`'s
    // values. `Bkt` and `One` are each contained in a key and are no key, so a reading that searched
    // the keys for the prefix (the per-value haystack reading a plain `let`'s one string keeps) passes
    // them; `Zzz` is in no key and fails under every reading.
    #[case(
        "key_in_captured_bucket_keys_param_when_let_read.guard",
        "buckets_prefix_bktone.yaml",
        PASSES
    )]
    #[case(
        "key_in_captured_bucket_keys_param_when_let_read.guard",
        "buckets_prefix_bkt.yaml",
        FAILS
    )]
    #[case(
        "key_in_captured_bucket_keys_param_when_let_read.guard",
        "buckets_prefix_one.yaml",
        FAILS
    )]
    #[case(
        "key_in_captured_bucket_keys_param_when_let_read.guard",
        "buckets_prefix_zzz.yaml",
        FAILS
    )]
    #[case(
        "name_in_filtered_bucket_names.guard",
        "buckets_name_bucket.yaml",
        FAILS
    )]
    #[case(
        "name_in_filtered_bucket_names.guard",
        "buckets_name_full.yaml",
        PASSES
    )]
    // An entry holding the `|` the join hint would join with is still an entry.
    #[case("allowed_types_wildcard.guard", "types_pipe_gp.yaml", FAILS)]
    // A scalar on the left is a member of the lists' members under a last-part enumeration too: a scalar
    // is never a member of a list, so `Mappings.TypesByRegion.*` over `{useast1: [gp2], uswest2: [gp3]}`
    // admits `gp2` and refuses `io1`, and `Port NOT IN Mappings.DenyGroups.*` over `{ssh: [22], rdp:
    // [3389]}` denies `22` and admits `80`, as the written-out `[22, 3389]` does.
    #[case("allowed_types_by_region.guard", "region_gp2.yaml", PASSES)]
    #[case("allowed_types_by_region.guard", "region_io1.yaml", FAILS)]
    #[case("denied_types_by_region.guard", "region_gp2.yaml", FAILS)]
    #[case("denied_types_by_region.guard", "region_io1.yaml", PASSES)]
    #[case("denied_port_groups.guard", "port_22.yaml", FAILS)]
    #[case("denied_port_groups.guard", "port_80.yaml", PASSES)]
    #[case("allowed_port_groups.guard", "port_22.yaml", PASSES)]
    #[case("allowed_port_groups.guard", "port_80.yaml", FAILS)]
    // Scalar results, for a list on the left, are pooled into one set: two policies whose `AllowedTypes`
    // are the scalars `gp2` and `gp3` spell out the list `[gp2, gp3]`, and `VolumeTypes: [gp2, gp3]` is
    // a subset of it, as it is of the written-out list. Two policies holding the lists `[gp2]` and `[gp3]`
    // keep their per-result reading, so `[gp2, gp3]` is a subset of neither and fails; a scalar `gp2`
    // beside a list `[gp3]` is the pool `[gp2]` beside the set `[gp3]`, a subset of neither, as `IN [gp2,
    // [gp3]]` refuses it. `[gp2]` is a subset of one set in all three spellings.
    #[case("allowed_lists_filtered.guard", "pscalar_gp2_gp3.yaml", PASSES)]
    #[case("allowed_lists_filtered.guard", "pscalar_gp2.yaml", PASSES)]
    #[case("allowed_lists_filtered.guard", "psingle_gp2_gp3.yaml", FAILS)]
    #[case("allowed_lists_filtered.guard", "psingle_gp2.yaml", PASSES)]
    #[case("allowed_lists_filtered.guard", "pmix_gp2_gp3.yaml", FAILS)]
    #[case("allowed_lists_filtered.guard", "pmix_gp2.yaml", PASSES)]
    // A `when` condition and a filter predicate read membership as a rule body does: `Tier: prod` against
    // `Tiers: [production]` is not a member, so the gate skips its block and the predicate selects nothing,
    // at exit 0, where containment ran the encryption check; `production` (a member) runs it and fails
    // the unencrypted volume, `dev` is in neither.
    #[case("tier_gate.guard", "tier_prod_unencrypted.yaml", PASSES)]
    #[case("tier_filter.guard", "tier_prod_unencrypted.yaml", PASSES)]
    #[case("tier_gate.guard", "tier_production_unencrypted.yaml", FAILS)]
    #[case("tier_gate.guard", "tier_dev_unencrypted.yaml", PASSES)]
    #[case("tier_filter.guard", "tier_production_unencrypted.yaml", FAILS)]
    #[case("tier_filter.guard", "tier_dev_unencrypted.yaml", PASSES)]
    // A literal on the left is one membership question in both polarities and under either quantifier:
    // `"2"` over `[gp2, io1]` is a member of nothing, so `some %needle IN` fails; `gp` is a member of
    // nothing, so `%needle NOT IN` passes; `gp2` is a member, so `some %needle NOT IN` fails.
    #[case("needle_2_some_in_types_wildcard.guard", "types_gp2_io1.yaml", FAILS)]
    #[case(
        "needle_gp_not_in_denied_types_wildcard.guard",
        "denied_types_gp2_io1.yaml",
        PASSES
    )]
    #[case(
        "needle_gp2_some_not_in_denied_types_wildcard.guard",
        "denied_types_gp2_io1.yaml",
        FAILS
    )]
    // A rule read through `not`, as a parameterized call or a named rule, reads the same membership:
    // `s` over `[ssh]` is not denied, so `not is_denied(Protocol)` passes; `not denied` passes too, but
    // the plain `denied` rule in the same file fails on `s`, so that file exits 19; `ssh` is denied under
    // both spellings. `when not is_regulated(Tier)` with `prod` over `[production]`: not a member, so the
    // negated gate opens and the unencrypted volume fails; `production` closes it; `dev` opens it.
    #[case("not_denied_call.guard", "protocol_s.yaml", PASSES)]
    #[case("not_denied_call.guard", "protocol_ssh.yaml", FAILS)]
    #[case("not_denied_named.guard", "protocol_s.yaml", FAILS)]
    #[case("not_denied_named.guard", "protocol_ssh.yaml", FAILS)]
    #[case("when_not_call_gate.guard", "tier_prod_unencrypted.yaml", FAILS)]
    #[case("when_not_call_gate.guard", "tier_production_unencrypted.yaml", PASSES)]
    #[case("when_not_call_gate.guard", "tier_dev_unencrypted.yaml", FAILS)]
    // `some` over the ports `8080` and `22` in that order passes on the `22`.
    #[case("some_port_in_ports.guard", "ports_8080_22.yaml", PASSES)]
    // A type block whose clause is read once per volume: `[gp]` is no subset of the types and fails,
    // `[gp2, gp3]` is one and passes; the rule fails on the first.
    #[case("lists_wildcard_block.guard", "volumes_a_gp_b_gp2_gp3.yaml", FAILS)]
    // A list each enumerated resource holds: its members are the set for a scalar on the left, so the
    // filtered-wildcard spelling agrees with the named one in both polarities. Every enumerated member
    // of the mapping and parameter fixtures carries the key, each with its own one-entry list, so the
    // set is their union.
    #[case("allowed_from_filtered_policy.guard", "policy_gp2.yaml", PASSES)]
    #[case("allowed_from_filtered_policy.guard", "policy_io1.yaml", FAILS)]
    #[case("allowed_from_named_policy.guard", "policy_gp2.yaml", PASSES)]
    #[case("allowed_from_named_policy.guard", "policy_io1.yaml", FAILS)]
    #[case("denied_from_filtered_policy.guard", "policy_gp2.yaml", FAILS)]
    #[case("denied_from_filtered_policy.guard", "policy_io1.yaml", PASSES)]
    #[case("denied_from_named_policy.guard", "policy_gp2.yaml", FAILS)]
    #[case("denied_from_named_policy.guard", "policy_io1.yaml", PASSES)]
    #[case("allowed_from_mapping_values.guard", "policy_gp2.yaml", PASSES)]
    #[case("allowed_from_mapping_values.guard", "policy_io1.yaml", FAILS)]
    #[case("allowed_from_parameter_values.guard", "policy_gp2.yaml", PASSES)]
    #[case("allowed_from_parameter_values.guard", "policy_io1.yaml", FAILS)]
    // A list on the left (`VolumeTypes`) is a subset question, as it is against the literal beside it.
    // An EMPTY list on the left is not a vacuous subset: it is an empty collection, which fails the
    // comparison as a missing key does, in both spellings alike.
    #[case("lists_wildcard.guard", "one_allowed.yaml", PASSES)]
    #[case("lists_wildcard.guard", "two_allowed.yaml", PASSES)]
    #[case("lists_wildcard.guard", "one_stranger.yaml", FAILS)]
    #[case("lists_wildcard.guard", "no_types.yaml", FAILS)]
    #[case("lists_literal.guard", "one_allowed.yaml", PASSES)]
    #[case("lists_literal.guard", "one_stranger.yaml", FAILS)]
    #[case("lists_literal.guard", "no_types.yaml", FAILS)]
    // A literal on the left.
    #[case("needle_gp_in_types_wildcard.guard", "volume_gp2.yaml", FAILS)]
    #[case("needle_empty_in_types_wildcard.guard", "volume_gp2.yaml", FAILS)]
    #[case("needle_gp2_in_types_wildcard.guard", "volume_gp2.yaml", PASSES)]
    // `NOT IN`: a scalar, then a list (`Protocols`) whose empty spelling is vacuously a subset.
    #[case("denied_protocols_wildcard.guard", "protocol_s.yaml", PASSES)]
    #[case("denied_protocols_wildcard.guard", "protocol_ssh.yaml", FAILS)]
    #[case("denied_protocols_wildcard.guard", "protocol_tcp.yaml", PASSES)]
    #[case("denied_lists_wildcard.guard", "no_protocols.yaml", FAILS)]
    #[case("denied_lists_wildcard.guard", "only_tcp.yaml", PASSES)]
    #[case("denied_lists_wildcard.guard", "ssh_and_tcp.yaml", FAILS)]
    #[case("denied_lists_literal.guard", "no_protocols.yaml", FAILS)]
    #[case("denied_lists_literal.guard", "only_tcp.yaml", PASSES)]
    // Controls: one list, one authored string, one joined string.
    #[case("allowed_types_list.guard", "volume_gp.yaml", FAILS)]
    #[case("allowed_types_list.guard", "volume_gp2.yaml", PASSES)]
    #[case("name_in_default.guard", "name_substring.yaml", PASSES)]
    #[case("name_in_default.guard", "name_other.yaml", FAILS)]
    #[case("name_in_joined_parts.guard", "name_substring.yaml", PASSES)]
    #[case("name_in_joined_parts.guard", "name_other.yaml", FAILS)]
    // `join` approximates per-entry containment and no more. Joined with no separator, `Types[*]` over
    // `[gp2, gp3]` is the one string `gp2gp3`, and a `Name` of `2gp` is found across the seam where
    // containment, searching each entry on its own, finds it in neither; a separator that cannot occur
    // in the values keeps the entries apart. And a literal on the left answers the opposite of
    // containment: `%needle IN Types[*]` with `gp2` fails there, every entry having to contain it, while
    // the joined string holds it once and passes.
    #[case("name_in_joined_types_nosep.guard", "name_2gp.yaml", PASSES)]
    #[case("name_in_joined_types.guard", "name_2gp.yaml", FAILS)]
    #[case("name_in_joined_types.guard", "name_gp2.yaml", PASSES)]
    #[case("needle_gp2_in_joined_types.guard", "volume_gp2.yaml", PASSES)]
    // A regex whose backtracking budget runs out is a refusal, and fails closed in both spellings, for a
    // scalar and for a list on the left.
    #[case("cat_in_let_patterns.guard", "cat_long.yaml", FAILS)]
    #[case("cat_in_let_patterns_named.guard", "cat_long.yaml", FAILS)]
    #[case("cats_in_let_patterns.guard", "cats_long.yaml", FAILS)]
    // `regex_replace` maps over its first argument only; an enumerating pattern argument does not make
    // its one result a set, so `bucket` is contained in the one string `-bucket`.
    #[case("name_in_replaced_default.guard", "name_substring.yaml", PASSES)]
    #[case("name_in_replaced_default.guard", "name_other.yaml", FAILS)]
    fn in_over_an_enumerating_query_is_membership(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
    ) {
        let rules = format!("/in-over-enumerating-query/{rules}");
        let data = format!("/in-over-enumerating-query/{data}");
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec![&data])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{rules} against {data}");
    }

    /// A key filter whose right-hand side resolves to an empty collection selects by polarity: no key
    /// under `==` and `IN`, where the rule reports SKIP, and every key under `!=` and `NOT IN`.
    ///
    /// `let names = Mappings.Allowed.Names[*]` over `Names: []` hands back no entry: the retrieval stops
    /// at the empty list and marks it as the value the query could not go on from. The key filter read
    /// that marker as a comparison nobody decided and selected no key under all four comparators, so the
    /// rule reported SKIP at exit 0 whichever way it was written. The exemption direction is the one
    /// that matters: `Resources[ keys NOT IN %exempt ].Properties.Encrypted == true` over an exemption
    /// list that is empty must check every resource, and a filter that selected none checked nothing.
    /// The clause rows beside the key-filter rows pin the clause path: a clause compared with the empty
    /// collection fails in both polarities, with the key filter's polarity rule in place and without it.
    /// Over `Names: [x]` every row has the comparison's own verdict: the key filter selects `x` under
    /// `==` and `IN` and `alpha` under `!=` and `NOT IN`, all four maps to `2`; the clause rows fail on
    /// `alpha` or on `x`. The empty list
    /// literal, `let names = []`, is the same empty set. A right-hand side that stops at a key the
    /// document lacks, inside an empty map or an empty list, is not an empty collection: it is an
    /// unresolved right-hand side, the keys it selects cannot be decided, and the filter fails closed
    /// under every comparator naming the path rather than selecting no key and letting the rule SKIP.
    #[rstest::rstest]
    #[case::keys_eq_over_empty(
        "keys_eq_names_over_a_collection.guard",
        "map_names_empty.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::keys_ne_over_empty(
        "keys_ne_names_over_a_collection.guard",
        "map_names_empty.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_in_over_empty(
        "keys_in_names_over_a_collection.guard",
        "map_names_empty.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::keys_not_in_over_empty(
        "keys_not_in_names_over_a_collection.guard",
        "map_names_empty.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_eq_over_x(
        "keys_eq_names_over_a_collection.guard",
        "map_names_x.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_ne_over_x(
        "keys_ne_names_over_a_collection.guard",
        "map_names_x.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_in_over_x(
        "keys_in_names_over_a_collection.guard",
        "map_names_x.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_not_in_over_x(
        "keys_not_in_names_over_a_collection.guard",
        "map_names_x.yaml",
        PASSES,
        "PASS"
    )]
    // The same four comparators over `Names: {}`: a `[*]` over a map is a pass-through, so the right-hand
    // side RESOLVES to the empty map rather than enumerating it, and it is the same empty set. Read as a
    // value, the empty map was a kind a string key cannot be compared with, and `!=` and `NOT IN` selected
    // no key and reported SKIP where the same filters over `Names: []` selected every key.
    #[case::keys_eq_over_empty_map(
        "keys_eq_names_over_a_collection.guard",
        "map_names_empty_map.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::keys_ne_over_empty_map(
        "keys_ne_names_over_a_collection.guard",
        "map_names_empty_map.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_in_over_empty_map(
        "keys_in_names_over_a_collection.guard",
        "map_names_empty_map.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::keys_not_in_over_empty_map(
        "keys_not_in_names_over_a_collection.guard",
        "map_names_empty_map.yaml",
        PASSES,
        "PASS"
    )]
    // The `.*` spelling over both empty collections, the two negative comparators: the enumeration leaves
    // the same marker the `[*]` spelling leaves, and the filter selects every key.
    #[case::keys_ne_all_values_over_empty_list(
        "keys_ne_names_all_values_over_a_collection.guard",
        "map_names_empty.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_not_in_all_values_over_empty_list(
        "keys_not_in_names_all_values_over_a_collection.guard",
        "map_names_empty.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_ne_all_values_over_empty_map(
        "keys_ne_names_all_values_over_a_collection.guard",
        "map_names_empty_map.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_not_in_all_values_over_empty_map(
        "keys_not_in_names_all_values_over_a_collection.guard",
        "map_names_empty_map.yaml",
        PASSES,
        "PASS"
    )]
    // A map WITH members on the right is its key set. `NOT IN` selects the bucket the map does not name
    // and checks it (PASS: BucketB is encrypted); `IN` selects the bucket it names and checks that one
    // (FAIL: BucketA is not). Read as one value, the map was a kind no string key compares with, and
    // both filters selected nothing and reported SKIP at exit 0.
    #[case::keys_not_in_a_map_with_a_member(
        "keys_not_in_exempt_map.guard",
        "map_exempt_one_bucket.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_in_a_map_with_a_member(
        "keys_in_exempt_map.guard",
        "map_exempt_one_bucket.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_eq_over_empty(
        "clause_eq_names_over_a_collection.guard",
        "map_names_empty.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_ne_over_empty(
        "clause_ne_names_over_a_collection.guard",
        "map_names_empty.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_in_over_empty(
        "clause_in_names_over_a_collection.guard",
        "map_names_empty.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_not_in_over_empty(
        "clause_not_in_names_over_a_collection.guard",
        "map_names_empty.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_eq_over_x(
        "clause_eq_names_over_a_collection.guard",
        "map_names_x.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_ne_over_x(
        "clause_ne_names_over_a_collection.guard",
        "map_names_x.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_in_over_x(
        "clause_in_names_over_a_collection.guard",
        "map_names_x.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::clause_not_in_over_x(
        "clause_not_in_names_over_a_collection.guard",
        "map_names_x.yaml",
        FAILS,
        "FAIL"
    )]
    // The empty list LITERAL, `let names = []`: the same empty set, the same verdict per polarity.
    #[case::keys_eq_over_literal_empty(
        "keys_eq_empty_literal.guard",
        "map_names_x.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::keys_ne_over_literal_empty(
        "keys_ne_empty_literal.guard",
        "map_names_x.yaml",
        PASSES,
        "PASS"
    )]
    #[case::keys_in_over_literal_empty(
        "keys_in_empty_literal.guard",
        "map_names_x.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::keys_not_in_over_literal_empty(
        "keys_not_in_empty_literal.guard",
        "map_names_x.yaml",
        PASSES,
        "PASS"
    )]
    fn a_key_filter_rhs_empty_set_is_decided_by_polarity(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
        #[case] status: &str,
    ) {
        key_filter_rule_status(rules, data, expected, status);
    }

    /// Not an empty set: a right-hand side that stops at a key the document lacks, inside an empty map
    /// or an empty list, fails the filter closed as an unresolved right-hand side does, under `==` as
    /// under every other comparator; it is not decided by polarity. Its own test, because its rows and
    /// the polarity rows move for different reasons.
    #[rstest::rstest]
    #[case::absent_parameter_in_an_empty_parameters_map(
        "keys_eq_absent_param_in_empty_parameters.guard",
        "map_empty_parameters.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::wildcard_over_a_key_missing_from_an_empty_map(
        "keys_eq_names_wildcard_over_empty_map.guard",
        "map_exempt_empty_map.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::index_into_an_empty_list(
        "keys_eq_first_name_over_empty_list.guard",
        "map_names_empty.yaml",
        FAILS,
        "FAIL"
    )]
    fn a_key_the_document_lacks_is_not_an_empty_set(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
        #[case] status: &str,
    ) {
        key_filter_rule_status(rules, data, expected, status);
    }

    /// The escape hatch for an optional exemption list. A key filter over a reference the document lacks
    /// fails closed, so a rule that is meant to apply only when the list is there guards the filter with
    /// `when %exempt exists { ... }`, the way the empty-reference callout guards a clause with
    /// `when <reference> !empty`. Over a template without the parameter the guarded rule is not applicable
    /// where the unguarded one fails; over a template with it both run the check, and the exempted
    /// bucket's missing encryption is not flagged while the other bucket's is checked.
    #[rstest::rstest]
    #[case::guarded_over_an_absent_list_is_not_applicable(
        "keys_not_in_absent_param_guarded_by_exists.guard",
        "absent_param_bucket_unencrypted.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::guarded_over_a_present_list_runs_the_check(
        "keys_not_in_absent_param_guarded_by_exists.guard",
        "exempt_param_bucket_unencrypted.yaml",
        PASSES,
        "PASS"
    )]
    #[case::unguarded_over_an_absent_list_fails_closed(
        "keys_not_in_absent_param.guard",
        "absent_param_bucket_unencrypted.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::unguarded_over_a_present_list_runs_the_check(
        "keys_not_in_absent_param.guard",
        "exempt_param_bucket_unencrypted.yaml",
        PASSES,
        "PASS"
    )]
    fn an_optional_exemption_list_is_guarded_with_when_exists(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
        #[case] status: &str,
    ) {
        key_filter_rule_status(rules, data, expected, status);
    }

    /// `some` against a right-hand query the document lacks, under `!=` and `NOT IN`, through the command.
    /// Each name's comparison against the absent value is a decided failure and nothing else, so the
    /// assertion fails at the validation failure code and the gate reports its rule not applicable at
    /// exit 0. Earlier versions filed a pass beside each failure under the negated comparators, which
    /// `some` settled on: the assertion passed and the gate ran its body.
    #[rstest::rstest]
    #[case::some_ne_asserted_fails(
        "some_name_ne_absent_param.guard",
        "names_without_parameters.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::some_not_in_as_a_gate_is_not_applicable(
        "some_name_not_in_absent_param_gate.guard",
        "names_without_parameters.yaml",
        PASSES,
        "SKIP"
    )]
    fn some_against_an_absent_right_hand_query_is_decided_by_the_unresolved_side(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
        #[case] status: &str,
    ) {
        key_filter_rule_status(rules, data, expected, status);
    }

    /// The record a key filter writes for a key against the empty set reaches every reporter: the
    /// verbose tree names the empty set as the compared value, the console summary renders each key's
    /// comparison, and `-o json` keeps each as a resolved check. The evaluator's own test
    /// (`a_key_filter_record_against_the_empty_set_carries_the_empty_set`) pins the record; this reads
    /// the same two comparisons back through the command, so a reporter that dropped a root-path
    /// resolved right-hand value would go red here and not only there.
    ///
    /// The rule asserts `!empty` over the selection so that it fails and the reporters print its records:
    /// under a rule that did not apply no reporter prints per-key records at all. With no right-hand
    /// value on the record, the verbose tree printed a bare `to=`, and the console summary and the
    /// structured report dropped both comparisons and kept the unary check alone, so a failing run named
    /// no key.
    #[test]
    fn an_empty_set_key_filter_renders_through_every_reporter() {
        let rules = "/in-over-enumerating-query/keys_eq_empty_literal_not_empty.guard";
        let data = "/in-over-enumerating-query/map_names_x.yaml";

        let (verbose_code, verbose, _) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .rules(vec![rules])
                .data(vec![data])
                .show_summary(vec!["all"])
                .verbose()
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            verbose_code,
            "the selection is empty, so `!empty` fails:\n{verbose}"
        );
        for key in ["alpha", "x"] {
            assert!(
                verbose.contains(&format!(
                    "Value=\"{key}\"), to=(resolved, Path=[L:0,C:0] Value=[]))"
                )),
                "the verbose tree compares {} with the empty set:\n{}",
                key,
                verbose
            );
            assert!(
                verbose.contains(&format!(
                    "provided value [\"{key}\"] did not match expected value [[]]"
                )),
                "the console summary renders {}'s comparison with the empty set:\n{}",
                key,
                verbose
            );
        }
        assert!(
            !verbose.contains("to=)") && !verbose.contains("[null]"),
            "no record without a right-hand value, and no null for one:\n{}",
            verbose
        );

        let (json_code, json, _) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .rules(vec![rules])
                .data(vec![data])
                .show_summary(vec!["none"])
                .output_format(Some("json"))
                .run(writer, reader)
        });
        assert_eq!(StatusCode::VALIDATION_ERROR, json_code, "{json}");
        assert_eq!(
            2,
            json.matches("\"value\": []").count(),
            "one resolved check per key, each compared with the empty set:\n{json}"
        );
        assert_eq!(
            2,
            json.matches("\"Resolved\"").count(),
            "both comparisons are kept as resolved checks:\n{json}"
        );
        for key in ["alpha", "x"] {
            assert!(
                json.contains(&format!("\"path\": \"/Resources/Cfg/Map/{key}\"")),
                "the check names {}:\n{}",
                key,
                json
            );
        }
    }

    /// A function over a query as the right-hand side, the query read from the resource beside the
    /// map: `to_lower(Wanted[*].Name)`. The names the query resolved are lowered and select the key. A
    /// member of `Wanted` with no `Name` is a value the query did not resolve, which the function hands
    /// on, so the filter fails closed on it, beside a resolved name or alone, under every comparator:
    /// `keys IN to_lower(...)` and `NOT IN` over members none of which has the field fail closed as the
    /// bare query does, rather than selecting nothing at exit 0. `Wanted: 42` under `[*]` is a scalar
    /// the enumeration cannot walk and fails closed too. `Wanted: []` is an enumeration over an empty
    /// collection, the empty set: no key under `==` and `IN`, every key under `!=` and `NOT IN`.
    /// `to_lower(Wanted)` handed the members themselves, maps or a number, has no value for them and
    /// fails closed, naming the function's reason.
    #[rstest::rstest]
    #[case::lowered_names_select_the_key(
        "keys_eq_lower_wanted_names.guard",
        "resource_wanted_x.yaml",
        PASSES,
        "PASS"
    )]
    #[case::lowered_names_beside_a_member_without_one(
        "keys_eq_lower_wanted_names.guard",
        "resource_wanted_mixed.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_names_ne_beside_a_member_without_one(
        "keys_ne_lower_wanted_names.guard",
        "resource_wanted_mixed.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_names_eq_where_no_member_has_one(
        "keys_eq_lower_wanted_names.guard",
        "resource_wanted_other.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_names_ne_where_no_member_has_one(
        "keys_ne_lower_wanted_names.guard",
        "resource_wanted_other.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_names_in_where_no_member_has_one(
        "keys_in_lower_wanted_names.guard",
        "resource_wanted_other.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_names_not_in_where_no_member_has_one(
        "keys_not_in_lower_wanted_names.guard",
        "resource_wanted_other.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_names_over_an_empty_list(
        "keys_eq_lower_wanted_names.guard",
        "resource_wanted_empty.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::lowered_names_ne_over_an_empty_list(
        "keys_ne_lower_wanted_names.guard",
        "resource_wanted_empty.yaml",
        PASSES,
        "PASS"
    )]
    #[case::lowered_names_in_over_an_empty_list(
        "keys_in_lower_wanted_names.guard",
        "resource_wanted_empty.yaml",
        PASSES,
        "SKIP"
    )]
    #[case::lowered_names_not_in_over_an_empty_list(
        "keys_not_in_lower_wanted_names.guard",
        "resource_wanted_empty.yaml",
        PASSES,
        "PASS"
    )]
    #[case::lowered_names_over_a_number(
        "keys_eq_lower_wanted_names.guard",
        "resource_wanted_number.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_members_eq(
        "keys_eq_lower_wanted.guard",
        "resource_wanted_x.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_members_ne(
        "keys_ne_lower_wanted.guard",
        "resource_wanted_mixed.yaml",
        FAILS,
        "FAIL"
    )]
    #[case::lowered_number_ne(
        "keys_ne_lower_wanted.guard",
        "resource_wanted_number.yaml",
        FAILS,
        "FAIL"
    )]
    fn a_key_filters_function_argument_is_read_from_the_resource(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
        #[case] status: &str,
    ) {
        key_filter_rule_status(rules, data, expected, status);
    }

    /// Runs one key-filter fixture and asserts the exit code and the rule's status line.
    fn key_filter_rule_status(rules: &str, data: &str, expected: i32, status: &str) {
        let rules_path = format!("/in-over-enumerating-query/{rules}");
        let data_path = format!("/in-over-enumerating-query/{data}");
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules_path])
            .data(vec![&data_path])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(expected, status_code, "{rules} against {data}:\n{output}");
        let rule_line = output
            .lines()
            .find(|line| line.contains(&format!("{rules}/")) && !line.starts_with("Evaluating"));
        assert!(
            rule_line.is_some_and(|line| line.trim_end().ends_with(status)),
            "{rules} against {data}: the rule's status line must end in {status}, got {:?}:\n{output}",
            rule_line
        );
    }

    /// A key filter whose right-hand side did not resolve says so in its report.
    ///
    /// The absent-parameter rows exit 19, and the summary under that exit said "provided value
    /// ["BucketA"] did not match expected value in [[{"Unrelated": ...}]]" for `IN`, the parameters map
    /// the retrieval stopped at standing in for a list the key was never compared with, and "did match
    /// expected value in" for `NOT IN`, a success about a comparison that never ran. The per-key record
    /// carries the reason now, where the retrieval stopped and what was left of the query, and the
    /// summary renders it instead of a verdict.
    #[rstest::rstest]
    #[case::in_selects_nothing_decidable("keys_in_absent_param.guard")]
    #[case::not_in_exempts_nothing_decidable("keys_not_in_absent_param.guard")]
    fn an_undecidable_key_filter_says_its_right_hand_side_did_not_resolve(#[case] rules: &str) {
        let rules = format!("/in-over-enumerating-query/{rules}");
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec![
                "/in-over-enumerating-query/absent_param_bucket_unencrypted.yaml",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(FAILS, status_code, "{rules}: the filter fails closed");
        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("did not resolve at /Parameters")
                && output.contains("so the keys it selects cannot be decided"),
            "{}: the summary says the right-hand side did not resolve, got:\n{}",
            rules,
            output
        );
        assert!(
            !output.contains("match expected value in"),
            "{}: no verdict is claimed about a comparison that never ran, got:\n{}",
            rules,
            output
        );
    }

    /// A key filter whose right-hand side is a function over an argument it cannot read says where the
    /// read stopped, or why the function had no value.
    ///
    /// The argument is read from the resource beside the map when the map does not hold it. The read
    /// beside the map is taken whenever that scope holds the first key, not only when it produces a
    /// value, so an argument the resource holds but that resolves to nothing readable (`Wanted[*].Name`
    /// over members without a `Name`) is reported where the read stopped rather than as a key missing
    /// from the MAP at the map's path, and an enumeration over `Wanted: []` is seen as the empty set.
    /// The read's own markers say where it stopped: inside the member without the field, or at the
    /// scalar a `[*]` cannot walk. A value the function could not take has no remaining query and
    /// the function's own reason, which is what the record says instead of a retrieval stop.
    #[rstest::rstest]
    #[case::a_member_without_the_field(
        "keys_in_lower_wanted_names.guard",
        "resource_wanted_other.yaml",
        "did not resolve at /Resources/Cfg/Wanted/0"
    )]
    #[case::a_scalar_under_the_enumeration(
        "keys_eq_lower_wanted_names.guard",
        "resource_wanted_number.yaml",
        "did not resolve at /Resources/Cfg/Wanted"
    )]
    #[case::a_value_the_function_cannot_take(
        "keys_eq_lower_wanted.guard",
        "resource_wanted_x.yaml",
        "had no value at /Resources/Cfg/Wanted/0"
    )]
    fn a_function_argument_the_filter_cannot_read_names_where_it_stopped(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: &str,
    ) {
        let rules = format!("/in-over-enumerating-query/{rules}");
        let data = format!("/in-over-enumerating-query/{data}");
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec![&data])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            FAILS, status_code,
            "{rules} against {data}: the filter fails closed"
        );
        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains(expected)
                && output.contains("so the keys it selects cannot be decided"),
            "{} against {}: the summary names where the read stopped, wanted {:?}, got:\n{}",
            rules,
            data,
            expected,
            output
        );
        assert!(
            !output.contains("did not resolve at /Resources/Cfg/Map"),
            "{} against {}: the argument was not missing from the map, got:\n{}",
            rules,
            data,
            output
        );
    }

    /// Membership against an enumerating query prints no notice: the reading change is this release's,
    /// recorded in docs/CLAUSES.md, and a clause that moved says so only through its verdict.
    ///
    /// Two rows that moved in opposite directions, and two that did not, are checked for an empty
    /// stderr; the exit codes are the membership table's.
    #[rstest::rstest]
    #[case("allowed_types_wildcard.guard", "volume_gp.yaml", FAILS)]
    #[case("denied_protocols_wildcard.guard", "protocol_s.yaml", PASSES)]
    #[case("allowed_types_wildcard.guard", "volume_gp2.yaml", PASSES)]
    #[case("allowed_types_wildcard.guard", "volume_io1.yaml", FAILS)]
    fn in_over_an_enumerating_query_prints_no_notice(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
    ) {
        let rules = format!("/in-over-enumerating-query/{rules}");
        let data = format!("/in-over-enumerating-query/{data}");
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec![&data])
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{rules} against {data}");
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            !stderr.contains("NOTICE:"),
            "{rules} against {data}: no notice is printed for the reading, stderr was {:?}",
            stderr
        );
    }

    /// A refusal on the list path names the entry that refused, not the first entry.
    ///
    /// `Cats IN %pats[*]` with `let pats = ["abc", /(?!x)((a+)+)b/]` and a list holding one
    /// thirty-character string of `a`s: the list walk compares each element with the entries in order,
    /// `"abc"` is a miss and the regex runs out of backtracking budget, so the refusal names the regex
    /// at `/1`, not `entries.first()`, `"abc"` at `/0`, an entry that refused nothing.
    #[test]
    fn in_over_an_enumerating_query_names_the_entry_that_refused() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "/in-over-enumerating-query/cats_in_let_patterns.guard",
            ])
            .data(vec!["/in-over-enumerating-query/cats_long.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a spent backtracking budget is a refusal, and the clause fails closed"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Path=/1[L:0,C:0] Value=\"/(?!x)((a+)+)b/\""),
            "the refusal should name the regex at its own path, got:\n{}",
            output
        );
        assert!(
            !output.contains("Path=/0[L:0,C:0] Value=\"abc\""),
            "the refusal must not name the entry that compared cleanly, got:\n{}",
            output
        );
    }

    /// A refusal on the entry-set path names the entry it was raised against, in the resource report.
    ///
    /// `Cat IN %pats[*]` with `let pats = [/(?!x)((a+)+)b/]` and a thirty-character `Cat` of `a`s
    /// exhausts the regex engine's backtracking budget, the one refusal `contained_in` raises against an
    /// entry set. `contained_in` raises it with the list the operator built from the entries at the root
    /// path, which would report the value as not in `[Path=[L:0,C:0] Value=["/(?!x)((a+)+)b/"]]`, the
    /// whole set as one value. The operator re-points the refusal at the first entry, so the refusal
    /// names the pattern itself at its own path (`/0`, the element of the literal list) and never the
    /// set built at the root path, and the file stays in the resource-grouped report: a reference
    /// outside `/Resources/` is not filed as a finding the resource reporter cannot place, which would
    /// demote the whole file to the generic one-line summary with the pattern gone from it. The named
    /// spelling `IN %pats` is the control: its pairing loop's refusal carries the literal list itself,
    /// and its report is the same.
    #[test]
    fn in_over_an_enumerating_query_names_an_entry_in_a_refusal() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/in-over-enumerating-query/cat_in_let_patterns.guard"])
            .data(vec!["/in-over-enumerating-query/cat_long.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a spent backtracking budget is a refusal, and the clause fails closed"
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains("Number of non-compliant resources 1"),
            "the finding stays in the resource-grouped report, got:\n{}",
            output
        );
        assert!(
            output.contains("Max limit for backtracking count exceeded"),
            "the refusal keeps its own reason, got:\n{}",
            output
        );
        assert!(
            output.contains("Path=/0[L:0,C:0] Value=\"/(?!x)((a+)+)b/\""),
            "the refusal should name the first entry at its own path, got:\n{}",
            output
        );
        assert!(
            !output.contains("Path=[L:0,C:0] Value=[\"/(?!x)((a+)+)b/\"]"),
            "the refusal must not name the set built at the root path, got:\n{}",
            output
        );
    }

    /// A rule literal on the left of an enumerating query reports its failure as the query-vs-query
    /// spelling does: against the entries, each named with its path.
    ///
    /// Over the nine-name fixture of `a_long_in_comparison_is_truncated_with_a_total`, with
    /// `let needle = "gp9"` and `%needle IN %allowed_names` in place of the volume's own property. The
    /// literal-left arm reports against the entries rather than handing back the raw `contained_in`
    /// result against a list built at the root path, which would say the needle `was not present in`
    /// one value at `Path=[L:0,C:0]` holding all nine names, with no name at a path a reader could
    /// follow. A rule literal belongs to
    /// no resource, so this failure is rendered under "Findings that belong to no resource", which names
    /// the first entries with their paths and withholds the rest behind an ellipsis; the
    /// five-shown-and-a-total rendering is the resource-grouped report's and is pinned by the test named
    /// above for a left-hand value that has a resource. Both halves are asserted here as there: a
    /// renderer that named no entry at all would satisfy the withheld check on its own.
    #[test]
    fn in_over_an_enumerating_query_names_the_entries_a_literal_failed_against() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["many-allowed-values-template.yaml"])
            .rules(vec!["needle-in-allowed-names.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the needle is not among the allowed names, so the rule must fail"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let finding = output
            .lines()
            .find(|line| line.contains("was not present in"))
            .unwrap_or_else(|| panic!("no membership finding in the report:\n{}", output));
        for entry in [
            "Path=/Resources/Allowed0/Properties/Name",
            "Path=/Resources/Allowed2/Properties/Name",
        ] {
            assert!(
                finding.contains(entry),
                "expected the entry {} named with its path, got: {}",
                entry,
                finding
            );
        }
        assert!(
            !finding.contains("Allowed8") && finding.contains("..."),
            "the tail of the allowlist should be withheld behind an ellipsis, got: {}",
            finding
        );
        assert!(
            !finding.contains("Path=[L:0,C:0] Value=[\"n0\""),
            "the entries must not be rendered as one list at the root path, got: {}",
            finding
        );
    }

    /// `IN` over a function of a list-valued key is membership, as it is over the bare key.
    ///
    /// `volume-type-in-lowered-allowlist.guard` lowercases `Mappings.Allowed.Types` (`[GP2, GP3]`) and
    /// asks whether the volume's type is among the results. The function answers one string per entry,
    /// and the expanded argument reports an entry set, not the shape the key's query reported, which
    /// names its value: two strings that name their value are two haystacks to `IN`, and the volume type
    /// `gp` would pass as a substring of `gp2`, exit 0 on a volume type the allowlist does not hold. The
    /// run exits 19 with the membership finding, as it does for `IN Mappings.Allowed.Types` over `GP`.
    #[test]
    fn in_over_a_lowered_allowlist_is_membership() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["lowered-allowlist-template.yaml"])
            .rules(vec!["volume-type-in-lowered-allowlist.guard"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`gp` is a prefix of `gp2`, not a member of the lowered allowlist, so the rule must fail:\n{}",
            output
        );
        assert!(
            output.contains("was not present in"),
            "expected the membership finding in the report, got:\n{}",
            output
        );
    }

    /// A comment after a closing `>>` ends the message there; the clause that follows is evaluated.
    ///
    /// `comment_after_closing_tag.guard` closes its first message with `>> # see runbook`. The message
    /// scan accepts a closing line whose `>>` is followed by a comment, not only one whose whole trimmed
    /// text is `>>`: passing this line over would run the scan on to the next bare `>>` and absorb the
    /// `Encrypted == true` clause between the two messages into the first message's text, exit 0
    /// against a template with `Encrypted: false` with nothing on either channel. The `>>` closes the
    /// message, the comment is a comment, and B's violation is reported at exit 19, exactly as in the
    /// bare-`>>` control below.
    #[test]
    fn a_comment_after_a_closing_tag_does_not_swallow_the_next_clause() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/comment_after_closing_tag.guard"])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the clause after the commented closing tag must be evaluated and must fail"
        );
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted")
                && output.contains("must be encrypted"),
            "B's violation and its own message must be reported:\n{}",
            output
        );
    }

    /// The same shape as the repository's own documentation writes it.
    ///
    /// `documented_commented_closing_tag.guard` is the Kubernetes rule from
    /// `docs/CONTEXTAWARE_EVALUATIONS_AND_LOOPS.md`, whose first message closes with
    /// `>> # yes this YAML formatted output messaging` and whose second clause, `memory exists`, has a
    /// block message of its own. Under the exact-match terminator that second clause was swallowed into
    /// the first message, so a pod with a CPU limit and no memory limit passed at exit 0. It fails at 19
    /// now, and the report names the missing key. (A key that is absent is a retrieval error, and that
    /// report carries the path and the key rather than the clause's custom message.)
    #[test]
    fn the_documented_commented_closing_tag_example_evaluates_both_clauses() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/documented_commented_closing_tag.guard",
            ])
            .data(vec!["message-closing-tag/pod_without_memory_limit.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the memory check after the commented closing tag must be evaluated and must fail"
        );
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("Could not find key memory"),
            "the memory clause must be the one reported as failing:\n{}",
            output
        );
    }

    /// Control for the tests above: the closing `>>` alone on its line, the shape the corpus
    /// messages use. This already reported B's violation and has to keep doing so.
    #[test]
    fn a_bare_closing_tag_still_reports_the_next_clause() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/bare_closing_tag.guard"])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted"),
            "the control must keep naming B's property:\n{}",
            output
        );
    }

    /// `or` after a closing `>>` joins the next clause as a disjunct, and both disjuncts are evaluated.
    ///
    /// `or_after_closing_tag.guard` closes its first message with `>> or`. Under the exact-match
    /// terminator the line was message text and B was swallowed, so with A false the rule failed
    /// whatever B held. Now the two clauses are `A or B`: with A false and B false the rule fails and
    /// names B; with A false and B true it passes. The second case is the one the old scan got wrong.
    #[rstest::rstest]
    #[case::both_disjuncts_fail(
        "message-closing-tag/template_a_wrong_b_false.yaml",
        StatusCode::VALIDATION_ERROR
    )]
    #[case::the_second_disjunct_holds(
        "message-closing-tag/template_a_wrong_b_true.yaml",
        StatusCode::SUCCESS
    )]
    fn an_or_after_a_closing_tag_joins_the_next_clause_as_a_disjunct(
        #[case] template: &str,
        #[case] expected: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/or_after_closing_tag.guard"])
            .data(vec![template])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read stdout");
        assert_eq!(
            expected, status_code,
            "`or` after the closing tag must join B as a disjunct; output:\n{}",
            output
        );
        if expected == StatusCode::VALIDATION_ERROR {
            assert!(
                output.contains("/Resources/B/Properties/Encrypted"),
                "B was evaluated as the second disjunct, so its failure is reported:\n{}",
                output
            );
        }
    }

    /// A rule name directly after a block message's terminator `>>` is the rule reference the grammar
    /// reads, the same as after an inline tag (the contract is the doc comment on `extract_message`).
    ///
    /// `rule_name_after_closing_tag.guard` closes its first message with `>> other`, where `other` is a
    /// rule the file declares, and `rule_name_and_comment_after_closing_tag.guard` with `>> other # see
    /// the runbook.`. Under the exact-match terminator both lines were message text and B was swallowed
    /// at exit 0. Now the `>>` closes the message, `other` is a dependency that holds, and B's clause is
    /// evaluated and fails at exit 19 with its property named. No parse error is raised.
    #[rstest::rstest]
    #[case::the_name_of_a_rule("message-closing-tag/rule_name_after_closing_tag.guard")]
    #[case::the_name_of_a_rule_then_a_comment(
        "message-closing-tag/rule_name_and_comment_after_closing_tag.guard"
    )]
    fn a_rule_name_after_a_block_closing_tag_is_the_reference_it_reads_as(#[case] rules: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read stdout");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`other` holds and B's clause after the message fails; stdout:\n{}",
            output
        );
        assert!(
            output.contains("/Resources/B/Properties/Encrypted"),
            "B's violation must be reported:\n{}",
            output
        );
    }

    /// An undeclared rule name after a block terminator is read as a reference and refused at evaluation,
    /// not at parse time.
    ///
    /// `text_after_closing_tag.guard` closes its first message with `>> foo`, and no rule `foo` exists.
    /// The parser reads the reference and the evaluator refuses it ("Rule foo by that name does not
    /// exist"), which it reports at the same exit code as a parse error but through its own channel, so
    /// the assertion reads the text. Under the exact-match terminator the line was message text and B was
    /// swallowed at exit 0.
    #[test]
    fn an_undeclared_rule_name_after_a_block_closing_tag_is_refused_at_evaluation() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/text_after_closing_tag.guard"])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_ne!(
            StatusCode::SUCCESS,
            status_code,
            "a reference to a rule that does not exist cannot pass silently; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("Rule foo by that name does not exist")
                && !stderr.contains("Parsing error handling rule file")
                && !stderr.contains("Unable to find a closing >> tag"),
            "the refusal is the evaluator's, naming the rule, not the parser's:\n{}",
            stderr
        );
    }

    /// An operator typo after a closing tag gets the grammar's own error, not the rule-reference advice.
    ///
    /// `operator_typo_after_closing_tag.guard` has `<< m >> Resources.B.Properties.Encrypted = true`, a
    /// single `=` where `==` was meant. The clause parser rejects it, and the rule-reference reading gets
    /// as far as the name `Resources` before the `.` stops it; no reference is produced, so the refusal is
    /// the grammar's, pointing at `.B.Properties.Encrypted = true` where it stopped. The advice to put a
    /// rule reference on its own line would be the wrong fix here, and this pins that it is not given.
    #[test]
    fn an_operator_typo_after_a_closing_tag_gets_the_grammars_own_error() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/operator_typo_after_closing_tag.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "an operator typo is a parse error; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains(".B.Properties.Encrypted = true")
                && !stderr.contains("a body line may not start with >>"),
            "the report must be the grammar's own error at the typo, without the body-line hint:\n{}",
            stderr
        );
    }

    /// A forgotten closing tag is refused even when a later line starts with `>>`.
    ///
    /// `forgotten_closing_tag.guard` forgets the tag on A's message, and B's block message closes with
    /// `>> # see runbook`. The exact-match terminator refused this file only because no line was exactly
    /// `>>`; a terminator that starts its line would close A's message on B's tag and delete B at exit 0
    /// when A holds. The `<<` inside the scanned body is the sign of a swallowed clause, and the file is
    /// refused at exit 5 with the forgotten tag named.
    #[test]
    fn a_forgotten_closing_tag_before_another_message_is_refused() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/forgotten_closing_tag.guard"])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a forgotten closing tag must be refused, not closed on the next message's tag; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("a << appears before the next closing >>"),
            "the report must say the tag was forgotten:\n{}",
            stderr
        );
    }

    /// A body line ending in `>>` followed by a clause with its own message is refused as a forgotten tag,
    /// and the error names that line as the one probably meant to close the message.
    ///
    /// `text_before_closing_tag.guard` writes its first message as `<< Violation: X` and then
    /// `Fix: Y >>`. That line was not a terminator under the exact-match rule, so the message stayed open
    /// until B's own `>>` and B was swallowed: exit 0 against `Encrypted: false`, with one clause in the
    /// parse tree. The `<<` on B's line refuses it now, at exit 5, and the error names `Fix: Y >>` and
    /// says where a closing tag goes.
    #[test]
    fn a_forgotten_tag_after_a_body_line_ending_in_a_closing_tag_names_that_line() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/text_before_closing_tag.guard"])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "B's << refuses the file as a forgotten tag; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("a << appears before the next closing >>")
                && stderr.contains("The earlier line `Fix: Y >>` (line 3) ends in >> after other text")
                && stderr.contains("the closing >> tag must start its line"),
            "the report must name the forgotten tag's line and the earlier line probably meant to close \
             the message:\n{}",
            stderr
        );
    }

    /// A body line that starts with `>>` closes the message, and the text after it is refused.
    ///
    /// `body_line_starting_with_closing_tag.guard` has `>> append to the runbook` inside its first
    /// message. Under the exact-match rule that line was text and the file parsed. Now the `>>` closes
    /// the message, and `append to the runbook` goes to the grammar, which refuses it at exit 5 with its
    /// own error. Loud, where the old scan silently read the line as text.
    #[test]
    fn a_body_line_starting_with_a_closing_tag_is_refused() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/body_line_starting_with_closing_tag.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a body line starting with >> closes the message and the rest is refused; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("fragment to the runbook")
                && stderr.contains("a body line may not start with >>"),
            "the report must be the grammar's refusal at `to` with the one hint that a body line may \
             not start with >>:\n{}",
            stderr
        );
    }

    /// A trailing comment after a misplaced closing tag does not hide it from the error.
    ///
    /// `comment_after_tag_on_body_line.guard` writes `Fix: Y >> # see runbook` inside A's message, and B's
    /// clause with its own message follows. The `<<` on B's line refuses the file at exit 5, and the
    /// report names the `Fix: Y >> # see runbook` line as the one probably meant to close the message,
    /// comment and all.
    #[test]
    fn a_closing_tag_followed_by_a_comment_on_a_body_line_is_refused() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/comment_after_tag_on_body_line.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a >> and a comment after body text must be refused; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("a << appears before the next closing >>")
                && stderr.contains(
                    "The earlier line `Fix: Y >> # see runbook` (line 3) ends in >> after other text"
                ),
            "the report must name the forgotten tag's line and the line holding the misplaced tag:\n{}",
            stderr
        );
    }

    /// A quoted `}` in a body and a later line ending in `>>` are the two readings of an unterminated
    /// message, and neither is given as the only fix.
    ///
    /// `json_body_before_tag_line.guard` quotes a JSON fragment (`{"a": 1` and `}`) inside A's message,
    /// then ends a line in `>>`, and no later line starts with `>>`. The report says the message may be
    /// missing its tag before the `}`, or may run to the `>>` line, whose tag must then start its line.
    #[test]
    fn an_unterminated_message_past_a_quoted_brace_names_both_readings() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/json_body_before_tag_line.guard"])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a body line ending in >> is refused; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("Two readings: the message opened at line 2 is missing its closing >> tag before `}` at line 4")
                && stderr.contains("or it runs to line 5, where the line `then redeploy >>` ends in >> after other text")
                && stderr.contains("the closing >> tag there must start its line"),
            "both readings must be named:\n{}",
            stderr
        );
    }

    /// A body line that ends in `>>` is text when a terminator line follows, and the message is complete.
    ///
    /// `list_type_in_message_body.guard` writes `Expected: List<List<String>>` inside A's message and
    /// closes it on the next line. Refusing a body line ending in `>>` on sight rejected this complete
    /// message; it parses, and B's clause after it fails at exit 19.
    #[test]
    fn a_body_line_ending_in_a_closing_tag_is_text_when_the_terminator_follows() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["message-closing-tag/list_type_in_message_body.guard"])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the message is complete and B's clause fails; stderr:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted"),
            "B's violation must be reported:\n{}",
            output
        );
    }

    /// A message body that quotes a rule header at the start of a line is refused, the cost of the check
    /// above.
    ///
    /// `quoted_rule_header_in_message_body.guard` writes a complete block message whose body holds `rule
    /// encrypted {` as a "Fix: add a rule such as" example, and closes it with its own `>>`. The scan
    /// cannot tell a quoted header from a swallowed one, so the file is refused at exit 5 with the header
    /// named; earlier releases read it as text. `docs/KNOWN_ISSUES.md` lists the shape and the rewrite
    /// (move the quoted header off the start of its line).
    #[test]
    fn a_quoted_rule_header_in_a_message_body_is_refused() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/quoted_rule_header_in_message_body.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a quoted rule header in a body is refused by the header check; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("the next line starting with >> is line 7")
                && stderr.contains("passed the rule header `rule encrypted {` at line 4")
                && stderr.contains("A message body may not hold a rule header"),
            "the report must name the quoted header and the terminator line:\n{}",
            stderr
        );
    }

    /// A terminator found past a rule header is refused, in every header style, so no edit of a stray `>>`
    /// can swallow a rule.
    ///
    /// Each fixture forgets the tag on rule one's message; rule two follows, and a `>>` alone on a line
    /// sits inside rule two. A terminator-line scan that stopped there would close rule one's message over
    /// rule two's header and clause, and the file would pass at exit 0 with rule two gone. The header is
    /// written three ways: `rule two {`, the two-line header the docs write (`rule two` with `when ...` on
    /// the next line), and a parameterized header `rule two(a) {`. Each is refused at exit 5 with the
    /// header and the terminator line named.
    #[rstest::rstest]
    #[case::a_brace_header(
        "message-closing-tag/terminator_past_a_rule_header.guard",
        "rule two {",
        7
    )]
    #[case::a_two_line_header(
        "message-closing-tag/terminator_past_a_two_line_rule_header.guard",
        "rule two",
        9
    )]
    #[case::a_parameterized_header(
        "message-closing-tag/terminator_past_a_parameterized_rule_header.guard",
        "rule two(a) {",
        7
    )]
    fn a_terminator_past_a_rule_header_is_refused(
        #[case] rules: &str,
        #[case] header: &str,
        #[case] terminator_line: u32,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a terminator past a rule header must be refused; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains(&format!(
                "the next line starting with >> is line {}",
                terminator_line
            )) && stderr.contains(&format!("passed the rule header `{}` at line 4", header))
                && stderr.contains("A message body may not hold a rule header"),
            "the report must name the terminator line and the rule header:\n{}",
            stderr
        );
    }

    /// `OR` after a closing `>>` is the same join as `or`: A false and B true passes.
    #[test]
    fn an_uppercase_or_after_a_closing_tag_joins_the_next_clause_as_a_disjunct() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/or_uppercase_after_closing_tag.guard",
            ])
            .data(vec!["message-closing-tag/template_a_wrong_b_true.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "`OR` after the closing tag must join B as a disjunct; output:\n{}",
            writer.stripped().expect("failed to read stdout")
        );
    }

    /// A block message inside a filter can end right before the `]`, so `>> ]` continues the grammar.
    ///
    /// `filter_message_closed_before_bracket.guard` writes `Resources.*[ Type == "x" <<`, a body, and
    /// `>> ] exists`. Under the exact-match terminator no line was exactly `>>`, so the file was refused as
    /// unterminated; the filter selects A and the rule passes at exit 0.
    #[test]
    fn a_closing_tag_before_the_filter_bracket_closes_the_message() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/filter_message_closed_before_bracket.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "`]` after the closing tag must close the filter; stderr:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );
    }

    /// A message on a `when` condition may be followed by the `{` that opens the block on the same line,
    /// in both message forms.
    ///
    /// `when_message_before_block.guard` writes `rule r when Resources.A.Type == "x" << why >> {`, and
    /// `when_block_message_before_block.guard` the same condition with a block message whose terminator
    /// line goes on with `>> {`. Both are legal grammar that parsed and evaluated before the closing-tag
    /// rules existed, so the admitted set after a closing tag includes the opening brace; B's clause inside
    /// the block fails at exit 19.
    #[rstest::rstest]
    #[case::inline_message("message-closing-tag/when_message_before_block.guard")]
    #[case::block_message("message-closing-tag/when_block_message_before_block.guard")]
    fn a_closing_tag_on_a_when_condition_may_be_followed_by_the_block_brace(#[case] rules: &str) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the block after the when condition's message must be evaluated; stderr:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted"),
            "B's violation must be reported:\n{}",
            output
        );
    }

    /// A second clause on the same line after an inline message is a clause, and it is evaluated.
    ///
    /// `clause_after_inline_message_on_one_line.guard` writes `Resources.A.Type == "x" << a message >>
    /// Resources.B.Properties.Encrypted == true` on one line. This parsed and evaluated before the
    /// closing-tag rules existed; the grammar reads the text after the tag as the clause it is, and B fails
    /// at exit 19 (the contract is the doc comment on `extract_message` in the parser).
    #[test]
    fn a_clause_on_the_same_line_after_an_inline_closing_tag_is_evaluated() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/clause_after_inline_message_on_one_line.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the clause after the inline message is evaluated and fails; stderr:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted"),
            "B's violation must be reported:\n{}",
            output
        );
    }

    /// A same-line clause is admitted by the grammar, not by its characters: an uppercase operator and a
    /// `this`-rooted query both pass and are evaluated.
    ///
    /// `uppercase_operator_clause_after_closing_tag.guard` writes `<< a message >>
    /// Resources.B.Properties.Missing EXISTS`, and `this_clause_after_closing_tag.guard` writes
    /// `<< a message >> this.Resources.B.Properties.Encrypted == true`. Both parsed and evaluated before
    /// the closing-tag rules existed; both fail at exit 19 against the template.
    #[rstest::rstest]
    #[case::uppercase_operator(
        "message-closing-tag/uppercase_operator_clause_after_closing_tag.guard",
        "Missing"
    )]
    #[case::this_rooted_query(
        "message-closing-tag/this_clause_after_closing_tag.guard",
        "/Resources/B/Properties/Encrypted"
    )]
    fn a_grammar_accepted_clause_after_an_inline_closing_tag_is_evaluated(
        #[case] rules: &str,
        #[case] named: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the clause after the inline message is evaluated and fails; stderr:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains(named),
            "the failing clause's subject must be reported:\n{}",
            output
        );
    }

    /// A `#` inside a string literal after an inline closing tag is the literal's, not a comment.
    ///
    /// `hash_in_literal_after_closing_tag.guard` writes `Resources.B.Properties.Encrypted == false << m >>
    /// Resources.A.Type == "x #1"` on one line; `hash_literal_after_closing_tag.guard` compares with `"#"`;
    /// `quoted_hash_and_comment_after_closing_tag.guard` compares with `'a # b'` and carries a real
    /// trailing comment. The text after the tag is read by the grammar as written before any comment is
    /// set aside, so each is a clause: with `Type: "x #1"` the first passes at exit 0 (as it did before the
    /// closing-tag rules), and against the plain template each fails at exit 19 on A's type.
    #[rstest::rstest]
    #[case::hash_in_literal_matching(
        "message-closing-tag/hash_in_literal_after_closing_tag.guard",
        "message-closing-tag/template_a_type_with_hash.yaml",
        StatusCode::SUCCESS
    )]
    #[case::hash_in_literal_not_matching(
        "message-closing-tag/hash_in_literal_after_closing_tag.guard",
        "message-closing-tag/template.yaml",
        StatusCode::VALIDATION_ERROR
    )]
    #[case::hash_literal(
        "message-closing-tag/hash_literal_after_closing_tag.guard",
        "message-closing-tag/template.yaml",
        StatusCode::VALIDATION_ERROR
    )]
    #[case::quoted_hash_then_comment(
        "message-closing-tag/quoted_hash_and_comment_after_closing_tag.guard",
        "message-closing-tag/template.yaml",
        StatusCode::VALIDATION_ERROR
    )]
    fn a_hash_inside_a_literal_after_an_inline_closing_tag_is_not_a_comment(
        #[case] rules: &str,
        #[case] template: &str,
        #[case] expected: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec![template])
            .run(&mut writer, &mut reader);

        assert_eq!(
            expected,
            status_code,
            "the clause after the inline message must parse and be evaluated; stderr:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );
    }

    /// What follows an inline closing tag is parsed by the grammar on the real file, so clauses that continue
    /// onto later lines, and a file with multi-byte characters before the tag, parse and evaluate.
    ///
    /// Four files that parsed before the closing-tag rules existed. `inline_then_block_message_clause.guard`
    /// puts a clause with its own block message after an inline one; `filter_opened_after_inline_message.guard`
    /// and `block_opened_after_inline_message.guard` open a filter and a block on the tag's line and close
    /// them later; `non_ascii_comment_before_inline_message.guard` starts with a comment in CJK characters,
    /// which made a probe that parsed a copy of the tag's line slice inside a character of the real file. All
    /// four fail at exit 19 on B.
    #[rstest::rstest]
    #[case::block_message_on_the_same_line(
        "message-closing-tag/inline_then_block_message_clause.guard"
    )]
    #[case::filter_opened("message-closing-tag/filter_opened_after_inline_message.guard")]
    #[case::block_opened("message-closing-tag/block_opened_after_inline_message.guard")]
    #[case::block_opened_by_a_bare_key(
        "message-closing-tag/bare_key_block_opened_after_inline_message.guard"
    )]
    #[case::multi_byte_comment_before(
        "message-closing-tag/non_ascii_comment_before_inline_message.guard"
    )]
    fn a_clause_continuing_past_an_inline_closing_tag_is_parsed_by_the_grammar(
        #[case] rules: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the file must parse and B's clause must fail; stderr:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted"),
            "B's violation must be reported:\n{}",
            output
        );
    }

    /// A rule name after an inline closing tag is a same-line conjunction, not message text.
    ///
    /// An inline message closes at the first `>>` on its line, so `<< a message >> other` always meant
    /// "and rule `other`", the same same-line conjunction that `A == "x" other` produces; only the block
    /// terminator line was ever message text. Refusing the inline form would be a change with no defect
    /// behind it, so these fixtures evaluate as the same-line conjunctions they are, against a template
    /// whose A has Type x and whose B is not encrypted: `other` and `thisRule` hold and B fails (exit 19);
    /// `other` carrying its own message, and `other |OR| B` with `other` holding, pass (exit 0); the `when`
    /// condition's `other {` holds and B inside the block fails (exit 19). None is a parse error.
    #[rstest::rstest]
    #[case::a_rule_name(
        "message-closing-tag/inline_rule_name_after_closing_tag.guard",
        StatusCode::VALIDATION_ERROR
    )]
    #[case::a_this_prefixed_rule_name(
        "message-closing-tag/this_prefixed_rule_name_after_closing_tag.guard",
        StatusCode::VALIDATION_ERROR
    )]
    #[case::a_rule_name_carrying_its_own_message(
        "message-closing-tag/bare_word_then_message_after_closing_tag.guard",
        StatusCode::SUCCESS
    )]
    #[case::a_rule_name_joined_by_or_bars(
        "message-closing-tag/or_bars_rule_name_after_closing_tag.guard",
        StatusCode::SUCCESS
    )]
    #[case::a_rule_name_as_a_when_condition_before_the_brace(
        "message-closing-tag/when_condition_rule_name_then_brace.guard",
        StatusCode::VALIDATION_ERROR
    )]
    fn a_rule_name_after_an_inline_closing_tag_keeps_its_reading(
        #[case] rules: &str,
        #[case] expected: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            expected, status_code,
            "a rule name after an inline tag is the reference it always was; stderr:\n{}",
            stderr
        );
    }

    /// An operator typo after a block terminator gets the grammar's own error, with neither hint.
    ///
    /// `block_operator_typo_after_closing_tag.guard` closes a block message with `>> Resources.B.Properties.Encrypted = true`,
    /// a single `=` where `==` was meant. `var_name` stops on the `.` after `Resources`, not on prose, so
    /// the body-line hint that `>> append to the runbook` gets is not given here either; the grammar's
    /// own error at `.B.Properties.Encrypted = true` stands in both message forms.
    #[test]
    fn an_operator_typo_after_a_block_closing_tag_gets_the_grammars_own_error() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/block_operator_typo_after_closing_tag.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "an operator typo is a parse error; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains(".B.Properties.Encrypted = true")
                && !stderr.contains("a body line may not start with >>"),
            "the report must be the grammar's own error at the typo, without the body-line hint:\n{}",
            stderr
        );
    }

    /// An inline message that opens another message before its own tag is a forgotten tag, not a message.
    ///
    /// `inline_forgotten_closing_tag.guard` writes `Resources.A.Type == "x" << forgot or
    /// Resources.B.Properties.Encrypted == true << must be encrypted >>` on one line. The `<<` before
    /// the closing tag is refused in the inline form as it is in the block form, at exit 5, naming the
    /// forgotten tag; closing at the first `>>` on the line instead would make B's clause A's message
    /// text and exit 0 against `Encrypted: false`.
    #[test]
    fn an_inline_closing_tag_after_a_second_opening_tag_is_refused() {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/inline_forgotten_closing_tag.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "an inline message holding a second << must be refused, not close on the later >>; stderr:\n{}",
            stderr
        );
        assert!(
            stderr.contains("a << appears before the next closing >>"),
            "the report must say the tag was forgotten:\n{}",
            stderr
        );
    }

    /// A `>>` in the middle of a body line is message text, and the clause after the message is evaluated.
    ///
    /// `midline_tag_in_message_body.guard` carries `Fix: echo x >> file` inside its first message. The
    /// line does not end in `>>`, so it is text; B's clause follows and fails at exit 19, with the first
    /// message intact. A refusal of every `>>` after text would have rejected this file for no gain: the
    /// `<<` check and the unterminated-tag error already keep a clause from being swallowed.
    #[test]
    fn a_tag_in_the_middle_of_a_body_line_is_message_text() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![
                "message-closing-tag/midline_tag_in_message_body.guard",
            ])
            .data(vec!["message-closing-tag/template.yaml"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read stdout");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "B's clause after the message must be evaluated and must fail; output:\n{}",
            output
        );
        assert!(
            output.contains("/Resources/B/Properties/Encrypted"),
            "B's violation must be reported:\n{}",
            output
        );
    }

    /// A JSON template whose string holds a surrogate-pair escape is read, and a finding after the
    /// pair on the same line is reported at the column the source text has it.
    ///
    /// libyaml refuses the pair, which would refuse the whole template, so the pair is rewritten as
    /// YAML's ten-character `\U0001F600` escape before the loader reads the text. The
    /// rewrite is two characters shorter than the twelve-character pair, so every later column on that
    /// line comes out of the loader two too small; the rewrite records where it shortened the line
    /// and the positions are corrected afterwards. `false` sits at column 69 of the input and is
    /// reported at column 69. Pinned so that a change to the rewrite or to the correction shows up as
    /// a moved column rather than as silence; the mechanism is on `rules::values::read_from`.
    #[test]
    fn a_json_template_with_a_surrogate_pair_is_read_and_a_later_finding_keeps_its_source_column() {
        let input = "{\"Resources\":{\"B\":{\"Properties\":{\"Label\":\"\\ud83d\\ude00\",\"Encrypted\":false}}}}";
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .verbose()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted[L:1,C:69]"),
            "the finding after the pair must keep its source column 69:\n{}",
            output
        );
    }

    /// Two surrogate pairs on one line, and a finding after both is still at its source column.
    ///
    /// Each rewritten pair shortens the line by two, so the loader's column for anything after the
    /// second pair is four too small, not two: the correction has to add back the shift of every pair
    /// before the position, not a fixed two. `json.dumps` writes a whole document on one line, so a
    /// template with several emoji in it is the ordinary case for this. `false` sits at column 81.
    #[test]
    fn two_surrogate_pairs_on_one_line_leave_a_later_finding_at_its_source_column() {
        let input = "{\"Resources\":{\"B\":{\"Properties\":{\"Label\":\"\\ud83d\\ude00\\ud83d\\ude01\",\"Encrypted\":false}}}}";
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .verbose()
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains("/Resources/B/Properties/Encrypted[L:1,C:81]"),
            "the finding after two pairs must keep its source column 81:\n{}",
            output
        );
    }

    /// A JSON template written in one of the shapes libyaml's scanner does not accept is rewritten
    /// the way a YAML emitter would write it and read, so the rule reaches its verdict.
    ///
    /// The same three shapes the `test` command pins for a spec file, on the data-file route: a member
    /// name past libyaml's simple-key limit, a line break between a member name and its colon, and a
    /// raw U+007F-U+009F character inside a string. All three are valid JSON and all three read before
    /// the YAML loader took over every route, so refusing them, even with a message naming the limit,
    /// was a regression on documents every JSON tool accepts. Each is rewritten before the loader
    /// reads the text, and `Encrypted: false` reaches the rule, which fails it at exit 19.
    #[rstest::rstest]
    #[case::a_member_name_past_the_limit(format!(
        "{{\"Resources\":{{\"B\":{{\"Properties\":{{\"Encrypted\":false,\"{}\":1}}}}}}}}",
        "k".repeat(1100)
    ))]
    #[case::a_line_break_before_the_colon(
        "{\"Resources\"\n:{\"B\":{\"Properties\":{\"Encrypted\":false}}}}".to_string()
    )]
    #[case::a_raw_control_character(
        "{\"Resources\":{\"B\":{\"Properties\":{\"Encrypted\":false,\"Label\":\"a\u{0080}b\"}}}}"
            .to_string()
    )]
    fn a_json_template_libyaml_cannot_scan_is_rewritten_and_read(#[case] input: String) {
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the document is read and the rule fails on it, rather than the file being refused:\n{}",
            err
        );
        assert!(
            !err.contains("valid JSON"),
            "nothing says the file could not be read:\n{}",
            err
        );
    }

    /// A JSON template whose string holds a raw U+0085, U+2028 or U+2029 reads the character, and a
    /// finding after it is reported where the loader would place it in the source.
    ///
    /// JSON permits the three unescaped, and the YAML reader treats each as a line break: inside a
    /// double-quoted scalar it is folded, so `"a<NEL>b"` read as `a b` and `"a <LS> b"` as `a<LS>b`,
    /// and the load succeeded, so no error said so. The character is escaped before the loader reads
    /// the text, and the first run pins the value through a rule that holds only when the string is
    /// intact. The second run pins the position: the loader counts the raw character as a line break,
    /// and the report's excerpt numbers lines the same way, so `false` after the break is on line 2 --
    /// for `"a<NEL>b"`, `b` 1, `"` 2, `,` 3, `"Encrypted"` 4 to 14, `:` 15, `false` 16; for the
    /// five-character strings one further along. The mechanism is on `rules::values::read_from`.
    #[rstest::rstest]
    #[case::a_next_line("a\u{0085}b", "a_raw_next_line_in_a_json_string_is_kept.guard", 16)]
    #[case::a_line_separator(
        "a \u{2028} b",
        "a_raw_line_separator_in_a_json_string_is_kept.guard",
        17
    )]
    #[case::a_paragraph_separator(
        "a \u{2029} b",
        "a_raw_line_separator_in_a_json_string_is_kept.guard",
        17
    )]
    fn a_json_template_with_a_raw_line_break_in_a_string_reads_the_character_and_keeps_positions(
        #[case] label: &str,
        #[case] rule: &str,
        #[case] column_after_the_break: usize,
    ) {
        let input = format!(
            "{{\"Resources\":{{\"B\":{{\"Properties\":{{\"Label\":\"{label}\",\"Encrypted\":false}}}}}}}}"
        );

        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .rules(vec![rule])
            .run(&mut writer, &mut reader);
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the string must hold the character, not a folded line break:\n{}",
            writer.err_to_stripped().expect("failed to read stderr")
        );

        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .verbose()
            .run(&mut writer, &mut reader);
        assert_eq!(StatusCode::VALIDATION_ERROR, status_code);
        let output = writer.stripped().expect("failed to read stdout");
        assert!(
            output.contains(&format!(
                "/Resources/B/Properties/Encrypted[L:2,C:{column_after_the_break}]"
            )),
            "the finding after the break is on line 2 at column {column_after_the_break}, as the \
             loader numbers the source:\n{}",
            output
        );
    }

    /// A YAML template that shares a block through an anchor and an alias is read with the alias
    /// resolved, as a `test` spec and the library entry point read the same document.
    ///
    /// The reader every route used before the YAML loader took over resolved aliases, and the loader
    /// refused them on this route alone, so a template that evaluated before was refused at exit 5
    /// with a message asking the author to write the value out. The one alias policy is restored:
    /// every route resolves them within the same budget, and the refusals that remain are the ones
    /// every route shares, pinned by the test after this one. The spec with the same document is
    /// `resources/test-command/aliases/type_through_an_alias_tests.yaml`, and the library entry
    /// point's pin sits beside it in `commands::helper`.
    #[rstest::rstest]
    #[case::the_rule_holds_through_the_alias("true", StatusCode::SUCCESS)]
    #[case::the_rule_fails_through_the_alias("false", StatusCode::VALIDATION_ERROR)]
    fn a_yaml_template_with_an_alias_resolves_it_as_the_other_routes_do(
        #[case] encrypted: &str,
        #[case] expected: i32,
    ) {
        let input = format!(
            "Base: &base {{Encrypted: {encrypted}}}\nResources: {{B: {{Properties: *base}}}}\n"
        );
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert_eq!(
            expected, status_code,
            "the aliased block is the rule's input, not a refusal:\n{}",
            err
        );
    }

    /// An alias the loader cannot resolve refuses a template with the loader's reason, the same
    /// reason the other routes give: an anchor no earlier node declares, or a copy past the budget,
    /// which on a template is one budget for the document whatever the document's root is.
    ///
    /// The third case is a document whose root is a sequence, which is the shape a JSON array
    /// takes. The spec loader resets its budget at every item of a root sequence, because each item
    /// is a test case; a data file is one document and keeps one budget, so the chain in the first
    /// item and the aliases in the second are charged together and the second item's seventh alias
    /// crosses it.
    #[rstest::rstest]
    #[case::an_undeclared_anchor(
        "Resources: {B: {Properties: *nope}}\n".to_string(),
        &["`*nope`", "declares"]
    )]
    #[case::a_chain_past_the_budget(
        format!("{}Resources: {{B: {{Properties: {{Encrypted: true}}}}}}\n", alias_chain("")),
        &["through aliases", "`*e`", "in one document"]
    )]
    #[case::a_root_sequence_spending_one_budget(
        format!(
            "{}- [*e, *e, *e, *e, *e, *e, *e, *e, *e]\n- [*e, *e, *e, *e, *e, *e, *e, *e, *e]\n",
            alias_chain("  ").replacen("  a:", "- a:", 1).replace("  f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e, *e]\n", "")
        ),
        &["through aliases", "`*e`", "in one document"]
    )]
    fn a_yaml_template_whose_alias_cannot_be_resolved_is_refused_with_the_loaders_reason(
        #[case] input: String,
        #[case] reasons: &[&str],
    ) {
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let err = writer.err_to_stripped().expect("failed to read stderr");
        for reason in reasons {
            assert!(
                err.contains(reason),
                "the refusal must carry `{reason}`:\n{}",
                err
            );
        }
        assert!(
            !err.contains("does not support YAML aliases"),
            "the refusal is the loader's reason, not a refusal of aliases as such:\n{}",
            err
        );
    }

    /// The six-level billion-laughs chain, `a` to `f`, each line prefixed with `indent`.
    fn alias_chain(indent: &str) -> String {
        let level = |name: char, previous: char| {
            format!(
                "{indent}{name}: &{name} [{}]\n",
                std::iter::repeat(format!("*{previous}"))
                    .take(10)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let mut text = format!("{indent}a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for (name, previous) in [('b', 'a'), ('c', 'b'), ('d', 'c'), ('e', 'd'), ('f', 'e')] {
            text.push_str(&level(name, previous));
        }
        text
    }

    /// A `!!int` whose payload is not an integer is refused as a key, or as a merge source, for the
    /// reason those shapes always had, with the position and the advice.
    ///
    /// The loader marks a tagged scalar it cannot read, and the mark is not forwarded as the refusal
    /// itself when it stands where a key or a merge source should be: forwarded, `<<: !!int abc` would
    /// be refused as "in data file t.yaml: abc", with no position and no word about the merge key, and
    /// `!!int abc` as a key would lose the key refusal's position and its advice to quote the key. Only
    /// the loader's own refusals are forwarded that way; a tag payload keeps the key and merge refusals.
    #[rstest::rstest]
    #[case::a_merge_key_given_a_tagged_integer(
        "Resources:\n  B:\n    Properties:\n      <<: !!int abc\n      Encrypted: true\n",
        "the merge key `<<` at L:4,C:11 must be given a mapping"
    )]
    #[case::a_tagged_integer_as_a_key(
        "Resources:\n  B:\n    Properties:\n      !!int abc: 1\n      Encrypted: true\n",
        "L:4,C:7, where the key is an unreadable value, !!int abc. Quote it to make it a string"
    )]
    fn a_tagged_scalar_that_is_not_its_type_is_refused_as_a_key_or_merge_source(
        #[case] input: &str,
        #[case] reason: &str,
    ) {
        let mut reader = Reader::new(ReadCursor(Cursor::new(input.as_bytes().to_vec())));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["encrypted_is_true.guard"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let err = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            err.contains(reason),
            "the refusal must be the key or merge refusal, with its position:\n{}",
            err
        );
    }

    /// A failed rule whose `or` a later disjunct decided reports nothing beneath that disjunction.
    ///
    /// `Missing exists or Type == 'AWS::EC2::Instance'` fails its first disjunct on a key the instance
    /// lacks and passes on its second; the clause beside it, `InstanceType == 'no-such-type'`, fails for
    /// real. The rule's failure is that clause alone: the console summary and the `-o json` report's
    /// `not_compliant` entry list one check, the `InstanceType` comparison, and the `Missing exists` miss
    /// appears nowhere, since a disjunct a sibling decided past is no part of the rule's failure. The
    /// walker's passing-disjunction arm (`find_failing_clauses`) is what keeps it out; before it, the
    /// failed first disjunct was listed as a violation beside the real one.
    #[rstest::rstest]
    #[case::json("json")]
    #[case::console("")]
    fn a_passing_disjunction_lists_nothing_beneath_it_in_the_report(#[case] output: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = match output {
            "" => ValidateTestRunner::default()
                .data(vec!["single-map-binding-with-password-template.yaml"])
                .rules(vec!["or_decided_by_its_second_disjunct.guard"])
                .show_summary(vec!["all"])
                .run(&mut writer, &mut reader),
            _ => ValidateTestRunner::default()
                .data(vec!["single-map-binding-with-password-template.yaml"])
                .rules(vec!["or_decided_by_its_second_disjunct.guard"])
                .output_format(Some(output))
                .show_summary(vec!["none"])
                .run(&mut writer, &mut reader),
        };
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the `InstanceType` clause fails the rule"
        );
        let text = writer.stripped().expect("failed to read the writer");
        assert!(
            text.contains("InstanceType") && !text.contains("Missing"),
            "the failing clause is listed and nothing beneath the passing disjunction is:\n{}",
            text
        );
        if output == "json" {
            let report: serde_json::Value = serde_json::from_str(&text)
                .expect("the structured output must be one JSON document");
            let checks = report["not_compliant"][0]["Rule"]["checks"]
                .as_array()
                .expect("the failed rule lists its checks");
            assert_eq!(
                1,
                checks.len(),
                "one check, the failing comparison, and none for the passing `or`:\n{}",
                text
            );
        }
    }

    /// `-o json` reports a clause-level `not` on a unary clause with the polarity the clause asked for.
    ///
    /// `not Resources.b exists` against a template that defines `b` fails, and before this the structured
    /// output explained that failure as `"comparison": ["Exists", false]` with an `error_message` saying
    /// the property "did not exist" -- the opposite of what happened, and advice to add the property the
    /// rule forbids. The verdict and the exit code were right throughout; only the recorded comparison was
    /// un-negated, so every reporter that reads it printed the inverse.
    ///
    /// The operator-level spelling `Resources.b not exists` is the control: it already recorded
    /// `["Exists", true]` and said "existed", and the two spellings must now agree. Parsed rather than
    /// scanned so the assertion reads the field a machine consumer would, and because the pretty-printed
    /// array spans three lines.
    #[rstest::rstest]
    #[case::clause_level_not("clause_level_not_exists.guard")]
    #[case::operator_level_not_is_the_control("operator_level_not_exists.guard")]
    fn a_clause_level_not_on_a_unary_clause_is_reported_with_its_own_polarity(#[case] rules: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["negated-unary-clause-template.yaml"])
            .rules(vec![rules])
            .output_format(Some("json"))
            .show_summary(vec!["none"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "`b` is present, so both spellings fail; this cell is about the explanation, not the verdict"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let report: serde_json::Value =
            serde_json::from_str(&output).expect("the structured output must be one JSON document");

        let unary = &report["not_compliant"][0]["Rule"]["checks"][0]["Clause"]["Unary"];
        assert_eq!(
            serde_json::json!(["Exists", true]),
            unary["check"]["Resolved"]["comparison"],
            "{}: the comparison must carry the negation the clause as a whole applied:\n{}",
            rules,
            output
        );

        let error_message = unary["messages"]["error_message"]
            .as_str()
            .expect("a failing unary clause carries an error message");
        assert!(
            error_message.ends_with("existed."),
            "{}: the reason must say the property existed, which is why `not ... exists` failed: {}",
            rules,
            error_message
        );
    }

    /// A query the engine cannot evaluate fails the block clause it heads, with the same exit code and
    /// the same report shape as the identical query written as an access clause.
    ///
    /// `let n = parse_float(Resources.*.Properties.Name)` over `Name: fifty` cannot be resolved: the
    /// conversion refuses the string with an incompatible-type error, and a clause whose query is `%n`
    /// receives it. As an access clause, `%n > 0`, that error has always been split by role: an assertion
    /// fails closed at exit 19 and the clause record carries the reason. As a block clause, `%n { this > 0
    /// }`, the same error was recorded as a FAIL and then propagated anyway, so the run printed its report
    /// and aborted at -1 with `Error occurred ...` on stderr. Under `-o json` that line landed inside the
    /// JSON array, between the file object and the closing bracket, and the output no longer parsed. Two
    /// spellings of one clause disagreed about whether the ruleset or the tool was at fault, and library
    /// callers got `Ok` for one and `Err` for the other.
    ///
    /// The first shape this was measured with was `Tags[0][ Key == 'Name' ] { Value == 'prod' }`, a
    /// filter applied directly to an indexed value. Whether retrieval refuses that depends on the query
    /// walker: here it is refused, and the fail-closed arm answers exit 19 with the refusal recorded; a
    /// walker that evaluates a filter after an index answers exit 19 by comparison, because `Value` is
    /// `dev`. The third row asserts only what the two have in common -- exit 19, one parseable document,
    /// and no function-shape reason -- so it holds on either walker and keeps the fixture in the suite.
    /// The function shape carries the refusal assertion, because it cannot be evaluated on any walker: a
    /// string that is not a number has no float to convert to.
    ///
    /// Every row is run through `-o json`, and the output is parsed rather than scanned: the defect was
    /// precisely that a scan for the reason would have succeeded on output no consumer could load. The
    /// reason itself must survive the move into the record -- before this the block record said only
    /// "query for block clause did not retrieve any value", and the real cause appeared nowhere but the
    /// abort line.
    #[rstest::rstest]
    #[case::block_clause(
        "block_clause_unconvertible_function.guard",
        "unconvertible-name-template.yaml",
        true
    )]
    #[case::access_clause_is_the_control(
        "access_clause_unconvertible_function.guard",
        "unconvertible-name-template.yaml",
        true
    )]
    #[case::a_filter_after_an_index_never_aborts_on_any_walker(
        "block_clause_filter_after_index.guard",
        "tags-filter-after-index-template.yaml",
        false
    )]
    fn an_unevaluatable_block_clause_query_fails_the_rule_closed_instead_of_aborting(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] unevaluatable: bool,
    ) {
        const REASON: &str = "failed to convert a string: fifty into a float";

        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec![data])
            .rules(vec![rules])
            .output_format(Some("json"))
            .structured()
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{}: a failing rule, whether the query was evaluated or could not be, is exit 19 and not a \
             broken tool",
            rules
        );

        let output = writer.stripped().expect("failed to read the writer");
        let report: serde_json::Value = serde_json::from_str(&output).unwrap_or_else(|e| {
            panic!(
                "{}: structured output must be one JSON document ({}), got:\n{}",
                rules, e, output
            )
        });

        assert_eq!(
            "FAIL", report[0]["status"],
            "{}: the file verdict is a failure in every row",
            rules
        );
        assert_eq!(
            unevaluatable,
            output.contains(REASON),
            "{}: the report names the query it could not evaluate exactly when there was one:\n{}",
            rules,
            output
        );
    }

    /// A filter-ending `!empty` that fails because its selection was empty says so, with the query.
    ///
    /// `Items[ Name == 'zzz' ] !empty` over a document with no such item selects nothing, and the clause
    /// fails, which is right. The record that failure leaves carries no value and no polarity, and the
    /// summary built from it filled both in wrong: the polarity defaulted to the positive operator, so the
    /// reason read "needed value at [null] was not empty" -- the opposite of why the clause failed -- and
    /// the path slot was blank, so the line opened "Property []". The structured and CFN-aware outputs had
    /// already been corrected to say the query selected no values; the generic summary, which every
    /// document without a `Resources` root reaches, had not.
    ///
    /// That record is only ever written for the negated form over an empty selection (the positive form
    /// over nothing passes), so its polarity is known and its reason is always "was empty". The sentence
    /// now names the query as the path and the empty selection as the value. The two controls pin the
    /// neighbors that were right before and must not move: the positive `empty` over a non-empty
    /// selection still says "was not empty" with the selected value, and a scalar `!empty` over a blank
    /// string still says "was empty" with its path.
    ///
    /// The path is the query the author wrote, with its filter spelled out and its literals in the rule
    /// language, and nothing else: not the rendering of the whole clause, which would read "Property
    /// [Items. (filter-clauses) not EMPTY]", stating a second time the operator the sentence already
    /// states in "was empty", replacing the filter with a placeholder, and putting the `not` in front of
    /// the query for the `not Items[..] empty` spelling of the same clause. Both spellings print the
    /// same subject. The same record is written for a lone variable bound to an empty selection,
    /// whose subject is the variable, and for a variable-rooted query, whose subject does not show the
    /// slot the parser reserves after the variable.
    #[rstest::rstest]
    #[case::not_empty_over_an_empty_selection(
        "filter_selection_not_empty.guard",
        "needed value at [[]] was empty",
        "Property [Items[ Name EQUALS 'zzz' ]] in data"
    )]
    #[case::not_before_the_query_names_the_same_subject(
        "filter_selection_not_empty_inverse.guard",
        "needed value at [[]] was empty",
        "Property [Items[ Name EQUALS 'zzz' ]] in data"
    )]
    #[case::some_the_author_wrote_stays_in_the_subject(
        "filter_selection_not_empty_some.guard",
        "needed value at [[]] was empty",
        "Property [some Items[ Name EQUALS 'zzz' ]] in data"
    )]
    #[case::a_lone_variable_bound_to_an_empty_selection(
        "filter_selection_not_empty_variable.guard",
        "needed value at [[]] was empty",
        "Property [%v] in data"
    )]
    #[case::a_variable_rooted_query_hides_the_reserved_slot(
        "filter_selection_not_empty_variable_rooted.guard",
        "needed value at [[]] was empty",
        "Property [%items[ Name EQUALS 'zzz' ]] in data"
    )]
    #[case::positive_empty_over_a_selection_is_the_control(
        "filter_selection_empty_positive.guard",
        "was not empty",
        "Property [/Items/0]"
    )]
    #[case::scalar_not_empty_over_a_blank_is_the_control(
        "scalar_not_empty_over_blank.guard",
        "needed value at [\"\"] was empty",
        "Property [/Blank]"
    )]
    fn an_empty_selection_under_not_empty_is_reported_as_empty(
        #[case] rules: &str,
        #[case] reason: &str,
        #[case] subject: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["empty-selection-items.yaml"])
            .rules(vec![rules])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{}: every row is a failing clause; this test is about the sentence",
            rules
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert!(
            output.contains(reason),
            "{}: the reason must say why the clause failed, expected {:?} in:\n{}",
            rules,
            reason,
            output
        );
        assert!(
            output.contains(subject),
            "{}: the sentence must name what was tested, expected {:?} in:\n{}",
            rules,
            subject,
            output
        );
    }

    /// Two `!empty` clauses that filter the same collection differently get two different subjects.
    ///
    /// The subject of the "was empty" sentence is the query with its filter spelled out, so each
    /// sentence names its own predicate, and the operator appears once, in the reason, rather than once
    /// in the reason and again in the subject. The rendering of the whole clause stands in
    /// `(filter-clauses)` for every filter, so as the subject it would put
    /// `Items[ Name == 'zzz' ] !empty` and `Items[ Name == 'yyy' ] !empty` under the one subject
    /// "Property [Items. (filter-clauses) not EMPTY]", and a reader with two failing rules could not
    /// tell from the summary which filter selected nothing.
    #[test]
    fn two_filters_over_one_collection_get_their_own_subjects() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["empty-selection-items.yaml"])
            .rules(vec!["filter_selection_not_empty_two_filters.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both rules select nothing and fail; this test is about their sentences"
        );

        let output = writer.stripped().expect("failed to read the writer");
        let subjects: Vec<&str> = output
            .lines()
            .filter(|line| line.contains("needed value at [[]] was empty"))
            .map(|line| {
                let start = line
                    .find("Property [")
                    .expect("the sentence opens with its subject");
                let end = line
                    .find("] in data")
                    .expect("the subject closes before the data file");
                &line[start + "Property [".len()..end]
            })
            .collect();

        assert_eq!(
            2,
            subjects.len(),
            "one sentence per failing clause, in:\n{}",
            output
        );
        assert_ne!(
            subjects[0], subjects[1],
            "two different filters must not share a subject, in:\n{}",
            output
        );
        for (subject, predicate) in subjects.iter().zip(["zzz", "yyy"]) {
            assert!(
                subject.contains(predicate),
                "the subject {:?} must spell the filter that selected nothing ({}), in:\n{}",
                subject,
                predicate,
                output
            );
            assert!(
                !subject.contains("EMPTY"),
                "the subject {:?} must not repeat the operator the reason already states, in:\n{}",
                subject,
                output
            );
        }
    }

    /// Two filters whose literals differ only in whitespace get two different subjects.
    ///
    /// The subject spells the filter the author wrote, and a renderer that normalizes the text it
    /// prints would fold `Name == 'a  b'` and `Name == 'a b'` into one subject, which is the collision
    /// the subject exists to remove. Each sentence must carry its own literal, spaces included.
    #[test]
    fn filters_differing_only_in_literal_whitespace_get_their_own_subjects() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["empty-selection-items.yaml"])
            .rules(vec!["filter_selection_not_empty_whitespace_literals.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both rules select nothing and fail; this test is about their sentences"
        );

        let output = writer.stripped().expect("failed to read the writer");
        for subject in [
            "Property [Items[ Name EQUALS 'a  b' ]] in data",
            "Property [Items[ Name EQUALS 'a b' ]] in data",
        ] {
            assert_eq!(
                1,
                output.matches(subject).count(),
                "each filter is named once with its own literal, expected {:?} once in:\n{}",
                subject,
                output
            );
        }
    }

    /// The structured report names the query of an empty selection, not the whole clause.
    ///
    /// The generic console summary was corrected first, but the structured report (`-o json`, `-o
    /// yaml`, `--structured`, and the CloudFormation-aware console output built from the same report)
    /// builds its own sentence for this record, and it kept printing the clause's rendering, so two
    /// filters over one collection were still told apart nowhere but the summary. The sentence now
    /// says the query selected no values and spells the query, so the two rules read differently
    /// here too. The clause's own `Context=` text is unchanged and is not what these cells read.
    #[rstest::rstest]
    #[case::structured_json(
        "json",
        "filter_selection_not_empty_two_filters.guard",
        &[
            "the query [Items[ Name EQUALS 'zzz' ]] selected no values to test",
            "the query [Items[ Name EQUALS 'yyy' ]] selected no values to test",
        ]
    )]
    #[case::structured_yaml(
        "yaml",
        "filter_selection_not_empty_two_filters.guard",
        &[
            "the query [Items[ Name EQUALS 'zzz' ]] selected no values to test",
            "the query [Items[ Name EQUALS 'yyy' ]] selected no values to test",
        ]
    )]
    #[case::lone_variable_in_json(
        "json",
        "filter_selection_not_empty_variable.guard",
        &["the query [%v] selected no values to test"]
    )]
    fn the_structured_report_names_the_query_of_an_empty_selection(
        #[case] format: &str,
        #[case] rules: &str,
        #[case] sentences: &[&str],
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["empty-selection-items.yaml"])
            .rules(vec![rules])
            .structured()
            .output_format(Some(format))
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{}: every rule selects nothing and fails; this test is about the sentences",
            rules
        );

        let output = writer.stripped().expect("failed to read the writer");
        for sentence in sentences {
            assert_eq!(
                1,
                output.matches(sentence).count(),
                "each filter's sentence names its own query once, expected {:?} in:\n{}",
                sentence,
                output
            );
        }
        assert!(
            !output.contains("was not empty"),
            "an empty selection must not be reported as not empty, in:\n{}",
            output
        );
    }

    /// `--print-json` writes the empty-selection record as it always did: the custom message or null.
    ///
    /// The record gained the query it was evaluated over so the reporters can name it. That field is
    /// for the reporters; the serialized record tree keeps its wire shape, `"NoValueForEmptyCheck":
    /// null` when the clause has no message and the message string when it has one, so a consumer of
    /// `--print-json` sees the same JSON with the query carried as without it.
    #[rstest::rstest]
    #[case::without_a_message("filter_selection_not_empty.guard", "\"NoValueForEmptyCheck\": null")]
    #[case::with_a_message(
        "filter_selection_not_empty_message.guard",
        "\"NoValueForEmptyCheck\": \"no item is named zzz\""
    )]
    fn print_json_keeps_the_empty_selection_record_shape(
        #[case] rules: &str,
        #[case] record: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["empty-selection-items.yaml"])
            .rules(vec![rules])
            .show_summary(vec!["none"])
            .print_json()
            .run(&mut writer, &mut reader);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{}: the clause selects nothing and fails; this test is about the record",
            rules
        );

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            1,
            output.matches(record).count(),
            "{}: the record keeps its wire shape, expected {:?} once in:\n{}",
            rules,
            record,
            output
        );
    }

    /// Every loader-parity document gets, as a data file, exactly the verdicts its spec expects of
    /// the `test` command, rule for rule.
    ///
    /// This is one half of a three-route pin whose verdict table lives in one place: the spec's
    /// `expectations.rules`. The `test` command checks itself against that file; this test reads the
    /// same file and asserts `validate`'s per-rule summary equals it; the next test reads it again and
    /// asserts the public `run_checks`'s compliant, non-compliant and not-applicable lists equal it. A
    /// route that drifts fails against the shared table rather than against its own copy, and a one-
    /// route edit to that table fails the other two. The exit code follows the table: 19 when any rule
    /// is expected to FAIL, 0 otherwise.
    ///
    /// The shapes. Wide numeric keys: a plain key the loader will not commit to a number is looked up
    /// by its source text; three rows (BIG_FLOAT_KEY, UNDERFLOW_ZERO_KEY, HUGE_FLOAT_KEY) are
    /// controls that look the keys up by a float rendering and FAIL with or without the source-text
    /// lookup, so they guard the loader's own key handling rather than the lookup itself.
    /// Non-finite spellings: `.Inf` and the rest stay the text the document wrote. Binary literal:
    /// `0b101` is a string, `0x1F` is 31. Keys that read alike: `1` beside `"1"` resolves last-wins.
    /// Shadowed merge key: a merge source whose two keys read as one name (`1` and `"1"`) sits under an
    /// explicit `"1"`; the merged `"1"` is a silent same-key override, the merged integer `1` is a
    /// collision that `validate` reports once (and the serde conversion refuses), and the document has
    /// one reading, `explicit`, on every route. Merge collision, one source and two sources: the
    /// integer and the string collide, `validate` reports once, the value is the last (one source) or
    /// the earlier source's (two). Merge same-key override: plain under plain and quoted under quoted
    /// are the merge key's documented use, silent everywhere, and the shape carries the SKIP row.
    #[rstest::rstest]
    #[case::wide_numeric_keys("wide-numeric-keys")]
    #[case::non_finite_spellings("non-finite-spellings")]
    #[case::binary_literal("binary-literal")]
    #[case::keys_that_read_alike("keys-that-read-alike")]
    #[case::shadowed_merge_key("shadowed-merge-key")]
    #[case::merge_collision_one_source("merge-collision-one-source")]
    #[case::merge_collision_two_sources("merge-collision-two-sources")]
    #[case::merge_same_key_override("merge-same-key-override")]
    fn a_loader_parity_document_gets_the_specs_verdicts_as_a_data_file(#[case] shape: &str) {
        let spec = std::fs::read_to_string(format!(
            "resources/test-command/loader-parity/{shape}/tests.yaml"
        ))
        .expect("the spec is readable");
        let cases = crate::utils::loader_parity_spec::loader_parity_spec_cases(&spec);
        assert!(!cases.is_empty(), "{}: the spec holds no case", shape);

        let (status_code, found) = loader_parity_verdicts(
            &format!("loader-parity/{shape}.yaml"),
            &format!("loader-parity/{shape}.guard"),
        );

        for case in &cases {
            let expected = &case.expectations;
            assert_eq!(
                expected, &found,
                "{}: validate's verdicts must equal the spec's expectations",
                shape
            );
            // 19 when any rule is expected to FAIL; 0 otherwise, SKIP rows included, since a
            // skipped rule is not a violation.
            let any_fail = expected.values().any(|verdict| verdict == "FAIL");
            assert_eq!(
                if any_fail {
                    StatusCode::VALIDATION_ERROR
                } else {
                    StatusCode::SUCCESS
                },
                status_code,
                "{}: the exit code must follow the table",
                shape
            );
        }
    }

    /// Every loader-parity document gets, through the public `run_checks`, exactly the verdicts its
    /// spec expects of the `test` command: the PASS names are the report's `compliant` list, the FAIL
    /// names its `not_compliant` list, the SKIP names its `not_applicable` list, and the status follows
    /// all three -- FAIL when any rule FAILs, SKIP when every rule SKIPs, PASS otherwise.
    ///
    /// The third route of the pin whose verdict table is the spec's `expectations.rules`, read by the
    /// one parser the three routes share (`utils::loader_parity_spec`); the test above holds `validate`
    /// to the same file and describes the shapes. All three lists are read, not `compliant` alone, so a
    /// rule that moved from FAIL to SKIP cannot pass unseen. `compliant` and `not_applicable` list
    /// names; `not_compliant` lists rule reports, each `{"Rule": {"name": ...}}`. Every case of a spec
    /// is checked so a second one is not left out.
    #[rstest::rstest]
    #[case::wide_numeric_keys("wide-numeric-keys")]
    #[case::non_finite_spellings("non-finite-spellings")]
    #[case::binary_literal("binary-literal")]
    #[case::keys_that_read_alike("keys-that-read-alike")]
    #[case::shadowed_merge_key("shadowed-merge-key")]
    #[case::merge_collision_one_source("merge-collision-one-source")]
    #[case::merge_collision_two_sources("merge-collision-two-sources")]
    #[case::merge_same_key_override("merge-same-key-override")]
    fn a_loader_parity_document_gets_the_specs_verdicts_through_run_checks(#[case] shape: &str) {
        let read = |path: String| {
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} is readable: {}", path, e))
        };
        let spec = read(format!(
            "resources/test-command/loader-parity/{shape}/tests.yaml"
        ));
        let document = read(format!("resources/validate/loader-parity/{shape}.yaml"));
        let rules = read(format!("resources/validate/loader-parity/{shape}.guard"));
        let cases = crate::utils::loader_parity_spec::loader_parity_spec_cases(&spec);
        assert!(!cases.is_empty(), "{}: the spec holds no case", shape);

        let report = cfn_guard::run_checks(
            cfn_guard::ValidateInput {
                content: &document,
                file_name: "document.yaml",
            },
            cfn_guard::ValidateInput {
                content: &rules,
                file_name: "rules.guard",
            },
            false,
        )
        .unwrap_or_else(|e| panic!("{}: run_checks refused the document: {}", shape, e));
        let json: serde_json::Value =
            serde_json::from_str(&report).expect("run_checks returns a JSON document");
        let status = json["status"]
            .as_str()
            .expect("the report has a status")
            .to_string();
        let list = |key: &str| -> std::collections::BTreeSet<String> {
            json[key]
                .as_array()
                .unwrap_or_else(|| panic!("{}: the report lists `{}`", shape, key))
                .iter()
                .map(|entry| match entry {
                    serde_json::Value::String(name) => name.clone(),
                    other => other["Rule"]["name"]
                        .as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "{}: an entry of `{}` names its rule, got {}",
                                shape, key, other
                            )
                        })
                        .to_string(),
                })
                .collect()
        };
        let found = (
            list("compliant"),
            list("not_compliant"),
            list("not_applicable"),
        );

        for case in &cases {
            let expected = &case.expectations;
            let by_verdict = |verdict: &str| -> std::collections::BTreeSet<String> {
                expected
                    .iter()
                    .filter(|(_, v)| v.as_str() == verdict)
                    .map(|(rule, _)| rule.clone())
                    .collect()
            };
            assert_eq!(
                (by_verdict("PASS"), by_verdict("FAIL"), by_verdict("SKIP")),
                found,
                "{}: run_checks's three lists must equal the spec's expectations",
                shape
            );
            let expected_status = if expected.values().any(|v| v == "FAIL") {
                "FAIL"
            } else if expected.values().any(|v| v == "PASS") {
                "PASS"
            } else {
                "SKIP"
            };
            assert_eq!(
                expected_status, status,
                "{}: the status must follow the table",
                shape
            );
        }
    }

    /// Every collision in a loader-parity document is reported as a duplicate key by `validate`, the
    /// route that has a stderr, and a same-key override is reported by none.
    ///
    /// A collision is two keys that read as one name but are not the same YAML key, wherever they sit:
    /// two explicit entries (`1` beside `"1"`, two warnings for the two pairs in keys-that-read-alike),
    /// one merge source (`<<: { 1: a, "1": b }`), two sources (`<<: [{ 1: a }, { "1": b }]`), or a
    /// merged key under an explicit one (shadowed-merge-key: the integer `1` collides with the
    /// explicit `"1"`, the merged `"1"` is a same-key override, one warning). A merged plain
    /// `BucketName` under an explicit plain `BucketName` is the merge key's documented use and warns
    /// nowhere. The verdicts are pinned above against the spec's table; this pins the notice count.
    /// The `test` command prints no such warning for a spec's input, which is not pinned either way.
    #[rstest::rstest]
    #[case::keys_that_read_alike("keys-that-read-alike", 2)]
    #[case::merge_collision_one_source("merge-collision-one-source", 1)]
    #[case::merge_collision_two_sources("merge-collision-two-sources", 1)]
    #[case::shadowed_merge_key("shadowed-merge-key", 1)]
    #[case::merge_same_key_override("merge-same-key-override", 0)]
    #[case::binary_literal("binary-literal", 0)]
    fn every_collision_is_reported_once_and_an_override_never(
        #[case] shape: &str,
        #[case] expected: usize,
    ) {
        let err = loader_parity_stderr(
            &format!("loader-parity/{shape}.yaml"),
            &format!("loader-parity/{shape}.guard"),
        );
        let warnings = err
            .lines()
            .filter(|line| line.starts_with("Warning: duplicate key "))
            .count();
        assert_eq!(
            expected, warnings,
            "{}: one duplicate-key notice per collision, none for an override, got:\n{}",
            shape, err
        );
    }

    /// The two notices for the explicit pairs name the two collapsed keys.
    #[test]
    fn keys_that_read_as_one_name_are_reported_by_path() {
        let err = loader_parity_stderr(
            "loader-parity/keys-that-read-alike.yaml",
            "loader-parity/keys-that-read-alike.guard",
        );
        let warnings: Vec<&str> = err
            .lines()
            .filter(|line| line.starts_with("Warning: duplicate key "))
            .collect();
        assert!(
            warnings.len() == 2
                && warnings[0].contains("/Resources/B/Properties/Tags/1")
                && warnings[1].contains("/Resources/B/Properties/Flags/true"),
            "the warnings must name the two collapsed keys, got:\n{}",
            err
        );
    }

    /// A duplicate-key notice names both positions in document order and says which value is
    /// evaluated. For a merged key that collided with a held key the held value stands: across two
    /// sources that is the earlier source's, the *first* position, which the notice says; under an
    /// explicit key it is the explicit entry's, the last. A pair the document writes into one mapping
    /// (one source holding both spellings) keeps the sentence it always had, the control that the
    /// existing notice is unchanged. Red on the two-sources shape with the earlier mechanism, which
    /// placed the merged entry before the held one and so printed "first at L:7 ... again at L:6 ...
    /// The last value", the evaluated value being on line 6; green with the collision recorded by the
    /// loader and the record naming the evaluated position.
    #[rstest::rstest]
    #[case::across_two_sources_the_first_value_is_evaluated(
        "merge-collision-two-sources",
        "/Resources/B/Properties/1",
        "first at L:6,C:11 and again at L:7,C:11. The first value is the one evaluated."
    )]
    #[case::under_an_explicit_key_the_last_value_is_evaluated(
        "shadowed-merge-key",
        "/Resources/B/Properties/1",
        "first at L:6,C:9 and again at L:8,C:7. The last value is the one evaluated."
    )]
    #[case::inside_one_source_the_last_value_is_evaluated(
        "merge-collision-one-source",
        "/Resources/B/Properties/1",
        "first at L:6,C:9 and again at L:7,C:9. The last value is the one evaluated."
    )]
    fn a_collision_notice_names_the_positions_in_order_and_the_evaluated_value(
        #[case] shape: &str,
        #[case] path: &str,
        #[case] tail: &str,
    ) {
        let err = loader_parity_stderr(
            &format!("loader-parity/{shape}.yaml"),
            &format!("loader-parity/{shape}.guard"),
        );
        let warnings: Vec<&str> = err
            .lines()
            .filter(|line| line.starts_with("Warning: duplicate key "))
            .collect();
        assert!(
            warnings.len() == 1
                && warnings[0].starts_with(&format!("Warning: duplicate key {path} in data file "))
                && warnings[0].ends_with(tail),
            "{}: one notice, naming {} and ending {:?}, got:\n{}",
            shape,
            path,
            tail,
            err
        );
    }

    /// A collision's notice is emitted where the value lands in the final tree, by the conversion that
    /// builds it, so it carries the path the value has after every merge is applied, names the entry
    /// whose value actually stands, and is not printed at all for a subtree the merge dropped.
    ///
    /// The loader records a collision by the merging mapping's position and the held key's;
    /// `try_from_marked` emits the notice when its walk of the finished document reaches that key in
    /// that mapping. So a collision inside a merge
    /// source (`inner` under `<<`) is reported at /outer/inner/1, where the value is, and not at
    /// /outer/<</inner/1, the source's position before the merge; the same source dropped as a
    /// same-key override by an explicit `inner` is never reached and prints nothing, as a plain
    /// duplicate pair in a dropped subtree prints nothing; a `!If`-tagged sequence item and a tagged
    /// root carry their `Fn::` segment and count as one item; and when the held name is itself written
    /// twice, the notice pairs the merged key with the entry the conversion kept, the last one, so the
    /// sentence names the value evaluated. Each rules file pins the value the notice describes. Red on
    /// every row with the collision rendered from the loader's stack at the inner mapping's close
    /// (paths under `<<`, a wrapper slot counted as an item, the dropped source reported, the first
    /// held entry named); green with the notice emitted by the conversion.
    ///
    /// The notice is printed for the mapping that merged, and for a copy of it, never for another
    /// mapping that merely holds the same keys. An alias is a copy of the anchored node, positions
    /// included, so on the alias row `Base`, `X` and `Y` all hold the key `1` at the anchor's position;
    /// only `X` merged a colliding `"1"` beside it, and only /Resources/X/1 is reported. Red with the
    /// loader's record keyed by the held key's position alone, which printed three notices, for
    /// /Base/1 and /Resources/Y/1 as well, each naming a "repeated" position inside `X`; green with
    /// the merging mapping's position in the key. When the mapping that merged is itself aliased
    /// (`X: &x { <<: [...] }` then `Y: *x`) the copy carries `X`'s position too and the notice is
    /// printed once per copy, /X/1 and /Y/1, as a duplicate pair inside an aliased mapping is. A
    /// source that is itself a mapping that merged (`<<: { <<: [...] }`, anchored or not) is taken
    /// apart by the enclosing merge and never walked, so its record is carried over with its entries
    /// and printed for the enclosing mapping, /R/1, and for every mapping that merges the anchored
    /// source, /S/1; red with the record left under the source's position, which printed nothing.
    #[rstest::rstest]
    #[case::inside_a_merge_source(
        "collision-in-merge-source",
        &["duplicate key /outer/inner/1 in data file <name>, first at L:4,C:13 and again at \
          L:5,C:7. The last value is the one evaluated."]
    )]
    #[case::inside_a_dropped_merge_source("collision-in-dropped-source", &[])]
    #[case::inside_a_tagged_sequence_item(
        "collision-in-tagged-item",
        &["duplicate key /List/0/Fn::If/1/1 in data file <name>, first at L:2,C:24 and again at \
          L:2,C:32. The last value is the one evaluated."]
    )]
    #[case::inside_a_tagged_root(
        "collision-in-tagged-root",
        &["duplicate key /Fn::Foo/1 in data file <name>, first at L:2,C:7 and again at L:3,C:1. \
          The last value is the one evaluated."]
    )]
    #[case::under_a_name_written_twice(
        "collision-under-duplicated-name",
        &[
            "duplicate key /outer/1 in data file <name>, first at L:3,C:3 and again at L:4,C:3. \
             The last value is the one evaluated.",
            "duplicate key /outer/1 in data file <name>, first at L:2,C:9 and again at L:4,C:3. \
             The last value is the one evaluated."
        ]
    )]
    #[case::under_a_name_written_twice_in_an_earlier_source(
        "collision-under-duplicated-name-across-sources",
        &[
            "duplicate key /outer/1 in data file <name>, first at L:3,C:9 and again at L:3,C:15. \
             The last value is the one evaluated.",
            "duplicate key /outer/1 in data file <name>, first at L:3,C:15 and again at L:4,C:9. \
             The first value is the one evaluated."
        ]
    )]
    #[case::through_an_alias_only_the_mapping_that_merged(
        "collision-through-an-alias",
        &["duplicate key /Resources/X/1 in data file <name>, first at L:1,C:12 and again at \
          L:3,C:18. The first value is the one evaluated."]
    )]
    #[case::across_two_aliases_only_the_mapping_that_merged_both(
        "collision-across-two-aliases",
        &["duplicate key /Resources/R/8080 in data file <name>, first at L:3,C:5 and again at \
          L:5,C:5. The first value is the one evaluated."]
    )]
    #[case::inside_a_source_that_is_itself_a_merge_mapping(
        "collision-in-a-merging-source",
        &["duplicate key /R/1 in data file <name>, first at L:3,C:12 and again at L:3,C:22. \
          The first value is the one evaluated."]
    )]
    #[case::inside_an_anchored_source_that_is_itself_a_merge_mapping(
        "collision-in-an-anchored-merging-source",
        &[
            "duplicate key /R/1 in data file <name>, first at L:1,C:9 and again at L:2,C:9. \
             The first value is the one evaluated.",
            "duplicate key /S/1 in data file <name>, first at L:1,C:9 and again at L:2,C:9. \
             The first value is the one evaluated."
        ]
    )]
    #[case::an_alias_of_the_mapping_that_merged_reports_once_per_copy(
        "collision-in-an-aliased-merging-mapping",
        &[
            "duplicate key /X/1 in data file <name>, first at L:1,C:12 and again at L:2,C:19. \
             The first value is the one evaluated.",
            "duplicate key /Y/1 in data file <name>, first at L:1,C:12 and again at L:2,C:19. \
             The first value is the one evaluated."
        ]
    )]
    #[case::inside_a_merging_source_listed_beside_another(
        "collision-in-a-listed-merging-source",
        &[
            "duplicate key /C/1 in data file <name>, first at L:1,C:9 and again at L:2,C:9. \
             The first value is the one evaluated.",
            "duplicate key /R/1 in data file <name>, first at L:1,C:9 and again at L:2,C:9. \
             The first value is the one evaluated."
        ]
    )]
    #[case::a_merging_source_listed_beside_one_of_its_own_inputs_is_reported_once(
        "collision-in-a-source-listed-beside-its-input",
        &[
            "duplicate key /S/1 in data file <name>, first at L:1,C:9 and again at L:2,C:9. \
             The first value is the one evaluated.",
            "duplicate key /R/1 in data file <name>, first at L:1,C:9 and again at L:2,C:9. \
             The first value is the one evaluated."
        ]
    )]
    // A name written anchored, plain and through an alias, in each order: every notice names the lines
    // the key was written at, the alias at its own line, and ends by naming the value that stands,
    // which for the pair of entries is a third line the pair does not name. Red before: the alias's
    // write was named at the anchor's position, so the first order read "first at L:2,C:3 and again at
    // L:3,C:3. The first value is the one evaluated." (sending the reader to `&k x: 1` while 3 stood)
    // followed by "first at L:2,C:3 and again at L:2,C:3. The last value is the one evaluated.", two
    // lines that contradicted each other and neither naming line 4.
    #[case::an_alias_written_after_a_plain_spelling(
        "alias-after-plain",
        &[
            "duplicate key /b/x in data file <name>, first at L:2,C:3 and again at L:3,C:3. \
             The value written at L:4,C:3 is the one evaluated.",
            "duplicate key /b/x in data file <name>, first at L:2,C:3 and again at L:4,C:3. \
             The last value is the one evaluated."
        ]
    )]
    #[case::an_alias_written_before_a_plain_spelling(
        "alias-before-plain",
        &[
            "duplicate key /b/x in data file <name>, first at L:2,C:3 and again at L:3,C:3. \
             The value written at L:4,C:3 is the one evaluated.",
            "duplicate key /b/x in data file <name>, first at L:2,C:3 and again at L:4,C:3. \
             The last value is the one evaluated."
        ]
    )]
    #[case::a_plain_spelling_written_before_the_anchor(
        "plain-before-anchor",
        &[
            "duplicate key /b/x in data file <name>, first at L:2,C:3 and again at L:3,C:3. \
             The value written at L:4,C:3 is the one evaluated.",
            "duplicate key /b/x in data file <name>, first at L:3,C:3 and again at L:4,C:3. \
             The last value is the one evaluated."
        ]
    )]
    fn a_collision_is_reported_where_its_value_lands(
        #[case] shape: &str,
        #[case] expected: &[&str],
    ) {
        let data = format!("merge-collisions/{shape}.yaml");
        let rules = format!("merge-collisions/{shape}.guard");
        let err = loader_parity_stderr(&data, &rules);
        // The data file's name in the notice is the runner's path to it; the comparison replaces it.
        let found: Vec<String> = err
            .lines()
            .filter_map(|line| line.strip_prefix("Warning: "))
            .map(|line| {
                let (head, rest) = line
                    .split_once(" in data file ")
                    .unwrap_or_else(|| panic!("{}: a notice names its data file: {}", shape, line));
                let (_, tail) = rest
                    .split_once(", first at ")
                    .unwrap_or_else(|| panic!("{}: a notice names its positions: {}", shape, line));
                format!("{head} in data file <name>, first at {tail}")
            })
            .collect();
        assert_eq!(
            expected.to_vec(),
            found,
            "{}: the notices must be these, in this order; stderr was:\n{}",
            shape,
            err
        );

        let (status_code, verdicts) = loader_parity_verdicts(&data, &rules);
        assert!(
            status_code == StatusCode::SUCCESS && verdicts.values().all(|v| v == "PASS"),
            "{}: the rule pinning the evaluated value must PASS, got {:?} with {:?}",
            shape,
            status_code,
            verdicts
        );
    }

    fn verdicts_of(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(rule, verdict)| (rule.to_string(), verdict.to_string()))
            .collect()
    }

    /// The per-rule verdicts in a `--show-summary all` report, by rule name.
    ///
    /// A summary line is the rule's path and its verdict and nothing else, so a line of exactly two
    /// words whose second is PASS, FAIL or SKIP is one; the `Status = ...` header and the explanation
    /// block below the summary have more words and are skipped. SKIP is kept: `--show-summary all`
    /// prints the skipped rules too, and a spec that expects SKIP for a gated rule has to be able to
    /// match them, as it does on the `run_checks` route through `not_applicable`.
    fn summary_verdicts(stdout: &str) -> std::collections::BTreeMap<String, String> {
        stdout
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                let (rule, verdict) = (words.next()?, words.next()?);
                if words.next().is_some() || !matches!(verdict, "PASS" | "FAIL" | "SKIP") {
                    return None;
                }
                Some((rule.rsplit('/').next()?.to_string(), verdict.to_string()))
            })
            .collect()
    }

    /// Runs one loader-parity data file against its rules under `--show-summary all` and returns the
    /// exit code with the per-rule verdicts.
    fn loader_parity_verdicts(
        data: &str,
        rules: &str,
    ) -> (i32, std::collections::BTreeMap<String, String>) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec![data])
            .rules(vec![rules])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let out = writer.stripped().expect("failed to read stdout");
        (status_code, summary_verdicts(&out))
    }

    /// The same run, returning stderr. A second run rather than a second return value, because the
    /// writer hands back either stream, not both.
    fn loader_parity_stderr(data: &str, rules: &str) -> String {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        ValidateTestRunner::default()
            .data(vec![data])
            .rules(vec![rules])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);
        writer.err_to_stripped().expect("failed to read stderr")
    }

    /// An explicit `!!int` over a hex or octal literal loads, and the rules run.
    ///
    /// `tagged_int_octal.yaml` writes `Mode: !!int 0o755` and `mode_is_493.guard` asserts the mode is
    /// 493. The tagged arm of the loader read its payload with `str::parse::<i64>`, decimal only, so
    /// the file was refused as unreadable at exit 5 ("Bad Value encountered parsing incoming file
    /// Value = 0o755") while the untagged control `plain_int_octal.yaml` loaded as 493 and exited 0.
    /// Both now exit 0. `!!int abc` is still refused: a payload no integer form resolves is a bad
    /// value under an explicit tag.
    ///
    /// A decimal with a redundant leading zero is refused under the tag when YAML 1.1 and YAML 1.2
    /// read it as different numbers: `tagged_int_leading_zero.yaml` writes `Mode: !!int 0755`, which
    /// is octal 493 to a 1.1 reader and decimal 755 to a 1.2 reader, and exits 5 with the reason on
    /// stderr (see `a_tagged_leading_zero_integer_says_what_to_write` for the text). Where the two
    /// readings agree the integer loads: `tagged_int_leading_zero_agreeing.yaml` writes
    /// `Mode: !!int 007`, which is 7 to both, and `mode_is_7.guard` passes at exit 0. A negative
    /// payload, `Mode: !!int -0755`, is refused the same way (its stderr is checked by
    /// `a_tagged_negative_leading_zero_integer_names_the_loaders_own_spelling`). The same rule
    /// reaches mapping keys: a property key `!!int 0755` exits 5 with the key refusal and the advice
    /// to write the quoted integer meant and then drop the tag, and a property key `!!int 007` is
    /// the key `7`: `key_7_is_seven.guard` reads `Resources.F.Properties."7"` and asserts its value,
    /// so the case passes only if the key loaded as the integer 7's text, not as "007" or anything
    /// else that does not refuse.
    #[rstest::rstest]
    #[case::tagged_octal("tagged_int_octal.yaml", "mode_is_493.guard", StatusCode::SUCCESS)]
    #[case::tagged_hex("tagged_int_hex.yaml", "mode_is_493.guard", StatusCode::SUCCESS)]
    #[case::tagged_word("tagged_int_word.yaml", "mode_is_493.guard", StatusCode::PARSING_ERROR)]
    #[case::tagged_leading_zero(
        "tagged_int_leading_zero.yaml",
        "mode_is_493.guard",
        StatusCode::PARSING_ERROR
    )]
    #[case::tagged_leading_zero_both_readers_agree_on(
        "tagged_int_leading_zero_agreeing.yaml",
        "mode_is_7.guard",
        StatusCode::SUCCESS
    )]
    #[case::tagged_negative_leading_zero(
        "tagged_int_negative_leading_zero.yaml",
        "mode_is_493.guard",
        StatusCode::PARSING_ERROR
    )]
    #[case::tagged_leading_zero_as_a_key(
        "tagged_int_leading_zero_key.yaml",
        "mode_is_7.guard",
        StatusCode::PARSING_ERROR
    )]
    #[case::tagged_leading_zero_key_both_readers_agree_on(
        "tagged_int_agreeing_key.yaml",
        "key_7_is_seven.guard",
        StatusCode::SUCCESS
    )]
    #[case::untagged_octal_control(
        "plain_int_octal.yaml",
        "mode_is_493.guard",
        StatusCode::SUCCESS
    )]
    fn an_explicitly_tagged_integer_in_a_radix_form_loads(
        #[case] data: &str,
        #[case] rules: &str,
        #[case] expected: i32,
    ) {
        let data = format!("/tagged-scalars/{data}");
        let rules = format!("/tagged-scalars/{rules}");
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec![&data])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{data}");
    }

    /// The refusal of `Mode: !!int 0755` says why the digits were not read and what to write.
    ///
    /// The error names the node as written and its position, then the two readings and the
    /// plain-decimal integer each one means: 493 if the octal was meant, 755 if the decimal was.
    /// The octal reading is offered as 493, not as `0o755`, because a YAML 1.1 reader, which is what
    /// CloudFormation is, has no `0o` form and reads `0o755` as a string; `0o755` is named only as
    /// this loader's own spelling. Before the reason existed, the error carried the node text and
    /// its position alone, with no account of why a string of digits was not an integer.
    #[test]
    fn a_tagged_leading_zero_integer_says_what_to_write() {
        let err = loader_parity_stderr(
            "/tagged-scalars/tagged_int_leading_zero.yaml",
            "/tagged-scalars/mode_is_493.guard",
        );

        for expected in [
            "Value = !!int 0755, Loc = L:4,C:13",
            "a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2",
            "write 493 if octal 755 was meant, or 755 if decimal was meant",
        ] {
            assert!(
                err.contains(expected),
                "stderr does not say {:?}:\n{}",
                expected,
                err
            );
        }
    }

    /// The refusal of `Mode: !!int -0755` keeps the sign in both integers and names no `0o` spelling.
    ///
    /// The integers offered are plain decimals, -493 and -755; the `0o` form is never named, signed
    /// or not, because a YAML 1.1 reader has no such form and reads it as a string, which is the
    /// divergence the refusal exists to prevent.
    #[test]
    fn a_tagged_negative_leading_zero_integer_keeps_the_sign_and_names_no_octal_spelling() {
        let err = loader_parity_stderr(
            "/tagged-scalars/tagged_int_negative_leading_zero.yaml",
            "/tagged-scalars/mode_is_493.guard",
        );

        for expected in [
            "Value = !!int -0755, Loc = L:4,C:13",
            "write -493 if octal -755 was meant, or -755 if decimal was meant",
        ] {
            assert!(
                err.contains(expected),
                "stderr does not say {:?}:\n{}",
                expected,
                err
            );
        }
        assert!(
            !err.contains("0o"),
            "no `0o` spelling may be offered or named:\n{}",
            err
        );
    }

    /// A property key `!!int 0755` is refused with the key's own advice: write the integer that was
    /// meant as a quoted string, after which the tag can be dropped. "Quote it to make it a string",
    /// the advice for every other unreadable key, does not fix this one: the quoted payload is
    /// refused the same way, and quoting the whole key gives a text neither YAML version would make
    /// of it; nor does dropping the tag alone, since an untagged `0755` is kept as that string. The
    /// integers are quoted because a key is text, which is also what the refusal's own wrapper says.
    #[test]
    fn a_tagged_leading_zero_integer_key_is_refused_with_the_key_advice() {
        let err = loader_parity_stderr(
            "/tagged-scalars/tagged_int_leading_zero_key.yaml",
            "/tagged-scalars/mode_is_7.guard",
        );

        for expected in [
            "L:4,C:7, where the key is an unreadable value, !!int 0755: a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2",
            "Write \"493\" if octal 755 was meant, or \"755\" if decimal was meant; the tag can then be dropped",
        ] {
            assert!(
                err.contains(expected),
                "stderr does not say {:?}:\n{}",
                expected,
                err
            );
        }
        assert!(
            !err.contains("Quote it to make it a string"),
            "the quoting advice does not fit a tagged key:\n{}",
            err
        );
    }

    /// An explicit `!!float` that is not a finite float is refused at load, with exit 5.
    ///
    /// `tagged_float_nan.yaml` writes `Ratio: !!float nan` and `ratio_is_not_one.guard` asserts
    /// `Ratio != 1.0`. The tagged arm of the loader took `str::parse::<f64>`'s answer unchecked, so
    /// the run built a `Float(NaN)`, printed "Status = FAIL" and then exited 255 when the reporter
    /// could not convert the NaN to a serde number. `!!float inf` went the other way and PASSed at
    /// exit 0. `tagged_float_underflow.yaml` writes `Threshold: !!float 1e-400`, which parsed to a
    /// silent `0.0` and PASSed `threshold_is_zero.guard` for a literal the author wrote as positive.
    /// All three are now refused as bad values, exit 5. The controls do not move: a tagged `1.5`
    /// PASSes, and the untagged `nan` and `1e-400` stay strings that fail their clauses at 19.
    #[rstest::rstest]
    #[case::tagged_nan(
        "ratio_is_not_one.guard",
        "tagged_float_nan.yaml",
        StatusCode::PARSING_ERROR
    )]
    #[case::tagged_inf(
        "ratio_is_not_one.guard",
        "tagged_float_inf.yaml",
        StatusCode::PARSING_ERROR
    )]
    #[case::tagged_underflow(
        "threshold_is_zero.guard",
        "tagged_float_underflow.yaml",
        StatusCode::PARSING_ERROR
    )]
    #[case::tagged_ordinary_control(
        "ratio_is_not_one.guard",
        "tagged_float_ordinary.yaml",
        StatusCode::SUCCESS
    )]
    #[case::untagged_nan_control(
        "ratio_is_not_one.guard",
        "plain_float_nan.yaml",
        StatusCode::VALIDATION_ERROR
    )]
    #[case::untagged_underflow_control(
        "threshold_is_zero.guard",
        "plain_float_underflow.yaml",
        StatusCode::VALIDATION_ERROR
    )]
    fn an_explicitly_tagged_float_that_is_not_finite_is_refused(
        #[case] rules: &str,
        #[case] data: &str,
        #[case] expected: i32,
    ) {
        let rules = format!("/tagged-scalars/{rules}");
        let data = format!("/tagged-scalars/{data}");
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec![&data])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{rules} against {data}");
    }

    /// An explicit `!!null` over something that is not a null spelling is refused, exit 5.
    ///
    /// `tagged_null_false.yaml` writes `IsLogging: !!null false` and `is_logging_is_false.guard`
    /// asserts `IsLogging == false`. The loader's `!!null` arm returned a null without reading the
    /// payload, so the `false` vanished and the clause failed at exit 19 with "not comparable null,
    /// bool", where the untagged `false` in `plain_false.yaml` compares and exits 0. The payload is
    /// now a bad value, exit 5. `!!null null` is still a null and still fails the same clause at 19,
    /// which is the control that the tag itself keeps working.
    #[rstest::rstest]
    #[case::tagged_false("tagged_null_false.yaml", StatusCode::PARSING_ERROR)]
    #[case::tagged_null_word_control("tagged_null_word.yaml", StatusCode::VALIDATION_ERROR)]
    #[case::untagged_false_control("plain_false.yaml", StatusCode::SUCCESS)]
    fn an_explicit_null_tag_over_a_non_null_payload_is_refused(
        #[case] data: &str,
        #[case] expected: i32,
    ) {
        let data = format!("/tagged-scalars/{data}");
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/tagged-scalars/is_logging_is_false.guard"])
            .data(vec![&data])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{data}");
    }

    /// A `!!` type tag the loader does not know is refused, exit 5, instead of being dropped.
    ///
    /// `double_bang_ref.yaml` writes `RoleName: !!Ref Foo`, a typo of `!Ref Foo`, and
    /// `rolename_is_foo.guard` asserts `RoleName == "Foo"`. The loader's fallthrough for an
    /// unrecognized `tag:yaml.org,2002:*` tag kept the payload as a plain string, so the rule PASSed
    /// at exit 0 and nothing named the tag. The same typo on a sequence, `RoleName: !!If [IsProd,
    /// Foo, Bar]` in `double_bang_if_sequence.yaml`, dropped the tag and loaded a bare list; it is
    /// refused at 5 too, with the tag and position in the message. The control `single_bang_ref.yaml`
    /// keeps `!Ref Foo` as `{"Ref": "Foo"}` and fails the same rule at 19, and `tagged_str_word.yaml`'s
    /// `!!str Foo` is a string and PASSes, because `!!str` is a type the loader knows. A tag from
    /// another dialect's namespace, `!!python/str Foo` in `foreign_namespace_tag.yaml`, is not a typo
    /// of an intrinsic and loads as the text "Foo" with a warning on stderr, so a directory walk is
    /// not stopped by a file cfn-guard was never meant to read.
    #[rstest::rstest]
    #[case::unknown_type_tag("double_bang_ref.yaml", StatusCode::PARSING_ERROR)]
    #[case::unknown_type_tag_on_a_sequence(
        "double_bang_if_sequence.yaml",
        StatusCode::PARSING_ERROR
    )]
    #[case::function_tag_control("single_bang_ref.yaml", StatusCode::VALIDATION_ERROR)]
    #[case::str_tag_control("tagged_str_word.yaml", StatusCode::SUCCESS)]
    #[case::foreign_namespace_loads_as_text("foreign_namespace_tag.yaml", StatusCode::SUCCESS)]
    fn an_unknown_type_tag_is_refused_not_dropped(#[case] data: &str, #[case] expected: i32) {
        let data = format!("/tagged-scalars/{data}");
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/tagged-scalars/rolename_is_foo.guard"])
            .data(vec![&data])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{data}");
    }

    /// A `!!` tag the loader reads past is reported on the command's stderr, one line per node.
    ///
    /// `three_foreign_tags.yaml` carries `!!python/str` on a scalar (L:1,C:4), `!!python/list` on a
    /// sequence (L:3,C:3) and `!!python/str` on a sequence item (L:4,C:5). None spells an intrinsic,
    /// so the document loads as if untagged and `a_is_a_string.guard` PASSes at exit 0. The warnings
    /// travel in the loader's result and are written through the writer beside the duplicate-key
    /// lines, which is what `err_to_stripped` reads; the loader itself writes nothing to stderr. Three
    /// lines, in document order, each with its own position, so a reader of a file tagged throughout
    /// knows which nodes were touched.
    #[test]
    fn a_tag_read_past_is_warned_about_once_per_node_through_the_writer() {
        let mut reader = Reader::default();
        let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
            .expect("a writer with both channels buffered");

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/tagged-scalars/a_is_a_string.guard"])
            .data(vec!["/tagged-scalars/three_foreign_tags.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);
        assert_eq!(StatusCode::SUCCESS, status_code);

        let stderr = writer.err_to_stripped().expect("the writer's stderr");
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|line| line.starts_with("Warning: cfn-guard does not read the YAML tag"))
            .collect();
        let expected = [
            ("`!!python/str` at L:1,C:4", 0),
            ("`!!python/list` at L:3,C:3", 1),
            ("`!!python/str` at L:4,C:5", 2),
        ];
        assert_eq!(
            expected.len(),
            warnings.len(),
            "one warning per tagged node, got:\n{stderr}"
        );
        for (needle, index) in expected {
            assert!(
                warnings[index].contains(needle)
                    && warnings[index].contains("three_foreign_tags.yaml")
                    && warnings[index].ends_with("the node is read as if it had no tag."),
                "line {index} should name {needle} and the file:\n{}",
                warnings[index]
            );
        }
    }

    /// An explicit `!!merge` over `<<` merges, as the plain `<<` does.
    ///
    /// `tagged_merge_key.yaml` writes `!!merge <<: { Type: AWS::S3::Bucket }` inside a resource and
    /// `bucket_type_is_s3.guard` asserts the merged `Type`. The merge index was decided on the
    /// absence of a tag, so the tagged key stayed a literal `<<` and the rule FAILed at 19 with `Type`
    /// unreachable; it now PASSes.
    #[test]
    fn an_explicit_merge_tag_merges_like_a_plain_merge_key() {
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec!["/tagged-scalars/bucket_type_is_s3.guard"])
            .data(vec!["/tagged-scalars/tagged_merge_key.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
    }

    /// A mixed-case `nUlL` is a string, and the four core-schema spellings are still null.
    ///
    /// `null_casings.yaml` writes `A: nUlL` and `B: NuLL` beside `null`, `Null`, `NULL` and `~`. The
    /// loader lowercased a plain scalar before matching it against the null set, so A and B were
    /// null and `mixed_case_null_is_a_string.guard` failed at 19 with "needed value at [null] was
    /// not a string". YAML 1.2 core resolves only the four exact spellings, which is what the control
    /// `core_schema_nulls_are_null.guard` asserts and what `serde_yaml` gave on the same bytes.
    #[rstest::rstest]
    #[case::mixed_case_is_a_string("mixed_case_null_is_a_string.guard", StatusCode::SUCCESS)]
    #[case::core_spellings_control("core_schema_nulls_are_null.guard", StatusCode::SUCCESS)]
    fn a_plain_null_is_resolved_by_exact_case(#[case] rules: &str, #[case] expected: i32) {
        let rules = format!("/tagged-scalars/{rules}");
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec!["/tagged-scalars/null_casings.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{rules}");
    }

    /// The payload of a `!Ref` is the text the document wrote, whatever it spells.
    ///
    /// `ref_payloads.yaml` writes `P: !Ref 123`, `Q: !Ref` and `S: !Ref Foo`.
    /// `ref_payloads_are_text.guard` asserts `P.Ref` is the string "123" and `Q.Ref` the empty
    /// string, and `ref_word_is_string.guard` that `S.Ref` is "Foo". A specifically tagged node is
    /// not implicitly resolved, so all three hold; a reading that typed the payloads Int and Null
    /// was tried and withdrawn, and these rows pin the text.
    #[rstest::rstest]
    #[case::number_and_empty_payloads("ref_payloads_are_text.guard", StatusCode::SUCCESS)]
    #[case::word_payload("ref_word_is_string.guard", StatusCode::SUCCESS)]
    fn a_tagged_scalar_payload_keeps_its_text(#[case] rules: &str, #[case] expected: i32) {
        let rules = format!("/tagged-scalars/{rules}");
        let mut reader = Reader::default();
        let mut writer = Writer::default();

        let status_code = ValidateTestRunner::default()
            .rules(vec![&rules])
            .data(vec!["/tagged-scalars/ref_payloads.yaml"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        assert_eq!(expected, status_code, "{rules}");
    }

    /// A query argument to a function inside a map key filter is relative to the map being filtered,
    /// as the filter's access-clause right-hand side is.
    ///
    /// `Map[ keys == Wanted ]` read `Wanted` from the map in hand. `Map[ keys == to_lower(Wanted) ]`
    /// handed the function the enclosing resolver, whose queries start at the document root, so the
    /// same name was looked up at the top of the document instead: with no root `Wanted` the filter
    /// selected nothing and the rule was reported not applicable at exit 0, and with an unrelated
    /// top-level `Wanted: beta` it selected `beta`, a key the map-relative spelling never named, and
    /// failed at exit 19. A literal argument behaved the same either way, which is what hid it.
    #[rstest::rstest]
    #[case::no_root_wanted("captures/key-filter-function-argument-template.yaml")]
    #[case::unrelated_root_wanted(
        "captures/key-filter-function-argument-root-wanted-template.yaml"
    )]
    fn a_function_argument_in_a_key_filter_is_relative_to_the_filtered_map(#[case] data: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec![data])
            .rules(vec!["captures/key_filter_function_argument.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "every rule selects `alpha` and compares its value 1, so the file is compliant:\n{}",
            output
        );
        for rule in [
            "plain_key",
            "func_key",
            "func_key_literal_control",
            "plain_value_control",
        ] {
            assert_eq!(
                Some("PASS".to_string()),
                rule_status_line(&output, rule),
                "{} passes; `func_key` skipped when `Wanted` was read from the root and failed when \
                 the root had an unrelated `Wanted`:\n{}",
                rule,
                output
            );
        }
    }

    /// The two kinds of notice the evaluator writes to stderr, read apart: the deprecations (a reading
    /// kept for one more release) and the warnings (a reading that already moved). The evaluator keeps
    /// them in two sets; on stderr each kind opens with its own marker, which is how this side of the
    /// process tells them apart. A test that asserts "no notice" reads both.
    #[derive(Debug, Default)]
    struct Notices {
        deprecations: Vec<String>,
        warnings: Vec<String>,
    }

    impl Notices {
        fn is_empty(&self) -> bool {
            self.deprecations.is_empty() && self.warnings.is_empty()
        }
    }

    /// Run `rules` over `data` once and return the exit code, the report and the notices on stderr.
    /// Both streams come from the one run, each written to a file and read back through a `Writer` of
    /// its own (`capture_both_streams`), since nothing public returns the pair at once.
    fn run_with_notices(data: &str, rules: &str) -> (i32, String, Notices) {
        run_with_notices_over(vec![data], rules)
    }

    const ROOT: &str = "the enclosing scope (the document root)";
    const RESOURCE: &str = "the enclosing scope (the value at /Resources/Cfg[";

    /// `run_with_notices` over several data files in one run, in the order given: the single-line
    /// output writes each file's report and its new notices as it goes, so the notices come back in
    /// the order the files were read.
    fn run_with_notices_over(data: Vec<&str>, rules: &str) -> (i32, String, Notices) {
        let (status_code, output, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(data.clone())
                .rules(vec![rules])
                .show_summary(vec!["all"])
                .run(writer, reader)
        });
        let mut notices = Notices::default();
        for line in stderr.lines() {
            if line.starts_with("DEPRECATION:") {
                notices.deprecations.push(line.to_string());
            } else if line.starts_with("Warning:") {
                notices.warnings.push(line.to_string());
            }
        }
        (status_code, output, notices)
    }

    /// A query argument the filtered map does not hold is read from the enclosing scope instead, and
    /// reading it from the resource is not deprecated.
    ///
    /// Map-relative first, then the scope the filter was reached in: for a filter on a member of a
    /// wildcard or a block clause's value that scope is the resource, so `Properties.Env` beside the
    /// `Mappings` being filtered resolves in both spellings. With arguments strictly map-relative both
    /// rules selected nothing and skipped at exit 0. The resource-level read is the documented
    /// behavior, not the older root-relative one, so it prints no notice; a version of the fallback
    /// that printed one on every read outside the map printed one here.
    #[test]
    fn a_key_filter_argument_the_map_lacks_is_read_from_the_enclosing_scope() {
        let (status_code, output, notices) = run_with_notices(
            "captures/env-mappings-template.yaml",
            "captures/key_filter_function_argument_in_a_wildcard.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        for rule in ["flat", "block"] {
            assert_eq!(
                Some("PASS".to_string()),
                rule_status_line(&output, rule),
                "{} selects `ALPHA` through the resource's `Env`; SKIP is the argument unresolved \
                 against the map alone:\n{}",
                rule,
                output
            );
        }
        assert!(
            notices.is_empty(),
            "reading the argument from the resource is the documented behavior and gets no notice, \
             got {:?}",
            notices
        );
    }

    /// The fallback reaches the document root and says so once on stderr, naming the call's location.
    ///
    /// The notice is on the document-root fallback only: an argument the map holds, or the resource
    /// beside it holds, is the documented reading and gets no notice. Asserted together with the
    /// verdict, because a notice that moves a verdict is not a notice. The location is part of the
    /// notice because notices are collected in a set: two calls with the same argument text would
    /// otherwise print once, and a reader could not tell which clause each was about.
    #[test]
    fn a_key_filter_argument_read_from_the_root_is_a_deprecation_notice() {
        let (status_code, output, notices) = run_with_notices(
            "captures/root-only-wanted-template.yaml",
            "captures/key_filter_root_only_argument.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "func_key"),
            "the root's `Wanted` is read when the map has none:\n{}",
            output
        );
        assert_eq!(
            1,
            notices.deprecations.len(),
            "one notice for the one argument read from the document root, got {:?}",
            notices
        );
        assert!(
            notices.warnings.is_empty(),
            "the fallback is a deprecation, not a warning: nothing was replaced, got {:?}",
            notices
        );
        let notice = &notices.deprecations[0];
        assert!(
            notice.contains("Wanted") && notice.contains("map being filtered"),
            "the notice names the argument and says where it was looked for first: {}",
            notice
        );
        assert!(
            notice.contains("Location[file:")
                && notice.contains("key_filter_root_only_argument.guard"),
            "the notice names the location of the call it is about: {}",
            notice
        );
    }

    /// When the map's value wins over a value in the enclosing scope that would have resolved
    /// differently, stderr says so: the reading moved, and the clause's verdict may have moved with it.
    ///
    /// `Map[ keys == to_lower(Wanted) ]` reads `Wanted` from the map. The other reading is the enclosing
    /// scope's: the document root for a filter written at the file's root, the resource beside the map
    /// under a wildcard or inside a block clause. With `Wanted: beta` there and `Wanted: alpha` in the
    /// map the filter selects `alpha`, where the enclosing scope's reading selects `beta`, so the two
    /// readings give the rule PASS and exit 19. The kept-reading notice fires when the map lacks the key
    /// and the root supplies it, and is silent here, where the map's own entry replaces the enclosing
    /// scope's: without this warning a rule written against that read that shares a key name with the
    /// map would change verdict with nothing on stderr. (The
    /// map-holds, scope-lacks case moved too, from SKIP to a verdict, and stays silent by design: it is
    /// the ordinary use of a map-relative argument, and a warning there would fire on every correct
    /// rule.) The notice is a warning, not a deprecation, because the move has already happened. It
    /// names the argument, the map's position, the enclosing scope's value and its position, the data
    /// file and the call, and says the verdict MAY have changed: only the argument's leading path of
    /// keys and indices is compared, in order and before the function runs, so `to_lower` can agree on
    /// values that differ only in case and a filter inside the argument can select the same members
    /// from different lists. Compared in order because `join` depends on it: `[a, b]` and `[b, a]`
    /// select different keys, so a reordered list warns, as does a scalar against a one-element list.
    /// Equal values get no warning. `this.Wanted` is the map-relative reading spelled out, and a
    /// `this` read as the enclosing scope is the other reading the warning exists for, so it is
    /// compared like every other argument and warns when the two readings differ. A filter-bearing
    /// argument gets one on its leading path (`Wanted`), read once more as a pure lookup that
    /// evaluates no filter.
    ///
    /// The warning names the argument as the author wrote it (`this.Wanted`, `Wanted[ w ]`, `Wanted[
    /// Use == true ].Name`), not as the record tree renders a query (`_.Wanted`, `Wanted[*]`, `Wanted.
    /// (filter-clauses).Name`), because its reader has to find the argument in their own file.
    ///
    /// A variable-rooted spelling warns where its reading moved and is silent where it did not, by the
    /// same comparison. `%resource.Map[ keys == to_lower(Wanted) ]` over `let resource = Resources.*`
    /// read the resource's `Wanted` before and reads the map's now, and warns, naming the resource as
    /// the enclosing scope. `%map[ keys == to_lower(Wanted) ]` over `let map = Resources.Cfg.Map` read
    /// the map's `Wanted` all along: a query rooted at a variable runs over the bound value, which is
    /// the map itself here, so the argument never read the document root and nothing moved. With
    /// arguments read from the enclosing scope instead, the bound-map spelling passes as it does
    /// map-relative, and the resource-bound one fails where it now passes.
    ///
    /// `ROOT` and `RESOURCE` are how the warning names the enclosing scope of a filter written at the
    /// file's root, and of one reached through the resource (a wildcard, a block clause, a variable
    /// bound to the resources): the scope the previous release read the argument from, which is the
    /// part of the line a reader acts on, so each row says which it expects rather than only that some
    /// scope is named.
    #[rstest::rstest]
    #[case::root_value_differs(
        "captures/key-filter-function-argument-root-wanted-template.yaml",
        "captures/key_filter_function_argument.guard",
        "func_key",
        "Wanted",
        ROOT,
        1
    )]
    #[case::resource_value_differs_under_a_wildcard(
        "captures/key-filter-function-argument-resource-wanted-template.yaml",
        "captures/key_filter_function_argument_wildcard.guard",
        "func_key_wildcard",
        "Wanted",
        RESOURCE,
        1
    )]
    #[case::resource_value_differs_in_a_block_clause(
        "captures/key-filter-function-argument-resource-wanted-template.yaml",
        "captures/key_filter_function_argument_block.guard",
        "func_key_block",
        "Wanted",
        RESOURCE,
        1
    )]
    #[case::root_value_is_the_same(
        "captures/key-filter-function-argument-same-root-wanted-template.yaml",
        "captures/key_filter_function_argument.guard",
        "func_key",
        "Wanted",
        ROOT,
        0
    )]
    #[case::root_list_in_another_order_warns(
        "captures/key-filter-function-argument-list-same-set-template.yaml",
        "captures/key_filter_function_argument_list.guard",
        "func_key_list",
        "Wanted[*]",
        ROOT,
        1
    )]
    #[case::root_list_differs(
        "captures/key-filter-function-argument-list-differs-template.yaml",
        "captures/key_filter_function_argument_list.guard",
        "func_key_list",
        "Wanted[*]",
        ROOT,
        1
    )]
    #[case::join_over_a_reordered_list_warns(
        "captures/key-filter-function-argument-join-template.yaml",
        "captures/key_filter_function_argument_join.guard",
        "func_key_join",
        "Parts[*]",
        ROOT,
        1
    )]
    #[case::scalar_against_a_one_element_list_warns(
        "captures/key-filter-function-argument-scalar-vs-list-template.yaml",
        "captures/key_filter_function_argument.guard",
        "func_key",
        "Wanted",
        ROOT,
        1
    )]
    #[case::this_prefix_at_the_root_moved_from_the_root_to_the_map(
        "captures/key-filter-function-argument-root-wanted-template.yaml",
        "captures/key_filter_function_argument_this.guard",
        "func_key_this",
        "this.Wanted",
        ROOT,
        1
    )]
    #[case::this_prefix_in_a_block_clause_moved_from_the_resource_to_the_map(
        "captures/key-filter-function-argument-resource-wanted-template.yaml",
        "captures/key_filter_function_argument_this_block.guard",
        "func_key_this_block",
        "this.Wanted",
        RESOURCE,
        1
    )]
    #[case::filter_in_the_argument_is_read_once_and_warned_once(
        "captures/key-filter-function-argument-filtered-template.yaml",
        "captures/key_filter_function_argument_filtered.guard",
        "func_key_filtered",
        "Wanted[ Use == true ].Name",
        ROOT,
        1
    )]
    #[case::variable_rooted_at_the_resource_moved_from_the_resource_to_the_map(
        "captures/key-filter-function-argument-resource-wanted-template.yaml",
        "captures/key_filter_function_argument_variable_resource.guard",
        "func_key_variable_resource",
        "Wanted",
        RESOURCE,
        1
    )]
    #[case::variable_bound_to_the_map_itself_moved_nothing(
        "captures/key-filter-function-argument-root-wanted-template.yaml",
        "captures/key_filter_function_argument_bound_map.guard",
        "func_key_bound_map",
        "Wanted",
        ROOT,
        0
    )]
    fn a_key_filter_argument_the_map_takes_over_from_the_root_is_a_warning(
        #[case] data: &str,
        #[case] rules: &str,
        #[case] rule: &str,
        #[case] argument: &str,
        #[case] scope: &str,
        #[case] expected_warnings: usize,
    ) {
        let (status_code, output, notices) = run_with_notices(data, rules);
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, rule),
            "{} reads the map's own value, whatever the enclosing scope holds:\n{}",
            rule,
            output
        );
        assert!(
            notices.deprecations.is_empty(),
            "the map answered, so nothing fell back and no deprecation, got {:?}",
            notices
        );
        assert_eq!(
            expected_warnings,
            notices.warnings.len(),
            "one warning when the enclosing scope's value differs from the map's, none otherwise, got \
             {:?}",
            notices
        );
        if expected_warnings == 1 {
            let warning = &notices.warnings[0];
            let data_file = data.rsplit('/').next().expect("a file name");
            assert!(
                warning.starts_with("Warning:")
                    && warning.contains(&format!(
                        "the function argument `{argument}` in a map key filter"
                    ))
                    && warning.contains("/Resources/Cfg/Map[")
                    && warning.contains("the enclosing scope")
                    && warning.contains("in data file ")
                    && warning.contains(&format!("{data_file},")),
                "the warning names the argument, the map's position, the enclosing scope's value and \
                 its position, and the data file (the path the command was given, as the \
                 duplicate-key warning names it): {}",
                warning
            );
            assert!(
                warning.contains("may change verdict"),
                "the warning says the verdict MAY have changed, not that it did: {}",
                warning
            );
            assert!(
                warning.contains(scope),
                "the warning names the scope the previous release read the argument from, {}: {}",
                scope,
                warning
            );
            assert!(
                warning.contains("Location[file:") && warning.contains(&rules[9..]),
                "the warning names the location of the call it is about: {}",
                warning
            );
        }
    }

    /// A named wildcard in the argument binds the map's elements only: the comparison against the
    /// enclosing scope never walks one.
    ///
    /// `Wanted[ w ]` binds every element the read walks to `%w`. The first version of the warning's
    /// comparison read the whole argument from the root as well, so under a document-rooted `when` the
    /// root's `Wanted: [beta]` was pushed into `%w` beside the map's `alpha` and `%w == 'alpha'` failed
    /// at exit 19 on a value the map never held. The comparison now reads only the argument's leading
    /// keys and indices (`Wanted`), a lookup that binds nothing, so `%w` is the map's and the warning
    /// still names the moved reading.
    #[test]
    fn a_named_wildcard_in_a_key_filter_argument_binds_only_the_maps_elements() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-named-wildcard-template.yaml",
            "captures/key_filter_function_argument_named_wildcard.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "capture_is_the_maps"),
            "`%w` holds the map's `alpha` only; FAIL is the root's `beta` read into it:\n{}",
            output
        );
        assert_eq!(
            1,
            notices.warnings.len(),
            "the leading `Wanted` differs between the map and the root, so the move is named once, \
             without walking the wildcard: {:?}",
            notices
        );
        assert!(
            notices.warnings[0].contains("the function argument `Wanted[ w ]` in a map key filter")
                && notices.deprecations.is_empty(),
            "the warning names the argument as written, capture and all, and nothing fell back: {:?}",
            notices
        );
    }

    /// `this.` keeps the read in the map when the map lacks the key: the argument is unresolved, so the
    /// filter fails closed with no fallback, and the warning names the reading that moved.
    ///
    /// `this` is not new syntax. Before map-relative arguments, `this.Wanted` inside a key filter's
    /// function read the enclosing scope's `Wanted`, the document root's here. An early version of the
    /// map-relative spelling fell back when the map lacked the key, so the author got the root's value
    /// anyway plus a deprecation telling them to use `%name` instead of the spelling they had just been
    /// told to use. `this` now means this map, and an argument the map does not hold is unresolved: the
    /// key filter's right-hand side cannot be read, so the keys it selects cannot be decided and the
    /// filter fails closed, the rule FAIL at the validation failure code rather than selecting nothing
    /// and reporting not applicable. Because the enclosing scope's `Wanted: alpha` would have resolved
    /// where the map's resolves to nothing, the move is still a warning, not silence: one warning naming
    /// both readings, no deprecation.
    #[test]
    fn a_this_prefixed_key_filter_argument_stays_in_the_map_when_the_map_lacks_the_key() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-this-root-only-template.yaml",
            "captures/key_filter_function_argument_this.guard",
        );
        assert_eq!(StatusCode::VALIDATION_ERROR, status_code, "{}", output);
        assert_eq!(
            Some("FAIL".to_string()),
            rule_status_line(&output, "func_key_this"),
            "the map has no `Wanted`, so `this.Wanted` is an unresolved right-hand side and the filter \
             fails closed; PASS would be the root's `Wanted` read through a fallback, SKIP a filter that \
             selected nothing and said so to nobody:\n{}",
            output
        );
        assert!(
            notices.deprecations.is_empty(),
            "nothing fell back to the root, so no deprecation, got {:?}",
            notices
        );
        assert_eq!(
            1,
            notices.warnings.len(),
            "the map resolves nothing where the root has a value, so the moved reading is named, got \
             {:?}",
            notices
        );
        assert!(
            notices.warnings[0].contains("the function argument `this.Wanted` in a map key filter")
                && notices.warnings[0].contains("resolves to nothing")
                && notices.warnings[0].contains("the enclosing scope")
                && notices.warnings[0].contains("/Wanted["),
            "the warning names the argument as written and both readings: the map's, which resolves \
             to nothing, and the enclosing scope's value and position: {}",
            notices.warnings[0]
        );
    }

    /// `this.Wanted` does not fall back to the resource beside the map either: under a wildcard, where
    /// the enclosing scope is the resource and the plain `to_lower(Wanted)` reads the resource's `Wanted`
    /// when the map lacks one, the `this.` spelling leaves the argument unresolved and the filter fails
    /// closed, with the moved-reading warning naming the resource's value the map does not have. The
    /// plain spelling over the same data is the control: it reads the resource's `alpha`, passes, and
    /// prints nothing, since reading the resource is the intended fallback and not a move.
    #[rstest::rstest]
    #[case::this_prefix_fails_closed_and_warns(
        "captures/key_filter_function_argument_this_wildcard.guard",
        "func_key_this_wildcard",
        StatusCode::VALIDATION_ERROR,
        "FAIL",
        1
    )]
    #[case::plain_argument_falls_back_to_the_resource(
        "captures/key_filter_function_argument_wildcard.guard",
        "func_key_wildcard",
        StatusCode::SUCCESS,
        "PASS",
        0
    )]
    fn a_this_prefixed_key_filter_argument_does_not_fall_back_to_the_resource_beside_the_map(
        #[case] rules: &str,
        #[case] rule: &str,
        #[case] expected_status_code: i32,
        #[case] expected_status: &str,
        #[case] expected_warnings: usize,
    ) {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-this-resource-only-template.yaml",
            rules,
        );
        assert_eq!(expected_status_code, status_code, "{}", output);
        assert_eq!(
            Some(expected_status.to_string()),
            rule_status_line(&output, rule),
            "{rule}: `this.Wanted` over a map without `Wanted` fails closed whatever the resource beside \
             the map holds; the plain `Wanted` reads the resource's:\n{output}"
        );
        assert!(
            notices.deprecations.is_empty(),
            "reading the resource is not deprecated and `this.` reads nothing outside the map, got {:?}",
            notices
        );
        assert_eq!(
            expected_warnings,
            notices.warnings.len(),
            "{rule}: one warning when the map resolves nothing where the resource has a value, none for \
             the plain spelling's intended fallback, got {:?}",
            notices
        );
        if expected_warnings == 1 {
            assert!(
                notices.warnings[0].contains("the function argument `this.Wanted` in a map key filter")
                    && notices.warnings[0].contains("resolves to nothing")
                    && notices.warnings[0].contains("/Resources/Cfg/Wanted["),
                "the warning names the map's reading, which resolves to nothing, and the resource's \
                 value and position: {}",
                notices.warnings[0]
            );
        }
    }

    /// A `this.`-prefixed argument the map does not hold, with no `Wanted` on the resource or at the
    /// root either, fails the filter closed and prints nothing: there is no other reading to compare
    /// with, so no warning, and nothing fell back, so no deprecation.
    #[test]
    fn a_this_prefixed_key_filter_argument_held_nowhere_fails_closed_in_silence() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-this-nowhere-template.yaml",
            "captures/key_filter_function_argument_this_wildcard.guard",
        );
        assert_eq!(StatusCode::VALIDATION_ERROR, status_code, "{}", output);
        assert_eq!(
            Some("FAIL".to_string()),
            rule_status_line(&output, "func_key_this_wildcard"),
            "the map has no `Wanted` and neither has anything around it: the argument is unresolved and \
             the filter fails closed, not SKIP:\n{output}"
        );
        assert!(
            notices.deprecations.is_empty() && notices.warnings.is_empty(),
            "no other reading exists to compare with, so no warning and no deprecation, got {:?}",
            notices
        );
    }

    /// A key filter the run never evaluates leaves no warning behind when a `when` is measured; the
    /// same filter reached by the run warns once.
    ///
    /// `%names` is a function result that kept an unresolved entry, so the `when` is read once more
    /// under a measurement with every condition evaluated on its own. In the first rules file the first
    /// disjunct passes and the key filter is never evaluated by the run; the measurement evaluates it,
    /// and the moved-reading warning was recorded whatever the measurement mode, so stderr named a
    /// clause the run never reached. The deprecations record nothing under a measurement; the warnings
    /// now follow the same rule. The positive control is the second rules file, the same `when` with
    /// the first disjunct false, so the run itself reaches the filter over the same template: exactly
    /// one warning, which shows the filter does warn on this template when a run evaluates it, so the
    /// first file's silence is the measurement recording nothing and not a filter that never warns.
    /// That a measurement is taken at all is asserted by the unit test beside the measurement counter.
    #[test]
    fn a_measured_when_leaves_no_key_filter_warning_behind() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-unreached-disjunct-template.yaml",
            "captures/key_filter_function_argument_unreached_disjunct.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "unreached_key_filter"),
            "the first disjunct passes and the body holds:\n{}",
            output
        );
        assert!(
            notices.is_empty(),
            "the key filter was evaluated only under the measurement, which records nothing, got {:?}",
            notices
        );

        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-unreached-disjunct-template.yaml",
            "captures/key_filter_function_argument_reached_disjunct.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "reached_key_filter"),
            "the first disjunct is false, the key filter selects `alpha`, the body holds:\n{}",
            output
        );
        assert_eq!(
            1,
            notices.warnings.len(),
            "the run reached the filter, whose map `Wanted: alpha` differs from the root's `beta`: one \
             warning, got {:?}",
            notices
        );
        assert!(
            notices.deprecations.is_empty(),
            "nothing fell back, got {:?}",
            notices
        );
    }

    /// One call site that moves for several maps is one warning, with the first example and a count.
    ///
    /// The warning's text names the map's position and the enclosing scope's, so `Resources.*.Map[
    /// keys == to_lower(Wanted) ]` over a template whose every resource differs produced one line per
    /// resource: a 500-resource template printed 500 lines for one clause. The other notices are kept
    /// to one per site; this one now is too, keyed by the call's location, keeping the first example
    /// and counting the rest.
    #[test]
    fn a_moved_reading_is_one_warning_per_call_site() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-two-resources-template.yaml",
            "captures/key_filter_function_argument_two_resources.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "func_key_per_resource"),
            "both maps' own `Wanted: alpha` select `alpha`, value 1:\n{}",
            output
        );
        assert!(
            notices.deprecations.is_empty(),
            "the maps answered, so nothing fell back, got {:?}",
            notices
        );
        assert_eq!(
            1,
            notices.warnings.len(),
            "one call site, one warning, whatever the number of maps it moved for, got {:?}",
            notices
        );
        assert!(
            notices.warnings[0].contains("/Resources/First/Map[")
                && !notices.warnings[0].contains("/Resources/Second/Map[")
                && notices.warnings[0].contains("1 more map"),
            "the first example is shown and the rest are counted: {}",
            notices.warnings[0]
        );
    }

    /// Two query arguments of one call that both moved are two warning lines, one per argument.
    ///
    /// The warning is kept once per call site, and a call has one site however many arguments it
    /// takes. Keyed by the site alone, the second argument's text was dropped on arrival (the site's
    /// entry existed) and its map was not counted (the same map was already counted for the first
    /// argument), so `regex_replace(Wanted, Pattern, 'a')` with both `Wanted` and `Pattern` differing
    /// between the map and the root printed one line naming `Wanted` and nothing about `Pattern`.
    /// Before the warning was kept per site, the two texts differed and both were printed. The key is
    /// the site and the argument, so each moved argument has its own line and its own count.
    #[test]
    fn two_moved_arguments_in_one_call_are_two_warning_lines() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-two-arguments-template.yaml",
            "captures/key_filter_function_argument_two_arguments.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "func_key_two_arguments"),
            "the map's `xlpha` with its own `^x` replaced selects `alpha`, value 1:\n{}",
            output
        );
        assert!(
            notices.deprecations.is_empty(),
            "nothing fell back: {:?}",
            notices
        );
        assert_eq!(
            2,
            notices.warnings.len(),
            "two arguments moved, two lines, got {:?}",
            notices
        );
        let names = |argument: &str| {
            notices
                .warnings
                .iter()
                .filter(|w| {
                    w.contains(&format!(
                        "the function argument `{argument}` in a map key filter"
                    ))
                })
                .count()
        };
        assert_eq!(
            (1, 1),
            (names("Wanted"), names("Pattern")),
            "one line names `Wanted` and one names `Pattern`: {:?}",
            notices
        );
        assert!(
            notices.warnings.iter().all(|w| !w.contains("more map")),
            "one map per argument, so no count on either line: {:?}",
            notices
        );
    }

    /// Each moved argument counts the maps it moved on, and not the maps another argument moved on.
    ///
    /// Two resources, two arguments: beside the first map only `Wanted` differs, beside the second only
    /// `Pattern`. With one entry per site, the first argument's line counted the second map as "1 more
    /// map" although `Wanted` had not moved there, and `Pattern`'s move was not named at all. Each
    /// argument's line names the map it moved on and carries no count.
    #[test]
    fn each_moved_argument_counts_only_the_maps_it_moved_on() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-mixed-arguments-template.yaml",
            "captures/key_filter_function_argument_mixed_arguments.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "func_key_mixed_arguments"),
            "both maps select `alpha` on their own values:\n{}",
            output
        );
        assert_eq!(
            2,
            notices.warnings.len(),
            "two arguments moved, each on one map: two lines, got {:?}",
            notices
        );
        let line_for = |argument: &str| {
            notices
                .warnings
                .iter()
                .find(|w| {
                    w.contains(&format!(
                        "the function argument `{argument}` in a map key filter"
                    ))
                })
                .unwrap_or_else(|| panic!("no line names `{argument}`: {:?}", notices))
        };
        let wanted = line_for("Wanted");
        let pattern = line_for("Pattern");
        assert!(
            wanted.contains("/Resources/First/Map[") && !wanted.contains("more map"),
            "`Wanted` moved on the first map only, so its line names it and counts no other: {}",
            wanted
        );
        assert!(
            pattern.contains("/Resources/Second/Map[") && !pattern.contains("more map"),
            "`Pattern` moved on the second map only, so its line names it and counts no other: {}",
            pattern
        );
    }

    /// One map read twice at one call site is one map: one line, no count.
    ///
    /// A parameterized rule called with the resource from the root and again with every resource (one)
    /// evaluates its key filter twice over the same map. The warning counts maps by path, so the second
    /// reading adds nothing to the line; a count that went by readings would say "1 more map" for a
    /// map there is one of.
    #[test]
    fn one_map_read_from_two_callers_is_one_line_with_no_count() {
        let (status_code, output, notices) = run_with_notices(
            "captures/key-filter-function-argument-resource-wanted-template.yaml",
            "captures/key_filter_function_argument_one_map_two_callers.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            (Some("PASS".to_string()), Some("PASS".to_string())),
            (
                rule_status_line(&output, "from_root"),
                rule_status_line(&output, "from_wildcard")
            ),
            "both callers select `alpha` on the map's own value:\n{}",
            output
        );
        assert_eq!(
            1,
            notices.warnings.len(),
            "one site, one map, one line, got {:?}",
            notices
        );
        assert!(
            notices.warnings[0].contains("/Resources/Cfg/Map[")
                && notices.warnings[0].contains("the value at /Resources/Cfg[")
                && !notices.warnings[0].contains("more map"),
            "the line names the map and the resource and counts no second map: {}",
            notices.warnings[0]
        );
    }

    /// One call site reached in two data files of one run is one warning line per data file, on the
    /// single-line output, each beside its file's report and naming its file.
    ///
    /// The single-line output writes each data file's notices beside that file's report. The warnings
    /// are kept once per call site and argument across the run, and the key carried no data file, so
    /// the second file's reading of the same call was dropped: a template whose verdict may have moved
    /// got no line at all, and the first file's count ("in this data file") hid that other files moved
    /// too, where the `test` command keeps one line per spec file. The data file is in the key as the
    /// spec file is: one line per data file whose reading moved, the count per file.
    #[test]
    fn a_moved_reading_is_one_warning_per_data_file() {
        let (status_code, output, notices) = run_with_notices_over(
            vec![
                "captures/key-filter-function-argument-resource-wanted-template.yaml",
                "captures/key-filter-function-argument-two-resources-template.yaml",
            ],
            "captures/key_filter_function_argument_two_resources.guard",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            2,
            output.matches("Status = PASS").count(),
            "both data files pass on the maps' own values:\n{}",
            output
        );
        assert_eq!(
            2,
            notices.warnings.len(),
            "one call site across two data files is one line per data file, got {:?}",
            notices
        );
        assert!(
            notices.warnings[0].contains("resource-wanted-template.yaml, where")
                && !notices.warnings[0].contains("more map"),
            "the first line is the first file's, naming it, with its one map and no count: {}",
            notices.warnings[0]
        );
        assert!(
            notices.warnings[1].contains("two-resources-template.yaml, where")
                && notices.warnings[1].contains("1 more map")
                && notices.warnings[1].contains("in this data file"),
            "the second line is the second file's, naming it, counting its own second map: {}",
            notices.warnings[1]
        );
    }

    /// One call site reached in two data files of one run is one warning line per data file, on a
    /// structured output.
    ///
    /// The structured reporters evaluate every data file and write one document; the warnings are
    /// carried across the files there too, keyed by the data file, so each file's reading of the call
    /// is its own line.
    #[rstest::rstest]
    #[case::json("json")]
    fn a_structured_output_writes_the_moved_reading_warning_once_per_data_file(
        #[case] format: &str,
    ) {
        let (status_code, output, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![
                    "captures/key-filter-function-argument-resource-wanted-template.yaml",
                    "captures/key-filter-function-argument-two-resources-template.yaml",
                ])
                .rules(vec![
                    "captures/key_filter_function_argument_two_resources.guard",
                ])
                .output_format(Some(format))
                .structured()
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}:\n{}\n{}",
            format,
            output,
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            2,
            warnings.len(),
            "{}: one call site across two data files is one warning per data file, got:\n{}",
            format,
            stderr
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("resource-wanted-template.yaml, where")
                    && !w.contains("more map"))
                && warnings
                    .iter()
                    .any(|w| w.contains("two-resources-template.yaml, where")
                        && w.contains("1 more map")),
            "{}: each line names its file and counts that file's maps, got:\n{}",
            format,
            stderr
        );
        assert!(
            !output.contains("Warning:"),
            "{}: the warning is not part of the document on stdout:\n{}",
            format,
            output
        );
    }

    /// Every structured output writes the moved-reading warning to stderr, once.
    ///
    /// The structured reporters drain the evaluator's warnings beside its deprecations; a reporter that
    /// read only the deprecations would drop a warning the documentation promises, and stdout, which is
    /// the document a pipeline parses, would say nothing about it. Pinned per format so a drain that
    /// stops reading the warnings turns its own row red: planting `warnings()` out of one reporter's
    /// drain fails that reporter's format and no other.
    #[rstest::rstest]
    #[case::json("json")]
    #[case::yaml("yaml")]
    #[case::sarif("sarif")]
    #[case::junit("junit")]
    fn a_structured_output_writes_the_moved_reading_warning_once(#[case] format: &str) {
        let (status_code, output, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![
                    "captures/key-filter-function-argument-two-resources-template.yaml",
                ])
                .rules(vec![
                    "captures/key_filter_function_argument_two_resources.guard",
                ])
                .output_format(Some(format))
                .structured()
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{}:\n{}\n{}",
            format,
            output,
            stderr
        );
        assert_eq!(
            1,
            stderr.lines().filter(|l| l.starts_with("Warning:")).count(),
            "{}: the one call site's moved reading is one warning on stderr, got:\n{}",
            format,
            stderr
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "{}: the maps answered, so nothing fell back, got:\n{}",
            format,
            stderr
        );
        assert!(
            !output.contains("Warning:"),
            "{}: the warning is not part of the document on stdout:\n{}",
            format,
            output
        );
    }

    /// A filter inside the argument runs once: the map's read records it, and the comparison against
    /// the enclosing scope reads only the leading `Wanted`, which records nothing.
    ///
    /// `Wanted[ Use == true ].Name` over a map `Wanted` with two members evaluates the filter once per
    /// member, so the verbose tree holds two filter blocks. A read of the whole argument from the root
    /// for the comparison would evaluate the filter again over the root's members and add their blocks
    /// to the tree. The move itself is still named: the root's `Wanted` differs from the map's, so one
    /// warning and no deprecation.
    #[test]
    fn a_filter_in_a_key_filter_argument_records_once() {
        let (status_code, output, stderr) = capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![
                    "captures/key-filter-function-argument-filtered-template.yaml",
                ])
                .rules(vec!["captures/key_filter_function_argument_filtered.guard"])
                .verbose()
                .run(writer, reader)
        });
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            2,
            output.matches("Filter/ConjunctionsBlock").count(),
            "one filter block per member of the map's `Wanted`, and none for the root's:\n{}",
            output
        );
        assert_eq!(
            1,
            stderr.lines().filter(|l| l.starts_with("Warning:")).count(),
            "one warning for the leading `Wanted` that differs from the root's, got:\n{}",
            stderr
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "nothing fell back to the root, so no deprecation, got:\n{}",
            stderr
        );
    }

    /// An argument the map holds is the map's, whatever it resolves to; only an absent key falls back.
    ///
    /// `Wanted: []` in the map resolves to the empty list: an empty set of names, so `==` selects
    /// nothing and both rules SKIP. `Wanted: [{Other: 1}]` in the map with `Wanted[*].Name` as the
    /// argument resolves to nothing either, but the key is present: the retrieval got past it and
    /// stopped inside its members, and the function hands that unresolved value on, so the filter
    /// fails closed on it; `to_lower(Wanted)` over the same list is handed a map where it wants a
    /// string, and the filter fails closed on that too. Either way the answer is the map's own, and
    /// neither reads the resource's `Wanted` beside the map: "no resolved value" is not read as
    /// "absent", so the fallback does not find the resource's `Wanted: [{Name: x}]`, select `x`, and
    /// pass the rule with a notice -- on a key the map holds.
    #[test]
    fn a_key_filter_argument_the_map_holds_never_falls_back() {
        for (data, label, code, status) in [
            (
                "captures/present-but-empty-wanted-template.yaml",
                "an empty list",
                StatusCode::SUCCESS,
                "SKIP",
            ),
            (
                "captures/present-but-unresolved-wanted-template.yaml",
                "members without the field",
                StatusCode::VALIDATION_ERROR,
                "FAIL",
            ),
        ] {
            let (status_code, output, notices) = run_with_notices(
                data,
                "captures/key_filter_argument_present_in_the_map.guard",
            );
            assert_eq!(code, status_code, "{}: {}", label, output);
            for rule in ["r", "r_members"] {
                assert_eq!(
                    Some(status.to_string()),
                    rule_status_line(&output, rule),
                    "{} with {}: the map's own `Wanted` decides the filter; PASS would be the \
                     resource's `Wanted` read through a key the map holds:\n{}",
                    rule,
                    label,
                    output
                );
            }
            // Nothing was read from outside the map, so no notice says so. A notice of another kind
            // may stand beside: `to_lower` over the empty list answers no values where it had one
            // unresolved entry, and that move is announced on its own.
            assert!(
                notices
                    .deprecations
                    .iter()
                    .chain(notices.warnings.iter())
                    .all(|notice| !notice.contains("read from the document root")),
                "{}: nothing was read from outside the map, so no notice says so, got {:?}",
                label,
                notices
            );
            assert_eq!(
                2,
                notices.warnings.len(),
                "{}: the resource's `Wanted` beside the map differs from the map's, so each of the two \
                 calls names the moved reading once, got {:?}",
                label,
                notices
            );
            // The notice of another kind that stands beside is the list-expansion one; the fallback's
            // own deprecation names the read from the document root, and none is here.
            assert!(
                notices.deprecations.iter().all(|notice| !notice
                    .contains("was not found in the map being filtered and was read from the document root instead")),
                "{}: nothing fell back to the resource, so no fallback deprecation, got {:?}",
                label,
                notices
            );
        }
    }

    /// A rule referenced by name is evaluated apart from the referencing rule's captures.
    ///
    /// `main`'s condition captures `b` as `[MyRole]`. Referencing `helper` from its body evaluated
    /// `helper` against the same root scope, so the capture in `helper`'s own condition was appended
    /// to the live map `main` was reading, and `%b == "MyRole"` compared `[MyRole, Bkt]` and failed at
    /// exit 19 -- when the reference came before the comparison. Moving the reference after it, or
    /// deleting it, gave exit 0, so clause order decided the verdict.
    #[rstest::rstest]
    #[case::reference_before_the_comparison("captures/referenced_rule_when_capture.guard")]
    #[case::reference_after_the_comparison("captures/referenced_rule_when_capture_reordered.guard")]
    #[case::no_reference("captures/referenced_rule_when_capture_without_reference.guard")]
    fn a_referenced_rules_condition_capture_stays_out_of_the_referencing_rule(#[case] rules: &str) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/role-and-bucket-template.yaml"])
            .rules(vec![rules])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "main's own capture is exactly the one role, so the file is compliant whatever the \
             clause order:\n{}",
            output
        );
        for rule in ["helper", "main"] {
            assert_eq!(
                Some("PASS".to_string()),
                rule_status_line(&output, rule),
                "{} passes; `main` failed on `Bkt`, a key its own condition never captured:\n{}",
                rule,
                output
            );
        }
    }

    /// A capture declared on a filter over a list binds the element the predicate selected.
    ///
    /// `Tags[*][ t | Key == 'Name' ]` parsed with the name `t` and selected the matching tag, but no
    /// arm bound the name: the map arms bind an entry's key, and a list element has none. `%t` then
    /// resolved to an empty selection, so `%t !empty` failed with a message blaming the selection
    /// (exit 19) and `%t.Value == 'dev'` was not applicable, while `%t exists` skipped and let the rule
    /// pass at exit 0 having read nothing. The map control is the documented shape and keeps working;
    /// the undeclared control pins that a name declared nowhere is still the rules file's error.
    #[rstest::rstest]
    #[case::not_empty("captures/list_capture_not_empty.guard", StatusCode::SUCCESS)]
    #[case::value_of_the_selected_tag("captures/list_capture_value.guard", StatusCode::SUCCESS)]
    #[case::map_capture_control("captures/map_capture_control.guard", StatusCode::SUCCESS)]
    #[case::undeclared_name_control(
        "captures/undeclared_capture_control.guard",
        StatusCode::PARSING_ERROR
    )]
    fn a_list_filter_capture_binds_the_selected_element(
        #[case] rules: &str,
        #[case] expected: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/tagged-bucket-template.yaml"])
            .rules(vec![rules])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(expected, status_code, "{}:\n{}", rules, output);
        if expected == StatusCode::SUCCESS {
            assert_eq!(
                Some("PASS".to_string()),
                rule_status_line(&output, "r"),
                "the rule reads the tag the filter selected, so it passes rather than skipping:\n{}",
                output
            );
        }
    }

    /// The `exists` spelling of the test above, which needs the verbose tree to be seen at all.
    ///
    /// Unbound, `%t exists` skipped, and a rule whose other clause passed reported PASS at exit 0; the
    /// exit code and the summary both read exactly as they do when `%t` is bound. The verbose record
    /// of the clause is what tells the two apart.
    #[test]
    fn a_list_filter_capture_read_by_exists_is_checked_rather_than_skipped() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/tagged-bucket-template.yaml"])
            .rules(vec!["captures/list_capture_exists.guard"])
            .show_summary(vec!["all"])
            .verbose()
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "r"),
            "{}",
            output
        );
        assert!(
            output.contains(
                "GuardClauseBlock(Status = PASS)[Context=GuardAccessClause#block %t EXISTS"
            ),
            "the clause has a value to test and passes on it:\n{}",
            output
        );
        assert!(
            !output.contains("Status = SKIP)[Context=GuardAccessClause#block %t EXISTS"),
            "a skip here is the unbound capture, reported at exit 0 as if it had been checked:\n{}",
            output
        );
    }

    /// A capture on a file-level projection binds the logical id on every path it is read from.
    ///
    /// The parent container is found in the scope that owns the binding. Found through the reader's
    /// scope instead, `Resources` was out of reach from a block clause or a type block body whose root
    /// is the role resource, and `b` bound the bucket's body there: `%b == 'A'` failed with
    /// "PathAwareValues are not comparable map, String" while the rule-level and `when` spellings
    /// passed. The documentation promises the key on every path.
    #[test]
    fn a_projection_capture_binds_the_key_on_every_path() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/bucket-and-role-template.yaml"])
            .rules(vec!["captures/projection_capture_on_every_path.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        for rule in ["top", "in_when_block", "in_block", "in_type_block"] {
            assert_eq!(
                Some("PASS".to_string()),
                rule_status_line(&output, rule),
                "{} binds `b` to the logical id `A`; FAIL is the member's body bound where the \
                 reader's scope could not reach `Resources`:\n{}",
                rule,
                output
            );
        }
    }

    /// The same projection reached through an alias bound in the type block, and through a
    /// parameterized rule's parameter, binds the key too.
    ///
    /// Both spellings carry the file-level binding into a scope rooted at the role: `let bs =
    /// %buckets` in the body, and `check(%buckets)` resolving `bs` to the caller's `%buckets`. The
    /// walk that finds the binding follows the alias to the file-level `let`; a separate owner
    /// computation named the alias instead, ran the container query at the role, found no
    /// `Resources`, and bound the bucket's body in both.
    #[test]
    fn a_projection_capture_binds_the_key_through_an_alias_and_a_parameter() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/bucket-and-role-template.yaml"])
            .rules(vec!["captures/projection_capture_through_an_alias.guard"])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        for rule in ["alias_in_type_block", "parameter_in_type_block"] {
            assert_eq!(
                Some("PASS".to_string()),
                rule_status_line(&output, rule),
                "{} binds `b` to the logical id `A`; FAIL is the body bound because the container \
                 was looked for in the alias's scope:\n{}",
                rule,
                output
            );
        }
    }

    /// A type block's condition hands its captures up on every exit, the undecidable one included.
    ///
    /// The condition's scope merges its captures into the rule's scope when the resource is done:
    /// after the body, and on the exempted path. The path where the condition cannot be decided and
    /// the type block fails closed for the resource left without merging, so `%cfg !empty` after the
    /// block read an empty selection and failed, where the other two exits let it read the key. The
    /// rule fails either way -- the type block failed closed -- so the clause's own record is what
    /// tells the two apart.
    #[test]
    fn a_type_block_condition_hands_its_captures_up_when_it_cannot_be_decided() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec![
                "captures/enabled-config-and-boolean-flag-template.yaml",
            ])
            .rules(vec![
                "captures/type_block_condition_capture_then_unevaluatable.guard",
            ])
            .show_summary(vec!["all"])
            .verbose()
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the undecidable condition fails the type block closed for the resource:\n{}",
            output
        );
        assert_eq!(
            Some("FAIL".to_string()),
            rule_status_line(&output, "r"),
            "{}",
            output
        );
        assert!(
            output.contains(
                "GuardClauseBlock(Status = PASS)[Context=GuardAccessClause#block %cfg not EMPTY"
            ),
            "the clause after the block reads the key the condition captured before it could not be \
             decided:\n{}",
            output
        );
    }

    /// `count(%id)` over a projection capture is the capture's own count: the ids this read of the
    /// filter bound, inside the iteration that bound them, and the union over every iteration after
    /// the block.
    ///
    /// Two buckets, two roles. Inside a type block's body or `when`, a block clause, the rule level
    /// or a rule `when`, `%buckets[ id | ... ]` binds the two bucket ids, so `count(%id)` is 2 on
    /// every one of the five paths. After a type block or a block clause over the two roles, the
    /// capture has been handed up once per role and the clause after the block reads the union, 4;
    /// the `_2` rules there state the per-iteration number and fail, the `_4` rules pass. The
    /// `count_in_type_block_when` row needs the condition's own per-resource scope: run against
    /// the rule's scope, a second role's condition read the first's captures beside its own.
    #[test]
    fn a_projection_capture_counts_its_ids_inside_an_iteration_and_their_union_after() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/two-buckets-two-roles-template.yaml"])
            .rules(vec![
                "captures/projection_capture_count_inside_iterations.guard",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(StatusCode::SUCCESS, status_code, "{}", output);
        for rule in [
            "count_in_type_block_body",
            "count_in_type_block_when",
            "count_in_block_clause",
            "count_at_rule_level",
            "count_in_rule_when",
        ] {
            assert_eq!(
                Some("PASS".to_string()),
                rule_status_line(&output, rule),
                "{} counts the two bucket ids this read bound:\n{}",
                rule,
                output
            );
        }

        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/two-buckets-two-roles-template.yaml"])
            .rules(vec![
                "captures/projection_capture_count_after_the_block.guard",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the `_2` rules state the per-iteration count after the block and fail:\n{}",
            output
        );
        for (rule, status) in [
            ("after_type_block_2", "FAIL"),
            ("after_type_block_4", "PASS"),
            ("after_block_clause_2", "FAIL"),
            ("after_block_clause_4", "PASS"),
        ] {
            assert_eq!(
                Some(status.to_string()),
                rule_status_line(&output, rule),
                "{} reads the union of both roles' captures, 4:\n{}",
                rule,
                output
            );
        }
    }

    fn validate_functions_fixture(rules: &str, data: &str) -> (i32, String) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .rules(vec![rules])
            .data(vec![data])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        (status_code, output)
    }

    /// A function over a selection it can only partly handle fails the elements it cannot, the way the
    /// bare query does.
    ///
    /// `to_lower(%ingress.IpProtocol)` over an ingress list holding `IpProtocol: -1`, or an entry with no
    /// `IpProtocol`, FAILs at 19, as `%ingress.IpProtocol == "TCP"` on the same template does.
    /// `resolve_function` keeps the function's per-element results: flattened, the `int` and the
    /// missing key would vanish before the comparison and only the `"tcp"` would be compared, PASS at
    /// exit 0, and a rule author who wrapped the query in `to_lower` to be case-insensitive would have
    /// turned the check off for the values it was written to catch.
    #[rstest::rstest]
    #[case::an_all_traffic_entry(
        "/functions/data/ingress_with_all_traffic.yaml",
        StatusCode::VALIDATION_ERROR,
        "/Resources/SG/Properties/SecurityGroupIngress/1/IpProtocol"
    )]
    #[case::an_entry_without_the_key(
        "/functions/data/ingress_without_protocol.yaml",
        StatusCode::VALIDATION_ERROR,
        "Could not find key IpProtocol"
    )]
    #[case::another_protocol_control(
        "/functions/data/ingress_with_udp.yaml",
        StatusCode::VALIDATION_ERROR,
        "udp"
    )]
    #[case::every_entry_tcp_control(
        "/functions/data/ingress_all_tcp.yaml",
        StatusCode::SUCCESS,
        "TCP_ONLY"
    )]
    fn a_string_function_over_a_mixed_selection_fails_what_it_cannot_lowercase(
        #[case] data: &str,
        #[case] expected: i32,
        #[case] named_in_the_report: &str,
    ) {
        let (status_code, output) =
            validate_functions_fixture("/functions/rules/lowercased_protocol.guard", data);

        assert_eq!(
            expected, status_code,
            "the function-wrapped allowlist must reach the verdict the bare query reaches:\n{}",
            output
        );
        assert!(
            output.contains(named_in_the_report),
            "the report must name {:?}:\n{}",
            named_in_the_report,
            output
        );
    }

    /// A value a function had no answer for is reported as such, not as a missing property.
    ///
    /// The unresolved result built for `IpProtocol: -1` leaves no query unsatisfied, so the console
    /// reporter prints it as a value with no answer, path and reason included, and not as
    /// `RequiredPropertyError` with `MissingProperty = to_lower(..)`, which would name a key nobody
    /// asked for on a value that was found.
    #[test]
    fn a_value_a_function_cannot_take_is_not_reported_as_a_missing_property() {
        let (status_code, output) = validate_functions_fixture(
            "/functions/rules/lowercased_protocol.guard",
            "/functions/data/ingress_with_all_traffic.yaml",
        );

        assert_eq!(StatusCode::VALIDATION_ERROR, status_code, "{}", output);
        for line in [
            "NoAnswerError {",
            "PropertyPath = /Resources/SG/Properties/SecurityGroupIngress/1/IpProtocol",
            "Reason = to_lower has no answer for the value at /Resources/SG/Properties/SecurityGroupIngress/1/IpProtocol",
            "it is int, which the function does not take",
        ] {
            assert!(
                output.contains(line),
                "the console block carries {:?}:\n{}",
                line,
                output
            );
        }
        assert!(
            !output.contains("MissingProperty") && !output.contains("RequiredPropertyError"),
            "a value that was found is not a missing property:\n{}",
            output
        );
    }

    /// One constant, one verdict, whether or not a function spelled it.
    ///
    /// `Ports not in parse_int("5")` PASSed at exit 0 where `Ports not in 5` FAILed at 19 with "Can not
    /// compare". `resolve_function` re-wrapped every result as `Resolved`, so the constant took the
    /// queried comparator arm, which drops the list-against-int refusal, while the bare literal took the
    /// literal arm, which reports it. A function over literal arguments only is a literal.
    #[test]
    fn a_constant_spelled_through_a_function_reaches_the_bare_literals_verdict() {
        let (bare_code, bare_output) = validate_functions_fixture(
            "/functions/rules/ports_not_in_five.guard",
            "/functions/data/ports.yaml",
        );
        let (function_code, function_output) = validate_functions_fixture(
            "/functions/rules/ports_not_in_parsed_five.guard",
            "/functions/data/ports.yaml",
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            bare_code,
            "control: the bare literal fails closed on a list against an int:\n{}",
            bare_output
        );
        assert_eq!(
            bare_code, function_code,
            "parse_int(\"5\") and 5 are the same constant and must reach the same verdict:\n{}",
            function_output
        );
    }

    /// A string function fed a value that is not a string names the value and its type; fed a key the
    /// template does not have, it names the missing key. Neither reads as "resolved to no values".
    ///
    /// The per-element `None` is kept, so the variable holds it and the report points at the template,
    /// not at the `let` of a variable holding nothing. The pattern here compiles, so what is reported is
    /// the input, not the pattern.
    #[rstest::rstest]
    #[case::an_integer_input(
        "/functions/rules/regex_replace_over_int.guard",
        "/Resources/Fn/Properties/Timeout",
        "int"
    )]
    #[case::a_missing_key(
        "/functions/rules/regex_replace_over_missing_key.guard",
        "/Resources/Fn/Properties",
        "Could not find key NoSuchKey"
    )]
    fn a_string_function_names_the_input_it_cannot_take(
        #[case] rules: &str,
        #[case] path: &str,
        #[case] reason: &str,
    ) {
        let (status_code, output) =
            validate_functions_fixture(rules, "/functions/data/function_with_timeout.yaml");

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the rule fails closed:\n{}",
            output
        );
        assert!(
            output.contains(path) && output.contains(reason),
            "the report must name the input at {:?} and the reason {:?}:\n{}",
            path,
            reason,
            output
        );
        assert!(
            !output.contains("resolved to no values"),
            "the input was found; it is the function that has no answer for it:\n{}",
            output
        );
    }

    /// A regex_replace pattern the template supplies that cannot be evaluated fails the clause at 19
    /// and names the property; it does not take the run down at 255.
    ///
    /// Both a pattern that does not compile and one that exhausts the engine's backtracking budget
    /// became `RegexError`, whose message says "for rules file" and which `is_unevaluatable` does not
    /// recognize, so the run printed its report and then exited 255 -- the code this repository reserves
    /// for the tool itself breaking. REAL_VIOLATION's FAIL was in the report, but a CI wrapper reads the
    /// exit code, and 255 says "retry the build", not "block the deploy". A template author could pick
    /// the exit code for their own violation by choosing the field's value.
    ///
    /// The same budget failure in a `==` regex comparison already failed only the clause. The function
    /// now does too: the pattern is compiled once, before any element, and each failure is classified
    /// on the provenance of what failed, naming the pattern and where it came from. A pattern written
    /// in the rules file that does not compile is `IncompatibleError`, and the run stops at 5 (the
    /// test below). A pattern read from the template, as here, is `Unevaluatable` whether it does not
    /// compile or its match exhausts the budget on the template's value: the clause fails and the
    /// run continues.
    #[rstest::rstest]
    #[case::does_not_compile(
        "/functions/data/pattern_that_does_not_compile.yaml",
        "USES_DATA_PATTERN    FAIL",
        "the pattern \"(\" at /Resources/Thing/Properties/Pattern"
    )]
    #[case::exhausts_the_backtracking_budget(
        "/functions/data/pattern_that_exhausts_backtracking.yaml",
        "USES_DATA_PATTERN    FAIL",
        "the pattern \"(?!x)((a+)+)b\" at /Resources/Thing/Properties/Pattern"
    )]
    #[case::compiles_control(
        "/functions/data/pattern_that_compiles.yaml",
        "USES_DATA_PATTERN    PASS",
        "REAL_VIOLATION       FAIL"
    )]
    fn a_data_supplied_pattern_that_cannot_be_evaluated_fails_its_clause_not_the_run(
        #[case] data: &str,
        #[case] verdict_line: &str,
        #[case] named_in_the_report: &str,
    ) {
        let (status_code, output) =
            validate_functions_fixture("/functions/rules/pattern_from_the_template.guard", data);

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "REAL_VIOLATION fails the file, and a bad pattern must not turn that into a tool failure:\n{}",
            output
        );
        assert!(
            output.contains("REAL_VIOLATION") && output.contains(verdict_line),
            "the report carries both rules, with {:?}:\n{}",
            verdict_line,
            output
        );
        assert!(
            output.contains(named_in_the_report),
            "the report must name {:?}:\n{}",
            named_in_the_report,
            output
        );
        assert!(
            !output.contains("for rules file"),
            "the pattern came from the template, not the rules file:\n{}",
            output
        );
    }

    /// A pattern in the rules file that does not compile is reported whatever the input is.
    ///
    /// The pattern was compiled inside the per-element loop, in the arm a string reaches, so over an
    /// integer property or a missing key it was never compiled and the author saw a failure about the
    /// input instead of the broken pattern. Compiled once before the loop, the pattern is the first
    /// thing reported. Written in the rules file, it is the author's mistake and stops the run at 5,
    /// where the same pattern read from the template fails only its clause (the cases above).
    #[test]
    fn a_pattern_that_does_not_compile_is_reported_even_when_no_string_reaches_it() {
        let (status_code, output) = validate_functions_fixture(
            "/functions/rules/regex_replace_bad_pattern_over_int.guard",
            "/functions/data/function_with_timeout.yaml",
        );

        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "a broken pattern written in the rules file stops the run:\n{}",
            output
        );
        assert!(
            output.contains("the pattern \"(\" in the rules file"),
            "the report must name the pattern and say it came from the rules file:\n{}",
            output
        );
    }

    /// A scalar argument bound to a query that selects more than one value is refused, naming the count.
    ///
    /// `substring`'s bounds, `join`'s delimiter and `regex_replace`'s pattern and replacement each read
    /// the first value of their argument and said nothing about the rest, so `substring(%name, 0,
    /// %ends)` with `%ends` resolving to `[3, 8]` answered for 3 alone and the rule PASSed at exit 0.
    /// The control binds the same arguments to one value each and still passes.
    #[rstest::rstest]
    #[case::two_values_are_refused(
        "/functions/rules/scalar_arguments_with_two_values.guard",
        StatusCode::VALIDATION_ERROR,
        "exactly one value, got 2"
    )]
    #[case::one_value_control(
        "/functions/rules/scalar_arguments_with_one_value.guard",
        StatusCode::SUCCESS,
        "REGEX_REPLACE_WITH_ONE_PATTERN    PASS"
    )]
    fn a_scalar_function_argument_must_resolve_to_exactly_one_value(
        #[case] rules: &str,
        #[case] expected: i32,
        #[case] named_in_the_report: &str,
    ) {
        let (status_code, output) =
            validate_functions_fixture(rules, "/functions/data/two_of_each_scalar.yaml");

        assert_eq!(expected, status_code, "{}", output);
        assert!(
            output.contains(named_in_the_report),
            "the report must carry {:?}:\n{}",
            named_in_the_report,
            output
        );
        if expected == StatusCode::VALIDATION_ERROR {
            for function in ["substring", "join", "regex_replace"] {
                assert!(
                    output.contains(&format!("{function} function requires")),
                    "{function} must refuse its two-valued argument:\n{}",
                    output
                );
            }
        }
    }

    /// A function argument that resolves to a list value is read as that list's elements, the way the
    /// comparison operators read one.
    ///
    /// `count(Resources.R.Properties.L)` over `L: [a, b, c]` answered 1 and `%n == 3` FAILed, while
    /// `Resources.R.Properties.L == ["a", "b", "c"]` on the same data PASSed; `join(%lit, ",")` over
    /// `let lit = ["a", "b", "c"]` refused with "Joining non string values"; `parse_int(Props.Ports)` over
    /// `Ports: ["80"]` resolved to nothing. The author had to know to write `[*]` for a function but not
    /// for an operator. The `[*]` spellings are the controls and answer the same values as before.
    #[test]
    fn a_function_reads_a_list_value_as_its_elements() {
        let (status_code, output) = validate_functions_fixture(
            "/functions/rules/functions_over_a_list_value.guard",
            "/functions/data/list_property.yaml",
        );

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "every rule compares against the list's elements:\n{}",
            output
        );
        assert!(
            output.contains("PASS rules") && !output.contains("FAIL"),
            "every rule is listed as passing and none as failing:\n{}",
            output
        );
        for rule in [
            "COUNT_OF_A_LIST_PROPERTY",
            "JOIN_OF_A_LIST_LITERAL",
            "COUNT_OF_A_LIST_LITERAL",
            "PARSE_INT_OF_A_LIST_PROPERTY",
            "COUNT_OF_THE_EXPANDED_LIST_CONTROL",
            "JOIN_OF_THE_EXPANDED_LIST_CONTROL",
        ] {
            assert!(
                output.contains(rule),
                "{rule} is in the report:\n{}",
                output
            );
        }
    }

    /// Runs `validate` over one rules file and one template and returns the exit code, stdout and
    /// stderr. `stripped` and `err_to_stripped` each consume the writer, so the command is run once per
    /// stream; it is deterministic over these inputs, so that reads the same output twice.
    fn validate_both_streams(rules: &str, data: &str) -> (i32, String, String) {
        validate_both_streams_with(rules, data, false)
    }

    /// `validate_both_streams`, with `--verbose` so stdout carries the evaluation tree.
    fn validate_both_streams_verbose(rules: &str, data: &str) -> (i32, String, String) {
        validate_both_streams_with(rules, data, true)
    }

    fn validate_both_streams_with(rules: &str, data: &str, verbose: bool) -> (i32, String, String) {
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let status_code = if verbose {
                ValidateTestRunner::default()
                    .data(vec![data])
                    .rules(vec![rules])
                    .show_summary(vec!["all"])
                    .verbose()
                    .run(&mut writer, &mut reader)
            } else {
                ValidateTestRunner::default()
                    .data(vec![data])
                    .rules(vec![rules])
                    .show_summary(vec!["all"])
                    .run(&mut writer, &mut reader)
            };
            (status_code, writer)
        };
        let (status_code, out_writer) = run();
        let (_, err_writer) = run();
        (
            status_code,
            out_writer.stripped().expect("failed to read stdout"),
            err_writer.err_to_stripped().expect("failed to read stderr"),
        )
    }

    /// A filter through a variable that a plain key path bound to ONE map tests that map itself when the
    /// map is one object (a non-null scalar entry, `Type`, beside its sub-map), as the authored
    /// `%v[*][ ... ]` reads it and as the previous release did: the predicate written against the map's
    /// own keys holds, the map is selected, and the rule applies.
    ///
    /// The fixture is the structure of a published registry rule, and the two templates are the two
    /// shapes its own tests carry: FAIL at the validation failure code over the authentication block
    /// that defines a password, PASS at exit 0 over the one that does not. Nothing is announced: the
    /// selection the previous release made is the selection made now, so there is no lost selection for
    /// the bound-map notice to name. Read apart from the wildcard spelling, this filter walked the one
    /// map's entries, selected nothing, and reported SKIP with a notice on a template that defines a
    /// password.
    ///
    /// The third template leaves the scalar `Type` entry out of the `Metadata` map: its map holds only
    /// the authentication block. The predicate, `"AWS::CloudFormation::Authentication" exists`, names
    /// a key the map holds itself and none of its map-valued entries holds, so the map is one object
    /// here too, and the rule FAILs at the validation failure code on the password with no notice.
    /// cfn-guard 3.2.1 also reports FAIL for this template (its reporter then exits 101).
    #[rstest::rstest]
    #[case::with_a_password(
        "single-map-binding-with-password-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "CFN_AUTHENTICATION_RULE    FAIL"
    )]
    #[case::with_a_password_and_no_type_entry(
        "single-map-binding-without-type-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "CFN_AUTHENTICATION_RULE    FAIL"
    )]
    #[case::without_a_password(
        "single-map-binding-without-password-template.yaml",
        StatusCode::SUCCESS,
        "CFN_AUTHENTICATION_RULE    PASS"
    )]
    fn a_filter_through_a_single_map_binding_tests_the_map_itself_as_the_wildcard_does(
        #[case] template: &str,
        #[case] expected_code: i32,
        #[case] verdict: &str,
    ) {
        let (status_code, stdout, stderr) =
            validate_both_streams("filter_through_a_single_map_binding.guard", template);

        assert_eq!(
            expected_code, status_code,
            "{template}: the rule applies to the one map and its verdict is the exit code; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(verdict),
            "{template}: the filter selected the map itself, so the when gate applies, got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "{template}: no selection was lost, so nothing is announced; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// A filter through a variable bound to a function's result, or to a map written out in the rules
    /// file, is read as a filter through a key-bound variable is. The bound map holds a non-null
    /// scalar entry (`Version`) and the predicate names `Statement`, a key none of its map-valued
    /// entries holds, so the map is one object: the filter tests the map itself, as the authored
    /// `[*]` does, `Statement exists` holds on it, the map is selected and `!empty` passes. The verdict
    /// is the one the `[*]` spelling of the same filter gives, read from `CONTROL_STAR_SPELLING` in the
    /// same file, and each subject file exits 0. The key spelling with no `[*]`
    /// (`CONTROL_KEY_SPELLING`, in `control_key_spelling_over_the_policy_doc.guard`, run apart so that
    /// the subject files stay clean) walks the map's entries instead, names a key of the map itself,
    /// and is refused: FAIL at exit 19 with the sentence that points the author at `X[*] { Key ==
    /// value }` and `X[*].Key == value`. Nothing is announced for either binding or for the control:
    /// no selection was lost, so there is no notice to write.
    #[rstest::rstest]
    #[case::function_result(
        "filter_through_a_function_result_binding.guard",
        "POLICY_HAS_A_STATEMENT"
    )]
    #[case::literal_map(
        "filter_through_a_literal_map_binding.guard",
        "LITERAL_POLICY_HAS_A_STATEMENT"
    )]
    fn a_filter_through_a_function_result_or_literal_binding_tests_the_map_itself(
        #[case] rules: &str,
        #[case] bound_rule: &str,
    ) {
        let (status_code, stdout, stderr) =
            validate_both_streams(rules, "bound-map-from-a-function-or-literal-template.yaml");

        // A summary line is `<rules file path>/<rule>    <verdict>`: two tokens, the first ending in
        // the rule's name. The report lines below the summary also name the rule, in other shapes.
        let verdict_of = |rule: &str| -> Option<String> {
            stdout.lines().find_map(|line| {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                match tokens.as_slice() {
                    [path, verdict] if path.ends_with(&format!("/{}", rule)) => {
                        Some((*verdict).to_string())
                    }
                    _ => None,
                }
            })
        };
        let bound = verdict_of(bound_rule);
        let star_control = verdict_of("CONTROL_STAR_SPELLING");
        assert_eq!(
            Some("PASS".to_string()),
            bound,
            "{rules}: the filter through the variable selects the one-object map, so `!empty` passes\n{stdout}"
        );
        assert_eq!(
            star_control, bound,
            "{rules}: the filter through the variable answers as the authored `[*]` spelling does\n{stdout}"
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "{rules}: both rules pass, so the subject file exits 0:\n{}\n{}",
            stdout,
            stderr
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "{rules}: no selection was lost, so nothing is announced; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );

        // The control, run apart: the key spelling with no `[*]` names a key of the map itself and
        // is refused.
        let (control_code, control_stdout, control_stderr) = validate_both_streams(
            "control_key_spelling_over_the_policy_doc.guard",
            "bound-map-from-a-function-or-literal-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            control_code,
            "{rules}: the key spelling with no `[*]` is refused, which is the exit code; stdout {:?}",
            control_stdout
        );
        assert_eq!(
            Some("FAIL".to_string()),
            rule_status_line(&control_stdout, "CONTROL_KEY_SPELLING"),
            "{rules}: the key spelling with no `[*]` names a key of the map itself and is refused\n{control_stdout}"
        );
        assert!(
            control_stdout.contains("Write `X[*] { Key == value }` or `X[*].Key == value`"),
            "{rules}: the refusal of the key spelling points at the `[*]` spellings, got {:?}",
            control_stdout
        );
        assert!(
            !control_stdout.contains("DEPRECATION") && !control_stderr.contains("DEPRECATION"),
            "{rules}: a refusal is answered in the report, not announced; stdout {:?} stderr {:?}",
            control_stdout,
            control_stderr
        );
    }

    /// A variable bound to a function's result and a variable bound to a map written out in the rules
    /// file, over a map that is a collection: two sub-maps, no scalar entry, every entry carrying
    /// `Sid`. `Sid !exists` rejects every entry, nothing is kept, and the predicate holds on the map by
    /// absence, so each filter loses its selection. Each `when` gate does not apply (both rules SKIP at
    /// exit 0) and each site is announced once. The function result's notice names the map by the
    /// path it was parsed from and the `let` as written, `let doc = json_parse(...)`; the literal's
    /// notice names the `let` as `let policy = { ... }` and does not repeat the literal's body.
    #[test]
    fn a_walking_filter_through_a_function_result_or_literal_binding_is_announced_by_its_binding() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "walking_filter_through_a_function_result_or_literal_binding.guard",
            "bound-collection-from-a-function-or-literal-template.yaml",
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both gates see an empty selection and do not apply; stdout {:?}",
            stdout
        );
        for rule in [
            "WALKING_PARSED_POLICY_HAS_NO_SID",
            "WALKING_LITERAL_POLICY_HAS_NO_SID",
        ] {
            assert_eq!(
                Some("SKIP".to_string()),
                rule_status_line(&stdout, rule),
                "{rule}: the filter kept nothing, so the gate does not apply; stdout {:?}",
                stdout
            );
        }
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(
            2,
            notices.len(),
            "one notice per filter site, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        let parsed: Vec<&&str> = notices
            .iter()
            .filter(|n| n.contains("let doc = json_parse(Resources.Q.Properties.PolicyText)"))
            .collect();
        assert_eq!(
            1,
            parsed.len(),
            "one notice names the function result's binding as written, got {:?}",
            notices
        );
        assert!(
            parsed[0].contains("the map parsed from /Resources/Q/Properties/PolicyText"),
            "the function result's notice names the path the map was parsed from, got {:?}",
            parsed[0]
        );
        let literal: Vec<&&str> = notices
            .iter()
            .filter(|n| n.contains("let policy = { ... }"))
            .collect();
        assert_eq!(
            1,
            literal.len(),
            "one notice names the literal's binding as written, got {:?}",
            notices
        );
        assert!(
            !literal[0].contains("\"Read\"") && !literal[0].contains("\"Write\""),
            "the literal's notice elides the literal's body, got {:?}",
            literal[0]
        );
    }

    /// Two bindings that hold the same one map, one by plain key descent and one through a projection
    /// that then descends a key. Each is filtered with a predicate that names a key of the map itself
    /// over entries that are all scalars. The map is one object, so both filters test the map
    /// itself, select it, and the rule's body fails as a comparison against the value "Enabled": a
    /// plain FAIL at exit 19 with no refusal sentence (nothing names `X` or "a key of the map
    /// itself") and no notice, because nothing was lost. The author's own `[*]` spelling of the same
    /// filter (`control_star_spelling`) fails the same way. The literal `Outer.Config[ Status ==
    /// 'Enabled' ]` is the one spelling that stays refused for its own key. cfn-guard 3.2.1 reads
    /// the variable spelling the same way: `%m[ Status == 'Enabled' ] !empty` passes over
    /// `{ Status: Enabled }`.
    #[test]
    fn both_spellings_over_one_map_test_the_map_alike() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_over_a_projected_binding.guard",
            "same-map-two-binding-spellings.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the two sub-map rules and the scalar-entry rules fail on the value they compare; stdout {:?}",
            stdout
        );
        for rule in [
            "filter_over_a_direct_scalar_entry_binding",
            "filter_over_a_projected_scalar_entry_binding",
            "control_star_spelling",
        ] {
            assert_eq!(
                Some("FAIL".to_string()),
                rule_status_line(&stdout, rule),
                "{rule}: the map's entries are all scalars, so the filter tests the map itself under every spelling and the body's comparison fails; stdout {:?}",
                stdout
            );
        }
        assert!(
            !stderr.contains("DEPRECATION") && !stdout.contains("DEPRECATION"),
            "the map is tested as one object and nothing was lost, so nothing is announced; the `Nested` pair \
             never held on its map, so nothing was lost there either; got stderr {:?}",
            stderr
        );
        for refusal in [
            "where `X` is",
            "a key of the map itself",
            "Could not be evaluated",
        ] {
            assert!(
                !stdout.contains(refusal),
                "a plain comparison failure carries no refusal text; found {:?} in stdout {:?}",
                refusal,
                stdout
            );
        }
        for (rule, path) in [
            (
                "filter_over_a_direct_scalar_entry_binding",
                "/Outer/Config/Status",
            ),
            (
                "filter_over_a_projected_scalar_entry_binding",
                "/Wrapper/Only/Config/Status",
            ),
            ("control_star_spelling", "/Outer/Config/Status"),
        ] {
            let property = format!("Property [{}] in data [", path);
            let rule_part = format!("is not compliant with [{}] because ", rule);
            assert!(
                stdout
                    .lines()
                    .any(|line| line.contains(&property) && line.contains(&rule_part)),
                "{rule}: the finding names the key's own path {path}, got stdout {:?}",
                stdout
            );
        }
    }

    /// A binding that holds several maps, filtered through the variable with a predicate that holds on
    /// exactly one of them, is read per map. The instance's `Properties` map holds scalar entries
    /// (`ImageId`, `InstanceType`) and the predicate names `ImageId`, a key none of the map's
    /// map-valued entries holds, so that map is one object: the filter tests it as a whole, as
    /// `%props[*][ ... ]` does, selects it, and the rule's body compares its `ImageId` to a value it
    /// does not have and FAILs at exit 19. The role's `Properties` map has no scalar entry and no
    /// `ImageId`, so the predicate does not hold on it and it is not selected. Nothing is announced.
    ///
    /// The second template is the registry's password shape. Its `Metadata` resource has no
    /// `Properties`, so the projection also yields an unresolved value beside the two maps; the rule
    /// is SKIP at exit 0 and no notice goes out there either. The notice for a binding that holds
    /// several maps, one of which has no scalar entry and keeps the walk, is pinned by the
    /// once-per-site cells below, which use the `Metadata` projection fixtures.
    #[rstest::rstest]
    #[case::instance_properties_with_an_image(
        "two-properties-maps-one-with-image-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "FILTER_THROUGH_A_KEY_TAILED_PROJECTION    FAIL"
    )]
    #[case::a_resource_without_properties_beside_them(
        "single-map-binding-with-password-template.yaml",
        StatusCode::SUCCESS,
        "FILTER_THROUGH_A_KEY_TAILED_PROJECTION    SKIP"
    )]
    fn a_filter_through_a_binding_that_held_several_maps_reads_each_map_as_the_wildcard_does(
        #[case] template: &str,
        #[case] expected_code: i32,
        #[case] verdict: &str,
    ) {
        let (status_code, stdout, stderr) =
            validate_both_streams("filter_through_a_key_tailed_projection.guard", template);
        assert_eq!(expected_code, status_code, "stdout {:?}", stdout);
        assert!(
            stdout.contains(verdict),
            "{template}: expected the summary to carry {:?}, got {:?}",
            verdict,
            stdout
        );
        if expected_code == StatusCode::VALIDATION_ERROR {
            assert!(
                stdout.contains("/Resources/EC2I4LBA1/Properties/ImageId")
                    && !stdout.contains("/Resources/RootRole/Properties/ImageId")
                    && !stdout.contains("Could not be evaluated"),
                "{template}: the body failed on the instance's own ImageId and nothing was refused, got {:?}",
                stdout
            );
        }
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "{template}: no selection was lost, so nothing is announced; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// A projecting binding read with the author's own `[*]` before the filter: `%b[*][ ... ]`. The
    /// reader walks the author's `[*]` whatever the binding did, and the held map is a role's
    /// Properties, maps and lists only, with no scalar entry, so by shape alone it is a collection. The
    /// predicate names `AssumeRolePolicyDocument`, a key the Properties map holds itself and none of its
    /// entries holds: a filter after a wildcard selects among members, and no member carries that key,
    /// so the filter is refused in both polarities, with the sentence a filter after a key is refused
    /// with, naming the key and the spellings that read the map itself (`X[*] { Key == value }`,
    /// `X[*].Key == value`), and the gated rule FAILs at exit 19. A
    /// refusal is a verdict in the report, not a notice, so nothing is announced. Between this and the
    /// previous release, which tested the map as a whole and ran the body, the author's `[*]` expanded
    /// the map into its entries, the filter selected nothing, the rule was SKIP at exit 0, and the lost
    /// selection was announced with this filter named: the one shape where an own-key filter after a
    /// wildcard was reported on stderr alone.
    #[test]
    fn a_filter_with_an_authored_star_over_a_projecting_binding_is_refused_by_name_and_not_announced(
    ) {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_with_an_authored_star_on_a_projecting_binding.guard",
            "role-with-all-map-properties-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a refusal fails the gated rule, stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("AUTHORED_STAR_ON_A_PROJECTING_BINDING    FAIL"),
            "got {:?}",
            stdout
        );
        // The console summary prints a refusal's explanation whole, behind the condition site's wrapper
        // and the `Unevaluatable` sentence's own: the key's sentence, the spellings, the definition of
        // `X` and the path all show, whatever the length of the query. (Every other message is cut at
        // `reporters::validate::common::LONGEST_RECORDED_MESSAGE`.)
        assert!(
            stdout.contains("`[*]` then no kept entry holds a key the predicate names")
                && stdout.contains("`Key` is `AssumeRolePolicyDocument`, a key of the map itself."),
            "the refusal opens with the wildcard and names the key, got {:?}",
            stdout
        );
        assert!(
            stdout.contains("where `X` is `%b`"),
            "the definition of `X` shows in the console summary in a `when` condition, got {:?}",
            stdout
        );
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(
            0,
            notices.len(),
            "a refusal is a verdict, not a notice, got {:?}",
            notices
        );
    }

    /// The notice for a filter through a binding that lost its map still reaches the `%b[*][ ... ]`
    /// shape, and the text names the author's `[*]`. The predicate names no key of the Properties map
    /// (`Nope !exists`), so the map is the collection its shape says and nothing is refused; the
    /// predicate holds on the map itself by a miss, anchored by nothing, and the map is not a uniform
    /// collection the predicate is about (its `Policies` entry is a list), so the pass is one the
    /// previous release selected the map on. The walk now selects the entries the predicate holds on in
    /// the map's place, the gate opens over them, the body runs and the rule PASSes at exit 0, and the
    /// lost selection is announced once with the filter spelled as the author wrote it, `%b[*][ ... ]`.
    /// This is the cell that pins the notice gate for an authored star, since the refusal cell above
    /// ends in the `AllIndices` arm before any notice logic runs.
    #[test]
    fn a_filter_with_an_authored_star_over_a_projecting_binding_held_by_a_miss_is_announced() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_with_an_authored_star_on_a_projecting_binding_held_by_a_miss.guard",
            "role-with-all-map-properties-template.yaml",
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the gate opens over the selected entries and the body passes, stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("AUTHORED_STAR_HELD_BY_A_MISS    PASS"),
            "got {:?}",
            stdout
        );
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        // Two readings announce the one site, as they do at every `%var[*][ f ]` site both can read
        // (`the_member_notice_quiet_record_is_keyed_by_provenance_and_kind`'s double-notice note): the
        // bound-map notice, for the filter through the binding that lost its map, and the member notice
        // for the filter after the author's `[*]`, whose predicate held on the Properties map only by the
        // absence of `Nope` and now selects among its entries. Until the member notice announced a hold
        // by absence this cell drew the bound-map notice alone.
        assert_eq!(
            2,
            notices.len(),
            "the bound-map notice and the member notice for the one filter site, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        let bound_map = notices
            .iter()
            .find(|notice| {
                notice.contains("did not select the map at /Resources/RootRole/Properties")
            })
            .copied()
            .unwrap_or_else(|| panic!("no bound-map notice among {:?}", notices));
        assert!(
            bound_map.contains("the filter `%b[*][ ")
                && bound_map
                    .contains("filter_with_an_authored_star_on_a_projecting_binding_held_by_a_miss.guard, line:"),
            "the bound-map notice names the filter with the author's `[*]`, the map that lost its selection and the line, got {:?}",
            bound_map
        );
        let member = notices
            .iter()
            .find(|notice| notice.contains("the filter after `[*]` at "))
            .copied()
            .unwrap_or_else(|| panic!("no member notice among {:?}", notices));
        assert!(
            member.contains("names `Nope`, a key the value at path /Resources/RootRole/Properties")
                && member.contains("where it held because no entry named `Nope` exists at that value")
                && member.contains("keeps 2 of them")
                && member.contains("Write `%b.Nope !exists` to ask that value for the key's absence, or `%b.*.Nope`"),
            "the member notice names the absent key, the hold by absence, the two entries kept and both spellings (the key asked through the variable, never bare), got {:?}",
            member
        );
    }

    /// A one-object filter whose predicate names a `%variable` bound to a query the run never read is
    /// not refused: the probe reads the binding quietly, `Kind == %k` fails on a Cfg with no `Kind`, the
    /// one-object reading does not hold, and `empty` passes at exit 0, as it does with `let k = 'k'`.
    /// The binary-level twin of the in-crate row (the parameterized and literal `%k` rows of the
    /// one-object probe tests), so a change to what the probe leaves unread cannot flip this verdict
    /// without a validate cell going red: the reading where the unread `%k` left `Owner !exists` to hold
    /// alone refused this filter at exit 19 and made the verdict turn on evaluation order.
    #[test]
    fn a_one_object_filter_through_a_query_bound_variable_the_run_never_read_is_not_refused() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "one_object_filter_through_a_query_bound_variable.guard",
            "one_object_cfg_beside_a_parameter.yaml",
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both rules pass over a selection of nothing, stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
        // The console pads rule names to one column, so the verdict is read per line, not by a fixed
        // run of spaces.
        let passes = |rule: &str| {
            stdout
                .lines()
                .any(|line| line.contains(&format!("/{rule}")) && line.trim_end().ends_with("PASS"))
        };
        assert!(
            passes("QUERY_BOUND_K_NEVER_READ") && passes("LITERAL_K"),
            "got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("Could not be evaluated"),
            "nothing is refused: the quietly read `%k` fails `Kind == %k` on a Cfg with no `Kind`, got {:?}",
            stdout
        );
    }

    /// A predicate that held on a named map only by a miss at the map's own first key selects the map
    /// when the map is one object, and nothing is announced.
    ///
    /// `let m = Resources.Metadata` with `%m[ Type == 'AWS::S3::Bucket' or Properties.Tags empty ]`: the
    /// `Type` clause resolves and fails, the `Properties.Tags empty` clause holds because `Metadata` has no
    /// `Properties`. `Metadata` holds a scalar `Type` beside its authentication sub-map and the predicate
    /// names no key the sub-map holds, so the map is one object: the filter tests it as a whole, as
    /// `%m[*][ ... ]` does, the second clause holds on it, and `Metadata` itself is selected. The `when`
    /// over the selection applies and the body compares the map's own `Type`, an authentication type and
    /// no bucket, so the rule FAILs at exit 19. The verdict is the one the previous release gave; what
    /// changed is that the filter through the variable and the filter after `[*]` select the same map,
    /// so there is no lost selection to name and stderr stays empty.
    #[test]
    fn a_filter_held_by_a_miss_at_a_named_maps_first_key_selects_the_map_and_is_not_announced() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_with_a_vacuous_disjunct.guard",
            "single-map-binding-with-password-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the when over the selected map applies and the body fails; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("FILTER_WITH_A_VACUOUS_DISJUNCT    FAIL"),
            "got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "the map is selected, so no selection was lost; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// A filter whose selection is one level DOWN from the map rather than nothing: `%p` holds one map
    /// with a scalar entry (`Name`) beside an `Inner` entry that is a map, and `Name` is also a key of
    /// `Inner`. The map is mixed (a scalar beside a map that holds the predicate's key), so the filter
    /// walks the entries as the literal `Properties[ Name exists ]` does: the scalar is passed over,
    /// `Inner` is selected, and `%p[ Name exists ]` selects `Inner`, not the map. Both rules read past
    /// the filter, so both compare `Inner` and not the map: `.Tags exists` fails on `Inner` (as it
    /// would on the map); `.Name == 'b'` compares `Inner`'s `b` alone, the map's `Name` string being a
    /// scalar entry the filter passes over, so it passes. The predicate holds by presence, not by
    /// absence, so the literal spelling is not refused either, and the walk's selection stands with
    /// no notice. Before the mixed shape took the literal reading, each filter was announced once as
    /// having not selected the map and having selected one entry in its place; neither is now. The
    /// cells below assert that no notice is written.
    #[test]
    fn a_filter_whose_selection_moved_down_is_announced() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_moved_down_to_an_entry.guard",
            "two-level-properties-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the Tags rule fails on Inner; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("MOVED_DOWN_TAGS    FAIL")
                && stdout.contains("MOVED_DOWN_NAME    PASS"),
            "the Tags rule fails on Inner, the Name rule passes on Inner's `b` with the Name string passed over; got {:?}",
            stdout
        );
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(
            0,
            notices.len(),
            "the mixed shape is never announced; got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stdout.contains("Could not be evaluated"),
            "the predicate holds by presence, so nothing is refused or announced in the report; got {:?}",
            stdout
        );
    }

    /// A filter whose predicate names another rule, and one whose predicate names a variable, over a
    /// map whose entries are scalars, so the walk never runs the predicate and the probe would be the
    /// first to. The probe is skipped for such predicates, because a named rule is evaluated by the
    /// root scope with its events and its own notices, and a variable first resolved there goes the
    /// same way: no notice, and the named rule's record appears exactly once in the verbose tree, at
    /// the top level where the file evaluates it. Both rules FAIL on the unresolved scalar entries.
    ///
    /// Red before the skip: the variable-naming filter was announced, through the probe resolving
    /// `%wanted` by way of the root scope.
    #[test]
    fn a_filter_whose_predicate_reaches_outside_the_map_is_not_announced() {
        let (status_code, stdout, stderr) = validate_both_streams_verbose(
            "filter_predicate_reaching_outside_the_map.guard",
            "same-map-two-binding-spellings.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "a predicate the probe cannot run quietly is not announced; got stderr {:?}",
            stderr
        );
        assert_eq!(
            1,
            stdout.matches("Rule(inner,").count(),
            "the named rule is evaluated once, at the top level, and never by the probe; got {:?}",
            stdout
        );
    }

    /// The filtered name is bound to another variable: `let a = Resources.Metadata` then `let b = %a`
    /// then `%b[ ... ]`. The notice names the `let` the author wrote for `b`, `let b = %a`, not the
    /// query at the end of the chain -- `let b = Resources.Metadata` is not a line in the file, and an
    /// author told to rebind it would look for it in vain. Red before this: the notice printed the chain's
    /// end. The template leaves the scalar `Type` entry out of the `Metadata` map, so the map has no
    /// scalar entry. The predicate, `testBasic !exists`, names no key the map holds itself (the
    /// authentication block holds `testBasic`), so the filter keeps the walk: the one entry carries the
    /// key and is rejected, nothing is kept, and the predicate holds on the map by absence, which is a
    /// lost selection. A predicate that names the map's own key is one object and draws no notice
    /// (`a_filter_through_a_chained_binding_or_a_parameter_tests_the_map_itself`, and the cells of
    /// `a_chained_binding_or_a_parameter_over_a_map_without_a_scalar_tests_the_map_itself`).
    #[test]
    fn a_filter_through_a_chained_binding_names_the_let_as_written() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "walking_filter_through_a_chained_binding.guard",
            "single-map-binding-without-type-template.yaml",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "stdout {:?}", stdout);
        assert!(
            stdout.contains("FILTER_THROUGH_A_CHAINED_BINDING    SKIP"),
            "the when gate does not apply once the filter selects nothing, got {:?}",
            stdout
        );
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(1, notices.len(), "got {:?}", notices);
        assert!(
            notices[0].contains("which `let b = %a` held")
                && !notices[0].contains("let b = Resources"),
            "the notice names the let as written, got {:?}",
            notices[0]
        );
    }

    /// The same two spellings over the template that keeps the scalar `Type` entry in the `Metadata`
    /// map: the filtered name bound to another variable (`let b = %a`), and a parameterized rule's
    /// parameter bound to `Resources.Metadata` at the call site. Either way the variable holds one map
    /// with a non-null scalar entry and the predicate names no key its map-valued entry holds, so the
    /// map is one object: the filter tests it as a whole, as `%b[*][ ... ]` does, selects it, and the
    /// rule applies. The password makes the body fail, so each rule FAILs at exit 19 and names the
    /// password's path. Nothing is announced: no selection was lost.
    #[rstest::rstest]
    #[case::chained_binding(
        "filter_through_a_chained_binding.guard",
        "FILTER_THROUGH_A_CHAINED_BINDING"
    )]
    #[case::parameter("filter_through_a_parameter.guard", "FILTER_THROUGH_A_PARAMETER")]
    fn a_filter_through_a_chained_binding_or_a_parameter_tests_the_map_itself(
        #[case] rules: &str,
        #[case] rule: &str,
    ) {
        let (status_code, stdout, stderr) =
            validate_both_streams(rules, "single-map-binding-with-password-template.yaml");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{rules}: the rule applies to the one map and fails on its password; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(&format!("{rule}    FAIL"))
                && stdout.contains(
                    "/Resources/Metadata/AWS::CloudFormation::Authentication/testBasic/password["
                ),
            "{rules}: the rule fails on the password under the selected map, got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "{rules}: no selection was lost, so nothing is announced; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// The same two fixtures over the template whose `Metadata` map has NO scalar entry: it holds the
    /// authentication block alone, and the predicate names that block, a key of the map itself that
    /// none of its map-valued entries holds. The map is one object here too, so the filter tests the
    /// map as a whole, holds, and selects it, and the rule FAILs at exit 19 on the password under the
    /// selected map. Nothing is announced and nothing is refused. The walk and its notice are drawn
    /// by the `walking_*` fixtures (`a_filter_through_a_chained_binding_names_the_let_as_written`,
    /// `a_filter_through_a_parameter_names_the_parameter_and_its_rule`).
    #[rstest::rstest]
    #[case::chained_binding(
        "filter_through_a_chained_binding.guard",
        "FILTER_THROUGH_A_CHAINED_BINDING"
    )]
    #[case::parameter("filter_through_a_parameter.guard", "FILTER_THROUGH_A_PARAMETER")]
    fn a_chained_binding_or_a_parameter_over_a_map_without_a_scalar_tests_the_map_itself(
        #[case] rules: &str,
        #[case] rule: &str,
    ) {
        let (status_code, stdout, stderr) =
            validate_both_streams(rules, "single-map-binding-without-type-template.yaml");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{rules}: the rule applies to the one map and fails on its password; stdout {:?}",
            stdout
        );
        assert_eq!(
            Some("FAIL".to_string()),
            rule_status_line(&stdout, rule),
            "{rules}: the gate opens on the selected map and the body fails; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(
                "/Resources/Metadata/AWS::CloudFormation::Authentication/testBasic/password"
            ),
            "{rules}: the rule fails on the password under the selected map, got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("Could not be evaluated"),
            "{rules}: the filter is not refused; got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "{rules}: no selection was lost, so nothing is announced; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// A clause grounded by a key that resolved before a nested filter that selected nothing:
    /// `%b[ Properties.Tags[ Key == 'Owner' ] empty ]` on a bucket with tags but no Owner tag. The
    /// clause holds on the bucket for real -- `Properties.Tags` is there, and no element of it has the
    /// key. The bucket holds a scalar `Type`, and the predicate's first key, `Properties`, is not a key
    /// of any of the bucket's map-valued entries, so the bucket is one object: the filter tests it as a
    /// whole, as `%b[*][ ... ]` does, the clause holds on it, and the bucket itself is selected, as the
    /// previous release selected it. The gate applies, the body fails on the missing Owner tag
    /// (exit 19), and nothing is announced: no selection was lost, so the grounding of a nested filter
    /// inside the predicate has no notice to gate here.
    #[test]
    fn a_filter_whose_clause_resolved_a_key_before_a_nested_filter_selects_the_bucket_itself() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_with_a_nested_filter_in_its_predicate.guard",
            "two-tagged-resources-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the gate opens on the selected bucket and the body fails; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("BUCKET_HAS_AN_OWNER_TAG    FAIL"),
            "the when gate applies once the filter selects the bucket, got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("/Resources/Bucket/Type"),
            "the body's comparison of the selection's own `Type` passes, since the bucket itself was \
             selected, so the report does not name it as failed; the tags clause is the failure, got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "the bucket is selected, so no selection was lost; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// A filter through a named-map binding whose predicate is an all-key absence check selects the
    /// map itself when the map is one object: `%b[ Properties.Tags !exists ]` on a bucket with
    /// `Properties` and no `Tags`. The bucket holds a scalar `Type`, and `Properties` is not a key of
    /// any of its map-valued entries, so the filter tests the bucket as a whole, as `%b[*][ ... ]`
    /// does: the check holds on it (`Properties` resolves and `Tags` does not), the bucket is selected
    /// in the same place the previous release selected it, the `when` gate over the selection applies,
    /// and the body fails on the missing `Tags` (exit 19). Nothing is announced: no selection was lost.
    #[test]
    fn a_filter_through_a_named_map_whose_absence_check_held_on_the_map_selects_the_map_itself() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_with_an_absence_check_in_its_predicate.guard",
            "bucket-without-tags-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the gate opens on the selected bucket and the body fails; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("BUCKET_HAS_TAGS    FAIL"),
            "the when gate applies once the filter selects the bucket, got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("/Resources/Bucket/Type"),
            "the body's comparison of the selection's own `Type` passes, since the bucket itself was \
             selected, so the report does not name it as failed; the tags clause is the failure, got {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "the bucket is selected, so no selection was lost; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// The population reached through an alias chain, or passed as a parameter, answers over a template
    /// with no resources as the direct `let r = Resources` does: the selection is empty, the rule is not
    /// applicable, the run exits 0 and prints nothing.
    ///
    /// The alias chain is read as the population although `r`'s own query is `%all` and not a key, so
    /// `let all = Resources` then `let r = %all` with
    /// `%r.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b'` over `{}` or over
    /// `{"Resources":{}}` SKIPs at exit 0 as the direct spelling does, and so does `check(%r)`, a
    /// parameterized rule passed the alias, which records the population at its call site through the
    /// same question. Read instead as a retrieval failure the operator decides, the empty selection
    /// would FAIL at exit 19, and a `!exists` or `empty` assertion over it would PASS. The direct
    /// spelling is the control. The `!exists` and `empty` rows pin the other direction: through the
    /// alias those assertions are not applicable over the absent collection, as the direct spelling's
    /// are. Nothing is printed on
    /// either stream for any row: these documents hold no map a `%r.*[ ... ]` could lose, so no notice is
    /// in play here (the `%r[ ... ]` spelling, which does reach the notice, is pinned in the evaluator's
    /// `an_alias_chain_to_the_population_is_followed_from_every_scope` and in the not-announced table).
    #[test]
    fn the_population_through_an_alias_chain_exits_zero_over_no_resources_as_the_direct_spelling_does(
    ) {
        const CLAUSE: &str = "%r.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b'";
        // The `!exists` and `empty` spellings over the same selection are the ones the README names as
        // moving from PASS to not applicable through the alias: an absent collection read as a retrieval
        // failure satisfied them, read as the population it is an empty selection they do not apply to.
        const ABSENT: &str = "%r.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName !exists";
        const EMPTY: &str = "%r.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags empty";
        let rules = [
            ("direct", format!("let r = Resources\nrule r {{ {CLAUSE} }}")),
            (
                "alias chain",
                format!("let all = Resources\nlet r = %all\nrule r {{ {CLAUSE} }}"),
            ),
            (
                "parameter passed the alias",
                "let all = Resources\nlet r = %all\nrule check(x) { %x.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b' }\nrule r { check(%r) }".to_string(),
            ),
            (
                "direct, !exists",
                format!("let r = Resources\nrule r {{ {ABSENT} }}"),
            ),
            (
                "alias chain, !exists",
                format!("let all = Resources\nlet r = %all\nrule r {{ {ABSENT} }}"),
            ),
            (
                "direct, empty",
                format!("let r = Resources\nrule r {{ {EMPTY} }}"),
            ),
            (
                "alias chain, empty",
                format!("let all = Resources\nlet r = %all\nrule r {{ {EMPTY} }}"),
            ),
        ];
        let documents = [r#"{}"#, r#"{"Resources":{}}"#];
        for (label, rule) in &rules {
            for document in documents {
                let payload = format!(
                    r#"{{"data": [{}], "rules": [{}]}}"#,
                    serde_json::to_string(document).unwrap(),
                    serde_json::to_string(rule).unwrap()
                );
                let run = || {
                    let mut reader =
                        Reader::new(ReadCursor(Cursor::new(payload.clone().into_bytes())));
                    let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                        .expect("Failed to create writer.");
                    let status_code = ValidateTestRunner::default()
                        .payload()
                        .run(&mut writer, &mut reader);
                    assert_eq!(
                        StatusCode::SUCCESS,
                        status_code,
                        "{} over {}: the population has nothing to select from, so the rule is not applicable",
                        label,
                        document
                    );
                    writer
                };
                let out = run().stripped().expect("failed to read stdout");
                let err = run().err_to_stripped().expect("failed to read stderr");
                assert!(
                    out.is_empty() && err.is_empty(),
                    "{} over {}: a run with nothing to check prints nothing:\nstdout:\n{}\nstderr:\n{}",
                    label,
                    document,
                    out,
                    err
                );
            }
        }
    }

    /// A comparison over an empty collection inside a parameterized rule's body reports what the same
    /// comparison reports at the top level. `%cfg.Sizes == 50` over an empty `Sizes` fails as a missing
    /// key does (KNOWN_ISSUES.md item 9: "The value is an empty collection, so there was nothing to
    /// compare, and an empty collection fails as a missing key does"), at exit 19 with nothing on
    /// stderr; the body is evaluated through the scope that binds `cfg`, and the verdict and the empty
    /// stderr come back through it unchanged. The control is the same clause written at the top level.
    /// A notice raised inside a parameterized rule's body reaching stderr is pinned by
    /// `a_filter_through_a_parameter_names_the_parameter_and_its_rule`.
    #[rstest::rstest]
    #[case(
        "vacuous_comparison_inside_a_parameterized_rule.guard",
        "VACUOUS_COMPARISON_INSIDE_A_PARAMETERIZED_RULE    FAIL"
    )]
    #[case(
        "vacuous_comparison_at_the_top_level.guard",
        "VACUOUS_COMPARISON_AT_THE_TOP_LEVEL    FAIL"
    )]
    fn a_notice_raised_inside_a_parameterized_rule_reaches_stderr(
        #[case] rules_file: &str,
        #[case] verdict_line: &str,
    ) {
        let (status_code, stdout, stderr) =
            validate_both_streams(rules_file, "empty-sizes-under-a-key-template.yaml");
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "a comparison over an empty collection fails, inside the rule body as at the top level; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(verdict_line)
                && stdout.contains(
                    "The value is an empty collection, so there was nothing to compare, and an empty \
                     collection fails as a missing key does"
                ),
            "the rule fails with the empty-collection reason, got {:?}",
            stdout
        );
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert!(
            notices.is_empty(),
            "an empty collection fails rather than passing with a notice, got {:?} from stderr {:?}",
            notices,
            stderr
        );
    }

    /// A filter through a projecting binding whose predicate names a key the map holds itself, over
    /// `Metadata` maps with no scalar entry. The instance's map holds the authentication block and an
    /// init block, and the predicate, `"AWS::CloudFormation::Authentication" exists`, names the first:
    /// a key of the map itself that none of its map-valued entries holds. The map is one object, so the
    /// filter tests it as a whole, the predicate holds, and the map is selected: the `when` gate opens
    /// and the body's `username` comparison fails the rule at exit 19. Over the template whose instance
    /// holds only an init block no map holds the key, nothing is selected and the rule is SKIP at exit
    /// 0. Neither template writes a notice, and nothing is refused. cfn-guard 3.2.1 gives the same two
    /// verdicts over these templates (FAIL at exit 19, SKIP at exit 0).
    #[rstest::rstest]
    #[case::with_the_authentication_block(
        "metadata-maps-authentication-and-init-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "FAIL"
    )]
    #[case::without_the_authentication_block(
        "metadata-maps-init-without-authentication-template.yaml",
        StatusCode::SUCCESS,
        "SKIP"
    )]
    fn a_filter_through_a_metadata_projection_tests_each_map_itself(
        #[case] template: &str,
        #[case] expected_code: i32,
        #[case] verdict: &str,
    ) {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_through_a_metadata_projection_as_one_object.guard",
            template,
        );
        assert_eq!(
            expected_code, status_code,
            "{template}: the exit code follows the rule's verdict; stdout {:?}",
            stdout
        );
        assert_eq!(
            Some(verdict.to_string()),
            rule_status_line(
                &stdout,
                "FILTER_THROUGH_A_METADATA_PROJECTION_AS_ONE_OBJECT"
            ),
            "{template}: the filter tests each map as a whole; stdout {:?}",
            stdout
        );
        if verdict == "FAIL" {
            assert!(
                stdout.contains("/Resources/EC2I4LBA1/Metadata")
                    && stdout.contains("no-such-user-zzz")
                    && !stdout.contains("Could not be evaluated"),
                "{template}: the body failed on the instance's own block, nothing was refused; stdout {:?}",
                stdout
            );
        }
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "{template}: the map is tested as one object and nothing was lost; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// One filter site, two data files whose matching resource has a different logical id, one
    /// structured report: the notice names a different map for each file, so the texts differ, and a
    /// set keyed by text wrote two lines for one filter. The structured validate reporters keep the
    /// once-per-site reading across data files by `(kind, site)`, as the test command does across
    /// cases: one line, the first file's. Red before: two lines, naming `/Resources/EC2I4LBA1/Metadata`
    /// and `/Resources/Instance/Metadata`. The filter is `testBasic !exists`. The maps it loses are
    /// the instances' `Metadata` maps, which have no scalar entry and keep the walk: the authentication
    /// block carries `testBasic` and is no member, the init block is selected in its place. The role's
    /// map holds one sub-map that lacks the key, a uniform population that draws no notice. A map with
    /// a scalar entry is one object and draws no notice either. The gate opens on the sub-maps selected,
    /// so both files exit 0.
    #[rstest::rstest]
    #[case("json")]
    #[case("junit")]
    fn a_site_notice_is_written_once_across_data_files_in_a_structured_report(
        #[case] output: &str,
    ) {
        let run = || {
            let mut reader = Reader::default();
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let status_code = ValidateTestRunner::default()
                .data(vec![
                    "metadata-maps-authentication-and-init-template.yaml",
                    "metadata-maps-authentication-and-init-other-id-template.yaml",
                ])
                .rules(vec!["filter_through_a_metadata_projection.guard"])
                .structured()
                .output_format(Some(output))
                .run(&mut writer, &mut reader);
            (status_code, writer)
        };
        let (status_code, _) = run();
        let (_, err_writer) = run();
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files exit 0: the gate opens on the selected sub-maps"
        );

        let stderr = err_writer.err_to_stripped().expect("failed to read stderr");
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(
            1,
            notices.len(),
            "one line for one filter site across two data files, got {:?} from stderr {:?}",
            notices,
            stderr
        );
        assert!(
            notices[0].contains("/Resources/EC2I4LBA1/Metadata"),
            "the first file's text is the one kept, got {:?}",
            notices[0]
        );
    }

    /// Runs the single-line `validate` output over `rules` and several data files and returns the exit
    /// code and the `DEPRECATION` lines and `NOTE:` trailers on stderr, in the order they were written;
    /// `is_trailer` tells the two apart.
    fn single_line_notices_across(rules: &str, data: Vec<&str>) -> (i32, Vec<String>) {
        let (status_code, stderr) = single_line_stderr_across(rules, data);
        let notices = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION") || is_trailer(l))
            .map(str::to_string)
            .collect();
        (status_code, notices)
    }

    /// Runs the single-line `validate` output over `rules` and several data files and returns the exit
    /// code and the whole of stderr, escape sequences removed, for a cell that reads more than the
    /// deprecation lines: the order of the notice lines against the other lines the run writes there.
    fn single_line_stderr_across(rules: &str, data: Vec<&str>) -> (i32, String) {
        single_line_stderr_across_with_parameters(rules, data, vec![])
    }

    /// `single_line_stderr_across` with input-parameter files passed as `-i`.
    fn single_line_stderr_across_with_parameters(
        rules: &str,
        data: Vec<&str>,
        parameters: Vec<&str>,
    ) -> (i32, String) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ValidateTestRunner::default()
            .data(data)
            .rules(vec![rules])
            .input_parameters(parameters)
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        (status_code, stderr)
    }

    /// Whether a line is the trailer the single-line output writes after its last data file, naming the
    /// later files that drew a notice the run announced once: a `NOTE:` line, its own kind, so a count of
    /// `DEPRECATION:` lines never includes it.
    fn is_trailer(line: &str) -> bool {
        line.starts_with("NOTE:")
    }

    /// A rule's notice is written once across the data files of one single-line run, while a file's
    /// own warning is written once per file: the two kinds of line on stderr follow two different
    /// rules, and one run shows both.
    ///
    /// The notice for a filter site describes the rule, so the set the single-line path carries writes
    /// it beside the first file that drew it and not again for the second (the cell above). A duplicate
    /// key is a fact about one data file, so its warning is that file's own and is written beside each
    /// file that holds one: two files each with a key written twice, two warning lines. Both files here
    /// hold the same two resources as the pair the filter-site cell runs, plus one key written twice,
    /// so the one filter site draws one notice and each file draws one warning. Red if the notice set
    /// ever swallowed the per-file warnings (one warning line) or wrote the notice per file (two notice
    /// lines). The run ends with the trailer naming the second file as one that drew the announced
    /// site; that line is a `NOTE:` line, so the count of `DEPRECATION:` lines is one with or without it.
    /// The filter is `testBasic !exists`; the maps it loses are the instances' `Metadata` maps, which
    /// have no scalar entry and keep the walk.
    #[test]
    fn a_rule_notice_is_written_once_and_a_file_warning_once_per_file_in_the_single_line_output() {
        let (status_code, stderr) = single_line_stderr_across(
            "filter_through_a_metadata_projection.guard",
            vec![
                "metadata-maps-authentication-and-init-duplicate-key-template.yaml",
                "metadata-maps-authentication-and-init-other-id-duplicate-key-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files exit 0 (the gate opens on the selected sub-maps):\n{}",
            stderr
        );
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("DEPRECATION:"))
            .collect();
        let trailers: Vec<&str> = stderr.lines().filter(|l| is_trailer(l)).collect();
        let duplicate_key_warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning: duplicate key "))
            .collect();
        assert_eq!(
            1,
            notices.len(),
            "one notice line for the one filter site across two data files:\n{}",
            stderr
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the one site the second file drew too:\n{}",
            stderr
        );
        assert!(
            trailers[0].contains(
                "metadata-maps-authentication-and-init-other-id-duplicate-key-template.yaml"
            ) && trailers[0].contains("the filter notice"),
            "the trailer names the second file and the filter notice:\n{}",
            trailers[0]
        );
        assert_eq!(
            2,
            duplicate_key_warnings.len(),
            "one duplicate-key warning per data file, two files:\n{}",
            stderr
        );
        assert!(
            duplicate_key_warnings[0].contains("/Resources/EC2I4LBA1/Properties/InstanceType")
                && duplicate_key_warnings[1]
                    .contains("/Resources/Instance/Properties/InstanceType"),
            "each warning names its own file's duplicate, in file order:\n{}",
            stderr
        );
    }

    /// The same two data files through the single-line output, which writes each file's notices beside
    /// that file's report: one line for the one filter site, the first file's text, and nothing for
    /// the second file. The notice is aimed at the author of a rule, and `validate -d dir/` over a
    /// directory of templates reached that author once per template for each filter: a near-identical
    /// line per file, differing only in the logical id of the map it names. The single-line path now
    /// keeps the once-per-site reading across the data-file loop, as the structured reporters and the
    /// test command do. Red before: two lines, naming `/Resources/EC2I4LBA1/Metadata` and then
    /// `/Resources/Instance/Metadata`. What the second file keeps is a trailer after the loop: one
    /// line naming the later files that drew a notice the run announced once, and which notice, so the
    /// reader of the run still learns that the second file hit the same site. The trailer says which
    /// kind of notice it refers to ("the filter notice") because one site can hold notices of two kinds.
    /// The filter is `testBasic !exists`; the maps it loses are the instances' `Metadata` maps, which
    /// have no scalar entry and keep the walk. The gate opens on the sub-maps selected, so both files
    /// exit 0.
    #[test]
    fn a_site_notice_is_written_once_across_data_files_in_the_single_line_output() {
        let (status_code, notices) = single_line_notices_across(
            "filter_through_a_metadata_projection.guard",
            vec![
                "metadata-maps-authentication-and-init-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files exit 0: the gate opens on the selected sub-maps"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            1,
            lines.len(),
            "one line for one filter site across two data files, got {:?}",
            notices
        );
        assert!(
            lines[0].contains("/Resources/EC2I4LBA1/Metadata")
                && lines[0].contains("filter_through_a_metadata_projection.guard, line:13,"),
            "the first file's text is the one kept, and it names the site, got {:?}",
            lines[0]
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the one repeated site, got {:?}",
            notices
        );
        assert!(
            trailers[0].starts_with("NOTE: also drawn by ")
                && trailers[0].contains("the filter notice for the site at Location[file:")
                && trailers[0].contains("filter_through_a_metadata_projection.guard, line:13,")
                && trailers[0]
                    .contains("metadata-maps-authentication-and-init-other-id-template.yaml")
                && !trailers[0].contains("metadata-maps-authentication-and-init-template.yaml"),
            "the trailer is a note naming the second file only, and the filter notice at its site, \
             got {:?}",
            trailers[0]
        );
        assert_eq!(
            1,
            notices
                .iter()
                .filter(|n| n.starts_with("DEPRECATION:"))
                .count(),
            "a count of DEPRECATION: lines is the one notice, unchanged by the trailer, got {:?}",
            notices
        );
    }

    /// The trailer names a repeated key-filter containment notice by its kind.
    ///
    /// A once-per-site notice is named in the trailer by its kind and site, and each kind has its words.
    /// The containment notice is drawn when a key filter's string right-hand value and a key stand in a
    /// containment that the equality reading does not select: here the tag `Env` against an allowlist
    /// read from the template that holds `Environment`, a strict containment, so the notice is drawn
    /// whether or not the two readings are compared more finely. Two templates carry the tag under
    /// different logical ids, so the second draws the notice the first announced, and the trailer names
    /// the second file and "the key-filter containment notice" at the filter's site. This is the cell
    /// that asserts those words: a kind the trailer could not name would be a compile error, but a kind
    /// named wrongly is not.
    #[test]
    fn the_trailer_names_the_containment_notice_by_its_kind() {
        let (status_code, notices) = single_line_notices_across(
            "tags_allowed_by_containment.guard",
            vec![
                "env-tag-first-template.yaml",
                "env-tag-second-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "both files fail: the tag `Env` is no longer selected by containment"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            1,
            lines.len(),
            "one containment notice for one filter site across two data files, got {:?}",
            notices
        );
        assert!(
            lines[0].contains("no longer selects the key `Env`")
                && lines[0].contains("contained in `Environment`")
                && lines[0].contains("tags_allowed_by_containment.guard, line:6,"),
            "the notice names the key, the string it is contained in and the site, got {:?}",
            lines[0]
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the one site the second file drew too, got {:?}",
            notices
        );
        assert!(
            trailers[0].contains("the key-filter containment notice for the site at Location[file:")
                && trailers[0].contains("tags_allowed_by_containment.guard, line:6,")
                && trailers[0].contains("env-tag-second-template.yaml")
                && !trailers[0].contains("env-tag-first-template.yaml"),
            "the trailer names the second file only, and the containment notice by its kind at its \
             site, got {:?}",
            trailers[0]
        );
    }

    /// A plain notice, one recorded with no site, whose text does not vary with the template is also
    /// written once across the data files of one single-line run, beside the first file that drew it.
    /// The set the single-line path now carries collapses plain notices once per distinct text, as the
    /// structured reports always did, for the reason the once-per-site collapse holds: the notice
    /// describes the rule, not the data, and one line per run is the rule author's view. Before the set,
    /// the line was written beside each file: two lines over these two templates. What the second file
    /// keeps is the same trailer a repeated site gets: one line after the run naming the second file and
    /// the notice it drew, by the notice's opening words, since a plain notice has no site to name. The
    /// trailer's reason, that a reader of a multi-file run can tell which files hit a notice the run
    /// announced once, holds for both collapses, so both get it.
    #[test]
    fn a_plain_notice_with_one_text_is_written_once_across_data_files_in_the_single_line_output() {
        let (status_code, notices) = single_line_notices_across(
            "incomparable_membership_clause.guard",
            vec![
                "incomparable-membership-template.yaml",
                "incomparable-membership-other-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the clause still passes in this release over both files"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            1,
            lines.len(),
            "one line for one plain notice text across two data files, got {:?}",
            notices
        );
        assert!(
            lines[0].contains("could not be compared with any element")
                && lines[0].contains("Name"),
            "the once-written line is the incomparable-membership notice, got {:?}",
            lines[0]
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the one repeated plain notice, got {:?}",
            notices
        );
        let opening = lines[0]
            .trim_start_matches("DEPRECATION:")
            .split_whitespace()
            .take(8)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            trailers[0].contains("incomparable-membership-other-template.yaml")
                && trailers[0].contains(&format!(
                    "the notice opening \"{opening} ...\" at Location[file:"
                ))
                && trailers[0].contains("incomparable_membership_clause.guard, line:14,")
                && !trailers[0].contains("incomparable-membership-template.yaml"),
            "the trailer names the second file only and the notice by its opening words and its \
             position, got {:?}",
            trailers[0]
        );
    }

    /// A moved-reading warning is written once per data file and is never trailed.
    ///
    /// The trailer exists for the notices the run announces once: a later data file that drew one gets
    /// no line of its own, so the trailer names it. The moved-reading warning is kept per data file
    /// instead, so a later file whose reading moved gets its own line beside its own report, and there
    /// is nothing for a trailer to name. Two templates whose readings both moved through one key filter
    /// print two `Warning:` lines, each naming its file and its own maps, and no `NOTE:` line: a
    /// trailer naming the second file for the warning would say the file was not told, when it was.
    #[test]
    fn a_moved_reading_warning_is_written_per_data_file_and_never_trailed() {
        let (status_code, stderr) = single_line_stderr_across(
            "captures/key_filter_function_argument_two_resources.guard",
            vec![
                "captures/key-filter-function-argument-resource-wanted-template.yaml",
                "captures/key-filter-function-argument-two-resources-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files pass on the maps' own values:\n{}",
            stderr
        );
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("Warning:"))
            .collect();
        assert_eq!(
            2,
            warnings.len(),
            "one warning per data file whose reading moved, got:\n{}",
            stderr
        );
        assert!(
            warnings[0].contains("resource-wanted-template.yaml, where")
                && warnings[1].contains("two-resources-template.yaml, where")
                && warnings[1].contains("1 more map"),
            "each line names its own file and counts that file's maps, in run order:\n{}",
            stderr
        );
        assert!(
            !stderr.lines().any(is_trailer) && !stderr.lines().any(|l| l.starts_with("NOTE:")),
            "a warning the later file got its own line for is not trailed, got:\n{}",
            stderr
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "the maps answered, so nothing fell back, got:\n{}",
            stderr
        );
    }

    /// Two plain notices of one kind are told apart in the trailer. The incomparable-membership notice
    /// opens with the clause as written and ends with the clause's position, so two clauses written the
    /// same way in one rules file draw two notices whose first words are the same and whose texts differ
    /// at the tail alone. Both are drawn again by the second template, so both land in one trailer (same
    /// later file); the trailer quotes each by its opening words AND the position it ends with, so the
    /// two descriptions differ. Red before: the opening words alone, and the trailer read the same
    /// description twice.
    #[test]
    fn two_plain_notices_of_one_kind_are_told_apart_in_the_trailer() {
        let (status_code, notices) = single_line_notices_across(
            "two_incomparable_membership_clauses.guard",
            vec![
                "incomparable-membership-template.yaml",
                "incomparable-membership-other-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both clauses still pass in this release over both files"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            2,
            lines.len(),
            "one line per clause, the two texts differing in their position alone, got {:?}",
            notices
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer, both notices drawn again by the same later file, got {:?}",
            notices
        );
        let (_, described) = trailers[0]
            .split_once(": the notice")
            .unwrap_or_else(|| panic!("no notice described in the trailer: {:?}", trailers[0]));
        let descriptions: Vec<&str> = described.split("; ").collect();
        assert_eq!(
            2,
            descriptions.len(),
            "two descriptions on the one line, got {:?}",
            trailers[0]
        );
        assert!(
            descriptions[0] != descriptions[1]
                && descriptions.iter().all(|d| {
                    d.contains("at Location[file:")
                        && d.contains("two_incomparable_membership_clauses.guard, line:")
                })
                && descriptions[0].contains("line:9,") != descriptions[1].contains("line:9,"),
            "the two descriptions differ by the position each notice ends with, got {:?}",
            trailers[0]
        );
    }

    /// A site first drawn by a LATER data file is written when that file is reached: the first file
    /// draws nothing (its `Metadata` maps hold no authentication block, so every entry of every map
    /// lacks `testBasic`, each map's entries are selected, and no selection is lost), the second draws
    /// the projection filter's notice, and the run writes exactly that one line, naming the second
    /// file's map. The three cells around this one all draw every notice from the first file, so a
    /// path that wrote only the first file's lines would have passed them; this one pins that the set
    /// across the loop admits a site whenever it is new, not only at the first file. One file drew the
    /// site, so no trailer follows. Both files exit 0: the gate opens on the sub-maps selected.
    #[test]
    fn a_site_notice_first_drawn_by_a_later_data_file_is_written() {
        let (status_code, notices) = single_line_notices_across(
            "filter_through_a_metadata_projection.guard",
            vec![
                "metadata-maps-init-without-authentication-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files exit 0: the gate opens on the selected sub-maps"
        );
        assert_eq!(
            1,
            notices.len(),
            "one line for the one site, drawn by the second file alone, got {:?}",
            notices
        );
        assert!(
            notices[0].contains("/Resources/Instance/Metadata")
                && notices[0].contains("filter_through_a_metadata_projection.guard, line:13,"),
            "the second file's text names its own map and the site, got {:?}",
            notices[0]
        );
    }

    /// A site drawn by more than one data file is announced once, beside the first file, and the run
    /// ends with one trailer for that site naming the later files that drew it too, so a reader of a
    /// multi-file run can tell which files hit a site after the first without the notice being
    /// repeated beside each of them. Two sites here: the `testBasic !exists` predicate loses its
    /// selection on both templates (the authentication block carries the key and is no member) and the
    /// `config !exists` predicate on the second alone (only its instance holds an init block, which
    /// carries `config`). So two notices, one per site, each the text of the first file that drew it,
    /// and exactly one trailer, for the authentication site, naming the second file and not the first;
    /// the init site, drawn once, gets none. The trailer is a `NOTE:` line: a notice, so the library
    /// entry drops it from a failure text as it drops the notices, and not a deprecation, so a count
    /// of `DEPRECATION:` lines stays at the two notices. The maps the filters lose are the instances'
    /// `Metadata` maps, which have no scalar entry and keep the walk. Both files exit 0: each gate
    /// opens on the sub-maps selected.
    #[test]
    fn a_site_repeated_across_data_files_gets_one_trailer_naming_the_later_files() {
        let (status_code, notices) = single_line_notices_across(
            "filter_through_two_metadata_sites_one_hit_later.guard",
            vec![
                "metadata-maps-authentication-without-init-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files exit 0: each gate opens on the selected sub-maps"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            2,
            lines.len(),
            "one notice per site across two data files, got {:?}",
            notices
        );
        let authentication_site = "filter_through_two_metadata_sites_one_hit_later.guard, line:11,";
        let init_site = "filter_through_two_metadata_sites_one_hit_later.guard, line:14,";
        assert!(
            lines.iter().any(|n| {
                n.contains(authentication_site) && n.contains("/Resources/Box/Metadata")
            }) && lines
                .iter()
                .any(|n| n.contains(init_site) && n.contains("/Resources/Instance/Metadata")),
            "each site's line is the first file's text that drew it, got {:?}",
            lines
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the one repeated site, got {:?}",
            notices
        );
        let trailer = trailers[0];
        assert!(
            trailer.starts_with("NOTE: also drawn by ")
                && trailer.contains("the filter notice for the site at Location[file:")
                && trailer.contains(authentication_site)
                && trailer.contains("metadata-maps-authentication-and-init-other-id-template.yaml")
                && !trailer.contains("metadata-maps-authentication-without-init-template.yaml")
                && !trailer.contains(init_site),
            "the trailer is a note naming the repeated site and only the files after its first, \
             got {:?}",
            trailer
        );
        assert_eq!(
            2,
            notices
                .iter()
                .filter(|n| n.starts_with("DEPRECATION:"))
                .count(),
            "a count of DEPRECATION: lines is the two notices, unchanged by the trailer, got {:?}",
            notices
        );
        assert_eq!(
            Some(trailer),
            notices.last(),
            "the trailer comes after every file's report, got {:?}",
            notices
        );
    }

    /// The control for `a_site_notice_is_written_once_across_data_files_in_the_single_line_output`:
    /// the dedup is by site, not by run. Two filter sites in one rules file over the same two data
    /// files write two lines, one per site, each naming the first file's map; a reading that kept one
    /// line per run, or one per text, would not produce exactly these two. Both sites are drawn by both
    /// files, so both are owed a trailer naming the second file, and since the files are the same the
    /// two go into one trailer line that lists both sites: one line per distinct list of later files,
    /// not one per site, so ten sites drawn by the same later files read on one line rather than the
    /// same file list ten times. Both rules gate on `testBasic !exists`, whose gate opens on the
    /// sub-maps selected, so both files exit 0.
    #[test]
    fn two_filter_sites_write_two_lines_across_data_files_in_the_single_line_output() {
        let (status_code, notices) = single_line_notices_across(
            "filter_through_two_metadata_projections.guard",
            vec![
                "metadata-maps-authentication-and-init-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "both files exit 0: the gates open on the selected sub-maps"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            2,
            lines.len(),
            "one line per filter site across two data files, got {:?}",
            notices
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the two sites the same later file drew, got {:?}",
            notices
        );
        assert!(
            trailers[0].contains("metadata-maps-authentication-and-init-other-id-template.yaml")
                && !trailers[0].contains("metadata-maps-authentication-and-init-template.yaml")
                && trailers[0]
                    .matches("the filter notice for the site at Location[file:")
                    .count()
                    == 2,
            "the one trailer names the second file and the filter notice at each of the two sites, \
             got {:?}",
            trailers[0]
        );
        // The lines come out in text order, which is not site order, so each site is looked up rather
        // than read by position.
        for line in ["line:9,", "line:12,"] {
            let site = format!("filter_through_two_metadata_projections.guard, {line}");
            let at_site: Vec<&&String> = lines.iter().filter(|n| n.contains(&site)).collect();
            assert_eq!(
                1,
                at_site.len(),
                "one line for the site at {line} got {:?}",
                notices
            );
            assert!(
                at_site[0].contains("/Resources/EC2I4LBA1/Metadata"),
                "the site's line is the first file's text, got {:?}",
                at_site[0]
            );
            assert!(
                trailers[0].contains(&site),
                "the trailer names the site at {line}, got {:?}",
                trailers[0]
            );
        }
    }

    /// The trailer is written when a later data file's evaluation stops the run with a rules-file
    /// error. The loop over the data files reports before it propagates, by design (the comment above
    /// `eval_rules_file` in the loop), and the trailer is part of what the run reports: files 1 and 2
    /// draw the filter site, file 3 holds the resource that opens a `when` whose body names a variable
    /// no `let` declares, and the run stops there with exit 5. Red before: the error left the function
    /// from inside the loop, before the trailer loop, so the two files' repeated site was recorded and
    /// never written. Now the first error ends the loop, the trailers for the sites recorded so far are
    /// written, and then the error is returned: the trailer is on stderr before the rules-file error
    /// line that `evaluate_rule` writes, and names the second file alone, since the third drew no
    /// notice.
    #[test]
    fn the_trailer_is_written_before_a_later_files_evaluation_error_is_propagated() {
        let (status_code, stderr) = single_line_stderr_across(
            "filter_through_a_metadata_site_then_a_gated_undeclared_name.guard",
            vec![
                "metadata-maps-authentication-and-init-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
                "metadata-maps-with-a-trigger-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::PARSING_ERROR,
            status_code,
            "the third file reaches a name no `let` declares, which exits 5; stderr {:?}",
            stderr
        );
        let lines: Vec<&str> = stderr.lines().collect();
        let notices: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with("DEPRECATION:"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            1,
            notices.len(),
            "one line for the one filter site, drawn by the first two files, got {:?}",
            stderr
        );
        let trailer = lines
            .iter()
            .position(|l| is_trailer(l))
            .unwrap_or_else(|| panic!("no trailer on stderr: {:?}", stderr));
        let error = lines
            .iter()
            .position(|l| l.starts_with("Error handling rule file"))
            .unwrap_or_else(|| panic!("no rules-file error on stderr: {:?}", stderr));
        assert!(
            trailer < error,
            "the trailer (line {trailer}) is written before the rules-file error (line {error}): {:?}",
            stderr
        );
        assert!(
            lines[trailer].contains("metadata-maps-authentication-and-init-other-id-template.yaml")
                && !lines[trailer].contains("metadata-maps-authentication-and-init-template.yaml")
                && !lines[trailer].contains("metadata-maps-with-a-trigger-template.yaml")
                && lines[trailer].contains("the filter notice for the site at Location[file:")
                && lines[trailer].contains(
                    "filter_through_a_metadata_site_then_a_gated_undeclared_name.guard, line:10,"
                ),
            "the trailer names the second file alone, and the filter notice at its site, got {:?}",
            lines[trailer]
        );
    }

    /// The trailer is written when a later data file's merge with the input parameters fails, the other
    /// exit that ended the loop before the trailers. Files 1 and 2 draw the filter site; file 3 holds a
    /// top-level `Parameters` key, as the `-i` file does, so merging the two refuses the duplicate key
    /// before anything in file 3 is evaluated, and the run stops there. The trailer for the site, naming
    /// file 2 alone, is on stderr before the error goes back. Red before: the merge's `?` left the loop
    /// from its first line, and the two files' repeated site was recorded and never written.
    #[test]
    fn the_trailer_is_written_before_a_later_files_parameter_merge_error_is_propagated() {
        let (status_code, stderr) = single_line_stderr_across_with_parameters(
            "filter_through_a_metadata_projection.guard",
            vec![
                "metadata-maps-authentication-and-init-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
                "two-properties-maps-with-parameters-template.yaml",
            ],
            vec!["input-parameters-dir/db_params.yaml"],
        );
        assert_eq!(
            StatusCode::INTERNAL_FAILURE,
            status_code,
            "the third file's `Parameters` collides with the input parameters' on merge; stderr {:?}",
            stderr
        );
        let lines: Vec<&str> = stderr.lines().collect();
        let notices: Vec<&&str> = lines
            .iter()
            .filter(|l| l.starts_with("DEPRECATION:"))
            .collect();
        assert_eq!(
            1,
            notices.len(),
            "one line for the one filter site, drawn by the first two files, got {:?}",
            stderr
        );
        let trailer = lines
            .iter()
            .find(|l| is_trailer(l))
            .unwrap_or_else(|| panic!("no trailer on stderr: {:?}", stderr));
        assert!(
            trailer.contains("metadata-maps-authentication-and-init-other-id-template.yaml")
                && !trailer.contains("metadata-maps-authentication-and-init-template.yaml")
                && !trailer.contains("two-properties-maps-with-parameters-template.yaml")
                && trailer.contains("the filter notice for the site at Location[file:")
                && trailer.contains("filter_through_a_metadata_projection.guard, line:13,"),
            "the trailer names the second file alone, and the filter notice at its site, got {:?}",
            trailer
        );
    }

    /// Two groups whose shortened file lists would read the same stay shortened and are told apart by
    /// the first name where they differ. Six templates over two sites: the first draws both, the next
    /// three draw both, the fifth draws the authentication-block site alone and the sixth the
    /// init-block site alone. The two sites' later-file lists share their first three names and their
    /// count and differ in the last file, so shortened they would both read "<three names> and 1 more".
    /// Each still names three files and counts the fourth, and adds the one name its list lacks and the
    /// other's holds (`not <the other site's own template>`), so the line stays bounded whatever the
    /// directory's size; a run over two hundred templates is pinned in the command's own unit cell. This
    /// cell once asserted the opposite shape, every file named in full and no count, and carried that
    /// shape in its name; that reading made the trailer's length grow with the directory, which is the
    /// line the count exists to prevent. The sites are `testBasic !exists` and `config !exists`; each
    /// rejects the block that carries its key, so the maps the filters lose are the instances'
    /// `Metadata` maps, which have no scalar entry and keep the walk. A template whose only block
    /// lacks the key (`testBasic` in the init-only template, `config` in the authentication-only
    /// one) selects that block, a uniform population, and draws no notice at that site. Every gate
    /// opens on the sub-maps selected, so every file exits 0.
    #[test]
    fn two_groups_whose_shortened_file_lists_would_read_the_same_stay_short_and_are_told_apart() {
        let (status_code, notices) = single_line_notices_across(
            "filter_through_authentication_and_init_sites.guard",
            vec![
                "metadata-maps-authentication-and-init-fourth-id-template.yaml",
                "metadata-maps-authentication-and-init-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
                "metadata-maps-authentication-and-init-third-id-template.yaml",
                "metadata-maps-authentication-without-init-template.yaml",
                "metadata-maps-init-without-authentication-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "every file exits 0: each gate opens on the selected sub-maps"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            2,
            lines.len(),
            "one line per site, both drawn by the first file, got {:?}",
            notices
        );
        assert_eq!(
            2,
            trailers.len(),
            "one trailer per later-file list, the two lists differing in their last file, got {:?}",
            notices
        );
        // Each trailer is found by its site; the file it lacks is what names it apart, so the
        // image-site trailer is the one that says "not <the instance-type-only template>".
        for (site, own, lacking) in [
            (
                "line:12,",
                "metadata-maps-authentication-without-init-template.yaml",
                "metadata-maps-init-without-authentication-template.yaml",
            ),
            (
                "line:15,",
                "metadata-maps-init-without-authentication-template.yaml",
                "metadata-maps-authentication-without-init-template.yaml",
            ),
        ] {
            let trailer = trailers
                .iter()
                .find(|t| {
                    t.contains(&format!(
                        "filter_through_authentication_and_init_sites.guard, {site}"
                    ))
                })
                .unwrap_or_else(|| panic!("no trailer for the site at {site}: {:?}", trailers));
            let (files, _) = trailer
                .split_once(": the filter notice")
                .unwrap_or_else(|| panic!("no notice named in the trailer: {:?}", trailer));
            assert!(
                files.starts_with("NOTE: also drawn by ")
                    && files.contains("metadata-maps-authentication-and-init-template.yaml")
                    && files
                        .contains("metadata-maps-authentication-and-init-other-id-template.yaml")
                    && files
                        .contains("metadata-maps-authentication-and-init-third-id-template.yaml")
                    && files.contains(" and 1 more, not ")
                    && files.ends_with(lacking)
                    && !files.contains(own)
                    && !files.contains("fourth-id"),
                "the trailer names three later files, counts the fourth, and says which file it \
                 lacks that the other list holds, got {:?}",
                trailer
            );
        }
    }

    /// The trailer is bounded: it names at most three of the later files and counts the rest, with the
    /// exact count. The case the trailer exists for, `validate -d dir/` over a directory of templates
    /// that all hit one `let`, would otherwise end in a line listing every template after the first,
    /// which is the line trained to be skipped the once-per-site collapse removed, in a new form. Five
    /// templates over one filter site: one notice, one trailer naming the second, third and fourth files
    /// in run order and "and 1 more" for the fifth, which is not named.
    #[test]
    fn a_trailer_names_at_most_three_later_files_and_counts_the_rest() {
        let (status_code, notices) = single_line_notices_across(
            "filter_through_a_metadata_projection.guard",
            vec![
                "metadata-maps-authentication-and-init-template.yaml",
                "metadata-maps-authentication-and-init-other-id-template.yaml",
                "metadata-maps-authentication-without-init-template.yaml",
                "metadata-maps-authentication-and-init-third-id-template.yaml",
                "metadata-maps-authentication-and-init-fourth-id-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "every file exits 0: the gate opens on the selected sub-maps"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            1,
            lines.len(),
            "one line for one filter site across five data files, got {:?}",
            notices
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the one site, got {:?}",
            notices
        );
        // The files come before the first notice named; the names are read by their position in that
        // part, since the runner hands the files over by path.
        let (files, _) = trailers[0]
            .split_once(": the filter notice")
            .unwrap_or_else(|| panic!("no notice named in the trailer: {:?}", trailers[0]));
        let position = |name: &str| {
            files
                .find(name)
                .unwrap_or_else(|| panic!("{name} is not named in {:?}", files))
        };
        assert!(
            position("metadata-maps-authentication-and-init-other-id-template.yaml")
                < position("metadata-maps-authentication-without-init-template.yaml")
                && position("metadata-maps-authentication-without-init-template.yaml")
                    < position("metadata-maps-authentication-and-init-third-id-template.yaml")
                && files.ends_with(" and 1 more")
                && !files.contains("fourth-id")
                && !files.contains("metadata-maps-authentication-and-init-template.yaml"),
            "the trailer names three later files in run order and counts the fourth, got {:?}",
            trailers[0]
        );
    }

    /// Two notices of two kinds at one site are told apart in the trailer. The kinds that can share a
    /// `FileLocation` on this tree are the two directions of the function-result gate notice: a `when`
    /// whose buckets move both ways records one notice per direction under the same `when` site (the
    /// filter notice sits at its predicate's first clause and the list-argument notice at its call, so
    /// neither can share a location with a `when` clause or with each other). Over two templates shaped
    /// alike under different logical ids, both files draw both notices from the one site; the two
    /// notices are written once each, beside the first file, and the one trailer (same later file for
    /// both) names the second file and both notices, each with its direction, so a reader can tell
    /// which of the two lines above each refers to. A trailer that carried the site alone would print
    /// the same text for both.
    #[test]
    fn two_kinds_of_notice_at_one_site_are_told_apart_in_the_trailer() {
        let (status_code, notices) = single_line_notices_across(
            "gate_moving_both_ways.guard",
            vec![
                "gate-moving-both-ways-template.yaml",
                "gate-moving-both-ways-other-ids-template.yaml",
            ],
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the `Kind: y` buckets run the block and fail its clause in both files"
        );
        let (trailers, lines): (Vec<&String>, Vec<&String>) =
            notices.iter().partition(|n| is_trailer(n));
        assert_eq!(
            2,
            lines.len(),
            "one line per direction at the one `when`, each the first file's text, got {:?}",
            notices
        );
        assert!(
            lines.iter().any(|n| {
                n.contains("its block ran before and is skipped now")
                    && n.contains("for the resource at /Resources/X1")
            }) && lines.iter().any(|n| {
                n.contains("its block was skipped before and runs now")
                    && n.contains("for the resource at /Resources/Y1")
            }),
            "each direction's line is the first file's, naming its first moved bucket, got {:?}",
            lines
        );
        assert_eq!(
            1,
            trailers.len(),
            "one trailer for the one later file, got {:?}",
            notices
        );
        assert!(
            trailers[0].contains("gate-moving-both-ways-other-ids-template.yaml")
                && trailers[0].contains(
                    "the gate notice (its block ran before and is skipped now) for the site at \
                     Location[file:"
                )
                && trailers[0].contains(
                    "the gate notice (its block was skipped before and runs now) for the site at \
                     Location[file:"
                )
                && trailers[0]
                    .matches("gate_moving_both_ways.guard, line:12,")
                    .count()
                    == 2
                && !trailers[0].contains("gate-moving-both-ways-template.yaml"),
            "the trailer names the second file and both notices at the one site by their direction, \
             got {:?}",
            trailers[0]
        );
    }

    /// The filtered name is a parameterized rule's parameter. There is no `let` for it, so the notice
    /// says which parameter of which rule, and what the call site bound it to, and its rewrite talks
    /// about the call rather than a `let`. Red before this: the notice printed `let m = Resources.Metadata`.
    ///
    /// The template leaves the scalar `Type` entry out of the `Metadata` map, so the map has no scalar
    /// entry. The predicate, `testBasic !exists`, names no key the map holds itself (the authentication
    /// block holds `testBasic`), so the filter keeps the walk: the one entry carries the key and is
    /// rejected, nothing is kept, and the predicate holds on the map by absence, which is a lost
    /// selection. A predicate that names the map's own key is one object, the filter selects it and
    /// there is no notice (`a_filter_through_a_chained_binding_or_a_parameter_tests_the_map_itself`).
    ///
    /// The verdict is the engine's: the walk selected nothing, so the `when` gate over the selection
    /// does not apply (SKIP) where a filter that tested the map as one value would have held on it.
    /// That move is what the notice is for. The notice site is reached at retrieval for any clause
    /// and does not hold the operator, so the runtime line names the moved selection, says once which
    /// way a verdict moves (the fail-open direction, except on the selection itself under `!empty`,
    /// which fails where it passed, and under a `when ... empty` gate, which now opens), and points to
    /// the per-operator table in the known-issues notes, which carry the provenance of the old
    /// reading (cfn-guard 3.2.1 read the bound map as one value; the per-operator table says which
    /// rows it was run on). An earlier text stated the old verdicts per operator at runtime and
    /// sorted them on whether the first key was one the map held, which was wrong for an `empty` gate
    /// (SKIP -> the rule runs, not SKIP) and for a key read below the selection, which is not
    /// applicable under every operator now (`.Missing !exists` PASS -> SKIP, not "SKIP where it
    /// failed"). This cell pins one marker per sentence, never the paragraph.
    #[test]
    fn a_filter_through_a_parameter_names_the_parameter_and_its_rule() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "walking_filter_through_a_parameter.guard",
            "single-map-binding-without-type-template.yaml",
        );
        assert_eq!(StatusCode::SUCCESS, status_code, "stdout {:?}", stdout);
        assert!(
            stdout.contains("FILTER_THROUGH_A_PARAMETER    SKIP"),
            "the walk selected nothing, so the gate over the selection does not apply; got {:?}",
            stdout
        );
        let notices: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("DEPRECATION"))
            .collect();
        assert_eq!(1, notices.len(), "got {:?}", notices);
        assert!(
            notices[0].contains(
                "which the parameter `m` of rule `has_no_test_basic`, bound to `Resources.Metadata` held"
            ) && notices[0].contains("pass `has_no_test_basic` one")
                && !notices[0].contains("let m ="),
            "the notice names the parameter, its rule and the call-site query, got {:?}",
            notices[0]
        );
        // One sentence-level marker per sentence of the lost-selection text, never the paragraph: the
        // moved selection, the one sentence on the direction, and the pointer to the per-operator table.
        for marker in [
            "The filter kept no member where the previous release selected the map itself, so a \
             clause over that selection reads a selection of nothing.",
            "Where a verdict moves it moves in the fail-open direction, except under an operator \
             applied directly to the selection: `!empty` fails where it passed, a `when ... empty` \
             gate now opens, a `when` gate on a named rule over the selection moves with that rule, \
             and a `count()` of the selection reads the entries kept.",
            "The per-operator table is in docs/KNOWN_ISSUES.md under `filter-through-a-variable`.",
        ] {
            assert!(
                notices[0].contains(marker),
                "the notice says {:?}, got {:?}",
                marker,
                notices[0]
            );
        }
        assert!(
            notices[0].contains("In the previous release a filter through a variable"),
            "the notice keeps the sentence on what the previous release selected, got {:?}",
            notices[0]
        );
        // The per-operator table and the sentences it replaced are not said at runtime.
        for gone in [
            "loosening a failure the guarded rule used to report",
            "On the selection itself, or on a key the map holds",
            "On a key the map lacks",
            "Every move that loosens a failure",
            "`empty` passes where it failed, the fail-open direction,",
            "where it compared the map's own entry",
            "by a static read of its tag",
            "where the old reading failed on the map",
            "SKIP, the fail-open direction",
            "fails on an unresolved entry",
            "such as a string, is reported unresolved",
            "KNOWN_ISSUES item 11",
            "except on the selection itself under `!empty`",
        ] {
            assert!(
                !notices[0].contains(gone),
                "the notice no longer says {:?}, got {:?}",
                gone,
                notices[0]
            );
        }
    }

    /// A projecting binding that resolves to exactly one map, filtered through the variable with a
    /// predicate that names a key of the map over scalar entries. The map is one object, so the
    /// filter tests the map itself and selects it, as the author's own `[*]` does and as cfn-guard
    /// 3.2.1 does (`!empty` passes over a map of scalars under a predicate naming its own key). The
    /// `when` gate opens and the rule fails on its body, `.Status == 'no-such-value-zzz'`, as a
    /// comparison against "Enabled" at exit 19: no refusal sentence and no notice, because the
    /// selection was not lost.
    #[test]
    fn a_filter_through_a_projecting_binding_that_held_one_map_tests_the_map_itself() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_through_a_projecting_one_map_binding.guard",
            "same-map-two-binding-spellings.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the map is selected, the gate opens and the body's comparison fails; stdout {:?}",
            stdout
        );
        assert_eq!(
            Some("FAIL".to_string()),
            rule_status_line(&stdout, "FILTER_THROUGH_A_PROJECTING_ONE_MAP_BINDING"),
            "the rule fails on its body, not on a refusal; stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("Property [/Wrapper/Only/Config/Status]")
                && stdout.contains(
                    "provided value [\"Enabled\"] did not match expected value [\"no-such-value-zzz\"]"
                ),
            "the failure is the body's comparison at the key's own path, got {:?}",
            stdout
        );
        for refusal in [
            "The filter selected nothing among the map's own entries",
            "a key of the map itself",
            "where `X` is",
            "Could not be evaluated",
        ] {
            assert!(
                !stdout.contains(refusal),
                "a map tested as one object is not refused; found {:?} in stdout {:?}",
                refusal,
                stdout
            );
        }
        assert!(
            !stderr.contains("DEPRECATION") && !stdout.contains("DEPRECATION"),
            "nothing was lost, so nothing is announced; got stderr {:?}",
            stderr
        );
    }

    /// The shapes next to the announced one, each with the verdict it has and no notice.
    ///
    /// `Resources` bound and filtered through the variable: the filter walks the resources, selects
    /// the one whose Type matches, and the rule FAILs on the password. In the previous release this
    /// selected nothing and was SKIP -- a fail-open -- so there is no earlier selection to tell the author about,
    /// and a notice here would say the opposite of what happened.
    ///
    /// The literal path `Resources.Metadata[ ... ]` is not among these rows any more: a filter after a
    /// key walks the map's entries, and this one names a key of the map itself, so it is refused rather
    /// than left to select nothing (`a_filter_on_the_literal_path_of_a_single_map_is_refused_not_announced`
    /// below has it, with no notice either way).
    ///
    /// A projecting binding, `Resources.*[ Type == ... ]`, then the filter through the variable: the
    /// binding produced the individuals, the filter tests each as a whole, and the rule FAILs. This is
    /// the rewrite the notice recommends, so it must be quiet.
    ///
    /// A single list bound by a key path: a filter over a list tests each element, through a variable
    /// or on the literal path, in the previous release and now. Measured: the list shape did not move,
    /// so it is a control rather than a second row of the notice.
    ///
    /// `Resources` filtered for a type the template does not define: the walk selects nothing and the
    /// predicate does not hold on `Resources` either, so the old reading selected nothing too. This row
    /// is the one that moves if the predicate-on-the-map condition is dropped.
    ///
    /// `Resources` filtered with an absence predicate, `%r[ Properties.Tags empty ] empty`, over a
    /// compliant template: the walk selects nothing, and `Properties.Tags empty` holds on `Resources`
    /// only vacuously, because `Resources` has no `Properties`. The previous reading selected
    /// `Resources` on that pass and failed the compliant template; this release passes it. No notice:
    /// a pass that resolved nothing against the map is not a selection an author relied on, and the
    /// notice's advice to rebind would be wrong for a rule written the way the docs recommend. This row
    /// is the one that moves if the probe counts a vacuous pass.
    ///
    /// The same population reached through an alias chain, `let all = Resources` then `let r = %all`,
    /// with the same absence predicate over the same compliant template: the notice reads the same map's
    /// entries whatever name the filter is written on, so this row is as quiet as the direct one. Red
    /// while the notice was decided from the binding's shape and `is_top_level_alias` read only the
    /// named binding's own query: `r`'s query is `%all`, not a key, so `r` was read as a named map and a
    /// compliant template drew a notice; a parameter passed `%all` was already read as the population.
    /// The verdict question still follows the chain, which the exit-code rows pin.
    #[rstest::rstest]
    #[case(
        "filter_through_a_resources_binding.guard",
        "single-map-binding-with-password-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "FILTER_THROUGH_A_RESOURCES_BINDING    FAIL"
    )]
    #[case(
        "filter_through_a_projecting_single_map_binding.guard",
        "single-map-binding-with-password-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "CFN_AUTHENTICATION_RULE    FAIL"
    )]
    #[case(
        "filter_through_a_single_list_binding.guard",
        "single-list-binding-template.yaml",
        StatusCode::SUCCESS,
        "FILTER_THROUGH_A_SINGLE_LIST_BINDING    PASS"
    )]
    #[case(
        "filter_through_a_resources_binding_matching_nothing.guard",
        "single-map-binding-with-password-template.yaml",
        StatusCode::SUCCESS,
        "FILTER_THROUGH_A_RESOURCES_BINDING_MATCHING_NOTHING    SKIP"
    )]
    #[case(
        "filter_through_resources_with_an_absence_predicate.guard",
        "two-tagged-resources-template.yaml",
        StatusCode::SUCCESS,
        "EVERY_RESOURCE_HAS_TAGS    PASS"
    )]
    // `let r = Resources` with `%r[ Properties.Tags empty ]` on a bucket that lacks tags: the walk selects
    // the untagged bucket, the rule fails on it as it should, and the predicate's pass on the `Resources`
    // map itself is vacuous: the unresolved result stops at `/Resources` itself, which
    // `path_is_strictly_below` rejects, so `note_grounding` marks nothing. The map's entries then
    // decide, and every resource is a map on which `Properties` resolves, so no notice goes out.
    #[case(
        "filter_through_resources_with_an_absence_predicate.guard",
        "bucket-without-tags-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "EVERY_RESOURCE_HAS_TAGS    FAIL"
    )]
    // The population through an alias chain, `let all = Resources` then `let r = %all`, over the
    // compliant template: the same vacuous pass on the same map, and the same entries decide it, so
    // nothing is announced, as for the direct `let r = Resources` row above; the chain's shape plays no
    // part in the notice while the map has entries (over `Resources: {}`, the next row, the binding is
    // all there is and `is_top_level_alias` follows the chain to keep the notice quiet).
    #[case(
        "filter_through_an_alias_of_the_resources_binding.guard",
        "two-tagged-resources-template.yaml",
        StatusCode::SUCCESS,
        "EVERY_RESOURCE_HAS_TAGS    PASS"
    )]
    // The same alias chain over `Resources: {}`: the map is present and empty, the filter has no entry
    // to walk and nothing to lose, the selection is empty and the rule passes; no notice. Red while the
    // quiet decision asked whether some entry resolved a key, which an empty map cannot answer.
    #[case(
        "filter_through_an_alias_of_the_resources_binding.guard",
        "empty-resources-template.yaml",
        StatusCode::SUCCESS,
        "EVERY_RESOURCE_HAS_TAGS    PASS"
    )]
    fn a_filter_through_a_binding_that_did_not_lose_its_selection_is_not_announced(
        #[case] rules: &str,
        #[case] template: &str,
        #[case] expected_status: i32,
        #[case] expected_line: &str,
    ) {
        let (status_code, stdout, stderr) = validate_both_streams(rules, template);

        assert_eq!(expected_status, status_code, "stdout {:?}", stdout);
        assert!(
            stdout.contains(expected_line),
            "expected the summary to carry {:?}, got stdout {:?}",
            expected_line,
            stdout
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "no selection was lost here, so nothing is announced; got stderr {:?}",
            stderr
        );
    }

    /// The literal-path spelling of the single-map predicate is refused, not announced.
    ///
    /// `Resources.Metadata[ "AWS::CloudFormation::Authentication" exists ... ]` filters the one map
    /// `Metadata` while naming a key of that map, which none of its entries can carry: the misreading
    /// "Metadata, when it has that key", refused the way `Resources.B1[ Type == 'X' ]` is. The rule
    /// is FAIL at the failure exit code, with the refusal naming the key in the report, where the
    /// previous release read it SKIP (the filter selected nothing, the gate did not open); it is a
    /// verdict and not a notice, so stderr carries no line for it, which is why the row is not among
    /// the not-announced controls above.
    #[test]
    fn a_filter_on_the_literal_path_of_a_single_map_is_refused_not_announced() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "filter_on_the_literal_path_of_a_single_map.guard",
            "single-map-binding-with-password-template.yaml",
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("CFN_AUTHENTICATION_RULE    FAIL"),
            "the rule fails on the refusal; got stdout {:?}",
            stdout
        );
        // The console summary prints the refusal whole: the key's sentence, both spellings, the
        // definition of `X` and the member spellings, whatever the length of the key and the query.
        assert!(
            stdout.contains("selected nothing among the map's own entries")
                && stdout.contains(
                    "`Key` is `AWS::CloudFormation::Authentication`, a key of the map itself."
                )
                && stdout.contains("Write `X[*] { Key == value }` or `X[*].Key == value`")
                && stdout.contains(
                    "where `X` is `Resources.Metadata`. For each member's own `Key`: `X.*.Key` or `X.* { Key == value }`. At path"
                ),
            "the console shows the key, both spellings, what `X` is and the member spellings; got stdout {:?}",
            stdout
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "a refusal is a verdict, not a notice; got stderr {:?}",
            stderr
        );

        // The full text, as `-o json` carries it, names the key the predicate read.
        let (json_status_code, json_stdout, _) = utils::capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec!["single-map-binding-with-password-template.yaml"])
                .rules(vec!["filter_on_the_literal_path_of_a_single_map.guard"])
                .show_summary(vec!["none"])
                .output_format(Some("json"))
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            json_status_code,
            "json stdout {:?}",
            json_stdout
        );
        // The entry under the key is itself a map (the authentication block), so the member spellings
        // follow the definition of `X` as one short sentence and the path comes after them as its own.
        assert!(
            json_stdout.contains(
                "`Key` is `AWS::CloudFormation::Authentication`, a key of the map itself"
            ) && json_stdout.contains("Write `X[*] { Key == value }` or `X[*].Key == value`")
                && json_stdout.contains(
                    "where `X` is `Resources.Metadata`. For each member's own `Key`: `X.*.Key` or `X.* { Key == value }`. At path"
                ),
            "the full refusal names the key the predicate read, both spellings, what `X` is, the member spellings and then the path; got json stdout {:?}",
            json_stdout
        );
    }

    /// The pass-over refusal under a `when` gate with a long real query and a two-clause predicate: the
    /// text opens with the definition of `X` and the remedy in placeholder spellings, then names the
    /// filter with its predicate once and says what it did. The console summary and the JSON report both
    /// carry the whole text.
    #[test]
    fn the_pass_over_refusal_defines_x_and_names_the_remedy_before_the_when_gates_cut() {
        const DEFINITION_AND_REMEDY: &str = "`X` is `Resources.WebServer.Properties.Configuration.Settings`. Write `X[*][ ... ]` to read one object and a list of them alike: the filter `X[";
        let (status_code, stdout, stderr) = validate_both_streams(
            "pass_over_long_query_when.guard",
            "pass-over-long-query-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(&format!(
                "{DEFINITION_AND_REMEDY} ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]` kept no entry and passed over `Mode`, a String, so an absence check selected nothing where the scalar passed over may have been the match; refused in both polarities, at path /Resources/WebServer/Properties/Configuration/Settings["
            )),
            "under a `when` the console shows the definition of `X`, the whole remedy and the predicate; got stdout {:?}",
            stdout
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "a refusal is a verdict, not a notice; got stderr {:?}",
            stderr
        );
        let (json_status_code, json_stdout, _) = utils::capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec!["pass-over-long-query-template.yaml"])
                .rules(vec!["pass_over_long_query_when.guard"])
                .show_summary(vec!["none"])
                .output_format(Some("json"))
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            json_status_code,
            "json stdout {:?}",
            json_stdout
        );
        assert!(
            json_stdout.contains(&format!(
                "{DEFINITION_AND_REMEDY} ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]` kept no entry and passed over `Mode`, a String, so an absence check selected nothing where the scalar passed over may have been the match; refused in both polarities, at path /Resources/WebServer/Properties/Configuration/Settings["
            )),
            "the JSON report carries the whole text, the predicate printed once after the remedy; got json stdout {:?}",
            json_stdout
        );
    }

    /// The pass-over refusal's five text arms, each read through the real console: the definition of `X`,
    /// the whole remedy, the predicate once and the sentence that says what the filter did all show in
    /// the console summary, and the JSON report carries the same text. The named-map arms run as `when`
    /// gates; the `this` arms, which the `when` grammar does not take (a block is not a condition), run as
    /// assertions inside a block over the member. All five over the same template, under the long real
    /// query `Resources.WebServer.Properties.Configuration.<Settings|Config|Nulls>` with a two-clause
    /// predicate; the one-object named arm is pinned by the cell above over its own fixture.
    #[test]
    fn the_pass_over_refusals_five_arms_show_their_definition_and_remedy_in_the_console() {
        const TEMPLATE: &str = "pass-over-four-arms-template.yaml";
        // (rules file, the definition and remedy the console must show, the whole text from the
        // definition on, which the console and the JSON report both carry)
        for (rules, shown, json_whole) in [
            (
                "pass_over_four_arms_member_when.guard",
                "`X` is `Resources.WebServer.Properties.Configuration.Config`. Write `X[*][ ... ]` to read one object and a list of them alike: the filter `X[",
                "`X` is `Resources.WebServer.Properties.Configuration.Config`. Write `X[*][ ... ]` to read one object and a list of them alike: the filter `X[ ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]` kept a map-valued entry in the map's place and passed over `Mode`, a String, so an absence check selected a field of what may be one object; refused in both polarities, at path /Resources/WebServer/Properties/Configuration/Config[",
            ),
            // The kept-null arm as a `when` gate over the long query: `Nulls` holds the scalar `Mode`
            // beside the null `B`, which both absence clauses keep, and no sub-map holds a predicate key,
            // so the one-object remedy is named, as for the kept-by-absence arm below, and the sentence
            // that names the null follows it.
            (
                "pass_over_four_arms_kept_null_when.guard",
                "`X` is `Resources.WebServer.Properties.Configuration.Nulls`. Write `X[*][ ... ]` to read one object and a list of them alike: the filter `X[",
                "`X` is `Resources.WebServer.Properties.Configuration.Nulls`. Write `X[*][ ... ]` to read one object and a list of them alike: the filter `X[ ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]` kept a null entry in the map's place and passed over `Mode`, a String, so an absence check selected a field of what may be one object; refused in both polarities, at path /Resources/WebServer/Properties/Configuration/Nulls[",
            ),
            // The `this` arms run as assertions inside a block over the member.
            (
                "pass_over_four_arms_block.guard",
                "`X` is the member the block is over. Write `X[*][ ... ]` to read the member as one object and a list of them alike, or the predicate as a clause over the member: the filter `this[ ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]`",
                "`X` is the member the block is over. Write `X[*][ ... ]` to read the member as one object and a list of them alike, or the predicate as a clause over the member: the filter `this[ ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]` kept no entry and passed over `Mode`, a String, so an absence check selected nothing where the scalar passed over may have been the match; refused in both polarities, at path /Resources/WebServer/Properties/Configuration/Settings[",
            ),
            (
                "pass_over_four_arms_block_member.guard",
                "`X` is the member the block is over. Write `X[*][ ... ]` to read the member as one object and a list of them alike, or the predicate as a clause over the member: the filter `this[ ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]`",
                "`X` is the member the block is over. Write `X[*][ ... ]` to read the member as one object and a list of them alike, or the predicate as a clause over the member: the filter `this[ ServerSideEncryptionConfiguration !exists LoggingConfiguration !exists ]` kept a map-valued entry in the map's place and passed over `Mode`, a String, so an absence check selected a field of what may be one object; refused in both polarities, at path /Resources/WebServer/Properties/Configuration/Config[",
            ),
            // The kept-scalar arm as a `when` gate over the long query: `Settings` holds two scalars, both
            // handed to the predicate for its `this exists` arm and both kept through the absence of
            // `ServerSideEncryptionConfiguration`, which a scalar holds for want of any key. The `this` arm
            // asks no more than existence, so the remedy asks the key of the map alone and names neither
            // `X[ ... ]` nor `X[*][ ... ]`, which over a map of scalars passes on every template.
            (
                "pass_over_four_arms_absence_when.guard",
                "`X` is `Resources.WebServer.Properties.Configuration.Settings`. Ask `X.Key !exists` of the map: the filter `X[",
                "`X` is `Resources.WebServer.Properties.Configuration.Settings`. Ask `X.Key !exists` of the map: the filter `X[ ServerSideEncryptionConfiguration !exists or this exists ]` kept `Mode`, a String, through `ServerSideEncryptionConfiguration !exists`, which a scalar holds for want of any key, so an absence check selected a field of what may be one object",
            ),
            // The same arm beside a member that holds the key, under a `this` arm that compares: `Mixed`
            // holds `Mode` beside `Inner`, which carries `ServerSideEncryptionConfiguration`, so the
            // remedy asks the key of the map first (that sentence ends inside the first 150 characters
            // of the text, over this long query) and then names the members spelling with no `this`
            // clause and the entries spelling with no absence clause.
            (
                "pass_over_four_arms_absence_when_member.guard",
                "`X` is `Resources.WebServer.Properties.Configuration.Mixed`. Ask `X.Key !exists` of the map. For the members, `X.*[ ... ]` with no `this` clause; for the entries, `X.*[ ... ]` with no absence clause: the filter `X[",
                "`X` is `Resources.WebServer.Properties.Configuration.Mixed`. Ask `X.Key !exists` of the map. For the members, `X.*[ ... ]` with no `this` clause; for the entries, `X.*[ ... ]` with no absence clause: the filter `X[ ServerSideEncryptionConfiguration !exists or this == 'zzz' ]` kept `Mode`, a String, through `ServerSideEncryptionConfiguration !exists`, which a scalar holds for want of any key, so an absence check selected a field of what may be one object",
            ),
        ] {
            let (status_code, stdout, stderr) = validate_both_streams(rules, TEMPLATE);
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{rules}: stdout {:?}",
                stdout
            );
            assert!(
                stdout.contains(shown),
                "{rules}: the console shows the definition of `X` and the whole remedy; got stdout {:?}",
                stdout
            );
            assert!(
                stdout.contains(json_whole),
                "{rules}: the console shows the whole text, the sentence after the remedy included; got stdout {:?}",
                stdout
            );
            assert!(
                !stderr.contains("DEPRECATION"),
                "{rules}: a refusal is a verdict, not a notice; got stderr {:?}",
                stderr
            );
            let (json_status_code, json_stdout, _) = utils::capture_both_streams(|writer, reader| {
                ValidateTestRunner::default()
                    .data(vec![TEMPLATE])
                    .rules(vec![rules])
                    .show_summary(vec!["none"])
                    .output_format(Some("json"))
                    .run(writer, reader)
            });
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                json_status_code,
                "{rules}: json stdout {:?}",
                json_stdout
            );
            assert!(
                json_stdout.contains(json_whole),
                "{rules}: the JSON report carries the whole text, the predicate printed once after the remedy; got json stdout {:?}",
                json_stdout
            );
        }
    }

    /// The block arm's own-key refusal is recorded PER VALUE (`eval_guard_block_clause` writes a failing
    /// `GuardClauseBlockCheck` carrying the text for the refused map and goes on to the block's other
    /// values), and that record reaches the reader: over three resources whose `Cfg` maps share `cpu`,
    /// `Resources.*.Cfg[*] { Limits exists  Tier == 'gold' }` refuses `R1.Cfg` (its own key `Limits` names a
    /// member `Other` lacks), passes `R2.Cfg` and fails `R3.Cfg` on its `Tier`, and the console summary and
    /// the JSON report both print the refusal with its path, `/Resources/R1/Cfg`, and the direct-path remedy,
    /// beside `R3`'s own failure. A record whose message no reporter printed would leave the rule FAIL with
    /// `R3`'s reason alone and the refused map unexplained
    /// (`every_recorded_explanation_has_a_rendering_path` counts the site; this is its end-to-end check).
    #[test]
    fn the_block_arms_per_value_refusal_reaches_the_console_and_the_json_report() {
        const REFUSAL: &str = "`[*]` handed the map at path /Resources/R1/Cfg[";
        const REMEDY: &str = "Write `X.Key == value` to read `X` as one object";
        let (status_code, stdout, _) = validate_both_streams(
            "own_key_block_per_value.guard",
            "own-key-block-per-value-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(REFUSAL) && stdout.contains(REMEDY),
            "the console prints the refused map's path and the remedy; got stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("/Resources/R3/Cfg/Tier"),
            "the console prints the third resource's own failure beside the refusal; got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("/Resources/R2/Cfg"),
            "the passing resource is reported as no failure; got stdout {:?}",
            stdout
        );
        let (status_code, json_stdout, _) = utils::capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec!["own-key-block-per-value-template.yaml"])
                .rules(vec!["own_key_block_per_value.guard"])
                .show_summary(vec!["none"])
                .output_format(Some("json"))
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "json stdout {:?}",
            json_stdout
        );
        assert!(
            json_stdout.contains(REFUSAL) && json_stdout.contains("/Resources/R3/Cfg/Tier"),
            "the JSON report carries the refusal and the third resource's failure; got json stdout {:?}",
            json_stdout
        );
    }

    /// The block arm's own-key refusal as a `when` GATE reaches the console whole on the OUTER rule's
    /// line: `rule inner(cfgs) { %cfgs[*] { Limits exists } }` under `rule outer when
    /// inner(Resources.*.Cfg)` over the per-value template (`R1.Cfg` ambiguous). `inner` is parameterized,
    /// so it is evaluated through the call alone and never reported on its own: the exit and every line
    /// are `outer`'s, which fails closed, and the console prints `outer`'s condition line with the
    /// refusal's path and its remedy, which stands last in a sentence longer than the console's bound for
    /// a text that is no refusal (a condition record flagged as no refusal would be cut there and would
    /// lose the remedy). The record is flagged by the registry (`eval_context::is_refusal`), whichever error
    /// variant carried the raise. The rule for the fixture: `inner` is never a top-level rule, since a
    /// top-level `inner` would show the same substrings from its own failure, with or without the gate's
    /// flag, and the cell would measure nothing of the gate.
    #[test]
    fn the_block_arms_gate_refusal_prints_its_remedy_whole_on_the_console() {
        let (status_code, stdout, _) = validate_both_streams(
            "own_key_block_gate.guard",
            "own-key-block-per-value-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("outer")
                && stdout.contains("The rule's condition could not be evaluated")
                && stdout.contains("`[*]` handed the map at path /Resources/R1/Cfg[")
                && stdout.contains("Write `X.Key == value` to read `X` as one object"),
            "the console prints the outer rule's condition line with the refusal's path and its remedy; got stdout {:?}",
            stdout
        );
        // Nothing is printed for `inner` but the one legitimate mention, the CALL inside `outer`'s
        // condition as written (`inner(Resources.*.Cfg)`): every line that names `inner` names it as that
        // call, so neither a rule line (`Rule inner`), a status, nor a nested clause label of its own
        // (`inner: %cfgs[*] { Limits exists }`) is printed.
        let inner_reported = stdout
            .lines()
            .any(|line| line.contains("inner") && !line.contains("inner("));
        assert!(
            !inner_reported,
            "the parameterized `inner` is printed nowhere but as the call in `outer`'s condition; got stdout {:?}",
            stdout
        );
    }

    /// What the own-key refusal says about the members is read off the map, and does not change with
    /// the order the members are written in: over `R1.Cfg: { Limits: { cpu }, Other: { cpu } }` the
    /// sentence says that no member holds a `Limits` of its own, `Other` among them, on the console and in
    /// the JSON report, and the template with `Other` written before `Limits` renders the SAME sentence.
    /// Before this the text named the first lacking member in map order and, when that was the one named
    /// like the key, said "while another member does": over this fixture it claimed another member held
    /// `Limits` when none did, and swapping the two members changed the text.
    #[test]
    fn the_own_key_refusals_member_sentence_is_read_off_the_map_in_either_member_order() {
        const SENTENCE: &str = " on as one object, and `Limits`, a key the block reads, is a key of that \
                                map and the name of one of its members and no member holds a `Limits` of \
                                its own, `Other` among them: `Limits` would be answered by the map's own \
                                entry named `Limits`, not by each member. Write `X.Key == value` to read \
                                `X` as one object, or `X.*.Key` or `X.* { Key == value }` to read each \
                                member's own `Key`, where `X` is `Resources.*.Cfg`.";
        for template in [
            "own-key-block-per-value-template.yaml",
            "own-key-block-per-value-template-swapped.yaml",
        ] {
            let (status_code, stdout, _) =
                validate_both_streams("own_key_block_per_value.guard", template);
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{template}: stdout {:?}",
                stdout
            );
            assert!(
                stdout.contains(SENTENCE),
                "{template}: the console prints the member sentence whole, read off the map; got stdout {:?}",
                stdout
            );
            let (status_code, json_stdout, _) = utils::capture_both_streams(|writer, reader| {
                ValidateTestRunner::default()
                    .data(vec![template])
                    .rules(vec!["own_key_block_per_value.guard"])
                    .show_summary(vec!["none"])
                    .output_format(Some("json"))
                    .run(writer, reader)
            });
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{template}: json stdout {:?}",
                json_stdout
            );
            assert!(
                json_stdout.contains(SENTENCE),
                "{template}: the JSON report carries the same sentence; got json stdout {:?}",
                json_stdout
            );
        }
    }

    /// The key spelling's own-key refusal reaches the console whole, remedy included, and the JSON report
    /// carries it, in both of the key spelling's assertion forms: the unary `resources[*].limits exists`
    /// over a Kubernetes `resources` map (the own key `limits` names a member `requests` lacks) and the
    /// binary `Resources[*].A.S == "abc"` over a `Resources` of two resources sharing their keys (the own
    /// key `A` names a member `B` lacks). The binary form's record is the comparison's own, which carries
    /// the refusal's sentence and the kind since the `LhsUnresolved` arm writes them; before that the
    /// console printed the missing property and the map it traversed to, and the remedy nowhere.
    #[test]
    fn the_key_spellings_refusal_reaches_the_console_whole_and_the_json_report() {
        const REFUSAL: &str = "`[*]` handed the map at path ";
        const REMEDY: &str = "Write `X.Key == value` to read `X` as one object";
        for (rules, template, written) in [
            (
                "own_key_key_spelling_exists.guard",
                "own-key-key-spelling-k8s-template.yaml",
                "where `X` is `resources`.",
            ),
            (
                "own_key_key_spelling_compare.guard",
                "own-key-key-spelling-two-resources-template.yaml",
                "where `X` is `Resources`.",
            ),
        ] {
            let (status_code, stdout, _) = validate_both_streams(rules, template);
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{rules}: stdout {:?}",
                stdout
            );
            assert!(
                stdout.contains(REFUSAL) && stdout.contains(REMEDY) && stdout.contains(written),
                "{rules}: the console prints the refusal with its remedy and its `X`; got stdout {:?}",
                stdout
            );
            let (status_code, json_stdout, _) = utils::capture_both_streams(|writer, reader| {
                ValidateTestRunner::default()
                    .data(vec![template])
                    .rules(vec![rules])
                    .show_summary(vec!["none"])
                    .output_format(Some("json"))
                    .run(writer, reader)
            });
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{rules}: json stdout {:?}",
                json_stdout
            );
            assert!(
                json_stdout.contains(REFUSAL) && json_stdout.contains(REMEDY),
                "{rules}: the JSON report carries the refusal with its remedy; got json stdout {:?}",
                json_stdout
            );
        }
    }

    /// The key spelling's own-key refusal met INSIDE a filter predicate reaches the console whole, remedy
    /// included, and the JSON report carries it: `Resources[ Cfg[*].Limits exists ] !empty` over `R1.Cfg`
    /// (the own key `Limits` names a member `Other` lacks) beside a decided `R2`. The refused marker stands
    /// at `R1`'s `Cfg` and the entry `R1` is left a plain marker the outer `!empty` fails closed on; the
    /// outer clause's record carries the refusal, and its sentence is the refusal's own text, with nothing
    /// of the entry's value in it to cut.
    #[test]
    fn the_key_spellings_refusal_inside_a_predicate_reaches_the_console_whole_and_the_json_report()
    {
        const REFUSAL: &str = "`[*]` handed the map at path /Resources/R1/Cfg";
        const REMEDY: &str = "Write `X.Key == value` to read `X` as one object";
        const WRITTEN: &str = "where `X` is `Cfg`.";
        let rules = "own_key_key_spelling_in_predicate.guard";
        let template = "own-key-key-spelling-in-predicate-template.yaml";
        let (status_code, stdout, _) = validate_both_streams(rules, template);
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{rules}: stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(REFUSAL) && stdout.contains(REMEDY) && stdout.contains(WRITTEN),
            "{rules}: the console prints the refusal with its remedy and its `X`; got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("Value traversed to"),
            "{rules}: the sentence is the refusal's own text, with no value traversed to; got stdout {:?}",
            stdout
        );
        let (status_code, json_stdout, _) = utils::capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![template])
                .rules(vec![rules])
                .show_summary(vec!["none"])
                .output_format(Some("json"))
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{rules}: json stdout {:?}",
            json_stdout
        );
        assert!(
            json_stdout.contains(REFUSAL) && json_stdout.contains(REMEDY),
            "{rules}: the JSON report carries the refusal with its remedy; got json stdout {:?}",
            json_stdout
        );
        assert!(
            !json_stdout.contains("Value traversed to"),
            "{rules}: the JSON report's sentence is the refusal's own text, with no value traversed to; got json stdout {:?}",
            json_stdout
        );
    }

    /// The key spelling's own-key refusal reaches the live `--verbose` TREE output whole, remedy included,
    /// and nothing of the refused map's value is printed there: `Resources[*].A.S == "abc"` over the two
    /// resources sharing `Type` and `S` (the own key `A` names a member `B` lacks) fails on the comparison's
    /// own record, flagged as the refusal it is, and the tree prints that record's sentence as the refusal's
    /// text, never "Value traversed to [..]" with the whole map in it.
    #[test]
    fn the_key_spellings_refusal_reaches_the_verbose_tree_whole() {
        const REFUSAL: &str = "`[*]` handed the map at path /Resources";
        const REMEDY: &str = "Write `X.Key == value` to read `X` as one object";
        let rules = "own_key_key_spelling_compare.guard";
        let template = "own-key-key-spelling-two-resources-template.yaml";
        let (status_code, stdout, _) = utils::capture_both_streams(|writer, reader| {
            ValidateTestRunner::default()
                .data(vec![template])
                .rules(vec![rules])
                .show_summary(vec!["all"])
                .verbose()
                .run(writer, reader)
        });
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "{rules}: verbose stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains(REFUSAL) && stdout.contains(REMEDY),
            "{rules}: the verbose tree carries the refusal with its remedy; got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("Value traversed to"),
            "{rules}: the verbose tree prints the refusal's own text, with no value traversed to; got stdout {:?}",
            stdout
        );
    }

    /// The member spellings of an own-key refusal sit between the definition of `X` and the path, only
    /// where a member is named like the key, and the console summary and the JSON report both print them
    /// whole, whatever the length of the key and the query.
    ///
    /// Five cells over templates (the template reporter is the one that prints a clause's explanation in
    /// its summary; a document with no `Resources` section is printed whole by the single-line reporter).
    /// The shortest pair, `BucketA` under `Resources`. A longer pair, `R1` under
    /// `Resources.A.Properties.Rules`. The longest pair a published rule writes,
    /// `AWS::CloudFormation::Authentication` under `Resources.WebServer.Metadata`. The `when` form of the
    /// `R1` pair, where the condition site's wrapper precedes the text. And the key spelling over
    /// `Resources.B1` naming `Type`, a string, which offers no member sentence in either report. Every
    /// expected string is the refusal's own wording.
    #[test]
    fn the_member_spellings_sit_before_the_path_in_the_console_and_the_json_report() {
        // The engine's `THE_MEMBER_SPELLINGS`, read from the one file both sides include at compile time
        // (`guard/resources/notices/member-spellings.txt`): this integration crate cannot read a
        // `pub(crate)` item, and the hand copy that stood here drifted the moment either side changed.
        const MEMBERS: &str = include_str!("../resources/notices/member-spellings.txt");
        const SPELLINGS: &str = "Write `X[*] { Key == value }` or `X[*].Key == value`";
        let json_of = |rules: &str, data: &str| {
            let (status_code, stdout, _) = utils::capture_both_streams(|writer, reader| {
                ValidateTestRunner::default()
                    .data(vec![data])
                    .rules(vec![rules])
                    .show_summary(vec!["none"])
                    .output_format(Some("json"))
                    .run(writer, reader)
            });
            assert_eq!(
                StatusCode::VALIDATION_ERROR,
                status_code,
                "{rules}: json stdout {:?}",
                stdout
            );
            stdout
        };

        // The shortest pair: the member sentence and then the path.
        let (status_code, stdout, stderr) = validate_both_streams(
            "own_key_member_hint_shortest.guard",
            "own-key-member-hint-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("`Key` is `BucketA`, a key of the map itself.")
                && stdout.contains(SPELLINGS)
                && stdout.contains(&format!("where `X` is `Resources`. {MEMBERS} At path /Resources[")),
            "the shortest refusal shows the key, both spellings, the whole member sentence and then the path on the console; got stdout {:?}",
            stdout
        );
        let json_stdout = json_of(
            "own_key_member_hint_shortest.guard",
            "own-key-member-hint-template.yaml",
        );
        assert!(
            json_stdout.contains(&format!(
                "where `X` is `Resources`. {MEMBERS} At path /Resources["
            )),
            "the JSON report carries the member sentence and then the path; got json stdout {:?}",
            json_stdout
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "a refusal is a verdict, not a notice; got stderr {:?}",
            stderr
        );

        // A longer pair: the whole member sentence and then the path, on both streams.
        let (status_code, stdout, _) = validate_both_streams(
            "own_key_member_hint_longest.guard",
            "own-key-member-hint-long-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("`Key` is `R1`, a key of the map itself.")
                && stdout.contains(SPELLINGS)
                && stdout.contains(&format!(
                    "where `X` is `Resources.A.Properties.Rules`. {MEMBERS} At path /Resources/A/Properties/Rules["
                )),
            "for `R1` under `Resources.A.Properties.Rules` the console shows the key, both spellings, the whole member sentence and then the path; got stdout {:?}",
            stdout
        );
        let json_stdout = json_of(
            "own_key_member_hint_longest.guard",
            "own-key-member-hint-long-template.yaml",
        );
        assert!(
            json_stdout.contains(&format!(
                "where `X` is `Resources.A.Properties.Rules`. {MEMBERS} At path /Resources/A/Properties/Rules["
            )),
            "the JSON report carries the member sentence and then the path; got json stdout {:?}",
            json_stdout
        );

        // The `when` form: the console shows the key, both spellings, the definition of `X`, the member
        // sentence and the path, behind the condition site's wrapper.
        let (status_code, stdout, _) = validate_both_streams(
            "own_key_member_hint_when.guard",
            "own-key-member-hint-long-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("`Key` is `R1`, a key of the map itself.")
                && stdout.contains(SPELLINGS)
                && stdout.contains(&format!(
                    "where `X` is `Resources.A.Properties.Rules`. {MEMBERS} At path /Resources/A/Properties/Rules["
                )),
            "under a `when` the console shows the key, both spellings, the definition of `X`, the member sentence and the path; got stdout {:?}",
            stdout
        );
        let json_stdout = json_of(
            "own_key_member_hint_when.guard",
            "own-key-member-hint-long-template.yaml",
        );
        assert!(
            json_stdout.contains(&format!(
                "where `X` is `Resources.A.Properties.Rules`. {MEMBERS} At path /Resources/A/Properties/Rules["
            )),
            "the JSON report of the `when` carries the whole text; got json stdout {:?}",
            json_stdout
        );

        // The longest pair a published rule writes: `AWS::CloudFormation::Authentication` under a resource's
        // `Metadata`. The console and the JSON report carry the sentence whole and then the path.
        let (status_code, stdout, _) = validate_both_streams(
            "own_key_authentication_member_hint.guard",
            "authentication-under-metadata-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("`Key` is `AWS::CloudFormation::Authentication`, a key of the map itself.")
                && stdout.contains(SPELLINGS)
                && stdout.contains(&format!(
                    "where `X` is `Resources.WebServer.Metadata`. {MEMBERS} At path /Resources/WebServer/Metadata["
                )),
            "for the authentication key under `Resources.WebServer.Metadata` the console shows the key, both spellings, the definition of `X`, the whole member sentence and then the path; got stdout {:?}",
            stdout
        );
        let json_stdout = json_of(
            "own_key_authentication_member_hint.guard",
            "authentication-under-metadata-template.yaml",
        );
        assert!(
            json_stdout.contains(&format!(
                "where `X` is `Resources.WebServer.Metadata`. {MEMBERS} At path /Resources/WebServer/Metadata["
            )),
            "the JSON report carries the whole member sentence and then the path; got json stdout {:?}",
            json_stdout
        );

        // The named map whose own key is a string: no member sentence anywhere, the path right after `X`.
        let (status_code, stdout, _) = validate_both_streams(
            "own_key_named_map_no_hint.guard",
            "own-key-named-map-template.yaml",
        );
        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        assert!(
            stdout.contains("where `X` is `Resources.B1`, at path /Resources/B1[")
                && !stdout.contains("For each member's own"),
            "a string own key gets the path right after the definition of `X` and no member sentence; got stdout {:?}",
            stdout
        );
        let json_stdout = json_of(
            "own_key_named_map_no_hint.guard",
            "own-key-named-map-template.yaml",
        );
        assert!(
            json_stdout.contains("where `X` is `Resources.B1`, at path /Resources/B1[")
                && !json_stdout.contains(MEMBERS),
            "the JSON report of the string own key carries no member sentence either; got json stdout {:?}",
            json_stdout
        );
    }

    /// The password a `WebServer` instance's `basic` authentication block holds, in the fixtures where it
    /// holds one.
    const WEBSERVER_PASSWORD: &str =
        "/Resources/WebServer/Metadata/AWS::CloudFormation::Authentication/WebCreds/password";
    /// The password a `LaunchConfig` launch configuration's `basic` block holds, where it holds one.
    const LAUNCH_CONFIGURATION_PASSWORD: &str =
        "/Resources/LaunchConfig/Metadata/AWS::CloudFormation::Authentication/FleetCreds/password";

    /// The count the single-line report prints ahead of the failing resources, read from its own line,
    /// or `None` when the report prints no such line (a run that failed nothing). Reading the whole
    /// line is what makes `1` mean one: a substring check for `... 1` is met by `... 10`.
    fn non_compliant_resource_count(output: &str) -> Option<usize> {
        output.lines().find_map(|line| {
            line.trim()
                .strip_prefix("Number of non-compliant resources ")
                .map(|count| {
                    count
                        .trim()
                        .parse::<usize>()
                        .unwrap_or_else(|_| panic!("unreadable count line {:?}", line))
                })
        })
    }

    /// Whether the single-line report opens a block for `resource`, which it does for each resource
    /// the rule failed on and for no other. The block's first line is `Resource = <id> {` and nothing
    /// else, so the whole line is compared.
    fn reports_resource(output: &str, resource: &str) -> bool {
        let opening = format!("Resource = {resource} {{");
        output.lines().any(|line| line.trim_end() == opening)
    }

    /// The two rewrites `docs/CLAUSES.md` gives under "Filtering through a variable", run against the
    /// templates the docs describe. Each row states what it pins: the exit code, the rule's verdict, how
    /// many resources the report counts as non-compliant (0 for a report that prints no count), the
    /// resources the report fails with the password path each failure names, and the resources the
    /// report must not open a block for because the rule did not fail on them.
    ///
    /// The rewrites are not interchangeable, and the verdicts show it. `let m = Resources.WebServer`
    /// with the predicate in the `when` condition checks only the instance it names: FAIL on its
    /// password with the launch configuration beside it unreported, PASS when its block holds none even
    /// while that launch configuration's holds one, SKIP on a template with no `WebServer`.
    /// `Resources.*[ ... ]` checks every resource carrying the block, whatever its type or logical id,
    /// since the filter has no `Type` clause: FAIL on the instance's password and on the launch
    /// configuration's, FAIL on the launch configuration's alone with the compliant `WebServer`
    /// unreported when the instance's block holds none, PASS when no selected block holds one. Neither
    /// raises the notice: the first has no filter through a variable, and the second filters a literal
    /// path. A PASS or SKIP report opens no resource block, so those rows carry no resource entries.
    #[rstest::rstest]
    #[case(
        "authentication_tested_in_the_when_condition.guard",
        "authentication-under-metadata-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "FAIL",
        1,
        &[("WebServer", WEBSERVER_PASSWORD)],
        &["LaunchConfig"]
    )]
    #[case(
        "authentication_tested_in_the_when_condition.guard",
        "authentication-under-metadata-password-outside-the-named-instance-template.yaml",
        StatusCode::SUCCESS,
        "PASS",
        0,
        &[],
        &[]
    )]
    #[case(
        "authentication_tested_in_the_when_condition.guard",
        "authentication-under-metadata-without-password-template.yaml",
        StatusCode::SUCCESS,
        "SKIP",
        0,
        &[],
        &[]
    )]
    #[case(
        "authentication_selected_from_the_resources.guard",
        "authentication-under-metadata-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "FAIL",
        2,
        &[
            ("WebServer", WEBSERVER_PASSWORD),
            ("LaunchConfig", LAUNCH_CONFIGURATION_PASSWORD)
        ],
        &[]
    )]
    #[case(
        "authentication_selected_from_the_resources.guard",
        "authentication-under-metadata-password-outside-the-named-instance-template.yaml",
        StatusCode::VALIDATION_ERROR,
        "FAIL",
        1,
        &[("LaunchConfig", LAUNCH_CONFIGURATION_PASSWORD)],
        &["WebServer"]
    )]
    #[case(
        "authentication_selected_from_the_resources.guard",
        "authentication-under-metadata-without-password-template.yaml",
        StatusCode::SUCCESS,
        "PASS",
        0,
        &[],
        &[]
    )]
    fn the_documented_authentication_rewrites_check_the_resources_they_select(
        #[case] rules: &str,
        #[case] template: &str,
        #[case] expected_status: i32,
        #[case] expected_verdict: &str,
        #[case] non_compliant_resources: usize,
        #[case] failed_resources: &[(&str, &str)],
        #[case] unreported_resources: &[&str],
    ) {
        let (status_code, stdout, stderr) = validate_both_streams(rules, template);

        assert_eq!(expected_status, status_code, "stdout {:?}", stdout);
        assert_eq!(
            Some(expected_verdict.to_string()),
            rule_status_line(&stdout, "authentication_has_no_password"),
            "stdout {:?}",
            stdout
        );
        assert_eq!(
            (non_compliant_resources > 0).then_some(non_compliant_resources),
            non_compliant_resource_count(&stdout),
            "the count the report prints, got stdout {:?}",
            stdout
        );
        for (resource, password) in failed_resources {
            assert!(
                reports_resource(&stdout, resource),
                "the report opens a block for {resource}, which the rule failed on; got stdout {:?}",
                stdout
            );
            assert!(
                stdout.contains(password),
                "the report names the password at {password}, got stdout {:?}",
                stdout
            );
        }
        for resource in unreported_resources {
            assert!(
                !reports_resource(&stdout, resource),
                "{resource} is not reported: the rule did not fail on it; got stdout {:?}",
                stdout
            );
        }
        assert!(
            !stderr.contains("DEPRECATION"),
            "neither rewrite filters through a variable holding a map, so nothing is announced; got stderr {:?}",
            stderr
        );
    }

    /// An absence predicate through a variable holding one resource holds on the resource itself when
    /// the resource is one object. Both spellings are pinned, since the notice once grounded `empty`
    /// apart from `not exists`: `let m = Resources.Only` then `%m[ Properties.Tags !exists ]` or
    /// `%m[ Properties.Tags empty ]` on a resource whose entries are the `Type` string and two maps
    /// without `Properties.Tags`. The resource holds a scalar entry and `Properties` is not a key of
    /// either map, so the filter tests the resource as a whole, as `%m[*][ ... ]` does: the absence
    /// holds on it, and the resource is selected in its own place. A positive `exists` over the
    /// selection passes, and so does the comparison of the selection's own `Type`, which only the
    /// resource itself answers (the `Metadata` and `Properties` entries a walk would select have none).
    /// The `Type` string is neither selected nor reported, and nothing is announced: no selection was
    /// lost. The template is this test's own, so the shape is pinned here and nowhere else.
    #[rstest::rstest]
    #[case("absence_predicate_through_an_instance_binding.guard")]
    #[case("empty_predicate_through_an_instance_binding.guard")]
    fn an_absence_predicate_through_an_instance_binding_selects_the_instance_itself(
        #[case] rules: &str,
    ) {
        let (status_code, stdout, stderr) =
            validate_both_streams(rules, "one-resource-two-maps-one-scalar-template.yaml");

        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the positive assertion passes on the selected resource; stdout {:?}",
            stdout
        );
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&stdout, "the_resource_itself_is_selected"),
            "stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("/Resources/Only/Type[")
                && !stdout.contains("Filter on value type that was not a struct or array"),
            "the scalar entry is neither selected nor reported, got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "the resource is selected, so no selection was lost; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// `docs/CLAUSES.md` says a positive predicate through a variable holding one resource holds on an
    /// entry that is itself a map carrying the key. `let m = Resources.Only` then
    /// `%m[ Metadata."AWS::CloudFormation::Authentication" exists ]` on a resource whose `Wrapper` entry
    /// carries that path: the `Wrapper` map is selected in the resource's place, so a `!exists` over the
    /// selection's passwords fails on the one under `Wrapper`, naming its path, while the resource's own
    /// `Metadata` and `Properties` maps are rejected and its `Type` string is read as absent. No notice:
    /// the predicate does not hold on the resource itself, so the resource lost no selection.
    #[test]
    fn a_positive_predicate_through_an_instance_binding_selects_the_entry_carrying_the_key() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "positive_predicate_through_an_instance_binding_selects_a_wrapper_entry.guard",
            "one-resource-with-a-wrapper-entry-template.yaml",
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the password under the selected Wrapper entry fails the `!exists`; stdout {:?}",
            stdout
        );
        assert_eq!(
            Some("FAIL".to_string()),
            rule_status_line(&stdout, "the_wrapper_entry_is_selected"),
            "stdout {:?}",
            stdout
        );
        assert!(
            reports_resource(&stdout, "Only")
                && stdout.contains(
                    "PropertyPath    = /Resources/Only/Wrapper/Metadata/AWS::CloudFormation::Authentication/WrappedCreds/password["
                ),
            "the failure names the password under the Wrapper entry the filter selected, got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("/Resources/Only/Type["),
            "the Type string is read as absent by `!exists`, not reported; got stdout {:?}",
            stdout
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "the predicate does not hold on the resource itself, so no selection was lost; got stderr {:?}",
            stderr
        );
    }

    /// The spelling `docs/CLAUSES.md` describes, `let m = Resources.WebServer` then
    /// `%m[ Metadata."AWS::CloudFormation::Authentication" exists ]`, on the template whose `WebServer`
    /// block holds a password. The resource holds a scalar `Type`, and `Metadata` is not a key of any
    /// of its map-valued entries (its `Metadata` and `Properties` maps), so the resource is one object:
    /// the filter tests it as a whole, as `%m[*][ ... ]` does, the predicate holds on it, and the
    /// resource is selected in its own place. Three rules over the selection: the ungated `!exists`
    /// FAILs on the password and names its path; behind `when %auth !empty` the same assertion applies
    /// and FAILs; a positive `exists` PASSes. The exit code is 19 and nothing is announced: no
    /// selection was lost.
    #[test]
    fn the_documented_filter_through_an_instance_binding_selects_the_instance_and_fails_on_its_password(
    ) {
        let (status_code, stdout, stderr) = validate_both_streams(
            "authentication_filtered_through_an_instance_binding.guard",
            "authentication-under-metadata-template.yaml",
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "the password under the selected WebServer fails the `!exists`; stdout {:?}",
            stdout
        );
        for (rule, verdict) in [
            ("authentication_has_no_password", "FAIL"),
            ("authentication_has_no_password_when_selected", "FAIL"),
            ("authentication_block_is_selected", "PASS"),
        ] {
            assert_eq!(
                Some(verdict.to_string()),
                rule_status_line(&stdout, rule),
                "{rule}: stdout {:?}",
                stdout
            );
        }
        assert!(
            stdout.contains(
                "PropertyPath    = /Resources/WebServer/Metadata/AWS::CloudFormation::Authentication/WebCreds/password["
            ),
            "the failure names the password under the selected WebServer; got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("/Resources/WebServer/Type[")
                && !stdout.contains("Filter on value type that was not a struct or array"),
            "the Type string is neither selected nor reported; got stdout {:?}",
            stdout
        );
        assert!(
            !stdout.contains("DEPRECATION") && !stderr.contains("DEPRECATION"),
            "the resource is selected, so no selection was lost; stdout {:?} stderr {:?}",
            stdout,
            stderr
        );
    }

    /// The same spelling on a template with no `WebServer`: the variable holds nothing, so no map lost
    /// a selection and nothing is announced. The ungated `!exists` still passes and the gated rule is
    /// still SKIP, which is why the docs send a rule that means to check the instance to the `when`
    /// condition or to `Resources.*[ ... ]`; the positive `exists` fails on the missing key.
    #[test]
    fn the_documented_filter_through_an_instance_binding_holding_nothing_is_not_announced() {
        let (status_code, stdout, stderr) = validate_both_streams(
            "authentication_filtered_through_an_instance_binding.guard",
            "authentication-under-metadata-without-password-template.yaml",
        );

        assert_eq!(
            StatusCode::VALIDATION_ERROR,
            status_code,
            "stdout {:?}",
            stdout
        );
        for (rule, verdict) in [
            ("authentication_has_no_password", "PASS"),
            ("authentication_has_no_password_when_selected", "SKIP"),
            ("authentication_block_is_selected", "FAIL"),
        ] {
            assert_eq!(
                Some(verdict.to_string()),
                rule_status_line(&stdout, rule),
                "{rule}: stdout {:?}",
                stdout
            );
        }
        assert!(
            stdout.contains("Could not find key WebServer inside struct at path /Resources"),
            "the failure names the key the variable could not resolve, got stdout {:?}",
            stdout
        );
        assert!(
            !stderr.contains("DEPRECATION"),
            "no map was held, so no selection was lost; got stderr {:?}",
            stderr
        );
    }

    /// A parameterized rule whose measured condition captures keys reads each key once.
    ///
    /// `guarded`'s condition reads `%x`, a parameter handed `to_lower(Resources.*.Properties.Tags)`,
    /// which resolves to two lowered tags beside an entry the role had no answer for. That reading
    /// makes the condition measured, and the measurement evaluated the condition again several times
    /// against the call's own scope, appending the two bucket keys to `%buckets` on each pass. The body's
    /// `count(%buckets)` then read 8 where the filter selected 2, and `main` failed at exit 19 over a
    /// template that complies.
    #[test]
    fn a_measured_condition_in_a_parameterized_rule_captures_each_key_once() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");

        let status_code = ValidateTestRunner::default()
            .data(vec!["captures/two-buckets-and-a-role-template.yaml"])
            .rules(vec![
                "captures/parameterized_rule_when_capture_measured.guard",
            ])
            .show_summary(vec!["all"])
            .run(&mut writer, &mut reader);

        let output = writer.stripped().expect("failed to read the writer");
        assert_eq!(
            StatusCode::SUCCESS,
            status_code,
            "the filter selected the two buckets, so `%buckets` holds two keys:\n{}",
            output
        );
        assert_eq!(
            Some("PASS".to_string()),
            rule_status_line(&output, "main"),
            "main passes; it failed when the measurement duplicated the capture:\n{}",
            output
        );
    }
}
