// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub(crate) mod utils;

#[cfg(test)]
mod parse_tree_tests {
    use cfn_guard::commands::{CfnGuard, PRINT_JSON, PRINT_YAML, RULES};
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
    use clap::Parser;
    use pretty_assertions::assert_eq;

    use crate::utils::{get_full_path_for_resource_file, Command, CommandTestRunner, StatusCode};
    use crate::{assert_output_from_file_eq, assert_output_from_str_eq};

    #[derive(Default)]
    struct ParseTreeTestRunner<'args> {
        rules: &'args str,
        // Never read: the `output` setter below assigns to `self.rules`, and `build_args` never emits
        // `--output`. Left as it was found, with the lint silenced on the field rather than on the whole
        // struct, so that removing the struct-wide allow could surface `print_yaml` being unused -- which
        // is what it did.
        #[allow(dead_code)]
        output: Option<&'args str>,
        print_json: bool,
        print_yaml: bool,
    }

    impl<'args> ParseTreeTestRunner<'args> {
        fn rules(&'args mut self, arg: &'args str) -> &'args mut ParseTreeTestRunner {
            self.rules = arg;
            self
        }

        #[allow(dead_code)]
        fn output(&'args mut self, arg: &'args str) -> &'args mut ParseTreeTestRunner {
            self.rules = arg;
            self
        }

        fn print_yaml(&'args mut self) -> &'args mut ParseTreeTestRunner {
            self.print_yaml = true;
            self
        }

        fn print_json(&'args mut self) -> &'args mut ParseTreeTestRunner {
            self.print_json = true;
            self
        }
    }

    impl<'args> CommandTestRunner for ParseTreeTestRunner<'args> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![
                Command::ParseTree.to_string(),
                format!("-{}", RULES.1),
                get_path_for_resource_file(self.rules),
            ];

            if self.print_yaml {
                args.push(format!("--{}", PRINT_YAML.0));
            }

            if self.print_json {
                args.push(format!("--{}", PRINT_JSON.0));
            }

            args
        }
    }

    fn get_path_for_resource_file(file: &str) -> String {
        get_full_path_for_resource_file(&format!("resources/{}", file))
    }

    /// `--print-yaml` selects YAML, and asking for both formats is an error rather than a coin toss.
    ///
    /// `self.print_yaml` was declared and read nowhere: the output was chosen by
    /// `match self.print_json`, so YAML was the fall-through rather than a thing anyone could ask for.
    /// There was no input for which `--print-yaml` changed the output, `-y` was indistinguishable from
    /// passing nothing, and `-p -y` -- two contradictory format requests -- resolved silently to JSON.
    /// The field's own comment said "default true" while clap's default for a `bool` is `false`, which
    /// is why the dead flag read as intentional.
    ///
    /// No flags still means YAML. That is not incidental: this repository's own CI runs
    /// `cfn-guard parse-tree --rules $rule` with no format flag.
    #[test]
    fn print_yaml_selects_yaml_and_no_flag_still_means_yaml() {
        const RULES: &str = "validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard";

        let mut default_writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let default_code = ParseTreeTestRunner::default()
            .rules(RULES)
            .run(&mut default_writer, &mut Reader::default());

        let mut yaml_writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let yaml_code = ParseTreeTestRunner::default()
            .print_yaml()
            .rules(RULES)
            .run(&mut yaml_writer, &mut Reader::default());

        let mut json_writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let json_code = ParseTreeTestRunner::default()
            .print_json()
            .rules(RULES)
            .run(&mut json_writer, &mut Reader::default());

        assert_eq!(StatusCode::SUCCESS, default_code);
        assert_eq!(StatusCode::SUCCESS, yaml_code);
        assert_eq!(StatusCode::SUCCESS, json_code);

        let default_out = default_writer.stripped().expect("failed to read stdout");
        let yaml_out = yaml_writer.stripped().expect("failed to read stdout");
        let json_out = json_writer.stripped().expect("failed to read stdout");

        assert_eq!(
            default_out, yaml_out,
            "--print-yaml must select the format that no flag already selects"
        );
        assert_ne!(
            default_out, json_out,
            "--print-json must select a different format"
        );
        serde_yaml::from_str::<serde_yaml::Value>(&yaml_out).expect("--print-yaml must emit YAML");
        serde_json::from_str::<serde_json::Value>(&json_out).expect("--print-json must emit JSON");
    }

    /// `--print-json` and `--print-yaml` together are refused.
    ///
    /// They named two formats and one silently won. Asserted through `try_parse_from` because the
    /// rejection is clap's; `ParseTree::output_format` refuses the same pair for library callers, whose
    /// builder sets the two fields independently and validates nothing.
    #[test]
    fn print_json_and_print_yaml_together_are_refused() {
        let error = CfnGuard::try_parse_from(vec![
            "cfn-guard",
            "parse-tree",
            "-r",
            "some-rules.guard",
            "-p",
            "-y",
        ])
        .expect_err("two contradictory format flags must not parse");

        assert_eq!(StatusCode::USAGE_ERROR, error.exit_code());
    }

    /// A directory handed to `--rules` is a rules file that cannot be used, which this command calls 5.
    ///
    /// A directory opens successfully and then fails in `read_to_string` with EISDIR, which `?` carried
    /// to `main` as -1 -- "Is a directory (os error 21)", naming neither the path nor the flag, and
    /// using the code this command otherwise reserves for cfn-guard failing.
    ///
    /// `PARSING_ERROR` for the reason `parse_tree` already gives for a rules file the parser rejects: a
    /// mistake in what the caller named is reported in this command's own vocabulary. `test` answers
    /// the same mistake with its 1 and `validate` walks the directory, which is its documented
    /// behaviour -- three subcommands, three documented codes, exactly as they already differ on a
    /// rules file the parser rejects.
    #[test]
    fn a_directory_given_to_rules_is_reported_as_an_unusable_rules_file() {
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ParseTreeTestRunner::default()
            .rules("validate/rules-dir")
            .run(&mut writer, &mut Reader::default());

        assert_eq!(StatusCode::PARSING_ERROR, status_code);
        let stderr = writer.err_to_stripped().expect("failed to read stderr");
        assert!(
            stderr.contains("a directory is not a rules file"),
            "the message must say what was wrong with the path, got: {}",
            stderr
        );
    }

    #[test]
    fn test_json_output() {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ParseTreeTestRunner::default()
            .print_json()
            .rules("validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard")
            .run(&mut writer, &mut reader);

        assert_eq!(StatusCode::SUCCESS, status_code);
        assert_output_from_file_eq!(
            "resources/parse-tree/output-dir/s3_bucket_server_side_encryption_parse_tree.json",
            writer
        )
    }

    const YAML_S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED_PARSE_TREE: &str =  "assignments:\n- var: s3_buckets_server_side_encryption\n  value:\n    AccessClause:\n      query:\n      - Key: Resources\n      - AllValues: null\n      - Filter:\n        - null\n        - - - Clause:\n                access_clause:\n                  query:\n                    query:\n                    - Key: Type\n                    match_all: true\n                  comparator:\n                  - Eq\n                  - false\n                  compare_with:\n                    Value:\n                      path: ''\n                      value: AWS::S3::Bucket\n                  custom_message: null\n                  location:\n                    line: 1\n                    column: 54\n                negation: false\n          - - Clause:\n                access_clause:\n                  query:\n                    query:\n                    - Key: Metadata\n                    - Key: guard\n                    - Key: SuppressedRules\n                    match_all: true\n                  comparator:\n                  - Exists\n                  - true\n                  compare_with: null\n                  custom_message: null\n                  location:\n                    line: 2\n                    column: 3\n                negation: false\n            - Clause:\n                access_clause:\n                  query:\n                    query:\n                    - Key: Metadata\n                    - Key: guard\n                    - Key: SuppressedRules\n                    - AllValues: null\n                    match_all: true\n                  comparator:\n                  - Eq\n                  - true\n                  compare_with:\n                    Value:\n                      path: ''\n                      value: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED\n                  custom_message: null\n                  location:\n                    line: 3\n                    column: 3\n                negation: false\n      match_all: true\nguard_rules:\n- rule_name: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED\n  conditions:\n  - - Clause:\n        access_clause:\n          query:\n            query:\n            - Key: '%s3_buckets_server_side_encryption'\n            match_all: true\n          comparator:\n          - Empty\n          - true\n          compare_with: null\n          custom_message: null\n          location:\n            line: 6\n            column: 52\n        negation: false\n  block:\n    assignments: []\n    conjunctions:\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_buckets_server_side_encryption'\n                - AllIndices: null\n                - Key: Properties\n                - Key: BucketEncryption\n                match_all: true\n              comparator:\n              - Exists\n              - false\n              compare_with: null\n              custom_message: null\n              location:\n                line: 7\n                column: 3\n            negation: false\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_buckets_server_side_encryption'\n                - AllIndices: null\n                - Key: Properties\n                - Key: BucketEncryption\n                - Key: ServerSideEncryptionConfiguration\n                - AllIndices: null\n                - Key: ServerSideEncryptionByDefault\n                - Key: SSEAlgorithm\n                match_all: true\n              comparator:\n              - In\n              - false\n              compare_with:\n                Value:\n                  path: ''\n                  value:\n                  - aws:kms\n                  - AES256\n              custom_message: \"\\n    Violation: S3 Bucket must enable server-side encryption.\\n    Fix: Set the S3 Bucket property BucketEncryption.ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm to either \\\"aws:kms\\\" or \\\"AES256\\\"\\n  \"\n              location:\n                line: 8\n                column: 3\n            negation: false\nparameterized_rules: []\n";
    const S3_BUCKET_PUBLIC_READ_PROHIBITED_PARSE_TREE: &str = "assignments:\n- var: s3_bucket_public_read_prohibited\n  value:\n    AccessClause:\n      query:\n      - Key: Resources\n      - AllValues: null\n      - Filter:\n        - null\n        - - - Clause:\n                access_clause:\n                  query:\n                    query:\n                    - Key: Type\n                    match_all: true\n                  comparator:\n                  - Eq\n                  - false\n                  compare_with:\n                    Value:\n                      path: ''\n                      value: AWS::S3::Bucket\n                  custom_message: null\n                  location:\n                    line: 1\n                    column: 53\n                negation: false\n      match_all: true\nguard_rules:\n- rule_name: S3_BUCKET_PUBLIC_READ_PROHIBITED\n  conditions:\n  - - Clause:\n        access_clause:\n          query:\n            query:\n            - Key: '%s3_bucket_public_read_prohibited'\n            match_all: true\n          comparator:\n          - Empty\n          - true\n          compare_with: null\n          custom_message: null\n          location:\n            line: 3\n            column: 44\n        negation: false\n  block:\n    assignments: []\n    conjunctions:\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_bucket_public_read_prohibited'\n                - AllIndices: null\n                - Key: Properties\n                - Key: PublicAccessBlockConfiguration\n                match_all: true\n              comparator:\n              - Exists\n              - false\n              compare_with: null\n              custom_message: null\n              location:\n                line: 4\n                column: 3\n            negation: false\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_bucket_public_read_prohibited'\n                - AllIndices: null\n                - Key: Properties\n                - Key: PublicAccessBlockConfiguration\n                - Key: BlockPublicAcls\n                match_all: true\n              comparator:\n              - Eq\n              - false\n              compare_with:\n                Value:\n                  path: ''\n                  value: true\n              custom_message: null\n              location:\n                line: 5\n                column: 3\n            negation: false\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_bucket_public_read_prohibited'\n                - AllIndices: null\n                - Key: Properties\n                - Key: PublicAccessBlockConfiguration\n                - Key: BlockPublicPolicy\n                match_all: true\n              comparator:\n              - Eq\n              - false\n              compare_with:\n                Value:\n                  path: ''\n                  value: true\n              custom_message: null\n              location:\n                line: 6\n                column: 3\n            negation: false\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_bucket_public_read_prohibited'\n                - AllIndices: null\n                - Key: Properties\n                - Key: PublicAccessBlockConfiguration\n                - Key: IgnorePublicAcls\n                match_all: true\n              comparator:\n              - Eq\n              - false\n              compare_with:\n                Value:\n                  path: ''\n                  value: true\n              custom_message: null\n              location:\n                line: 7\n                column: 3\n            negation: false\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_bucket_public_read_prohibited'\n                - AllIndices: null\n                - Key: Properties\n                - Key: PublicAccessBlockConfiguration\n                - Key: RestrictPublicBuckets\n                match_all: true\n              comparator:\n              - Eq\n              - false\n              compare_with:\n                Value:\n                  path: ''\n                  value: true\n              custom_message: \"\\n    Violation: S3 Bucket Public Write Access controls need to be restricted.\\n    Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.\\n  \"\n              location:\n                line: 8\n                column: 3\n            negation: false\nparameterized_rules: []\n";
    const S3_BUCKET_LOGGING_ENABLED_PARSE_TREE: &str = "assignments:\n- var: s3_buckets_bucket_logging_enabled\n  value:\n    AccessClause:\n      query:\n      - Key: Resources\n      - AllValues: null\n      - Filter:\n        - null\n        - - - Clause:\n                access_clause:\n                  query:\n                    query:\n                    - Key: Type\n                    match_all: true\n                  comparator:\n                  - Eq\n                  - false\n                  compare_with:\n                    Value:\n                      path: ''\n                      value: AWS::S3::Bucket\n                  custom_message: null\n                  location:\n                    line: 30\n                    column: 54\n                negation: false\n          - - Clause:\n                access_clause:\n                  query:\n                    query:\n                    - Key: Metadata\n                    - Key: guard\n                    - Key: SuppressedRules\n                    match_all: true\n                  comparator:\n                  - Exists\n                  - true\n                  compare_with: null\n                  custom_message: null\n                  location:\n                    line: 31\n                    column: 3\n                negation: false\n            - Clause:\n                access_clause:\n                  query:\n                    query:\n                    - Key: Metadata\n                    - Key: guard\n                    - Key: SuppressedRules\n                    - AllValues: null\n                    match_all: true\n                  comparator:\n                  - Eq\n                  - true\n                  compare_with:\n                    Value:\n                      path: ''\n                      value: S3_BUCKET_LOGGING_ENABLED\n                  custom_message: null\n                  location:\n                    line: 32\n                    column: 3\n                negation: false\n      match_all: true\nguard_rules:\n- rule_name: S3_BUCKET_LOGGING_ENABLED\n  conditions:\n  - - Clause:\n        access_clause:\n          query:\n            query:\n            - Key: '%s3_buckets_bucket_logging_enabled'\n            match_all: true\n          comparator:\n          - Empty\n          - true\n          compare_with: null\n          custom_message: null\n          location:\n            line: 35\n            column: 37\n        negation: false\n  block:\n    assignments: []\n    conjunctions:\n    - - Clause:\n          Clause:\n            access_clause:\n              query:\n                query:\n                - Key: '%s3_buckets_bucket_logging_enabled'\n                - AllIndices: null\n                - Key: Properties\n                - Key: LoggingConfiguration\n                match_all: true\n              comparator:\n              - Exists\n              - false\n              compare_with: null\n              custom_message: \"\\n    Violation: S3 Bucket Logging needs to be configured to enable logging.\\n    Fix: Set the S3 Bucket property LoggingConfiguration to start logging into S3 bucket.\\n  \"\n              location:\n                line: 36\n                column: 3\n            negation: false\nparameterized_rules: []\n";

    #[rstest::rstest]
    #[case(
        "validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        YAML_S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED_PARSE_TREE,
        StatusCode::SUCCESS
    )]
    #[case(
        "validate/rules-dir/s3_bucket_public_read_prohibited.guard",
        S3_BUCKET_PUBLIC_READ_PROHIBITED_PARSE_TREE,
        StatusCode::SUCCESS
    )]
    #[case(
        "validate/rules-dir/s3_bucket_logging_enabled.guard",
        S3_BUCKET_LOGGING_ENABLED_PARSE_TREE,
        StatusCode::SUCCESS
    )]
    fn test_yaml_output(
        #[case] rules_arg: &str,
        #[case] expected_writer_output: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ParseTreeTestRunner::default()
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_str_eq!(expected_writer_output, writer)
    }

    /// The message for a path that is not there, which is the operating system's and so differs by
    /// platform. A function rather than a `const` because each `#[case]` argument is an expression
    /// evaluated inside the generated test, and only one of the three cases wants this.
    fn missing_file_error() -> &'static str {
        if cfg!(windows) {
            "Error occurred I/O error when reading The system cannot find the file specified. (os error 2)\n"
        } else {
            "Error occurred I/O error when reading No such file or directory (os error 2)\n"
        }
    }

    /// The three distinguishable things that can be wrong with the rules file `parse-tree` is given,
    /// each with its own exit code and its own stderr.
    ///
    /// This was two cases sharing one expected output, and that output was an **I/O** error -- which
    /// only both files being missing could satisfy. `dne.guard` is missing deliberately; the name says
    /// so. The second case pointed at `validate/rules-dir/malformed-rule.guard`, and the file is at
    /// `validate/malformed-rule.guard`, one directory up. So it failed at `File::open`, matched the
    /// shared I/O string, and passed green. `parse-tree`'s parse-error exit code therefore had *no*
    /// coverage, which is how it went to `main`'s catch-all and exited -1 unnoticed.
    ///
    /// Splitting them and giving each its own expected output is what stops one case from being
    /// satisfied by another's failure mode. The three are deliberately different answers:
    ///
    /// - a path that does not exist is `INTERNAL_FAILURE`, unchanged, and shared with `validate` and
    ///   `test`, which report a missing file the same way;
    /// - a file the parser rejects is `PARSING_ERROR`, which is what `validate` has always returned
    ///   for it and what `parse-tree` now returns too;
    /// - a file that parses but names an undeclared variable is `SUCCESS` with empty stderr, because
    ///   `parse-tree` parses and does not resolve. That row is not a bug being pinned but a boundary:
    ///   it is what keeps a future "report unresolved names" change from being made here by accident,
    ///   where only `validate` has the data to resolve against.
    ///
    /// The middle case reuses `validate/unparsable-rule.guard`, whose message marker is left
    /// unterminated. It is the repository's genuinely unparsable rules file and the structured
    /// `validate` tests already assert `PARSING_ERROR` against it; borrowing it here is what makes the
    /// two subcommands demonstrably agree on one file rather than on two files that merely resemble
    /// each other.
    #[rstest::rstest]
    #[case::a_path_that_does_not_exist(
        "validate/rules-dir/dne.guard",
        StatusCode::INTERNAL_FAILURE,
        missing_file_error()
    )]
    #[case::a_rules_file_the_parser_rejects(
        "validate/unparsable-rule.guard",
        StatusCode::PARSING_ERROR,
        "Parsing error handling rule file = unparsable-rule.guard, Error = Parser Error when parsing \
         `Parsing Error Error parsing file  at line 3 at column 53, when handling expecting either a \
         property access \"engine.core\" or value like \"string\" or [\"this\", \"that\"]/Unable to find \
         a closing >> tag for message, fragment  'Enabled'\n        <<the closing marker for this \
         message is missing, so the file will not parse\n    }\n}\n`\n---\n"
    )]
    #[case::a_rules_file_naming_an_undeclared_variable(
        "validate/malformed-rule.guard",
        StatusCode::SUCCESS,
        ""
    )]
    fn test_exit_code_per_kind_of_unusable_rules_file(
        #[case] rules_arg: &str,
        #[case] expected_status_code: i32,
        #[case] expected_err_output: &str,
    ) {
        let mut reader = Reader::default();
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ParseTreeTestRunner::default()
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);

        assert_eq!(expected_err_output, writer.err_to_stripped().unwrap());
    }

    #[rstest::rstest]
    #[case(
        "parse-tree/rules-dir/iterate_through_json_list_without_key.guard",
        "resources/parse-tree/output-dir/test_rule_iterate_through_json_list_without_key.yaml",
        StatusCode::SUCCESS
    )]
    #[case(
        "parse-tree/rules-dir/rule_with_this_keyword.guard",
        "resources/parse-tree/output-dir/test_rule_with_this_keyword.yaml",
        StatusCode::SUCCESS
    )]
    #[case(
        "validate/functions/rules/string_manipulation.guard",
        "resources/parse-tree/output-dir/parse_tree_functions.yaml",
        StatusCode::SUCCESS
    )]
    fn test_yaml_output_compare_buffer_to_file(
        #[case] rules_arg: &str,
        #[case] expected_writer_output: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = ParseTreeTestRunner::default()
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_file_eq!(expected_writer_output, writer)
    }
}
