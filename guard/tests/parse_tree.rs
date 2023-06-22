// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod parse_tree_tests {
    use cfn_guard::commands::{PARSE_TREE, PRINT_JSON, PRINT_YAML, RULES};
    use cfn_guard::utils::reader::ReadBuffer::Stdin;
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};

    use crate::utils::{get_full_path_for_resource_file, CommandTestRunner, StatusCode};
    use crate::{assert_output_from_file_eq, assert_output_from_str_eq};

    #[allow(dead_code)]
    #[derive(Default)]
    struct ParseTreeTestRunner<'args> {
        rules: &'args str,
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

        #[allow(dead_code)]
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
                String::from(PARSE_TREE),
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

    #[test]
    fn test_json_output() {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
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
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ParseTreeTestRunner::default()
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_str_eq!(expected_writer_output, writer)
    }

    #[rstest::rstest]
    #[case(
        "validate/rules-dir/dne.guard",
        "Error occurred I/O error when reading No such file or directory (os error 2)\n",
        StatusCode::INTERNAL_FAILURE
    )]
    #[case(
        "validate/rules-dir/malformed-rule.guard",
        "Error occurred I/O error when reading No such file or directory (os error 2)\n",
        StatusCode::INTERNAL_FAILURE
    )]
    fn test_yaml_output_with_expected_failures(
        #[case] rules_arg: &str,
        #[case] expected_writer_output: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ParseTreeTestRunner::default()
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_eq!(expected_writer_output, writer.err_to_stripped().unwrap());
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
        let mut reader = Reader::new(Stdin(std::io::stdin()));
        let mut writer = Writer::new(WBVec(vec![]), WBVec(vec![]));
        let status_code = ParseTreeTestRunner::default()
            .rules(rules_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_file_eq!(expected_writer_output, writer)
    }
}
