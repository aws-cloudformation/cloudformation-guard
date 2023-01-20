// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod parse_tree_command_tests {
    use std::io::stdout;
    use cfn_guard;
    use cfn_guard::commands::{RULES, PARSE_TREE, PRINT_JSON};
    use cfn_guard::utils::writer::{Writer, WriteBuffer::Stdout, WriteBuffer::Vec as WBVec};
    use indoc::indoc;
    use crate::{assert_output_from_file_eq, assert_output_from_str_eq};
    use crate::utils::{get_full_path_for_resource_file, cfn_guard_test_command};

    #[test]
    fn test_json_output() {
        let rules_arg = get_full_path_for_resource_file(
            "resources/validate/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        );

        let rules_option = format!("-{}", RULES.1);
        let print_json_flag = format!("--{}", PRINT_JSON.0);
        let args = vec![PARSE_TREE,
                        &rules_option, &rules_arg,
                        &print_json_flag];

        let mut writer = Writer::new(WBVec(vec![]));
        let status_code = cfn_guard_test_command(
            args,
            &mut writer
        );

        assert_eq!(0, status_code);
        assert_output_from_str_eq!(
            "{\"assignments\":[{\"var\":\"s3_buckets_server_side_encryption\",\"value\":{\"AccessClause\":{\"query\":[{\"Key\":\"Resources\"},{\"AllValues\":null},{\"Filter\":[null,[[{\"Clause\":{\"access_clause\":{\"query\":{\"query\":[{\"Key\":\"Type\"}],\"match_all\":true},\"comparator\":[\"Eq\",false],\"compare_with\":{\"Value\":{\"path\":\"\",\"value\":\"AWS::S3::Bucket\"}},\"custom_message\":null,\"location\":{\"line\":1,\"column\":54}},\"negation\":false}}],[{\"Clause\":{\"access_clause\":{\"query\":{\"query\":[{\"Key\":\"Metadata\"},{\"Key\":\"guard\"},{\"Key\":\"SuppressedRules\"}],\"match_all\":true},\"comparator\":[\"Exists\",true],\"compare_with\":null,\"custom_message\":null,\"location\":{\"line\":2,\"column\":3}},\"negation\":false}},{\"Clause\":{\"access_clause\":{\"query\":{\"query\":[{\"Key\":\"Metadata\"},{\"Key\":\"guard\"},{\"Key\":\"SuppressedRules\"},{\"AllValues\":null}],\"match_all\":true},\"comparator\":[\"Eq\",true],\"compare_with\":{\"Value\":{\"path\":\"\",\"value\":\"S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED\"}},\"custom_message\":null,\"location\":{\"line\":3,\"column\":3}},\"negation\":false}}]]]}],\"match_all\":true}}}],\"guard_rules\":[{\"rule_name\":\"S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED\",\"conditions\":[[{\"Clause\":{\"access_clause\":{\"query\":{\"query\":[{\"Key\":\"%s3_buckets_server_side_encryption\"}],\"match_all\":true},\"comparator\":[\"Empty\",true],\"compare_with\":null,\"custom_message\":null,\"location\":{\"line\":6,\"column\":52}},\"negation\":false}}]],\"block\":{\"assignments\":[],\"conjunctions\":[[{\"Clause\":{\"Clause\":{\"access_clause\":{\"query\":{\"query\":[{\"Key\":\"%s3_buckets_server_side_encryption\"},{\"AllIndices\":null},{\"Key\":\"Properties\"},{\"Key\":\"BucketEncryption\"}],\"match_all\":true},\"comparator\":[\"Exists\",false],\"compare_with\":null,\"custom_message\":null,\"location\":{\"line\":7,\"column\":3}},\"negation\":false}}}],[{\"Clause\":{\"Clause\":{\"access_clause\":{\"query\":{\"query\":[{\"Key\":\"%s3_buckets_server_side_encryption\"},{\"AllIndices\":null},{\"Key\":\"Properties\"},{\"Key\":\"BucketEncryption\"},{\"Key\":\"ServerSideEncryptionConfiguration\"},{\"AllIndices\":null},{\"Key\":\"ServerSideEncryptionByDefault\"},{\"Key\":\"SSEAlgorithm\"}],\"match_all\":true},\"comparator\":[\"In\",false],\"compare_with\":{\"Value\":{\"path\":\"\",\"value\":[\"aws:kms\",\"AES256\"]}},\"custom_message\":\"\\n    Violation: S3 Bucket must enable server-side encryption.\\n    Fix: Set the S3 Bucket property BucketEncryption.ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm to either \\\"aws:kms\\\" or \\\"AES256\\\"\\n  \",\"location\":{\"line\":8,\"column\":3}},\"negation\":false}}}]]}}],\"parameterized_rules\":[]}"
            , writer
        )
    }
}