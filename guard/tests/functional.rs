// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod utils;

#[cfg(test)]
mod tests {
    use cfn_guard;
    use crate::utils;
    use cfn_guard::commands::{VALIDATE, DATA, RULES, INPUT_PARAMETERS};

    #[test]
    fn test_run_check() {
        let data = String::from(
            r#"
                {
                    "Resources": {
                        "VPC" : {
                            "Type" : "AWS::ApiGateway::Method",
                            "Properties" : {
                                "AuthorizationType" : "10.0.0.0/24"
                            }
                        }
                    }
                }
            "#,
        );
        let rule = "AWS::ApiGateway::Method { Properties.AuthorizationType == \"NONE\"}";
        let expected =
            r#"[{
                "eval_type": "Rule",
                "context": "default",
                "msg": "DEFAULT MESSAGE(FAIL)",
                "from": null,
                "to": null,
                "status": "FAIL",
                "comparator": null,
                "children": [
                  {
                    "eval_type": "Type",
                    "context": "AWS::ApiGateway::Method",
                    "msg": "DEFAULT MESSAGE(FAIL)",
                    "from": null,
                    "to": null,
                    "status": "FAIL",
                    "comparator": null,
                    "children": [
                      {
                        "eval_type": "Filter",
                        "context": "Path=/Resources/VPC[L:0,C:0],Type=MapElement",
                        "msg": "DEFAULT MESSAGE(PASS)",
                        "from": null,
                        "to": null,
                        "status": "PASS",
                        "comparator": null,
                        "children": [
                          {
                            "eval_type": "Conjunction",
                            "context": "cfn_guard::rules::exprs::GuardClause",
                            "msg": "DEFAULT MESSAGE(PASS)",
                            "from": null,
                            "to": null,
                            "status": "PASS",
                            "comparator": null,
                            "children": [
                              {
                                "eval_type": "Clause",
                                "context": " Type EQUALS  \"AWS::ApiGateway::Method\"",
                                "msg": "DEFAULT MESSAGE(PASS)",
                                "from": null,
                                "to": null,
                                "status": "PASS",
                                "comparator": [
                                  "Eq",
                                  false
                                ],
                                "children": []
                              }
                            ]
                          }
                        ]
                      },
                      {
                        "eval_type": "Type",
                        "context": "AWS::ApiGateway::Method#0(/Resources/VPC[L:0,C:0])",
                        "msg": "DEFAULT MESSAGE(FAIL)",
                        "from": null,
                        "to": null,
                        "status": "FAIL",
                        "comparator": null,
                        "children": [
                          {
                            "eval_type": "Conjunction",
                            "context": "cfn_guard::rules::exprs::GuardClause",
                            "msg": "DEFAULT MESSAGE(FAIL)",
                            "from": null,
                            "to": null,
                            "status": "FAIL",
                            "comparator": null,
                            "children": [
                              {
                                "eval_type": "Clause",
                                "context": " Properties.AuthorizationType EQUALS  \"NONE\"",
                                "msg": "DEFAULT MESSAGE(FAIL)",
                                "from": {
                                  "path": "/Resources/VPC/Properties/AuthorizationType",
                                  "value": "10.0.0.0/24"
                                },
                                "to": {
                                  "path": "",
                                  "value": "NONE"
                                },
                                "status": "FAIL",
                                "comparator": [
                                  "Eq",
                                  false
                                ],
                                "children": []
                              }
                            ]
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            ]"#;
        let verbose = true;
        let serialized =   cfn_guard::run_checks(&data, &rule, verbose).unwrap();
        let result = serde_json::from_str::<serde_json::Value>(&serialized).ok().unwrap();
        let expected = serde_json::from_str::<serde_json::Value>(expected).ok().unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_single_data_file_single_rules_file_compliant(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/s3-public-read-prohibited-template-compliant.yaml");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/s3_bucket_public_read_prohibited.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg];
        assert_eq!(0, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_single_data_file_single_rules_file(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/s3_bucket_public_read_prohibited.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_data_dir_single_rules_file(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/s3_bucket_public_read_prohibited.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_single_data_file_rules_dir(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_data_dir_rules_dir(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_multiple_data_files_single_rules_file(){
        let data_arg1 = utils::get_full_path_for_resource_file("resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml");
        let data_arg2 = utils::get_full_path_for_resource_file("resources/data-dir/s3-public-read-prohibited-template-compliant.yaml");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/s3_bucket_public_read_prohibited.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg1,
                        &data_option, &data_arg2,
                        &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_single_data_file_multiple_rules_files(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml");
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/rules-dir/s3_bucket_public_read_prohibited.guard");
        let rules_arg2 = utils::get_full_path_for_resource_file("resources/rules-dir/s3_bucket_server_side_encryption_enabled.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg1,
                        &rules_option, &rules_arg2];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_data_file_and_dir_single_rules_file(){
        let data_arg1 = utils::get_full_path_for_resource_file("resources/s3-server-side-encryption-template-non-compliant-2.yaml");
        let data_arg2 = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/s3_bucket_public_read_prohibited.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg1,
                        &data_option, &data_arg2,
                        &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_single_data_file_rules_file_and_dir(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml");
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let rules_arg2 = utils::get_full_path_for_resource_file("resources/s3_bucket_server_side_encryption_enabled_2.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg1,
                        &rules_option, &rules_arg2];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_data_dir_rules_file_and_dir(){
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let rules_arg2 = utils::get_full_path_for_resource_file("resources/s3_bucket_server_side_encryption_enabled_2.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg1,
                        &rules_option, &rules_arg2];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_data_file_and_dir_rules_dir(){
        let data_arg1 = utils::get_full_path_for_resource_file("resources/s3-server-side-encryption-template-non-compliant-2.yaml");
        let data_arg2 = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg1,
                        &data_option, &data_arg2,
                        &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_data_file_and_dir_rules_file_and_dir(){
        let data_arg1 = utils::get_full_path_for_resource_file("resources/s3-server-side-encryption-template-non-compliant-2.yaml");
        let data_arg2 = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let rules_arg2 = utils::get_full_path_for_resource_file("resources/s3_bucket_server_side_encryption_enabled_2.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg1,
                        &data_option, &data_arg2,
                        &rules_option, &rules_arg1,
                        &rules_option, &rules_arg2];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_single_input_parameters_file(){
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg = utils::get_full_path_for_resource_file("resources/input-parameters-dir/db_params.yaml");
        let rules_arg = utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg,
                        &input_parameters_option, &input_parameters_arg];
        assert_eq!(5, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_multiple_input_parameters_files(){
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg1 = utils::get_full_path_for_resource_file("resources/input-parameters-dir/db_params.yaml");
        let input_parameters_arg2 = utils::get_full_path_for_resource_file("resources/input-parameters-dir/db_metadata.yaml");
        let rules_arg = utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg,
                        &input_parameters_option, &input_parameters_arg1,
                        &input_parameters_option, &input_parameters_arg2];
        assert_eq!(0, utils::cfn_guard_test_command(args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_input_parameters_dir(){
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg = utils::get_full_path_for_resource_file("resources/input-parameters-dir/");
        let rules_arg = utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![VALIDATE,
                        &data_option, &data_arg,
                        &rules_option, &rules_arg,
                        &input_parameters_option, &input_parameters_arg];
        assert_eq!(0, utils::cfn_guard_test_command(args));
    }

}