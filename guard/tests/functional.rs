// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod utils;

#[cfg(test)]
mod tests {
    use std::fmt::format;

    use cfn_guard;
    use cfn_guard::commands::validate::Validate;
    use cfn_guard::commands::{DATA, INPUT_PARAMETERS, RULES, VALIDATE};
    use cfn_guard::commands::wrapper::{WrappedType, Wrapper};

    use crate::utils;

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
        let expected = r#"{
                  "context": "File(rules=1)",
                  "container": {
                    "FileCheck": {
                      "name": "",
                      "status": "FAIL",
                      "message": null
                    }
                  },
                  "children": [
                    {
                      "context": "default",
                      "container": {
                        "RuleCheck": {
                          "name": "default",
                          "status": "FAIL",
                          "message": null
                        }
                      },
                      "children": [
                        {
                          "context": "TypeBlock#AWS::ApiGateway::Method",
                          "container": {
                            "TypeCheck": {
                              "type_name": "AWS::ApiGateway::Method",
                              "block": {
                                "at_least_one_matches": false,
                                "status": "FAIL",
                                "message": null
                              }
                            }
                          },
                          "children": [
                            {
                              "context": "Filter/Map#1",
                              "container": {
                                "Filter": "PASS"
                              },
                              "children": [
                                {
                                  "context": "GuardAccessClause#block Type EQUALS  \"AWS::ApiGateway::Method\"",
                                  "container": {
                                    "GuardClauseBlockCheck": {
                                      "at_least_one_matches": false,
                                      "status": "PASS",
                                      "message": null
                                    }
                                  },
                                  "children": [
                                    {
                                      "context": " Type EQUALS  \"AWS::ApiGateway::Method\"",
                                      "container": {
                                        "ClauseValueCheck": "Success"
                                      },
                                      "children": []
                                    }
                                  ]
                                }
                              ]
                            },
                            {
                              "context": "TypeBlock#AWS::ApiGateway::Method/0",
                              "container": {
                                "TypeBlock": "FAIL"
                              },
                              "children": [
                                {
                                  "context": "GuardAccessClause#block Properties.AuthorizationType EQUALS  \"NONE\"",
                                  "container": {
                                    "GuardClauseBlockCheck": {
                                      "at_least_one_matches": false,
                                      "status": "FAIL",
                                      "message": null
                                    }
                                  },
                                  "children": [
                                    {
                                      "context": " Properties.AuthorizationType EQUALS  \"NONE\"",
                                      "container": {
                                        "ClauseValueCheck": {
                                          "Comparison": {
                                            "comparison": [
                                              "Eq",
                                              false
                                            ],
                                            "from": {
                                              "Resolved": {
                                                "path": "/Resources/VPC/Properties/AuthorizationType",
                                                "value": "10.0.0.0/24"
                                              }
                                            },
                                            "to": {
                                              "Resolved": {
                                                "path": "",
                                                "value": "NONE"
                                              }
                                            },
                                            "message": null,
                                            "custom_message": null,
                                            "status": "FAIL"
                                          }
                                        }
                                      },
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
                  ]
                }"#;
        let verbose = true;
        use cfn_guard::*;
        let serialized = run_checks(
            ValidateInput {
                content: &data,
                file_name: "functional_test.json",
            },
            ValidateInput {
                content: &rule,
                file_name: "functional_test.rule",
            },
            verbose,
        )
        .unwrap();
        let result = serde_json::from_str::<serde_json::Value>(&serialized)
            .ok()
            .unwrap();
        let expected = serde_json::from_str::<serde_json::Value>(expected)
            .ok()
            .unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_single_data_file_single_rules_file_compliant() {
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        assert_eq!(0, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rules_file() {
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_data_dir_single_rules_file() {
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_rules_dir() {
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_data_dir_rules_dir() {
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_multiple_data_files_single_rules_file() {
        let data_arg1 = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let data_arg2 = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-compliant.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_multiple_rules_files() {
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg1 = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let rules_arg2 = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_data_file_and_dir_single_rules_file() {
        let data_arg1 = utils::get_full_path_for_resource_file(
            "resources/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let data_arg2 = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_rules_file_and_dir() {
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let rules_arg2 = utils::get_full_path_for_resource_file(
            "resources/s3_bucket_server_side_encryption_enabled_2.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_data_dir_rules_file_and_dir() {
        let data_arg = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let rules_arg2 = utils::get_full_path_for_resource_file(
            "resources/s3_bucket_server_side_encryption_enabled_2.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_data_file_and_dir_rules_dir() {
        let data_arg1 = utils::get_full_path_for_resource_file(
            "resources/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let data_arg2 = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_data_file_and_dir_rules_file_and_dir() {
        let data_arg1 = utils::get_full_path_for_resource_file(
            "resources/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let data_arg2 = utils::get_full_path_for_resource_file("resources/data-dir/");
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/rules-dir/");
        let rules_arg2 = utils::get_full_path_for_resource_file(
            "resources/s3_bucket_server_side_encryption_enabled_2.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_single_input_parameters_file() {
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg =
            utils::get_full_path_for_resource_file("resources/input-parameters-dir/db_params.yaml");
        let rules_arg =
            utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_multiple_input_parameters_files() {
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg1 =
            utils::get_full_path_for_resource_file("resources/input-parameters-dir/db_params.yaml");
        let input_parameters_arg2 = utils::get_full_path_for_resource_file(
            "resources/input-parameters-dir/db_metadata.yaml",
        );
        let rules_arg =
            utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg1,
            &input_parameters_option,
            &input_parameters_arg2,
        ];
        assert_eq!(0, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_input_parameters_dir() {
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg =
            utils::get_full_path_for_resource_file("resources/input-parameters-dir/");
        let rules_arg =
            utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];
        assert_eq!(0, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_malformed_rules_file() {
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file("resources/malformed-rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        // -1 status code equates to Error being thrown
        assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_malformed_data_file_single_rules_file() {
        let data_arg = utils::get_full_path_for_resource_file("resources/malformed-template.yaml");
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/s3_bucket_server_side_encryption_enabled_2.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        // -1 status code equates to Error being thrown
        assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_malformed_input_parameters_file() {
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg =
            utils::get_full_path_for_resource_file("resources/malformed-template.yaml");
        let rules_arg =
            utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];
        // -1 status code equates to Error being thrown
        assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_blank_rules_file() {
        // The parsing exits with status code 5 = FAIL for allowing other rules to get evaluated even when one of them fails to get parsed
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file("resources/blank-rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_blank_and_valid_rules_file() {
        // The parsing exits with status code 5 = FAIL for allowing other rules to get evaluated even when one of them fails to get parsed
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg1 = utils::get_full_path_for_resource_file("resources/blank-rule.guard");
        let rules_arg2 = utils::get_full_path_for_resource_file(
            "resources/s3_bucket_server_side_encryption_enabled_2.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg1,
            &rules_option,
            &rules_arg2,
        ];
        assert_eq!(5, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_blank_data_file_single_rules_file() {
        let data_arg = utils::get_full_path_for_resource_file("resources/blank-template.yaml");
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/s3_bucket_server_side_encryption_enabled_2.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        // -1 status code equates to Error being thrown
        assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_blank_and_valid_data_file_single_rules_file() {
        let data_arg1 = utils::get_full_path_for_resource_file("resources/blank-template.yaml");
        let data_arg2 = utils::get_full_path_for_resource_file(
            "resources/s3-server-side-encryption-template-non-compliant-2.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/s3_bucket_server_side_encryption_enabled_2.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg1,
            &data_option,
            &data_arg2,
            &rules_option,
            &rules_arg,
        ];
        // -1 status code equates to Error being thrown
        assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_blank_input_parameters_file() {
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg =
            utils::get_full_path_for_resource_file("resources/blank-template.yaml");
        let rules_arg =
            utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg,
        ];
        // -1 status code equates to Error being thrown
        assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rules_file_blank_and_valid_input_parameters_file() {
        let data_arg = utils::get_full_path_for_resource_file("resources/db_resource.yaml");
        let input_parameters_arg1 =
            utils::get_full_path_for_resource_file("resources/blank-template.yaml");
        let input_parameters_arg2 =
            utils::get_full_path_for_resource_file("resources/input-parameters-dir/db_params.yaml");
        let rules_arg =
            utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard");
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let input_parameters_option = format!("-{}", INPUT_PARAMETERS.1);
        let args = vec![
            VALIDATE,
            &data_option,
            &data_arg,
            &rules_option,
            &rules_arg,
            &input_parameters_option,
            &input_parameters_arg1,
            &input_parameters_option,
            &input_parameters_arg2,
        ];
        // -1 status code equates to Error being thrown
        assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args));
    }

    #[test]
    fn test_single_data_file_single_rule_file_when_either_data_or_rule_file_dne() {
        for arg in vec![
            (
                utils::get_full_path_for_resource_file("fake_file.yaml"),
                utils::get_full_path_for_resource_file("resources/db_param_port_rule.guard"),
            ),
            (
                utils::get_full_path_for_resource_file("resources/db_resource.yaml"),
                utils::get_full_path_for_resource_file("fake_file.guard"),
            ),
        ] {
            let data_option = &format!("-{}", DATA.1);
            let rules_option = &format!("-{}", RULES.1);
            let args = vec![VALIDATE, data_option, &arg.0, rules_option, &arg.1];
            assert_eq!(-1, utils::cfn_guard_test_command(Validate::new(), args))
        }
    }

    #[test]
    fn test_single_data_file_single_rules_file_verbose() {
        let data_arg = utils::get_full_path_for_resource_file(
            "resources/data-dir/s3-public-read-prohibited-template-non-compliant.yaml",
        );
        let rules_arg = utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_public_read_prohibited.guard",
        );
        let data_option = format!("-{}", DATA.1);
        let rules_option = format!("-{}", RULES.1);
        let args = vec![VALIDATE, &data_option, &data_arg, &rules_option, &rules_arg];
        let mut writer = Wrapper::new(WrappedType::Vec(vec![]));
        let status_code = utils::cfn_guard_test_command_verbose(Validate::new(), args, &mut writer);
        assert_eq!(5, status_code);



        // let expected = "some str";
        let expected = "s3-public-read-prohibited-template-non-compliant.yaml Status = FAIL\nFAILED rules\ns3_bucket_public_read_prohibited.guard/S3_BUCKET_PUBLIC_READ_PROHIBITED    FAIL\n---\nEvaluating data s3-public-read-prohibited-template-non-compliant.yaml against rules s3_bucket_public_read_prohibited.guard\nNumber of non-compliant resources 1\nResource = MyBucket {\n  Type      = AWS::S3::Bucket\n  Rule = S3_BUCKET_PUBLIC_READ_PROHIBITED {\n    ALL {\n      Check =  %s3_bucket_public_read_prohibited[*].Properties.PublicAccessBlockConfiguration EXISTS   {\n        RequiredPropertyError {\n          PropertyPath = /Resources/MyBucket/Properties[L:13,C:6]\n          MissingProperty = PublicAccessBlockConfiguration\n          Reason = Could not find key PublicAccessBlockConfiguration inside struct at path /Resources/MyBucket/Properties[L:13,C:6]\n          Code:\n               11.      #   BlockPublicPolicy: true\n               12.      #   IgnorePublicAcls: true\n               13.      #   RestrictPublicBuckets: true\n               14.      BucketEncryption:\n               15.        ServerSideEncryptionConfiguration:\n               16.          - ServerSideEncryptionByDefault:\n        }\n      }\n      Check =  %s3_bucket_public_read_prohibited[*].Properties.PublicAccessBlockConfiguration.BlockPublicAcls EQUALS  true {\n        RequiredPropertyError {\n          PropertyPath = /Resources/MyBucket/Properties[L:13,C:6]\n          MissingProperty = PublicAccessBlockConfiguration.BlockPublicAcls\n          Reason = Could not find key PublicAccessBlockConfiguration inside struct at path /Resources/MyBucket/Properties[L:13,C:6]\n          Code:\n               11.      #   BlockPublicPolicy: true\n               12.      #   IgnorePublicAcls: true\n               13.      #   RestrictPublicBuckets: true\n               14.      BucketEncryption:\n               15.        ServerSideEncryptionConfiguration:\n               16.          - ServerSideEncryptionByDefault:\n        }\n      }\n      Check =  %s3_bucket_public_read_prohibited[*].Properties.PublicAccessBlockConfiguration.BlockPublicPolicy EQUALS  true {\n        RequiredPropertyError {\n          PropertyPath = /Resources/MyBucket/Properties[L:13,C:6]\n          MissingProperty = PublicAccessBlockConfiguration.BlockPublicPolicy\n          Reason = Could not find key PublicAccessBlockConfiguration inside struct at path /Resources/MyBucket/Properties[L:13,C:6]\n          Code:\n               11.      #   BlockPublicPolicy: true\n               12.      #   IgnorePublicAcls: true\n               13.      #   RestrictPublicBuckets: true\n               14.      BucketEncryption:\n               15.        ServerSideEncryptionConfiguration:\n               16.          - ServerSideEncryptionByDefault:\n        }\n      }\n      Check =  %s3_bucket_public_read_prohibited[*].Properties.PublicAccessBlockConfiguration.IgnorePublicAcls EQUALS  true {\n        RequiredPropertyError {\n          PropertyPath = /Resources/MyBucket/Properties[L:13,C:6]\n          MissingProperty = PublicAccessBlockConfiguration.IgnorePublicAcls\n          Reason = Could not find key PublicAccessBlockConfiguration inside struct at path /Resources/MyBucket/Properties[L:13,C:6]\n          Code:\n               11.      #   BlockPublicPolicy: true\n               12.      #   IgnorePublicAcls: true\n               13.      #   RestrictPublicBuckets: true\n               14.      BucketEncryption:\n               15.        ServerSideEncryptionConfiguration:\n               16.          - ServerSideEncryptionByDefault:\n        }\n      }\n      Check =  %s3_bucket_public_read_prohibited[*].Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets EQUALS  true {\n        Message {\n          Violation: S3 Bucket Public Write Access controls need to be restricted.\n          Fix: Set S3 Bucket PublicAccessBlockConfiguration properties for BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets parameters to true.\n        }\n        RequiredPropertyError {\n          PropertyPath = /Resources/MyBucket/Properties[L:13,C:6]\n          MissingProperty = PublicAccessBlockConfiguration.RestrictPublicBuckets\n          Reason = Could not find key PublicAccessBlockConfiguration inside struct at path /Resources/MyBucket/Properties[L:13,C:6]\n          Code:\n               11.      #   BlockPublicPolicy: true\n               12.      #   IgnorePublicAcls: true\n               13.      #   RestrictPublicBuckets: true\n               14.      BucketEncryption:\n               15.        ServerSideEncryptionConfiguration:\n               16.          - ServerSideEncryptionByDefault:\n        }\n      }\n    }\n  }\n}\n";


        let string = writer.from_utf8().unwrap();
        assert_eq!(expected, string)
    }

}

#[cfg(test)]
mod test_test_command {
    use cfn_guard::commands::test::Test;
    use cfn_guard::commands::{RULES, TEST, TEST_DATA};
    use cfn_guard::Error;
    use rstest::rstest;

    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_test_data_file_with_shorthand_reference(#[case] file_type: &str) -> Result<(), Error> {
        let test_data_arg = crate::utils::get_full_path_for_resource_file(&format!(
            "resources/test-data-dir/s3_bucket_logging_enabled_tests.{}",
            file_type
        ));
        let rule_arg = crate::utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_logging_enabled.guard",
        );
        let data_option = format!("-{}", TEST_DATA.1);
        let rules_option = format!("-{}", RULES.1);

        let args = vec![TEST, &data_option, &test_data_arg, &rules_option, &rule_arg];

        assert_eq!(0, crate::utils::cfn_guard_test_command(Test::new(), args));
        Ok(())
    }

    #[rstest::rstest]
    #[case("json")]
    #[case("yaml")]
    fn test_test_data_file(#[case] file_type: &str) -> Result<(), Error> {
        let test_data_arg = crate::utils::get_full_path_for_resource_file(&format!(
            "resources/test-data-dir/s3_bucket_server_side_encryption_enabled.{}",
            file_type
        ));
        let rule_arg = crate::utils::get_full_path_for_resource_file(
            "resources/rules-dir/s3_bucket_server_side_encryption_enabled.guard",
        );
        let data_option = format!("-{}", TEST_DATA.1);
        let rules_option = format!("-{}", RULES.1);

        let args = vec![TEST, &data_option, &test_data_arg, &rules_option, &rule_arg];

        assert_eq!(0, crate::utils::cfn_guard_test_command(Test::new(), args));
        Ok(())
    }
}
