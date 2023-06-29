// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod functional_tests {

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
                      "name": "functional_test.json",
                      "status": "FAIL",
                      "message": null
                    }
                  },
                  "children": [
                    {
                      "context": "functional_test.rule/default",
                      "container": {
                        "RuleCheck": {
                          "name": "functional_test.rule/default",
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
                content: rule,
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
}
