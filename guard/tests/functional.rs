// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cfn_guard;

mod tests {
    use super::*;
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
        let mut expected = String::from(
            r#"
            [
              {
                "eval_type": "Rule",
                "context": "default",
                "msg": "DEFAULT MESSAGE(FAIL)",
                "from": null,
                "to": null,
                "status": "FAIL",
                "children": [
                  {
                    "eval_type": "Type",
                    "context": "AWS::ApiGateway::Method",
                    "msg": "DEFAULT MESSAGE(FAIL)",
                    "from": null,
                    "to": null,
                    "status": "FAIL",
                    "children": [
                      {
                        "eval_type": "Filter",
                        "context": "Path=/Resources/VPC,Type=MapElement",
                        "msg": "DEFAULT MESSAGE(PASS)",
                        "from": null,
                        "to": null,
                        "status": "PASS",
                        "children": [
                          {
                            "eval_type": "Conjunction",
                            "context": "cfn_guard::rules::exprs::GuardClause",
                            "msg": "DEFAULT MESSAGE(PASS)",
                            "from": null,
                            "to": null,
                            "status": "PASS",
                            "children": [
                              {
                                "eval_type": "Clause",
                                "context": "Clause(Location[file:, line:1, column:14], Check: Type  EQUALS String(\"AWS::ApiGateway::Method\"))",
                                "msg": "DEFAULT MESSAGE(PASS)",
                                "from": null,
                                "to": null,
                                "status": "PASS",
                                "children": []
                              }
                            ]
                          }
                        ]
                      },
                      {
                        "eval_type": "Type",
                        "context": "AWS::ApiGateway::Method#0(/Resources/VPC)",
                        "msg": "DEFAULT MESSAGE(FAIL)",
                        "from": null,
                        "to": null,
                        "status": "FAIL",
                        "children": [
                          {
                            "eval_type": "Conjunction",
                            "context": "cfn_guard::rules::exprs::GuardClause",
                            "msg": "DEFAULT MESSAGE(FAIL)",
                            "from": null,
                            "to": null,
                            "status": "FAIL",
                            "children": [
                              {
                                "eval_type": "Clause",
                                "context": "Clause(Location[file:lambda, line:1, column:27], Check: Properties.AuthorizationType  EQUALS String(\"NONE\"))",
                                "msg": "(DEFAULT: NO_MESSAGE)",
                                "from": {
                                  "String": [
                                    "/Resources/VPC/Properties/AuthorizationType",
                                    "10.0.0.0/24"
                                  ]
                                },
                                "to": {
                                  "String": [
                                    "lambda/1/27/Clause/",
                                    "NONE"
                                  ]
                                },
                                "status": "FAIL",
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
            "#,
            );

        // Remove white spaces from expected and calculated result for easy comparison.
        expected.retain(|c| !c.is_whitespace());

        let mut serialized =   cfn_guard::run_checks(&data, &rule).unwrap();
        println!("{}", serialized);
        serialized.retain(|c| !c.is_whitespace());

        assert_eq!(expected, serialized);
    }

}
