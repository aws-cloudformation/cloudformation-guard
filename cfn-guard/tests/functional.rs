// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests
use cfn_guard;
use std::env;
use std::fs;

mod tests {
    use super::*;

    fn props_fixture() -> serde_json::Value {
        match serde_yaml::from_str(
            r#"AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        ) {
            Ok(v) => v,
            Err(e) => {
                dbg!(e);
                serde_json::from_str(r#"{}"#).unwrap()
            }
        }
    }

    #[test]
    fn test_lax_boolean_correction() {
        let mut template_contents = String::from(
            r#"
                {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 101,
                        "Encrypted": True,
                        "AvailabilityZone" : "us-west-2b"
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 99,
                        "Encrypted": true,
                        "AvailabilityZone" : "us-west-2c"
                    }
                }
            }
        }"#,
        );
        let mut rules_file_contents = String::from("AWS::EC2::Volume Encrypted == true");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );
        rules_file_contents = String::from("AWS::EC2::Volume Encrypted == True");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        template_contents = String::from(
            r#"
                {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 101,
                        "Encrypted": false,
                        "AvailabilityZone" : "us-west-2b"
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 99,
                        "Encrypted": False,
                        "AvailabilityZone" : "us-west-2c"
                    }
                }
            }
        }"#,
        );
        rules_file_contents = String::from("AWS::EC2::Volume Encrypted == false");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from("AWS::EC2::Volume Encrypted == False");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        template_contents = String::from(
            r#"
                {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 101,
                        "AvailabilityZone" : "us-west-2b",
                        "Encrypted": false
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 99,
                        "AvailabilityZone" : "us-west-2c",
                        "Encrypted": False
                    }
                }
            }
        }"#,
        );
        rules_file_contents = String::from("AWS::EC2::Volume Encrypted == false");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from("AWS::EC2::Volume Encrypted == False");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        template_contents = String::from(
            r#"
                {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 101,
                        "AvailabilityZone" : "us-west-2b"
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 99,
                        "AvailabilityZone" : "us-west-2c"
                    }
                }
            }
        }"#,
        );
        rules_file_contents = String::from("AWS::EC2::Volume Encrypted == false");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from("AWS::EC2::Volume Encrypted == False");
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn test_fail_on_regex_require_not_match() {
        let template_contents = fs::read_to_string("tests/ebs_volume_template.json")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_content = String::from(r#"AWS::EC2::Volume Encrypted != /true/"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_content, true).unwrap(),
            (
                vec![
                    String::from(
                        r#"[NewVolume2] failed because [Encrypted] is [true] and the pattern [true] is not permitted"#
                    ),
                    String::from(
                        r#"[NewVolume] failed because [Encrypted] is [true] and the pattern [true] is not permitted"#
                    )
                ],
                2
            )
        );
    }

    #[test]
    fn test_fail_on_regex_require_not_match_custom_message() {
        let template_contents = fs::read_to_string("tests/ebs_volume_template.json")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_content =
            String::from(r#"AWS::EC2::Volume Encrypted != /true/ << lorem ipsum"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_content, true).unwrap(),
            (
                vec![
                    String::from(
                        r#"[NewVolume2] failed because [Encrypted] is [true] and lorem ipsum"#
                    ),
                    String::from(
                        r#"[NewVolume] failed because [Encrypted] is [true] and lorem ipsum"#
                    )
                ],
                2
            )
        );
    }

    #[test]
    fn test_fail_require_not_custom_message() {
        let template_contents = fs::read_to_string("tests/ebs_volume_template.json")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_content =
            String::from(r#"AWS::EC2::Volume Encrypted != true << lorem ipsum"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_content, true).unwrap(),
            (
                vec![
                    String::from(
                        r#"[NewVolume2] failed because [Encrypted] is [true] and lorem ipsum"#
                    ),
                    String::from(
                        r#"[NewVolume] failed because [Encrypted] is [true] and lorem ipsum"#
                    )
                ],
                2
            )
        );
    }

    #[test]
    fn test_bad_template() {
        let template_contents = fs::read_to_string("tests/broken_template_file.json")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents =
            fs::read_to_string("tests/ebs_volume_rule_set_custom_msg.passing")
                .unwrap_or_else(|err| format!("{}", err));
        let error = match cfn_guard::run_check(&template_contents, &rules_file_contents, true) {
            Ok(_) => "".to_string(),
            Err(e) => e,
        };
        assert_eq!(
            error,
            String::from("Template file format was unreadable as json or yaml: invalid type: string \"THIS IS MEANT TO BE INVALID\", expected a map at line 1 column 1")
        );
    }

    #[test]
    fn test_custom_fail_message_pass() {
        let template_contents = fs::read_to_string("tests/ebs_volume_template.json")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents =
            fs::read_to_string("tests/ebs_volume_rule_set_custom_msg.passing")
                .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn test_custom_fail_message_fail() {
        // The results of this test are counter-intuitive because of the 'and the permitted value is'
        // result for one.  This is actually a correct behavior in the system right now in that the rule
        // defined in the rule set is
        //   AWS::EC2::Volume Size == 201i |OR| AWS::EC2::Volume Size == 199 "lorem ipsum"
        // Since an |OR| is a join of two discrete rules, you can see how the first half lacks a custom message.
        // I decided to leave that detail in the results to underscore the behavior so that it doesn't get
        // lost in the shuffle.
        let template_contents = fs::read_to_string("tests/ebs_volume_template.json")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents =
            fs::read_to_string("tests/ebs_volume_rule_set_custom_msg.failing")
                .unwrap_or_else(|err| format!("{}", err));
        let mut outcome = vec![
            String::from("[NewVolume2] failed because [Encrypted] is [true] and enc lorem ipsum"),
            String::from("[NewVolume2] failed because [Size] is [99] and or lorem ipsum"),
            String::from("[NewVolume2] failed because [Size] is [99] and the permitted value is [201]"),
            String::from("[NewVolume2] failed because ipsum lorem ipsum"),
            String::from("[NewVolume2] failed because [AvailabilityZone] is [us-west-2c] and azs lorem ipsum"),
            String::from("[NewVolume] failed because [AvailabilityZone] is [us-west-2b] and azs lorem ipsum"),
            String::from("[NewVolume] failed because [Encrypted] is [true] and enc lorem ipsum"),
            String::from("[NewVolume] failed because [Size] is [101] and or lorem ipsum"),
            String::from("[NewVolume] failed because [Size] is [101] and the permitted value is [201]"),
            String::from("[NewVolume] failed because ipsum lorem ipsum"),
            ];
        outcome.sort();
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (outcome, 2)
        );
    }

    #[test]
    fn test_not_in_list_fail() {
        let template_contents = String::from(
            r#"
                {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 101,
                        "Encrypted": true,
                        "AvailabilityZone" : "us-west-2b"
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 99,
                        "Encrypted": true,
                        "AvailabilityZone" : "us-west-2c"
                    }
                }
            }
        }"#,
        );

        let rules_file_contents = fs::read_to_string("tests/test_not_in_list_fail.ruleset")
            .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![
                String::from("[NewVolume2] failed because [us-west-2c] is not in [us-east-1a,us-east-1b,us-east-1c] for [AvailabilityZone]"),
                String::from("[NewVolume] failed because [us-west-2b] is not in [us-east-1a,us-east-1b,us-east-1c] for [AvailabilityZone]"),
            ], 2)
        );
    }

    #[test]
    fn test_in_list_fail_custom_message() {
        let template_contents = String::from(
            r#"
                {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 101,
                        "Encrypted": true,
                        "AvailabilityZone" : "us-west-2b"
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 99,
                        "Encrypted": true,
                        "AvailabilityZone" : "us-west-2c"
                    }
                }
            }
        }"#,
        );

        let rules_file_contents =
            fs::read_to_string("tests/test_in_list_fail_custom_message.ruleset")
                .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![
                String::from("[NewVolume2] failed because [AvailabilityZone] is [us-west-2c] and lorem ipsum"),
                String::from("[NewVolume] failed because [AvailabilityZone] is [us-west-2b] and lorem ipsum"),
            ], 2)
        );
    }

    #[test]
    fn test_get_resource_value_string() {
        let props = props_fixture();
        let field = vec!["AssumeRolePolicyDocument", "Version"];
        let result = cfn_guard::util::get_resource_prop_value(&props, &field).unwrap();
        assert_eq!(result, String::from("2012-10-17"))
    }

    #[test]
    fn test_get_resource_value_by_list_index() {
        let props = props_fixture();
        let field = vec!["AssumeRolePolicyDocument", "Statement", "0", "Effect"];
        let result = cfn_guard::util::get_resource_prop_value(&props, &field).unwrap();
        assert_eq!(result, String::from("Allow"))
    }

    #[test]
    fn test_mismatched_or_types_pass() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* == %{MOTP} |OR| AWS::IAM::Role AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/"#,
        );
        env::set_var("MOTP", "ec2.amazonaws.com"); // Env vars need to be unique to each test because they're global when `cargo test` runs
        let empty_vec: Vec<String> = Vec::new();
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (empty_vec, 0)
        );
    }

    #[test]
    fn test_mismatched_or_types_fail() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.0.Principal.Service.0 == %{MOTF} |OR| AWS::IAM::Role AssumeRolePolicyDocument.Version == /(\d{5})-(\d{2})-(\d{2})/"#,
        );
        env::set_var("MOTF", "motf"); // Env vars need to be unique to each test because they're global when `cargo test` runs
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0.Principal.Service.0] is [ec2.amazonaws.com] and the permitted value is [motf]"),
                  String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Version] is [2012-10-17] and the permitted pattern is [(\\d{5})-(\\d{2})-(\\d{2})]"), ],
             2)
        );
    }

    #[test]
    fn test_wildcard_not_eq_fail() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* != lambda.amazonaws.com
            AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* != ec2.amazonaws.com"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![
                String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0.Principal.Service.0] is [ec2.amazonaws.com] and that value is not permitted"),
                String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0.Principal.Service.1] is [lambda.amazonaws.com] and that value is not permitted"),
                String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.1.Principal.Service.0] is [lambda.amazonaws.com] and that value is not permitted"),
                String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.1.Principal.Service.1] is [ec2.amazonaws.com] and that value is not permitted"),
                String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.2.Principal.Service.0] is [lambda.amazonaws.com] and that value is not permitted"),
                String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.2.Principal.Service.1] is [ec2.amazonaws.com] and that value is not permitted"), ],
             2)
        );
    }

    #[test]
    fn test_wildcard_not_eq_pass() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* != wcf"#,
        );
        let empty_vec: Vec<String> = Vec::new();
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (empty_vec, 0)
        );
    }

    #[test]
    fn test_wildcard_eq_pass() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* == lambda.amazonaws.com"#,
        );
        let empty_vec: Vec<String> = Vec::new();
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (empty_vec, 0)
        );
    }

    #[test]
    fn test_wildcard_eq_fail() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* == wcf"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0.Principal.Service.0] is [ec2.amazonaws.com] and the permitted value is [wcf]"),
                  String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0.Principal.Service.1] is [lambda.amazonaws.com] and the permitted value is [wcf]"),
                  String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.1.Principal.Service.0] is [lambda.amazonaws.com] and the permitted value is [wcf]"),
                  String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.1.Principal.Service.1] is [ec2.amazonaws.com] and the permitted value is [wcf]"),
                  String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.2.Principal.Service.0] is [lambda.amazonaws.com] and the permitted value is [wcf]"),
                  String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.2.Principal.Service.1] is [ec2.amazonaws.com] and the permitted value is [wcf]"), ],
             2)
        );
    }

    #[test]
    fn test_env_var_pass() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.0.Principal.Service.0 == %{SERV_PRIN_EVP}"#,
        );

        env::set_var("SERV_PRIN_EVP", "lambda.amazonaws.com"); // Env vars need to be unique to each test because they're global when `cargo test` runs
        let empty_vec: Vec<String> = Vec::new();
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (empty_vec, 0)
        );
    }

    #[test]
    fn test_env_var_fail() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.0.Principal.Service.0 == %{SERV_PRIN_EVF}"#,
        );
        env::set_var("SERV_PRIN_EVF", "evf.amazonaws.com"); // Env vars need to be unique to each test because they're global when `cargo test` runs
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0.Principal.Service.0] is [lambda.amazonaws.com] and the permitted value is [evf.amazonaws.com]")], 2)
        );
    }

    #[test]
    fn test_regex_pass() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/"#,
        );
        let empty_vec: Vec<String> = Vec::new();
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (empty_vec, 0)
        );
    }

    #[test]
    fn test_regex_fail() {
        let template_file_contents = String::from(
            r#"Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Version == /(\d{5})-(\d{2})-(\d{2})/"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Version] is [2012-10-17] and the permitted pattern is [(\\d{5})-(\\d{2})-(\\d{2})]")], 2)
        );
    }

    #[test]
    fn test_missing_prop() {
        let template_file_contents = String::from(
            r#"{
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 100,
                        "AvailabilityZone" : "us-east-1b",
                        "DeletionPolicy" : "Snapshot"
                    }
                }
            }
        }"#,
        );
        let rules_file_contents = String::from(
            r#"let require_encryption = true
AWS::EC2::Volume Encrypted != %require_encryption"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume] failed because it does not contain the required property of [Encrypted]")], 2)
        );
    }

    #[test]
    fn test_missing_variable() {
        let template_file_contents = String::from(
            r#"{
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 100,
                        "AvailabilityZone" : "us-east-1b",
                        "Encrypted": true,
                        "DeletionPolicy" : "Snapshot"
                    }
                }
            }
        }"#,
        );
        let rules_file_contents = String::from(
            r#"
AWS::EC2::Volume Encrypted != %require_encryption"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume] failed because there is no value defined for [%require_encryption] to check [Encrypted] against")], 2)
        );
    }

    #[test]
    fn test_or_should_pass() {
        let template_file_contents = String::from(
            r#"{
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 100,
                        "Encrypted" : true,
                        "AvailabilityZone" : "us-east-1b",
                        "DeletionPolicy" : "Snapshot"
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 101,
                        "Encrypted" : true,
                        "AvailabilityZone" : "us-east-1b",
                        "DeletionPolicy" : "Snapshot"
                    }
                }
            }
        }"#,
        );
        let rules_file_contents = String::from(
            r#"
AWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [101]"),
                  String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [99]"),],
             2)
        );
    }

    #[test]
    fn test_less_than_comparison() {
        let template_file_contents = String::from(
            r#"{
                "Resources": {
                    "NewVolume" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 100,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    },
                    "NewVolume2" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 101,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    }
                }
            }"#,
        );
        let rules_file_contents = String::from(
            r#"
AWS::EC2::Volume Size < 101"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume2] failed because [Size] is [101] and the permitted value is [< 101]"), ],
             2)
        );
    }

    #[test]
    fn test_greater_than_comparison() {
        let template_file_contents = String::from(
            r#"{
                "Resources": {
                    "NewVolume" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 100,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    },
                    "NewVolume2" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 101,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    }
                }
            }"#,
        );
        let rules_file_contents = String::from(
            r#"
AWS::EC2::Volume Size > 100"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (
                vec![String::from(
                    "[NewVolume] failed because [Size] is [100] and the permitted value is [> 100]"
                ),],
                2
            )
        );
    }

    #[test]
    fn test_less_than_or_equal_to_comparison() {
        let template_file_contents = String::from(
            r#"{
                "Resources": {
                    "NewVolume" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 100,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    },
                    "NewVolume2" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 101,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    }
                }
            }"#,
        );
        let rules_file_contents = String::from(
            r#"
AWS::EC2::Volume Size <= 100"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume2] failed because [Size] is [101] and the permitted value is [<= 100]"), ],
             2)
        );
    }

    #[test]
    fn test_greater_than_or_equal_to_comparison() {
        let template_file_contents = String::from(
            r#"{
                "Resources": {
                    "NewVolume" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 100,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    },
                    "NewVolume2" : {
                        "Type" : "AWS::EC2::Volume",
                        "Properties" : {
                            "Size" : 101,
                            "Encrypted" : true,
                            "AvailabilityZone" : "us-east-1b",
                            "DeletionPolicy" : "Snapshot"
                        }
                    }
                }
            }"#,
        );
        let rules_file_contents = String::from(
            r#"
AWS::EC2::Volume Size >= 101"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [>= 101]"), ],
             2)
        );
    }

    #[test]
    fn test_json_results() {
        let template_file_contents = String::from(
            r#"{
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 100,
                        "Encrypted" : true,
                        "AvailabilityZone" : "us-east-1b",
                        "DeletionPolicy" : "Snapshot"
                    }
                }
            }
        }"#,
        );
        let rules_file_contents = String::from(
            r#"
let require_encryption = true
let snap_type = Snapshot
let disallowed_azs = [us-east-1a,us-east-1b,us-east-1c]


AWS::EC2::Volume AvailabilityZone NOT_IN %disallowed_azs
AWS::EC2::Volume DeletionPolicy == %snap_type
AWS::EC2::Volume Encrypted != %require_encryption
AWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume] failed because [Encrypted] is [true] and that value is not permitted"),
                  String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [101]"),
                  String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [99]"),
                  String::from("[NewVolume] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]")],
             2)
        );
    }

    #[test]
    fn test_yaml_results() {
        let template_file_contents = String::from(
            r#"Resources:
  NewVolume:
    Type: AWS::EC2::Volume
    Properties :
        Size: 100
        Encrypted: true
        AvailabilityZone: 'us-east-1b'
        DeletionPolicy: 'Snapshot'"#,
        );
        let rules_file_contents = String::from(
            r#"
let require_encryption = true
let snap_type = Snapshot
let disallowed_azs = [us-east-1a,us-east-1b,us-east-1c]


AWS::EC2::Volume AvailabilityZone NOT_IN %disallowed_azs
AWS::EC2::Volume DeletionPolicy == %snap_type
AWS::EC2::Volume Encrypted != %require_encryption
AWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_file_contents, &rules_file_contents, true).unwrap(),
            (vec![
                String::from("[NewVolume] failed because [Encrypted] is [true] and that value is not permitted"),
                String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [101]"),
                String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [99]"),
                String::from("[NewVolume] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]"), ],
             2)
        );
    }

    #[test]
    fn test_wildcard_tail_pass() {
        let template_contents = fs::read_to_string("tests/wildcard_rule_end_template_pass.yaml")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = String::from(
            r#"AWS::EC2::SecurityGroup Tags.* == {"Key":"EnvironmentType","Value":"EnvironmentType"}
                  AWS::EC2::SecurityGroup Tags.* == {"Key":"OwnerContact","Value":"OwnerContact"}"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn test_wildcard_tail_fail() {
        let template_contents = fs::read_to_string("tests/wildcard_rule_end_template_fail.yaml")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = String::from(
            r#"AWS::EC2::SecurityGroup Tags.* == {"Key":"EnvironmentType","Value":"EnvironmentType"}
                  AWS::EC2::SecurityGroup Tags.* == {"Key":"OwnerContact","Value":"OwnerContact"}"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (
                vec![
                    String::from(
                        r#"[ClusterSg] failed because [Tags.0] is [{"Key":"Name","Value":"${EnvironmentType}-${ClusterName}-sg"}] and the permitted value is [{"Key":"EnvironmentType","Value":"EnvironmentType"}]"#
                    ),
                    String::from(
                        r#"[ClusterSg] failed because [Tags.0] is [{"Key":"Name","Value":"${EnvironmentType}-${ClusterName}-sg"}] and the permitted value is [{"Key":"OwnerContact","Value":"OwnerContact"}]"#
                    ),
                    String::from(
                        r#"[ClusterSg] failed because [Tags.1] is [{"Key":"ClusterName","Value":"ECSCluster"}] and the permitted value is [{"Key":"EnvironmentType","Value":"EnvironmentType"}]"#
                    ),
                    String::from(
                        r#"[ClusterSg] failed because [Tags.1] is [{"Key":"ClusterName","Value":"ECSCluster"}] and the permitted value is [{"Key":"OwnerContact","Value":"OwnerContact"}]"#
                    ),
                    String::from(
                        r#"[ClusterSg] failed because [Tags.2] is [{"Key":"Scope","Value":"ecs"}] and the permitted value is [{"Key":"EnvironmentType","Value":"EnvironmentType"}]"#
                    ),
                    String::from(
                        r#"[ClusterSg] failed because [Tags.2] is [{"Key":"Scope","Value":"ecs"}] and the permitted value is [{"Key":"OwnerContact","Value":"OwnerContact"}]"#
                    ),
                ],
                2
            )
        );
    }

    #[test]
    fn test_diff_wildcard_type_pass() {
        let template_contents = fs::read_to_string("tests/aws-waf-security-automations.template")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string("tests/wildcard_iam_rule_set.passing")
            .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn test_diff_wildcard_type_fail() {
        let template_contents = fs::read_to_string("tests/aws-waf-security-automations.template")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string("tests/wildcard_not_in_iam_rule_set.failing")
            .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[LambdaRoleHelper] failed because [lambda.amazonaws.com] is in [lambda.amazonaws.com, ec2.amazonaws.com] which is not permitted for [AssumeRolePolicyDocument.Statement.0.Principal.Service.0]"), ],
             2)
        );
    }

    #[test]
    fn test_wildcard_action_pass() {
        let template_contents = fs::read_to_string("tests/wildcard_action.template")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string("tests/wildcard_action.pass")
            .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn test_wildcard_action_fail() {
        let template_contents = fs::read_to_string("tests/wildcard_action.template")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string("tests/wildcard_action.fail")
            .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[EndpointCloudWatchRoleC3C64E0F] failed because [AssumeRolePolicyDocument.Statement.0.Action] is [sts:AssumeRole] and that value is not permitted"),
                  String::from("[HelloHandlerServiceRole11EF7C63] failed because [AssumeRolePolicyDocument.Statement.0.Action] is [sts:AssumeRole] and that value is not permitted")],
             2)
        );
    }

    #[test]
    fn test_do_not_fail_when_type_lacks_property_for_wildcard() {
        // NOTE:  If this test is failing, it's probably because you're hitting the old process::exit statement
        // That shows up as an empty "error:  test failed"
        // Try running with "cargo test -- --nocapture"
        // If you see "Could not load value"... then it's the process exit
        let template_contents = fs::read_to_string(
            "tests/test_do_not_fail_when_type_lacks_property_for_wildcard.template",
        )
        .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string(
            "tests/test_do_not_fail_when_type_lacks_property_for_wildcard.ruleset",
        )
        .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume2] failed because it does not contain the required property of [Tags.0.Key]"),
                  String::from("[NewVolume2] failed because it does not contain the required property of [Tags.1.Key]"),
                  String::from("[NewVolume] failed because [Tags.0.Key] is [uaid] and the permitted value is [uai]"),
                  String::from("[NewVolume] failed because [Tags.1.Key] is [tag2] and the permitted value is [uai]")],
             2)
        );
    }

    #[test]
    fn test_run_wildcard_check_without_strict_check() {
        // NOTE:  If this test is failing, it's probably because you're hitting the old process::exit statement
        // That shows up as an empty "error:  test failed"
        // Try running with "cargo test -- --nocapture"
        // If you see "Could not load value"... then it's the process exit
        let template_contents = fs::read_to_string(
            "tests/test_do_not_fail_when_type_lacks_property_for_wildcard.template",
        )
        .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string(
            "tests/test_do_not_fail_when_type_lacks_property_for_wildcard.ruleset",
        )
        .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![String::from("[NewVolume] failed because [Tags.0.Key] is [uaid] and the permitted value is [uai]"),
                  String::from("[NewVolume] failed because [Tags.1.Key] is [tag2] and the permitted value is [uai]")],
             2)
        );
    }

    #[test]
    fn test_for_getatt_yaml() {
        let template_contents = fs::read_to_string("tests/getatt_template.yaml")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string("tests/getatt_template.ruleset")
            .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![String::from("[EC2Instance] failed because [t3.medium] is not in [t2.nano,t2.micro,t2.small,t3.nano,t3.micro,t3.small] for [InstanceType]"),
                  String::from("[InstanceSecurityGroup] failed because [SecurityGroupIngress] is [[{\"CidrIp\":\"SSHLocation\",\"FromPort\":22,\"IpProtocol\":\"tcp\",\"ToPort\":22}]] and the permitted value is [[{\"CidrIp\":\"SSHLocation\",\"FromPort\":33322,\"IpProtocol\":\"tcp\",\"ToPort\":33322}]]"),
                  String::from("[NewVolume] failed because [Size] is [512] and the permitted value is [128]"),
                  String::from("[NewVolume] failed because [Size] is [512] and the permitted value is [256]"),
                  String::from("[NewVolume] failed because [[\"EC2Instance\",\"AvailabilityZone\"]] is not in [us-east-1a,us-east-1b,us-east-1c] for [AvailabilityZone]")],
             2)
        )
    }

    #[test]
    fn test_for_getatt_json() {
        let template_contents = fs::read_to_string("tests/getatt_template.json")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string("tests/getatt_template.ruleset")
            .unwrap_or_else(|err| format!("{}", err));
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![String::from("[NewVolume2] failed because [Encrypted] is [true] and that value is not permitted"),
                  String::from("[NewVolume2] failed because [Size] is [99] and the permitted value is [128]"),
                  String::from("[NewVolume2] failed because [Size] is [99] and the permitted value is [256]"),
                  String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [128]"),
                  String::from("[NewVolume] failed because [Size] is [100] and the permitted value is [256]"),
                  String::from("[NewVolume] failed because [{\"Fn::GetAtt\":[\"EC2Instance\",\"AvailabilityZone\"]}] is not in [us-east-1a,us-east-1b,us-east-1c] for [AvailabilityZone]")
            ],
             2)
        )
    }

    #[test]
    fn test_missing_resources_in_template() {
        let template_contents = fs::read_to_string("tests/no_resources_template.yaml")
            .unwrap_or_else(|err| format!("{}", err));
        let rules_file_contents = fs::read_to_string("tests/no_resources_template.ruleset")
            .unwrap_or_else(|err| format!("{}", err));
        let error = match cfn_guard::run_check(&template_contents, &rules_file_contents, true) {
            Ok(_) => "".to_string(),
            Err(e) => e,
        };
        assert_eq!(
            error,
            String::from("Template file does not contain a [Resources] section to check")
        )
    }

    #[test]
    fn test_parse_lists_with_json() {
        let mut template_contents =
            fs::read_to_string("tests/parse_lists_with_json_test-template.yaml")
                .unwrap_or_else(|err| format!("{}", err));
        let mut rules_file_contents = String::from(
            r#"
                let tag_vals = ["test", 1, ["a", "b"], {"Key":"OwnerContact","Value":"OwnerContact"},{"Key":"OwnerContact","Value":{"Ref":"OwnerContact"}}]
                AWS::EC2::SecurityGroup Tags.* NOT_IN %tag_vals
            "#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (
                vec![String::from(
                    r#"[ClusterSg] failed because [{"Key":"OwnerContact","Value":"OwnerContact"}] is in ["test", 1, ["a", "b"], {"Key":"OwnerContact","Value":"OwnerContact"},{"Key":"OwnerContact","Value":{"Ref":"OwnerContact"}}] which is not permitted for [Tags.1]"#
                )],
                2
            )
        );
        rules_file_contents = String::from(
            r#"
                let tag_vals = ["test", 1, ["a", "b"], {"Key":"OwnerContact","Value":"OwnerContact"},{"Key":"OwnerContact","Value":{"Ref":"OwnerContact"}}]
                AWS::EC2::SecurityGroup Tags.* IN %tag_vals
            "#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );
        template_contents = fs::read_to_string("tests/parse_lists_with_json_test-template.json")
            .unwrap_or_else(|err| format!("{}", err));
        let mut rules_file_contents = String::from(
            r#"
                let tag_vals = ["test", 1, ["a", "b"], {"Key":"OwnerContact","Value":"OwnerContact"},{"Key":"OwnerContact","Value":{"Ref":"OwnerContact"}}]
                AWS::EC2::SecurityGroup Tags.* NOT_IN %tag_vals
            "#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (
                vec![String::from(
                    r#"[ClusterSg] failed because [{"Key":"OwnerContact","Value":{"Ref":"OwnerContact"}}] is in ["test", 1, ["a", "b"], {"Key":"OwnerContact","Value":"OwnerContact"},{"Key":"OwnerContact","Value":{"Ref":"OwnerContact"}}] which is not permitted for [Tags.1]"#
                )],
                2
            )
        );
        rules_file_contents = String::from(
            r#"
                let tag_vals = ["test", 1, ["a", "b"], {"Key":"OwnerContact","Value":"OwnerContact"},{"Key":"OwnerContact","Value":{"Ref":"OwnerContact"}}]
                AWS::EC2::SecurityGroup Tags.* IN %tag_vals
            "#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn test_wildcard_descent() {
        // Pass *.*.*
        let template_contents = fs::read_to_string("tests/wildcard-descent-template.yaml")
            .unwrap_or_else(|err| format!("{}", err));
        let mut rules_file_contents = String::from(
            r#"
            let log_stuff = [Solution, Data, LogLevel]
            AWS::Lambda::Function Environment.*.*.* IN %log_stuff"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        // Fail *.*.*
        rules_file_contents = String::from(
            r#"
            let log_stuff = [Solution, Data, LogLevel]
            AWS::Lambda::Function Environment.*.*.* NOT_IN %log_stuff"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (
                vec![
                    String::from(
                        r#"[LambdaWAFHelperFunction] failed because [Data] is in [Solution, Data, LogLevel] which is not permitted for [Environment.Variables.LOG_LEVEL.1]"#
                    ),
                    String::from(
                        r#"[LambdaWAFHelperFunction] failed because [LogLevel] is in [Solution, Data, LogLevel] which is not permitted for [Environment.Variables.LOG_LEVEL.2]"#
                    ),
                    String::from(
                        r#"[LambdaWAFHelperFunction] failed because [Solution] is in [Solution, Data, LogLevel] which is not permitted for [Environment.Variables.LOG_LEVEL.0]"#
                    )
                ],
                2
            )
        );

        // Pass over-wildcarding (ie, wildcards in structures that don't extend that deeply
        rules_file_contents = String::from(r#"AWS::Lambda::Function MemorySize.*.* IN [128]"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        // Pass for checks of a list inside of a list
        rules_file_contents = String::from(
            r#"AWS::Lambda::Function Environment.*.* IN [["Solution", "Data", "LogLevel"]]"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        // Fail for checks of a list inside of a list
        rules_file_contents = String::from(
            r#"AWS::Lambda::Function Environment.*.* NOT_IN [["Solution", "Data", "LogLevel"]]"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (
                vec![String::from(
                    r#"[LambdaWAFHelperFunction] failed because [["Solution","Data","LogLevel"]] is in [["Solution", "Data", "LogLevel"]] which is not permitted for [Environment.Variables.LOG_LEVEL]"#
                )],
                2
            )
        );

        // Pass for checks of a wildcard in the middle of the properties
        rules_file_contents = String::from(
            r#"AWS::Lambda::Function Environment.*.LOG_LEVEL IN [["Solution", "Data", "LogLevel"]]"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        // Fail for checks of a wildcard in the middle of the properties
        rules_file_contents = String::from(
            r#"AWS::Lambda::Function Environment.*.LOG_LEVEL NOT_IN [["Solution", "Data", "LogLevel"]]"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (
                vec![String::from(
                    r#"[LambdaWAFHelperFunction] failed because [["Solution","Data","LogLevel"]] is in [["Solution", "Data", "LogLevel"]] which is not permitted for [Environment.Variables.LOG_LEVEL]"#
                )],
                2
            )
        );

        // Pass for checks of a wildcard at the start of the properties
        rules_file_contents = String::from(
            r#"AWS::Lambda::Function *.*.LOG_LEVEL IN [["Solution", "Data", "LogLevel"]]"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );

        // Fail for checks of a wildcard at the start of the properties
        rules_file_contents = String::from(
            r#"AWS::Lambda::Function *.*.LOG_LEVEL NOT_IN [["Solution", "Data", "LogLevel"]]"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (
                vec![String::from(
                    r#"[LambdaWAFHelperFunction] failed because [["Solution","Data","LogLevel"]] is in [["Solution", "Data", "LogLevel"]] which is not permitted for [Environment.Variables.LOG_LEVEL]"#
                )],
                2
            )
        );
    }

    #[test]
    fn test_bad_rule() {
        let template_contents = fs::read_to_string("tests/conditional-ddb-template.yaml")
            .unwrap_or_else(|err| format!("{}", err));

        let rules_file_contents = String::from(
            "AWS::DynamoDB::Table if Tags == /.*PROD.*/ then .DeletionPolicy == Retain",
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false),
            Err(String::from(
                r#"BAD RULE: "AWS::DynamoDB::Table if Tags == /.*PROD.*/ then .DeletionPolicy == Retain""#
            ))
        );
    }

    #[test]
    fn test_conditional_check() {
        let template_contents = fs::read_to_string("tests/conditional-ddb-template.yaml")
            .unwrap_or_else(|err| format!("{}", err));

        let mut rules_file_contents = String::from(
            "AWS::DynamoDB::Table when Tags == /.*PROD.*/ check .DeletionPolicy == Retain",
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            "AWS::DynamoDB::Table when Tags != /.*DEV.*/ check .DeletionPolicy == Retain",
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            "AWS::DynamoDB::Table WHEN Tags == /.*PROD.*/ check .DeletionPolicy != Retain",
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![String::from("[DDBTable] failed because [.DeletionPolicy] is [Retain] and that value is not permitted when AWS::DynamoDB::Table Tags == /.*PROD.*/")],
             2)
        );
        rules_file_contents = String::from(
            "AWS::DynamoDB::Table when Tags != /.*DEV.*/ CHECK .DeletionPolicy != Retain",
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![String::from("[DDBTable] failed because [.DeletionPolicy] is [Retain] and that value is not permitted when AWS::DynamoDB::Table Tags != /.*DEV.*/")], 2)
        )
    }

    #[test]
    fn test_compound_conditional_check() {
        let template_contents = fs::read_to_string("tests/conditional-ddb-template.yaml")
            .unwrap_or_else(|err| format!("{}", err));

        let mut rules_file_contents = String::from(
            "AWS::DynamoDB::Table when Tags == /.*PROD.*/ check .DeletionPolicy == Retain |OR|AWS::DynamoDB::Table WHEN Tags.* == /.*DEV.*/ CHECK .UpdateReplacePolicy == Retain",
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            "AWS::DynamoDB::Table when Tags != /.*DEV.*/ CHECK .DeletionPolicy == Retain |OR| AWS::DynamoDB::Table Tags.* != PROD",
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            r#"AWS::DynamoDB::Table WHEN Tags == /.*PROD.*/ check .DeletionPolicy != Retain"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (
                vec![String::from(
                    r#"[DDBTable] failed because [.DeletionPolicy] is [Retain] and that value is not permitted when AWS::DynamoDB::Table Tags == /.*PROD.*/"#
                )],
                2
            )
        );
    }

    #[test]
    fn test_conditional_checks_with_custom_messages() {
        let template_contents = fs::read_to_string("tests/conditional-ddb-template.yaml")
            .unwrap_or_else(|err| format!("{}", err));

        let rules_file_contents = String::from(
            r#"AWS::DynamoDB::Table WHEN Tags == /.*PROD.*/ << custom conditional message check .DeletionPolicy != Retain << custom consequent message"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (
                vec![String::from(
                    r#"[DDBTable] failed because [.DeletionPolicy] is [Retain] and custom consequent message when AWS::DynamoDB::Table Tags == /.*PROD.*/ << custom conditional message"#
                )],
                2
            )
        );
    }

    #[test]
    fn test_conditional_corner_cases() {
        // This test ensures that missing properties _aren't_ checked and an alternative approach to expressing conditional forms across different types
        let template_contents =
            fs::read_to_string("tests/test-multiple-resources-conditional-template.yaml")
                .unwrap_or_else(|err| format!("{}", err));

        let rules_file_contents = String::from(
            r#"AWS::Lambda::Function WHEN madeupproperty == somevalue << test of cond message CHECK ProvisioningArtifactName == apig_2.0 << test of cons message
            AWS::Lambda::Function Runtime != /.*/ |OR| AWS::ServiceCatalog::CloudFormationProvisionedProduct ProvisioningParameters.*.Value == lambdaFunction.Arn
            AWS::Lambda::Function Runtime != Java |OR| AWS::ServiceCatalog::CloudFormationProvisionedProduct ProvisioningParameters.*.Value == lambdaFunction.Arn
            AWS::ServiceCatalog::CloudFormationProvisionedProduct ProvisioningParameters.*.Value == lambdaFunction.Arn"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false).unwrap(),
            (vec![], 0)
        )
    }

    #[test]
    fn test_conditional_bad_consequent() {
        // This test ensures that missing properties _aren't_ checked and an alternative approach to expressing conditional forms across different types
        let template_contents =
            fs::read_to_string("tests/test-multiple-resources-conditional-template.yaml")
                .unwrap_or_else(|err| format!("{}", err));

        let rules_file_contents = String::from(
            r#"AWS::Lambda::Function WHEN madeupproperty == somevalue << test of cond message CHECK AWS::EC2::Volume ProvisioningArtifactName == apig_2.0 << test of cons message"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false),
            Err(String::from(
                r#"Invalid consequent: 'AWS::EC2::Volume ProvisioningArtifactName == apig_2.0 << test of cons message' in 'AWS::Lambda::Function WHEN madeupproperty == somevalue << test of cond message CHECK AWS::EC2::Volume ProvisioningArtifactName == apig_2.0 << test of cons message'. Consequents cannot contain resource types."#
            ))
        )
    }

    #[test]
    fn test_bad_assignment() {
        let template_contents =
            fs::read_to_string("tests/test-multiple-resources-conditional-template.yaml")
                .unwrap_or_else(|err| format!("{}", err));

        let rules_file_contents = String::from(r#"let x == y"#);

        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, false),
            Err(String::from(
                r#"Bad Assignment Operator: [==] in 'let x == y'"#
            ))
        )
    }
    #[test]
    fn test_root_wildcard() {
        let template_contents = fs::read_to_string("tests/root-wildcard-template.json")
            .unwrap_or_else(|err| format!("{}", err));

        let mut rules_file_contents = String::from(r#"AWS::EC2::Volume * != true"#);

        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (
                vec![
                    String::from(
                        r#"[NewVolume2] failed because [Encrypted] is [true] and that value is not permitted"#
                    ),
                    String::from(
                        r#"[NewVolume2] failed because it does not contain the required property of [AutoEnableIO]"#
                    ),
                    String::from(
                        r#"[NewVolume] failed because [AutoEnableIO] is [true] and that value is not permitted"#
                    ),
                    String::from(
                        r#"[NewVolume] failed because [Encrypted] is [true] and that value is not permitted"#
                    )
                ],
                2
            )
        );

        rules_file_contents = String::from(r#"AWS::EC2::Volume * == true"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        )
    }
    #[test]
    fn test_stringifed_json_descent() {
        let template_contents = fs::read_to_string("tests/stringified-json-template.yaml")
            .unwrap_or_else(|err| format!("{}", err));

        let mut rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.0 == {      "Effect": "Allow",      "Principal": {        "Service": [          "notlambda.amazonaws.com"        ]      }    } "#,
        );

        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.* == {      "Effect": "Allow",      "Principal": {        "Service": [          "notlambda.amazonaws.com"        ]      }    } "#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.0 == {"Effect": "Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents =
            String::from(r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.0.Effect == Allow"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents =
            String::from(r#"AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Effect == Allow"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument == {"Statement":[{"Effect": "Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}]}"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );

        rules_file_contents = String::from(
            r#"AWS::IAM::Role AssumeRolePolicyDocument != {"Statement":[{"Effect": "Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}]}
                  AWS::IAM::Role AssumeRolePolicyDocument.Statement != [{"Effect": "Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}]
                  AWS::IAM::Role AssumeRolePolicyDocument.Statement.0 != {"Effect": "Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}
                  AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Effect != Allow"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (
                vec![String::from("[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0.Effect] is [Allow] and that value is not permitted"),
            String::from(r#"[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement.0] is [{"Effect":"Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}] and that value is not permitted"#),
            String::from(r#"[LambdaRoleHelper] failed because [AssumeRolePolicyDocument.Statement] is [[{"Effect":"Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}]] and that value is not permitted"#),
            String::from(r#"[LambdaRoleHelper] failed because [AssumeRolePolicyDocument] is [{"Statement":[{"Effect":"Allow","Principal":{"Service":["notlambda.amazonaws.com"]}}]}] and that value is not permitted"#)],
                2
            )
        )
    }
    #[test]
    fn test_correct_whitespace() {
        // Value comparisons during rule eval remove whitespace but the result message should not to avoid confusing the user
        let template_contents = String::from(
            r#"Resources:
  NewVolume:
    Type: AWS::EC2::Volume
    Properties :
        Description: This is a description"#,
        );
        let rules_file_contents =
            String::from(r#"AWS::EC2::Volume Description == This is  a  description"#); // inserted a space on either side of 'a'
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn test_for_inline_comment() {
        let template_contents = String::from(
            r#"Resources:
  NewVolume:
    Type: AWS::EC2::Volume
    Properties :
        Description: This is a description"#,
        );
        let rules_file_contents = String::from(
            r#"AWS::EC2::Volume Description == This is  a  description # this comment shouldn't be here"#,
        );
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![String::from("[NewVolume] failed because [Description] is [This is a description] and the permitted value is [This is  a  description # this comment shouldn't be here]")], 2)
        );
    }

    #[test]
    fn test_for_comments_with_whitespace() {
        let template_contents = String::from(
            r#"Resources:
  NewVolume:
    Type: AWS::EC2::Volume
    Properties :
        Description: This is a description"#,
        );
        let rules_file_contents = String::from(r#"                         # Comment!! :-o"#);
        assert_eq!(
            cfn_guard::run_check(&template_contents, &rules_file_contents, true).unwrap(),
            (vec![], 0)
        );
    }
}
