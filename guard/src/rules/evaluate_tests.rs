use super::*;
use crate::rules::parser::{rules_file, Span};
use crate::commands::files::read_file_content;
use std::fs::File;
use std::convert::TryFrom;

const RULES_FILES_EXAMPLE: &str = r###"
rule iam_role_exists {
    Resources.*[ Type == "AWS::IAM::Role" ] EXISTS
}

rule iam_role_lambda_compliance when iam_role_exists {
    let roles = Resources.*[ Type == "AWS::IAM::Role" ]
    let select_lambda_service = %roles.Properties.AssumeRolePolicyDocument.Statement[ Principal.Service EXISTS
                                                                                      Principal.Service.* == /^lambda/ ]

    %select_lambda_service EMPTY or
    %select_lambda_service.Action.* == /sts:AssumeRole/
}
"###;


fn parse_rules<'c>(rules: &'c str, name: &'c str) -> Result<RulesFile<'c>> {
    let span = Span::new_extra(rules, name);
    rules_file(span)
}

fn read_data(file: File) -> Result<Value> {
    let context = read_file_content(file)?;
    match serde_json::from_str::<serde_json::Value>(&context) {
        Ok(value) => Value::try_from(value),
        Err(_) => {
            let value = serde_yaml::from_str::<serde_json::Value>(&context)?;
            Value::try_from(value)
        }
    }
}

#[test]
fn guard_access_clause_test_all_up() -> Result<()> {
    let rules = parse_rules(RULES_FILES_EXAMPLE, "iam-rules.gr")?;
    let root = read_data(File::open("assets/cfn-lambda.yaml")?)?;
    Ok(())
}

struct DummyEval{}
impl EvaluationContext for DummyEval {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        unimplemented!()
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        unimplemented!()
    }

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<Value>, to: Option<Value>, status: Status) {
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
    }
}

#[test]
fn guard_access_clause_tests() -> Result<()> {
    let dummy = DummyEval{};
    let root = read_data(File::open("assets/cfn-lambda.yaml")?)?;
    let clause = GuardClause::try_from(
        r#"Resources.*[ Type == "AWS::IAM::Role" ].Properties.AssumeRolePolicyDocument.Statement[
                     Principal.Service EXISTS
                     Principal.Service == /^lambda/ ].Action == "sts:AssumeRole""#
    )?;
    let status = clause.evaluate(&root, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(Status::PASS, status);

    let clause = GuardClause::try_from(
        r#"Resources.*[ Type == "AWS::IAM::Role" ].Properties.AssumeRolePolicyDocument.Statement[
                     Principal.Service EXISTS
                     Principal.Service == /^notexists/ ].Action == "sts:AssumeRole""#
    )?;
    match clause.evaluate(&root, &dummy) {
        Ok(_) => assert!(false),
        Err(_) => {}
    }
    Ok(())
}

#[test]
fn rule_clause_tests() -> Result<()> {
    let dummy = DummyEval{};
    let r = r###"
    rule check_all_resources_have_tags_present {
    let all_resources = Resources.*.Properties

    %all_resources.Tags EXISTS
    %all_resources.Tags !EMPTY
}
    "###;
    let rule = Rule::try_from(r)?;

    let v = r#"
    {
        "Resources": {
            "vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/25",
                    "Tags": [
                        {
                            "Key": "my-vpc",
                            "Value": "my-vpc"
                        }
                    ]
                }
            }
        }
    }
    "#;

    let value = Value::try_from(v)?;
    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(Status::PASS, status);

    let r = r###"
    rule iam_basic_checks {
  AWS::IAM::Role {
    Properties.AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/
    Properties.PermissionsBoundary == /arn:aws:iam::(\d{12}):policy/
    when Properties.Tags EXISTS
         Properties.Tags !EMPTY {

        Properties.Tags.Value == /[a-zA-Z0-9]+/
        Properties.Tags.Key   == /[a-zA-Z0-9]+/
    }
  }
}"###;
    let rule = Rule::try_from(r)?;
    Ok(())
}

struct Reporter<'r>(&'r dyn EvaluationContext);
impl<'r> EvaluationContext for Reporter<'r> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        self.0.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.0.rule_status(rule_name)
    }

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<Value>, to: Option<Value>, status: Status) {
        println!("{} {} {}", eval_type, context, status);
        self.0.end_evaluation(
            eval_type, context, msg, from, to, status
        )
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
        println!("{} {}", eval_type, context);
    }
}

#[test]
fn rules_file_tests() -> Result<()> {
    let file = r###"
let iam_resources = Resources.*[ Type == "AWS::IAM::Role" ]
rule iam_resources_exists {
    %iam_resources !EMPTY
}

rule iam_basic_checks when iam_resources_exists {
    %iam_resources.Properties.AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/
    %iam_resources.Properties.PermissionsBoundary == /arn:aws:iam::(\d{12}):policy/
    when %iam_resources.Properties.Tags EXISTS
         %iam_resources.Properties.Tags !EMPTY {

        %iam_resources.Properties.Tags.Value == /[a-zA-Z0-9]+/
        %iam_resources.Properties.Tags.Key   == /[a-zA-Z0-9]+/
    }
}"###;

    let value = r###"
    {
        "Resources": {
            "iamrole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "PermissionsBoundary": "arn:aws:iam::123456789012:policy/permboundary",
                    "AssumeRolePolicyDocument": {
                        "Version": "2021-01-10",
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*"
                        }
                    }
                }
            }
        }
    }
    "###;

    let root = Value::try_from(value)?;
    let rules_file = RulesFile::try_from(file)?;
    let root_context = RootScope::new(&rules_file, &root);
    let reporter = Reporter(&root_context);
    let status = rules_file.evaluate(&root, &reporter)?;
    assert_eq!(Status::PASS, status);
    Ok(())
}

#[test]
fn test_iam_statement_clauses() -> Result<()> {
    let sample = r###"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "false"},
                    "StringEquals": {"aws:SourceVpc": "vpc-12243sc"}
                }
            },
            {
                "Sid": "ServicePutObject",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "true"}
                }
            }
        ]
    }
    "###;
    let value = Value::try_from(sample)?;

    let dummy = DummyEval{};
    let reporter = Reporter(&dummy);

    let clause = "Statement[ Condition EXISTS ].Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] NOT EMPTY";
    // let clause = "Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ]";
    let parsed = GuardClause::try_from(clause)?;
    let status = parsed.evaluate(&value, &reporter)?;
    println!("Status {:?}", status);
    assert_eq!(Status::PASS, status);

    let clause = r#"Statement[ Condition EXISTS
                                     Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] NOT EMPTY
    "#;
    let parsed = GuardClause::try_from(clause)?;
    let status = parsed.evaluate(&value, &reporter)?;
    println!("Status {:?}", status);
    assert_eq!(Status::PASS, status);

    let sample = r###"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "false"}
                }
            },
            {
                "Sid": "ServicePutObject",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "true"}
                }
            }
        ]
    }
    "###;
    let value = Value::try_from(sample)?;
    let parsed = GuardClause::try_from(clause)?;
    let status = parsed.evaluate(&value, &reporter)?;
    println!("Status {:?}", status);
    assert_eq!(Status::FAIL, status);

    Ok(())
}

#[test]
fn test_api_gateway() -> Result<()> {
    let rule = r###"
rule check_rest_api_private {
  AWS::ApiGateway::RestApi {
    # Endpoint configuration must only be private
    Properties.EndpointConfiguration.Types == ["PRIVATE"]

    # At least one statement in the resource policy must contain a condition with the key of "aws:sourceVpc" or "aws:sourceVpce"
    Properties.Policy.Statement[ Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] ] !EMPTY
  }
}
    "###;

    let rule = Rule::try_from(rule)?;

    let resources = r###"
    {
        "Resources": {
            "apigatewayapi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "PrincipalPutObjectIfIpAddress",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "false"},
                                    "StringEquals": {"aws:SourceVpc": "vpc-12243sc"}
                                }
                            },
                            {
                                "Sid": "ServicePutObject",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "true"}
                                }
                            }
                        ]
                    },
                    "EndpointConfiguration"; ["PRIVATE"]
                }
            }
        }
    }
    "###;

    let value = Value::try_from(resources)?;
    let dummy = DummyEval{};
    let reporter = Reporter(&dummy);
    let status = rule.evaluate(&value, &reporter)?;
    println!("{}", status);
    Ok(())
}

