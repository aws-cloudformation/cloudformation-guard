use super::*;
use super::super::path_value;
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
    let _rules = parse_rules(RULES_FILES_EXAMPLE, "iam-rules.gr")?;
    let _root = read_data(File::open("assets/cfn-lambda.yaml")?)?;
    Ok(())
}

struct DummyEval{}
impl EvaluationContext for DummyEval {
    fn resolve_variable(&self, _variable: &str) -> Result<Vec<&PathAwareValue>> {
        unimplemented!()
    }

    fn rule_status(&self, _rule_name: &str) -> Result<Status> {
        unimplemented!()
    }

    fn end_evaluation(&self, _eval_type: EvaluationType, _context: &str, _msg: String, _from: Option<PathAwareValue>, _to: Option<PathAwareValue>, _status: Option<Status>) {
    }

    fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {
    }
}

#[test]
fn guard_access_clause_tests() -> Result<()> {
    let dummy = DummyEval{};
    let root = read_data(File::open("assets/cfn-lambda.yaml")?)?;
    let root = PathAwareValue::try_from(root)?;
    let clause = GuardClause::try_from(
        r#"Resources.*[ Type == "AWS::IAM::Role" ].Properties.AssumeRolePolicyDocument.Statement[
                     Principal.Service EXISTS
                     Principal.Service == /^lambda/ ].Action == "sts:AssumeRole""#
    )?;
    let status = clause.evaluate(&root, &dummy)?;
    assert_eq!(Status::PASS, status);

    let clause = GuardClause::try_from(
        r#"Resources.*[ Type == "AWS::IAM::Role" ].Properties.AssumeRolePolicyDocument.Statement[
                     Principal.Service EXISTS
                     Principal.Service == /^notexists/ ].Action == "sts:AssumeRole""#
    )?;
    match clause.evaluate(&root, &dummy) {
        Ok(Status::SKIP) => {},
        _rest => assert!(false)
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
    let value = PathAwareValue::try_from(value)?;
    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(Status::PASS, status);

    let r = r###"
    rule iam_basic_checks {
  AWS::IAM::Role {
    Properties.AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/
    Properties.PermissionsBoundary == /arn:aws:iam::(\d{12}):policy/
    Properties.Tags[*].Value == /[a-zA-Z0-9]+/
    Properties.Tags[*].Key   == /[a-zA-Z0-9]+/
  }
}"###;
    let _rule = Rule::try_from(r)?;
    Ok(())
}

struct Reporter<'r>(&'r dyn EvaluationContext);
impl<'r> EvaluationContext for Reporter<'r> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        self.0.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.0.rule_status(rule_name)
    }

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<PathAwareValue>, to: Option<PathAwareValue>, status: Option<Status>) {
        println!("{} {} {:?}", eval_type, context, status);
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
    let root = PathAwareValue::try_from(root)?;
    let rules_file = RulesFile::try_from(file)?;
    let root_context = RootScope::new(&rules_file, &root);
    let reporter = Reporter(&root_context);
    let status = rules_file.evaluate(&root, &reporter)?;
    assert_eq!(Status::PASS, status);
    Ok(())
}

#[test]
fn rules_not_in_tests() -> Result<()> {
    let clause = "Resources.*.Type NOT IN [/AWS::IAM/, /AWS::S3/]";
    let parsed = GuardClause::try_from(clause)?;
    let value = "{ Resources: { iam: { Type: 'AWS::IAM::Role' } } }";
    let parsed_value = PathAwareValue::try_from(value)?;
    let dummy = DummyEval{};
    let status = parsed.evaluate(&parsed_value, &dummy)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

const SAMPLE: &str = r###"
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
    let value = PathAwareValue::try_from(value)?;

    let dummy = DummyEval{};
    let reporter = Reporter(&dummy);

    let clause = "Statement[ Condition EXISTS ].Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] NOT EMPTY";
    // let clause = "Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ]";
    let parsed = GuardClause::try_from(clause)?;
    let status = parsed.evaluate(&value, &reporter)?;
    assert_eq!(Status::PASS, status);

    let clause = r#"Statement[ Condition EXISTS
                                     Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] NOT EMPTY
    "#;
    let parsed = GuardClause::try_from(clause)?;
    let status = parsed.evaluate(&value, &reporter)?;
    assert_eq!(Status::PASS, status);

    let value = Value::try_from(SAMPLE)?;
    let value = PathAwareValue::try_from(value)?;
    let parsed = GuardClause::try_from(clause)?;
    let status = parsed.evaluate(&value, &reporter)?;
    assert_eq!(Status::FAIL, status);

    Ok(())
}

#[test]
fn test_api_gateway() -> Result<()> {
    let rule = r###"
rule check_rest_api_private {
  AWS::ApiGateway::RestApi {
    # Endpoint configuration must only be private
    Properties.EndpointConfiguration == ["PRIVATE"]

    # At least one statement in the resource policy must contain a condition with the key of "aws:sourceVpc" or "aws:sourceVpce"
    Properties.Policy.Statement[ Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] !EMPTY
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
                    "EndpointConfiguration": ["PRIVATE"]
                }
            }
        }
    }"###;

    let value = Value::try_from(resources)?;
    let value = PathAwareValue::try_from(value)?;
    let dummy = DummyEval{};
    let reporter = Reporter(&dummy);
    let status = rule.evaluate(&value, &reporter)?;
    assert_eq!(status, Status::PASS);
    Ok(())
}

#[test]
fn testing_iam_role_prov_serve() -> Result<()> {
    let resources = r###"
    {
        "Resources": {
            "CounterTaskDefExecutionRole5959CB2D": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {
                            "Service": "ecs-tasks.amazonaws.com"
                            }
                        }],
                        "Version": "2012-10-17"
                    },
                    "PermissionBoundary": {"Fn::Sub" : "arn::aws::iam::${AWS::AccountId}:policy/my-permission-boundary"},
                    "Tags": [{ "Key": "TestRole", "Value": ""}]
                },
                "Metadata": {
                    "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
                }
            }
        }
    }
    "###;

    let rules = r###"
let iam_roles = Resources.*[ Type == "AWS::IAM::Role"  ]
let ecs_tasks = Resources.*[ Type == "AWS::ECS::TaskDefinition" ]

rule deny_permissions_boundary_iam_role {
    # atleast one Tags contains a Key "TestRole"
    %iam_roles {
        Properties {
            Tags[ Key == "TestRole" ] NOT EMPTY
            PermissionBoundary NOT EXISTS
        }
    }
}"###;

    let rules_file = RulesFile::try_from(rules)?;
    let value = PathAwareValue::try_from(resources)?;

    // let dummy = DummyEval{};
    let root_context = RootScope::new(&rules_file, &value);
    let reporter = Reporter(&root_context);
    let status = rules_file.evaluate(&value, &reporter)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

#[test]
fn testing_sg_rules_pro_serve() -> Result<()> {
    let sgs = r###"
    [{
    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "Description": "Allow all outbound traffic by default",
            "IpProtocol": "-1"
          }
        ],
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
},
    {
    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "SecurityGroupEgress": [
          {
            "CidrIpv6": "::/0",
            "Description": "Allow all outbound traffic by default",
            "IpProtocol": "-1"
          }
        ],
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
}, {
    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "SecurityGroupEgress": [
          {
            "CidrIp": "10.0.0.0/16",
            "Description": "",
            "IpProtocol": "-1"
          }
        ],
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
},
{    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
}]"###;

    let rules = r###"
let sgs = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule deny_egress {
    # Ensure that none of the security group contain a rule
    # that has Cidr Ip set to any
    %sgs {
        Properties.SecurityGroupEgress[ CidrIp   == "0.0.0.0/0" or
                                        CidrIpv6 == "::/0" ] EMPTY
    }
}"###;

    let rules_file = RulesFile::try_from(rules)?;
    let values = PathAwareValue::try_from(sgs)?;
    let samples = match values {
        PathAwareValue::List((_p, v)) => v,
        _ => unreachable!()
    };

    let statues = [Status::FAIL, Status::FAIL, Status::PASS, Status::PASS];
    for (index, each) in samples.iter().enumerate() {
        let root_context = RootScope::new(&rules_file, each);
        let reporter = Reporter(&root_context);
        let status = rules_file.evaluate(each, &reporter)?;
        assert_eq!(status, statues[index]);
    }

    let sample = r#"{ "Resources": {} }"#;
    let value = PathAwareValue::try_from(sample)?;
    let rule = r###"
rule deny_egress {
    # Ensure that none of the security group contain a rule
    # that has Cidr Ip set to any
    Resources.*[ Type == "AWS::EC2::SecurityGroup" ] {
        Properties.SecurityGroupEgress[ CidrIp   == "0.0.0.0/0" or
                                        CidrIpv6 == "::/0" ] EMPTY
    }
}"###;

    let dummy = DummyEval{};
    let rule_parsed = Rule::try_from(rule)?;
    let status = rule_parsed.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_s3_bucket_pro_serv() -> Result<()> {
    let values = r###"
    [
{
    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : false,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : false,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : false,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : false
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : false,
                "BlockPublicPolicy" : false,
                "IgnorePublicAcls" : false,
                "RestrictPublicBuckets" : false
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
            "BlockPublicAcls" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
            "BlockPublicAcls" : true,
            "BlockPublicPolicy" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
            "BlockPublicAcls" : true,
            "BlockPublicPolicy" : true,
            "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
}]"###;

    let parsed_values = match PathAwareValue::try_from(values)? {
        PathAwareValue::List((_, v)) => v,
        _ => unreachable!()
    };

    let rule = r###"
    rule deny_s3_public_bucket {
    Resources.*[ Type == 'AWS::S3::Bucket' ] {
        Properties {
            BlockPublicAcls == true
            BlockPublicPolicy == true
            IgnorePublicAcls == true
            RestrictPublicBuckets == true
        }
    }
}"###;

    let statues = [
        Status::PASS,
        Status::FAIL,Status::FAIL,Status::FAIL,Status::FAIL,Status::FAIL,
        Status::FAIL, Status::FAIL,
        Status::FAIL,Status::FAIL,Status::FAIL,
    ];
    let s3_rule = Rule::try_from(rule)?;
    let dummy = DummyEval{};
    let reported = Reporter(&dummy);
    for (idx, each) in parsed_values.iter().enumerate() {
        let status = s3_rule.evaluate(each, &reported)?;
        println!("Status#{} = {}", idx, status);
        assert_eq!(status, statues[idx]);
    }
    Ok(())
}

struct VariableResolver<'a, 'b>(&'a dyn EvaluationContext, HashMap<String, Vec<&'b PathAwareValue>>);

impl<'a, 'b> EvaluationContext for VariableResolver<'a, 'b> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        if let Some(value) = self.1.get(variable) {
            Ok(value.clone())
        }
        else {
            self.0.resolve_variable(variable)
        }
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.0.rule_status(rule_name)
    }

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<PathAwareValue>, to: Option<PathAwareValue>, status: Option<Status>) {
        self.0.end_evaluation(eval_type, context, msg, from, to, status);
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
        self.0.start_evaluation(eval_type, context);
    }
}

#[test]
fn test_iam_subselections() -> Result<()> {
    let template = r###"
    {
        Resources: {
            # NOT SELECTED
            one: {
                Type: "AWS::IAM::Role",
                Properties: {
                    Tags: [
                      {
                        Key: "TestRole",
                        Value: ""
                      }
                    ],
                    PermissionsBoundary: "aws:arn"
                }
            },
            # SELECTED
            two:
            {
                Type: "AWS::IAM::Role",
                Properties: {
                    Tags: [
                      {
                        Key: "TestRole",
                        Value: ""
                      }
                    ]
                }
            },
            # NOT SELECTED
            three: {
                Type: "AWS::IAM::Role",
                Properties: {
                    Tags: [],
                    PermissionsBoundary: "aws:arn"
                }
            },
            # NOT SELECTED #1, SELECTED #2
            four:
            {
                Type: "AWS::IAM::Role",
                Properties: {
                    Tags: [
                      {
                        Key: "Prod",
                        Value: ""
                      }
                    ]
                }
            }
        }
    }
    "###;

    let value = Value::try_from(template)?;
    let value = PathAwareValue::try_from(value)?;
    let query = AccessQuery::try_from(
        r#"Resources.*[
                    Type == "AWS::IAM::Role"
                    Properties.Tags[ Key == "TestRole" ] !EMPTY
                    Properties.PermissionsBoundary !EXISTS
                 ]"#
    )?;
    let dummy = DummyEval{};
    let selected = value.select(query.match_all, &query.query, &dummy)?;
    println!("Selected {:?}", selected);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].self_path(), &Path::try_from("/Resources/two")?);
    let expected = PathAwareValue::try_from((r#"
            {
                Type: "AWS::IAM::Role",
                Properties: {
                    Tags: [
                      {
                        Key: "TestRole",
                        Value: ""
                      }
                    ]
                }
            }
    "#, Path::try_from("/Resources/two")?))?;
    assert_eq!(selected[0], &expected);

    let query = AccessQuery::try_from(
        r#"Resources.*[
                    Type == "AWS::IAM::Role"
                    Properties.Tags[ Key == "TestRole" or Key == "Prod" ] !EMPTY
                    Properties.PermissionsBoundary !EXISTS
                 ]"#
    )?;
    let selected = value.select(query.match_all, &query.query, &dummy)?;
    println!("Selected {:?}", selected);
    assert_eq!(selected.len(), 2);
    let expected2 = PathAwareValue::try_from(
        (r#"
            {
                Type: "AWS::IAM::Role",
                Properties: {
                    Tags: [
                      {
                        Key: "Prod",
                        Value: ""
                      }
                    ]
                }
            }
        "#, Path::try_from("/Resources/four")?)
    )?;
    assert_eq!(selected[0], &expected);
    assert_eq!(selected[1], &expected2);


    let rules_file = r###"
let iam_roles = Resources.*[ Type == "AWS::IAM::Role"  ]

rule deny_permissions_boundary_iam_role when %iam_roles !EMPTY {
    # atleast one Tags contains a Key "TestRole"
    %iam_roles[
        # Properties.Tags !EMPTY
        Properties.Tags[ Key == "TestRole" ] !EMPTY
        Properties.PermissionsBoundary !EXISTS
    ] !EMPTY
}
    "###;

    let rules = RulesFile::try_from(rules_file)?;
    let root_scope = RootScope::new(&rules, &value);
    let reporter = Reporter(&root_scope);
    let status = rules.evaluate(&value, &reporter)?;
    println!("Status = {}", status);
    assert_eq!(status, Status::PASS);
    let fail_value= PathAwareValue::try_from(
        (r#"
            { Resources: {
                one: {
                    Type: "AWS::IAM::Role",
                    Properties: {
                        Tags: [
                          {
                            Key: "Prod",
                            Value: ""
                          }
                        ]
                    }
                }
                }
            }
        "#, Path::try_from("/Resources/four")?)
    )?;
    let root_scope = RootScope::new(&rules, &fail_value);
    let reporter = Reporter(&root_scope);
    let status = rules.evaluate(&fail_value, &reporter)?;
    println!("Status = {}", status);
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_rules_with_some_clauses() -> Result<()> {
    let query = r#"Resources.*[ Type == 'AWS::IAM::Role' ].Properties[
        Tags !empty
        some Tags[*] {
            Key == /[A-Za-z0-9]+Role/
        }
    ]"#;
    let resources = r#"    {
      "Resources": {
          "CounterTaskDefExecutionRole5959CB2D": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "AssumeRolePolicyDocument": {
                      "Statement": [
                      {
                          "Action": "sts:AssumeRole",
                          "Effect": "Allow",
                          "Principal": {
                          "Service": "ecs-tasks.amazonaws.com"
                          }
                      }],
                      "Version": "2012-10-17"
                  },
                  "PermissionsBoundary": {"Fn::Sub" : "arn::aws::iam::${AWS::AccountId}:policy/my-permission-boundary"},
                  "Tags": [{ "Key": "TestRole", "Value": ""}]
              },
              "Metadata": {
                  "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
              }
          },
          "BlankRole001": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "AssumeRolePolicyDocument": {
                      "Statement": [
                      {
                          "Action": "sts:AssumeRole",
                          "Effect": "Allow",
                          "Principal": {
                          "Service": "ecs-tasks.amazonaws.com"
                          }
                      }],
                      "Version": "2012-10-17"
                  },
                  "Tags": [{ "Key": "FooBar", "Value": ""}]
              },
              "Metadata": {
                  "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
              }
          },
          "BlankRole002": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "AssumeRolePolicyDocument": {
                      "Statement": [
                      {
                          "Action": "sts:AssumeRole",
                          "Effect": "Allow",
                          "Principal": {
                          "Service": "ecs-tasks.amazonaws.com"
                          }
                      }],
                      "Version": "2012-10-17"
                  }
              },
              "Metadata": {
                  "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
              }
          }
      }
    }
    "#;
    let value = PathAwareValue::try_from(resources)?;
    let parsed = AccessQuery::try_from(query)?;
    let dummy = DummyEval{};
    let selected = value.select(parsed.match_all, &parsed.query, &dummy)?;
    println!("{:?}", selected);
    assert_eq!(selected.len(), 1);
    Ok(())
}

#[test]
fn test_support_for_atleast_one_match_clause() -> Result<()> {
    let clause_some_str  = r#"some Tags[*].Key == /PROD/"#;
    let clause_some = GuardClause::try_from(clause_some_str)?;

    let clause_str  = r#"Tags[*].Key == /PROD/"#;
    let clause = GuardClause::try_from(clause_str)?;

    let values_str  = r#"{
        Tags: [
            {
                Key: "InPROD",
                Value: "ProdApp"
            },
            {
                Key: "NoP",
                Value: "NoQ"
            }
        ]
    }
    "#;
    let values = PathAwareValue::try_from(values_str)?;
    let dummy = DummyEval{};

    let status = clause_some.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"{ Tags: [] }"#;
    let values = PathAwareValue::try_from(values_str)?;
    let status = clause_some.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"{ }"#;
    let values = PathAwareValue::try_from(values_str)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let r = clause_some.evaluate(&values, &dummy);
    assert_eq!(r.is_err(), false);
    assert_eq!(r.unwrap(), Status::FAIL);

    //
    // Trying out the selection filters
    //
    let selection_str = r#"Resources.*[
        Type == 'AWS::DynamoDB::Table'
        some Properties.Tags[*].Key == /PROD/
    ]"#;
    let _query = AccessQuery::try_from(selection_str)?;
    let resources_str = r#"{
        Resources: {
            ddbSelected: {
                Type: 'AWS::DynamoDB::Table',
                Properties: {
                    Tags: [
                        {
                            Key: "PROD",
                            Value: "ProdApp"
                        }
                    ]
                }
            },
            ddbNotSelected: {
                Type: 'AWS::DynamoDB::Table'
            }
        }
    }"#;
    let resources = PathAwareValue::try_from(resources_str)?;
    let selection_query = AccessQuery::try_from(selection_str)?;
    let selected = resources.select(selection_query.match_all, &selection_query.query, &dummy)?;
    println!("Selected = {:?}", selected);
    assert_eq!(selected.len(), 1);

    let resources_str = r#"{
        Resources: {
            ddbSelected: {
                Type: 'AWS::DynamoDB::Table',
                Properties: {
                    Tags: [
                        {
                            Key: "PROD",
                            Value: "ProdApp"
                        }
                    ]
                }
            },
            ddbNotSelected: {
                Type: 'AWS::DynamoDB::Table',
                Properties: {
                    Tags: []
                }
            }
        }
    }"#;
    let resources = PathAwareValue::try_from(resources_str)?;
    let selection_query = AccessQuery::try_from(selection_str)?;
    let selected = resources.select(selection_query.match_all, &selection_query.query, &dummy)?;
    println!("Selected = {:?}", selected);
    assert_eq!(selected.len(), 1);

    Ok(())
}

#[test]
fn double_projection_tests() -> Result<()> {
    let rule_str = r###"
    rule check_ecs_against_local_or_metadata {
        let ecs_tasks = Resources.*[
            Type == 'AWS::ECS::TaskDefinition'
            Properties.TaskRoleArn exists
        ]

        let iam_references = some %ecs_tasks.Properties.TaskRoleArn.'Fn::GetAtt'[0]
        when %iam_references !empty {
            let iam_local = Resources.%iam_references
            %iam_local.Type == 'AWS::IAM::Role'
            %iam_local.Properties.PermissionsBoundary exists
        }

        let ecs_task_role_is_string = %ecs_tasks[
            Properties.TaskRoleArn is_string
        ]
        when %ecs_task_role_is_string !empty {
            %ecs_task_role_is_string.Metadata.NotRestricted exists
        }
    }
    "###;

    let resources_str = r###"
    {
        Resources: {
            ecs: {
                Type: 'AWS::ECS::TaskDefinition',
                Metadata: {
                    NotRestricted: true
                },
                Properties: {
                    TaskRoleArn: "aws:arn..."
                }
            },
            ecs2: {
              Type: 'AWS::ECS::TaskDefinition',
              Properties: {
                TaskRoleArn: { 'Fn::GetAtt': ["iam", "arn"] }
              }
            },
            iam: {
              Type: 'AWS::IAM::Role',
              Properties: {
                PermissionsBoundary: "aws:arn"
              }
            }
        }
    }
    "###;
    let value = PathAwareValue::try_from(resources_str)?;
    let dummy = DummyEval{};
    let rule = Rule::try_from(rule_str)?;
    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::PASS);

    let resources_str = r###"
    {
        Resources: {
            ecs2: {
              Type: 'AWS::ECS::TaskDefinition',
              Properties: {
                TaskRoleArn: { 'Fn::GetAtt': ["iam", "arn"] }
              }
            }
        }
    }
    "###;
    let value = PathAwareValue::try_from(resources_str)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("{}", status);
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_map_keys_function() -> Result<()> {
    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true

    "#;
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;

    let rule_str = r#"
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]
rule check_rest_api_is_private_and_has_access when %api_gws !empty {
    %api_gws.Properties.EndpointConfiguration == ["PRIVATE"]
    some %api_gws.Properties.Policy.Statement[*].Condition[ keys == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !empty
}"#;
    let rule = RulesFile::try_from(rule_str)?;
    let root = RootScope::new(&rule, &value);
    let status = rule.evaluate(&value, &root)?;
    assert_eq!(status, Status::FAIL);

    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true
                    'aws:sourceVpc': ['vpc-1234']

    "#;
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let root = RootScope::new(&rule, &value);
    let status = rule.evaluate(&value, &root)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_compare_loop_atleast_one_eq() -> Result<()> {
    let root = Path::root();
    let lhs = [
        PathAwareValue::String((root.clone(), "aws:isSecure".to_string())),
        PathAwareValue::String((root.clone(), "aws:sourceVpc".to_string())),
    ];
    let rhs = [
        PathAwareValue::Regex((root.clone(), "aws:[sS]ource(Vpc|VPC|Vpce|VPCE)".to_string())),
    ];

    let lhs_values = lhs.iter().collect::<Vec<&PathAwareValue>>();
    let rhs_values = rhs.iter().collect::<Vec<&PathAwareValue>>();

    //
    // match any one rhs = false, at-least-one = false
    //
    let (result, _first, _with) = compare_loop(
        &lhs_values, &rhs_values, path_value::compare_eq, false, false
    )?;
    assert_eq!(result, false);

    //
    // match any one rhs = false, at-least-one = false
    //
    let (result, _first, _with) = compare_loop(
        &lhs_values, &rhs_values, path_value::compare_eq, false, true
    )?;
    assert_eq!(result, true);

    //
    // match any one rhs = true, at-least-one = false
    //
    let (result, _first, _with) = compare_loop(
        &lhs_values, &rhs_values, path_value::compare_eq, true, false
    )?;
    assert_eq!(result, false);

    Ok(())
}

#[test]
fn block_evaluation() -> Result<()> {
    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true
                    'aws:sourceVpc': ['vpc-1234']
              - Action: Allow
                Resource: ['*', "aws:"]

    "#;
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let clause_str = r#"Resources.*[ Type == 'AWS::ApiGateway::RestApi' ].Properties {
        EndpointConfiguration == ["PRIVATE"]
        some Policy.Statement[*] {
            Action == 'Allow'
            Condition[ keys == 'aws:IsSecure' ] !empty
        }
    }
    "#;
    let clause = GuardClause::try_from(clause_str)?;
    let dummy = DummyEval{};
    let status = clause.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::PASS);
    Ok(())
}

#[test]
fn block_evaluation_fail() -> Result<()> {
    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true
                    'aws:sourceVpc': ['vpc-1234']
              - Action: Allow
                Resource: ['*', "aws:"]
      apiGw2:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]

    "#;
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let clause_str = r#"Resources.*[ Type == 'AWS::ApiGateway::RestApi' ].Properties {
        EndpointConfiguration == ["PRIVATE"]
        some Policy.Statement[*] {
            Action == 'Allow'
            Condition[ keys == 'aws:IsSecure' ] !empty
        }
    }
    "#;
    let clause = GuardClause::try_from(clause_str)?;
    let dummy = DummyEval{};
    let status = clause.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

#[test]
fn embedded_when_clause_redshift_use_case_test() -> Result<()> {
    let rule = r###"
#
# Find all Redshift subnet group resource and extract all subnet Ids that are referenced
#
let local_subnet_refs = Resources.*[ Type == /Redshift::ClusterSubnetGroup/ ].Properties.SubnetIds[ Ref exists ].Ref
rule redshift_is_not_internet_accessible when %local_subnet_refs !empty {

    #
    # check that all local references where indeed subnet type. FAIL otherwise
    #
    Resources.%local_subnet_refs.Type == 'AWS::EC2::Subnet'

    #
    # Find out all Subnet Route Associations with the set of subnets and extract the
    # Route Table references that they have
    #
    let route_tables = some Resources.*[
        Type == 'AWS::EC2::SubnetRouteTableAssociation'
        Properties.SubnetId.Ref in %local_subnet_refs
    ].Properties.RouteTableId.Ref

    #
    # If no associations are present in the template then we SKIP the check
    #
    when %route_tables !empty {
        #
        # Ensure that all of these references where indeed RouteTable references
        #
        Resources.%route_tables.Type == 'AWS::EC2::RouteTable'

        #
        # Find all routes that have a gateways associated with the route table and extract
        # all their references
        #
        let gws_ids = some Resources.*[
            Type == 'AWS::EC2::Route'
            Properties.GatewayId.Ref exists
            Properties.RouteTableId.Ref in %route_tables
        ].Properties.GatewayId.Ref

        #
        # if no gateways or route association were found then we skip the check
        #
        when %gws_ids !empty {
            Resources.%gws_ids.Type != 'AWS::EC2::InternetGateway'
        }
    }

}"###;

    let value_str = r###"
    Resources:
      rcsg:
        Type: 'AWS::Redshift::ClusterSubnetGroup'
        Properties:
          SubnetIds: [{Ref: subnet}, "subnet-2"]
      subnet:
        Type: 'AWS::EC2::Subnet'
      subRtAssoc:
        Type: 'AWS::EC2::SubnetRouteTableAssociation'
        Properties:
          SubnetId: { Ref: subnet }
          RouteTableId: { Ref: rt }
      rt:
        Type: 'AWS::EC2::RouteTable'
      route1:
        Type: 'AWS::EC2::Route'
        Properties:
          GatewayId: { Ref: gw }
          RouteTableId: { Ref: rt }
      gw:
        Type: 'AWS::EC2::InternetGateway'
    "###;

    let rules_files = RulesFile::try_from(rule)?;
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let root = RootScope::new(&rules_files, &value);
    let status = rules_files.evaluate(&value, &root)?;
    assert_eq!(status, Status::FAIL);

    let value_str = r###"
    Resources:
      rcsg:
        Type: 'AWS::Redshift::ClusterSubnetGroup'
        Properties:
          SubnetIds: [{Ref: subnet}, "subnet-2"]
      subnet:
        Type: 'AWS::EC2::Subnet'
      subRtAssoc:
        Type: 'AWS::EC2::SubnetRouteTableAssociation'
        Properties:
          SubnetId: { Ref: subnet }
          RouteTableId: { Ref: rt }
      rt:
        Type: 'AWS::EC2::RouteTable'
      route1:
        Type: 'AWS::EC2::Route'
        Properties:
          GatewayId: { Ref: gw }
          RouteTableId: { Ref: rt }
      gw:
        Type: 'AWS::EC2::TransitGateway'
    "###;

    let rules_files = RulesFile::try_from(rule)?;
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let root = RootScope::new(&rules_files, &value);
    let status = rules_files.evaluate(&value, &root)?;
    assert_eq!(status, Status::PASS);

    let value_str = r###"
    Resources:
      rcsg:
        Type: 'AWS::Redshift::ClusterSubnetGroup'
        Properties:
          SubnetIds: [{Ref: subnet}, "subnet-2"]
      subnet:
        Type: 'AWS::EC2::Subnet'
      subRtAssoc:
        Type: 'AWS::EC2::SubnetRouteTableAssociation'
        Properties:
          SubnetId: { Ref: subnet }
          RouteTableId: { Ref: rt }
      rt:
        Type: 'AWS::EC2::RouteTable'
      route1:
        Type: 'AWS::EC2::Route'
        Properties:
          GatewayId: { Ref: gw }
          RouteTableId: { Ref: rt }
    "###;

    let rules_files = RulesFile::try_from(rule)?;
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let root = RootScope::new(&rules_files, &value);
    let status = rules_files.evaluate(&value, &root)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

struct Tracker<'a> {
    root: &'a dyn EvaluationContext,
    expected: HashMap<String, Status>
}

impl<'a> EvaluationContext for Tracker<'a> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        self.root.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.root.rule_status(rule_name)
    }

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<PathAwareValue>, to: Option<PathAwareValue>, status: Option<Status>) {
        self.root.end_evaluation(eval_type, context, msg, from, to, status.clone());
        if eval_type == EvaluationType::Rule {
            match self.expected.get(context) {
                Some(e) => {
                    assert_eq!(*e, status.unwrap());
                },
                _ => unreachable!()
            }
        }
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
        self.root.start_evaluation(eval_type, context)
    }
}

#[test]
fn rule_clause_when_check() -> Result<()> {
    let rules_skipped = r#"
    rule skipped when skip !exists {
        Resources.*.Properties.Tags !empty
    }

    rule dependent_on_skipped when skipped {
        Resources.*.Properties exists
    }

    rule dependent_on_dependent when dependent_on_skipped {
        Resources.*.Properties exists
    }

    rule dependent_on_not_skipped when !skipped {
        Resources.*.Properties exists
    }
    "#;

    let input = r#"
    {
        skip: true,
        Resources: {
            first: {
                Type: 'WhackWhat',
                Properties: {
                    Tags: [{ hi: "there" }, { right: "way" }]
                }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules = RulesFile::try_from(rules_skipped)?;
    let root = RootScope::new(&rules, &resources);
    let mut expectations = HashMap::with_capacity(3);
    expectations.insert("skipped".to_string(), Status::SKIP);
    expectations.insert("dependent_on_skipped".to_string(), Status::SKIP);
    expectations.insert("dependent_on_dependent".to_string(), Status::SKIP);
    expectations.insert("dependent_on_not_skipped".to_string(), Status::PASS);
    let tracker = Tracker{ root: &root, expected: expectations };

    let status = rules.evaluate(&resources, &tracker)?;
    assert_eq!(status, Status::PASS);

    let input = r#"
    {
        Resources: {
            first: {
                Type: 'WhackWhat',
                Properties: {
                    Tags: [{ hi: "there" }, { right: "way" }]
                }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules = RulesFile::try_from(rules_skipped)?;
    let root = RootScope::new(&rules, &resources);
    let mut expectations = HashMap::with_capacity(3);
    expectations.insert("skipped".to_string(), Status::PASS);
    expectations.insert("dependent_on_skipped".to_string(), Status::PASS);
    expectations.insert("dependent_on_dependent".to_string(), Status::PASS);
    expectations.insert("dependent_on_not_skipped".to_string(), Status::SKIP);
    let tracker = Tracker{ root: &root, expected: expectations };

    let status = rules.evaluate(&resources, &tracker)?;
    assert_eq!(status, Status::PASS);
    Ok(())
}

#[test]
fn test_field_type_array_or_single() -> Result<()> {
    let statements = r#"{
        Statement: [{
            Action: '*',
            Effect: 'Allow',
            Resources: '*'
        }, {
            Action: ['api:Get', 'api2:Set'],
            Effect: 'Allow',
            Resources: '*'
        }]
    }
    "#;
    let path_value = PathAwareValue::try_from(statements)?;
    let clause = GuardClause::try_from(r#"Statement[*].Action != '*'"#)?;
    let dummy = DummyEval{};
    let status = clause.evaluate(&path_value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let statements = r#"{
        Statement: {
            Action: '*',
            Effect: 'Allow',
            Resources: '*'
        }
    }
    "#;
    let path_value = PathAwareValue::try_from(statements)?;
    let status = clause.evaluate(&path_value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(r#"Statement[*].Action[*] != '*'"#)?;
    let status = clause.evaluate(&path_value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    // Test old format
    let clause = GuardClause::try_from(r#"Statement.*.Action.* != '*'"#)?;
    let status = clause.evaluate(&path_value, &dummy)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

#[test]
fn test_for_not_in() -> Result<()> {
    let statments = r#"
    {
      "mainSteps": [
          {
            "action": "aws:updateAgent"
          },
          {
            "action": "aws:configurePackage"
          }
        ]
    }"#;

    let clause = GuardClause::try_from(r#"mainSteps[*].action !IN ["aws:updateSsmAgent", "aws:updateAgent"]"#)?;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(statments)?)?;
    let dummy = DummyEval{};
    let status = clause.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

#[test]
fn test_rule_with_range_test() -> Result<()> {
    let rule_str = r#"rule check_parameter_validity {
     InputParameter.TcpBlockedPorts[*] {
         this in r[0, 65535] <<[NON_COMPLIANT] Parameter TcpBlockedPorts has invalid value.>>
     }
 }"#;

    let rule = Rule::try_from(rule_str)?;

    let value_str = r#"
    InputParameter:
        TcpBlockedPorts:
            - 21
            - 22
            - 101
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let dummy = DummyEval{};
    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_inner_when_skipped() -> Result<()> {
    let rule_str = r#"
    rule no_wild_card_in_managed_policy {
        Resources.*[ Type == /ManagedPolicy/ ] {
            when Properties.ManagedPolicyName != /Admin/ {
                Properties.PolicyDocument.Statement[*].Action[*] != '*'
            }
        }
    }
    "#;

    let rule = Rule::try_from(rule_str)?;
    let dummy = DummyEval{};

    let value_str = r#"
    Resources:
      ReadOnlyAdminPolicy:
        Type: 'AWS::IAM::ManagedPolicy'
        Properties:
          PolicyDocument:
            Statement:
              - Action: '*'
                Effect: Allow
                Resource: '*'
            Version: 2012-10-17
          Description: ''
          ManagedPolicyName: AdminPolicy
      ReadOnlyPolicy:
        Type: 'AWS::IAM::ManagedPolicy'
        Properties:
          PolicyDocument:
            Statement:
              - Action:
                  - 'cloudwatch:*'
                  - '*'
                Effect: Allow
                Resource: '*'
            Version: 2013-10-17
          Description: ''
          ManagedPolicyName: OperatorPolicy
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;

    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let value_str = r#"
    Resources:
      ReadOnlyAdminPolicy:
        Type: 'AWS::IAM::ManagedPolicy'
        Properties:
          PolicyDocument:
            Statement:
              - Action: '*'
                Effect: Allow
                Resource: '*'
            Version: 2012-10-17
          Description: ''
          ManagedPolicyName: AdminPolicy
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::SKIP);

    let value_str = r#"
    Resources: {}
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let value_str = r#"{}"#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let status = rule.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn empty_all_values_fails() -> Result<()> {
    let resources_str = r#"{ Resources: {} }"#;
    let resources = PathAwareValue::try_from(resources_str)?;

    let all_tags = GuardClause::try_from("Resources.*.Properties.Tags !empty")?;
    let dummy = DummyEval{};
    let status = all_tags.evaluate(&resources, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let all_tags = GuardClause::try_from("Resources.* { Properties.Tags !empty }")?;
    let dummy = DummyEval{};
    let status = all_tags.evaluate(&resources, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let all_tags = GuardClause::try_from("Resources.* !empty { Properties.Tags !empty }")?;
    let dummy = DummyEval{};
    let status = all_tags.evaluate(&resources, &dummy)?;
    assert_eq!(status, Status::FAIL);

    //
    // Block level failures
    //
    let block_clause = GuardClause::try_from(r#"some Properties.Tags[*] {
        Key == /PROD$/
        Value == /^App/
    }"#)?;
    let values_str= r#"
    Properties:
        Tags: []
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    Properties:
        NoTags: Check
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    NoProperties:
        NoTags: Check
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"{}"#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    Properties:
        Tags:
            - Key: Beta
              Value: BetaAppNoMatch
            - Key: NotPRODEnding
              Value: AppEvenIfThisMatches
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    Properties:
        Tags:
            - Key: EndingPROD
              Value: BetaAppNoMatch
            - Key: NotPRODEnding
              Value: AppEvenIfThisMatches
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    Properties:
        Tags:
            - Key: SomePROD
              Value: AppThisWorks
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);


    let values_str= r#"
    Properties:
        Tags:
            - Key: Beta
              Value: BetaAppNoMatch
            - Key: SomePROD
              Value: AppThisWorks
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    //
    // Block level ALL cases
    //
    let block_clause = GuardClause::try_from(r#"Properties.Tags[*] {
        Key == /PROD$/
        Value == /^App/
    }"#)?;

    let values_str= r#"
    Properties:
        Tags:
            - Key: Beta
              Value: BetaAppNoMatch
            - Key: SomePROD
              Value: AppThisWorks
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    Properties:
        Tags:
            - Key: SomePROD
              Value: AppThisWorks
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    let values_str= r#"
    Properties:
        Tags:
            - Key: SomePROD
              Value: AppThisWorks
            - Key: AnotherSomePROD
              Value: AppAnotherThisWorks
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = block_clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn filter_return_empty_direct_clause_skip() -> Result<()> {

    let dummy = DummyEval{};
    let clause_str = r#"some Properties.Tags[*].Key == /PROD$/"#;
    let clause = GuardClause::try_from(clause_str)?;

    let values_str = r#"
    Properties:
        Tags: []
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    Properties:
        NoTags: Check
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"
    NoProperties:
        NoTags: Check
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str= r#"{}"#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"
    Properties:
        Tags:
            - Key: EndPROD
              Value: AppStart
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    let rule_str = r#"rule not_the_same_as_block {
        #
        # These are 2 independent clauses, this is not the same as a block
        # clause, each clause is evalulate separately. Hence when the input is
        #
        #    Properties:
        #        Tags:
        #            - Key: EndPROD
        #              Value: NoTAppStart
        #            - Key: NotPRODEnd
        #              Value: AppStart
        #
        # This will PASS due to some clause
        #
        some Properties.Tags[*].Key == /PROD$/
        some Properties.Tags[*].Value == /^App/
    }
    "#;
    let rule = Rule::try_from(rule_str)?;

    let values_str = r#"
    Properties:
        Tags:
            - Key: EndPROD
              Value: AppStart
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    let values_str = r#"
    Properties:
        Tags:
            - Key: EndPROD
              Value: NotAppStart
            - Key: NotPRODEnd
              Value: AppStart
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn filter_based_single_clause() -> Result<()> {
    let clause = GuardClause::try_from(
        r#"Properties.Tags[ Key == /PROD$/ ].Value == /^App/"#)?;
    let dummy = DummyEval{};

    let values_str = r#"
    Properties:
        Tags: []
    "#;
    let values = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(values_str)?
    )?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::SKIP);

    let values_str = r#"
    Properties:
        Tags:
            - Key: EndPROD
              Value: NotAppStart
            - Key: NotPRODEnd
              Value: AppStart
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"
    Properties:
        Tags:
            - Key: EndPROD
              Value: AppStart
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    let values_str = r#"
    Properties:
        Tags:
            - Key: EndPROD
              Value: AppStart
            - Key: NotPRODEnd
              Value: AppStart
    "#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(values_str)?)?;
    let status = clause.evaluate(&values, &dummy)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn cross_ref_test() -> Result<()> {
    let query_str = r#"Resources.*[
    Type in [/IAM::Policy/, /IAM::ManagedPolicy/]
    some Properties.PolicyDocument.Statement[*] {
        some Action[*] == 'cloudwatch:CreateLogGroup'
        Effect == 'Allow'
    }
]"#;
    let query = AccessQuery::try_from(query_str)?;
    let resources_str = r###"
  Resources:
    ReadOnlyPolicy:
      Type: 'AWS::IAM::Policy'
      Properties:
        PolicyDocument:
          Statement:
            - Action:
                - 'cloudwatch:Describe*'
                - 'cloudwatch:List*'
              Effect: Deny
              Resource: '*'
            - Action:
                - 'cloudwatch:Describe*'
                - 'cloudwatch:CreateLogGroup'
              Effect: Allow
              Resource: '*'
          Version: 2012-10-17
        Description: ''
        Roles:
          - Ref: EcsTaskInstanceRole
        ManagedPolicyName: OperatorPolicy
    EcsTaskInstanceRole:
      Type: 'AWS::IAM::Role'
      Properties:
        AssumeRolePolicyDocument:
          Statement:
            - Action: 'sts:AssumeRole'
              Effect: Allow
              Principal:
                Service: 'ecs-tasks.amazonaws.com'
          Version: 2012-10-17
        Description: This Admin Operator role
        RoleName: EcsTaskInstanceRole
        Tags:
          - Key: Team
            Value: IAM
          - Key: IsPipeline
            Value: 'false'
          - Key: RoleARN
            Value: !Sub 'arn:aws:iam::${AWS::AccountId}:role/EcsTaskInstanceRole'
          - Key: VPC
            Value: BOM-EgressVPC

    "###;
    let resources = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(resources_str)?)?;
    let dummy = DummyEval{};
    let selected = resources.select(query.match_all, &query.query, &dummy)?;
    println!("{:?}", selected);
    assert_eq!(selected.len(), 1);

    let rule_str = r###"rule certain_actions_forbid_for_ecs_role {
    let policies_with_create_log_group = Resources.*[
        Type in [/IAM::Policy/, /IAM::ManagedPolicy/]
        some Properties.PolicyDocument.Statement[*] {
            some Action[*] == 'cloudwatch:CreateLogGroup'
            Effect == 'Allow'
        }
    ]

    let role_refs = some %policies_with_create_log_group.Properties.Roles[*].Ref
    Resources.%role_refs {
        Type == 'AWS::IAM::Role'
        Properties.AssumeRolePolicyDocument.Statement[*] {
            Principal[*] {
                Service != /^ecs-tasks/
            }
        }
    }
}"###;
    let rule = RulesFile::try_from(rule_str)?;
    let root = RootScope::new(&rule, &resources);
    let status = rule.evaluate(&resources, &root)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}