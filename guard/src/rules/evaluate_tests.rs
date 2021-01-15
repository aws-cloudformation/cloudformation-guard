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

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<Value>, to: Option<Value>, status: Option<Status>) {
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
    Properties.Tags[*].Value == /[a-zA-Z0-9]+/
    Properties.Tags[*].Key   == /[a-zA-Z0-9]+/
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

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<Value>, to: Option<Value>, status: Option<Status>) {
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
    let rules_file = RulesFile::try_from(file)?;
    let root_context = RootScope::new(&rules_file, &root);
    let reporter = Reporter(&root_context);
    let status = rules_file.evaluate(&root, &reporter)?;
    assert_eq!(Status::PASS, status);
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

    let value = Value::try_from(SAMPLE)?;
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
    let dummy = DummyEval{};
    let reporter = Reporter(&dummy);
    let status = rule.evaluate(&value, &reporter)?;
    println!("{}", status);
    Ok(())
}

#[test]
fn testing_IAM_role_prov_serve() -> Result<()> {
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

rule deny_permissions_boundary_iam_role when %iam_roles !EMPTY {
    # atleast one Tags contains a Key "TestRole"
    %iam_roles.Properties.Tags[ Key == "TestRole" ] NOT EMPTY
    %iam_roles.Properties.PermissionBoundary !EXISTS
}

rule deny_task_role_no_permission_boundary when %ecs_tasks !EMPTY {
    let task_role = %ecs_tasks.Properties.TaskRoleArn

    when %task_role.'Fn::GetAtt' EXISTS {
        let role_name = %task_role.'Fn::GetAtt'[0]
        let iam_roles_by_name = Resources.*[ KEYS == %role_name ]
        %iam_roles_by_name !EMPTY
        iam_roles_by_name.Properties.Tags !EMPTY
    } or
    %task_role == /aws:arn/ # either a direct string or
}
    "###;

    let rules_file = RulesFile::try_from(rules)?;
    let value = Value::try_from(resources)?;

    // let dummy = DummyEval{};
    let root_context = RootScope::new(&rules_file, &value);
    let reporter = Reporter(&root_context);
    let status = rules_file.evaluate(&value, &reporter)?;
    println!("{}", status);
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
}]

    "###;

    let rules = r###"
let sgs = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule deny_egress when %sgs NOT EMPTY {
    # Ensure that none of the security group contain a rule
    # that has Cidr Ip set to any
    %sgs.Properties.SecurityGroupEgress[ CidrIp   == "0.0.0.0/0" or
                                         CidrIpv6 == "::/0" ] EMPTY
}

    "###;

    let rules_file = RulesFile::try_from(rules)?;

    let values = Value::try_from(sgs)?;
    let samples = match values {
        Value::List(v) => v,
        _ => unreachable!()
    };

    for (index, each) in samples.iter().enumerate() {
        let root_context = RootScope::new(&rules_file, each);
        let reporter = Reporter(&root_context);
        let status = rules_file.evaluate(each, &reporter)?;
        println!("{}", format!("Status {} = {}", index, status).underline());
    }

    let sample = r#"{ "Resources": {} }"#;
    let value = Value::try_from(sample)?;
    let rule = r###"
rule deny_egress {
    # Ensure that none of the security group contain a rule
    # that has Cidr Ip set to any
    Resources.*[ Type == "AWS::EC2::SecurityGroup" ]
        .Properties.SecurityGroupEgress[ CidrIp   == "0.0.0.0/0" or
                                         CidrIpv6 == "::/0" ] EMPTY
}
    "###;

    let dummy = DummyEval{};
    let rule_parsed = Rule::try_from(rule)?;
    let status = rule_parsed.evaluate(&value, &dummy)?;
    println!("Status {:?}", status);

    Ok(())

}

#[test]
fn test_s3_bucket_pro_serv() -> Result<()> {
    let values = r###"
    [{
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
}]

    "###;

    let parsed_values = match Value::try_from(values)? {
        Value::List(v) => v,
        _ => unreachable!()
    };

    let rule = r###"
    rule deny_s3_public_bucket {
    AWS::S3::Bucket {  # this is just a short form notation for Resources.*[ Type == "AWS::S3::Bucket" ]
        Properties.BlockPublicAcls NOT EXISTS or
        Properties.BlockPublicPolicy NOT EXISTS or
        Properties.IgnorePublicAcls NOT EXISTS or
        Properties.RestrictPublicBuckets NOT EXISTS or

        Properties.BlockPublicAcls == false or
        Properties.BlockPublicPolicy == false or
        Properties.IgnorePublicAcls == false or
        Properties.RestrictPublicBuckets == false
    }
}

    "###;

    let s3_rule = Rule::try_from(rule)?;
    let dummy = DummyEval{};
    let reported = Reporter(&dummy);
    for (idx, each) in parsed_values.iter().enumerate() {
        let status = s3_rule.evaluate(each, &reported)?;
        println!("Status#{} = {}", idx, status);
    }
    Ok(())
}


