use std::convert::{TryFrom, TryInto};

use super::*;
use crate::rules::exprs::{AccessQuery, GuardClause};
use crate::rules::exprs::{Rule, TypeBlock};
use std::collections::HashMap;
use std::fs::read_to_string;

use crate::rules::path_value::traversal::{Traversal, TraversalResult};
use crate::rules::path_value::{PathAwareValue, QueryResolver};
use crate::rules::{
    errors::ErrorKind, Error, Evaluate, EvaluationContext, EvaluationType, Result, Status,
};

#[test]
fn test_convert_from_to_value() -> Result<()> {
    let val = r#"
        {
            "first": {
                "block": [{
                    "number": 10,
                    "hi": "there"
                }, {
                    "number": 20,
                    "hi": "hello"
                }],
                "simple": "desserts"
            },
            "second": 50
        }
        "#;
    let json: serde_json::Value = serde_json::from_str(val)?;
    let value = Value::try_from(&json)?;
    //
    // serde_json uses a BTree for the value which preserves alphabetical
    // order for the keys
    //
    assert_eq!(
        value,
        Value::Map(make_linked_hashmap(vec![
            (
                "first",
                Value::Map(make_linked_hashmap(vec![
                    (
                        "block",
                        Value::List(vec![
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("there".to_string())),
                                ("number", Value::Int(10)),
                            ])),
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("hello".to_string())),
                                ("number", Value::Int(20)),
                            ]))
                        ])
                    ),
                    ("simple", Value::String("desserts".to_string())),
                ]))
            ),
            ("second", Value::Int(50))
        ]))
    );
    Ok(())
}

#[test]
fn test_convert_into_json() -> Result<()> {
    let value = r#"
        {
             first: {
                 block: [{
                     hi: "there",
                     number: 10
                 }, {
                     hi: "hello",
                     # comments in here for the value
                     number: 20
                 }],
                 simple: "desserts"
             }, # now for second value
             second: 50
        }
        "#;

    let value_str = r#"
        {
            "first": {
                "block": [{
                    "number": 10,
                    "hi": "there"
                }, {
                    "number": 20,
                    "hi": "hello"
                }],
                "simple": "desserts"
            },
            "second": 50
        }
        "#;

    let json: serde_json::Value = serde_json::from_str(value_str)?;
    let type_value = Value::try_from(value)?;
    assert_eq!(
        type_value,
        Value::Map(make_linked_hashmap(vec![
            (
                "first",
                Value::Map(make_linked_hashmap(vec![
                    (
                        "block",
                        Value::List(vec![
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("there".to_string())),
                                ("number", Value::Int(10)),
                            ])),
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("hello".to_string())),
                                ("number", Value::Int(20)),
                            ]))
                        ])
                    ),
                    ("simple", Value::String("desserts".to_string())),
                ]))
            ),
            ("second", Value::Int(50))
        ]))
    );

    let converted: Value = (&json).try_into()?;
    assert_eq!(converted, type_value);
    Ok(())
}

#[test]
fn test_query_on_value() -> Result<()> {
    let content = read_to_string("assets/cfn-template.json")?;
    let value = PathAwareValue::try_from(content.as_str())?;

    struct DummyResolver<'a> {
        cache: HashMap<&'a str, Vec<&'a PathAwareValue>>,
    };
    impl<'a> EvaluationContext for DummyResolver<'a> {
        fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
            if let Some(v) = self.cache.get(variable) {
                return Ok(v.clone());
            }
            Err(Error::new(ErrorKind::MissingVariable(format!(
                "Not found {}",
                variable
            ))))
        }

        fn rule_status(&self, _rule_name: &str) -> Result<Status> {
            unimplemented!()
        }

        fn end_evaluation(
            &self,
            _eval_type: EvaluationType,
            _context: &str,
            _msg: String,
            _from: Option<PathAwareValue>,
            _to: Option<PathAwareValue>,
            _status: Option<Status>,
            _cmp: Option<(CmpOperator, bool)>,
        ) {
        }

        fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {}
    }
    let dummy = DummyResolver {
        cache: HashMap::new(),
    };

    //
    // Select all resources inside a template
    //
    let query = AccessQuery::try_from("Resources.*")?;
    let selected = value.select(query.match_all, &query.query, &dummy)?;
    assert_eq!(selected.len(), 17);
    for each in selected {
        if let PathAwareValue::Map(_index) = each {
            continue;
        }
        assert!(false);
    }

    //
    // Select all IAM::Role resources inside the template
    //
    let query = AccessQuery::try_from("Resources.*[ Type == \"AWS::IAM::Role\" ]")?;
    let selected = value.select(query.match_all, &query.query, &dummy)?;
    assert_eq!(selected.len(), 1);

    println!("{:?}", selected[0]);
    let iam_role = selected[0];

    //
    // Select all policies that has Effect "allow"
    //
    let query = AccessQuery::try_from(
        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ]",
    )?;
    let selected = iam_role.select(query.match_all, &query.query, &dummy)?;
    assert_eq!(selected.len(), 2);

    //
    // This is the case with IAM roles where Action can be either a single value or array
    //
    //    let clause = GuardClause::try_from(
    //        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ].Action != \"*\"")?;
    //    let status = clause.evaluate(iam_role, &dummy)?;
    //    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(
        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ].Action.* != \"*\"",
    )?;
    let status = clause.evaluate(iam_role, &dummy)?;
    assert_eq!(status, Status::FAIL);

    //
    // Making it work with variable references
    //
    let block = r###"
    AWS::IAM::Role {
        let statements = Properties.Policies.*.PolicyDocument.Statement[ Effect == "Allow" ]

        # %statements.Action != "*" OR
        %statements.Action.* != "*"

        %statements.Resource != "*" # OR
        # %statements.Resource.* != "*"
    }
    "###;
    let type_block = TypeBlock::try_from(block)?;
    let status = type_block.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_type_block_with_var_query_evaluation() -> Result<()> {
    let content = read_to_string("assets/cfn-template.json")?;
    let value = PathAwareValue::try_from(content.as_str())?;

    struct DummyResolver {};
    impl EvaluationContext for DummyResolver {
        fn resolve_variable(&self, _variable: &str) -> Result<Vec<&PathAwareValue>> {
            unimplemented!()
        }

        fn rule_status(&self, _rule_name: &str) -> Result<Status> {
            unimplemented!()
        }

        fn end_evaluation(
            &self,
            _eval_type: EvaluationType,
            _context: &str,
            _msg: String,
            _from: Option<PathAwareValue>,
            _to: Option<PathAwareValue>,
            _status: Option<Status>,
            _cmp: Option<(CmpOperator, bool)>,
        ) {
        }

        fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {}
    }
    let dummy = DummyResolver {};

    let block = r###"
    rule check_subnets when Resources.*[ Type == "AWS::EC2::VPC" ] !EMPTY {
        # Ensure that Zone is always set
        AWS::EC2::Subnet Properties.AvailabilityZone NOT EMPTY

        # Check if either IPv6 is correctly on or IPv4
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation EXISTS
            Properties.AssignIpv6AddressOnCreation == true
            Properties.Ipv6CidrBlock EXISTS
            Properties.CidrBlock NOT EXISTS
        } OR
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation !EXISTS or
            Properties.AssignIpv6AddressOnCreation == false
            Properties.CidrBlock EXISTS
            Properties.Ipv6CidrBlock NOT EXISTS
        }
    }
    "###;
    let rule = Rule::try_from(block)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::PASS);

    let block = r###"
    rule check_subnets {
        # Ensure that Zone is always set
        AWS::EC2::Subnet Properties.AvailabilityZone NOT EMPTY

        # Check if either IPv6 is correctly on or IPv4
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation EXISTS
            Properties.AssignIpv6AddressOnCreation == true
            Properties.Ipv6CidrBlock EXISTS
            Properties.CidrBlock NOT EXISTS
        } OR
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation !EXISTS or
            Properties.AssignIpv6AddressOnCreation == false
            Properties.CidrBlock EXISTS
            Properties.Ipv6CidrBlock NOT EXISTS
        }
    }
    "###;
    let rule = Rule::try_from(block)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::PASS);

    let content = r###"
    {
       "Resources": {
           "subnet": {
              "Type": "AWS::EC2::Subnet",
              "Properties": {
                  "AvailabilityZone": "us-east-2a",
                  "AssignIpv6AddressOnCreation": true,
                  "CidrBlock": "10.0.0.0/12"
              }
           }
       }
    }
    "###;
    let value = PathAwareValue::try_from(content)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::FAIL);

    let content = r###"
    {
       "Resources": {
           "subnet": {
              "Type": "AWS::EC2::Subnet",
              "Properties": {
                  "AvailabilityZone": "us-east-2a",
                  "CidrBlock": "10.0.0.0/12"
              }
           }
       }
    }
    "###;
    let value = PathAwareValue::try_from(content)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_parse_string_with_colon() -> Result<()> {
    // let s = r#"'aws:AssumeRole'"#;
    let s = r#""aws:AssumeRole""#;
    let _value = Value::try_from(s)?;
    Ok(())
}

#[test]
fn test_yaml_json_mapping() -> Result<()> {
    let resources = r###"
    apiVersion: v1
    spec:
      containers:
        - image: docker/httpd
          cpu: 2
          memory: 10
    "###;

    let resources_json = r###"{
        "Resources": {
            "s3": {
               "Type": "AWS::S3::Bucket",
               "Properties": {
                  "AccessControl": "PublicRead"
               }
            }
        }
    }
    "###;

    let value = super::read_from(resources)?;
    println!("{:?}", value);
    let path_value = PathAwareValue::try_from((value, super::super::path_value::Path::root()))?;
    println!("{:?}", path_value);

    let value = super::read_from(resources_json)?;
    println!("{:?}", value);
    let path_value = PathAwareValue::try_from((value, super::super::path_value::Path::root()))?;
    println!("{:?}", path_value);
    Ok(())
}

#[test]
fn test_yaml_json_mapping_2() -> Result<()> {
    let resources = r###"
MyNotCondition:
    !Not [!Equals [!Ref EnvironmentType, prod]]
Resources:
  myEC2Instance:
    Type: "AWS::EC2::Instance"
    Properties:
      ImageId: !FindInMap
        - RegionMap
        - !Ref 'AWS::Region'
        - HVM64
      InstanceType: m1.small
  s3:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: !Sub
        - /${a}/works
        - a: this

      Others: !Select [ "1", [ "apples", "grapes", "oranges", "mangoes" ] ]
      TestJoin: !Join [ ":", [ a, b, c ] ]
      TestJoinWithRef: !Join [ ":", [ !Ref A, b, c ] ]
      "###;

    let value = super::read_from(resources)?;
    println!("{:?}", value);
    let path_value = PathAwareValue::try_from((value, super::super::path_value::Path::root()))?;
    let traversal = Traversal::from(&path_value);
    let root = traversal.root().unwrap();
    let test_join = traversal.at(
        "/Resources/s3/Properties/TestJoinWithRef/Fn::Join/1/0",
        root,
    )?;
    assert_eq!(matches!(test_join, TraversalResult::Value(_)), true);
    let condition = traversal.at("/MyNotCondition/Fn::Not/0/Fn::Equals/0/Ref", root)?;
    assert_eq!(matches!(condition, TraversalResult::Value(_)), true);
    match condition {
        TraversalResult::Value(val) => {
            assert_eq!(val.value().is_scalar(), true);
            match val.value() {
                PathAwareValue::String((_, v)) => {
                    assert_eq!(v, "EnvironmentType");
                }
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }

    let ec2_image = match traversal.at(
        "/Resources/myEC2Instance/Properties/ImageId/Fn::FindInMap",
        root,
    )? {
        TraversalResult::Value(n) => n,
        _ => unreachable!(),
    };
    match traversal.at("0/0", ec2_image)?.as_value().unwrap().value() {
        PathAwareValue::String((_, region)) => {
            assert_eq!("RegionMap", region);
        }
        _ => unreachable!(),
    }

    match traversal
        .at("0/1/Ref", ec2_image)?
        .as_value()
        .unwrap()
        .value()
    {
        PathAwareValue::String((_, region)) => {
            assert_eq!("AWS::Region", region);
        }
        _ => unreachable!(),
    }

    match traversal.at("0/2", ec2_image)?.as_value().unwrap().value() {
        PathAwareValue::String((_, region)) => {
            assert_eq!("HVM64", region);
        }
        _ => unreachable!(),
    }

    println!("{:?}", path_value);
    Ok(())
}
