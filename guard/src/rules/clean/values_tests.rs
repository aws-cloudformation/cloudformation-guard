use std::convert::{TryInto, TryFrom};

use crate::errors;

use super::*;
use std::fs::read_to_string;
use super::super::parser::AccessQueryWrapper;
use super::super::exprs::{GuardClause, GuardNamedRuleClause};
use std::collections::HashMap;
use super::super::exprs::{TypeBlock, Rule};
use super::super::evaluate::{RootScope, BlockScope};

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
    assert_eq!(value, Value::Map(
        make_linked_hashmap(vec![
            ("first", Value::Map(make_linked_hashmap(vec![
                ("block", Value::List(vec![
                    Value::Map(make_linked_hashmap(vec![
                        ("hi", Value::String("there".to_string())),
                        ("number", Value::Int(10)),
                    ])),
                    Value::Map(make_linked_hashmap(vec![
                        ("hi", Value::String("hello".to_string())),
                        ("number", Value::Int(20)),
                    ]))
                ])),
                ("simple", Value::String("desserts".to_string())),
            ]))),
            ("second", Value::Int(50))
        ])
    ));
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
    assert_eq!(type_value, Value::Map(
        make_linked_hashmap(vec![
            ("first", Value::Map(make_linked_hashmap(vec![
                ("block", Value::List(vec![
                    Value::Map(make_linked_hashmap(vec![
                        ("hi", Value::String("there".to_string())),
                        ("number", Value::Int(10)),
                    ])),
                    Value::Map(make_linked_hashmap(vec![
                        ("hi", Value::String("hello".to_string())),
                        ("number", Value::Int(20)),
                    ]))
                ])),
                ("simple", Value::String("desserts".to_string())),
            ]))),
            ("second", Value::Int(50))
        ])
    ));

    let converted: Value = (&json).try_into()?;
    assert_eq!(converted, type_value);
    Ok(())
}

#[test]
fn test_query_on_value() -> Result<()> {
    let content = read_to_string("assets/cfn-template.json")?;
    let value = Value::try_from(content.as_str())?;

    struct DummyResolver<'a>{
        cache: HashMap<&'a str, Vec<&'a Value>>
    };
    impl<'a> EvaluationContext for DummyResolver<'a> {
        fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
            if let Some(v) = self.cache.get(variable) {
                return Ok(v.clone())
            }
            Err(Error::new(ErrorKind::MissingVariable(
                format!("Not found {}", variable))))
        }

        fn rule_status(&self, rule_name: &str) -> Result<Status> {
            unimplemented!()
        }
    }
    let mut dummy = DummyResolver{
        cache: HashMap::new()
    };

    //
    // Select all resources inside a template
    //
    let query = AccessQueryWrapper::try_from("Resources.*")?.0;
    let selected = value.query(0, &query, &dummy)?;
    assert_eq!(selected.len(), 17);
    for each in selected {
        if let Value::Map(index) = each {
            continue;
        }
        assert!(false);
    }

    //
    // Select all IAM::Role resources inside the template
    //
    let query  = AccessQueryWrapper::try_from("Resources.*[ Type == \"AWS::IAM::Role\" ]")?.0;
    let selected = value.query(0, &query, &dummy)?;
    assert_eq!(selected.len(), 1);

    println!("{:?}", selected[0]);
    let iam_role = selected[0];

    //
    // Select all policies that has Effect "allow"
    //
    let query  = AccessQueryWrapper::try_from("Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ]")?.0;
    let selected = iam_role.query(0, &query, &dummy)?;
    assert_eq!(selected.len(), 2);

    //
    // This is the case with IAM roles where Action can be either a single value or array
    //
//    let clause = GuardClause::try_from(
//        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ].Action != \"*\"")?;
//    let status = clause.evaluate(iam_role, &dummy)?;
//    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(
        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ].Action.* != \"*\"")?;
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
    //let root = BlockScope::new(&type_block.block, &value, &dummy);
    let status = type_block.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_type_block_with_var_query_evaluation() -> Result<()> {
    let content = read_to_string("assets/cfn-template.json")?;
    let value = Value::try_from(content.as_str())?;

    struct DummyResolver{};
    impl EvaluationContext for DummyResolver {
        fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
            unimplemented!()
        }

        fn rule_status(&self, rule_name: &str) -> Result<Status> {
            unimplemented!()
        }
    }
    let dummy = DummyResolver{};

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
    let value = Value::try_from(content)?;
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
    let value = Value::try_from(content)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::PASS);


    Ok(())
}
