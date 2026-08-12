use super::*;
use pretty_assertions::assert_eq;
use std::convert::{TryFrom, TryInto};

use crate::rules::path_value::traversal::{Traversal, TraversalResult};
use crate::rules::path_value::PathAwareValue;
use crate::rules::Result;

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

    let resources_json = r#"{
        "Resources": {
            "s3": {
               "Type": "AWS::S3::Bucket",
               "Properties": {
                  "AccessControl": "PublicRead"
               }
            }
        }
    }
    "#;

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
    let resources = r#"
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
      "#;

    let value = super::read_from(resources)?;
    println!("{:?}", value);
    let path_value = PathAwareValue::try_from((value, super::super::path_value::Path::root()))?;
    let traversal = Traversal::from(&path_value);
    let root = traversal.root().unwrap();
    let test_join = traversal.at(
        "/Resources/s3/Properties/TestJoinWithRef/Fn::Join/1/0",
        root,
    )?;
    assert!(matches!(test_join, TraversalResult::Value(_)));
    let condition = traversal.at("/MyNotCondition/Fn::Not/0/Fn::Equals/0/Ref", root)?;
    assert!(matches!(condition, TraversalResult::Value(_)));
    match condition {
        TraversalResult::Value(val) => {
            assert!(val.value().is_scalar());
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
