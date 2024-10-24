use pretty_assertions::assert_eq;
use std::rc::Rc;

use super::super::collections::count;
use super::*;
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::exprs::AccessQuery;
use crate::rules::path_value::*;
use crate::rules::EvalContext;

#[test]
fn test_json_parse() -> crate::rules::Result<()> {
    let value_str = r#"
    Resources:
      newServ:
        Type: AWS::New::Service
        Properties:
          Policy: |
            {
               "Principal": "*",
               "Actions": ["s3*", "ec2*"]
            }
      s3:
         Type: AWS::S3::Bucket
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let query =
        AccessQuery::try_from(r#"Resources[ Type == 'AWS::New::Service' ].Properties.Policy"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        PathAwareValue::Int((_, cnt)) => assert_eq!(cnt, 1),
        _ => unreachable!(),
    }

    let json = json_parse(&results)?;
    assert_eq!(json.len(), 1);
    let path_value = json[0].as_ref().unwrap();
    assert!(matches!(path_value, PathAwareValue::Map(_)));
    if let PathAwareValue::Map((_, map)) = path_value {
        assert_eq!(map.values.len(), 2);
        assert!(map.values.contains_key("Principal"));
        assert!(map.values.contains_key("Actions"));
    }

    Ok(())
}

#[test]
fn test_regex_replace() -> crate::rules::Result<()> {
    let value_str = r#"
    Resources:
      newServ:
        Type: AWS::New::Service
        Properties:
          Policy: |
            {
               "Principal": "*",
               "Actions": ["s3*", "ec2*"]
            }
          Arn: arn:aws:newservice:us-west-2:123456789012:Table/extracted
      s3:
         Type: AWS::S3::Bucket
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let query =
        AccessQuery::try_from(r#"Resources[ Type == 'AWS::New::Service' ].Properties.Arn"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        PathAwareValue::Int((_, cnt)) => assert_eq!(cnt, 1),
        _ => unreachable!(),
    }

    let replaced = regex_replace(
        &results,
        "^arn:(\\w+):(\\w+):([\\w0-9-]+):(\\d+):(.+)$",
        "${1}/${4}/${3}/${2}-${5}",
    )?;
    assert_eq!(replaced.len(), 1);
    let path_value = replaced[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!("aws/123456789012/us-west-2/newservice-Table/extracted", val);
    }

    Ok(())
}

#[test]
fn test_substring() -> crate::rules::Result<()> {
    let value_str = r#"
    Resources:
      newServ:
        Type: AWS::New::Service
        Properties:
          Policy: |
            {
               "Principal": "*",
               "Actions": ["s3*", "ec2*"]
            }
          Arn: arn:aws:newservice:us-west-2:123456789012:Table/extracted
      s3:
         Type: AWS::S3::Bucket
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let query =
        AccessQuery::try_from(r#"Resources[ Type == 'AWS::New::Service' ].Properties.Arn"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        PathAwareValue::Int((_, cnt)) => assert_eq!(cnt, 1),
        _ => unreachable!(),
    }

    let replaced = substring(&results, 0, 3)?;
    assert_eq!(replaced.len(), 1);
    let path_value = replaced[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!("arn", val);
    }

    Ok(())
}
