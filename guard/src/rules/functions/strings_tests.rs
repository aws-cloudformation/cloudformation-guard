use super::*;
use super::super::collections::count;
use crate::rules::eval_context::*;
use crate::rules::path_value::*;
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::EvalContext;
use crate::rules::exprs::AccessQuery;


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
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?
    )?;

    let mut eval = BasicQueryTesting {root: &value, recorder: None};
    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::New::Service' ].Properties.Policy"#)?;
    let results = eval.query(&query.query)?;
    let cnt = count(&results);
    assert_eq!(cnt, 1);
    let json = json_parse(&results)?;
    assert_eq!(json.len(), 1);
    let path_value = json[0].as_ref().unwrap();
    assert_eq!(matches!(path_value, PathAwareValue::Map(_)), true);
    if let PathAwareValue::Map((path, map)) = path_value {
        assert_eq!(map.values.len(), 2);
        assert_eq!(map.values.contains_key("Principal"), true);
        assert_eq!(map.values.contains_key("Actions"), true);
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
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?
    )?;

    let mut eval = BasicQueryTesting {root: &value, recorder: None};
    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::New::Service' ].Properties.Arn"#)?;
    let results = eval.query(&query.query)?;
    let cnt = count(&results);
    assert_eq!(cnt, 1);

    let replaced = regex_replace(
        &results, "^arn:(\\w+):(\\w+):([\\w0-9-]+):(\\d+):(.+)$", "${1}/${4}/${3}/${2}-${5}")?;
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
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?
    )?;

    let mut eval = BasicQueryTesting {root: &value, recorder: None};
    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::New::Service' ].Properties.Arn"#)?;
    let results = eval.query(&query.query)?;
    let cnt = count(&results);
    assert_eq!(cnt, 1);

    let replaced = substring( &results, 0, 3)?;
    assert_eq!(replaced.len(), 1);
    let path_value = replaced[0].as_ref().unwrap();
    if let PathAwareValue::String((_, val)) = path_value {
        assert_eq!("arn", val);
    }

    Ok(())
}
