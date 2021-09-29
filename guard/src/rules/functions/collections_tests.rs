use super::*;
use crate::rules::eval_context::*;
use crate::rules::path_value::*;
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::EvalContext;
use crate::rules::exprs::AccessQuery;
use std::convert::TryFrom;

#[test]
fn test_count_function() -> crate::rules::Result<()> {
    let value_str = r#"Resources: {}"#;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?
    )?;

    let mut eval = BasicQueryTesting {root: &value};
    let query = AccessQuery::try_from(r#"Resources"#)?;
    let results = eval.query(&query.query)?;
    let cnt = count(&results);
    assert_eq!(cnt, 1);

    let value_str = r#"{}"#;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?
    )?;

    let mut eval = BasicQueryTesting {root: &value};
    let query = AccessQuery::try_from(r#"Resources"#)?;
    let results = eval.query(&query.query)?;
    let cnt = count(&results);
    assert_eq!(cnt, 0);

    let value_str = r#"
    Resources:
      s3:
        Type: AWS::S3::Bucket
      s32:
        Type: AWS::S3::Bucket
    "#;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?
    )?;
    let mut eval = BasicQueryTesting {root: &value};
    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::S3::Bucket' ]"#)?;
    let results = eval.query(&query.query)?;
    let cnt = count(&results);
    assert_eq!(cnt, 2);

    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::EC2::Instance' ]"#)?;
    let results = eval.query(&query.query)?;
    let cnt = count(&results);
    assert_eq!(cnt, 0);

    Ok(())
}
