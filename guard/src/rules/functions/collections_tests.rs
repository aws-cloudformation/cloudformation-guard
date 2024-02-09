use super::*;
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::exprs::AccessQuery;
use crate::rules::path_value::*;
use crate::rules::EvalContext;
use pretty_assertions::assert_eq;
use std::convert::TryFrom;
use std::rc::Rc;

#[test]
fn test_count_function() -> crate::rules::Result<()> {
    let value_str = r#"Resources: {}"#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let query = AccessQuery::try_from(r#"Resources"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        PathAwareValue::Int((_, cnt)) => assert_eq!(cnt, 1),
        _ => unreachable!(),
    }

    let value_str = r#"{}"#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let query = AccessQuery::try_from(r#"Resources"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        PathAwareValue::Int((_, cnt)) => assert_eq!(cnt, 0),
        _ => unreachable!(),
    }

    let value_str = r#"
    Resources:
      s3:
        Type: AWS::S3::Bucket
      s32:
        Type: AWS::S3::Bucket
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::S3::Bucket' ]"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        PathAwareValue::Int((_, cnt)) => assert_eq!(cnt, 2),
        _ => unreachable!(),
    }

    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::EC2::Instance' ]"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        PathAwareValue::Int((_, cnt)) => assert_eq!(cnt, 0),
        _ => unreachable!(),
    }
    Ok(())
}
