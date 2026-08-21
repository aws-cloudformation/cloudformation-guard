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

/// `substring` indexes characters, and does not panic on a string that is not ASCII.
///
/// The bounds were checked against `val.len()`, which counts bytes, and the slice that followed
/// panics unless both ends land on a character boundary. `substring(x, 0, 3)` on `naïve` aborted the
/// process with `byte index 3 is not a char boundary` and exit 101 -- a stack trace rather than a
/// diagnostic, which in CI reads as the tool breaking rather than the policy failing.
///
/// The out-of-range and inverted cases keep answering with no value rather than panicking or clamping,
/// which is what the surrounding code already did for those.
#[test]
fn substring_counts_characters_and_does_not_panic() -> crate::rules::Result<()> {
    let cases = [
        // (input, from, to, expected)
        ("hello-world", 0, 5, Some("hello")),
        // Byte 3 is inside the two bytes of `ï`. This is the panic.
        ("naïve", 0, 3, Some("naï")),
        ("naïve", 0, 5, Some("naïve")),
        ("naïve", 2, 4, Some("ïv")),
        ("日本語", 0, 2, Some("日本")),
        ("日本語", 1, 3, Some("本語")),
        // Past the end, in characters: `naïve` is 5 characters even though it is 6 bytes.
        ("naïve", 0, 6, None),
        ("naïve", 5, 6, None),
        // Empty, inverted and degenerate ranges answer with no value, as before.
        ("", 0, 1, None),
        ("hello", 3, 3, None),
        ("hello", 4, 2, None),
    ];

    for (input, from, to, expected) in cases {
        let value = PathAwareValue::String((Path::root(), String::from(input)));
        let args = vec![QueryResult::Resolved(Rc::new(value))];

        let result = substring(&args, from, to)?;
        assert_eq!(result.len(), 1, "one input, one answer");

        match (&result[0], expected) {
            (Some(PathAwareValue::String((_, got))), Some(want)) => assert_eq!(
                got, want,
                "substring({:?}, {}, {}) should be {:?}",
                input, from, to, want
            ),
            (None, None) => {}
            (got, want) => panic!(
                "substring({:?}, {}, {}) gave {:?}, expected {:?}",
                input, from, to, got, want
            ),
        }
    }

    Ok(())
}
