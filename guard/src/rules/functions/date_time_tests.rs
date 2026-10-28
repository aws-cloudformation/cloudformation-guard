use std::{convert::TryFrom, rc::Rc};

use crate::rules::{
    eval_context::eval_context_tests::BasicQueryTesting,
    exprs::AccessQuery,
    functions::date_time::{now, parse_epoch},
    path_value::PathAwareValue,
    EvalContext, QueryResult,
};
use chrono::Utc;
use pretty_assertions::assert_eq;
use rstest::rstest;

const VALUE_STR: &str = r#"
{
    "Resources": {
        "LambdaFunction": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "UpdatedAt": "2024-08-21T00:00:00Z",
                "CreatedAt": "2024-08-13T00:00:00Z",
                "BadValue": "not-a-date"
            }
        }
    }
}
    "#;

#[rstest]
#[case(r#"UpdatedAt"#, 1724198400, false)]
#[case(r#"CreatedAt"#, 1723507200, false)]
#[case(r#"BadValue"#, 1723507200, true)]
fn test_parse_epoch(
    #[case] query_str: &str,
    #[case] expected_epoch: i64,
    #[case] should_error: bool,
) -> crate::rules::Result<()> {
    let value = PathAwareValue::try_from(serde_json::from_str::<serde_json::Value>(VALUE_STR)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
    };
    let root_query =
        format!(r#"Resources[ Type == 'AWS::Lambda::Function' ].Properties.{query_str}"#,);
    let query = AccessQuery::try_from(root_query.as_str())?;
    let results = eval.query(&query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let epoch_values = parse_epoch(&results);
    if should_error {
        assert!(epoch_values.is_err());
    } else {
        assert!(epoch_values.is_ok());
        let epoch_values = epoch_values.unwrap();
        assert_eq!(epoch_values.len(), 1);
        // A comparison, not a pattern. This was `matches!(.., PathAwareValue::Int((_, _expected_epoch)))`,
        // and an identifier in a pattern is a fresh binding rather than the variable in scope, so it
        // matched every `Int` and the case's epoch was never checked: `parse_epoch` answering 0 for
        // every timestamp passed all three cases.
        match epoch_values[0].as_ref().unwrap() {
            PathAwareValue::Int((_, got)) => assert_eq!(*got, expected_epoch, "{query_str}"),
            other => panic!(
                "parse_epoch({}) should give an Int; got {:?}",
                query_str, other
            ),
        }
    }

    Ok(())
}

#[rstest]
fn test_now() {
    let now_result = now();
    assert!(now_result.is_ok());

    let now_vec = now_result.unwrap();
    assert_eq!(now_vec.len(), 1);

    let now_option = now_vec.first().unwrap();
    assert!(now_option.is_some());

    let now_value = now_option.as_ref().unwrap();

    let timestamp = match now_value {
        PathAwareValue::Int((_, timestamp)) => *timestamp,
        _ => unreachable!(),
    };

    let now = Utc::now().timestamp();

    assert!((now - timestamp).abs() <= 1);
}
