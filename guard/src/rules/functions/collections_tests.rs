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
        Some(PathAwareValue::Int((_, cnt))) => assert_eq!(cnt, 1),
        other => panic!("expected a count, got {:?}", other),
    }

    let value_str = r#"{}"#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let query = AccessQuery::try_from(r#"Resources"#)?;
    let results = eval.query(&query.query)?;

    // The root document is `{}`, so `Resources` is absent -- but the map the query searched is itself
    // empty, which is a collection with no members and counts 0. A key absent from a struct that does
    // hold something is the case that now answers with no value, and
    // `count_does_not_invent_a_value_for_an_unresolved_selection` covers it.
    match count(&results) {
        Some(PathAwareValue::Int((_, cnt))) => assert_eq!(cnt, 0),
        other => panic!("expected a count, got {:?}", other),
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
        Some(PathAwareValue::Int((_, cnt))) => assert_eq!(cnt, 2),
        other => panic!("expected a count, got {:?}", other),
    }

    let query = AccessQuery::try_from(r#"Resources[ Type == 'AWS::EC2::Instance' ]"#)?;
    let results = eval.query(&query.query)?;

    match count(&results) {
        Some(PathAwareValue::Int((_, cnt))) => assert_eq!(cnt, 0),
        other => panic!("expected a count, got {:?}", other),
    }
    Ok(())
}

/// `count` answers 0 for a collection that is there and holds nothing, and answers nothing for a query
/// that named something absent.
///
/// It used to filter the unresolved results out and count what was left, so both cases came back as the
/// `Int` 0 -- and 0 is a value, so it compares. A one-letter typo turned a check into a green build:
/// `count(%b.Properties.Grantz.*) == 0` passed at exit 0 on a bucket whose correctly spelled `Grants`
/// holds a public grant, and the same rule spelled `Grants` exited 19. `count` was the only function
/// that did this. On the same absent path `to_upper`, `parse_int`, `substring` and `json_parse` all
/// report "resolved to no values", and `join` errors, each at exit 19.
///
/// The two cases are distinguishable, which is what makes this fixable without losing the empty
/// collection. A wildcard over a collection with no members leaves `traversed_to` pointing at that
/// collection, so the query reached it and 0 is the honest count. A key that was not found leaves
/// `traversed_to` pointing at the struct that was searched, so there is no collection to count.
///
/// A selection that resolved for some values and not others still counts the ones it found: a rule over
/// several buckets where only one carries `Grants` is asking how many grants exist, not whether every
/// bucket has the key. Only a selection where nothing at all resolved can be a missing path.
#[test]
fn count_does_not_invent_a_value_for_an_unresolved_selection() -> crate::rules::Result<()> {
    let document = r#"
    Resources:
      goodbucket:
        Type: AWS::S3::Bucket
        Properties:
          PublicAccessBlockConfiguration:
            BlockPublicAcls: true
      openbucket:
        Type: AWS::S3::Bucket
        Properties:
          Grants:
            - Grantee: AllUsers
              Permission: FULL_CONTROL
      emptybucket:
        Type: AWS::S3::Bucket
        Properties:
          Grants: []
    "#;

    let cases = [
        // (query, expected count, what the query is)
        // The typo. `Grantz` exists nowhere, so nothing resolves and there is no collection.
        (
            r#"Resources[ Type == 'AWS::S3::Bucket' ].Properties.Grantz.*"#,
            None,
            "a key that is absent from every selected value",
        ),
        // A path that is absent higher up, which is the same thing further from the leaf.
        (
            r#"Resources.doesNotExist.Whatever.*"#,
            None,
            "a path absent from the root",
        ),
        // The control. `Grants: []` is a real list with no members, and 0 is the count of it. This one
        // answered 0 before the change too, and has to keep doing so.
        (
            r#"Resources.emptybucket.Properties.Grants.*"#,
            Some(0),
            "a list that is present and empty",
        ),
        // A filter matching nothing selects nothing at all rather than failing to resolve, so it counts
        // 0. This is the shape most rules are written in.
        (
            r#"Resources[ Type == 'AWS::EC2::Instance' ]"#,
            Some(0),
            "a filter that matches nothing",
        ),
        // Resolved for one bucket, unresolved for the two others. The one grant still counts.
        (
            r#"Resources[ Type == 'AWS::S3::Bucket' ].Properties.Grants.*"#,
            Some(1),
            "a selection that resolved for some values only",
        ),
        (
            r#"Resources[ Type == 'AWS::S3::Bucket' ]"#,
            Some(3),
            "three buckets",
        ),
    ];

    for (query, expected, description) in cases {
        let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(document)?)?;
        let mut eval = BasicQueryTesting {
            root: Rc::new(value),
            recorder: None,
        };
        let results = eval.query(&AccessQuery::try_from(query)?.query)?;

        match (count(&results), expected) {
            (Some(PathAwareValue::Int((_, got))), Some(want)) => {
                assert_eq!(got, want, "count({query}) -- {description}")
            }
            (None, None) => {}
            (got, want) => panic!(
                "count({}) gave {:?}, expected {:?} -- {}",
                query, got, want, description
            ),
        }
    }

    Ok(())
}
