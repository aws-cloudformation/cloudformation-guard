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
        Some(PathAwareValue::Int((_, cnt))) => assert_eq!(cnt, 1),
        other => panic!("expected a count, got {:?}", other),
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
        Some(PathAwareValue::Int((_, cnt))) => assert_eq!(cnt, 1),
        other => panic!("expected a count, got {:?}", other),
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
        Some(PathAwareValue::Int((_, cnt))) => assert_eq!(cnt, 1),
        other => panic!("expected a count, got {:?}", other),
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

/// Runs `json_parse` over a single property whose value is `embedded`.
///
/// The outer document is built as a `serde_yaml::Value` rather than as text so the embedded string
/// needs no YAML quoting -- these cases are about characters (`<<`, quotes, `#`) that a quoting pass
/// would be the thing under test.
fn json_parse_embedded(embedded: &str) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut root = serde_yaml::Mapping::new();
    root.insert(
        serde_yaml::Value::String("Doc".to_string()),
        serde_yaml::Value::String(embedded.to_string()),
    );
    let value = PathAwareValue::try_from(serde_yaml::Value::Mapping(root))?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let results = eval.query(&AccessQuery::try_from("Doc")?.query)?;

    json_parse(&results)
}

/// The one answer of a `json_parse` over a single property, as a map.
fn sole_map(parsed: &[Option<PathAwareValue>]) -> &crate::rules::path_value::MapValue {
    assert_eq!(parsed.len(), 1, "one input, one answer");
    match parsed[0].as_ref().expect("a string input parses") {
        PathAwareValue::Map((_, map)) => map,
        other => panic!("expected a map, got {:?}", other),
    }
}

/// `json_parse` keeps a member literally named `<<`.
///
/// JSON has no merge keys. Reading the string with `serde_yaml` and converting it through the
/// merge-resolving `TryFrom<&serde_yaml::Value>` applied YAML's rule anyway, so the valid JSON
/// `{"<<": {"hoisted": "yes"}, "b": "kept"}` lost the `"<<"` member and gained `hoisted` at the top
/// level: `%p["<<"] exists` FAILed at exit 19 while `%p.hoisted == "yes"` PASSed at 0, against a
/// document every other JSON reader in a pipeline hands over intact.
///
/// The sibling `"b"` is asserted because the failure mode is a hoist and not a drop -- a conversion that
/// merely lost the whole mapping would also satisfy an assertion about `<<` alone.
#[test]
fn json_parse_keeps_a_member_named_as_the_merge_key() -> crate::rules::Result<()> {
    let parsed = json_parse_embedded(r#"{"<<": {"hoisted": "yes"}, "b": "kept"}"#)?;
    let map = sole_map(&parsed);

    assert!(
        map.values.contains_key("<<"),
        "the `<<` member is gone; keys are {:?}",
        map.values.keys().collect::<Vec<_>>()
    );
    assert!(
        !map.values.contains_key("hoisted"),
        "the `<<` value's contents were hoisted to the top level; keys are {:?}",
        map.values.keys().collect::<Vec<_>>()
    );
    assert!(map.values.contains_key("b"), "the sibling member is kept");
    assert_eq!(map.values.len(), 2, "exactly the two members written");

    Ok(())
}

/// The literal reading reaches a `<<` at any depth, not just the document's root.
///
/// `MergeKey` is threaded through every recursive arm of the conversion for this: a nested `<<` would
/// otherwise still be resolved, and nesting is where an embedded IAM policy actually puts its objects.
#[test]
fn json_parse_keeps_a_nested_member_named_as_the_merge_key() -> crate::rules::Result<()> {
    let parsed = json_parse_embedded(r#"{"outer": [{"<<": {"hoisted": "yes"}, "b": "kept"}]}"#)?;
    let map = sole_map(&parsed);

    let inner = match map.values.get("outer").expect("outer is present") {
        PathAwareValue::List((_, items)) => match &items[0] {
            PathAwareValue::Map((_, map)) => map,
            other => panic!("expected a map inside the list, got {:?}", other),
        },
        other => panic!("expected a list, got {:?}", other),
    };

    assert!(
        inner.values.contains_key("<<"),
        "the nested `<<` member is gone; keys are {:?}",
        inner.values.keys().collect::<Vec<_>>()
    );
    assert!(
        !inner.values.contains_key("hoisted"),
        "the nested `<<` value's contents were hoisted; keys are {:?}",
        inner.values.keys().collect::<Vec<_>>()
    );

    Ok(())
}

/// `json_parse` still refuses a duplicate member name.
///
/// This is the first of three pins on the parser staying `serde_yaml`. Parsing with `serde_json`
/// instead would be the obvious way to drop merge-key semantics, and it accepts a duplicate name --
/// last one wins, measured `{"a": 1, "a": 2}` -> `{"a": 2}`. The refusal is what
/// `guard/resources/validate/functions/data/embedded_json_the_parser_rejects.yaml` exists to pin, and it
/// is reported as a policy failure rather than a broken tool, so making the string readable would
/// silently change what that fixture measures.
#[test]
fn json_parse_refuses_a_duplicate_member_name() {
    let err =
        json_parse_embedded(r#"{"a": 1, "a": 2}"#).expect_err("a duplicate member name is refused");

    let message = err.to_string();
    assert!(
        message.contains("failed to parse the string at"),
        "the refusal should name the property, got {}",
        message
    );
    assert!(
        message.contains("duplicate entry"),
        "the refusal should say what was wrong, got {}",
        message
    );
}

/// `json_parse` reads an integer above `i64::MAX` as its digits, not as a negative.
///
/// The second pin on the parser, and the reason it gives has expired. It used to be that
/// `TryFrom<&serde_json::Value>`'s `is_u64` arm was still `num.as_u64().unwrap() as i64` -- the
/// bit-pattern reinterpretation reading `18446744073709551615` as exactly `-1`, inverting every
/// numeric guard at exit 0 -- so swapping the parser for `serde_json` would have reintroduced the
/// sign flip the `serde_yaml` arm had been fixed for. That arm keeps the digits now as well, so the
/// swap would not reintroduce it and this case no longer argues against the swap. The first and
/// third pins still do, and they are the two reasons `Value::try_from_json`'s comment now gives.
///
/// What it pins instead is the reading through `json_parse`'s path. `json_parse` converts with
/// `Value::try_from_json`, so it shares `convert_yaml`'s `is_u64` arm with the
/// `TryFrom<&serde_yaml::Value>` entry point `values_tests.rs` covers, and reverting that arm fails
/// both -- measured. The two are not the same cell, though: that one stops at a `Value`, and this
/// one carries on through the `PathAwareValue::try_from` `json_parse` calls next, so it asserts
/// the `PathAwareValue` a clause is evaluated against. This is the case that says a wide integer
/// survives the whole of what `json_parse` does to it, digits included.
#[test]
fn json_parse_reads_an_integer_wider_than_i64_as_digits() -> crate::rules::Result<()> {
    let parsed = json_parse_embedded(r#"{"v": 18446744073709551615}"#)?;
    let map = sole_map(&parsed);

    match map.values.get("v").expect("v is present") {
        PathAwareValue::String((_, digits)) => assert_eq!("18446744073709551615", digits),
        other => panic!(
            "an integer above i64::MAX should keep its digits, got {:?}",
            other
        ),
    }

    Ok(())
}

/// `json_parse` still accepts the YAML-only spellings it accepted before.
///
/// The third pin on the parser, and the reason the fix changes the conversion rather than the parser.
/// `serde_yaml` accepts a superset of JSON, so every shape here reaches `json_parse` successfully
/// today; `serde_json` refuses all of them (measured: unquoted key, single quotes and a trailing
/// comment each give "key must be a string" or "trailing characters"). Narrowing the accepted input is
/// a behavior change no caller asked for, and it would land on templates that work now.
#[rstest::rstest]
#[case::unquoted_key("{a: 1}")]
#[case::single_quoted_key("{'a': 1}")]
#[case::trailing_comment(r#"{"a": 1} # a comment"#)]
#[case::trailing_comma(r#"{"a": 1,}"#)]
#[case::block_mapping("a: 1")]
fn json_parse_accepts_the_yaml_spellings_it_accepted_before(
    #[case] embedded: &str,
) -> crate::rules::Result<()> {
    let parsed = json_parse_embedded(embedded)?;
    let map = sole_map(&parsed);

    assert!(
        map.values.contains_key("a"),
        "{embedded} should still parse to a map with `a`; keys are {:?}",
        map.values.keys().collect::<Vec<_>>()
    );

    Ok(())
}
