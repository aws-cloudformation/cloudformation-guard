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

/// `regex_replace` keeps the text that the pattern did not match.
///
/// It used to expand the captures into a fresh empty string and return that, so everything outside the
/// match was dropped: `regex_replace("prod-database-01", "database", "db")` answered `"db"` rather than
/// `"prod-db-01"`. Every shipped example anchors its pattern with `^...$`, which makes the match span
/// the whole string, so there was never any outside text to lose and no test noticed.
///
/// The no-match row is the one that mattered in practice. An unmatched pattern produced `""`, and `""`
/// is a value, so it compares: a rule that normalised an optional prefix before checking a name got a
/// pass on the name it meant to catch. Returning the input unchanged is what a replace does, and it
/// falls out of copying the unmatched remainder rather than needing a case of its own.
#[test]
fn regex_replace_keeps_the_text_outside_the_match() -> crate::rules::Result<()> {
    let cases = [
        // (input, pattern, replacement, expected)
        // A match in the middle. The prefix and the suffix both have to survive.
        ("prod-database-01", "database", "db", "prod-db-01"),
        // Several matches, each with a capture. The gaps between them are text too.
        ("a1b2c3", r"(\d)", "<${1}>", "a<1>b<2>c<3>"),
        // A match at one end only.
        ("prod-database-01", "^prod-", "", "database-01"),
        ("prod-database-01", "-01$", "", "prod-database"),
        // No match at all: the input, unchanged. This is the fail-open case.
        (
            "MY_SECRET_BUCKET",
            "^arn:aws:s3:::(.+)$",
            "${1}",
            "MY_SECRET_BUCKET",
        ),
        ("prod-database-01", "nothing-here", "x", "prod-database-01"),
        // Anchored across the whole string, which is what the shipped fixtures and the doc example
        // do. There is no outside text, so this answer is the same before and after.
        (
            "arn:aws:newservice:us-west-2:123456789012:Table/extracted",
            r"^arn:(\w+):(\w+):([\w0-9-]+):(\d+):(.+)$",
            "${1}/${4}/${3}/${2}-${5}",
            "aws/123456789012/us-west-2/newservice-Table/extracted",
        ),
    ];

    for (input, pattern, replacement, expected) in cases {
        let value = PathAwareValue::String((Path::root(), String::from(input)));
        let args = vec![QueryResult::Resolved(Rc::new(value))];

        let result = regex_replace(&args, pattern, replacement)?;
        assert_eq!(result.len(), 1, "one input, one answer");

        match &result[0] {
            Some(PathAwareValue::String((_, got))) => assert_eq!(
                got, expected,
                "regex_replace({:?}, {:?}, {:?})",
                input, pattern, replacement
            ),
            other => panic!(
                "regex_replace({:?}, {:?}, {:?}) gave {:?}, expected {:?}",
                input, pattern, replacement, other, expected
            ),
        }
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

/// `json_parse` still reads an integer above `i64::MAX` as its digits, not as a negative.
///
/// The second pin on the parser. `serde_json` routes to `TryFrom<&serde_json::Value>`, whose `is_u64`
/// arm is still `num.as_u64().unwrap() as i64` -- the bit-pattern reinterpretation that reads
/// `18446744073709551615` as exactly `-1`, inverting every numeric guard at exit 0. That is the sign
/// flip the `serde_yaml` arm in `values.rs` was fixed for, and the literal is valid JSON, so the swap
/// would reintroduce it here.
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
