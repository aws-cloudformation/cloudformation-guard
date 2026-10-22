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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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
        true,
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
/// Expanding the captures into a fresh empty string and returning that would drop everything outside
/// the match: `regex_replace("prod-database-01", "database", "db")` would answer `"db"` rather than
/// `"prod-db-01"`. Every shipped example anchors its pattern with `^...$`, which makes the match span
/// the whole string, so none of them has outside text to lose and none would notice.
///
/// The no-match row is the one that matters in practice. An unmatched pattern that produced `""` would
/// hand the rule a value, and `""` compares: a rule that normalizes an optional prefix before checking a
/// name would get a pass on the name it meant to catch. Returning the input unchanged is what a replace
/// does, and it falls out of copying the unmatched remainder rather than needing a case of its own.
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
        // do. There is no outside text, so a replacement that dropped the unmatched remainder would give
        // the same answer here.
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

        let result = regex_replace(&args, pattern, replacement, true)?;
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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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
/// which is what the surrounding code already did for those. An in-bounds range of length zero is the
/// empty string; `substring_of_an_in_bounds_empty_range_is_the_empty_string` is the test for that.
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
        // Out-of-bounds and inverted ranges answer with no value, as before.
        ("", 0, 1, None),
        ("hello", 4, 2, None),
        // An in-bounds range of length zero is the empty string, not no value.
        ("hello", 3, 3, Some("")),
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

/// `substring` over an in-bounds range of length zero is the empty string, not no value.
///
/// The guard was `!val.is_empty() && from < to && ...`, so `substring("abc", 1, 1)` and
/// `substring("", 0, 0)` both pushed `None`, the variable resolved to no values, and `%s == ""` failed
/// with a diagnostic pointing the author at the `let`. `docs/FUNCTIONS.md` promises skipping only for
/// an index out of bounds, and `[1, 1)` is inside every string of length one or more, as `[0, 0)` is
/// inside the empty string. Out-of-bounds and inverted ranges still answer with no value.
#[test]
fn substring_of_an_in_bounds_empty_range_is_the_empty_string() -> crate::rules::Result<()> {
    let cases = [
        // (input, from, to, expected)
        // The defect: in bounds, zero length, answered nothing.
        ("abc", 1, 1, Some("")),
        ("abc", 0, 0, Some("")),
        // Both ends at the length is in bounds for an exclusive end.
        ("abc", 3, 3, Some("")),
        ("", 0, 0, Some("")),
        // Still no value: an end past the length, or a start after the end.
        ("abc", 4, 4, None),
        ("", 0, 1, None),
        ("", 1, 1, None),
        ("abc", 2, 1, None),
        // The documented use is unchanged.
        ("arn:aws:s3:::b", 0, 3, Some("arn")),
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

/// Queries `query` against `document` the way a rule does, so a wildcard over an empty list reaches
/// the function as the unresolved result `accumulate` produces, not as a hand-built value.
fn query_results(document: &str, query: &str) -> crate::rules::Result<Vec<QueryResult>> {
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(document)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
    };
    eval.query(&AccessQuery::try_from(query)?.query)
}

/// `join` over a collection that is present and empty is the empty string.
///
/// A wildcard over a list with no members reaches the function as an unresolved result whose
/// `traversed_to` is that list, and `join` errored on every unresolved result alike: "Joining
/// unresolved values is not allowed Path=/Resources/Svc/Collection Value=[]" at exit 19, calling an
/// existing empty list an unresolved path. `count` already tells the two apart and answers 0 for the
/// same shape; `join` now answers `""` for it, and a member that is present and empty contributes
/// nothing to a join over several resources. A key that is absent is still an error.
#[test]
fn join_of_a_present_but_empty_collection_is_the_empty_string() -> crate::rules::Result<()> {
    let document = r#"
    Resources:
      Svc:
        Type: AWS::New::Service
        Collection: []
      Full:
        Type: AWS::New::Service
        Collection: [a, b]
    "#;

    // The defect. The list is there and holds nothing.
    let results = query_results(document, "Resources.Svc.Collection.*")?;
    match join(&results, ",")? {
        PathAwareValue::String((path, joined)) => {
            assert_eq!(joined, "", "join over an empty collection");
            assert_eq!(
                path.0, "/Resources/Svc/Collection",
                "the answer sits at the collection that was reached"
            );
        }
        other => panic!("join over an empty collection gave {:?}", other),
    }

    // Over several resources, the empty member contributes nothing and leaves no stray delimiter,
    // whichever side of the members it falls on.
    let results = query_results(document, "Resources.*.Collection.*")?;
    match join(&results, ",")? {
        PathAwareValue::String((_, joined)) => assert_eq!(joined, "a,b"),
        other => panic!("join over a mixed selection gave {:?}", other),
    }

    let reversed = r#"
    Resources:
      Full:
        Type: AWS::New::Service
        Collection: [a, b]
      Svc:
        Type: AWS::New::Service
        Collection: []
    "#;
    let results = query_results(reversed, "Resources.*.Collection.*")?;
    match join(&results, ",")? {
        PathAwareValue::String((_, joined)) => assert_eq!(joined, "a,b"),
        other => panic!("join over a mixed selection gave {:?}", other),
    }

    // A key that is not there is still refused: there is no collection to join.
    let results = query_results(document, "Resources.Svc.Missing.*")?;
    match join(&results, ",") {
        Err(crate::Error::Unevaluatable(message)) => assert!(
            message.contains("unresolved"),
            "an absent key should still be reported as unresolved; got {:?}",
            message
        ),
        other => panic!("join over an absent key should be refused; got {:?}", other),
    }

    // A key absent from a struct that is itself empty is an absent key, not an empty collection.
    // The struct the query searched has no members, but the query stopped at `Tags`, a key it did
    // not find, not at an expansion that ran out of members. Reading the empty struct as the
    // collection would make `join(%r.Properties.Tags[*].Key, ",") != "forbidden"` pass on a bucket
    // that has no tags key at all.
    let bare = r#"
    Resources:
      Bare:
        Type: AWS::S3::Bucket
        Properties: {}
    "#;
    let results = query_results(bare, "Resources.Bare.Properties.Tags[*].Key")?;
    match join(&results, ",") {
        Err(crate::Error::Unevaluatable(message)) => assert!(
            message.contains("unresolved"),
            "a key absent from an empty struct should still be reported as unresolved; got {:?}",
            message
        ),
        other => panic!(
            "join over a key absent from an empty struct should be refused; got {:?}",
            other
        ),
    }

    // The same empty struct expanded directly is a collection with no members, and joins to "".
    let results = query_results(bare, "Resources.Bare.Properties.*")?;
    match join(&results, ",")? {
        PathAwareValue::String((_, joined)) => assert_eq!(joined, ""),
        other => panic!("join over an expansion of an empty struct gave {:?}", other),
    }

    Ok(())
}

/// `join` places its answer at the path its members share, not at the first member.
///
/// Same mechanism as `count`: the result took `args[0]`'s path, so a failing `join(%names, ",") == "x"`
/// over two buckets was reported at `/Resources/BucketA/Properties/BucketName`, naming one bucket for a
/// string built from both. The answer now sits at the longest common prefix of the members' paths.
#[test]
fn join_sits_at_the_path_its_members_share() -> crate::rules::Result<()> {
    let document = r#"
    Resources:
      BucketA:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: a
      BucketB:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: b
      Svc:
        Type: AWS::New::Service
        Collection: [x, y, z]
    "#;

    let cases = [
        // (query, expected text, expected path)
        (
            r#"Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName"#,
            "a,b",
            "/Resources",
        ),
        (
            r#"Resources.Svc.Collection.*"#,
            "x,y,z",
            "/Resources/Svc/Collection",
        ),
        (
            r#"Resources.Svc.Collection[0]"#,
            "x",
            "/Resources/Svc/Collection/0",
        ),
    ];

    for (query, expected, expected_path) in cases {
        let results = query_results(document, query)?;
        match join(&results, ",")? {
            PathAwareValue::String((path, joined)) => {
                assert_eq!(joined, expected, "join({query})");
                assert_eq!(path.0, expected_path, "where join({query}) is placed");
                // The serde-backed loader behind `query_results` records no positions, so every
                // member here is at the neutral location and so is the answer; the location rules
                // are measured on positioned values in `count_sits_at_the_path_its_members_share`,
                // through the same `common_path`.
                assert_eq!(path.1, Location::default());
            }
            other => panic!("join({}) gave {:?}", query, other),
        }
    }

    Ok(())
}

/// `join` refuses a member that is not a string, and the refusal names the member.
///
/// A non-string member is not skipped: the first one is a refusal (`Unevaluatable`, the data's) and
/// the clause bails at exit 19, and `docs/FUNCTIONS.md` says so. A join that silently dropped the `1`
/// in `[a, 1, b]` would satisfy `== "a,b"` and hide the member the author most likely wants to hear
/// about.
#[test]
fn join_refuses_a_non_string_element() -> crate::rules::Result<()> {
    let mixed = r#"
    Resources:
      Thing:
        Type: AWS::New::Service
        Collection: [a, 1, b]
    "#;
    let results = query_results(mixed, "Resources.Thing.Collection.*")?;
    match join(&results, ",") {
        Err(crate::Error::Unevaluatable(message)) => {
            assert!(
                message.contains("Joining non string values"),
                "the refusal should say what was wrong; got {:?}",
                message
            );
            assert!(
                message.contains("/Resources/Thing/Collection/1"),
                "the refusal should name the offending member; got {:?}",
                message
            );
        }
        other => panic!("join over [a, 1, b] should be refused; got {:?}", other),
    }

    // The control: a collection of strings joins.
    let strings = r#"
    Resources:
      Thing:
        Type: AWS::New::Service
        Collection: [a, b, c]
    "#;
    let results = query_results(strings, "Resources.Thing.Collection.*")?;
    match join(&results, ",")? {
        PathAwareValue::String((_, joined)) => assert_eq!(joined, "a,b,c"),
        other => panic!("join over [a, b, c] gave {:?}", other),
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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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

/// `json_parse` refuses two member names that differ as YAML scalars but read as one key.
///
/// The string is parsed by `serde_yaml`, which accepts YAML-only spellings, so `{1: "first", "1":
/// "second"}` arrives as two distinct keys: the integer 1 and the string "1". Every key becomes text
/// on the way into the value model, and both became the text "1", so the second insert replaced the
/// first and nothing said so: `%p."1" == "second"` PASSed and `%p."1" == "first"` FAILed at exit 19,
/// on a document the author may well have meant the other way round. The data-file loader `validate`
/// reads with reports the same pair as a duplicate key; this route has no warning channel, so it
/// refuses, which is also what `serde_yaml` itself does for two byte-identical names.
///
/// The refusal names the key, since a document with several embedded strings gives the author nothing
/// else to search for. The boolean pair is the other spelling the collision has, and the single quoted
/// key is the control: one key named "1" is an ordinary member.
#[rstest::rstest]
#[case::an_integer_and_a_string(r#"{1: "first", "1": "second"}"#, "1")]
#[case::a_boolean_and_a_string(r#"{true: "first", "true": "second"}"#, "true")]
fn json_parse_refuses_two_keys_that_read_as_one(#[case] embedded: &str, #[case] key: &str) {
    let err = json_parse_embedded(embedded)
        .expect_err("two keys that read as the same name must be refused, not collapsed");

    let message = err.to_string();
    assert!(
        message.contains("failed to convert the parsed string at"),
        "the refusal should name the property, got {}",
        message
    );
    assert!(
        message.contains(&format!("`{key}`")),
        "the refusal should name the colliding key, got {}",
        message
    );
}

/// The control for the test above: a single member named "1" is read as that member.
#[test]
fn json_parse_keeps_a_single_numeric_looking_member() -> crate::rules::Result<()> {
    let parsed = json_parse_embedded(r#"{"1": "only"}"#)?;
    let map = sole_map(&parsed);

    assert_eq!(
        map.values.keys().collect::<Vec<_>>(),
        vec!["1"],
        "one member named \"1\" is one key"
    );
    assert!(
        matches!(map.values.get("1"), Some(PathAwareValue::String((_, s))) if s == "only"),
        "the member keeps its value, got {:?}",
        map.values.get("1")
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
/// arm keeps the digits; an arm reading `num.as_u64().unwrap() as i64` would reinterpret the bit
/// pattern and read `18446744073709551615` as exactly `-1`, inverting every numeric guard at exit 0.
/// Keeping the digits there is not the whole answer: `serde_json` parses an integer past `u64::MAX` as a
/// float before any conversion sees it, where `serde_yaml` refuses the literal, so the swap would still
/// change what this function makes of a valid JSON integer.
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

/// Each refusal `regex_replace` makes is classified on the provenance of what failed, and each case
/// here accepts only the variant its provenance owes: a rules-file pattern that does not compile is
/// `IncompatibleError`; a backtracking budget spent on a template input is `Unevaluatable`. Both name
/// the pattern.
///
/// A pattern that does not compile, and a pattern whose match exhausts the engine's backtracking
/// budget, were both `RegexError`. That class says "parse error for rules file", which is wrong for a
/// pattern the template supplied, and `is_unevaluatable` does not recognize it, so the error left the
/// evaluator and the run exited 255 after printing its report. Both are classified by provenance now
/// (see `compile_pattern`): the pattern here is passed as the rules file's, which is the author's
/// mistake, `IncompatibleError`; the same pattern read from the template is the data's,
/// `Unevaluatable`, and the clause fails. The budget failure is answered on the input's provenance,
/// and the input here is a template value, so that case is `Unevaluatable`.
///
/// Both arms are guarded on `authors_mistake`. Without the guard on the `IncompatibleError` arm the
/// budget case passed under either variant, so a regression that stopped the run on a template
/// input's exhausted budget stayed green here.
///
/// The compile now happens once, ahead of the loop, so it is reported whether or not any element is a
/// string; the run-time error names the value the pattern was run against.
#[rstest::rstest]
#[case::does_not_compile("prod-database-01", "(", true)]
#[case::exhausts_the_backtracking_budget(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "(?!x)((a+)+)b",
    false
)]
fn regex_replace_refuses_each_failure_on_the_variant_its_provenance_owes(
    #[case] input: &str,
    #[case] pattern: &str,
    #[case] authors_mistake: bool,
) {
    let args = vec![crate::rules::QueryResult::Resolved(Rc::new(
        PathAwareValue::String((Path::root(), input.to_string())),
    ))];

    match regex_replace(&args, pattern, "x", true) {
        Err(crate::Error::Unevaluatable(message)) if !authors_mistake => assert!(
            message.contains("regex_replace") && message.contains(pattern),
            "the refusal names the function and the pattern: {:?}",
            message
        ),
        Err(crate::Error::IncompatibleError(message)) if authors_mistake => assert!(
            message.contains("regex_replace") && message.contains(pattern),
            "the refusal names the function and the pattern: {:?}",
            message
        ),
        other => panic!(
            "regex_replace with the pattern {:?} must be refused by provenance (authors_mistake = {}), got {:?}",
            pattern, authors_mistake, other
        ),
    }
}

/// With no string among the inputs the pattern is still compiled, so a broken one is still reported,
/// on the pattern's own provenance: the rules file's here.
#[test]
fn regex_replace_compiles_the_pattern_before_reading_any_input() {
    let args = vec![crate::rules::QueryResult::Resolved(Rc::new(
        PathAwareValue::Int((Path::root(), 5)),
    ))];

    assert!(
        matches!(
            regex_replace(&args, "(", "x", true),
            Err(crate::Error::IncompatibleError(_))
        ),
        "an integer input does not hide a pattern that does not compile"
    );
    assert!(
        matches!(
            regex_replace(&args, "(", "x", false),
            Err(crate::Error::Unevaluatable(_))
        ),
        "the same pattern read from the template is the data's refusal"
    );
}
