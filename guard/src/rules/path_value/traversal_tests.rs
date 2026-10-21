use super::*;
use pretty_assertions::assert_eq;
use std::borrow::Cow;
use std::convert::TryFrom;

#[test]
fn test_absolute_pointer_traversal() -> crate::rules::Result<()> {
    let value = PathAwareValue::try_from(crate::rules::values::read_from(
        r#"
        Resources:
          Helper:
            Type: AWS::S3::Bucket
          s3:
            Type: AWS::S3::Bucket
            Properties:
              Name: MyBucket
              AnalyticsConfiguration:
                - Prefix: MyBucket/2021/10
                  StorageClassAnalysis:
                    DataExport:
                      Destination:
                        BucketAccountId: 123456789012
                        BucketArn: arn:aws:s3:us-west-2:123456789112:ThatBucket/2021
                        Format: Parquet
                  TagFilters:
                    - Key: ProdApp
                      Value: MyAppStuff
              InventoryConfigurations:
                - Id: InventoryConfigurationId
                  Destination:
                    BucketArn:
                      Fn::GetAtt:
                        - Helper
                        - Arn
                    Format: CSV
                    Prefix: InventoryDestinationPrefix
                  Enabled: true
                  IncludedObjectVersions: Current
                  Prefix: InventoryConfigurationPrefix
                  ScheduleFrequency: Weekly
        "#,
    )?)?;

    let traversal = Traversal::from(&value);
    let root = traversal.root().unwrap();
    let result = traversal.at("/", root)?;
    assert!(matches!(result, TraversalResult::Value(_)));
    if let TraversalResult::Value(curr) = result {
        assert!(std::ptr::eq(&value, curr.value));
    }
    let result = match result {
        TraversalResult::Value(val) => val,
        _ => unreachable!(),
    };

    let result = traversal.at("/Resources/s3/Properties/AnalyticsConfiguration", result)?;
    assert!(matches!(result, TraversalResult::Value(_)));
    let result = match result {
        TraversalResult::Value(val) => val,
        _ => unreachable!(),
    };
    assert!(matches!(result.value, PathAwareValue::List(_)));

    //
    // Testing relative
    //
    let upward = traversal.at("1/Name", result)?;
    assert!(matches!(upward, TraversalResult::Value(_)));
    let upward = match upward {
        TraversalResult::Value(up) => up,
        _ => unreachable!(),
    };
    match upward.value {
        PathAwareValue::String((path, value)) => {
            assert_eq!(path.0, "/Resources/s3/Properties/Name");
            assert_eq!(value, "MyBucket");
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// A miss costs a map lookup, not a rendering of the rest of the document.
///
/// Building the "did not yield value ... expected sub-paths" message eagerly with `format!` would
/// render the sub-paths, `nodes.range(pointer..)`, on every miss: every node whose path sorts after
/// the pointer, each Debug-printed with its whole subtree. The console reporter misses once per
/// non-compliant resource that has no `Metadata.aws:cdk:path` and throws the `Err` away unread, so
/// on a template with N failing resources it would do N renders of the document's tail that nothing
/// ever saw. Measured at about a second of an eleven-second report for 1000 resources.
///
/// The error borrows the traversal and renders the candidates only when displayed, which is what
/// this test pins: the value `at` returns is the `NotFound` variant holding the pointer, not a string,
/// and displaying it still produces the message with the sibling paths in it, so the one caller that
/// does propagate the error with `?` (the Terraform reporter) prints what it printed before. A timing
/// assertion would be a flaky test; the shape is the guarantee.
#[test]
fn a_miss_does_not_render_the_rest_of_the_document() -> crate::rules::Result<()> {
    let mut doc = String::from("Resources:\n");
    for i in 0..1000 {
        doc.push_str(&format!(
            "  R{:05}:\n    Type: AWS::X::Y\n    Properties:\n      Size: {}\n",
            i, i
        ));
    }
    let value = PathAwareValue::try_from(crate::rules::values::read_from(&doc)?)?;
    let traversal = Traversal::from(&value);
    let root = traversal.root().unwrap();
    let resource = match traversal.at("/Resources/R00000", root)? {
        TraversalResult::Value(node) => node,
        other => panic!("expected a node, got {:?}", other),
    };

    // Control: the lookup the reporter makes first does hit.
    assert!(matches!(
        traversal.at("0/Type", resource),
        Ok(TraversalResult::Value(_))
    ));

    // The miss the reporter makes on every hand-written template.
    let err = traversal
        .at("0/Metadata/aws:cdk:path", resource)
        .expect_err("no resource carries a cdk path");
    match &err {
        TraversalError::NotFound { pointer, .. } => {
            assert_eq!(pointer, "/Resources/R00000/Metadata/aws:cdk:path");
        }
        other => panic!("a miss is NotFound, got {:?}", other),
    }

    // Rendering is on demand and still names the candidates; converting into the crate error keeps
    // the text, so a caller that propagates with `?` sees no change.
    let rendered = err.to_string();
    assert!(
        rendered.contains("did not yield value")
            && rendered.contains("/Resources/R00000/Properties"),
        "rendering must still carry the message and the sibling paths, got: {}",
        &rendered[..rendered.len().min(400)]
    );
    match Error::from(err) {
        Error::RetrievalError(text) => assert_eq!(text, rendered),
        other => panic!(
            "a traversal miss converts to RetrievalError, got {:?}",
            other
        ),
    }

    // The two other misses keep their wording.
    let beyond = traversal
        .at("5/Type", resource)
        .expect_err("a resource has one ancestor, not five");
    assert!(matches!(beyond, TraversalError::BeyondRoot { .. }));
    assert_eq!(
        beyond.to_string(),
        "No more ancestors found. Path 5/Type pointing to beyond root"
    );

    Ok(())
}

fn value_at<'a>(traversal: &'a Traversal<'_>, pointer: &str, from: &'a Node<'_>) -> &'a Node<'a> {
    match traversal.at(pointer, from) {
        Ok(TraversalResult::Value(node)) => node,
        other => panic!("{:?} should resolve to a node, got {:?}", pointer, other),
    }
}

fn string_at(traversal: &Traversal<'_>, pointer: &str, from: &Node<'_>) -> String {
    match value_at(traversal, pointer, from).value() {
        PathAwareValue::String((_, s)) => s.clone(),
        other => panic!("{:?} should be a string, got {:?}", pointer, other),
    }
}

/// A key holding a `/` gets its own index entry instead of sharing one with a nested path.
///
/// `Path` joins segments with a bare `/`, so the key `A/B` under `Resources` and the key `B` under
/// `Resources.A` both carry the path string `/Resources/A/B`, and the index, keyed on that string,
/// kept whichever was inserted last. `at("/Resources/A/B")` then answered with a different node
/// depending on the order the two keys appeared in the file, and the console reporter printed
/// `Type = Nested::Child` for a resource whose `Type` is `Flat::Resource`.
///
/// The index now keys each node on a JSON Pointer (RFC 6901): a `~` in a segment is written `~0` and a
/// `/` is written `~1`, so the two nodes have the keys `/Resources/A/B` and `/Resources/A~1B` and
/// resolve apart whatever the order. The path strings on the values themselves are untouched; this
/// is the index's business only. The raw spelling of a key holding a `/` or `~` is a miss, not a
/// fallback: a key `t~1u` and a key `t/u` would otherwise share one spelling again.
#[test]
fn a_key_holding_a_slash_resolves_apart_from_the_nested_path() -> crate::rules::Result<()> {
    for (label, doc) in [
        (
            "flat key first",
            "Resources:\n  \"A/B\":\n    Type: Flat::Resource\n  A:\n    Type: Outer::Resource\n    B:\n      Type: Nested::Child\n",
        ),
        (
            "nested key first",
            "Resources:\n  A:\n    Type: Outer::Resource\n    B:\n      Type: Nested::Child\n  \"A/B\":\n    Type: Flat::Resource\n",
        ),
    ] {
        let value = PathAwareValue::try_from(crate::rules::values::read_from(doc)?)?;
        let traversal = Traversal::from(&value);
        let root = traversal.root().unwrap();

        // The structural reading of `/Resources/A/B` is the nested node, in either order.
        let nested = value_at(&traversal, "/Resources/A/B", root);
        assert_eq!(
            string_at(&traversal, "0/Type", nested),
            "Nested::Child",
            "{}: /Resources/A/B is the nested node",
            label
        );
        assert_eq!(nested.parent(), Some("/Resources/A"), "{}", label);

        // The escaped pointer is the flat key, and relative pointers from it stay inside it.
        let flat = value_at(&traversal, "/Resources/A~1B", root);
        assert_eq!(
            string_at(&traversal, "0/Type", flat),
            "Flat::Resource",
            "{}: /Resources/A~1B is the flat key",
            label
        );
        assert_eq!(flat.parent(), Some("/Resources"), "{}", label);
        assert_eq!(
            string_at(&traversal, "1/A/Type", flat),
            "Outer::Resource",
            "{}: one level up from the flat key is Resources",
            label
        );

        // The value's own path string is not what changed: both nodes still say `/Resources/A/B`.
        assert_eq!(flat.value().self_path().0, "/Resources/A/B", "{}", label);
        assert_eq!(nested.value().self_path().0, "/Resources/A/B", "{}", label);
    }

    // A key holding a `~`, a key spelled like an escape, and a key holding a `/` each have exactly
    // one pointer. The raw spellings miss: `/t~u` is not a pointer, and `/t~1u` is the pointer of
    // the key `t/u`, not of the key `t~1u`.
    let value = PathAwareValue::try_from(crate::rules::values::read_from(
        "\"x/y\": one\n\"t~u\": two\n\"t~1u\": three\n\"t/u\": four\n",
    )?)?;
    let traversal = Traversal::from(&value);
    let root = traversal.root().unwrap();
    assert_eq!(string_at(&traversal, "/x~1y", root), "one");
    assert_eq!(string_at(&traversal, "/t~0u", root), "two");
    assert_eq!(string_at(&traversal, "/t~01u", root), "three");
    assert_eq!(string_at(&traversal, "/t~1u", root), "four");
    for raw in ["/x/y", "/t~u"] {
        assert!(
            matches!(
                traversal.at(raw, root),
                Err(TraversalError::NotFound { .. })
            ),
            "{:?} is a raw spelling, not a pointer, and must miss",
            raw
        );
    }
    assert_eq!(
        escape_pointer_segment("a~b/c"),
        "a~0b~1c",
        "the escape callers use to spell a key as a pointer segment"
    );
    assert!(
        matches!(escape_pointer_segment("plain"), Cow::Borrowed("plain")),
        "a segment with nothing to escape is borrowed"
    );

    // `{:?}` of a miss names the pointer and counts the index; it does not print it. Six nodes: the
    // root, its alias, and the four keys.
    let miss = traversal.at("/nowhere", root).expect_err("misses");
    assert_eq!(
        format!("{:?}", miss),
        "NotFound { pointer: \"/nowhere\", current: \"\", traversal: <6 nodes> }"
    );

    // The segment a pointer carries reads back as the key it names.
    assert_eq!(unescape_pointer_segment("A~1B"), "A/B");
    assert_eq!(unescape_pointer_segment("t~01u"), "t~1u");
    assert_eq!(unescape_pointer_segment("a~0b~1c"), "a~b/c");
    assert_eq!(unescape_pointer_segment("plain"), "plain");
    assert!(
        matches!(unescape_pointer_segment("plain"), Cow::Borrowed("plain")),
        "a segment with nothing to unescape is borrowed"
    );
    assert_eq!(
        unescape_pointer_segment("odd~x~"),
        "odd~x~",
        "a `~` not followed by 0 or 1 is left as written"
    );

    Ok(())
}

/// A relative pointer from `root()` extends the root's own pointer, not the alias it was found under.
///
/// The alias node under `/` carried `/` as its pointer, so `at("0/Resources", root)` built
/// `//Resources` and missed, while the same lookup from the node under `""` resolved. Both entries
/// are the document; they now carry the same pointer.
#[test]
fn a_relative_pointer_from_the_root_alias_resolves() -> crate::rules::Result<()> {
    let value = PathAwareValue::try_from(crate::rules::values::read_from(
        "Resources:\n  R:\n    Type: AWS::X::Y\n",
    )?)?;
    let traversal = Traversal::from(&value);
    let root = traversal.root().unwrap();
    let resources = value_at(&traversal, "0/Resources", root);
    assert!(matches!(resources.value(), PathAwareValue::Map(_)));
    assert_eq!(resources.parent(), Some(""));
    assert_eq!(
        string_at(&traversal, "0/Resources/R/Type", root),
        "AWS::X::Y"
    );
    assert!(
        matches!(
            traversal.at("1/Resources", root),
            Err(TraversalError::BeyondRoot { .. })
        ),
        "the root has no parent to climb to"
    );
    Ok(())
}

/// A finding's path resolves to the pointer of the node it came from.
///
/// The reporters file findings by the value's path string, which two nodes can share. Given the path
/// -- string and source position -- the index names the node's pointer, so the two file apart. For a
/// document without an escaped key the pointer is the path string and the lookup is one `get`.
#[test]
fn a_path_resolves_to_the_pointer_of_its_node() -> crate::rules::Result<()> {
    let doc = "Resources:\n  \"A/B\":\n    Type: Flat::Resource\n  A:\n    Type: Outer::Resource\n    B:\n      Type: Nested::Child\n  Plain:\n    Type: AWS::X::Y\n";
    let value = PathAwareValue::try_from(crate::rules::values::read_from(doc)?)?;
    let traversal = Traversal::from(&value);
    let root = traversal.root().unwrap();

    let flat_type = value_at(&traversal, "/Resources/A~1B/Type", root).value();
    let nested_type = value_at(&traversal, "/Resources/A/B/Type", root).value();
    assert_eq!(flat_type.self_path().0, nested_type.self_path().0);
    assert_ne!(flat_type.self_path().1, nested_type.self_path().1);
    assert_eq!(
        traversal.pointer_for(flat_type.self_path()),
        Some("/Resources/A~1B/Type")
    );
    assert_eq!(
        traversal.pointer_for(nested_type.self_path()),
        Some("/Resources/A/B/Type")
    );
    // The evaluator records a clone of the value; the path is what it has, and the path suffices.
    let cloned = flat_type.clone();
    assert_eq!(
        traversal.pointer_for(cloned.self_path()),
        Some("/Resources/A~1B/Type")
    );

    // A path string no node has, such as a literal's, resolves to nothing. The root's empty path
    // resolves to the root.
    assert_eq!(
        traversal.pointer_for(&Path::try_from("/Resources/Missing").unwrap()),
        None
    );
    assert_eq!(traversal.pointer_for(&Path::root()), Some(""));

    // A position no node has (merged input parameters carry none) falls back to the first node with
    // the path string, in pointer order.
    let unplaced = Path::new("/Resources/A/B/Type".to_string(), 0, 0);
    assert_eq!(
        traversal.pointer_for(&unplaced),
        Some("/Resources/A/B/Type")
    );

    // Without an escaped key anywhere the pointer is the path string.
    let plain_value = PathAwareValue::try_from(crate::rules::values::read_from(
        "Resources:\n  Plain:\n    Type: AWS::X::Y\n",
    )?)?;
    let plain = Traversal::from(&plain_value);
    let plain_root = plain.root().unwrap();
    let plain_type = value_at(&plain, "/Resources/Plain/Type", plain_root).value();
    assert_eq!(
        plain.pointer_for(plain_type.self_path()),
        Some("/Resources/Plain/Type")
    );
    Ok(())
}
