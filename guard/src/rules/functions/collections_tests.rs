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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
    };
    let query = AccessQuery::try_from(r#"Resources"#)?;
    let results = eval.query(&query.query)?;

    // The root document is `{}`, so `Resources` is absent. The map the query searched happens to be
    // empty, but the query stopped at a key it did not find, not at an expansion that ran out of
    // members, so there is no collection to count and the answer is nothing. Reading the empty struct
    // it searched as the collection it was looking for would answer 0;
    // `count_does_not_invent_a_value_for_an_unresolved_selection` has the general case.
    assert!(
        count(&results).is_none(),
        "a key absent from an empty struct is still an absent key"
    );

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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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

/// `count` places its answer at the path its members share, not at the first member.
///
/// The result took `args[0]`'s path, so `count(%buckets) == 3` over two buckets failed "at"
/// `/Resources/BucketA`: the report named BucketA as the non-compliant resource for a number that
/// describes both buckets, and the same template with the resources in the other order named
/// BucketB. A reader fixing what the report points at fixes the wrong thing.
///
/// The answer now sits at the longest common prefix of the members' paths: the collection for a
/// wildcard over one list, `/Resources` for an aggregate over several resources, and the member's own
/// path when there is one member.
///
/// The location goes with the path. When the shared path is a member's own path -- one member, or an
/// empty collection a wildcard reached -- the answer carries that member's location. When the shared
/// path is the members' immediate parent, the collection they were enumerated from, the answer carries
/// the first member's location: that member sits inside the collection the finding is about, so a code
/// excerpt opened there shows the members. When the shared prefix is further up than that, the
/// location is the neutral `L:0,C:0`: nothing the members know points at such a prefix, and the first
/// member's position would point a reader at one branch of a number that describes several.
///
/// Loaded through the libyaml loader, because the serde-backed one records no positions and every
/// location would be the neutral one, so the cells about location would measure nothing.
#[test]
fn count_sits_at_the_path_its_members_share() -> crate::rules::Result<()> {
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
    Empty: []
"#;

    /// Where the answer's location comes from.
    enum At {
        /// The neutral location: the shared prefix is further up than the members' parent.
        Neutral,
        /// The location of the one member whose own path the answer sits at.
        TheMember,
        /// The first member's location: the shared path is the members' immediate parent.
        TheFirstMember,
    }

    let cases = [
        // (query, expected count, expected path, expected location)
        // The defect: two resources, one answer, placed at neither of them. `/Resources` is the
        // buckets' immediate parent, so the position is the first bucket's.
        (
            r#"Resources.*[ Type == 'AWS::S3::Bucket' ]"#,
            2,
            "/Resources",
            At::TheFirstMember,
        ),
        // The same two buckets, but the members are three levels below the shared prefix, so no
        // member's position describes it.
        (
            r#"Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName"#,
            2,
            "/Resources",
            At::Neutral,
        ),
        // A wildcard over one list sits at the list, not at its first element, with the first
        // element's position: the list is the members' parent, and the excerpt opens inside it.
        (
            r#"Resources.Svc.Collection.*"#,
            3,
            "/Resources/Svc/Collection",
            At::TheFirstMember,
        ),
        // An empty collection already sat at the collection; that stays, and the collection is the
        // one member, so its position comes along.
        (
            r#"Resources.Svc.Empty.*"#,
            0,
            "/Resources/Svc/Empty",
            At::TheMember,
        ),
        // One member: its own path and position.
        (
            r#"Resources.Svc.Collection[0]"#,
            1,
            "/Resources/Svc/Collection/0",
            At::TheMember,
        ),
    ];

    for (query, expected_count, expected_path, at) in cases {
        let value = PathAwareValue::try_from(crate::rules::values::read_from(document)?)?;
        let mut eval = BasicQueryTesting {
            root: Rc::new(value),
            recorder: None,
            refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
        };
        let results = eval.query(&AccessQuery::try_from(query)?.query)?;

        let path = match count(&results) {
            Some(PathAwareValue::Int((path, got))) => {
                assert_eq!(got, expected_count, "count({query})");
                assert_eq!(path.0, expected_path, "where count({query}) is placed");
                path
            }
            other => panic!("count({}) gave {:?}, expected a count", query, other),
        };

        match at {
            At::Neutral => assert_eq!(
                path.1,
                Location::default(),
                "count({query}) sits at a prefix further up than its members' parent, so its location is neutral"
            ),
            At::TheFirstMember => {
                let first = match &results[0] {
                    QueryResult::Literal(v) | QueryResult::Resolved(v) => v.self_path().clone(),
                    QueryResult::UnResolved(ur) => ur.traversed_to.self_path().clone(),
                };
                assert_ne!(
                    first.1,
                    Location::default(),
                    "the libyaml loader should have placed the first member of {query}"
                );
                assert_eq!(
                    path.1, first.1,
                    "count({query}) sits at its members' parent, with the first member's position"
                );
            }
            At::TheMember => {
                assert_eq!(results.len(), 1, "{query} should select one member");
                let member = match &results[0] {
                    QueryResult::Literal(v) | QueryResult::Resolved(v) => v.self_path().clone(),
                    QueryResult::UnResolved(ur) => ur.traversed_to.self_path().clone(),
                };
                assert_ne!(
                    member.1,
                    Location::default(),
                    "the libyaml loader should have placed {query}"
                );
                assert_eq!(path, member, "count({query}) sits at its one member");
            }
        }
    }

    Ok(())
}

/// When the members share no path at all, the answer falls back to the first member's path.
///
/// A segment-wise common prefix of `/Resources/A` and `/Outputs/B` is the empty string, which is the
/// root's path and would place a finding about two named values at the document. The first member's
/// path is at least a place the number was computed from. A selection that is all literals shares the
/// root legitimately and stays there.
#[test]
fn an_aggregate_over_members_sharing_nothing_sits_at_the_first_member() {
    let resources_a = PathAwareValue::String((Path::new("/Resources/A".into(), 3, 5), "a".into()));
    let outputs_b = PathAwareValue::String((Path::new("/Outputs/B".into(), 9, 5), "b".into()));
    let args = vec![
        QueryResult::Resolved(Rc::new(resources_a.clone())),
        QueryResult::Resolved(Rc::new(outputs_b)),
    ];

    match count(&args) {
        Some(PathAwareValue::Int((path, 2))) => assert_eq!(
            path,
            *resources_a.self_path(),
            "nothing is shared, so the first member's path and position are used"
        ),
        other => panic!("count over two unrelated members gave {:?}", other),
    }

    let literals = vec![
        QueryResult::Literal(Rc::new(PathAwareValue::Int((Path::root(), 1)))),
        QueryResult::Literal(Rc::new(PathAwareValue::Int((Path::root(), 2)))),
    ];
    match count(&literals) {
        Some(PathAwareValue::Int((path, 2))) => {
            assert_eq!(path, Path::root(), "literals share the root, and sit there")
        }
        other => panic!("count over two literals gave {:?}", other),
    }
}

/// `count` answers 0 for a collection that is there and holds nothing, and answers nothing for a query
/// that named something absent.
///
/// Filtering the unresolved results out and counting what is left would answer the `Int` 0 for both
/// cases -- and 0 is a value, so it compares. A one-letter typo would turn a check into a green build:
/// `count(%b.Properties.Grantz.*) == 0` would pass at exit 0 on a bucket whose correctly spelled
/// `Grants` holds a public grant, while the same rule spelled `Grants` exits 19. No other function
/// answers that way: on the same absent path `to_upper`, `parse_int`, `substring` and `json_parse` all
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
      barebucket:
        Type: AWS::S3::Bucket
        Properties: {}
    "#;

    let cases = [
        // (query, expected count, what the query is)
        // The typo. `Grantz` exists nowhere, so nothing resolves and there is no collection.
        (
            r#"Resources[ Type == 'AWS::S3::Bucket' ].Properties.Grantz.*"#,
            None,
            "a key that is absent from every selected value",
        ),
        // A key absent from a struct that is itself empty. The struct the query searched has no
        // members, but the query stopped at `Tags`, a key, not at an expansion that ran out: there is
        // no collection, and reading the empty struct as one would count 0 for a bucket with no tags
        // key at all.
        (
            r#"Resources.barebucket.Properties.Tags[*].Key"#,
            None,
            "a key absent from an empty struct",
        ),
        // The same empty struct expanded directly is a collection with no members, and counts 0.
        (
            r#"Resources.barebucket.Properties.*"#,
            Some(0),
            "an expansion over an empty struct",
        ),
        // A path that is absent higher up, which is the same thing further from the leaf.
        (
            r#"Resources.doesNotExist.Whatever.*"#,
            None,
            "a path absent from the root",
        ),
        // The control. `Grants: []` is a real list with no members, and 0 is the count of it. A count that
        // read an absent path as 0 would answer this row the same way; it is the empty-list answer that
        // has to hold.
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
            Some(4),
            "four buckets",
        ),
    ];

    for (query, expected, description) in cases {
        let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(document)?)?;
        let mut eval = BasicQueryTesting {
            root: Rc::new(value),
            recorder: None,
            refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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
