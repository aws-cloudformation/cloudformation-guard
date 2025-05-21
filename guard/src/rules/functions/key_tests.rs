use crate::rules::functions::key::key;
use crate::rules::path_value::{Path, PathAwareValue};
use crate::rules::{QueryResult, UnResolved};
use std::rc::Rc;

fn resolved(path: &str) -> QueryResult {
    let path = Path::new(path.to_string(), 0, 0);
    QueryResult::Resolved(Rc::new(PathAwareValue::String((path, "value".to_string()))))
}

fn keys(results: Vec<Option<PathAwareValue>>) -> Vec<Option<String>> {
    results
        .into_iter()
        .map(|each| match each {
            Some(PathAwareValue::String((_, key))) => Some(key),
            Some(other) => panic!("expected a string result, got {:?}", other),
            None => None,
        })
        .collect()
}

#[test]
fn returns_the_last_path_segment_of_every_value() {
    let result = key(&[
        resolved("/Resources/MyBucket"),
        resolved("/Resources/MyQueue"),
        resolved("/Resources/MyBucket/Properties/Tags/0"),
    ]);

    assert_eq!(
        keys(result),
        vec![
            Some("MyBucket".to_string()),
            Some("MyQueue".to_string()),
            Some("0".to_string()),
        ]
    );
}

#[test]
fn returns_no_results_for_empty_input() {
    assert!(key(&[]).is_empty());
}

#[test]
fn skips_values_with_no_key() {
    let root = QueryResult::Resolved(Rc::new(PathAwareValue::String((
        Path::root(),
        "value".to_string(),
    ))));

    assert_eq!(keys(key(&[root])), vec![None]);
}

#[test]
fn skips_unresolved_queries() {
    let unresolved = QueryResult::UnResolved(UnResolved {
        traversed_to: Rc::new(PathAwareValue::String((
            Path::new("/Resources/MyBucket".to_string(), 0, 0),
            "value".to_string(),
        ))),
        remaining_query: "Properties.Tags".to_string(),
        reason: None,
    });

    assert_eq!(
        keys(key(&[unresolved, resolved("/Resources/MyQueue")])),
        vec![None, Some("MyQueue".to_string())]
    );
}
