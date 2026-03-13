#[cfg(test)]
use crate::rules::functions::key;
use crate::rules::path_value::{Path, PathAwareValue};
use crate::rules::QueryResult;
use std::rc::Rc;

#[test]
fn test_key_function_returns_last_segment() {
    let path = Path::new("/Resources/MyBucket".to_string(), 0, 0);
    let value = PathAwareValue::String((path.clone(), "test-value".to_string()));
    let result = key::key(&[QueryResult::Resolved(Rc::new(value))]);
    if let PathAwareValue::String((_, key_str)) = result {
        assert_eq!(key_str, "MyBucket");
    } else {
        panic!("Expected String result");
    }
}

#[test]
fn test_key_function_empty_args() {
    let result = key::key(&[]);
    if let PathAwareValue::String((_, key_str)) = result {
        assert_eq!(key_str, "");
    } else {
        panic!("Expected String result");
    }
}
