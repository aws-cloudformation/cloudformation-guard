use crate::rules::path_value::{Path, PathAwareValue};
use crate::rules::QueryResult;

#[cfg(test)]
#[path = "key_tests.rs"]
mod key_tests;

pub(crate) fn key(args: &[QueryResult]) -> PathAwareValue {
    // Return the key (logical id) for the first resolved argument
    for arg in args {
        match arg {
            QueryResult::Resolved(val) | QueryResult::Literal(val) => {
                let path = val.self_path();
                // Use relative() to get the last segment/key
                let key = path.relative();
                return PathAwareValue::String((path.clone(), key.to_string()));
            }
            QueryResult::UnResolved(unresolved) => {
                let path = unresolved.traversed_to.self_path();
                let key = path.relative();
                return PathAwareValue::String((path.clone(), key.to_string()));
            }
        }
    }
    // If no key found, return empty string at root
    PathAwareValue::String((Path::root(), String::new()))
}
