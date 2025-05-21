use crate::rules::path_value::PathAwareValue;
use crate::rules::QueryResult;

#[cfg(test)]
#[path = "key_tests.rs"]
mod key_tests;

/// Projects each value onto the name it is stored under, the last segment of its path.
///
/// One result per input value. Values with no name, such as the document root, and
/// unresolved queries produce no result.
pub(crate) fn key(args: &[QueryResult]) -> Vec<Option<PathAwareValue>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                let path = v.self_path();
                if path.0.is_empty() {
                    aggr.push(None);
                } else {
                    aggr.push(Some(PathAwareValue::String((
                        path.clone(),
                        path.relative().to_string(),
                    ))));
                }
            }
            QueryResult::UnResolved(_) => aggr.push(None),
        }
    }
    aggr
}
