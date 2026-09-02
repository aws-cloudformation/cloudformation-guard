use crate::rules::{
    path_value::{Path, PathAwareValue},
    QueryResult,
};

/// Whether a query stopped at a collection that is there and holds nothing.
///
/// `accumulate` and `accumulate_map` in `eval_context.rs` report an unresolved result when a wildcard
/// reaches a list or map with no members, and the value they hand back is that collection. A key that
/// was not found reports one too, but hands back the struct it searched. So the shape of `traversed_to`
/// says which of the two happened, and only the first is a collection whose count is zero.
fn reached_an_empty_collection(value: &PathAwareValue) -> bool {
    match value {
        PathAwareValue::List((_, list)) => list.is_empty(),
        PathAwareValue::Map((_, map)) => map.is_empty(),
        _ => false,
    }
}

/// How many values a query selected, or nothing when the query did not resolve at all.
///
/// `count` used to drop the unresolved results and count the rest, which meant a query naming something
/// absent came back as the `Int` 0. That is a value, so it compares, and `count(%b.Properties.Grantz.*)
/// == 0` passed at exit 0 on a bucket whose correctly spelled `Grants` holds a public grant. One letter
/// stood between a check and a green build, and nothing in the output said the path was not found.
///
/// `count` was alone in this. Given the same absent path, `to_upper`, `parse_int`, `substring` and
/// `json_parse` all resolve to no values and the clause fails at exit 19, and `join` errors at 19.
///
/// Three cases have to stay apart, and they are distinguishable:
///
/// - A query that selected nothing, such as a filter matching no resource, produces no results at all.
///   Zero is the count of nothing and this is the shape most rules are written in.
/// - A wildcard over a collection with no members produces an unresolved result holding that
///   collection. The query reached it, so zero is the honest count -- `Grants: []` really has no grants.
/// - A key that was not found produces an unresolved result holding the struct that was searched. There
///   is no collection, so there is no count, and this is the one that now answers with nothing.
///
/// A selection that resolved for some values and not for others keeps counting the ones it found. A rule
/// over several buckets where only one carries `Grants` is asking how many grants exist, not whether
/// every bucket has the key, so only a selection where nothing resolved can be a missing path. Where
/// nothing resolved and the reasons are mixed -- one empty collection, one absent key -- the absent key
/// decides it and the answer is nothing, which fails the clause rather than passing it.
pub(crate) fn count(args: &[QueryResult]) -> Option<PathAwareValue> {
    if args.is_empty() {
        return Some(PathAwareValue::Int((Path::root(), 0)));
    }

    let mut resolved = 0;
    let mut absent_path = false;
    for arg in args.iter() {
        match arg {
            QueryResult::Literal(_) | QueryResult::Resolved(_) => resolved += 1,
            QueryResult::UnResolved(ur) => {
                if !reached_an_empty_collection(&ur.traversed_to) {
                    absent_path = true;
                }
            }
        }
    }

    if resolved == 0 && absent_path {
        return None;
    }

    let path = match &args[0] {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => val.self_path().clone(),
        QueryResult::UnResolved(val) => val.traversed_to.self_path().clone(),
    };

    Some(PathAwareValue::Int((path, resolved as i64)))
}

#[cfg(test)]
#[path = "collections_tests.rs"]
mod collections_tests;
