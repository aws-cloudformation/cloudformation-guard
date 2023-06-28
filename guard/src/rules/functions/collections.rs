use crate::rules::{
    path_value::{Path, PathAwareValue},
    QueryResult,
};

pub(crate) fn count(args: &[QueryResult]) -> PathAwareValue {
    let count = args
        .iter()
        .filter(|query| !matches!(query, QueryResult::UnResolved(_)))
        .count();

    dbg!(&args);
    match args.is_empty() {
        true => PathAwareValue::Int((Path::root(), 0)),
        false => {
            let path = match &args[0] {
                QueryResult::Literal(val) | QueryResult::Resolved(val) => val.self_path().clone(),
                QueryResult::UnResolved(val) => val.traversed_to.self_path().clone(),
            };

            PathAwareValue::Int((path, count as i64))
        }
    }
}

#[cfg(test)]
#[path = "collections_tests.rs"]
mod collections_tests;
