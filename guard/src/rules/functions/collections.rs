use crate::rules::{
    path_value::{Path, PathAwareValue},
    QueryResult,
};

pub(crate) fn count(args: &[QueryResult]) -> PathAwareValue {
    let count = args.iter().fold(0, |each, entry| match entry {
        QueryResult::Literal(_) | QueryResult::Resolved(_) => each + 1,
        _ => each,
    });

    let count2 = args
        .iter()
        .filter(|query| !matches!(query, QueryResult::UnResolved(_)))
        .count();

    assert_eq!(count, count2);

    match count {
        0 => PathAwareValue::Int((Path::root(), 0)),
        count => {
            let path = match &args[0] {
                QueryResult::Literal(val) | QueryResult::Resolved(val) => val.self_path().clone(),
                _ => unreachable!(),
            };

            PathAwareValue::Int((path, count as i64))
        }
    }
}

#[cfg(test)]
#[path = "collections_tests.rs"]
mod collections_tests;
