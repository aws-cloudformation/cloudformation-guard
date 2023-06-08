use crate::rules::QueryResult;

pub(crate) fn count(args: &[QueryResult]) -> u32 {
    args.iter().fold(0, |each, entry| match entry {
        QueryResult::Literal(_) | QueryResult::Resolved(_) => each + 1,
        _ => each,
    })
}

#[cfg(test)]
#[path = "collections_tests.rs"]
mod collections_tests;
