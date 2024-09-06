use crate::rules::{
    path_value::{Path, PathAwareValue},
    QueryResult,
};
use chrono::prelude::*;
use chrono::Utc;

pub(crate) fn parse_epoch(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = vec![];
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::String((path, val)) => {
                    let datetime = DateTime::parse_from_rfc3339(val)
                        .map_err(|e| {
                            crate::Error::ParseError(format!(
                                "Failed to parse datetime: {val} at {path}: {e}"
                            ))
                        })?
                        .with_timezone(&Utc);
                    let epoch = datetime.timestamp();
                    aggr.push(Some(PathAwareValue::Int((path.clone(), epoch))));
                }
                _ => {
                    aggr.push(None);
                }
            },
            _ => {
                aggr.push(None);
            }
        }
    }

    Ok(aggr)
}

pub(crate) fn now() -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let now = Utc::now().timestamp();
    let path = Path::root();
    let path_aware_value = PathAwareValue::Int((path, now));
    Ok(vec![Some(path_aware_value)])
}

#[cfg(test)]
#[path = "date_time_tests.rs"]
mod date_time_tests;
