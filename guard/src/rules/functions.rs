use crate::rules::QueryResult;
use crate::rules::path_value::PathAwareValue;

use urlencoding;
use std::convert::TryFrom;

pub(crate) fn count(args: &[QueryResult<'_>]) -> u32 {
    args.iter().fold(0, |each, entry| match entry {
        QueryResult::Literal(_) |
        QueryResult::Resolved(_) => each + 1,
        _ => each
    })
}

pub(crate) fn url_decode(args: &[QueryResult<'_>]) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) |
            QueryResult::Resolved(val) => match *val {
                PathAwareValue::String((path, val)) => {
                    if let Ok(aggr_str) = urlencoding::decode(val.as_str()) {
                        aggr.push(Some(PathAwareValue::String((path.clone(), aggr_str.into_owned()))));
                    }
                    else {
                        aggr.push(None);
                    }
                }
                _ => {
                    aggr.push(None);
                }
            },
            _ => {
                aggr.push(None);
            },
        }
    }
    Ok(aggr)
}

pub(crate) fn json_parse(args: &[QueryResult<'_>]) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) |
            QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = v {
                    let value = serde_yaml::from_str::<serde_json::Value>(val)?;
                    aggr.push(
                        Some(
                            PathAwareValue::try_from((&value, path.clone()))?)
                    );
                }
                else {
                    aggr.push(None);
                }
            },
            _ => {aggr.push(None)},
        }
    }
    Ok(aggr)
}

pub(crate) fn regex_replace(args: &[QueryResult<'_>], extract_expr: &str, replace_expr: &str) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) |
            QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = v {
                    let regex = regex::Regex::new(extract_expr)?;
                    let mut replaced = replace_expr.to_string();
                    for cap in regex.captures_iter(val) {
                        cap.expand(replace_expr, &mut replaced);
                    }
                    aggr.push(Some(
                        PathAwareValue::String((path.clone(), replaced))
                    ));
                }
                else {
                    aggr.push(None);
                }
            },
            _ => {aggr.push(None);}
        }
    }
    Ok(aggr)
}

#[cfg(test)]
#[path = "functions_tests.rs"]
mod functions_tests;

