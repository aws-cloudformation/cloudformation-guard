use crate::rules::path_value::{Path, PathAwareValue};
use crate::rules::QueryResult;

use crate::rules::errors::Error;
use fancy_regex::Regex;
use nom::Slice;
use std::convert::TryFrom;

pub(crate) fn url_decode(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::String((path, val)) => {
                    if let Ok(aggr_str) = urlencoding::decode(val.as_str()) {
                        aggr.push(Some(PathAwareValue::String((
                            path.clone(),
                            aggr_str.into_owned(),
                        ))));
                    } else {
                        aggr.push(None);
                    }
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

pub(crate) fn json_parse(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = &**v {
                    let value = serde_yaml::from_str::<serde_yaml::Value>(val)?;
                    aggr.push(Some(PathAwareValue::try_from((&value, path.clone()))?));
                } else {
                    aggr.push(None);
                }
            }
            _ => aggr.push(None),
        }
    }
    Ok(aggr)
}

pub(crate) fn regex_replace(
    args: &[QueryResult],
    extract_expr: &str,
    replace_expr: &str,
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = &**v {
                    let regex = Regex::new(extract_expr)?;
                    let mut replaced = String::with_capacity(replace_expr.len() * 2);
                    for cap in regex.captures_iter(val) {
                        cap?.expand(replace_expr, &mut replaced);
                    }
                    aggr.push(Some(PathAwareValue::String((path.clone(), replaced))));
                } else {
                    aggr.push(None);
                }
            }
            _ => {
                aggr.push(None);
            }
        }
    }
    Ok(aggr)
}

pub(crate) fn substring(
    args: &[QueryResult],
    from: usize,
    to: usize,
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = &**v {
                    if !val.is_empty() && from < to && from <= val.len() && to <= val.len() {
                        let sub = val.as_str().slice(from..to).to_string();
                        aggr.push(Some(PathAwareValue::String((path.clone(), sub))));
                    } else {
                        aggr.push(None);
                    }
                } else {
                    aggr.push(None);
                }
            }
            _ => {
                aggr.push(None);
            }
        }
    }
    Ok(aggr)
}

pub(crate) fn to_upper(args: &[QueryResult]) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = &**v {
                    aggr.push(Some(PathAwareValue::String((
                        path.clone(),
                        val.to_uppercase(),
                    ))));
                } else {
                    aggr.push(None);
                }
            }
            _ => {
                aggr.push(None);
            }
        }
    }
    Ok(aggr)
}

pub(crate) fn to_lower(args: &[QueryResult]) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = &**v {
                    aggr.push(Some(PathAwareValue::String((
                        path.clone(),
                        val.to_lowercase(),
                    ))));
                } else {
                    aggr.push(None);
                }
            }
            _ => {
                aggr.push(None);
            }
        }
    }
    Ok(aggr)
}

pub(crate) fn join(args: &[QueryResult], delimiter: &str) -> crate::rules::Result<PathAwareValue> {
    let mut aggr = String::with_capacity(512);
    let total = args.len();

    for (index, entry) in args.iter().enumerate() {
        match entry {
            QueryResult::Resolved(v) | QueryResult::Literal(v) => {
                if let PathAwareValue::String((_, val)) = &**v {
                    aggr.push_str(val);

                    if total - 1 > index {
                        aggr.push_str(delimiter);
                    }
                } else {
                    return Err(Error::IncompatibleError(format!(
                        "Joining non string values {}",
                        v
                    )));
                }
            }
            QueryResult::UnResolved(ur) => {
                return Err(Error::IncompatibleError(format!(
                    "Joining non unresolved values is not allowed {}, unsatisfied part {}",
                    ur.traversed_to, ur.remaining_query
                )));
            }
        }
    }
    Ok(PathAwareValue::String((Path::root(), aggr)))
}

#[cfg(test)]
#[path = "strings_tests.rs"]
mod strings_tests;
