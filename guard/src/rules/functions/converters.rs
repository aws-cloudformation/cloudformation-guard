use crate::rules::{path_value::PathAwareValue, QueryResult};

pub(crate) fn parse_float(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = vec![];
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::String((path, val)) => {
                    let number = match val.parse::<f64>() {
                        Ok(f) => Some(PathAwareValue::Float((path.clone(), f))),
                        Err(_) => {
                            return Err(crate::Error::ParseError(format!(
                                "attempting to convert a string: {val} into a number at {path}"
                            )))
                        }
                    };

                    aggr.push(number)
                }
                PathAwareValue::Int((path, val)) => {
                    aggr.push(Some(PathAwareValue::Float((path.clone(), *val as f64))))
                }
                PathAwareValue::Float((path, val)) => {
                    aggr.push(Some(PathAwareValue::Float((path.clone(), *val))))
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

pub(crate) fn parse_int(args: &[QueryResult]) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = vec![];
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::String((path, val)) => {
                    let number = match val.parse::<i64>() {
                        Ok(i) => Some(PathAwareValue::Int((path.clone(), i))),
                        Err(_) => {
                            return Err(crate::Error::ParseError(format!(
                                "attempting to convert a string: {val} into a number at {path}"
                            )))
                        }
                    };

                    aggr.push(number)
                }
                PathAwareValue::Int((path, val)) => {
                    aggr.push(Some(PathAwareValue::Int((path.clone(), *val))))
                }
                PathAwareValue::Float((path, val)) => {
                    aggr.push(Some(PathAwareValue::Int((path.clone(), *val as i64))))
                }
                PathAwareValue::Bool((path, val)) => {
                    aggr.push(Some(PathAwareValue::Int((path.clone(), *val as i64))))
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

pub(crate) fn parse_boolean(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = vec![];
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::Bool((path, val)) => {
                    aggr.push(Some(PathAwareValue::Bool((path.clone(), *val))))
                }
                PathAwareValue::String((path, val)) => match val.to_lowercase().as_str() {
                    "true" => aggr.push(Some(PathAwareValue::Bool((path.clone(), true)))),
                    "false" => aggr.push(Some(PathAwareValue::Bool((path.clone(), false)))),
                    _ => {
                        return Err(crate::Error::ParseError(format!(
                            "attempting to convert a string: {val} into a boolean at {path}"
                        )))
                    }
                },
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

pub(crate) fn parse_string(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = vec![];
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::Int((path, val)) => aggr.push(Some(PathAwareValue::String((
                    path.clone(),
                    val.to_string(),
                )))),
                PathAwareValue::Float((path, val)) => aggr.push(Some(PathAwareValue::String((
                    path.clone(),
                    val.to_string(),
                )))),
                PathAwareValue::Bool((path, val)) => aggr.push(Some(PathAwareValue::String((
                    path.clone(),
                    val.to_string(),
                )))),
                PathAwareValue::String((path, val)) => {
                    aggr.push(Some(PathAwareValue::String((path.clone(), val.clone()))))
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

#[cfg(test)]
#[path = "converters_tests.rs"]
mod converters_test;
