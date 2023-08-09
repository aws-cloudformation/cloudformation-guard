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
                                "failed to convert a string: {val} into a float at {path}"
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
                PathAwareValue::Char((path, val)) => {
                    aggr.push(Some(PathAwareValue::Float((path.clone(), {
                        let path = path;
                        val.to_digit(10).ok_or(crate::Error::ParseError(format!(
                            "failed to convert a character: {val} into a float at {path}"
                        )))
                    }?
                        as f64))))
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
                                "failed to convert a string: {val} into an integer at {path}"
                            )))
                        }
                    };

                    aggr.push(number)
                }
                PathAwareValue::Int((path, val)) => {
                    aggr.push(Some(PathAwareValue::Int((path.clone(), *val))))
                }
                PathAwareValue::Char((path, val)) => {
                    aggr.push(Some(PathAwareValue::Int((path.clone(), {
                        let path = path;
                        val.to_digit(10).ok_or(crate::Error::ParseError(format!(
                            "failed to convert a character: {val} into an integer at {path}"
                        )))
                    }?
                        as i64))))
                }
                PathAwareValue::Float((path, val)) => {
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

pub(crate) fn parse_bool(
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
                            "failed to convert a string: {val} into a boolean at {path}"
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

pub(crate) fn parse_str(args: &[QueryResult]) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
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
                PathAwareValue::Char((path, val)) => aggr.push(Some(PathAwareValue::String((
                    path.clone(),
                    val.to_string(),
                )))),
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

pub(crate) fn parse_char(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = vec![];
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::Int((path, val)) => {
                    if *val < 0 || *val > 9 {
                        return Err(crate::Error::ParseError(format!(
                            "failed to convert an int: {val} into a char at {path}"
                        )));
                    }

                    let c = char::from_digit(*val as u32, 10).ok_or(crate::Error::ParseError(
                        format!("failed to convert an int: {val} into a char at {path}"),
                    ))?;

                    aggr.push(Some(PathAwareValue::Char((path.clone(), c))));
                }

                PathAwareValue::String((path, val)) => {
                    if val.len() > 1 {
                        return Err(crate::Error::ParseError(format!(
                            "failed to convert an string: {val} into a char at {path}"
                        )));
                    }
                    match val.chars().next() {
                        Some(c) => aggr.push(Some(PathAwareValue::Char((path.clone(), c)))),
                        None => aggr.push(None),
                    }
                }
                PathAwareValue::Char((path, val)) => aggr.push(Some(PathAwareValue::String((
                    path.clone(),
                    val.to_string(),
                )))),
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
