//! Conversions from a data value to another type.
//!
//! A conversion that cannot be made reports `IncompatibleError`, not `ParseError`. Nothing here parses:
//! the rules file is already parsed and valid, and what failed is a *value in the input* not supporting
//! the operation asked of it. `ParseError` made the CLI print "Parser Error when parsing ..." and exit
//! 255, so a template with one unconvertible field looked like a malformed rules file and took every
//! other rule's verdict down with it -- `parse_int` on a non-numeric string discarded an unrelated
//! rule's real violation and reported an internal error instead.
//!
//! `IncompatibleError` is the classification the evaluator already understands: `is_unevaluatable`
//! recognises it, so the clause fails closed where it is an assertion, the rest of the file still
//! reports, and the run exits 19 as a policy failure rather than 255 as a tool failure.
//!
//! `docs/FUNCTIONS.md` says these functions error on input they cannot convert, and they still do. What
//! changed is the blast radius and the label.

use crate::rules::{path_value::PathAwareValue, QueryResult};

pub(crate) fn parse_float(
    args: &[QueryResult],
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = vec![];
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => match &**val {
                PathAwareValue::String((path, val)) => {
                    // A literal too large to represent is refused, not turned into infinity.
                    //
                    // `parse::<f64>()` answers `Ok(inf)` for an overflowing literal rather than `Err`, so
                    // "1e400" and "9e999" both became `inf` and compared equal -- a rule asserting the two
                    // are the same number was satisfied. Same defect as the saturating cast in
                    // `parse_int` below, and the same damaging direction.
                    //
                    // "NaN" and "inf" written out in the data are refused by the same check. Their verdict
                    // does not move: a NaN already failed every comparison it reached, reported as
                    // `[Float values are not comparable]`. What changes is that the diagnostic names the
                    // property instead of surfacing further down as a comparison that could not be made.
                    // A value that cannot take part in a comparison is not a float a rule can use.
                    let number = match val.parse::<f64>() {
                        Ok(f) if f.is_finite() => Some(PathAwareValue::Float((path.clone(), f))),
                        Ok(_) => {
                            return Err(crate::Error::IncompatibleError(format!(
                                "failed to convert a string: {val} into a float at {path}, \
                                 it is not a finite number"
                            )))
                        }
                        Err(_) => {
                            return Err(crate::Error::IncompatibleError(format!(
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
                        val.to_digit(10)
                            .ok_or(crate::Error::IncompatibleError(format!(
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
                            return Err(crate::Error::IncompatibleError(format!(
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
                        val.to_digit(10)
                            .ok_or(crate::Error::IncompatibleError(format!(
                                "failed to convert a character: {val} into an integer at {path}"
                            )))
                    }?
                        as i64))))
                }
                PathAwareValue::Float((path, val)) => {
                    // A float that does not fit is refused, not clamped to the nearest end.
                    //
                    // `*val as i64` saturates, and nothing said it had: 1.0e30 and 1.0e40 differ by ten
                    // orders of magnitude and both answered 9223372036854775807, so a rule asserting the
                    // two are equal passed at exit 0. NaN cast to 0, a number the input never denoted.
                    //
                    // Truncation toward zero stays -- `docs/FUNCTIONS.md:362` promises it. What that
                    // document does not promise is that a value too large to represent becomes i64::MAX;
                    // it says the conversion errors on input it cannot convert, and this is that.
                    //
                    // The bounds are not symmetric. -2^63 is exactly representable as an f64, so the low
                    // end is inclusive. i64::MAX is 2^63 - 1, which is *not* representable, so
                    // `i64::MAX as f64` rounds up to 2^63 and the high end has to be exclusive -- with
                    // `>` instead of `>=` the value 2^63 would pass the check and then saturate anyway.
                    let truncated = val.trunc();
                    if !truncated.is_finite()
                        || truncated < i64::MIN as f64
                        || truncated >= i64::MAX as f64
                    {
                        return Err(crate::Error::IncompatibleError(format!(
                            "failed to convert a float: {val} into an integer at {path}, \
                             it does not fit"
                        )));
                    }

                    aggr.push(Some(PathAwareValue::Int((path.clone(), truncated as i64))))
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
                        return Err(crate::Error::IncompatibleError(format!(
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
                        return Err(crate::Error::IncompatibleError(format!(
                            "failed to convert an int: {val} into a char at {path}"
                        )));
                    }

                    let c = char::from_digit(*val as u32, 10).ok_or(
                        crate::Error::IncompatibleError(format!(
                            "failed to convert an int: {val} into a char at {path}"
                        )),
                    )?;

                    aggr.push(Some(PathAwareValue::Char((path.clone(), c))));
                }

                PathAwareValue::String((path, val)) => {
                    if val.len() > 1 {
                        return Err(crate::Error::IncompatibleError(format!(
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
