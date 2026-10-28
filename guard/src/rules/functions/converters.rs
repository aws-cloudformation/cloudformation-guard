//! Conversions from a data value to another type.
//!
//! A conversion that cannot be made reports an error classified by where the input came from, never
//! `ParseError`. Nothing here parses: the rules file is already parsed and valid. `ParseError` made the
//! CLI print "Parser Error when parsing ..." and exit 255, so a template with one unconvertible field
//! looked like a malformed rules file and took every other rule's verdict down with it -- `parse_int`
//! on a non-numeric string discarded an unrelated rule's real violation and reported an internal error
//! instead.
//!
//! `Error::unanswerable` picks the variant. A value the template supplied (`QueryResult::Resolved`) is
//! `Unevaluatable`, which `is_unevaluatable` recognizes: the clause fails closed where it is an
//! assertion, the rest of the file still reports, and the run exits 19 as a policy failure rather than
//! 255 as a tool failure. A value written in the rules file (`QueryResult::Literal`, as in
//! `parse_int("abc")`) can never convert, so that is the author's mistake: `IncompatibleError`, which
//! stops the run.
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
                            return Err(crate::Error::unanswerable(
                                entry,
                                format!(
                                    "failed to convert a string: {val} into a float at {path}, \
                                     it is not a finite number"
                                ),
                            ))
                        }
                        Err(_) => {
                            return Err(crate::Error::unanswerable(
                                entry,
                                format!("failed to convert a string: {val} into a float at {path}"),
                            ))
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
                        val.to_digit(10).ok_or(crate::Error::unanswerable(
                            entry,
                            format!("failed to convert a character: {val} into a float at {path}"),
                        ))
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
                            return Err(crate::Error::unanswerable(
                                entry,
                                format!(
                                    "failed to convert a string: {val} into an integer at {path}"
                                ),
                            ))
                        }
                    };

                    aggr.push(number)
                }
                PathAwareValue::Int((path, val)) => {
                    aggr.push(Some(PathAwareValue::Int((path.clone(), *val))))
                }
                PathAwareValue::Char((path, val)) => {
                    aggr.push(Some(PathAwareValue::Int((path.clone(), {
                        val.to_digit(10).ok_or(crate::Error::unanswerable(
                            entry,
                            format!(
                                "failed to convert a character: {val} into an integer at {path}"
                            ),
                        ))
                    }?
                        as i64))))
                }
                PathAwareValue::Float((path, val)) => {
                    // A float that does not fit is refused, not clamped to the nearest end.
                    //
                    // `*val as i64` saturates and says nothing about it: without this check 1.0e30 and
                    // 1.0e40, ten orders of magnitude apart, both answer 9223372036854775807, so a rule
                    // asserting the two are equal passes at exit 0, and NaN casts to 0, a number the
                    // input never denoted.
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
                        return Err(crate::Error::unanswerable(
                            entry,
                            format!(
                                "failed to convert a float: {val} into an integer at {path}, \
                                 it does not fit"
                            ),
                        ));
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
                        return Err(crate::Error::unanswerable(
                            entry,
                            format!("failed to convert a string: {val} into a boolean at {path}"),
                        ))
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

/// The canonical text of a float: the shortest digits that read back as the same value, keeping the
/// decimal point when the value is integral.
///
/// This is the one rendering of a float as text in the crate. `parse_string` uses it for the value it
/// hands a rule; `libyaml::loader::stringify_scalar_key` and `values::scalar_key_name` use it for the
/// name a float mapping key stands for, so `Mappings: { 1.0: x }` is reachable as `Mappings."1.0"`
/// from either loader and `parse_string(1.0) == "1.0"` names the same key.
///
/// `f64::to_string()` is `Display`, and `Display` drops a zero fractional part: `2.0_f64.to_string()`
/// is `"2"`. So a template field `Version: 2.0` converted to `"2"`, a rule written against the
/// template's own spelling (`parse_string(%v) == "2.0"`) failed at exit 19 while `== "2"` passed, and
/// the Int `2` and the Float `2.0` were the same string after conversion.
///
/// An integral value is rendered as its `Display` text with `.0` appended; anything else keeps the
/// `Display` text alone, so `1.5`, `0.1` and `0.0000001` are unchanged and a fractional value is never
/// rounded. `Display` for `f64` never uses an exponent, so the appended point always follows digits.
///
/// Appending to `Display` rather than formatting with `{:.1}`, because a fixed precision prints the
/// exact binary expansion while `Display` prints the shortest digits that read back as the same
/// float. Above about 2^53 the two differ: `1e23` is `100000000000000000000000` under `Display` and
/// `99999999999999991611392.0` under `{:.1}`, and the template author wrote the former. The two key
/// renderers used `{:.1}` and had this divergence too. `Debug` is not used either, because it switches
/// to an exponent for large magnitudes (`1e20`) and `Display` does not, and the two must agree on
/// which digits a reader sees.
///
/// Non-finite values are rendered as `Display` spells them (`NaN`, `inf`, `-inf`). A key renderer that
/// wants YAML's `.nan` / `.inf` spelling decides that before calling this.
pub(crate) fn float_to_string(val: f64) -> String {
    if val.is_finite() && val.fract() == 0.0 {
        format!("{val}.0")
    } else {
        val.to_string()
    }
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
                    float_to_string(*val),
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
                        return Err(crate::Error::unanswerable(
                            entry,
                            format!("failed to convert an int: {val} into a char at {path}"),
                        ));
                    }

                    let c = char::from_digit(*val as u32, 10).ok_or(crate::Error::unanswerable(
                        entry,
                        format!("failed to convert an int: {val} into a char at {path}"),
                    ))?;

                    aggr.push(Some(PathAwareValue::Char((path.clone(), c))));
                }

                PathAwareValue::String((path, val)) => {
                    // Characters, not bytes.
                    //
                    // This was `val.len() > 1`, and `String::len()` counts bytes, so a single character
                    // that is not ASCII was refused as too long: "é" is one character and two bytes, an
                    // emoji is one and four. The line below already reads the value with
                    // `val.chars().next()`, so the extraction was by character and only the guard was
                    // not. `strings.rs` carries a comment about fixing this same confusion in
                    // `substring`; it was applied there and not here.
                    //
                    // Unicode scalar values, which is what `chars()` yields and what `substring` indexes
                    // by. An `e` followed by a combining accent is two of those and is still refused,
                    // even though it draws as one glyph -- the two functions agreeing matters more than
                    // which of the two readings is chosen.
                    //
                    // The count goes in the message. The old one reported a failed conversion, which read
                    // as though the character were at fault rather than the length.
                    let length = val.chars().count();
                    if length > 1 {
                        return Err(crate::Error::unanswerable(
                            entry,
                            format!(
                                "failed to convert a string: {val} into a char at {path}, \
                                 it is {length} characters long"
                            ),
                        ));
                    }
                    match val.chars().next() {
                        Some(c) => aggr.push(Some(PathAwareValue::Char((path.clone(), c)))),
                        None => aggr.push(None),
                    }
                }
                // A Char in, the same Char out.
                //
                // This pushed a `String`. The body was character-for-character `parse_str`'s Char arm,
                // which is where it was copied from, and every other arm here pushes a `Char` -- so the
                // function's output type depended on its input type, which is the one thing a converter
                // must not do. `parse_char(parse_char(x))` was a String where `parse_char(x)` was a Char,
                // and a comparison against a string literal passed on the nested form where the single
                // call could not match.
                //
                // The arm was unexecuted by the suite, which is how it survived. `test_parse_char` looks
                // like it covers it -- it queries a field declared `Char: '1'` -- but that test asserts
                // the queried value is a String, because that is what the YAML `'1'` loads as, so the
                // call goes down the String arm above.
                PathAwareValue::Char((path, val)) => {
                    aggr.push(Some(PathAwareValue::Char((path.clone(), *val))))
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
