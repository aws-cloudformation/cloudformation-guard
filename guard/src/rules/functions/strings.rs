use crate::rules::path_value::{Path, PathAwareValue};
use crate::rules::QueryResult;

use crate::rules::errors::Error;
use fancy_regex::Regex;
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
                    // A string the parser refuses is `IncompatibleError`, and it names the property.
                    //
                    // Both errors here describe a value in the *template*, and both propagated
                    // unchanged: the parse error as `YamlError`, the conversion as `InternalError`.
                    // Neither class is recognised by `is_unevaluatable`, so a duplicate key in one
                    // embedded string aborted the evaluation with "bailing" and the run exited 255 --
                    // while a security group open to 0.0.0.0/0 in the same file was reported and
                    // counted. Only the exit code was wrong, and that is the code a CI wrapper reads to
                    // tell "block the deploy" from "the tool broke, retry it".
                    //
                    // A duplicate key is the ordinary case for this. RFC 8259 leaves duplicate names to
                    // the implementation and most JSON readers keep the last one, so a template can
                    // carry a policy that every other tool in the pipeline accepts.
                    //
                    // Neither message named the property, so an author with several embedded strings had
                    // to guess which was at fault. The conversion error was worse: its own path is the
                    // one inside the parsed value, which is empty at the root, and it printed
                    // "for key in a map at ,".
                    let value = serde_yaml::from_str::<serde_yaml::Value>(val).map_err(|e| {
                        crate::Error::IncompatibleError(format!(
                            "failed to parse the string at {path} as JSON: {e}"
                        ))
                    })?;
                    let parsed = PathAwareValue::try_from((&value, path.clone())).map_err(|e| {
                        crate::Error::IncompatibleError(format!(
                            "failed to convert the parsed string at {path}: {e}"
                        ))
                    })?;
                    aggr.push(Some(parsed));
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
                    let regex = Regex::try_from(extract_expr).map_err(Box::new)?;
                    // The whole string, not just the captures.
                    //
                    // This expanded each capture into a fresh empty `String` and returned that, so
                    // every character the pattern did not match was dropped:
                    // `regex_replace("prod-database-01", "database", "db")` answered `"db"` where a
                    // replace gives `"prod-db-01"`, and a pattern matching several times returned the
                    // expansions run together with the gaps between them gone. No fixture caught it
                    // because all of them, and the example in `docs/FUNCTIONS.md`, anchor the pattern
                    // with `^...$` so the match covers the whole string and there is no outside text.
                    //
                    // A pattern that did not match returned `""`, which is the same bug seen from the
                    // other side and the damaging one: `""` is a value, so it compares. A rule that
                    // stripped an optional prefix before testing a name passed on a name it was
                    // written to catch, silently and at exit 0. Copying the unmatched remainder
                    // answers both -- with nothing matched the remainder is the whole input, which is
                    // what a replace returns.
                    //
                    // `try_replacen` rather than `replace_all`: `replace_all` delegates to `replacen`,
                    // which is `try_replacen(..).unwrap()`, so a match that fails at run time -- a
                    // backtrack limit, which `fancy_regex` can hit and the plain `regex` crate cannot
                    // -- would panic and exit 101 instead of reporting. A limit of 0 means no limit,
                    // and `&str` as the replacement expands through `Captures::expand`, so `${1}` and
                    // the rest of the substitution syntax read exactly as they did before.
                    let replaced = regex
                        .try_replacen(val, 0, replace_expr)
                        .map_err(Box::new)?
                        .into_owned();
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
                    // Character indices, not byte indices.
                    //
                    // The bounds were checked against `val.len()`, which counts bytes, and the slice
                    // that followed panics unless both ends land on a character boundary. So
                    // `substring(x, 0, 3)` on `naïve` aborted the process: byte 3 is inside the two
                    // bytes of `ï`. Not a clean error -- a Rust panic and exit 101, with a stack
                    // trace instead of a diagnostic, which in CI reads as the tool breaking rather
                    // than the policy failing.
                    //
                    // Characters rather than a boundary check that returns nothing, because
                    // `docs/FUNCTIONS.md` calls these a "starting index" and an "ending index" into a
                    // string, and a rule author counting a prefix counts characters. For ASCII -- the
                    // ARNs and resource names these are written against, including the example in
                    // that document -- the two readings are identical, so this changes no working
                    // rule. It replaces a crash on the rules that are not ASCII.
                    let length = val.chars().count();
                    if !val.is_empty() && from < to && from <= length && to <= length {
                        let sub: String = val.chars().skip(from).take(to - from).collect();
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
                    "Joining unresolved values is not allowed {}, unsatisfied part {}",
                    ur.traversed_to, ur.remaining_query
                )));
            }
        }
    }

    match args.is_empty() {
        true => Ok(PathAwareValue::String((Path::root(), aggr))),
        false => {
            let path = match &args[0] {
                QueryResult::Literal(val) | QueryResult::Resolved(val) => val.self_path().clone(),
                QueryResult::UnResolved(val) => val.traversed_to.self_path().clone(),
            };
            Ok(PathAwareValue::String((path, aggr)))
        }
    }
}

#[cfg(test)]
#[path = "strings_tests.rs"]
mod strings_tests;
