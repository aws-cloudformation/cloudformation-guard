use crate::rules::path_value::PathAwareValue;
use crate::rules::QueryResult;

use super::collections::{common_path, stopped_at_an_empty_collection};
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
                    // A string the parser refuses is answered by provenance like every other
                    // conversion (`Error::unanswerable`): from the template, a fact about the data the
                    // clause fails closed on; written in the rules file, the author's mistake, which
                    // stops the run. Either way it names the property.
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
                        crate::Error::unanswerable(
                            entry,
                            format!("failed to parse the string at {path} as JSON: {e}"),
                        )
                    })?;
                    // `Value::try_from_json`, not the plain `TryFrom<&serde_yaml::Value>`, because the
                    // string is JSON and JSON has no merge keys. The plain conversion resolves `<<` as
                    // YAML's merge key, so `{"<<": {"hoisted": "yes"}, "b": "kept"}` -- valid JSON, and
                    // an ordinary object to every other reader in a pipeline -- lost the `"<<"` member
                    // and hoisted its contents: `%p["<<"] exists` FAILed while `%p.hoisted == "yes"`
                    // PASSed. The argument for reading it literally is on `values::merge_into`.
                    //
                    // The parser stays `serde_yaml`, so nothing about the accepted input changes. See
                    // `Value::try_from_json` for why `serde_json` is not used instead.
                    let parsed = crate::rules::values::Value::try_from_json(&value)
                        .and_then(|converted| PathAwareValue::try_from((&converted, path.clone())))
                        .map_err(|e| {
                            crate::Error::unanswerable(
                                entry,
                                format!("failed to convert the parsed string at {path}: {e}"),
                            )
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

/// The pattern for `regex_replace_with`, compiled once, or the refusal naming it.
///
/// The compile sat inside the per-element loop, in the arm a string reaches, so a pattern that does not
/// compile was recompiled for every string and never compiled at all when no element was one: over an
/// integer property or a missing key the author saw a failure about the input and the broken pattern
/// went unreported. And it was `RegexError`, which says "parse error for rules file" even for a pattern
/// the template supplied, and which `is_unevaluatable` does not recognize, so the run printed its
/// report and then exited 255 -- a tool failure, for a bad value in the data.
///
/// Two errors are classified by provenance between here and `regex_replace_with`. A pattern that does
/// not compile is answered on the pattern's own provenance, `pattern_from_rules_file`: written in the
/// rules file it is the author's mistake and stops the run, read from the template it is a fact about
/// the data and the clause fails. A match that spends the regex engine's backtracking budget is answered
/// on the input's provenance, not the pattern's: the budget is spent walking the input, and the same
/// literal pattern runs fine on one template's value and runs out on another's, so a template input
/// makes it a fact about that data (held in an `or`, failed closed as an assertion) while a literal
/// input makes it the author's. The caller knows both and this function no longer can once the pattern
/// is a `&str`; `origin` is where the pattern came from as the caller spells it, the property's path or
/// "in the rules file" for a quoted literal, so the refusal can say so.
pub(crate) fn compile_pattern(
    extract_expr: &str,
    origin: Option<&str>,
    pattern_from_rules_file: bool,
) -> crate::rules::Result<Regex> {
    Regex::try_from(extract_expr).map_err(|e| {
        Error::unanswerable_from(
            pattern_from_rules_file,
            format!(
                "regex_replace could not compile the pattern {extract_expr:?}{}: {e}",
                origin.map_or(String::new(), |origin| format!(" {origin}"))
            ),
        )
    })
}

/// `compile_pattern` and `regex_replace_with` in one call, for tests of the function on its own. The
/// evaluator compiles the pattern itself so the refusal can say where the pattern came from.
#[cfg(test)]
pub(crate) fn regex_replace(
    args: &[QueryResult],
    extract_expr: &str,
    replace_expr: &str,
    pattern_from_rules_file: bool,
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    regex_replace_with(
        args,
        &compile_pattern(extract_expr, None, pattern_from_rules_file)?,
        None,
        replace_expr,
    )
}

/// `origin` is where `regex` came from, as `compile_pattern` was told it, so a run-time failure names
/// the pattern's source beside the value it was run against.
pub(crate) fn regex_replace_with(
    args: &[QueryResult],
    regex: &Regex,
    origin: Option<&str>,
    replace_expr: &str,
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    let mut aggr = Vec::with_capacity(args.len());
    for entry in args.iter() {
        match entry {
            QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                if let PathAwareValue::String((path, val)) = &**v {
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
                    //
                    // A run-time failure, which is the backtracking budget, is classified on the
                    // input's provenance, as `compile_pattern`'s doc says; it was `RegexError`, which
                    // stopped the run whatever the source, where the `==` regex comparison already
                    // failed only its clause on the same exhausted budget. The refusal names the value
                    // it happened on and where the pattern came from.
                    let replaced = regex
                        .try_replacen(val, 0, replace_expr)
                        .map_err(|e| {
                            Error::unanswerable(
                                entry,
                                format!(
                                    "regex_replace could not match the pattern {:?}{} against the \
                                     value at {path}: {e}",
                                    regex.as_str(),
                                    origin.map_or(String::new(), |origin| format!(" {origin}"))
                                ),
                            )
                        })?
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
                    //
                    // `from <= to`, not `from < to`, and no test for an empty input. The range is
                    // `[from, to)`, so `[1, 1)` is inside `"abc"` and `[0, 0)` is inside `""`, and
                    // both select the empty string. The old guard pushed `None` for them, the
                    // variable then resolved to no values, and `%s == ""` failed with a diagnostic
                    // pointing at the `let` -- for an input that was present and a range that was
                    // in bounds. Only an end past the length, or a start past the end, is out of
                    // bounds, and only those answer with no value.
                    let length = val.chars().count();
                    if from <= to && to <= length {
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
    let mut parts: Vec<&str> = Vec::with_capacity(args.len());

    for entry in args.iter() {
        match entry {
            QueryResult::Resolved(v) | QueryResult::Literal(v) => {
                if let PathAwareValue::String((_, val)) = &**v {
                    parts.push(val);
                } else {
                    // By provenance: a non-string the template supplied is a fact about the data, a
                    // non-string written in the rules file is the author's mistake.
                    return Err(Error::unanswerable(
                        entry,
                        format!("Joining non string values {}", v),
                    ));
                }
            }
            QueryResult::UnResolved(ur) => {
                // A collection that is there and holds nothing contributes nothing. A key that was
                // not found is still an error.
                //
                // `accumulate` reports a wildcard over an empty list as an unresolved result whose
                // `traversed_to` is that list, and this arm errored on every unresolved result alike.
                // So `join(%svc.Collection.*, ",")` over `Collection: []` bailed the clause with
                // "Joining unresolved values is not allowed ... Value=[]", calling a list that is in
                // the template an unresolved path, where `count` on the same binding answers 0.
                // Where the query stopped says which of the two happened, and a key missing from an
                // empty struct is still a missing key; `count` reads it the same way, and
                // `stopped_at_an_empty_collection` is the shared test. The refusal is the data's
                // (`Unevaluatable`): the value the template holds did not resolve.
                if !stopped_at_an_empty_collection(ur) {
                    return Err(Error::Unevaluatable(format!(
                        "Joining unresolved values is not allowed {}, unsatisfied part {}",
                        ur.traversed_to, ur.remaining_query
                    )));
                }
            }
        }
    }

    // Joined from the parts that were kept, so a skipped member never leaves a delimiter behind.
    // The old loop pushed a delimiter after every member but the last by index, which would have
    // put a stray one at the end when the last member was an empty collection.
    let aggr = parts.join(delimiter);

    // At the path the members share, not the first member's. `common_path` says why.
    Ok(PathAwareValue::String((common_path(args), aggr)))
}

#[cfg(test)]
#[path = "strings_tests.rs"]
mod strings_tests;
