pub(crate) mod traversal;

use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
//
// Std Libraries
//
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::Formatter;

use crate::rules::evaluate::{resolve_query, AutoReport};
use crate::rules::EvaluationType;

use super::errors::Error;
use super::exprs::{QueryPart, SliceDisplay};
use super::{Evaluate, EvaluationContext, Status};
//
// Local mod
//
use super::values::*;
use crate::rules::exprs::LetValue;
use fancy_regex::Regex;
use serde::ser::{SerializeMap, SerializeStruct};
use std::hash::{Hash, Hasher};

//
// crate level
//
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub(crate) struct Location {
    pub(crate) line: usize,
    pub(crate) col: usize,
}

impl Location {
    #[cfg(test)]
    pub(crate) fn new(line: usize, col: usize) -> Self {
        Location { line, col }
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("L:{},C:{}", self.line, self.col))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Path(pub(crate) String, pub(crate) Location);

/// A key a document declared more than once inside one mapping.
///
/// Both locations are carried, not just the repeated one, because a warning that a key is duplicated
/// without saying where is unusable on a template of any size: the reader needs the line they can
/// see and the line that actually decided the value. A key name reused in two *different* mappings
/// is ordinary and is not this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DuplicateKey {
    pub(crate) path: String,
    pub(crate) first: Location,
    pub(crate) repeated: Location,
}

impl Path {
    #[cfg(test)]
    pub(crate) fn new(path: String, line: usize, col: usize) -> Path {
        Path(path, Location::new(line, col))
    }

    pub(crate) fn with_location(&self, loc: Location) -> Self {
        Path(self.0.clone(), loc)
    }
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}[{}]", self.0, self.1))
    }
}

impl Path {
    pub(crate) fn root() -> Self {
        Path("".to_string(), Location::default())
    }

    pub(crate) fn relative(&self) -> &str {
        match self.0.rfind('/') {
            Some(pos) => &self.0[pos + 1..],
            None => &self.0,
        }
    }
}

impl TryFrom<&str> for Path {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Path(value.to_string(), Location::default()))
    }
}

impl TryFrom<&[&str]> for Path {
    type Error = Error;

    fn try_from(value: &[&str]) -> Result<Self, Self::Error> {
        Ok(Path(
            value
                .iter()
                .map(|s| (*s).to_string())
                .fold(String::from(""), |mut acc, part| {
                    if acc.is_empty() {
                        acc.push_str(part.as_str());
                    } else {
                        acc.push('/');
                        acc.push_str(part.as_str());
                    }
                    acc
                }),
            Location::default(),
        ))
    }
}

impl TryFrom<&[String]> for Path {
    type Error = Error;

    fn try_from(value: &[String]) -> Result<Self, Self::Error> {
        let vec = value.iter().map(String::as_str).collect::<Vec<&str>>();
        Path::try_from(vec.as_slice())
    }
}

impl Path {
    pub(crate) fn extend_str(&self, part: &str) -> Path {
        let mut copy = self.0.clone();
        copy.push('/');
        copy.push_str(part);
        Path(copy, self.1)
    }

    pub(crate) fn extend_string(&self, part: &str) -> Path {
        self.extend_str(part)
    }

    pub(crate) fn extend_usize(&self, part: usize) -> Path {
        let as_str = part.to_string();
        self.extend_string(&as_str)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MapValue {
    pub(crate) keys: Vec<PathAwareValue>,
    pub(crate) values: indexmap::IndexMap<String, PathAwareValue>,
}

impl Serialize for MapValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (key, value) in self.values.iter() {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl PartialEq for MapValue {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl Eq for MapValue {}

impl MapValue {
    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) enum PathAwareValue {
    Null(Path),
    String((Path, String)),
    Regex((Path, String)),
    Bool((Path, bool)),
    Int((Path, i64)),
    Float((Path, f64)),
    Char((Path, char)),
    List((Path, Vec<PathAwareValue>)),
    Map((Path, MapValue)),
    RangeInt((Path, RangeType<i64>)),
    RangeFloat((Path, RangeType<f64>)),
    RangeChar((Path, RangeType<char>)),
}

impl Hash for PathAwareValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PathAwareValue::String((_, s)) | PathAwareValue::Regex((_, s)) => {
                s.hash(state);
            }

            PathAwareValue::Char((_, c)) => {
                c.hash(state);
            }
            PathAwareValue::Int((_, i)) => {
                i.hash(state);
            }
            PathAwareValue::Null(_) => {
                "NULL".hash(state);
            }
            PathAwareValue::Float((_, f)) => {
                // A float that is exactly an integer hashes as that integer, because `eq` says the
                // two are equal: `compare_values` compares an integer against a float numerically,
                // so `Int(-1) == Float(-1.0)`. Every other float hashes its bit pattern.
                //
                // `*f as u64` did neither of those things. That cast saturates, so every negative
                // float hashed as 0 while its integer twin hashed as itself, and it truncates, so
                // 1.1 and 1.9 both hashed as 1. Colliding is legal for a hash. Disagreeing with
                // `eq` is not, and `PathAwareValue` asserts `Eq`.
                match float_as_exact_i64(*f) {
                    Some(i) => i.hash(state),
                    None => f.to_bits().hash(state),
                }
            }

            PathAwareValue::RangeChar((_, r)) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            }

            PathAwareValue::RangeInt((_, r)) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            }

            PathAwareValue::RangeFloat((_, r)) => {
                // Canonicalised the same way as a scalar float, and for the same reason: `as u64`
                // saturates, so every range with a negative bound hashed that bound as 0, and it
                // truncates, so `r[1.1, 2.9]` and `r[1.9, 2.1]` hashed alike. This is also what keeps
                // the hash agreeing with the equality arm added below for two ranges, where `-0.0` and
                // `0.0` are equal bounds and have different bit patterns.
                //
                // Missed when the scalar arm above was fixed: the cast appeared twice and only one
                // copy was corrected.
                for bound in [r.lower, r.upper] {
                    match float_as_exact_i64(bound) {
                        Some(i) => i.hash(state),
                        None => bound.to_bits().hash(state),
                    }
                }
                r.inclusive.hash(state);
            }

            PathAwareValue::Bool((_, b)) => {
                b.hash(state);
            }

            PathAwareValue::List((_, l)) => {
                for each in l {
                    each.hash(state);
                }
            }

            // Hashed in sorted key order, not in iteration order. `eq` for a map is
            // `IndexMap::eq` -- a length check plus a lookup per key -- so it does not care what
            // order the entries are in, while `IndexMap`'s iteration order is insertion order. So
            // two maps holding the same entries written in a different order were equal and hashed
            // differently, which is the `Eq`/`Hash` contract violation `equal_values_hash_equally`
            // exists to prevent, in the same `match` as the `Float` cast it was written for.
            //
            // Sorting rather than combining the per-entry hashes commutatively: a commutative fold
            // has to reduce each entry to a value of its own first, and `Hash` is handed one `H`
            // with no way to construct a second hasher of that type. Sorting costs an allocation
            // per hash, on a path nothing hot uses.
            PathAwareValue::Map((_, map)) => {
                let mut entries = map
                    .values
                    .iter()
                    .collect::<Vec<(&String, &PathAwareValue)>>();
                entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                for (key, value) in entries {
                    key.hash(state);
                    value.hash(state);
                }
            }
        }
    }
}

impl PartialEq for PathAwareValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PathAwareValue::Map((_, map)), PathAwareValue::Map((_, map2))) => map == map2,

            (PathAwareValue::List((_, list)), PathAwareValue::List((_, list2))) => list == list2,

            (PathAwareValue::Bool((_, b1)), PathAwareValue::Bool((_, b2))) => b1 == b2,

            // `unwrap_or(false)` rather than `unwrap`, and the difference is a process abort.
            //
            // The `unwrap` carried the comment "given that we have already validated the regular
            // expression", which is a false premise. Validation at parse time proves the pattern
            // *compiles*; it says nothing about whether a match *completes*. `fancy_regex` returns
            // a `Result` from `is_match` because a pattern with a lookaround or a backreference
            // runs on its backtracking engine, and a nested quantifier can then exceed the
            // backtrack limit on a long value -- `/(?!zzz)(\w+\s?)+!/` against eighty characters
            // holding no `!` did it, at exit 101, for the whole file. That is the failure the
            // `unwrap_or(false)` answers.
            //
            // The two `false`s here are not the same `false`, and only one of them is live.
            // `Regex::new` failing is a pattern that will not *compile*, and that is `Err(_)`;
            // `is_match` returning `Err` is a pattern that compiled and then could not be
            // *evaluated*, and that is the `unwrap_or`. Measured by making each panic in turn:
            // `Err(_)` leaves the whole suite green, and the `unwrap_or` fails the three cases of
            // `a_regex_in_a_list_literal_fails_the_clause_instead_of_aborting`.
            //
            // `Err(_) => false` is unreachable as things stand, by construction rather than by
            // luck. Only two arms build a `PathAwareValue::Regex`: one from `MarkedValue::Regex`,
            // which nothing in the crate ever constructs, and one from `Value::Regex`, which
            // `parse_regex_inner` builds only after `Regex::try_from` has accepted the pattern --
            // it answers `nom::Err::Failure` otherwise, so a rules file holding `/a(/` exits 5 at
            // parse time and never reaches an evaluator. JSON and YAML have no regex spelling, so a
            // data file or `--input-parameters` cannot smuggle one past that check either.
            //
            // It stays, and as `false` rather than `unreachable!()`. What makes it unreachable is a
            // property of the callers and not of this match, so it returns the moment anything
            // builds a `PathAwareValue::Regex` without compiling it first: a `MarkedValue::Regex`
            // that starts being constructed, a parser that stops refusing, or a third construction
            // site. `unreachable!()` would turn each of those into a panic inside a comparison,
            // which is the abort the first paragraph is about avoiding.
            //
            // `false` is a compromise and not the honest answer, so it is worth being plain about
            // what it costs. `PartialEq` returns `bool` and cannot report anything, and the arms
            // cannot simply go: `contained_in` in `eval/operators.rs` decides `X in [/re/]` by
            // asking `elem == rest` for each element before it asks anything else, so a panic in
            // these arms takes a run down. Reached by
            // `a_regex_in_a_list_literal_fails_the_clause_instead_of_aborting` and by the four
            // `IN`/`NOT IN` cases of `an_ordinary_regex_comparison_is_unchanged`, of which only the
            // first reaches the error path.
            //
            // The compromise survives because `eq` is not the last word on that path.
            // `contained_in` asks `compare_eq` for each element `eq` turned down, and `compare_eq`
            // returns `Error::RegexError` rather than a verdict; `contained_in` promotes that to
            // `NotComparable` and carries the reason out. So a regex that cannot be evaluated reads
            // as "not equal" here and is named one line later.
            //
            // The unwrapped spelling does not arrive here at all: `X == /re/` asks `compare_eq`
            // directly, which is why the `==`/`!=` cases of that same test stay clear of these arms
            // while the `IN` ones do not.
            (PathAwareValue::String((_, s)), PathAwareValue::Regex((_, r))) => {
                match Regex::new(r.as_str()) {
                    Ok(regex) => regex.is_match(s.as_str()).unwrap_or(false),
                    Err(_) => false,
                }
            }
            (PathAwareValue::Regex((_, r)), PathAwareValue::String((_, s))) => {
                match Regex::new(r.as_str()) {
                    Ok(regex) => regex.is_match(s.as_str()).unwrap_or(false),
                    Err(_) => false,
                }
            }
            (PathAwareValue::Regex((_, r)), PathAwareValue::Regex((_, s))) => r == s,

            // Two ranges are equal when they describe the same range. Structural, so it is reflexive,
            // symmetric and transitive -- unlike the membership arms that used to live here, which
            // answered "is this scalar inside that range" and made `eq` neither reflexive nor
            // symmetric. Membership is `compare_eq`'s job and stays there.
            //
            // Without these arms a range was not equal to *itself*: the fall-through asks
            // `compare_values`, which reports two ranges as incomparable, and `impl Eq` below then
            // promises a reflexivity the type did not have. Found by review of the commit that removed
            // the membership arms, which closed the symmetry hole and left this one open.
            //
            // A NaN bound would break reflexivity again, since `f64::NaN != f64::NaN`. Ranges are only
            // built from parsed numeric literals, and NaN is not one, so it is unreachable rather than
            // handled.
            (PathAwareValue::RangeInt((_, r)), PathAwareValue::RangeInt((_, r2))) => r == r2,
            (PathAwareValue::RangeFloat((_, r)), PathAwareValue::RangeFloat((_, r2))) => r == r2,
            (PathAwareValue::RangeChar((_, r)), PathAwareValue::RangeChar((_, r2))) => r == r2,

            (rest, rest2) => match compare_values(rest, rest2) {
                Ok(ordering) => matches!(ordering, Ordering::Equal),
                Err(_) => false,
            },
        }
    }
}

/// `eq` above is a match relation, and `Eq` claims more than it delivers.
///
/// A string equals a regex it matches, and that arm is load-bearing rather than decorative:
/// `contained_in` decides `X in [/re/]` by asking `eq` for each element of the list literal, so a
/// panic in that arm ends the run at 101. Map key filters do not come through it, despite the
/// spelling: `QueryPart::MapKeyFilter` in `eval_context.rs` hands its keys to
/// `real_binary_operation`, which asks `compare_eq`. It also puts a ceiling on how honest `Hash` can be,
/// because a regex and every string matching it would have to share one hash. So `eq` is not
/// transitive, and `PathAwareValue` must not key a hashed collection that can hold a `Regex`.
///
/// One hashed collection does key on it: the grouping of comparison results by their left-hand value
/// in `report_at_least_one`. That is safe for a reason rather than by luck -- its keys come from the
/// document under validation, and a `Regex` only ever arrives as a rule literal on the right-hand
/// side of a comparison.
///
/// Range membership used to be answered here too, which broke symmetry outright:
/// `Int(50) == RangeInt(5..100)` held while the reverse did not, there being no reverse arm. Those
/// arms were removed rather than mirrored, because membership is `compare_eq`'s job and it keeps its
/// own range table.
///
/// A range nested in a list literal does still arrive here, through `Vec::contains` in
/// `contained_in`, and that is what the removed arms were not reaching: `contains` asks
/// `element == value`, so it needed the reverse arm, the one that never existed. Membership through a
/// list was therefore answered `false` for every range, in both polarities, until `contained_in`
/// started asking `compare_eq` as well. The arms stay out; the caller asks the function that has the
/// table.
///
/// Numeric widening does stay, reached through `compare_values`. Unlike the other two it is an
/// equivalence relation on the values it relates, and `Hash` agrees with it.
///
/// For the same reason the type has no `PartialOrd`, and must not be given one. Rust requires
/// `a.partial_cmp(b) == Some(Ordering::Equal)` exactly when `a == b`, and no ordering can satisfy that
/// against a match relation: a regex would have to order `Equal` with every string it matches and
/// those strings order differently from each other. The impl that used to stand here compared
/// `self_path().0`, the path string, and ignored the value, so it disagreed with `eq` in both
/// directions -- every rule literal is built with `Path::root()` and so shares the path `""`, which
/// made `partial_cmp` report `Equal` for any two literals in any rules file, `15` against `"abc"`
/// included, while two equal values read from different properties ordered `Less` or `Greater`.
/// Nothing consumed it, which is how it survived; `sort_by(|a, b| a.partial_cmp(b).unwrap())` is one
/// line away and would have ordered by path.
///
/// Ordering values is `compare_lt` and its three siblings, which return `Result` and can refuse a
/// pair they cannot order. That is the behaviour the language needs and a `PartialOrd` cannot express.
impl Eq for PathAwareValue {}

impl TryFrom<&str> for PathAwareValue {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = Value::try_from(value)?;
        PathAwareValue::try_from((&value, Path::try_from("")?))
    }
}

impl TryFrom<(&str, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(value: (&str, Path)) -> Result<Self, Self::Error> {
        let parsed = Value::try_from(value.0)?;
        PathAwareValue::try_from((&parsed, value.1))
    }
}

impl TryFrom<(&serde_json::Value, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(incoming: (&serde_json::Value, Path)) -> Result<Self, Self::Error> {
        let root = incoming.0;
        let path = incoming.1;
        let value = Value::try_from(root)?;
        PathAwareValue::try_from((&value, path))
    }
}

impl TryFrom<(&serde_yaml::Value, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(incoming: (&serde_yaml::Value, Path)) -> Result<Self, Self::Error> {
        let root = incoming.0;
        let path = incoming.1;
        let value = Value::try_from(root)?;
        PathAwareValue::try_from((&value, path))
    }
}

impl TryFrom<Value> for PathAwareValue {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        PathAwareValue::try_from((&value, Path::root()))
    }
}

impl TryFrom<serde_yaml::Value> for PathAwareValue {
    type Error = Error;

    fn try_from(value: serde_yaml::Value) -> Result<Self, Self::Error> {
        PathAwareValue::try_from((&value, Path::root()))
    }
}

impl TryFrom<serde_json::Value> for PathAwareValue {
    type Error = Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        PathAwareValue::try_from((&value, Path::root()))
    }
}

impl TryFrom<(&Value, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(incoming: (&Value, Path)) -> Result<Self, Self::Error> {
        let root = incoming.0;
        let path = incoming.1;

        match root {
            Value::String(s) => Ok(PathAwareValue::String((path, s.to_owned()))),
            Value::Int(num) => Ok(PathAwareValue::Int((path, *num))),
            Value::Float(flt) => Ok(PathAwareValue::Float((path, *flt))),
            Value::Regex(s) => Ok(PathAwareValue::Regex((path, s.clone()))),
            Value::Char(c) => Ok(PathAwareValue::Char((path, *c))),
            Value::RangeChar(r) => Ok(PathAwareValue::RangeChar((path, r.clone()))),
            Value::RangeInt(r) => Ok(PathAwareValue::RangeInt((path, r.clone()))),
            Value::RangeFloat(r) => Ok(PathAwareValue::RangeFloat((path, r.clone()))),
            Value::Bool(b) => Ok(PathAwareValue::Bool((path, *b))),
            Value::Null => Ok(PathAwareValue::Null(path)),
            Value::List(v) => {
                let mut result: Vec<PathAwareValue> = Vec::with_capacity(v.len());
                for (idx, each) in v.iter().enumerate() {
                    let sub_path = path.extend_usize(idx);
                    let value = PathAwareValue::try_from((each, sub_path.clone()))?;
                    result.push(value);
                }
                Ok(PathAwareValue::List((path, result)))
            }

            Value::Map(map) => {
                let mut keys = Vec::with_capacity(map.len());
                let mut values = indexmap::IndexMap::with_capacity(map.len());
                for each_key in map.keys() {
                    let sub_path = path.extend_string(each_key);
                    let value = PathAwareValue::String((sub_path, each_key.to_string()));
                    keys.push(value);
                }

                for (each_key, each_value) in map {
                    let sub_path = path.extend_string(each_key);
                    let value = PathAwareValue::try_from((each_value, sub_path))?;
                    values.insert(each_key.to_owned(), value);
                }
                Ok(PathAwareValue::Map((path, MapValue { keys, values })))
            }
        }
    }
}

impl TryFrom<MarkedValue> for PathAwareValue {
    type Error = Error;

    fn try_from(value: MarkedValue) -> Result<Self, Self::Error> {
        Self::try_from((value, Path::root()))
    }
}
impl TryFrom<(MarkedValue, Path)> for PathAwareValue {
    type Error = Error;

    /// Drops any duplicate keys the document held. Callers that report them use
    /// `try_from_marked` instead; this exists for the ones with nowhere to report to.
    fn try_from(incoming: (MarkedValue, Path)) -> Result<Self, Self::Error> {
        Self::try_from_marked(incoming, &mut vec![])
    }
}

impl PathAwareValue {
    /// The conversion, collecting the keys a mapping declared twice as it goes.
    ///
    /// This is where the duplicate is visible and nowhere earlier is: the loader keys its map on
    /// `(String, Location)`, so two same-named keys at different lines are two separate entries and
    /// both survive it. They collapse here, where the map is rebuilt keyed on the name alone, and
    /// this is also the only point that holds the path the key was reached by. Collection is
    /// per-mapping by construction, since the check is the insert into the map being built for one
    /// mapping, so a name reused across two mappings cannot register.
    pub(crate) fn try_from_marked(
        incoming: (MarkedValue, Path),
        duplicates: &mut Vec<DuplicateKey>,
    ) -> Result<Self, Error> {
        let root = incoming.0;
        let path = incoming.1;

        match root {
            MarkedValue::String(s, loc) => Ok(PathAwareValue::String((path.with_location(loc), s))),
            MarkedValue::Int(num, loc) => Ok(PathAwareValue::Int((path.with_location(loc), num))),
            MarkedValue::Float(flt, loc) => {
                Ok(PathAwareValue::Float((path.with_location(loc), flt)))
            }
            MarkedValue::Regex(s, loc) => Ok(PathAwareValue::Regex((path.with_location(loc), s))),
            MarkedValue::Char(c, loc) => Ok(PathAwareValue::Char((path.with_location(loc), c))),
            MarkedValue::RangeChar(r, loc) => {
                Ok(PathAwareValue::RangeChar((path.with_location(loc), r)))
            }
            MarkedValue::RangeInt(r, loc) => {
                Ok(PathAwareValue::RangeInt((path.with_location(loc), r)))
            }
            MarkedValue::RangeFloat(r, loc) => {
                Ok(PathAwareValue::RangeFloat((path.with_location(loc), r)))
            }
            MarkedValue::Bool(b, loc) => Ok(PathAwareValue::Bool((path.with_location(loc), b))),
            MarkedValue::Null(loc) => Ok(PathAwareValue::Null(path.with_location(loc))),
            MarkedValue::List(v, _) => {
                let mut result: Vec<PathAwareValue> = Vec::with_capacity(v.len());

                for (idx, each) in v.into_iter().enumerate() {
                    let sub_path = path.extend_usize(idx);
                    let loc = *each.location();
                    let value =
                        Self::try_from_marked((each, sub_path.with_location(loc)), duplicates)?;
                    result.push(value);
                }

                Ok(PathAwareValue::List((path, result)))
            }

            MarkedValue::Map(map, loc) => {
                let mut keys = Vec::with_capacity(map.len());
                let mut values = indexmap::IndexMap::with_capacity(map.len());
                let mut first_seen: indexmap::IndexMap<String, Location> =
                    indexmap::IndexMap::with_capacity(map.len());
                for ((each_key, loc), each_value) in map {
                    let sub_path = path.extend_string(&each_key);
                    let sub_path = sub_path.with_location(*each_value.location());
                    let key_path = sub_path.0.clone();
                    let value = Self::try_from_marked((each_value, sub_path), duplicates)?;
                    // Pushed only when the insert added a new entry. `values` is an `IndexMap` and
                    // dedups; `keys` did not, so a document with a repeated key left the two different
                    // lengths -- and `eval_context` pairs them *positionally*
                    // (`map.keys.iter().zip(map.values.values())`), so every entry after the duplicate
                    // was bound to the wrong key.
                    //
                    // On a template declaring `A` twice, with `C` the only public bucket,
                    // `Resources[ nm | Properties.Public == true ]` captured `nm` as "A" -- a bucket
                    // whose `Public` is false -- and the last key was dropped entirely. Remove the
                    // duplicate and the same rule captures "C". A rule that reports the wrong logical
                    // id sends someone to the wrong resource.
                    //
                    // Only the key side was affected, which is why it needs a capture to see at all: a
                    // value traversal such as `Resources.*[ Type == ... ] { ... }` never reads `keys`
                    // and always found `C`.
                    //
                    // Last-write-wins on the value is unchanged, and the key keeps the position of its
                    // first appearance, which is what `IndexMap` does for the value too.
                    //
                    // That same insert is what tells a duplicate from a first appearance, so the
                    // collection below costs no second pass over the mapping.
                    if values.insert(each_key.to_owned(), value).is_none() {
                        first_seen.insert(each_key.to_owned(), loc);
                        keys.push(PathAwareValue::String((
                            path.with_location(loc),
                            each_key.to_string(),
                        )));
                    } else if let Some(first) = first_seen.get(&each_key) {
                        duplicates.push(DuplicateKey {
                            path: key_path,
                            first: *first,
                            repeated: loc,
                        });
                    }
                }
                Ok(PathAwareValue::Map((
                    path.with_location(loc),
                    MapValue { keys, values },
                )))
            }

            MarkedValue::BadValue(val, loc) => Err(Error::ParseError(format!(
                "Bad Value encountered parsing incoming file Value = {}, Loc = {}",
                val, loc
            ))),
        }
    }
}

impl<'a> TryInto<(String, serde_json::Value)> for &'a PathAwareValue {
    type Error = Error;

    fn try_into(self) -> Result<(String, serde_json::Value), Self::Error> {
        let top = self.self_path().0.clone();
        match self {
            PathAwareValue::Null(_) => Ok((top, serde_json::Value::Null)),
            PathAwareValue::String((_, s)) => Ok((top, serde_json::Value::String(s.clone()))),
            PathAwareValue::Regex((_, r)) => {
                Ok((top, serde_json::Value::String(format!("/{}/", r))))
            }
            PathAwareValue::Bool((_, bool_)) => Ok((top, serde_json::Value::Bool(*bool_))),
            PathAwareValue::Int((_, i64_)) => Ok((
                top,
                serde_json::Value::Number(serde_json::Number::from(*i64_)),
            )),
            PathAwareValue::Float((_, f64_)) => Ok((
                top,
                serde_json::Value::Number(match serde_json::Number::from_f64(*f64_) {
                    Some(num) => num,
                    None => {
                        return Err(Error::IncompatibleError(format!(
                            "Could not convert float {} to serde::Value::Number",
                            *f64_
                        )))
                    }
                }),
            )),
            PathAwareValue::Char((_, char_)) => {
                Ok((top, serde_json::Value::String(char_.to_string())))
            }

            PathAwareValue::List((_, list)) => {
                let mut values = Vec::with_capacity(list.len());
                for each in list {
                    let (_, val): (String, serde_json::Value) = each.try_into()?;
                    values.push(val);
                }
                Ok((top, serde_json::Value::Array(values)))
            }

            PathAwareValue::Map((_, map)) => {
                let mut values = serde_json::Map::new();
                for (key, value) in map.values.iter() {
                    let (_, val): (String, serde_json::Value) = value.try_into()?;
                    values.insert(key.clone(), val);
                }
                Ok((top, serde_json::Value::Object(values)))
            }

            PathAwareValue::RangeFloat((_, range_)) => {
                let range_encoding = format!(
                    "{}{},{}{}",
                    if range_.inclusive & LOWER_INCLUSIVE > 0 {
                        "["
                    } else {
                        "("
                    },
                    range_.lower,
                    range_.upper,
                    if range_.inclusive & UPPER_INCLUSIVE > 0 {
                        "]"
                    } else {
                        ")"
                    },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            }

            PathAwareValue::RangeChar((_, range_)) => {
                let range_encoding = format!(
                    "{}{},{}{}",
                    if range_.inclusive & LOWER_INCLUSIVE > 0 {
                        "["
                    } else {
                        "("
                    },
                    range_.lower,
                    range_.upper,
                    if range_.inclusive & UPPER_INCLUSIVE > 0 {
                        "]"
                    } else {
                        ")"
                    },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            }

            PathAwareValue::RangeInt((_, range_)) => {
                let range_encoding = format!(
                    "{}{},{}{}",
                    if range_.inclusive & LOWER_INCLUSIVE > 0 {
                        "["
                    } else {
                        "("
                    },
                    range_.lower,
                    range_.upper,
                    if range_.inclusive & UPPER_INCLUSIVE > 0 {
                        "]"
                    } else {
                        ")"
                    },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            }
        }
    }
}

pub(crate) trait QueryResolver {
    fn select(
        &self,
        all: bool,
        query: &[QueryPart<'_>],
        eval: &dyn EvaluationContext,
    ) -> Result<Vec<&PathAwareValue>, Error>;
}

impl QueryResolver for PathAwareValue {
    fn select(
        &self,
        all: bool,
        query: &[QueryPart<'_>],
        resolver: &dyn EvaluationContext,
    ) -> Result<Vec<&PathAwareValue>, Error> {
        if query.is_empty() {
            return Ok(vec![self]);
        }

        match &query[0] {
            QueryPart::This => self.select(all, &query[1..], resolver),

            QueryPart::Key(key) => {
                match list_index_of(self, key) {
                    Some(index) => match self {
                        PathAwareValue::List((_, list)) => {
                            PathAwareValue::retrieve_index(self, index, list, query).map_or_else(
                                |e| self.map_error_or_empty(all, e),
                                |val| val.select(all, &query[1..], resolver),
                            )
                        }

                        _ => self.map_some_or_error_all(all, query),
                    },

                    None => match self {
                        PathAwareValue::Map((path, map)) => {
                            //
                            // Variable interpolation support.
                            //
                            if query[0].is_variable() {
                                let var = query[0].variable().unwrap();
                                let keys = resolver.resolve_variable(var)?;
                                let mut acc = Vec::with_capacity(keys.len());
                                let keys = if query.len() > 1 {
                                    match query[1] {
                                        QueryPart::AllIndices(_) | QueryPart::Key(_) => keys,
                                        QueryPart::Index(index) => {
                                            match index_offset(index, keys.len()) {
                                                Some(check) => vec![keys[check]],
                                                None => self.map_some_or_error_all(all, query)?,
                                            }
                                        },

                                        _ => return Err(Error::IncompatibleError(
                                            format!("THIS type of variable interpolation is not supported {}, {}", self.type_info(), SliceDisplay(query))
                                        ))
                                    }
                                } else {
                                    keys
                                };
                                for each_key in keys {
                                    if let PathAwareValue::String((_, k)) = each_key {
                                        if let Some(next) = map.values.get(k) {
                                            acc.extend(next.select(all, &query[1..], resolver)?);
                                        } else if all {
                                            return Err(Error::
                                                RetrievalError(
                                                    format!("Could not locate key = {} inside object/map = {:?}, Path = {}, remaining query = {}",
                                                            key, self, path, SliceDisplay(query))
                                                ));
                                        }
                                    } else {
                                        return Err(Error
                                            ::NotComparable(
                                                format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                        SliceDisplay(query),
                                                        each_key.type_info(),
                                                        each_key.self_value()
                                               )

                                        ));
                                    }
                                }
                                Ok(acc)
                            } else if let Some(next) = map.values.get(key) {
                                next.select(all, &query[1..], resolver)
                            } else {
                                self.map_some_or_error_all(all, query)
                            }
                        }

                        _ => self.map_some_or_error_all(all, query),
                    },
                }
            }

            QueryPart::Index(array_idx) => match self {
                PathAwareValue::List((_path, vec)) => {
                    PathAwareValue::retrieve_index(self, *array_idx, vec, query).map_or_else(
                        |e| self.map_error_or_empty(all, e),
                        |val| val.select(all, &query[1..], resolver),
                    )
                }

                _ => self.map_some_or_error_all(all, query),
            },

            QueryPart::AllIndices(_name) => {
                match self {
                    PathAwareValue::List((_path, elements)) => {
                        PathAwareValue::accumulate(self, all, &query[1..], elements, resolver)
                    }

                    //
                    // Often in the place where a list of values is accepted
                    // single values often are accepted. So proceed to the next
                    // part of your query
                    //
                    rest => rest.select(all, &query[1..], resolver),
                }
            }

            QueryPart::AllValues(_name) => {
                match self {
                    //
                    // Supporting old format
                    //
                    PathAwareValue::List((_path, elements)) => {
                        PathAwareValue::accumulate(self, all, &query[1..], elements, resolver)
                    }

                    PathAwareValue::Map((_path, map)) => {
                        let values: Vec<&PathAwareValue> = map.values.values().collect();
                        let mut resolved = Vec::with_capacity(values.len());
                        for each in values {
                            resolved.extend(each.select(all, &query[1..], resolver)?);
                        }
                        Ok(resolved)
                    }

                    //
                    // Often in the place where a list of values is accepted
                    // single values often are accepted. So proceed to the next
                    // part of your query
                    //
                    rest => rest.select(all, &query[1..], resolver),
                }
            }

            QueryPart::MapKeyFilter(_name, filter) => match self {
                PathAwareValue::Map((_, map)) => {
                    let mut selected = Vec::with_capacity(map.values.len());
                    match &filter.compare_with {
                        LetValue::AccessClause(query) => {
                            let values = resolve_query(false, &query.query, self, resolver)?;
                            for key in map.keys.iter() {
                                if values.contains(&key) {
                                    match key {
                                        PathAwareValue::String((_, v)) => {
                                            selected.push(map.values.get(v).unwrap());
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                            }
                        }

                        LetValue::Value(path_value) => {
                            for key in map.keys.iter() {
                                if key == path_value {
                                    match key {
                                        PathAwareValue::String((_, v)) => {
                                            selected.push(map.values.get(v).unwrap());
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                            }
                        }

                        // Not `unreachable!()` any more. It was true only because the parser could not
                        // build a key filter with a function call on the right, and that was the defect --
                        // the same input parsed as an ordinary filter over a property named `keys` and
                        // returned a different verdict. Now that the parser builds it, an abort here would
                        // be one panic away from any caller of this resolver.
                        //
                        // Resolving it is the live engine's job and it does resolve it, in
                        // `eval_context::query_retrieval_with_converter`; this resolver has no function
                        // machinery to reach for and no command path reaches this arm. So it says what it
                        // cannot do rather than dying of it.
                        LetValue::FunctionCall(function) => {
                            return Err(Error::RetrievalError(format!(
                                "A key filter with a function call on the right, {}, needs the evaluation \
                                 context that resolves functions. This resolver does not have one.",
                                function.name
                            )))
                        }
                    };
                    if query.len() > 1 {
                        let mut acc = Vec::with_capacity(selected.len());
                        for each in selected {
                            acc.extend(each.select(all, &query[1..], resolver)?)
                        }
                        Ok(acc)
                    } else {
                        Ok(selected)
                    }
                }

                _ => self.map_some_or_error_all(all, query),
            },

            QueryPart::Filter(_name, conjunctions) => {
                match self {
                    PathAwareValue::List((path, vec)) => {
                        let mut selected = Vec::with_capacity(vec.len());
                        let context = format!("Path={},Type=Array", path);
                        for each in vec {
                            let mut filter =
                                AutoReport::new(EvaluationType::Filter, resolver, &context);
                            match conjunctions.evaluate(each, resolver) {
                                Err(Error::RetrievalError(e)) => {
                                    if all {
                                        return Err(Error::RetrievalError(e));
                                    }
                                    // Else treat is like a filter
                                }
                                Err(Error::IncompatibleRetrievalError(e)) => {
                                    if all {
                                        return Err(Error::IncompatibleRetrievalError(e));
                                    }
                                    // Else treat is like a filter
                                }
                                Err(e) => return Err(e),
                                Ok(status) => match status {
                                    Status::PASS => {
                                        filter.status(Status::PASS);
                                        let index: usize = if query.len() > 1 {
                                            match &query[1] {
                                                QueryPart::AllIndices(_) => 2,
                                                _ => 1,
                                            }
                                        } else {
                                            1
                                        };
                                        selected.extend(each.select(
                                            all,
                                            &query[index..],
                                            resolver,
                                        )?);
                                    }
                                    rest => {
                                        filter.status(rest);
                                    }
                                },
                            }
                        }
                        Ok(selected)
                    }

                    PathAwareValue::Map((path, _map)) => {
                        let context = format!("Path={},Type=MapElement", path);
                        let mut filter =
                            AutoReport::new(EvaluationType::Filter, resolver, &context);
                        conjunctions.evaluate(self, resolver).map_or_else(
                            |e| self.map_error_or_empty(all, e),
                            |status| match status {
                                Status::PASS => {
                                    filter.status(Status::PASS);
                                    self.select(all, &query[1..], resolver)
                                }
                                rest => {
                                    filter.status(rest);
                                    Ok(vec![])
                                }
                            },
                        )
                    }

                    _ => self.map_some_or_error_all(all, query),
                }
            }
        }
    }
}

impl Serialize for PathAwareValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let result: crate::rules::Result<(String, serde_json::Value)> = self.try_into();
        match result {
            Ok((path, value)) => {
                let mut struct_ser = serializer.serialize_struct("PathAwareValue", 2)?;
                struct_ser.serialize_field("path", &path)?;
                struct_ser.serialize_field("value", &value)?;
                struct_ser.end()
            }
            Err(e) => Err(serde::ser::Error::custom(e)),
        }
    }
}

impl PathAwareValue {
    pub(crate) fn merge(mut self, other: PathAwareValue) -> crate::rules::Result<PathAwareValue> {
        match (&mut self, other) {
            (PathAwareValue::List((_path, vec)), PathAwareValue::List((_p2, other_vec))) => {
                vec.extend(other_vec)
            }

            (PathAwareValue::Map((_, map)), PathAwareValue::Map((path, other_map))) => {
                for (key, value) in other_map.values {
                    if map.values.contains_key(&key) {
                        return Err(Error::MultipleValues(format!(
                            "Key {}, already exists in map",
                            key
                        )));
                    }

                    map.values.insert(key.clone(), value);
                    map.keys
                        .push(PathAwareValue::String((path.extend_str(&key), key)));
                }
            }

            (this, that) => {
                return Err(Error::IncompatibleError(format!(
                    "Types are not compatible for merges {}, {}",
                    this.type_info(),
                    that.type_info()
                )))
            }
        }
        Ok(self)
    }

    pub(crate) fn is_list(&self) -> bool {
        matches!(self, PathAwareValue::List((_, _)))
    }

    pub(crate) fn is_map(&self) -> bool {
        matches!(self, PathAwareValue::Map((_, _)))
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, PathAwareValue::Null(_))
    }

    fn map_error_or_empty(&self, all: bool, e: Error) -> Result<Vec<&PathAwareValue>, Error> {
        if !all {
            match e {
                Error::IncompatibleRetrievalError(_) | Error::RetrievalError(_) => Ok(vec![]),

                rest => Err(rest),
            }
        } else {
            Err(e)
        }
    }

    fn map_some_or_error_all(
        &self,
        all: bool,
        query: &[QueryPart<'_>],
    ) -> Result<Vec<&PathAwareValue>, Error> {
        if all {
            Err(Error::IncompatibleRetrievalError(
                format!("Attempting to retrieve array index or key from map at path = {} , Type was not an array/object {}, Remaining Query = {}",
                        self.self_value().0, self.type_info(), SliceDisplay(query))
            ))
        } else {
            Ok(vec![])
        }
    }

    pub(crate) fn is_scalar(&self) -> bool {
        !self.is_list() && !self.is_map()
    }

    pub(crate) fn self_path(&self) -> &Path {
        self.self_value().0
    }

    pub(crate) fn self_value(&self) -> (&Path, &PathAwareValue) {
        match self {
            PathAwareValue::Null(path) => (path, self),
            PathAwareValue::String((path, _)) => (path, self),
            PathAwareValue::Regex((path, _)) => (path, self),
            PathAwareValue::Bool((path, _)) => (path, self),
            PathAwareValue::Int((path, _)) => (path, self),
            PathAwareValue::Float((path, _)) => (path, self),
            PathAwareValue::Char((path, _)) => (path, self),
            PathAwareValue::List((path, _)) => (path, self),
            PathAwareValue::Map((path, _)) => (path, self),
            PathAwareValue::RangeInt((path, _)) => (path, self),
            PathAwareValue::RangeFloat((path, _)) => (path, self),
            PathAwareValue::RangeChar((path, _)) => (path, self),
        }
    }

    pub(crate) fn type_info(&self) -> &'static str {
        match self {
            PathAwareValue::Null(_path) => "null",
            PathAwareValue::String((_path, _)) => "String",
            PathAwareValue::Regex((_path, _)) => "Regex",
            PathAwareValue::Bool((_path, _)) => "bool",
            PathAwareValue::Int((_path, _)) => "int",
            PathAwareValue::Float((_path, _)) => "float",
            PathAwareValue::Char((_path, _)) => "char",
            PathAwareValue::List((_path, _)) => "array",
            PathAwareValue::Map((_path, _)) => "map",
            PathAwareValue::RangeInt((_path, _)) => "range(int, int)",
            PathAwareValue::RangeFloat((_path, _)) => "range(float, float)",
            PathAwareValue::RangeChar((_path, _)) => "range(char, char)",
        }
    }

    pub(crate) fn retrieve_index<'v>(
        parent: &PathAwareValue,
        index: i64,
        list: &'v Vec<PathAwareValue>,
        query: &[QueryPart<'_>],
    ) -> Result<&'v PathAwareValue, Error> {
        if let Some(check) = index_offset(index, list.len()) {
            Ok(&list[check])
        } else {
            Err(Error::
                RetrievalError(
                    format!("Array Index out of bounds for path = {} on index = {} inside Array = {:?}, remaining query = {}",
                            parent.self_path(), index, list, SliceDisplay(query))
                ))
        }
    }

    pub(crate) fn accumulate<'v>(
        parent: &PathAwareValue,
        all: bool,
        query: &[QueryPart<'_>],
        elements: &'v Vec<PathAwareValue>,
        resolver: &dyn EvaluationContext,
    ) -> Result<Vec<&'v PathAwareValue>, Error> {
        if elements.is_empty() && !query.is_empty() && all {
            return Err(Error::RetrievalError(format!(
                "No entries for path = {} . Remaining Query {}",
                parent.self_path(),
                SliceDisplay(query)
            )));
        }

        let mut accumulated = Vec::with_capacity(elements.len());
        for each in elements {
            if !query.is_empty() {
                accumulated.extend(each.select(all, query, resolver)?);
            } else {
                accumulated.push(each);
            }
        }
        Ok(accumulated)
    }
}

/// Is an integer inside a float range, and a float inside an integer range.
///
/// `WithinRange` is generic over a single type, so `i64` has an impl for `RangeType<i64>` and `f64`
/// for `RangeType<f64>`, and the two mixed pairings have none. They fell through to `compare_values`,
/// which reports `int` against `range(float, float)` as incomparable -- so `Size IN r[5.0, 100.0]`
/// failed a `Size: 50` that sits inside the range, and `IN r[5, 100]` failed a `Size: 50.5`. A wrong
/// verdict rather than a wrong skip, and the same defect as the scalar case one function below: the
/// mixed-numeric widening landed on the scalar arms and stopped there.
///
/// Bounds are compared through `compare_int_to_float` for the reason given on that function. Casting
/// the integer to `f64` instead would round above 2^53 and silently move the bound, which on a range
/// check means quietly admitting or excluding a value at the edge.
fn int_within_float_range(value: i64, range: &RangeType<f64>) -> bool {
    let above_lower = match compare_int_to_float(value, range.lower) {
        Some(Ordering::Greater) => true,
        Some(Ordering::Equal) => range.inclusive & LOWER_INCLUSIVE > 0,
        _ => false,
    };
    let below_upper = match compare_int_to_float(value, range.upper) {
        Some(Ordering::Less) => true,
        Some(Ordering::Equal) => range.inclusive & UPPER_INCLUSIVE > 0,
        _ => false,
    };
    above_lower && below_upper
}

fn float_within_int_range(value: f64, range: &RangeType<i64>) -> bool {
    // `compare_int_to_float` orders the integer against the float, so each result is reversed to
    // read as the value against the bound.
    let above_lower = match compare_int_to_float(range.lower, value).map(Ordering::reverse) {
        Some(Ordering::Greater) => true,
        Some(Ordering::Equal) => range.inclusive & LOWER_INCLUSIVE > 0,
        _ => false,
    };
    let below_upper = match compare_int_to_float(range.upper, value).map(Ordering::reverse) {
        Some(Ordering::Less) => true,
        Some(Ordering::Equal) => range.inclusive & UPPER_INCLUSIVE > 0,
        _ => false,
    };
    above_lower && below_upper
}

/// Order an integer against a float without going through a lossy conversion.
///
/// `(i as f64).partial_cmp(f)` is the obvious spelling and it is wrong: `i64` values above 2^53
/// are not exactly representable in `f64`, so the cast rounds and two distinct values can compare
/// `Equal`. Casting the other way is exact once the float is known to be in range, because
/// `floor` is exact on `f64` and `as i64` then truncates a value that is already integral.
///
/// Returns `None` only for NaN, matching what `f64::partial_cmp` does for float-to-float.
fn compare_int_to_float(i: i64, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }

    // 2^63. `i64::MAX as f64` rounds *up* to this value, so comparing against `i64::MAX as f64`
    // would let f == 2^63 through, and the `as i64` below would then saturate to `i64::MAX` and
    // report a spurious `Equal`. Bound on 2^63 itself instead.
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    if f >= TWO_POW_63 {
        return Some(Ordering::Less); // every i64 is smaller
    }
    if f < -TWO_POW_63 {
        return Some(Ordering::Greater); // every i64 is larger
    }

    // -2^63 <= f < 2^63, so `floor` is representable as i64 and the cast is exact.
    let truncated = f.floor();
    Some(match i.cmp(&(truncated as i64)) {
        // Same integral part, so the float decides it: anything above its own floor has a
        // fraction left over and is therefore the larger of the two.
        Ordering::Equal if f > truncated => Ordering::Less,
        ordering => ordering,
    })
}

/// The index a [`QueryPart::Key`] stands for, and `None` when it stands for a key name.
///
/// `Items.0` is index access written without brackets, which is why a key is read as a number at all.
/// A map takes that same text as a key name, and deciding on the text alone made any key that reads
/// as an integer unaddressable: `Mappings.AccountToEnv."123456789012".Env` resolved to nothing on a
/// template that has exactly that key, and quoting it in the rule changed nothing, because the quotes
/// are gone by the time retrieval sees a `Key`. Quoting is how the language says "this is a name" --
/// it is what `docs/KNOWN_ISSUES.md` prescribes for a key containing a dash -- so there was no
/// spelling that worked. `"1.5"` resolved and `"80"` did not, which is the shape of an `i64` parse
/// rather than of anything to do with maps.
///
/// Account ids, ports and status codes are all real map keys that read as integers, and a rule that
/// names one silently matched nothing.
///
/// Both engines ask this question, so they get the same answer from one place.
pub(crate) fn list_index_of(current: &PathAwareValue, key: &str) -> Option<i64> {
    match current {
        PathAwareValue::List(_) => key.parse::<i64>().ok(),
        _ => None,
    }
}

/// The offset an array index refers to in a collection of `len` elements, or `None` when it refers to
/// none of them.
///
/// A negative index counts back from the end, which is what the syntax implies and what `[-1]` means
/// in every other tool that spells it that way. It used to be the magnitude: on `[a, b, c]`,
/// `Items[-1]` returned `b` and `Items[-3]` was reported out of bounds, so the offset was inverted and
/// off by one at the same time. Nothing asserted it in either direction, and the behaviour is
/// undocumented, which is how it survived -- `docs/CLAUSES.md` now describes it.
///
/// `try_from` rather than `as usize`, because the index is an `i64`: on a 32-bit target the cast would
/// truncate and could land back inside the collection, turning an out-of-range index into a wrong
/// element rather than a rejection.
pub(crate) fn index_offset(index: i64, len: usize) -> Option<usize> {
    let magnitude = usize::try_from(index.unsigned_abs()).ok()?;
    let offset = match index < 0 {
        true => len.checked_sub(magnitude)?,
        false => magnitude,
    };
    match offset < len {
        true => Some(offset),
        false => None,
    }
}

/// The `i64` a float is exactly equal to, if there is one.
///
/// Only `Hash` needs this, so that `Int(n)` and `Float(n as f64)` hash alike -- `compare_values`
/// makes them equal, and a `Hash` that disagreed with `eq` would be unsound. The bound is 2^63
/// rather than `i64::MAX as f64` for the reason given on [`compare_int_to_float`].
///
/// `-0.0` reports `Some(0)`, which is wanted: it compares equal to `0.0`, so the two must hash
/// alike, and their bit patterns differ.
fn float_as_exact_i64(f: f64) -> Option<i64> {
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    // The NaN test is kept separate even though the range check would also reject it, so that the
    // three reasons to have no exact integer stay legible: not a number, out of range, has a
    // fraction.
    if f.is_nan() || !(-TWO_POW_63..TWO_POW_63).contains(&f) || f.floor() != f {
        return None;
    }
    Some(f as i64)
}

fn compare_values(first: &PathAwareValue, other: &PathAwareValue) -> Result<Ordering, Error> {
    match (first, other) {
        //
        // scalar values
        //
        (PathAwareValue::Null(_), PathAwareValue::Null(_)) => Ok(Ordering::Equal),
        (PathAwareValue::Int((_, i)), PathAwareValue::Int((_, o))) => Ok(i.cmp(o)),
        (PathAwareValue::String((_, s)), PathAwareValue::String((_, o))) => Ok(s.cmp(o)),
        (PathAwareValue::Float((_, f)), PathAwareValue::Float((_, s))) => match f.partial_cmp(s) {
            Some(o) => Ok(o),
            None => Err(Error::NotComparable(
                "Float values are not comparable".to_owned(),
            )),
        },

        // A number is a number. Without these two arms `Size > 10` reports the template's own
        // value as not comparable the moment someone writes `50.5` instead of `50`, and in a
        // `when` condition that non-PASS becomes a SKIP, which exits 0 and takes the guarded
        // body with it. Pinned by `mixed_int_and_float_operands_compare_numerically`.
        (PathAwareValue::Int((_, i)), PathAwareValue::Float((_, f))) => {
            compare_int_to_float(*i, *f)
                .ok_or_else(|| Error::NotComparable("Float values are not comparable".to_owned()))
        }
        (PathAwareValue::Float((_, f)), PathAwareValue::Int((_, i))) => {
            compare_int_to_float(*i, *f)
                .map(Ordering::reverse)
                .ok_or_else(|| Error::NotComparable("Float values are not comparable".to_owned()))
        }

        (PathAwareValue::Char((_, f)), PathAwareValue::Char((_, s))) => Ok(f.cmp(s)),
        (_, _) => Err(Error::NotComparable(format!(
            "PathAwareValues are not comparable {}, {}",
            first.type_info(),
            other.type_info()
        ))),
    }
}

#[allow(clippy::never_loop)]
pub(crate) fn compare_eq(first: &PathAwareValue, second: &PathAwareValue) -> Result<bool, Error> {
    let (reg, s) = match (first, second) {
        (PathAwareValue::String((_, s)), PathAwareValue::Regex((_, r))) => {
            (Regex::try_from(r.as_str()).map_err(Box::new)?, s.as_str())
        }
        (PathAwareValue::Regex((_, r)), PathAwareValue::String((_, s))) => {
            (Regex::try_from(r.as_str()).map_err(Box::new)?, s.as_str())
        }

        (PathAwareValue::String((_, s1)), PathAwareValue::String((_, s2))) => return Ok(s1 == s2),

        (PathAwareValue::Map((_, map)), PathAwareValue::Map((_, map2))) => {
            return Ok('result: loop {
                if map.values.len() == map2.values.len() {
                    for (key, value) in map.values.iter() {
                        match map2.values.get(key) {
                            Some(value2) => {
                                if !compare_eq(value, value2)? {
                                    break 'result false;
                                }
                            }

                            None => {
                                break 'result false;
                            }
                        }
                    }
                    break 'result true;
                }
                break 'result false;
            })
        }

        (PathAwareValue::List((_, list)), PathAwareValue::List((_, list2))) => {
            return Ok('result: loop {
                //
                // Order does matter
                //
                if list.len() == list2.len() {
                    for (left, right) in list.iter().zip(list2.iter()) {
                        if !compare_eq(left, right)? {
                            break 'result false;
                        }
                    }
                    break 'result true;
                }
                break 'result false;
            });
        }

        (PathAwareValue::Bool((_, b1)), PathAwareValue::Bool((_, b2))) => return Ok(b1 == b2),

        (PathAwareValue::Regex((_, r)), PathAwareValue::Regex((_, s))) => return Ok(r == s),

        // Two ranges are equal when they describe the same range, which is what `PartialEq` already
        // says three arms of its own. `compare_eq` is the equality function `==` actually calls --
        // `EqOperation` hands it to `match_value` -- and it had no such arm, so its `(_, _)`
        // fall-through asked `compare_values`, whose only range arms are the membership cells below.
        // Two ranges landed on the incomparable catch-all, and `%allowed == r[80,90]` reported
        // `Value=[80,90] not equal to value [80,90]` with reason `not comparable range(int, int),
        // range(int, int)`. A reason that refutes itself on its face.
        //
        // Both polarities were affected, so a rule author had no working spelling: `!=` on the same
        // pair also refused, because the negation wrapper in `eval/operators.rs` inverts `Fail` and
        // `Success` and passes `NotComparable` through untouched -- correctly, since "could not be
        // answered" must not become a pass. `in [r[80,90]]` was the only spelling that worked, and only
        // because `contained_in` consults `PartialEq` first.
        //
        // Structural, matching `PartialEq`'s arms exactly rather than asking whether the two ranges
        // admit the same values: `r[1,3]` and `r[1,4)` over the integers admit the same set and are
        // written differently, and answering `==` on the admitted set would make equality depend on the
        // bound type in a way nothing else in the file does.
        //
        // The collection arms above recurse into `compare_eq`, so this also settles a map or list
        // holding a range: `{p: r[80,90]} == {p: r[80,90]}` refused for the same reason and now decides.
        (PathAwareValue::RangeInt((_, r)), PathAwareValue::RangeInt((_, r2))) => return Ok(r == r2),
        (PathAwareValue::RangeFloat((_, r)), PathAwareValue::RangeFloat((_, r2))) => {
            return Ok(r == r2)
        }
        (PathAwareValue::RangeChar((_, r)), PathAwareValue::RangeChar((_, r2))) => {
            return Ok(r == r2)
        }

        //
        // Range checks
        //
        (PathAwareValue::Int((_, value)), PathAwareValue::RangeInt((_, r))) => {
            return Ok(value.is_within(r))
        }

        (PathAwareValue::Float((_, value)), PathAwareValue::RangeFloat((_, r))) => {
            return Ok(value.is_within(r))
        }

        (PathAwareValue::Int((_, value)), PathAwareValue::RangeFloat((_, r))) => {
            return Ok(int_within_float_range(*value, r))
        }

        (PathAwareValue::Float((_, value)), PathAwareValue::RangeInt((_, r))) => {
            return Ok(float_within_int_range(*value, r))
        }

        (PathAwareValue::Char((_, value)), PathAwareValue::RangeChar((_, r))) => {
            return Ok(value.is_within(r))
        }

        (_, _) => {
            return match compare_values(first, second)? {
                Ordering::Equal => Ok(true),
                _ => Ok(false),
            }
        }
    };
    let match_result = reg.is_match(s);
    match match_result {
        Ok(is_match) => Ok(is_match),
        Err(error) => Err(Error::from(Box::new(error))),
    }
}

pub(crate) fn compare_lt(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Equal | Ordering::Greater => Ok(false),
            Ordering::Less => Ok(true),
        },
        Err(e) => Err(e),
    }
}

pub(crate) fn compare_le(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(false),
            Ordering::Equal | Ordering::Less => Ok(true),
        },
        Err(e) => Err(e),
    }
}

pub(crate) fn compare_gt(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(true),
            Ordering::Less | Ordering::Equal => Ok(false),
        },
        Err(e) => Err(e),
    }
}

pub(crate) fn compare_ge(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater | Ordering::Equal => Ok(true),
            Ordering::Less => Ok(false),
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "path_value_tests.rs"]
mod path_value_tests;
