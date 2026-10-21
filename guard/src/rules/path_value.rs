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
use super::{QueryResult, UnResolved, UnResolvedKind};
use crate::rules::eval::key_filter;
use crate::rules::exprs::LetValue;
use fancy_regex::Regex;
use serde::ser::{SerializeMap, SerializeStruct};
use std::hash::{Hash, Hasher};
use std::rc::Rc;

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
///
/// `evaluated` is the site of the write whose value the document resolved to. For a key written twice
/// in one mapping that is the last one, `repeated`; for a merged key that collided with a held key of
/// another form (`libyaml::loader::Loader::collisions`) it is the held entry, which across two merge
/// sources is the earlier line, `first`. The notice names it rather than assuming.
///
/// Every position is a site the key was written at. A key written through an alias (`*k: 2` after
/// `&k x: 1`) is named at the alias's own line, not at the anchor's, so a pair that is an anchored key
/// beside its alias reads as two lines, as a plain pair does, and two aliases of an anchor written
/// elsewhere read as the two alias lines. `evaluated` can then be a third site: a name written in plain
/// form between an anchored key and its alias (`&k x: 1`, `x: 2`, `*k: 3`) has the pair of its two
/// entries at lines 2 and 3 while the value that stands was written at line 4, and the record says so
/// ([`DuplicateKey::evaluated_sentence`]) rather than pointing the reader at a line whose text is not
/// the value evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DuplicateKey {
    pub(crate) path: String,
    pub(crate) first: Location,
    pub(crate) repeated: Location,
    pub(crate) evaluated: Location,
}

impl DuplicateKey {
    /// The sentence the notice ends with, naming the value that stands: "The first value is the one
    /// evaluated." when `evaluated` is the earlier of two distinct positions, "The last value is the one
    /// evaluated." when it is the later, and "The value written at `<position>` is the one evaluated."
    /// when it is neither, which happens when the standing value was written by an alias at a site the
    /// pair does not name. The first two are what every key written twice in plain form gets; the third
    /// is the one wording that is true whichever order an anchored key, its alias and a plain spelling
    /// of the name were written in, because it names the site itself instead of one of two that may
    /// both hold other text.
    pub(crate) fn evaluated_sentence(&self) -> String {
        if self.evaluated == self.repeated {
            "The last value is the one evaluated.".to_string()
        } else if self.evaluated == self.first {
            "The first value is the one evaluated.".to_string()
        } else {
            format!(
                "The value written at {} is the one evaluated.",
                self.evaluated
            )
        }
    }
}

/// The merged keys the libyaml loader dropped because they read as a held key of another form
/// (`libyaml::loader::apply_merges`), by where each collision happened: the `Location` of the mapping
/// that applied the merge, paired with the `Location` of the held key the merged key collided with,
/// to the positions of the merged keys. The loader records positions only; `try_from_marked_reporting`
/// turns each into a `DuplicateKey` when its walk of the finished document reaches the held key *in
/// that mapping*, so the record carries the path the value has after every merge is applied and names
/// the entry whose value stands, and a collision inside a subtree a later merge dropped is never
/// reached and never reported.
///
/// The mapping's position is part of the key because the held key's alone does not name one entry.
/// An alias stands for a copy of the anchored node, positions included, so `<<: *base` puts the
/// anchored mapping's keys, at the anchored mapping's positions, into every mapping that merges it,
/// and the anchored mapping itself keeps them where it was written. A record keyed by the held key
/// alone matched all of those entries, and a collision one merge produced was reported once per copy
/// of the anchor, with the anchor's own entry and every other merge of it named as a duplicate.
///
/// Two consequences of keying by the mapping's position. A merge source that is itself a mapping that
/// merged is taken apart by the enclosing merge and never walked, so `apply_merges` copies the records
/// it holds over to the enclosing mapping as the entries move; the walk then meets them there. And a
/// copy of the mapping that merged, made by an alias of that mapping, carries the mapping's own
/// position as well as its keys, so the record matches in the copy too and the notice is printed once
/// per copy, as a duplicate pair written inside an aliased mapping is reported once per copy.
///
/// A key written twice at one position travels here too, as its own kind of record: an anchored key
/// beside an alias of it, or two aliases of one anchor, is one entry to the loader's map, so the pair
/// cannot be two entries for the conversion to collapse; the loader counts how many more times the
/// position was written, and the conversion reports each as a duplicate at that entry. It is kept
/// apart from the merged records because it means something else: a merged record is attached at the
/// name's last entry, where the value the merge lost to stands; a repeated position is reported at its
/// own entry, once per extra write, and the value that stands is the name's last entry's, as for any
/// key written twice.
///
/// Beside the count, the same record keeps the site of every write an alias made to the key position
/// ([`KeyWrites::alias_sites`]): the alias's own line and column, which the copy it pushes does not
/// carry, since a copy keeps its anchor's position. Those sites are what the conversion names in a
/// record. Without them a pair that was an anchored key beside its alias read as one position written
/// twice, two aliases of an anchor written in another mapping named that other mapping's line, and a
/// plain spelling between an anchored key and its alias was told the "first" value stood when the
/// alias, at a line nothing named, had written the value that did.
///
/// The count and the sites are one record, written by one call per write (`add_key_write`) and carried
/// whole when a merge moves the entry (`carry_key_writes`), so the two cannot disagree: a second write
/// of a position is always an alias's copy, since two scalars of one document cannot share a line and
/// column, and a repeat that arrives with no site is recorded at the key's own position, so every
/// counted write has a site to be named at. Kept as two indices filled by two calls, a repeat recorded
/// with no site was a shape nothing refused, and the conversion, reading the sites first, would have
/// passed it in silence and lost its notice; a debug-only check at the writer closed that in test
/// builds and left it open in the build users run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeyCollisions {
    /// By the merging mapping's position and the held key's position: the merged keys' positions, in
    /// document order.
    merged: std::collections::HashMap<(Location, Location), Vec<Location>>,
    /// By the mapping's position and the key's position: how that position was written as a key of
    /// the mapping, beyond one plain write. A key written once in plain form has no entry.
    writes: std::collections::HashMap<(Location, Location), KeyWrites>,
}

/// How one key position of one mapping was written: how many times beyond the first, and the own
/// position of every alias that wrote it, in document order, the first write included when it was an
/// alias. A key the anchor wrote once and an alias wrote again has one repeat and one site, the
/// alias's; the plain write is the write the count holds beyond the sites, and it comes first, since
/// an alias follows its anchor. A repeat recorded without a site carries the key's own position as its
/// site, so `alias_sites` is never shorter than `repeats`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeyWrites {
    pub(crate) repeats: usize,
    pub(crate) alias_sites: Vec<Location>,
}

impl KeyCollisions {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.merged.is_empty() && self.writes.is_empty()
    }

    /// Records one write of the key at `key_at` of the mapping at `mapping_at`: made by the alias at
    /// `site` when there is one, and a repeat of the position when `repeated`. A plain first write
    /// records nothing. A repeat that arrives with no site is recorded at the key's own position: the
    /// position was already in the map, so the write happened, and the notice must count it even when
    /// the line it was written at is not known. Every repeat the loader makes is an alias's copy and
    /// comes with the alias's site, so this path is never taken by a document; it exists so that a
    /// write the loader failed to attribute degrades the notice's line, never its count. Refusing the
    /// call in a debug build instead left a release build free to record the count with no site, and
    /// the conversion, finding no site to name, reported that write as nothing.
    pub(crate) fn add_key_write(
        &mut self,
        mapping_at: Location,
        key_at: Location,
        site: Option<Location>,
        repeated: bool,
    ) {
        let site = match (site, repeated) {
            (None, false) => return,
            (None, true) => key_at,
            (Some(site), _) => site,
        };
        let record = self.writes.entry((mapping_at, key_at)).or_default();
        if repeated {
            record.repeats += 1;
        }
        record.alias_sites.push(site);
    }

    /// Carries the record of the key at `key_at` of the mapping at `source_at` over to the mapping at
    /// `mapping_at`, whole, for an entry a merge moved from the source into that mapping; nothing when
    /// the source holds no record for it.
    pub(crate) fn carry_key_writes(
        &mut self,
        source_at: Location,
        mapping_at: Location,
        key_at: Location,
    ) {
        let Some(carried) = self.writes.get(&(source_at, key_at)).cloned() else {
            return;
        };
        let record = self.writes.entry((mapping_at, key_at)).or_default();
        record.repeats += carried.repeats;
        record.alias_sites.extend(carried.alias_sites);
    }

    /// How the key at `key_at` of the mapping at `mapping_at` was written beyond one plain write; `None`
    /// for a key written once in plain form.
    pub(crate) fn writes_at(&self, mapping_at: Location, key_at: Location) -> Option<&KeyWrites> {
        self.writes.get(&(mapping_at, key_at))
    }

    /// The merged keys recorded against the held key at `held_at` of the mapping at `mapping_at`.
    pub(crate) fn merged_against(
        &self,
        mapping_at: Location,
        held_at: Location,
    ) -> Option<&Vec<Location>> {
        self.merged.get(&(mapping_at, held_at))
    }

    /// The record for the held key at `held_at` of the mapping at `mapping_at`, made if absent.
    pub(crate) fn merged_against_mut(
        &mut self,
        mapping_at: Location,
        held_at: Location,
    ) -> &mut Vec<Location> {
        self.merged.entry((mapping_at, held_at)).or_default()
    }

    /// The same records with every position mapped through `f`: the JSON route puts a loaded document
    /// back on the source text's positions, records included.
    pub(crate) fn with_positions(self, f: impl Fn(Location) -> Location) -> Self {
        KeyCollisions {
            merged: self
                .merged
                .into_iter()
                .map(|((mapping_at, held), merged)| {
                    (
                        (f(mapping_at), f(held)),
                        merged.into_iter().map(&f).collect(),
                    )
                })
                .collect(),
            writes: self
                .writes
                .into_iter()
                .map(|((mapping_at, key_at), writes)| {
                    (
                        (f(mapping_at), f(key_at)),
                        KeyWrites {
                            repeats: writes.repeats,
                            alias_sites: writes.alias_sites.into_iter().map(&f).collect(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Every merged position recorded, over every held key: the count the tests read as the collisions
    /// the loader recorded.
    #[cfg(test)]
    pub(crate) fn merged_count(&self) -> usize {
        self.merged.values().map(Vec::len).sum()
    }
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

/// `{text}[{location}]`, through `shown_with_location` with the path's own text, so `Display` and a
/// rendering of a cut text are one rendering.
impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown_with_location(&self.0))
    }
}

impl Path {
    pub(crate) fn root() -> Self {
        Path("".to_string(), Location::default())
    }

    /// `shown`, a rendering of this path's text (the text itself, or the text with its middle cut and
    /// marked), followed by the location: `{shown}[{location}]`. The ONE place a text is joined to the
    /// location: `Display` passes the path's own text through it, and `eval_context::template_path`
    /// passes the text it shows, whole or cut, so the two cannot render the location differently.
    pub(crate) fn shown_with_location(&self, shown: &str) -> String {
        format!("{shown}[{}]", self.1)
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

            // Hashed as the one-character string it is, not as a `char`. `compare_values` relates
            // `Char('b')` to `String("b")`, and the fall-through in `PartialEq` delegates to
            // `compare_values`, so `eq` says the two are equal. `Hash for char` is
            // `state.write_u32(*self as u32)` and `Hash for str` is
            // `state.write(self.as_bytes()); state.write_u8(0xff)`, so for `'b'` the hasher was handed
            // `62 00 00 00` in one case and `62 ff` in the other -- equal values, different hashes,
            // which is the contract `equal_values_hash_equally` exists to hold.
            //
            // Same class of break as the `Float` cast below and unnoticed for the same reason: the one
            // live consumer keys on map keys, which are always strings.
            //
            // `encode_utf8` into a stack buffer rather than `to_string()`, so the bytes go through
            // `str`'s impl -- which is the impl the equal `String` uses -- without allocating.
            PathAwareValue::Char((_, c)) => {
                let mut buf = [0u8; 4];
                c.encode_utf8(&mut buf).hash(state);
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
            // Where a verdict can be reported, it is, and the list of spellings that reach a reporting
            // comparator is worth keeping honest. `X == /re/` asks `compare_eq`. `X in [/re/]` reaches
            // `contained_in`, which asks `compare_eq` as well and reports its error. `%q == %r` and
            // `%q != %r` between two queries reach `EqOperation`'s both-operands-are-queries branch,
            // which asks `compare_eq_symmetric` per pair and reports what comes back; deciding there
            // with `Vec::contains`, which is this `eq`, would swallow the error here where nothing can
            // report it, and `!=` on two incomparable properties would pass at exit 0 with nothing in
            // the report.
            //
            // "So no comparison *verdict* is decided through this arm any more" is what this paragraph
            // said, qualified only by `Vec::contains` inside `reverse_diff` -- which asks whether a
            // value is one of the ones already put in a diff rather than what the clause answers. That
            // qualification is incomplete, and the sentence it qualifies is false.
            //
            // `InOperation::compare`'s `(Some, None)` arm is the second route, and there the answer IS
            // what the clause answers: with no list among the right-hand values and a list-valued
            // literal on the left, it decides membership element-wise with `Vec::contains`, which is
            // this `eq`, and `compare_eq` is not consulted on that path. So a refusal swallowed here --
            // `compare_values(String, Int)` for `[5]` against `["5"]`, read as `false` -- is a verdict
            // there, which makes this a `NotComparable` suppression on the `IN` path that the inventory
            // above `InOperation` in `eval/operators.rs`, which counts the `compare_eq` ones, does not
            // list. The arm's own code is the record of its current shape and of which polarities the
            // route reaches; what is invariant is that the verdict is decided by `PartialEq`, where no
            // reason can be reported.
            //
            // Recorded at length because a claim that the comparison operators do not come through
            // here, or a qualification that names only one of the two routes, hides this one.
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
            // symmetric and transitive; a membership arm here, answering "is this scalar inside that
            // range", would make `eq` neither reflexive nor symmetric. Membership is `compare_eq`'s
            // job and stays there.
            //
            // Without these arms a range is not equal to *itself*: the fall-through asks
            // `compare_values`, which reports two ranges as incomparable, and `impl Eq` below then
            // promises a reflexivity the type does not have.
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
/// in `report_by_lhs`. That is safe for a reason rather than by luck -- its keys come from the
/// document under validation, and a `Regex` only ever arrives as a rule literal on the right-hand
/// side of a comparison.
///
/// Range membership is not answered here either: a membership arm would break symmetry outright,
/// `Int(50) == RangeInt(5..100)` holding while the reverse did not for want of a reverse arm.
/// Membership is `compare_eq`'s job and it keeps its own range table. That table is one-directional,
/// as such arms are, so `compare_eq_symmetric` is where `==` gets the operand order put right, because
/// `compare_eq` is shared with `IN`, for which one-directional is correct. Membership arms would not
/// belong here even mirrored: `eq` is `Vec::contains`'s comparator, and a range reaching it that way
/// needs the structural answer rather than the membership one.
///
/// A range nested in a list literal does still arrive here, through `Vec::contains` in
/// `contained_in`, and that is what the removed arms were not reaching: `contains` asks
/// `element == value`, so it needed the reverse arm, the one that never existed. Membership through a
/// list was therefore answered `false` for every range, in both polarities, until `contained_in`
/// started asking `compare_eq` as well. The arms stay out; the caller asks the function that has the
/// table.
///
/// Two widenings do stay, both reached through `compare_values`: a number against a number across
/// `Int` and `Float`, and a `Char` against the one-character `String` that spells it. Unlike the regex
/// arm each is an equivalence relation on the values it relates, and `Hash` agrees with both -- a
/// `Float` that is exactly an integer hashes as that integer, and a `Char` hashes as its one-character
/// string.
///
/// Those two `Hash` arms are obligations this comment creates rather than incidental facts about it.
/// The fall-through in `PartialEq` delegates to `compare_values`, so **every arm added to
/// `compare_values` widens `eq`**, and has to be matched in `Hash` in the same commit or the type stops
/// satisfying the `Eq` it claims. The `Char`/`String` arms were added without that step and the two
/// hashed differently until it was caught; `equal_values_hash_equally` now pins both widenings so the
/// next one cannot land silently.
///
/// For the same reason the type has no `PartialOrd`, and must not be given one. Rust requires
/// `a.partial_cmp(b) == Some(Ordering::Equal)` exactly when `a == b`, and no ordering can satisfy that
/// against a match relation: a regex would have to order `Equal` with every string it matches and
/// those strings order differently from each other. An impl that compared `self_path().0`, the path
/// string, and ignored the value would disagree with `eq` in both directions -- every rule literal is
/// built with `Path::root()` and so shares the path `""`, so `partial_cmp` would report `Equal` for
/// any two literals in any rules file, `15` against `"abc"` included, while two equal values read from
/// different properties would order `Less` or `Greater`; `sort_by(|a, b| a.partial_cmp(b).unwrap())`
/// is one line away and would order by path.
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

/// The two positions in document order: by line, then by column.
fn document_order(a: Location, b: Location) -> (Location, Location) {
    if (a.line, a.col) <= (b.line, b.col) {
        (a, b)
    } else {
        (b, a)
    }
}

/// What `try_from_marked_reporting` needs to know about a mapping's keys before it walks the entries:
/// for each entry, the index of the first entry of its name and the site of the last's standing write,
/// and, keyed by that last index, the merged keys the loader recorded as colliding with any entry of
/// the name in this mapping, the one at `mapping_at`.
///
/// One pass over the keys, hashing each name once by reference, with nothing allocated per key: the
/// per-name table borrows the names and is dropped before the entries are walked by value. The record
/// for a repeated key needs the last entry of the name, which is ahead of the repeat in the walk, so a
/// pre-pass is the only way to name the value that stands without a second pass after the walk; the
/// same table says where a collision's record belongs (at the name's last entry) and which entry it
/// pairs the merged key with.
///
/// An entry's position is where its key scalar was written, which for an alias's copy is the anchor's
/// line. A record names write SITES instead: the first site of an entry is its own position when the
/// anchor wrote it here, or the first alias's line when every write was an alias; its last site is the
/// last alias's line when one wrote it, else its position. The loader recorded, in one record per
/// position (`KeyCollisions::writes_at`), the alias sites and how many writes beyond the first the
/// position took: writes beyond the alias sites are the one plain write, the anchor's, which comes
/// first because an alias follows its anchor.
struct MappingPlan {
    first_of: Vec<usize>,
    /// By entry index: the site of the entry's first write.
    first_sites: Vec<Location>,
    /// By entry index: the site of the entry's last write, whose value is the entry's.
    last_sites: Vec<Location>,
    last_of: Vec<usize>,
    collided_at_last: std::collections::HashMap<usize, Vec<Location>>,
    /// By entry index: the sites of the entry's writes after the first (an anchored key beside an
    /// alias of it, or a second alias of one anchor). Reported at that entry, not at the name's last,
    /// since it is not a merge the name lost to but one more write of the same key.
    later_writes: std::collections::HashMap<usize, Vec<Location>>,
}

impl MappingPlan {
    fn of(
        entries: &[((String, Location), MarkedValue)],
        mapping_at: Location,
        collisions: &KeyCollisions,
    ) -> MappingPlan {
        let mut by_name: std::collections::HashMap<&str, (usize, usize)> =
            std::collections::HashMap::with_capacity(entries.len());
        let mut first_of = Vec::with_capacity(entries.len());
        let mut first_sites = Vec::with_capacity(entries.len());
        let mut last_sites = Vec::with_capacity(entries.len());
        for (idx, ((name, loc), _)) in entries.iter().enumerate() {
            let slot = by_name.entry(name.as_str()).or_insert((idx, idx));
            slot.1 = idx;
            first_of.push(slot.0);
            first_sites.push(*loc);
            last_sites.push(*loc);
        }
        let last_of: Vec<usize> = entries
            .iter()
            .map(|((name, _), _)| by_name[name.as_str()].1)
            .collect();
        let mut collided_at_last: std::collections::HashMap<usize, Vec<Location>> =
            std::collections::HashMap::new();
        let mut later_writes: std::collections::HashMap<usize, Vec<Location>> =
            std::collections::HashMap::new();
        if !collisions.is_empty() {
            // Looked up with this mapping's own position, so a record attaches to the mapping that
            // merged and to a copy of it, never to another mapping that merely holds the same keys:
            // the anchored mapping those keys were copied from, and another mapping that merged the
            // same anchor, carry the same key positions under their own positions and do not match.
            // A copy of this mapping made by an alias carries this position too, and matches.
            for (idx, ((_, loc), _)) in entries.iter().enumerate() {
                if let Some(merged) = collisions.merged_against(mapping_at, *loc) {
                    collided_at_last
                        .entry(last_of[idx])
                        .or_default()
                        .extend(merged.iter().copied());
                }
                // One record holds the count and the sites, so a position with a repeat always has a
                // site to name; a key written once in plain form has no record and keeps its own
                // position as its one site.
                let Some(key_writes) = collisions.writes_at(mapping_at, *loc) else {
                    continue;
                };
                // The writes in order: the anchor's own, at the key's position, when the position
                // took one write more than the aliases made, then each alias at its own site.
                let writes = key_writes.repeats + 1;
                let plain_first = writes > key_writes.alias_sites.len();
                let mut sites: Vec<Location> = Vec::with_capacity(writes);
                if plain_first {
                    sites.push(*loc);
                }
                sites.extend(key_writes.alias_sites.iter().copied());
                first_sites[idx] = sites[0];
                last_sites[idx] = sites[sites.len() - 1];
                if sites.len() > 1 {
                    later_writes.insert(idx, sites[1..].to_vec());
                }
            }
        }
        MappingPlan {
            first_of,
            first_sites,
            last_sites,
            last_of,
            collided_at_last,
            later_writes,
        }
    }

    /// The sites of entry `idx`'s writes after its first: one record each.
    fn later_writes(&self, idx: usize) -> &[Location] {
        self.later_writes.get(&idx).map_or(&[], Vec::as_slice)
    }

    /// The index of the first entry with the same name as entry `idx`; `idx` itself for a first
    /// appearance.
    fn first_of(&self, idx: usize) -> usize {
        self.first_of[idx]
    }

    /// The site of entry `idx`'s first write: where a reader finds the key.
    fn location(&self, idx: usize) -> Location {
        self.first_sites[idx]
    }

    /// The site of the standing write of the last entry with the same name as entry `idx`: where the
    /// value that stands was written.
    fn last_location(&self, idx: usize) -> Location {
        self.last_sites[self.last_of[idx]]
    }

    /// The merged keys that collided with the name of entry `idx`, given at the name's last entry only,
    /// so the records come out once, where the kept value is.
    fn collided_at(&self, idx: usize) -> Option<&[Location]> {
        if self.last_of[idx] != idx {
            return None;
        }
        self.collided_at_last.get(&idx).map(Vec::as_slice)
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
        Self::try_from_marked_reporting(incoming, &KeyCollisions::new(), duplicates)
    }

    /// The conversion, also turning the loader's recorded merge collisions (`KeyCollisions`) into
    /// duplicate-key records as the walk reaches each held key.
    ///
    /// Emitted here rather than by the loader because this walk is the one that knows where a value
    /// finally lands: a merge source's mapping closes under `<<` before the merge that places it is
    /// applied, a tagged container sits under its `Fn::` name only once it is closed, and a source a
    /// later merge drops as a same-key override is never walked at all. Each record pairs the merged
    /// key with the entry whose value this conversion kept -- the last entry of the name in the
    /// mapping, which is `evaluated` -- so when the held name is itself written twice the notice
    /// names the value that stands, not the first spelling of it. The records for a mapping follow
    /// its own duplicate pairs, so a name both repeated and collided with reports the repeat first.
    pub(crate) fn try_from_marked_reporting(
        incoming: (MarkedValue, Path),
        collisions: &KeyCollisions,
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
                    let value = Self::try_from_marked_reporting(
                        (each, sub_path.with_location(loc)),
                        collisions,
                        duplicates,
                    )?;
                    result.push(value);
                }

                Ok(PathAwareValue::List((path, result)))
            }

            MarkedValue::Map(map, loc) => {
                let entries: Vec<((String, Location), MarkedValue)> = map.into_iter().collect();
                let plan = MappingPlan::of(&entries, loc, collisions);
                let mut keys = Vec::with_capacity(entries.len());
                let mut values = indexmap::IndexMap::with_capacity(entries.len());
                for (idx, ((each_key, loc), each_value)) in entries.into_iter().enumerate() {
                    let sub_path = path.extend_string(&each_key);
                    let sub_path = sub_path.with_location(*each_value.location());
                    // The key's path text is copied once per entry: a first appearance carries it as
                    // the key's own path (below), and a repeat's or a collision's record names it.
                    // Pathing the key to itself needs the text for every name, so there is no copy to
                    // save by making it only for the entries that get a record.
                    let first = plan.first_of(idx);
                    let collided = plan.collided_at(idx);
                    let key_path = sub_path.0.clone();
                    let value = Self::try_from_marked_reporting(
                        (each_value, sub_path),
                        collisions,
                        duplicates,
                    )?;
                    // `keys` gets an entry only for a name's first appearance. `values` is an
                    // `IndexMap` and dedups; `keys` did not, so a document with a repeated key left the
                    // two different lengths -- and `eval_context` pairs them *positionally*
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
                    // first appearance, which is what `IndexMap` does for the value too. Which
                    // appearance this is, and where the last one of the name sits, the plan read off
                    // the keys before the walk, so a repeat's record can name the entry whose value
                    // stands: the last of the name, not the repeat just seen.
                    //
                    // The key is pathed to itself, `/Resources/Bad`, with its own line and column, as
                    // the serde constructor above and `merge` below path the same key by name. Pathing
                    // it to the mapping that holds it, `/Resources`, would make a failing comparison
                    // on a captured key name the resource under `test` and `run_checks` and lose it
                    // under `validate`, the one route that comes through here. The keyed path is the
                    // one that says which resource; the location is the
                    // key's rather than the value's, which is where the author will look for it.
                    if first == idx {
                        keys.push(PathAwareValue::String((
                            Path(key_path.clone(), loc),
                            each_key.clone(),
                        )));
                    } else {
                        // In document order. The entries are in the order the loader inserted them,
                        // which is the document's except for a key written again at a position the
                        // mapping already held (an alias of an anchored key after a plain spelling of
                        // the name): the loader moves that entry to the end so that the value written
                        // last stands, and the pair's two positions then read out of order. The
                        // positions are each entry's first write site; the value that stands was
                        // written at the name's last entry's last site, which can be a third line (the
                        // alias's) that the pair does not name, and the record says so.
                        let (first_at, repeated_at) =
                            document_order(plan.location(first), plan.location(idx));
                        duplicates.push(DuplicateKey {
                            path: key_path.clone(),
                            first: first_at,
                            repeated: repeated_at,
                            evaluated: plan.last_location(idx),
                        });
                    }
                    values.insert(each_key, value);
                    // This entry's own position written again as a key of this mapping: an anchored
                    // key beside an alias of it, or two aliases of one anchor, which the loader could
                    // hold only as one entry. One record per later write, at this entry, pairing the
                    // first write's site with the later write's own (the alias's line, which the copy
                    // it pushed did not carry), and the name's last entry's standing write as the one
                    // evaluated. Reported here rather than at the name's last entry, because it is not
                    // a merge the name lost to: the name's own pair, when it is written in plain form
                    // as well, has its record above, and attaching this one there re-paired it into
                    // that record and printed the same notice twice.
                    for site in plan.later_writes(idx) {
                        duplicates.push(DuplicateKey {
                            path: key_path.clone(),
                            first: plan.location(idx),
                            repeated: *site,
                            evaluated: plan.last_location(idx),
                        });
                    }
                    // A merged key the loader dropped against this name, recorded here at the name's
                    // last entry, the one whose value stands: after the pair's own record, and before
                    // any later key's children are walked, so the records come out in document order.
                    // The pair is given in document order too, with the kept entry's standing write as
                    // the evaluated one; a kept entry an alias wrote is named at the alias's line.
                    if let Some(merged) = collided {
                        let in_order =
                            |a: Location, b: Location| (a.line, a.col) <= (b.line, b.col);
                        let kept = plan.location(idx);
                        for merged_at in merged {
                            let (first, repeated) = if in_order(kept, *merged_at) {
                                (kept, *merged_at)
                            } else {
                                (*merged_at, kept)
                            };
                            duplicates.push(DuplicateKey {
                                path: key_path.clone(),
                                first,
                                repeated,
                                evaluated: plan.last_location(idx),
                            });
                        }
                    }
                }
                Ok(PathAwareValue::Map((
                    path.with_location(loc),
                    MapValue { keys, values },
                )))
            }

            // The text is the node as written. A reason, when the loader attached one, is what made
            // a plausible payload unreadable and what to write instead; it is added here, after the
            // position, so that the value and its position read as they always have.
            MarkedValue::BadValue(val, None, loc) => Err(Error::ParseError(format!(
                "Bad Value encountered parsing incoming file Value = {}, Loc = {}",
                val, loc
            ))),
            MarkedValue::BadValue(val, Some(reason), loc) => Err(Error::ParseError(format!(
                "Bad Value encountered parsing incoming file Value = {}, Loc = {}: {}; {}",
                val,
                loc,
                reason.why(),
                reason.fix()
            ))),
            // A node the loader refused carries the refusal, which names its own position, so it is
            // the message as it is. Rendering it as a bad value read "Value = the merge key `<<` at
            // L:26,C:9 must be given a mapping ..., Loc = L:26,C:5": a refusal presented as a value,
            // with the position given twice.
            MarkedValue::Refused(refusal, _) => Err(Error::ParseError(refusal)),
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

            // A variable shares the arm: its name is never an integer, and the `is_variable` branch
            // below is the one that interpolates it.
            QueryPart::Key(key) | QueryPart::Variable(key) => {
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
                                // `consumed` is how many parts this arm has used up: the interpolated
                                // key, plus the index that chose among the resolved names when there
                                // is one. Starting the recursion below at `query[1]` for every shape
                                // would apply an index just applied to the key list a second time, to
                                // the value the chosen key selected: `Resources.%names[0].Type` would
                                // pick the first name and then try to index into that resource's map,
                                // an empty selection, or with `all` an error naming
                                // `Remaining Query = 0.Type`, and `Type` never read. The live engine's
                                // interpolation path counts its consumed parts the same way.
                                let (keys, consumed) = if query.len() > 1 {
                                    match query[1] {
                                        // `AuthoredIndices` reads as the bare `[*]` it is. The
                                        // fallthrough is an `IncompatibleError`, so omitting it here
                                        // would turn a spelling this walker accepts into a refusal.
                                        QueryPart::AllIndices(_)
                                        | QueryPart::AuthoredIndices
                                        | QueryPart::Key(_)
                                        | QueryPart::Variable(_) => (keys, 1),
                                        QueryPart::Index(index) => {
                                            match index_offset(index, keys.len()) {
                                                Some(check) => (vec![keys[check]], 2),
                                                None => (self.map_some_or_error_all(all, query)?, 2),
                                            }
                                        },

                                        _ => return Err(Error::IncompatibleError(
                                            format!("THIS type of variable interpolation is not supported {}, {}", self.type_info(), SliceDisplay(query))
                                        ))
                                    }
                                } else {
                                    (keys, 1)
                                };
                                for each_key in keys {
                                    if let PathAwareValue::String((_, k)) = each_key {
                                        if let Some(next) = map.values.get(k) {
                                            acc.extend(next.select(
                                                all,
                                                &query[consumed..],
                                                resolver,
                                            )?);
                                        } else if all {
                                            return Err(Error::
                                                RetrievalError(
                                                    format!("Could not locate key = {} inside object/map = {:?}, Path = {}, remaining query = {}",
                                                            query[0], self, path, SliceDisplay(query))
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

            // `AuthoredIndices` is a bare `[*]`, so this walker treats it as one. The variant records
            // which of the two wrote the part, and nothing in `select` asks: the slot decision it makes
            // below at `query[1]` is left exactly as it was, so this walker's answers do not move.
            QueryPart::AllIndices(..) | QueryPart::AuthoredIndices => {
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
                    // The right-hand side as the live engine's key filter sees it, in two steps that
                    // happen in the same order there. First as written -- one `QueryResult` per
                    // literal or resolved value, a list still a list -- which is what the widening
                    // reads: a list on the right, of any length, makes `==` membership. Then expanded
                    // one level by `interpolated_keys`, the expansion the live engine performs for the
                    // same comparison, so that `keys in ['a', 'b']` compares each key against `'a'` and
                    // against `'b'` rather than against the list; a nested `[['a']]` expands to the
                    // single value `['a']` and no further. Widening after the expansion read a
                    // one-element list as one value and kept `==`, so `[ keys == [r[a,f]] ]` selected
                    // nothing here and in the live engine alike while `[ keys == [r[a,f], r[x,z]] ]`
                    // selected the covered keys.
                    fn resolved(values: Vec<&PathAwareValue>) -> Vec<QueryResult> {
                        values
                            .into_iter()
                            .map(|value| QueryResult::Resolved(Rc::new(value.clone())))
                            .collect()
                    }
                    // Whether a right-hand query that failed to resolve failed because one of its
                    // enumerations (`[*]` or `.*`) ran over a collection with nothing in it: the query up
                    // to that enumeration resolves, and every value it reaches is an empty list, an
                    // empty map or a null. A query with no enumeration, or none of whose prefixes
                    // resolves to only such values, failed for a value the document lacks.
                    fn enumerates_an_empty_collection(
                        query: &[QueryPart<'_>],
                        root: &PathAwareValue,
                        resolver: &dyn EvaluationContext,
                    ) -> bool {
                        // Every enumeration is a candidate, not only the last: over
                        // `Names[*].Inner[*]` with `Names: []` the first enumeration is the one that
                        // ran over nothing, and the prefix up to the last one cannot be resolved at
                        // all (a query remains after the empty `Names`, which this resolver reports
                        // as an error), so probing the last alone read the empty set as a value the
                        // document lacks and failed the filter closed where the live engine, whose
                        // retrieval leaves its marker at the first empty collection, decides it.
                        query
                            .iter()
                            .enumerate()
                            .filter(|(_, part)| {
                                matches!(
                                    part,
                                    QueryPart::AllIndices(_)
                                        | QueryPart::AuthoredIndices
                                        | QueryPart::AllValues(_)
                                )
                            })
                            .any(|(enumeration, _)| {
                                match resolve_query(true, &query[..enumeration], root, resolver) {
                                    Ok(values) => {
                                        !values.is_empty()
                                            && values.iter().all(|value| match value {
                                                PathAwareValue::List((_, elements)) => {
                                                    elements.is_empty()
                                                }
                                                PathAwareValue::Map((_, map)) => {
                                                    map.values.is_empty()
                                                }
                                                PathAwareValue::Null(_) => true,
                                                _ => false,
                                            })
                                    }
                                    Err(_) => false,
                                }
                            })
                    }
                    let rhs: Vec<QueryResult> = match &filter.compare_with {
                        // Resolved with `all` on first, so that a value the query cannot reach is seen.
                        // With `all` off a missing path yields nothing and the fold sees a shorter list,
                        // and `keys not in Allowed[*].Key` over an `Allowed` whose second element has
                        // no `Key` then asked only "differs from the first?" and selected every other
                        // key. The live engine carries such a value as an unresolved entry, and the
                        // shared fold reads an unresolved entry that is not the empty-enumeration
                        // marker as a comparison it cannot finish, failing the filter closed under
                        // every comparator with the path the retrieval stopped at; this arm hands the
                        // fold the same entry, resolving what it can and adding one unresolved entry
                        // for what it could not, so it is refused the same way.
                        LetValue::AccessClause(query) => {
                            match resolve_query(true, &query.query, self, resolver) {
                                Ok(values) => resolved(values),
                                Err(Error::RetrievalError(reason))
                                | Err(Error::IncompatibleRetrievalError(reason)) => {
                                    let mut entries =
                                        resolved(resolve_query(false, &query.query, self, resolver)?);
                                    // An enumeration over a collection with nothing in it is not a
                                    // value the document lacks. The live engine's retrieval leaves a
                                    // marker typed `EmptyEnumeration` for `Names[*]` over `Names: []`,
                                    // and `key_filter::normalize_rhs` reads that marker as a right-hand
                                    // side with no value in it, so the filter is decided by polarity.
                                    // This resolver only sees the error, so it asks the question the
                                    // marker answers: does the query up to ANY of its enumerations
                                    // reach nothing but empty collections (or nulls)? If so the error
                                    // was that enumeration finding no entry, and the same typed
                                    // marker is pushed; otherwise the document lacks something on the
                                    // way, and the entry stays an unresolved right-hand side. Any
                                    // enumeration, not the last: `Names[*].Inner[*]` over `Names: []`
                                    // is empty at the first, and the prefix up to the last cannot be
                                    // resolved at all (`enumerates_an_empty_collection`).
                                    let kind = match enumerates_an_empty_collection(
                                        &query.query,
                                        self,
                                        resolver,
                                    ) {
                                        true => UnResolvedKind::EmptyEnumeration,
                                        false => UnResolvedKind::Absent,
                                    };
                                    entries.push(QueryResult::UnResolved(UnResolved {
                                        traversed_to: Rc::new(self.clone()),
                                        remaining_query: format!("{}", SliceDisplay(&query.query)),
                                        reason: Some(reason),
                                        kind,
                                    }));
                                    entries
                                }
                                Err(other) => return Err(other),
                            }
                        }

                        LetValue::Value(path_value) => {
                            vec![QueryResult::Literal(Rc::new(path_value.clone()))]
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

                    // This arm reads `comparator` as well as `compare_with`. Matching on `compare_with`
                    // alone would evaluate every spelling as equality: `keys != 'a'` would select
                    // exactly the key `a`, the set `keys == 'a'` selects, and `keys not in ['a', 'b']`
                    // would select nothing, because a key is never equal to a list, with the parser's
                    // `NotEq` and `NotIn` never read.
                    //
                    // What a comparator means for a key is decided in `eval::key_filter`, the one
                    // entry point both this arm and the live engine's `real_binary_operation` ask, so
                    // the two cannot drift. The evidence it returns is for the records the live
                    // engine keeps; this arm has none. A comparison the engine could not finish fails
                    // the selection closed, as it does there, rather than shrinking it by a key nobody
                    // decided about.
                    // How the right-hand query reaches its values, read off its PARTS: this resolver has
                    // no retrieval notes, where the live engine reads the walk's own report. The reading
                    // is `RhsEnumeration::of_parts`, one definition beside the live engine's
                    // `part_projects`, so the two engines name a shape the same way; this arm carried two
                    // copies of that rule and they had drifted (a variable-interpolated key projects
                    // live, and `Groups.%names` read each group as its key set here). The LAST part
                    // enumerating or selecting makes each resolved value a member (`Entries[*]`, a
                    // filter, `%names` as the last key), where an EARLIER part enumerating and the rest
                    // descending keys (`Groups.*.Buckets`) makes each value what one member holds at that
                    // key, a map among them its key set. One flag for any enumeration anywhere read
                    // `Groups.*.Buckets` as `LastPart`, kept each group's `Buckets` map whole and
                    // selected no key under either `IN` or `NOT IN`, where the live engine read the key
                    // set. An enumerating query is a set at any length, so `keys == %names[*]` over a
                    // one-element binding selects what `keys == %names` does, here as in the live
                    // engine; a literal and a function call enumerate nothing.
                    //
                    // Except the parser's reserved slot. Slot 1 of a variable-rooted query with a
                    // remainder is an `AllIndices(None)` the parser inserts, not the author's `[*]`
                    // (that one is `AuthoredIndices`), and the live engine consumes it without a mark
                    // on its notes, so `%names[0]` names one value and `%names.k` names one key's value.
                    // Counting the slot read `keys == %names[0]` as enumerating here, widened it to
                    // membership and selected the covered keys, while the live engine kept `==` and
                    // selected nothing: one query, two answers.
                    //
                    // KNOWN DRIFT, the one the parts cannot close: a bare binding name. The live engine
                    // keeps the shape notes of the query a binding was assigned from, so `%spread`
                    // bound to `%one[*]` is a set through its bare name, as the enumeration it stands
                    // for. This resolver asks its `EvaluationContext` for a binding's values and the
                    // trait has no method that says how those values were reached, so `keys == %spread`
                    // reads one value where it has one and keeps `==`. Closing it means a shape method
                    // on `EvaluationContext`, which is a trait change for a resolver no command path
                    // reaches; both parity tables carry the row and name the drift.
                    let rhs_shape = match &filter.compare_with {
                        LetValue::AccessClause(query) => {
                            crate::rules::eval_context::RhsEnumeration::of_parts(&query.query)
                        }
                        LetValue::Value(_) | LetValue::FunctionCall(_) => {
                            crate::rules::eval_context::RhsEnumeration::Names
                        }
                    };
                    let rhs_enumerated = rhs_shape.is_entry_set();
                    // The entries that stand for "no value here" (an empty enumeration's marker, a
                    // null) are dropped before anything counts or compares, by the one function the
                    // live engine's key filter asks too, so an empty exemption list exempts nothing on
                    // either engine, and a map the query named is its key set where a map the query
                    // enumerated to is a member. The maps the author's `[*]` passed on unchanged as the
                    // last part are named, not members, and this resolver has no retrieval notes to
                    // say which values those were; it reads them off the parts and the paths instead:
                    // a query ending `Key[*]` handed on every map value whose path ends in that key
                    // (`Mappings.Exempt.Names[*]` over `Names: { BucketA: true }` resolves to the map
                    // at `/Mappings/Exempt/Names`), where a list under that key enumerates to members
                    // at paths one segment longer. `%v[*]`, whose binding this resolver cannot see
                    // (the known drift above), passes nothing it can name. The path's last segment IS
                    // the key, slash and all: a key that holds a `/` (`app.kubernetes.io/name`) spans
                    // what `rsplit('/')` read as two segments and matched against neither.
                    let passed_on: Vec<Path> = match (&filter.compare_with, rhs_enumerated) {
                        (LetValue::AccessClause(query), true) => match query.query.as_slice() {
                            [.., QueryPart::Key(key), QueryPart::AllIndices(_) | QueryPart::AuthoredIndices] => {
                                rhs.iter()
                                    .filter_map(|each| match each {
                                        QueryResult::Resolved(value) if value.is_map() => {
                                            Some(value.self_path())
                                        }
                                        _ => None,
                                    })
                                    .filter(|path| {
                                        path.0
                                            .strip_suffix(key.as_str())
                                            .is_some_and(|prefix| prefix.ends_with('/'))
                                    })
                                    .cloned()
                                    .collect()
                            }
                            _ => vec![],
                        },
                        _ => vec![],
                    };
                    let rhs_passed_on = crate::rules::eval_context::PassedOn::of(passed_on);
                    let normalized = key_filter::normalize_rhs(&rhs, rhs_shape, &rhs_passed_on);
                    let rhs = normalized.values;
                    let cmp = key_filter::key_comparator(
                        filter.comparator,
                        &rhs,
                        rhs_enumerated || normalized.named_a_map,
                    );
                    let rhs = crate::rules::eval_context::interpolated_keys(&rhs);
                    let mut selected = Vec::with_capacity(map.values.len());
                    for key in map.keys.iter() {
                        let selection = key_filter::select_key(cmp, Rc::new(key.clone()), &rhs);
                        if let Some(reason) = selection.undecided {
                            return Err(Error::UndecidableComparison(reason));
                        }
                        if selection.selected {
                            match key {
                                PathAwareValue::String((_, v)) => {
                                    selected.push(map.values.get(v).unwrap());
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
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
                                                // As in `evaluate::resolve_variable_query`: answering
                                                // the same as `AllIndices` is what leaves this
                                                // walker's answers unmoved by the variant existing.
                                                QueryPart::AllIndices(_)
                                                | QueryPart::AuthoredIndices => 2,
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
/// verdict rather than a wrong skip, and the same defect as the scalar case one function below: a
/// mixed-numeric widening that covers the scalar arms and stops there.
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
/// The evaluator and the legacy resolver both ask this question, so they get the same answer from one
/// place.
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
/// in every other tool that spells it that way; `docs/CLAUSES.md` describes it. Reading the magnitude
/// instead would be inverted and off by one at the same time: on `[a, b, c]`, `Items[-1]` would return
/// `b` and `Items[-3]` would be reported out of bounds.
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

/// The refusal for a float that cannot be ordered, which in practice is a NaN.
///
/// Shared so that the range-membership arms of `compare_eq` refuse in the same words `compare_values`
/// does. The message says "Float values" rather than naming NaN because the condition it reports is
/// `partial_cmp` answering `None`, and that is what the caller can act on.
fn float_is_not_comparable() -> Error {
    Error::NotComparable("Float values are not comparable".to_owned())
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
            None => Err(float_is_not_comparable()),
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

        // A `Char` against a `String`, ordered as the one-character string it is.
        //
        // Without these two arms `parse_char`'s output could not be checked against anything a rules
        // file can write. There is no `Char` literal in the language: `parse_scalar_value` is
        // `alt((parse_string, parse_float, parse_int_value, parse_bool, parse_regex))`, and
        // `parse_char` is reachable from `range_value` only, so `'1'` and `"1"` both parse as
        // `Value::String`. The documented example for the function --
        // `let converted = parse_char(..)` then `%converted == '1'` -- therefore failed for every
        // input, with `not comparable char, String` blaming the template's type. It is the only one of
        // the five converters whose result cannot be compared with a literal; `parse_int`,
        // `parse_float`, `parse_boolean` and `parse_string` all produce a value that matches one.
        //
        // In `compare_values` rather than in `compare_eq`, so that ordering gets the same answer as
        // equality. Adding it to `compare_eq` alone would have left `%c == "b"` deciding while
        // `%c < "c"` refused, which is the shape of asymmetry this file has had to fix twice.
        //
        // Ordered as strings, not gated on the string's length. Refusing a multi-character string would
        // make comparability depend on a value rather than on a pair of types, and `<` needs a total
        // order to be any use. `'b'` against `"bc"` is Less, which is what the same two values would
        // have compared as if `parse_char` had not been applied -- and that equivalence is the point:
        // conversion should not change the answer to a comparison the language could already make.
        // Byte-wise `str` ordering agrees with code-point ordering under UTF-8, so this is consistent
        // with the `(Char, Char)` arm above.
        //
        // The narrowest fix, and not the only candidate. `parse_char` could have returned a
        // one-character `String` instead, which needs no new arms -- but a `String` does not compare
        // with a `RangeChar` either (`"b" in r[a,z]` refuses), so that would break `%c in r[a,z]`,
        // which works today and is the other half of what the function is for. Whether `Char` should
        // exist in the value space at all is a real question, and a `String`-against-`RangeChar` arm is
        // what would settle it; that is a wider change than this finding.
        (PathAwareValue::Char((_, c)), PathAwareValue::String((_, s))) => Ok(c.to_string().cmp(s)),
        (PathAwareValue::String((_, s)), PathAwareValue::Char((_, c))) => Ok(s.cmp(&c.to_string())),

        (_, _) => Err(Error::NotComparable(format!(
            "PathAwareValues are not comparable {}, {}",
            first.type_info(),
            other.type_info()
        ))),
    }
}

// How many times `compare_eq` has run on this thread, for tests that pin how often a comparison is
// made rather than what it answers. Thread-local because the test harness runs tests on their own
// threads, so one test's count cannot leak into another's. Absent from a release build.
#[cfg(test)]
thread_local! {
    pub(crate) static COMPARE_EQ_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[allow(clippy::never_loop)]
pub(crate) fn compare_eq(first: &PathAwareValue, second: &PathAwareValue) -> Result<bool, Error> {
    #[cfg(test)]
    COMPARE_EQ_CALLS.with(|calls| calls.set(calls.get() + 1));

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
        // Without it two ranges fall to the incomparable catch-all, and `%allowed == r[80,90]` reports
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

        // A NaN refuses rather than answering false, which is what the four range-membership
        // comparisons on a float would otherwise do. `is_within` is `le`/`lt`/`ge`/`gt` and
        // `float_within_int_range` reads `compare_int_to_float`'s `None` through a `_ => false` arm, so
        // every one of them reports "not in the range" for a value that cannot be ordered against
        // either bound. That is a decision, and `!=` and `NOT IN` then invert it into a pass, so a
        // denylist would admit a value that is not a number. Every other comparison against a NaN
        // already refuses, through `compare_values` and `compare_int_to_float`, and both polarities of a
        // refusal fail the clause -- these four were the only ones answering.
        //
        // **No input can reach it as the tree stands, and it is kept anyway.** When this was written the
        // scenario was live: a `Float(NaN)` did arrive from a document. It cannot now, because the serde
        // loader gained a finiteness gate afterwards (in `impl TryFrom<&serde_yaml::Value> for Value`,
        // which stringifies a non-finite float to `.nan` / `.inf` / `-.inf`), and every other way a
        // `Float` is built from input has one. There are four more, five gates in all: the untagged arm
        // of `libyaml::loader::Loader::handle_scalar_event`; the `!!float` arm it dispatches to in
        // `handle_type_ref`, which went without a gate for a while, so `!!float nan` did arrive here and
        // the reporter aborted converting it to a serde number; the rules-file float literal in
        // `rules::parser::parse_float`, where a non-finite literal is a parse error; and the `to_float`
        // function's own `functions::converters::parse_float`, which yields no value for one.
        // `serde_json::Number` cannot hold a NaN in the first place -- JSON has no spelling for one, and
        // `1e400` in a JSON data file loads as the string `"1e400"` through the YAML reader rather than
        // as an infinity.
        //
        // So it becomes reachable again the moment any of those five gates goes, or a sixth construction
        // site appears -- which is a property of the callers and not of this match, exactly as for the
        // `Err(_) => false` arm in `PartialEq` above. Not `unreachable!()` for the same reason given
        // there: that would turn each of those changes into a panic inside a comparison, and a widened
        // contract reaching a panic is worse than a widened contract reaching a refusal. The guard is
        // one `is_nan` call on a path that already does four comparisons.
        //
        // Only the scalar is tested. A range's bounds come from `parse_range` in the rules parser,
        // which builds them with `parse_float`, and that rejects a literal which is not finite -- so a
        // `RangeFloat` cannot hold a NaN bound and a guard for one would be unreachable.
        //
        // The reason text is `compare_values`'s own for the same condition, because it is the same
        // condition: a float that cannot be ordered.
        (PathAwareValue::Float((_, value)), PathAwareValue::RangeFloat((_, r))) => {
            return match value.is_nan() {
                true => Err(float_is_not_comparable()),
                false => Ok(value.is_within(r)),
            }
        }

        (PathAwareValue::Int((_, value)), PathAwareValue::RangeFloat((_, r))) => {
            return Ok(int_within_float_range(*value, r))
        }

        (PathAwareValue::Float((_, value)), PathAwareValue::RangeInt((_, r))) => {
            return match value.is_nan() {
                true => Err(float_is_not_comparable()),
                false => Ok(float_within_int_range(*value, r)),
            }
        }

        (PathAwareValue::Char((_, value)), PathAwareValue::RangeChar((_, r))) => {
            return Ok(value.is_within(r))
        }

        // A null is equal to a null and to no text, number, boolean, character, map or list, and that
        // is a decision, not a refusal.
        //
        // Without these arms a null on one side only fell through to `compare_values`, whose only
        // null arm is `(Null, Null)`, and came back `NotComparable`. A refusal fails both polarities:
        // the negation wrapper in `eval/operators.rs` inverts `Fail` and `Success` and passes
        // `NotComparable` through untouched, correctly, since "could not be answered" must not become
        // a pass. So `X != null` could never PASS on any input, `X == null` on a present value failed
        // for the reason "not comparable String, null" rather than "not equal", and a gate written
        // `when %volumes.Ebs != null { ... }` or `when Resources.V.Ebs != null { ... }` for "Ebs is
        // set" never opened, skipping the body it guards at exit 0 for every template. With the null on
        // the left, `KmsKeyId != 'a'` on a `KmsKeyId: null` PASSes rather than refusing, and
        // `KmsKeyId in [...]` / `not in [...]` decide instead of refusing, so a denylist is satisfied by
        // a null and the incomparable-membership notice does not fire for one.
        //
        // The kinds are named rather than matched with `_`. A range or a regex against null stays on
        // the refusal path below: "is null inside r[0,1023]" and "does null match /^public-/" have no
        // answer, and a `false` there would let `Port != r[0,1023]` and `Name != /^public-/` PASS on a
        // property that is present and null.
        //
        // In `compare_eq` and not in `compare_values`, deliberately, and against the pattern the
        // `Char`-against-`String` arms above argue for. Equality against null has an answer; ordering
        // against null does not, and `compare_lt` and friends should keep refusing `Size > null`
        // rather than inventing a place for null in the order. `(Null, Null)` is repeated here so
        // that the null cells are read together; `compare_values` keeps its own copy for the
        // ordering operators, where two nulls are still `Equal`.
        (PathAwareValue::Null(_), PathAwareValue::Null(_)) => return Ok(true),
        (
            PathAwareValue::Null(_),
            PathAwareValue::String(_)
            | PathAwareValue::Int(_)
            | PathAwareValue::Float(_)
            | PathAwareValue::Bool(_)
            | PathAwareValue::Char(_)
            | PathAwareValue::Map(_)
            | PathAwareValue::List(_),
        )
        | (
            PathAwareValue::String(_)
            | PathAwareValue::Int(_)
            | PathAwareValue::Float(_)
            | PathAwareValue::Bool(_)
            | PathAwareValue::Char(_)
            | PathAwareValue::Map(_)
            | PathAwareValue::List(_),
            PathAwareValue::Null(_),
        ) => return Ok(false),

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

/// `compare_eq` with the operands put in the order its range table expects, for the operators that
/// have no left and right.
///
/// `compare_eq` is a match function rather than an equality function, whatever its name says: its five
/// range arms ask "is this scalar inside that range", and they are all written scalar-on-the-left
/// because every caller but one has a subject and a pattern. `IN` does -- `Port IN r[80,90]` tests
/// `Port` against the range and never the reverse -- and so do the map key filters and the `NOT IN`
/// deprecation probe.
///
/// `==` is the exception. It relates two values with no subject among them, and it is symmetric by
/// contract; `impl Eq for PathAwareValue` says so, and calls the identical one-directional shape in
/// `PartialEq` a symmetry bug. Asked directly, `compare_eq` gave `Resources.R.Properties.A ==
/// r[80,90]` a PASS and `%l == Resources.R.Properties.A` for the same two values `not comparable
/// range(int, int), int`.
///
/// So the swap lives here, at the operator that needs it, rather than as five more arms in the table.
/// Mirroring the table was tried first and reaches four other callers, three of which then answer a
/// question nobody asked: `%range in [15]` becomes "15 is inside the range" instead of "the range is
/// one of these elements", the key filter's membership loop, as it then was, does the same, and
/// `incomparable_membership` stops emitting
/// its `NOT IN` deprecation notice because the comparison it probes with now succeeds. Measured, not
/// predicted -- the mirrored version moved six `IN`/`NOT IN` cells of the operator matrix, and `in`
/// membership is exactly what must not move. The notice half of that is unmeasured: the predicate
/// flattens both operands, so which pairs it probes with differs from a whole-value reading, and a claim
/// about the notice needs its own measurement. The six moved cells are the reason the mirror was
/// rejected and they are about the operator, not the notice.
///
/// Exactly the five pairings the table has, and no others. Swapping every range-against-non-range pair
/// was the first version and it moved the wording of forty refusals: a range against a `bool` has no arm
/// in either order, so the swap changed nothing about the verdict and made `compare_values` report
/// `not comparable bool, range(char, char)` for a clause written `%range == true`. Naming the operands
/// in the opposite order to the clause is the defect F10 is about; a fix for one asymmetry must not
/// introduce it somewhere else. So a pair with no reverse arm keeps the order it arrived in, and its
/// reason still reads left-to-right.
///
/// One consequence the caller list above does not spell out, and it is the widest thing the swap did.
/// `EqOperation`'s literal-on-the-left branch has a `single_value` arm that unwraps a right-hand `List`
/// and compares the left operand against **each element** (`impl Comparator for EqOperation`). With a range on
/// the left that arm now answers `%range == <query yielding a list>` element-wise, so a clause a reader
/// parses as "these two are the same thing" answers "every one of these is inside the range". It refused
/// before, at exit 19.
///
/// Deliberately left as it is, because the alternatives are worse in both directions. The mirror --
/// `<query yielding a list> == %range` -- has distributed element-wise since before this swap, through
/// the same unwrapping in the opposite branch, so refusing on this side would restore the asymmetry the
/// swap exists to remove and `impl Eq for PathAwareValue` calls a bug. Nor is the new answer a rubber
/// stamp: it discriminates. `r[0,10]` against a query yielding `[1, 99]` fails, and against one yielding
/// `[1, "x"]` fails in both polarities. It is also the same comparison as
/// `%range == <query yielding a scalar>`, which is squarely what the swap is for, and a one-element list
/// answers the same way a bare scalar does.
///
/// What remains open, and is not this function's to settle: the literal spelling of the same clause,
/// `%range == [1, 2]`, still refuses -- on both sides of the round and in both operand orders. So the
/// language answers a list-against-range comparison when the list arrives through a query and refuses
/// when it is written out. That axis pre-dates the swap; the swap widened it by one cell. Closing it
/// means deciding whether `list == range` should have meant membership in the first place, which is the
/// same question as whether `Char` belongs in the value space, and neither is a change to make from here.
///
/// Two ranges are left alone as well. `compare_eq` relates them structurally and is already symmetric
/// there, and swapping would only change which of the two the message names first.
pub(crate) fn compare_eq_symmetric(
    first: &PathAwareValue,
    second: &PathAwareValue,
) -> Result<bool, Error> {
    match (first, second) {
        (
            PathAwareValue::RangeInt(_) | PathAwareValue::RangeFloat(_),
            PathAwareValue::Int(_) | PathAwareValue::Float(_),
        )
        | (PathAwareValue::RangeChar(_), PathAwareValue::Char(_)) => compare_eq(second, first),

        _ => compare_eq(first, second),
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
