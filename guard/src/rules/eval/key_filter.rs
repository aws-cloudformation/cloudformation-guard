//! Map key filters, `[ keys <cmp> <rhs> ]`, decided in one place.
//!
//! The evaluator and the legacy resolver, two code paths in one binary, ask this module and nothing
//! else: `real_binary_operation` in the live engine, which also records the evidence `select_key` hands
//! back, and the `MapKeyFilter` arm of the legacy `QueryResolver::select` in `path_value.rs`, which
//! records nothing. Each path carried its own copy of these rules before they were gathered here, and
//! the copies disagreed three times over: the legacy resolver ignored the comparator altogether; the
//! evaluator read a string key `in` a string element as a substring test; and the evaluator's evidence
//! pass unwrapped a one-element list literal a second time where the legacy resolver did not, so
//! `[ keys == [['a']] ]` selected `a` on one path and nothing on the other. A verdict that lives in one
//! function cannot be two verdicts.
//!
//! The rules, in the order `select_key` applies them:
//!
//! - [`crate::rules::eval::key_filter::normalize_rhs`] drops the entries that stand for no value (the marker of an enumeration over
//!   an empty collection, a null, an empty list or map) and reads a map the right-hand query NAMED
//!   (`%exempt` bound to `Mappings.Exempt.Buckets`, a literal `{ BucketA: true }`) as its KEY SET,
//!   one value per key. A map the query ENUMERATED to (`%buckets` bound to a filter over `Resources`,
//!   `Entries[*]` over a list of maps) is a member of the set the enumeration produced and is kept
//!   whole; a string key against it has no answer, as against a list. Which of the two a map is comes
//!   from the retrieval's own report that the query enumerated, not from the map.
//! - [`crate::rules::eval::key_filter::key_comparator`] reads the right-hand side BEFORE it is expanded, and widens `==` and `!=` to
//!   membership when that side is a set: a list, literal or resolved, of any length; a query that
//!   enumerated (`%r[*]`, `KeyList[*]`, `Allowed[*].Key`), whatever it produced; a named map read as
//!   its key set, of any size; or more than one right-hand value. The shape decides, not the count of
//!   values the expansion produces, so a one-element list literal `[r[a,f]]` is compared the way
//!   `[r[a,f], r[x,z]]` is, `%r[*]` over a one-element binding the way `%r` is, and a one-key map the
//!   way a two-key map is; adding an unrelated element to a list cannot change how the first element
//!   compares.
//! - The right-hand side then arrives at `select_key` expanded one level, the way `interpolated_keys`
//!   expands a list-valued binding, so `keys in ['a', 'b']` and `keys in %names` both arrive as the
//!   values `'a'` and `'b'`. Nothing here unwraps further: `[['a']]` arrives as the single value
//!   `['a']`, and a string key against a list has no answer. That is the rule the scalar `==` settled
//!   for a nested one-element list -- the one unwrap a list literal earns is the expansion.
//! - [`crate::rules::eval::key_filter::key_pair_compare`] is the one comparison, under the widened comparator. A regex element matches
//!   as a pattern and a range element as a range, and a string is equal to a string, not to a string
//!   that contains it.
//! - A pair the comparator refuses as a kind mismatch has no answer.
//! - `==` and `in` select a key equal to one value. `!=` and `not in` select a key equal to none, so
//!   the negated fold is ALL rather than the inverse of ANY, and a pairing with no answer is enough to
//!   keep a key out of the selection under either of them: a denylist with a hole in it does not admit
//!   a key on the strength of the half that resolved. A right-hand side with no value at all is the
//!   empty set: no key is in it, so `==` and `in` select none, and every key is outside it, so `!=` and
//!   `not in` select every key. [`crate::rules::eval::key_filter::normalize_rhs`] is what makes a right-hand side empty when its query
//!   enumerated a collection with nothing in it, or reached a null, and [`crate::rules::eval::key_filter::empty_set_selects`] is the
//!   one answer to the empty set, which the live engine asks before it records and the fold asks over
//!   no comparisons, so an empty exemption list exempts nothing on either engine.
//! - A comparison the engine could not finish -- a regex out of backtracking budget -- is not a kind
//!   mismatch and cannot be read as "did not match". For a key no other pairing settled it fails the
//!   whole selection closed, with the reason `unanswerable_reason` gives it, which is the text the
//!   live engine's records already use. A key another pairing matched is settled whatever the
//!   unfinished one would have said -- in the set under `==` and `in`, out of it under `!=` and
//!   `not in` -- and is decided, not failed. So does a right-hand value the query could not reach:
//!   it was meant to be in the set and nobody can say whether the key equals it, so for a key no
//!   resolved member matched the keys the filter selects cannot be decided, and it fails closed under
//!   every comparator naming the path the retrieval stopped at. Read as "no answer" it kept the key
//!   out and said nothing, and an exemption list the template lacks exempted every key from its check
//!   at exit 0.
//!
//! Each pair is compared once. The evidence the live engine records and the outcome the fold reads
//! come from the same call, which is why `select_key` returns both rather than a verdict alone.

use std::rc::Rc;

use super::operators::{compare_eq_for_membership, Unanswerable};
use super::{
    keep_latest_refusal_else_registered_else_first_ranking, map_key_refusal, ComparisonResult,
    ComparisonWithRhs, LhsRhsPair, NotComparableWithRhs, Ranking, UnResolvedRhs,
};
use crate::rules::errors::RefusalToken;
use crate::rules::eval_context::{PassedOn, RhsEnumeration};
use crate::rules::exprs::MapKeyComparator;
use crate::rules::path_value::{compare_eq, PathAwareValue};
use crate::rules::{Error, QueryResult, UnResolvedKind};

/// The right-hand side as the set of names it denotes: the entries that stand for "no value here"
/// removed, and a map read as its key set.
///
/// The entries that stand for no value: the marker the retrieval leaves for an enumeration over an
/// EMPTY collection (`Names[*]` or `Names.*` over `Names: []` or `{}`, typed
/// `UnResolvedKind::EmptyEnumeration`), a null (`Names:` with nothing after it in YAML), which is the
/// value a key holds when it holds nothing, and a collection with nothing in it, resolved or literal.
/// A resolved one is what the retrieval hands back when the query names the empty collection itself
/// rather than enumerating it: `[*]` over a map is a pass-through, so `Names[*]` over `Names: {}`
/// resolves to the empty map, and a bare `let names = Mappings.Exempt.Names` over `{}` or `[]` resolves
/// to the collection. A literal one is the author's `let exempt = []` or `let exempt = {}`. None is a
/// value the filter could not read; each is a collection with nothing in it, and a right-hand side left
/// with no entry is the empty set, which [`key_selected_from`] decides by polarity. Read as a value,
/// the resolved empty map was a kind a string key cannot be compared with, so no key was selected under
/// either polarity and `keys NOT IN %names` over an empty exemption MAP reported SKIP at exit 0 having
/// checked nothing, where the same filter over an empty exemption LIST checked every key. An
/// `UnResolved` of any other kind, a value the document lacks (an absent parameter, a member without
/// the field, an index past the end), is kept, and the fold reads it as a right-hand side the filter
/// cannot decide.
///
/// A map with something in it, resolved or literal, is its KEY SET: one entry per key, so
/// `keys NOT IN %exempt` with `let exempt = Mappings.Exempt.Buckets` over `Buckets: { BucketA: true }`
/// selects every key but `BucketA`, and `keys IN %exempt` selects `BucketA`. That is the reading an
/// empty map already had, the empty set, continued to a map with members: a map's names are its keys,
/// and the value under a key is a mark an author leaves beside a name (`true`, a comment, a reason),
/// not a name. Read as one value, a map with members was a kind a string key cannot be compared with,
/// so no key was selected under either polarity: `keys NOT IN %exempt` checked every resource over
/// `Buckets: {}` and checked none, at exit 0, the moment one exemption entry was added. Each key keeps
/// the tag of the map it came from, so a literal map's keys are literals and a resolved map's keys are
/// resolved values at their own paths, and more than one key widens `==` to membership through
/// [`key_comparator`] as a list would. A map nested in a list (`[{ a: 1 }]`) is a MEMBER of the set,
/// not the set, and is left as it is: the expansion yields it as one value, which a string key has no
/// answer against, as in the previous release.
///
/// The evaluator and the legacy resolver both call this BEFORE they expand the right-hand values one
/// level and before they count or compare, so that an empty exemption list exempts nothing on either and
/// an exemption map exempts its keys on either: the live engine in `real_binary_operation`, and the
/// legacy `MapKeyFilter` arm in `path_value.rs`, which builds the same typed marker when its own
/// resolution of the right-hand query finds the enumerated collection empty. Before the expansion is
/// what keeps a MEMBER apart from the set: a literal `[[]]` is one entry holding a one-element list and
/// is kept here; the expansion then yields its one member, the empty list, which is a value the author
/// wrote and a member of the set, not the set being empty. A string key against a list is a pairing with
/// no answer, so no key is selected under either polarity, as in the previous release. A literal empty
/// list is dropped here, as the resolved one is: the same empty set by the shorter road.
///
/// A map with entries on the right is read two ways, and `rhs_shape`, the retrieval's own report, tells
/// them apart PER VALUE. A map the query NAMED (`let exempt = Mappings.Exempt.Buckets`, a literal `{
/// BucketA: true }`, `Mappings.Exempt.Names[*]` over `Names: { BucketA: true }`, whose `[*]` handed the
/// map on unchanged, `Mappings.Exempt.*.Buckets`, whose key step names each group's map) is its key set:
/// one value per key, so `keys IN %exempt` selects `BucketA`. A map the query ENUMERATED to (`%buckets`
/// bound to `Resources[ Type == 'AWS::S3::Bucket' ]`, `Entries[*]` over a list of maps) is a MEMBER of
/// the set the enumeration produced, kept whole: the enumeration's values are the set, whatever kind
/// they are, and a string key against a map is a pairing with no answer, as against a list. Read as key
/// sets, the selected buckets' field names (`Type`, `Properties`) became the names `keys NOT IN %buckets`
/// compared against, and every resource was selected; and `Entries[*]` over `[{ Name: BucketA }]`
/// selected a resource called `Name` where the bare `Entries`, which arrives as a list of the same maps,
/// selected none. The two spellings of one collection now agree. Decided by one flag for the whole
/// query, the passed-on map was a member too: `let exempt = Mappings.Exempt.Names[*]` over `Names: {}`
/// checked every key, and over `Names: { BucketA: true }` kept the map whole, selected no key and
/// reported SKIP at exit 0, so the first exemption entry switched the check off. The flag is per value
/// now (`rhs_passed_on`, the retrieval's record of the maps the `[*]` passed on, by path), so
/// `Mappings.*.Names[*]` over a list-valued and a map-valued `Names` reads the list's members and the
/// map's keys. Nothing below the top level is expanded either way: `[{ a: true }]` holds one member,
/// the map.
pub(crate) fn normalize_rhs(
    rhs: &[QueryResult],
    rhs_shape: RhsEnumeration,
    rhs_passed_on: &PassedOn,
) -> NormalizedRhs {
    let mut named_a_map = false;
    let values = rhs
        .iter()
        .filter(|each| !stands_for_no_entry(each))
        .flat_map(|each| {
            // Decided per VALUE, from what the retrieval reported about each map: a map the last part
            // enumerated to or selected is a member; a map the author's `[*]` passed on unchanged as
            // the last part, a map a key step named after an earlier enumeration (`Exempt.*.Buckets`)
            // and a map a query with no enumeration named are the map the query named, its key set.
            // One flag for the whole query read `Names[*]` over `Names: { BucketA: true }` as a member
            // and selected no key, and `Mappings.*.Names[*]` over a list-valued and a map-valued
            // `Names` cannot be read right by any one flag.
            let a_member = match each {
                QueryResult::Resolved(value) | QueryResult::Literal(value) => {
                    rhs_shape == RhsEnumeration::LastPart && !rhs_passed_on.names(value.self_path())
                }
                QueryResult::UnResolved(_) => true,
            };
            match a_member {
                true => vec![each.clone()],
                false => match as_key_set(each) {
                    Some(keys) => {
                        named_a_map = true;
                        keys
                    }
                    None => vec![each.clone()],
                },
            }
        })
        .collect();
    NormalizedRhs {
        values,
        named_a_map,
    }
}

/// What [`normalize_rhs`] made of a key filter's right-hand side.
pub(crate) struct NormalizedRhs {
    /// The right-hand values the keys are compared against: a named map's keys in its place, every
    /// other entry as it arrived, the entries that stand for no value dropped.
    pub(crate) values: Vec<QueryResult>,
    /// Whether a NAMED map with entries was read as its key set. A key set is a set at any size, so the
    /// widening in [`key_comparator`] reads this beside `rhs_enumerated`: `keys == %exempt` over a
    /// one-key map is membership as over two. Read from the count of values instead, a one-key map
    /// stayed `==` and a two-key map widened, which is the count deciding that [`key_comparator`]'s
    /// own comment rules out.
    pub(crate) named_a_map: bool,
}

/// A map entry as its keys, one entry per key with the map's own tag; `None` for any other entry. The
/// empty map never arrives: [`normalize_rhs`] drops it first as an entry that stands for no value.
fn as_key_set(entry: &QueryResult) -> Option<Vec<QueryResult>> {
    let (value, literal) = match entry {
        QueryResult::Resolved(value) => (value, false),
        QueryResult::Literal(value) => (value, true),
        QueryResult::UnResolved(_) => return None,
    };
    match &**value {
        PathAwareValue::Map((_, map)) => Some(
            map.keys
                .iter()
                .map(|key| {
                    let key = Rc::new(key.clone());
                    match literal {
                        true => QueryResult::Literal(key),
                        false => QueryResult::Resolved(key),
                    }
                })
                .collect(),
        ),
        _ => None,
    }
}

fn stands_for_no_entry(entry: &QueryResult) -> bool {
    match entry {
        QueryResult::UnResolved(unresolved) => {
            matches!(unresolved.kind, UnResolvedKind::EmptyEnumeration)
        }
        QueryResult::Resolved(value) | QueryResult::Literal(value) => match &**value {
            PathAwareValue::Null(_) => true,
            PathAwareValue::List((_, list)) => list.is_empty(),
            PathAwareValue::Map((_, map)) => map.is_empty(),
            _ => false,
        },
    }
}

/// The comparator a key filter is evaluated with, given its right-hand side as written, before the
/// one-level expansion: equality against a set is membership.
///
/// A set is a list on the right -- a list literal, or a query result that holds a list -- of any
/// length; a right-hand query that enumerated, `rhs_enumerated`, whatever it produced; or more than
/// one right-hand value, which is how a query over several elements arrives. The shape decides, not
/// the number of values the expansion produces. A count read after the expansion would let a
/// one-element list expand to one value and stay `==`: `[ keys == [r[a,f]] ]` would ask
/// `compare_eq`, which refuses a string against a char range, and select nothing, while
/// `[ keys == [r[a,f], r[x,z]] ]` would be widened to `in`, ask the membership comparator, and select
/// `b`, so an unrelated second element would change how the first one compared. A bare scalar on the
/// right is not a set, so `keys == 'a'` and `keys == r[a,f]` stay `==`.
///
/// `rhs_is_a_set` is what the values cannot say about their own shape, from two reports: the
/// retrieval's, that the right-hand query expanded or selected (`%r[*]`, `KeyList[*]`,
/// `Allowed[*].Key`), since `%r[*]` over a one-element binding and a bare `r[a,f]` both arrive as one
/// `RangeChar`; and [`normalize_rhs`]'s, that a NAMED map was read as its key set
/// (`NormalizedRhs::named_a_map`), since the one key of `{ a: true }` arrives as the one string a bare
/// `'a'` does. Without the first the count decided again for the `[*]` spellings, and `keys == %r[*]`
/// selected nothing over `let r = [r[a,f]]` while `keys == %r` over the same binding selected `a`
/// and `b`. Without the second a one-key map stayed `==` and a two-key map widened. An enumerating
/// query is a set at any length, as the interpolation of a `KeyList[*]` of one key already is, and so
/// is a key set.
///
/// The one call of `MapKeyComparator::as_membership` on the key-filter path. The widened comparator
/// decides the verdict and nothing the live engine's records show: those take the shape of the
/// operator the author wrote and name it, so a `keys == [...]` is reported as `==` however it was
/// decided.
pub(crate) fn key_comparator(
    cmp: MapKeyComparator,
    rhs: &[QueryResult],
    rhs_is_a_set: bool,
) -> MapKeyComparator {
    let is_list = |each: &QueryResult| match each {
        QueryResult::Literal(value) | QueryResult::Resolved(value) => {
            matches!(**value, PathAwareValue::List(_))
        }
        QueryResult::UnResolved(_) => false,
    };
    match rhs_is_a_set || rhs.len() > 1 || rhs.iter().any(is_list) {
        true => cmp.as_membership(),
        false => cmp,
    }
}

/// The one comparison a key filter makes of a key against a right-hand value, under a comparator
/// [`key_comparator`] has already widened.
///
/// Split by comparator so that membership has a site of its own. `in` and `not in` are membership
/// questions and ask the operators' one membership comparator, `compare_eq_for_membership`, the
/// function `contained_in` and its siblings ask, which reads a one-character string as the character
/// before asking a char range so that `[ keys IN r[a,f] ]` answers a one-character key as
/// `Key IN r[a,f]` does; the two comparators differ in that pairing alone. That arm is the one site of
/// the key filter that knows about it, and no other site needs to. `==` and `!=` ask `compare_eq` in
/// any case, because `"b" == r[a,f]` is not a question a range answers, and a `==` against a set has
/// been widened to `in` before it arrives here.
pub(crate) fn key_pair_compare(
    cmp: MapKeyComparator,
    key: &PathAwareValue,
    value: &PathAwareValue,
) -> Result<bool, Error> {
    match cmp {
        MapKeyComparator::In | MapKeyComparator::NotIn => compare_eq_for_membership(key, value),
        MapKeyComparator::Eq | MapKeyComparator::NotEq => compare_eq(key, value),
    }
}

/// What one key-against-value comparison said, classified once.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum KeyPairOutcome {
    /// The comparator answered.
    Equal(bool),
    /// No answer: a kind mismatch. The key is selected under neither polarity on the strength of this
    /// pairing. A right-hand value the query could not reach is not this; it is `Unfinished`, below.
    NoAnswer,
    /// The engine gave up part way -- a regex out of backtracking budget -- or the right-hand value was
    /// one nobody could decide. Not "did not match": it fails the whole selection closed unless another
    /// pairing matched the key, which settles it under every comparator; `reason` is the text to
    /// report.
    Unfinished {
        reason: String,
        /// The refusal's token when the right-hand value was a marker carrying one
        /// (`UnResolvedKind::refusal`: a refusal's own marker, or a plain marker handing a token on), so
        /// the error the fold raises carries it and a filter predicate run that ends on that error marks
        /// its entry a refusal; `None` for a regex out of budget and for a right-hand value the query
        /// could not reach. Dropped here, the token of an own-key refusal on the filter's right-hand side
        /// (`keys IN Allowed[*].Type`) never reached the map's marker, and `some X != Resources.*[ M[
        /// keys IN Allowed[*].Type ] !empty ].Name` passed over the map nobody could decide where a
        /// refusal fails it closed. Never filtered on the marker's text: a tokened marker is a refused
        /// read by its token whatever its reason (`eval::refused_read_text`), and a filter that dropped
        /// the token where the text was unregistered rebuilt the map's marker plain under a second key
        /// filter, which passed over it.
        token: Option<RefusalToken>,
        /// Whether `reason`, when the filter's fold over its keys keeps THIS pairing, is a sentence to
        /// register as a refused read's (`eval_context::register_refusal`): the pairing sentence built
        /// over a marker that stands for a refused read (`eval::is_refused_read`: a token, or a reason
        /// the registry holds), so the map's marker, which takes the kept sentence as its reason, is
        /// read as a refused read by text where it carries no token. Never for the wrap of a TOKENED
        /// marker whose reason is a NUMBERED text of registered sentences
        /// (`eval_context::numbered_refusal_parts`: the joined text the registry never holds, not even
        /// inside a wrap; the token carries the refusal for it), nor for a regex out of budget, nor for a
        /// right-hand value the query could not reach; a numbered text on a marker with NO token has
        /// nothing but the registry to say it is a refused read, so its wrap is registered. Decided here,
        /// where the marker is read once, and acted on by `real_binary_operation` for the one pairing its
        /// fold over every key kept; among token-less pairings the fold ranks a set bit over a clear one.
        register: bool,
    },
}

/// The outcome a piece of evidence stands for. The class comes from the cause `map_key_refusal` took
/// from `unanswerable_reason`, so nothing is re-derived from the wording of a reason.
fn outcome_of(evidence: &ComparisonResult) -> KeyPairOutcome {
    match evidence {
        ComparisonResult::Comparable(ComparisonWithRhs { outcome, .. }) => {
            KeyPairOutcome::Equal(*outcome)
        }
        ComparisonResult::NotComparable(NotComparableWithRhs {
            cause: Unanswerable::IncomparableKinds,
            ..
        }) => KeyPairOutcome::NoAnswer,
        ComparisonResult::NotComparable(NotComparableWithRhs {
            cause: Unanswerable::EngineGaveUp,
            reason,
            ..
        }) => KeyPairOutcome::Unfinished {
            reason: reason.clone(),
            token: None,
            register: false,
        },
        // A right-hand value the query could not reach is not a value the key differs from or equals;
        // it is a name the set was meant to hold and nobody can read. Read as "no answer" it kept the
        // key out of the selection and said nothing: `keys NOT IN %exempt` over an exemption list the
        // template lacks selected no key, the rule reported SKIP at exit 0, and nothing was checked.
        // The keys such a filter selects cannot be decided, so it fails the whole selection closed, as
        // an unfinished comparison does, with a reason naming the path the retrieval stopped at and
        // the query it still had to walk.
        ComparisonResult::UnResolvedRhs(unresolved) => match unresolved.did_not_resolve_reason() {
            // A marker among the right-hand values that carries a token (a refusal's own, or a plain
            // marker handing one on) carries it on, whatever its text; a marker with none, and a value
            // the query could not reach, carry none. Whether the marker stands for a REFUSED READ is
            // decided once, by the one predicate every reader of a marker asks
            // (`eval::is_refused_read`: a token, or a plain marker whose own reason the registry
            // holds), and that answer decides `register`: whether the sentence built here, when the
            // filter's fold over its keys keeps this pairing, enters the registry so the map's marker
            // reads as a refused read by text where it has no token. The wrap of a TOKENED marker whose
            // reason is a NUMBERED text of registered sentences is never registered (the joined text the
            // registry never holds, not even inside a wrap; its token carries the refusal, as it does
            // for the arm that wraps a refused right-hand QUERY, `rhs_undecided`). This is a
            // classifier: it writes nothing to the registry, and it re-reads nothing after this. The
            // registration is `real_binary_operation`'s, once, for the one pairing its fold over every
            // key kept: registered per pairing here, the wraps of the pairings the fold did NOT keep
            // entered the registry too, texts no marker ever carried; registered per key in
            // `select_key`, one key's wrap entered the registry while another key's sentence became
            // the map's marker.
            Some(reason) => {
                let (token, register) = match &unresolved.rhs {
                    QueryResult::UnResolved(marker) => {
                        let inner = crate::rules::eval::undecidable_reason(marker);
                        let inner = inner.as_deref().unwrap_or_default();
                        let refused = crate::rules::eval::is_refused_read(marker, inner);
                        let token = marker.kind.refusal();
                        // The predicate reads a tokened marker as a refused read, so this holds by its
                        // definition; it is here so a change to the predicate that drops the token
                        // arm shows in a debug build instead of leaving a tokened pairing the
                        // registry does not know.
                        debug_assert!(
                            refused || token.is_none(),
                            "a marker carrying a token is a refused read whatever its text: {}",
                            inner
                        );
                        // The wrap of a NUMBERED text is left unregistered only where the token
                        // carries the refusal for it; a numbered text met with no token (a raise over
                        // two token-less registered markers, whose entry a predicate run left plain
                        // with no token to hand on) has nothing else to say the marker is a refused
                        // read, so its wrap is registered as any other registered reason's is.
                        let numbered =
                            crate::rules::eval_context::numbered_refusal_parts(inner).is_some();
                        (token, refused && !(numbered && token.is_some()))
                    }
                    QueryResult::Resolved(_) | QueryResult::Literal(_) => (None, false),
                };
                KeyPairOutcome::Unfinished {
                    reason,
                    token,
                    register,
                }
            }
            // Built from an `UnResolved` result alone by `select_key`; a resolved value held here would
            // be a pairing that was never compared, which is still a pairing nobody decided.
            None => KeyPairOutcome::NoAnswer,
        },
    }
}

/// Whether a key is selected by `[ keys <cmp> <rhs> ]` when the right-hand side is the empty set: the
/// key equals none of its values, so `!=` and `not in` select it and `==` and `in` do not. The one
/// place the rule is written. The live engine asks it in `real_binary_operation` before it records the
/// keys, and [`key_selected_from`] asks it over no comparisons, so the legacy resolver, which asks the
/// fold alone, cannot answer differently. The rule started as "there was at least one value" once, on
/// the reasoning that `all` over no values is not a denylist that admits every key; but an exemption
/// list with nothing in it exempts nothing, and a filter that selected no key under `not in` checked
/// nothing at exit 0.
pub(crate) fn empty_set_selects(cmp: MapKeyComparator) -> bool {
    matches!(cmp, MapKeyComparator::NotEq | MapKeyComparator::NotIn)
}

/// The pairing [`key_selected_from`] kept for a key it could not decide, handed back whole: the reason
/// and the token the filter raises for the map (`Error::UndecidableComparison`, built by the caller that
/// folds the keys), and whether the reason is a sentence to register when that fold keeps it
/// (`KeyPairOutcome::Unfinished::register`, read where the pairing was classified). Carried as a value
/// rather than found again: the pairing the fold kept was once re-found over the outcomes by equality,
/// a `RefusalToken` comparison the token's own module reads only through `later_than`, and its marker's
/// reason re-classified, two readers of one fact that could disagree on trailing whitespace.
#[derive(Debug, Clone)]
pub(crate) struct KeptPairing {
    pub(crate) reason: String,
    pub(crate) token: Option<RefusalToken>,
    pub(crate) register: bool,
}

/// The verdict for one key from its classified comparisons, under a comparator [`key_comparator`] has
/// already widened, with the unfinished pairings ranked by `ranking`, the ranking of the filter predicate
/// runs the filter runs under (`eval::ranking_under`; `eval::no_frame_ranking` under none). The rules are
/// in the module comment; over no comparisons at all the answer is [`empty_set_selects`]'s. The ranking
/// is a parameter because this classifier holds no evaluation context: the comparison that calls
/// [`select_key`] holds it and hands it one call down. A key nobody could decide is the kept pairing,
/// whole ([`KeptPairing`]).
pub(crate) fn key_selected_from(
    cmp: MapKeyComparator,
    outcomes: &[KeyPairOutcome],
    ranking: Ranking<'_>,
) -> Result<bool, KeptPairing> {
    if outcomes.is_empty() {
        return Ok(empty_set_selects(cmp));
    }
    let mut equal_to_one = false;
    let mut equal_to_none = true;
    // The kept pairing's reason with its registration bit, the two read together off one outcome.
    let mut unfinished: Option<(&String, bool)> = None;
    // The reason and the token kept are one pairing's (`keep_latest_refusal_else_registered_else_first_ranking`):
    // the unfinished pairing whose right-hand value was the highest-ranked refusal's marker, minted
    // latest among those, reason and token together; else the first unfinished pairing whose sentence is
    // one to register (a plain marker whose own reason the registry holds, a refused read by text); else
    // the first unfinished pairing's reason, with `None`. A refusal minted inside a filter predicate run
    // marks the run's entry wherever its marker stands among the right-hand values, so a plain unfinished
    // pairing met first does not hide a refusal met after it, nor does an earlier-minted refusal's marker
    // hide a later one of the same rank, and the error raised names the refusal rather than pairing
    // another pairing's text with the refusal's token; and a spent regex budget met first does not hide
    // a registered marker met after it, so the map's marker reads as the refused read it stands beside
    // whatever the right-hand order. Ranked by minting alone, a token the run could not read as its own
    // (a binding of an older scope resolved inside it) outranked the entry's own earlier refusal here,
    // and the entry read PLAIN in one resource order and REFUSED in the other (pinned, both resource
    // orders and both conjunct orders, by `eval_tests.rs`'s
    // `a_key_filter_under_a_run_keeps_the_entrys_own_refusal_over_a_later_binding_resolved_token`).
    let mut refusal: Option<RefusalToken> = None;
    for each in outcomes {
        match each {
            KeyPairOutcome::Equal(true) => {
                equal_to_one = true;
                equal_to_none = false;
            }
            KeyPairOutcome::Equal(false) => {}
            KeyPairOutcome::NoAnswer => equal_to_none = false,
            // Noted, not returned: whether it decides anything depends on what the other pairings
            // said, and the fold has to read them all first.
            KeyPairOutcome::Unfinished {
                reason,
                token,
                register,
            } => {
                keep_latest_refusal_else_registered_else_first_ranking(
                    &mut unfinished,
                    &mut refusal,
                    reason,
                    *register,
                    *token,
                    ranking,
                );
            }
        }
    }
    // One match settles the key under every comparator -- in the set under `==` and `in`, out of it
    // under `!=` and `not in` -- and nothing an unfinished pairing could have said would move it, so
    // the unfinished pairing is undecidable only for a key no pairing settled. Returning the error at
    // the first unfinished pairing, whatever the others said, failed `[ keys in [/^Name$/, <a regex
    // out of budget>] ]` closed on the key `Name`: one pattern too expensive for one key stopped the
    // filter deciding keys the other patterns had already settled.
    if equal_to_one {
        return Ok(matches!(cmp, MapKeyComparator::Eq | MapKeyComparator::In));
    }
    if let Some((reason, register)) = unfinished {
        return Err(KeptPairing {
            reason: reason.clone(),
            token: refusal,
            register,
        });
    }
    Ok(match cmp {
        MapKeyComparator::Eq | MapKeyComparator::In => false,
        MapKeyComparator::NotEq | MapKeyComparator::NotIn => equal_to_none,
    })
}

/// A key whose selection moved because a string on the right-hand side is read as a value the key is
/// equal to, where the previous release read it as text the key could be contained in.
///
/// In the previous release, the live engine's `in` and `not in` read a string right-hand value against a
/// string key as `value.contains(key)`, and widened a written `==` or `!=` to that reading whenever
/// the right-hand side held more than one value. So `[ keys IN 'Environment' ]` selected the key `Env`,
/// `[ keys NOT IN 'aws:cloudformation:stack-name' ]` left the key `aws:cloudformation` out, and
/// `[ keys IN %allowed ]` over a binding holding strings selected every key that was a substring of one
/// of them. A list literal was never read that way: it arrived as one value and its elements were
/// compared by equality, so `[ keys IN ['Environment'] ]` selected `Environment` and nothing else, as it
/// does now. [`containment_move`] reconstructs the previous release's reading for one key and says
/// whether it selected the key where [`select_key`] now does not, or the other way about.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContainmentMove {
    /// Whether the previous release's reading selected the key.
    pub(crate) selected_before: bool,
    /// The right-hand strings the key is contained in, in right-hand order: the values the previous
    /// release's reading decided the key on.
    pub(crate) contained_in: Vec<String>,
}

/// The previous release's containment reading of `[ keys <written> <rhs> ]` for `key`, against
/// `selected`, the selection [`select_key`] reached under the widened comparator.
///
/// `rhs_as_written` is the right-hand side BEFORE the one-level expansion, because the previous release
/// counted those values to decide whether to widen `==` and `!=`: a list literal was one value and
/// stayed equality, two query results were two and became membership. The previous release's reading of
/// a string pairing: the value contains the key, negated first under `not in`; the key was selected when
/// one pairing held. `None` when the written comparator stayed equality there, when any right-hand value
/// is not a string (a list's elements and a scalar of another kind were compared by equality then as now,
/// and a mixed right-hand side is left unannounced rather than compared a second time: the engine
/// compares each pair once, which a test counts), when a value the query could not reach is among them,
/// when both readings select the key alike, or when the move is not containment's; `Some` names the
/// move. No comparator is called here: containment is a text test, and that is the whole difference.
///
/// Containment's, and not the fold's. The previous release also folded a negated comparator as ANY: a
/// key was selected under `not in` when ONE right-hand value did not contain it, where the fold now
/// needs EVERY value to differ from it. Over a deny list of two or more names, a key EQUAL to one of them
/// is therefore selected by the previous release's reading (the other name does not contain it) and not
/// by this one, and that move has nothing to do with containment: with equality in place of containment
/// under the same ANY fold the key is selected just the same. Announced as containment, that move would
/// tell the author of `Tags[ keys NOT IN %reserved ]` over `['Owner', 'CostCenter']` that their tag
/// `Owner` is "contained in `Owner`" and to match the key as text instead, once per site on an ordinary
/// exact-name deny list. So the previous release's reading is computed twice under the same fold, once
/// with containment and once with equality, and the notice goes out only when the two differ: at least
/// one right-hand string contains the key without equalling it, and that is what moved the selection. A
/// move the fold alone explains gets no containment notice here.
pub(crate) fn containment_move(
    written: MapKeyComparator,
    rhs_as_written: &[QueryResult],
    key: &PathAwareValue,
    selected: bool,
) -> Option<ContainmentMove> {
    let PathAwareValue::String((_, key_text)) = key else {
        return None;
    };
    let not_in = match written {
        MapKeyComparator::In => false,
        MapKeyComparator::NotIn => true,
        MapKeyComparator::Eq if rhs_as_written.len() > 1 => false,
        MapKeyComparator::NotEq if rhs_as_written.len() > 1 => true,
        MapKeyComparator::Eq | MapKeyComparator::NotEq => return None,
    };
    if rhs_as_written.is_empty() {
        return None;
    }
    let mut contained_in = Vec::new();
    let mut selected_before = false;
    let mut selected_before_by_equality = false;
    for each in rhs_as_written {
        let text = match each {
            QueryResult::Literal(value) | QueryResult::Resolved(value) => match &**value {
                PathAwareValue::String((_, text)) => text,
                _ => return None,
            },
            QueryResult::UnResolved(_) => return None,
        };
        let contains = text.contains(key_text.as_str());
        if contains {
            contained_in.push(text.clone());
        }
        if contains != not_in {
            selected_before = true;
        }
        if (text == key_text) != not_in {
            selected_before_by_equality = true;
        }
    }
    if selected_before == selected || selected_before == selected_before_by_equality {
        return None;
    }
    Some(ContainmentMove {
        selected_before,
        contained_in,
    })
}

/// A key whose selection moved because a negated key filter over two or more right-hand values is
/// folded as ALL where the previous release folded it as ANY: the move [`containment_move`] leaves
/// unannounced by design, since equality under the ANY fold selects the key just the same.
///
/// The previous release selected a key under `not in`, and under a `!=` widened over two or more
/// values, when ONE right-hand value differed from it. Over a deny or exemption list of two or more names
/// a key EQUAL to one of them was therefore selected, because the other name differed, and was checked;
/// the fold now needs EVERY value to differ, so the key is left out. `Resources[ keys NOT IN %exempt ]`
/// over `let exempt = Mappings.Exempt.Names[*]` with two bucket names exempts the exempt buckets that
/// the previous release checked (FAIL to PASS beside a compliant sibling, FAIL to SKIP without one),
/// `Tags[ keys NOT IN %reserved ]` over two reserved names exempts the reserved tags the previous
/// release checked, and in the previous release a binding that resolves to two or more lists
/// (`Mappings.*.Names` over two mappings) selected a key one list held because the other did not. A
/// list literal, bound or inline, never folded as ANY (it arrived as one value whose elements were
/// compared by equality), a single value folds the same either way, and `in` is ANY in the previous
/// release as in this one, so none of those moves.
///
/// Both lists are rendered as the rule language spells a list, each element in single quotes
/// (`['BucketB', 'BucketD']`), so an element holding a comma or a space reads as the one element it is;
/// a string value is rendered bare. An element holding a backtick is not escaped and breaks the backticks
/// the notice wraps a value in; no key name measured carries one.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FoldMove {
    /// The right-hand values that hold the key, each once, in right-hand order: a string equal to it, or
    /// a list with an element equal to it, rendered as above.
    pub(crate) held_by: Vec<String>,
    /// The right-hand values that selected the key under the previous release's fold, in right-hand
    /// order: for a string, one that does not contain the key; for a list, one with no element equal to
    /// it. Never one that holds the key.
    pub(crate) differs_from: Vec<String>,
}

/// One right-hand value as the notice spells it: a string bare, a list of strings as the rule language
/// writes a list literal, each element in single quotes. `None` for a value of another kind, or a list
/// with an element that is not a string, which [`fold_move`] leaves unannounced.
fn rendered_value(value: &PathAwareValue) -> Option<String> {
    match value {
        PathAwareValue::String((_, text)) => Some(text.clone()),
        PathAwareValue::List((_, elements)) => {
            let mut quoted = Vec::with_capacity(elements.len());
            for element in elements {
                match element {
                    PathAwareValue::String((_, text)) => quoted.push(format!("'{}'", text)),
                    _ => return None,
                }
            }
            Some(format!("[{}]", quoted.join(", ")))
        }
        _ => None,
    }
}

/// How the previous release's ANY fold selected `key` under a negated `[ keys <written> <rhs> ]`,
/// against `selected`, the selection [`select_key`] reached under the ALL fold.
///
/// `rhs_as_written` is the right-hand side before the one-level expansion, as [`containment_move`]
/// reads it: the previous release counted those values to decide whether a written `!=` was widened to
/// `not in`. The previous release's reading of one pairing, as [`containment_move`] reconstructs it: the
/// key was in a right-hand string when the string CONTAINED it, and the negated fold selected the key
/// when one value did not; a list value held the key when one of its string elements was EQUAL to it,
/// membership and not containment (measured on the previous release's binary over two mappings' name
/// lists: `[BucketA]` beside `[BucketB]` selected `BucketA` because the second list did not hold it, and
/// `[BucketA]` beside `[BucketALogs]` selected it too, `BucketALogs` being another name and not a string
/// that contains the key). So a key equal to one value and contained in every other
/// (`['Env', 'Environment']` with the key `Env`) was left out then, as it is now, and is no move;
/// reconstructed by equality that shape would be announced as a move that never happened, and
/// reconstructed by containment for a list's elements the `[BucketALogs]` shape, a FAIL turned PASS,
/// would be announced by nothing. `None` when the written comparator is not negated
/// or stayed equality (`!=` over one value), when fewer than two values stand on the right (one value
/// folds the same under ANY and ALL), when any right-hand value is neither a string nor a list of strings
/// (a scalar of another kind was compared by equality then as now, and a mixed right-hand side is left
/// unannounced here as it is for containment), when a value the query could not reach is among them (the
/// filter fails closed on it instead), when no value holds the key (selected under both folds) or every
/// value does (selected under neither), or when the engine's selection is not the one the fold explains.
/// `Some` names the values that selected the key before. Disjoint from [`containment_move`]: that one is
/// `Some` only when equality under the ANY fold disagrees with containment under it, and this one
/// reads containment, so a key that moved for containment's reason is containment's to announce.
pub(crate) fn fold_move(
    written: MapKeyComparator,
    rhs_as_written: &[QueryResult],
    key: &PathAwareValue,
    selected: bool,
) -> Option<FoldMove> {
    let PathAwareValue::String((_, key_text)) = key else {
        return None;
    };
    if !fold_can_move(written, rhs_as_written) {
        return None;
    }
    let key_text = key_text.as_str();
    // The values decided first and rendered after: a right-hand side of many values over many keys
    // renders nothing for the keys that drew no notice.
    let mut holders: Vec<&PathAwareValue> = Vec::new();
    let mut selectors: Vec<&PathAwareValue> = Vec::new();
    for each in rhs_as_written {
        let value = match each {
            QueryResult::Literal(value) | QueryResult::Resolved(value) => &**value,
            QueryResult::UnResolved(_) => return None,
        };
        // (whether the value selected the key under the previous release's fold, whether it holds the
        // key)
        let (selected_before, holds) = match value {
            // A string: the key was in it when it contained the key; it holds the key when equal.
            PathAwareValue::String((_, text)) => (!text.contains(key_text), text == key_text),
            // A list: membership. An element equal to the key is the only way a list held it, then as
            // now; an element that merely contains the key (`BucketALogs` for `BucketA`) did not.
            PathAwareValue::List((_, elements)) => {
                let mut holds = false;
                for element in elements {
                    match element {
                        PathAwareValue::String((_, text)) => holds |= text == key_text,
                        _ => return None,
                    }
                }
                (!holds, holds)
            }
            _ => return None,
        };
        if holds && !holders.iter().any(|held| *held == value) {
            holders.push(value);
        }
        if selected_before {
            selectors.push(value);
        }
    }
    // Selected before: one value did not hold the key. Selected now: no value holds it.
    if selectors.is_empty() || holders.is_empty() || selected {
        return None;
    }
    Some(FoldMove {
        held_by: holders
            .into_iter()
            .map(rendered_value)
            .collect::<Option<Vec<_>>>()?,
        differs_from: selectors
            .into_iter()
            .map(rendered_value)
            .collect::<Option<Vec<_>>>()?,
    })
}

// The number of containment notices whose text was built, for the test that pins that a site already
// recorded does not build another: the notice is kept once per site, so every text built past the first
// is formatted and thrown away. Per thread, as the other probe counters in `eval_context.rs` are.
#[cfg(test)]
thread_local! {
    pub(in crate::rules) static CONTAINMENT_NOTICES_BUILT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[inline]
fn count_containment_notice_built() {
    #[cfg(test)]
    CONTAINMENT_NOTICES_BUILT.with(|built| built.set(built.get() + 1));
}

/// The body of the notice for a [`ContainmentMove`]: which key moved at which filter, the string it
/// is contained in, and the rewrite. The body alone: the root scope writes the notice prefix in front
/// of it when it stores it.
pub(crate) fn containment_move_notice(
    written: MapKeyComparator,
    key: &PathAwareValue,
    moved: &ContainmentMove,
    location: &crate::rules::exprs::FileLocation<'_>,
) -> String {
    count_containment_notice_built();
    let operator = match written {
        MapKeyComparator::Eq => "==",
        MapKeyComparator::NotEq => "!=",
        MapKeyComparator::In => "IN",
        MapKeyComparator::NotIn => "NOT IN",
    };
    // The key and the strings it is contained in are data: a document key and the right-hand values,
    // which a document or a rules literal may fill with a tab, a zero-width or a bidi character, or a
    // backslash. Each is written as document text is everywhere a notice quotes it, controls as their
    // escapes and the backslash doubled, so the notice stays one line and a key named `a\b` and one
    // named `a<LF>b` print apart; the sink asserts no control reached it.
    let key_text = match key {
        PathAwareValue::String((_, text)) => crate::utils::writer::escaped_for_display(text),
        _ => String::new(),
    };
    let contained = moved
        .contained_in
        .iter()
        .map(|text| format!("`{}`", crate::utils::writer::escaped_for_display(text)))
        .collect::<Vec<_>>()
        .join(", ");
    let (now, before) = match moved.selected_before {
        true => ("no longer selects", "selected"),
        false => ("now selects", "left out"),
    };
    let location = crate::utils::writer::location_for_notice(location);
    format!(
        "the key filter `keys {operator}` at {location} {now} the key `{key_text}`, which before this \
         release it {before}: the key is contained in {contained}, and a string on the right of a key \
         filter was read as text the key could be contained in, where it is read as a value the key is \
         equal to. The notice is for this release only; the next release gives the new selection without \
         it. To select the keys a string contains, match the key as text instead (`keys == /pattern/`); \
         to select a key by name, this is now the reading.",
    )
}

// The number of fold notices whose text was built, for the test that pins that a site already recorded
// does not build another; see `CONTAINMENT_NOTICES_BUILT`. And the number of times the fold notice
// asked the evaluator whether its site is recorded, for the test that pins that a filter the fold
// cannot move (`keys IN`, or one value on the right) never asks: the lookup renders the site's position
// and probes a set, once per key of every map the filter runs over.
#[cfg(test)]
thread_local! {
    pub(in crate::rules) static FOLD_NOTICES_BUILT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    pub(in crate::rules) static FOLD_SITE_LOOKUPS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[inline]
fn count_fold_notice_built() {
    #[cfg(test)]
    FOLD_NOTICES_BUILT.with(|built| built.set(built.get() + 1));
}

#[inline]
pub(crate) fn count_fold_site_lookup() {
    #[cfg(test)]
    FOLD_SITE_LOOKUPS.with(|lookups| lookups.set(lookups.get() + 1));
}

/// Whether the previous release's fold could have moved a key under this filter at all: a negated
/// comparator (`NOT IN`, or `!=` widened over more than one value) over two or more right-hand values.
/// The same two tests [`fold_move`] opens with, read before any per-key work so that the common
/// `keys IN %allowed` and the one-value `!=` pay nothing for the fold notice, not even the lookup of
/// their site (`the_fold_sites_lookup_is_skipped_for_a_filter_the_fold_cannot_move` counts).
pub(crate) fn fold_can_move(written: MapKeyComparator, rhs_as_written: &[QueryResult]) -> bool {
    match written {
        MapKeyComparator::NotIn => {}
        MapKeyComparator::NotEq if rhs_as_written.len() > 1 => {}
        MapKeyComparator::In | MapKeyComparator::Eq | MapKeyComparator::NotEq => return false,
    }
    rhs_as_written.len() >= 2
}

/// The body of the notice for a [`FoldMove`]: which key moved at which filter, the value it is equal
/// to, and what to write instead. The body alone, as [`containment_move_notice`]'s is.
pub(crate) fn fold_move_notice(
    written: MapKeyComparator,
    key: &PathAwareValue,
    moved: &FoldMove,
    location: &crate::rules::exprs::FileLocation<'_>,
) -> String {
    count_fold_notice_built();
    let operator = match written {
        MapKeyComparator::Eq => "==",
        MapKeyComparator::NotEq => "!=",
        MapKeyComparator::In => "IN",
        MapKeyComparator::NotIn => "NOT IN",
    };
    // Data, written as [`containment_move_notice`] writes its key and strings: controls escaped and the
    // backslash doubled, so a key named `a\b` and one named `a<LF>b` print apart and the line holds.
    let key_text = match key {
        PathAwareValue::String((_, text)) => crate::utils::writer::escaped_for_display(text),
        _ => String::new(),
    };
    let backticked = |values: &[String]| {
        values
            .iter()
            .map(|text| format!("`{}`", crate::utils::writer::escaped_for_display(text)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let held_by = backticked(&moved.held_by);
    let selected_by = backticked(&moved.differs_from);
    let location = crate::utils::writer::location_for_notice(location);
    format!(
        "the key filter `keys {operator}` at {location} no longer selects the key `{key_text}`, which \
         before this release it selected. Two or more values stand on the right, and a negated key filter \
         used to select a key as soon as one value did not hold it, where it now selects a key that no \
         value holds (equal to none of the strings, an element of none of the lists). The key is held by \
         {held_by}; before this release {selected_by}, which did not hold it, selected it. The notice is \
         for this release only; the next release gives the new selection without it. To leave a key out \
         by name, this is now the reading; to select the keys that differ from one particular value, \
         write that value alone on the right.",
    )
}

/// What [`select_key`] decided about one key, with the comparisons it decided it from.
pub(crate) struct KeySelection {
    /// Whether the key is in the filter's selection. `false` when `undecided` is set.
    pub(crate) selected: bool,
    /// The reason the selection could not be decided, when it could not: a comparison the engine could
    /// not finish (a regex out of backtracking budget), or a right-hand value the query could not reach,
    /// which lands here with the path the retrieval stopped at. The caller fails the filter closed on it
    /// for the map it was selecting from; the key is not selected meanwhile.
    pub(crate) undecided: Option<String>,
    /// The refusal token the undecided reason carries (`KeyPairOutcome::Unfinished`), paired with it:
    /// `Some` when the kept pairing's right-hand value was a marker carrying a token, which is the pairing
    /// whose token ranks highest and was minted latest among those when there is one
    /// (`keep_latest_refusal_else_first_ranking`); `None` with no undecided reason, or when none of the
    /// key's unfinished pairings carried a token.
    pub(crate) refusal: Option<RefusalToken>,
    /// Whether `undecided` is a sentence to register as a refused read's when the filter's fold over its
    /// keys keeps this key's (`KeyPairOutcome::Unfinished::register`, the kept pairing's bit); `false`
    /// with no undecided reason. Read by `real_binary_operation` after that fold, the one place the
    /// pairing sentence enters the registry. Nothing is registered here: a selection is one key's
    /// verdict, and the map's marker takes the sentence of the one key the fold kept.
    pub(crate) register: bool,
    /// One entry per right-hand value, in right-hand order: the comparison made, or the refusal, or the
    /// unresolved value that was never a value to compare against. For the records.
    pub(crate) evidence: Vec<ComparisonResult>,
}

/// The one entry point: whether `key` is selected by `[ keys <cmp> <rhs> ]`, with the evidence.
///
/// `cmp` is the comparator [`key_comparator`] widened for this right-hand side, and `rhs` is the
/// right-hand side expanded one level. Each right-hand value is compared once, and the same comparison
/// is both the evidence returned and the outcome folded, by `ranking`, the ranking of the filter
/// predicate runs the caller runs under ([`key_selected_from`]).
pub(crate) fn select_key(
    cmp: MapKeyComparator,
    key: Rc<PathAwareValue>,
    rhs: &[QueryResult],
    ranking: Ranking<'_>,
) -> KeySelection {
    let mut evidence = Vec::with_capacity(rhs.len());
    let mut outcomes = Vec::with_capacity(rhs.len());
    for each in rhs {
        let compared = match each {
            QueryResult::Literal(value) | QueryResult::Resolved(value) => {
                match key_pair_compare(cmp, &key, value) {
                    Ok(outcome) => ComparisonResult::Comparable(ComparisonWithRhs {
                        outcome,
                        pair: LhsRhsPair {
                            lhs: Rc::clone(&key),
                            rhs: Rc::clone(value),
                        },
                    }),
                    Err(err) => map_key_refusal(err, Rc::clone(&key), Rc::clone(value)),
                }
            }
            QueryResult::UnResolved(_) => ComparisonResult::UnResolvedRhs(UnResolvedRhs {
                rhs: each.clone(),
                lhs: Rc::clone(&key),
            }),
        };
        outcomes.push(outcome_of(&compared));
        evidence.push(compared);
    }

    match key_selected_from(cmp, &outcomes, ranking) {
        Ok(selected) => KeySelection {
            selected,
            undecided: None,
            refusal: None,
            register: false,
            evidence,
        },
        Err(KeptPairing {
            reason,
            token,
            register,
        }) => KeySelection {
            selected: false,
            undecided: Some(reason),
            refusal: token,
            register,
            evidence,
        },
    }
}
