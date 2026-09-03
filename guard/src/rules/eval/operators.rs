use std::rc::Rc;

use crate::rules::errors::Error;
use crate::rules::path_value::*;
use crate::rules::{CmpOperator, QueryResult, UnResolved};

#[derive(Clone, Debug)]
pub(crate) struct LhsRhsPair {
    pub(crate) lhs: Rc<PathAwareValue>,
    pub(crate) rhs: Rc<PathAwareValue>,
}

impl LhsRhsPair {
    fn new(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> LhsRhsPair {
        LhsRhsPair { lhs, rhs }
    }
}

/// Which operand a [`QueryIn`]'s `diff` was taken from.
///
/// The reporter files every element of the diff as the finding's subject and prints the *other* operand
/// as what it was compared with, so it has to know which side is which. Without that it printed one set
/// on both sides: for a diff taken from the right, `eval.rs` still used `qin.rhs` as the comparison set,
/// and the finding read "property B was not present in [B]" -- a claim refuted by the set it names.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum DiffFrom {
    Lhs,
    Rhs,
}

#[derive(Clone, Debug)]
pub(crate) struct QueryIn {
    pub(crate) diff: Vec<Rc<PathAwareValue>>,
    /// The left-hand values that collide with nothing on the right.
    ///
    /// A separate field because `diff` answers "what should the report name" and this answers "which
    /// left-hand values found nothing", and the two part company for two unrelated reasons: under
    /// [`DiffFrom::Rhs`] the diff holds right-hand values instead, and under
    /// [`QueryIn::partly_matched`] a left-hand list is in the diff because `IN` rejected it and out of
    /// this set because the right-hand side names one of its elements. Equal to `diff` everywhere else,
    /// which is [`QueryIn::new`] and so every remaining `IN` spelling and most of `==`. The negation
    /// wrapper needs the second question and only ever had the first.
    ///
    /// "Collide" rather than "found no equal", which is what this said while `partly_matched` did not
    /// exist: a list-valued left-hand side with one element named on the right has no equal there and
    /// collides with it anyway, and `NOT IN` has to deny it.
    pub(crate) lhs_unmatched: Vec<Rc<PathAwareValue>>,
    pub(crate) lhs: Vec<Rc<PathAwareValue>>,
    pub(crate) rhs: Vec<Rc<PathAwareValue>>,
    pub(crate) diff_from: DiffFrom,
}

impl QueryIn {
    /// The ordinary case: the diff holds left-hand values that found nothing to match on the right.
    /// Every `IN` spelling produces this, and so does `==` whenever the reporter can place a left-hand
    /// value.
    fn new(
        diff: Vec<Rc<PathAwareValue>>,
        lhs: Vec<Rc<PathAwareValue>>,
        rhs: Vec<Rc<PathAwareValue>>,
    ) -> QueryIn {
        QueryIn {
            lhs,
            rhs,
            lhs_unmatched: diff.clone(),
            diff,
            diff_from: DiffFrom::Lhs,
        }
    }

    /// `IN` between two queries, where the values the report should name and the values that collide
    /// with the right-hand side are not the same set.
    ///
    /// A list-valued left-hand side only *partly* present in a right-hand one is in both: it is outside
    /// `IN`, so the report names it, and it is outside `NOT IN` as well, because the right-hand side
    /// names one of its elements. `collides` is the left-hand values in that position, and it is removed
    /// from `lhs_unmatched` rather than from `diff`, which is what keeps the two answers apart --
    /// `Pair NOT IN Deny` must deny a `Pair` of `[1, 2]` against a `Deny` of `[1, 3]`, and
    /// `Pair IN Deny` must still fail and still name `/Pair` when it does.
    ///
    /// `diff_from` stays [`DiffFrom::Lhs`]: the diff is left-hand values either way, so the reporter
    /// prints the right-hand operand as what they were compared with, exactly as for [`QueryIn::new`].
    /// Only the negation wrapper reads `lhs_unmatched`, so nothing else can see the difference.
    fn partly_matched(
        diff: Vec<Rc<PathAwareValue>>,
        collides: Vec<Rc<PathAwareValue>>,
        lhs: Vec<Rc<PathAwareValue>>,
        rhs: Vec<Rc<PathAwareValue>>,
    ) -> QueryIn {
        QueryIn {
            lhs,
            rhs,
            lhs_unmatched: reverse_diff(collides, &diff),
            diff,
            diff_from: DiffFrom::Lhs,
        }
    }

    /// `==` only, and only when the reporter would have nothing to say about the left operand: either
    /// every left-hand value found a match and the right-hand operand has values besides, or the left
    /// operand contributed only rule literals, which have no path to file a finding against. The
    /// right-hand values are then the evidence a reader can act on.
    ///
    /// `lhs_unmatched` is passed separately and is **not** the diff. In the second case above the left
    /// operand does have unmatched values -- they are just unreportable -- and the negation wrapper has
    /// to negate against those rather than against the right-hand extras. Deriving it from the diff is
    /// what made `%literal != %document_query` fail for two values that are comparable and unequal.
    fn from_rhs(
        diff: Vec<Rc<PathAwareValue>>,
        lhs_unmatched: Vec<Rc<PathAwareValue>>,
        lhs: Vec<Rc<PathAwareValue>>,
        rhs: Vec<Rc<PathAwareValue>>,
    ) -> QueryIn {
        QueryIn {
            lhs,
            rhs,
            diff,
            lhs_unmatched,
            diff_from: DiffFrom::Rhs,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ListIn {
    pub(crate) diff: Vec<Rc<PathAwareValue>>,
    pub(crate) lhs: Rc<PathAwareValue>,
    pub(crate) rhs: Rc<PathAwareValue>,
}

impl ListIn {
    fn new(
        diff: Vec<Rc<PathAwareValue>>,
        lhs: Rc<PathAwareValue>,
        rhs: Rc<PathAwareValue>,
    ) -> ListIn {
        ListIn { lhs, rhs, diff }
    }
}

/// The elements of a [`ListIn`]'s left-hand list that the right-hand side did match.
///
/// `ListIn::diff` holds the elements that found nothing, so this is its complement, and it is the set
/// `NOT IN` reports: those are the values that collide with the denylist. Empty exactly when nothing
/// collided, which is both the verdict the negation wrapper needs and the question
/// `InOperation`'s two-query arm asks about a partly-present left-hand list. One function rather than
/// two loops, so the two spellings of `NOT IN` cannot disagree about what counts as a collision --
/// disagreeing about that is what let `Pair NOT IN Deny` admit a `Pair` the written-out denylist denied.
///
/// An empty result is not the same as an empty `diff`. A left-hand list that is empty has no elements to
/// match, so both are empty and nothing collided, which is the answer `Empty NOT IN [[9]]` needs.
fn matched_elements(lin: &ListIn) -> Vec<Rc<PathAwareValue>> {
    let elements = match &*lin.lhs {
        PathAwareValue::List((_, elements)) => elements,
        // `ListIn` is constructed only by `contained_in`'s list-valued left-hand arm.
        _ => unreachable!(),
    };

    elements
        .iter()
        .map(|each| Rc::new(each.clone()))
        .filter(|each| !lin.diff.contains(each))
        .collect()
}

#[derive(Clone, Debug)]
pub(crate) enum Compare {
    Value(LhsRhsPair),
    QueryIn(QueryIn),
    ListIn(ListIn),
    ValueIn(LhsRhsPair),
}

#[derive(Clone, Debug)]
pub(crate) enum ComparisonResult {
    Success(Compare),
    Fail(Compare),
    NotComparable(NotComparable),
    RhsUnresolved(UnResolved, Rc<PathAwareValue>),
}

#[derive(Clone, Debug)]
pub(crate) enum ValueEvalResult {
    LhsUnresolved(UnResolved),
    ComparisonResult(ComparisonResult),
}

impl ValueEvalResult {
    pub(crate) fn fail<C>(self, c: C) -> ValueEvalResult
    where
        C: FnOnce(ValueEvalResult) -> ValueEvalResult,
    {
        if let ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) = &self {
            self
        } else {
            c(self)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum EvalResult {
    Skip,
    /// The left-hand side resolved to values but the right-hand side resolved to
    /// nothing, so there was no reference to compare against. Only produced by the
    /// bare `CmpOperator` comparator; the `(CmpOperator, bool)` wrapper resolves it
    /// using the operator's polarity and never passes it further up.
    EmptyRhs,
    /// Empty RHS on a positive comparison (`==`, `IN`): no value can be one of zero
    /// references, so every left-hand value fails.
    EmptyRhsUnsatisfiable,
    /// Empty RHS on a negated comparison (`!=`, `NOT IN`): there is nothing to
    /// collide with, so the clause holds.
    EmptyRhsVacuouslyTrue,
    Result(Vec<ValueEvalResult>),
}

#[derive(Clone, Debug)]
pub(crate) struct NotComparable {
    pub(crate) reason: String,
    pub(crate) pair: LhsRhsPair,
}

pub(crate) trait Comparator {
    fn compare(&self, lhs: &[QueryResult], rhs: &[QueryResult])
        -> crate::rules::Result<EvalResult>;
}

pub(crate) trait UnaryComparator {
    fn compare(&self, lhs: &[QueryResult]) -> crate::rules::Result<EvalResult>;
}

struct CommonOperator {
    comparator: fn(&PathAwareValue, &PathAwareValue) -> crate::rules::Result<bool>,
}

struct EqOperation {}
struct InOperation {}

fn selected<U, R>(query_results: &[QueryResult], mut c: U, mut r: R) -> Vec<Rc<PathAwareValue>>
where
    U: FnMut(&UnResolved),
    R: FnMut(&mut Vec<Rc<PathAwareValue>>, Rc<PathAwareValue>),
{
    let mut aggregated = Vec::with_capacity(query_results.len());
    for each in query_results {
        match each {
            QueryResult::Literal(l) => r(&mut aggregated, Rc::clone(l)),
            QueryResult::Resolved(l) => r(&mut aggregated, Rc::clone(l)),
            QueryResult::UnResolved(ur) => c(ur),
        }
    }
    aggregated
}

fn flattened<U>(query_results: &[QueryResult], c: U) -> Vec<Rc<PathAwareValue>>
where
    U: FnMut(&UnResolved),
{
    // TODO: this can probably be improved with less clones..
    selected(query_results, c, |into, p| match &*p {
        PathAwareValue::List((_, list)) => {
            into.extend(list.iter().cloned().map(Rc::new).collect::<Vec<_>>());
        }

        rest => into.push(Rc::new(rest.clone())),
    })
}

impl Comparator for CommonOperator {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult],
        rhs: &[QueryResult],
    ) -> crate::rules::Result<EvalResult> {
        let mut results = Vec::with_capacity(lhs.len());
        let lhs_flattened = flattened(lhs, |ur| {
            results.push(ValueEvalResult::LhsUnresolved(ur.clone()))
        });
        let rhs_flattened = flattened(rhs, |ur| {
            results.extend(lhs_flattened.iter().map(|lhs| {
                ValueEvalResult::ComparisonResult(ComparisonResult::RhsUnresolved(
                    ur.clone(),
                    lhs.clone(),
                ))
            }))
        });
        let rhs = &rhs_flattened;
        for each_lhs in lhs_flattened {
            for each_rhs in rhs {
                results.push(match_value(
                    each_lhs.clone(),
                    each_rhs.clone(),
                    self.comparator,
                ));
            }
        }
        Ok(EvalResult::Result(results))
    }
}

fn match_value<C>(
    each_lhs: Rc<PathAwareValue>,
    each_rhs: Rc<PathAwareValue>,
    comparator: C,
) -> ValueEvalResult
where
    C: Fn(&PathAwareValue, &PathAwareValue) -> crate::rules::Result<bool>,
{
    match comparator(&each_lhs, &each_rhs) {
        Ok(cmp) => {
            if cmp {
                success(each_lhs, each_rhs)
            } else {
                fail(each_lhs, each_rhs)
            }
        }

        Err(err) => not_comparable_because(each_lhs, each_rhs, unanswerable_reason(err)),
    }
}

/// Turns a comparator's error into the reason recorded against the clause.
///
/// Every way a comparator can fail means the same thing to the caller: this comparison has no
/// answer. None of them is a reason to stop the run, so none of them may reach a panic. The arm
/// that was missing was `RegexError`, and the catch-all that used to stand here was
/// `unreachable!()`, so a rules file with one unevaluatable regex aborted the process at exit 101
/// and took every other rule's verdict with it.
///
/// The two reachable variants today are `NotComparable`, from `compare_values` under all five
/// comparators, and `RegexError`, from `compare_eq` alone. Anything else still reports rather than
/// aborts, because a wrong-looking message beats no verdict at all.
fn unanswerable_reason(err: Error) -> String {
    match err {
        Error::NotComparable(reason) => reason,

        // `fancy_regex` returns a `Result` from `is_match` because its backtracking engine gives
        // up rather than running forever: a pattern holding a lookaround or a backreference cannot
        // use the linear automaton, and a nested quantifier then makes the number of paths to try
        // grow with the length of the input. `/(?!zzz)(\w+\s?)+!/` against eighty characters that
        // hold no `!` exceeds the limit, and the same pattern against fifteen does not, so a rule
        // that passes review can still fail on a longer `UserData` or policy document.
        //
        // `fancy_regex`'s own message is reported rather than `RegexError`'s, which reads "Regex
        // expression parse error" -- true of a pattern that would not compile, and misleading
        // about one that compiled and then ran out of backtracking.
        Error::RegexError(err) => {
            format!("The regular expression could not be evaluated against the value: {err}")
        }

        rest => format!("The comparison could not be performed: {rest}"),
    }
}

fn not_comparable_because(
    lhs: Rc<PathAwareValue>,
    rhs: Rc<PathAwareValue>,
    reason: String,
) -> ValueEvalResult {
    ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(NotComparable {
        reason,
        pair: LhsRhsPair { lhs, rhs },
    }))
}

fn is_literal(query_results: &[QueryResult]) -> Option<Rc<PathAwareValue>> {
    if query_results.len() == 1 {
        if let QueryResult::Literal(p) = &query_results[0] {
            return Some(Rc::clone(p));
        }
    }
    None
}

/// `==` between a scalar and a one-element list, whichever side each is on.
///
/// The `(None, Some)` arm of `EqOperation::compare` compares a scalar left-hand value with the single
/// element of a one-element list literal rather than with the list, so `Val == ["Name"]` holds for a
/// `Val` of `Name`. `is_literal` answers only for a lone `QueryResult::Literal`, so a variable bound to
/// a query arrives as `Resolved` and the same two values reached the `(None, None)` arm, where
/// `compare_eq_symmetric` has no scalar-against-list arm and refused: `Val == %onekey` exited 19 on the
/// pair its typed-out spelling passed.
///
/// Symmetric because the arm that first called it is. That arm reads `==` as equality of two operand
/// sets and folds in both directions so an extra value on either side is seen, so a one-sided unwrap
/// would leave the reverse pass unmatched and the clause still failing.
///
/// Every arm of `EqOperation::compare` asks this now, and originally two of them did not. A rule
/// literal that is a one-element list reaches `(Some, None)` or `(Some, Some)`, both of which compared
/// the list against the scalar whole and refused the pair: `%lit_other != Val` for a `Val` of `Name` and
/// a `lit_other` of `["Other"]` exited 19 reading "PathAwareValues are not comparable array, String",
/// two values that visibly differ, while `Val != %otherkey` -- the same question with the list arriving
/// from a query -- passed. Being asked from every arm is the point: this relates one pair of shapes, and
/// an arm that does not ask disagrees with the ones that do.
///
/// Two arms reach the same verdict without it, and asking anyway is harmless there. A literal scalar
/// against a query list, and a query list against a literal scalar, walk the list and compare element by
/// element, so a one-element list already answers as its element does. By the time this is called on
/// those paths both operands are scalars and it falls straight through.
///
/// One element only, and only against a scalar. Widening further would make `==` mean membership, which
/// is `IN`'s reading and already available; two lists, or a scalar against a list of two, keep the
/// answer they had.
fn compare_eq_unwrapping_a_one_element_list(
    lhs: &PathAwareValue,
    rhs: &PathAwareValue,
) -> crate::rules::Result<bool> {
    let single_element = |value: &PathAwareValue| match value {
        PathAwareValue::List((_, inner)) if inner.len() == 1 => Some(inner[0].clone()),
        _ => None,
    };

    if lhs.is_scalar() {
        if let Some(inner) = single_element(rhs) {
            return compare_eq_symmetric(lhs, &inner);
        }
    } else if rhs.is_scalar() {
        if let Some(inner) = single_element(lhs) {
            return compare_eq_symmetric(&inner, rhs);
        }
    }

    compare_eq_symmetric(lhs, rhs)
}

fn string_in(lhs_value: Rc<PathAwareValue>, rhs_value: Rc<PathAwareValue>) -> ValueEvalResult {
    match (&*lhs_value, &*rhs_value) {
        (PathAwareValue::String((_, lhs)), PathAwareValue::String((_, rhs))) => {
            if rhs.contains(lhs) {
                success(lhs_value, rhs_value)
            } else {
                fail(lhs_value, rhs_value)
            }
        }

        _ => not_comparable(lhs_value, rhs_value),
    }
}

/// `IN` reads a string on the right as containment, and only falls back to membership.
///
/// The one spelling of that order, so that the arms of `InOperation::compare` cannot disagree about it
/// again. `string_in` answers "not comparable" for anything but two strings, and `fail` runs the
/// fallback for every result that is not a success, so a non-string pair reaches `contained_in`
/// unchanged.
fn substring_or_contained_in(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> ValueEvalResult {
    string_in(Rc::clone(&lhs), Rc::clone(&rhs)).fail(|_| contained_in(lhs, rhs))
}

/// How much of this left-hand value `IN` finds inside a string on the right.
///
/// Three answers, not two, and `Partial` is the one that has to exist. The `(None, Some)` arm applies
/// `string_in` once per left-hand element, expanding a list-valued one, so a list is really N separate
/// comparisons folded by ALL: `["s3","arn"] in "aws:arn:s3::${s3}"` holds, `["zz","qq"]` does not, and
/// `["s3","zzz"]` -- one element found, one not -- cannot satisfy ALL in *either* polarity and so fails
/// both. `(None, None)` compares a left-hand result whole and has one boolean per result, which can say
/// "in" or "not in" and had no way to say the third thing. So it answered the partial case as a plain
/// miss, and negating a miss passes: `["s3","zzz"] NOT IN Haystack` reported compliance while the
/// haystack verbatim contained `s3`, and its typed-out spelling failed.
///
/// Only a list can be partly found, so `Partial` and `HoldsANonString` both name a list. `NotAString`
/// is the sibling for everything this function does not decompose, and exists for the same reason as
/// `HoldsANonString`, which is recorded below.
///
/// `HoldsANonString` is separate from `Partial`, and the reason is a defect this function shipped with.
/// Containment cannot be asked of an element that is not a string, and the literal arm says so: it hands
/// each element to `string_in`, which answers "not comparable" for a non-string, and one such result
/// makes the ALL-fold fail in both polarities. The first version of this function had `found` return
/// `false` for a non-string, conflating "is a string and is not contained" with "cannot be asked", so a
/// list of nothing but non-strings counted zero hits and came out `NoneFound` -- a plain miss, which
/// negates to a pass. `[5, 6] NOT IN Haystack` reported compliance where its typed-out spelling failed.
///
/// `["s3", 5]` masked it. That list has a contained string, so it reached `Partial` and failed closed for
/// the right verdict by the wrong route, and the cell passed. A cell that passes for the wrong reason is
/// worse than one that fails, because it reads as coverage: it is why the grid now carries `[5, 6]` as
/// well, and why the non-string test comes *before* the hit count rather than after it.
///
/// Measured at three points before the fix, all FAIL under the literal spelling and PASS under the query
/// spelling, so this was never a regression from any of them: `258772a` (before substring `IN` reached a
/// query at all), `aae25d0` (which made it reach one), and `fe4ac73` (which added `Partial`).
///
/// The empty-list guard is `contained_in`'s, for the reason recorded there: an empty collection passing
/// a comparison is what `vacuous_comparison_notice` in `eval.rs` is deprecating, so this does not add
/// another one. Empty is `NoneFound` rather than unanswerable because it keeps its existing answer --
/// `NOT IN` over nothing passes -- and folding it in would change a cell this is not about.
///
/// A non-string, non-list left-hand value used to be left out, and the reason given for leaving it out
/// was checked against the wrong spelling. It read: `contained_in` already asks `compare_eq` for such a
/// value and gets "not comparable", so `%int in Haystack` and `%int not in Haystack` both fail already.
/// That is true, and it is true of the `(Some, None)` arm, which is where a literal needle goes:
/// `substring_or_contained_in` there falls through to `contained_in` per result and the incomparable
/// answer is the clause's answer. The `(None, None)` arm keeps one verdict for the whole left-hand
/// operand set and only treats `contained_in`'s *Success* as a match, so an incomparable pairing was
/// indistinguishable from a miss, joined the unmatched diff, and negated to a pass. With
/// `Haystack: "aws:arn:s3::${s3}"`, none of these denied anything, and the fourth is why the row above
/// no longer calls them scalars:
///
/// ```text
/// Int    5        not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Float  5.5      not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Bool   true     not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Map    {a: 1}   not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Null   null     not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// ```
///
/// Reporting that incomparable answer from the loop instead was tried and rejected. `contained_in`
/// answers "not comparable" for a *list* against a string too -- lists and strings are not comparable
/// types -- and containment has already decided that pairing, correctly, as a genuine miss. So the
/// blanket reading turns `NoneList not in Haystack`, every element a string and none present, from PASS
/// into FAIL. That is `undenied_wholly_absent_list_query_haystack`, kept as a control by the commit
/// that added `HoldsANonString`, and it fails under the blanket fix and passes under this one.
#[derive(Copy, Clone, PartialEq)]
enum StringContainment {
    /// Every element, or the scalar itself, is contained.
    All,
    /// Every element is a string; some are contained and some are not, so no single answer is right in
    /// either polarity.
    Partial,
    /// At least one element is not a string, so containment cannot be asked of it.
    HoldsANonString,
    /// The left-hand value is neither a string nor a list, so containment cannot be asked of it as a
    /// whole. Separate from `HoldsANonString` because the two complaints are about different things:
    /// that one is about elements this function tested one at a time, and this one is about a value it
    /// never decomposed, so a message naming elements would describe contents nothing looked at.
    ///
    /// The reason used to read "a scalar holds nothing", and a `Map` refutes it. Only `List` is
    /// decomposed here, so `Map` arrives at the same arm as `Null`, `Bool`, `Int`, `Float`, `Char`,
    /// `Regex` and the three range kinds, and `{"a": 1}` plainly holds something.
    /// `denied_map_query_needle_query_haystack` in
    /// `substring_in_answers_the_same_against_a_query_as_against_a_literal` is that cell. The message it
    /// produces was accurate all along -- `Value={"a":1} is not a string, so it cannot be tested for
    /// containment in ...`, at exit 19 -- and only the justification for it was wrong.
    NotAString,
    /// Every element is a string and none is contained, or the right-hand side is not a string at all.
    NoneFound,
}

fn found_in_string(lhs: &PathAwareValue, rhs: &PathAwareValue) -> StringContainment {
    let haystack = match rhs {
        PathAwareValue::String((_, haystack)) => haystack,
        _ => return StringContainment::NoneFound,
    };

    let contained = |value: &PathAwareValue| match value {
        PathAwareValue::String((_, needle)) => Some(haystack.contains(needle)),
        _ => None,
    };

    match lhs {
        PathAwareValue::List((_, elements)) => {
            if elements.is_empty() {
                return StringContainment::NoneFound;
            }

            // Before the hit count, not after it: a non-string element decides the answer however many
            // of its neighbours are contained.
            if elements.iter().any(|element| contained(element).is_none()) {
                return StringContainment::HoldsANonString;
            }

            match elements
                .iter()
                .filter(|element| contained(element).unwrap_or(false))
                .count()
            {
                0 => StringContainment::NoneFound,
                hits if hits == elements.len() => StringContainment::All,
                _ => StringContainment::Partial,
            }
        }

        // Bound as `not_a_list`, and it used to be bound as `scalar`: a `Map` arrives here, so the old
        // name described a subset of what the arm receives.
        not_a_list => match contained(not_a_list) {
            Some(true) => StringContainment::All,
            Some(false) => StringContainment::NoneFound,
            None => StringContainment::NotAString,
        },
    }
}

fn not_comparable(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> ValueEvalResult {
    ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(NotComparable {
        pair: LhsRhsPair {
            lhs: Rc::clone(&lhs),
            rhs: Rc::clone(&rhs),
        },
        reason: format!("Type not comparable, {}, {}", lhs, rhs),
    }))
}

fn success(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> ValueEvalResult {
    ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(LhsRhsPair {
        lhs,
        rhs,
    })))
}

fn fail(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> ValueEvalResult {
    ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(LhsRhsPair {
        lhs,
        rhs,
    })))
}

/// Whether one left-hand element is one of a right-hand list's elements.
///
/// `PartialEq` and then `compare_eq`, which is the idiom `d7f01ec` put in the scalar-left-hand arm of
/// `contained_in` and is here for the reason it gives there. `Vec::contains` decides membership with
/// `PartialEq` alone, `PartialEq` is asked `element == value`, and the range table is written the other
/// way round -- scalar on the left, range on the right -- and lives in `compare_eq`. So a list-valued
/// left-hand side could not have an element matched by a range written beside it: for `Ports` of `[85]`,
/// `Ports IN [r[80,90]]` failed and `Ports NOT IN [r[80,90]]` passed, a denylist of forbidden port
/// ranges admitting every port. The scalar spelling of the same question was right, because it reaches
/// `compare_eq`.
///
/// Asking both is not belt and braces, and it is not redundant either way round. `compare_eq` answers
/// everything `PartialEq` answers here -- two equal ranges, a string against a regex it matches, a
/// number across `Int` and `Float`, a `Char` against the one-character string that spells it, and two
/// collections structurally -- and adds exactly `compare_eq`'s five range-membership arms. So this can
/// only add a match, never remove one, and `PartialEq` stays first because it short circuits on the
/// common case and costs one comparison on a path that runs one anyway.
///
/// `unwrap_or(false)` rather than the `RegexError` promotion the scalar arm does. `Err` here is
/// `NotComparable` in every case the suite reaches, it arrives constantly, and swallowing it is the
/// point: a pair that cannot be compared is not a match, so the element belongs in the diff below rather
/// than aborting the clause. `compare_eq`'s `(_, _)` fall-through asks `compare_values`, whose own
/// `(_, _)` refuses any pairing of kinds it has no arm for, and a denylist written beside values of
/// another kind is ordinary rather than exotic.
///
/// Measured, by replacing this `unwrap_or(false)` with a panic on `Err`: 58 tests redden, one recorded
/// error each, all 58 `NotComparable` from that fall-through -- `int, array` 26, `String, array` 12,
/// `map, array` 8, `int, String` 8, `array, int` 4. (`cargo test --all` counts them 116 times, because
/// the lib target and the bin target each compile this module.) So this is not an unreachable arm kept
/// for safety. The sibling scalar arm below swallows the same error through its own `Err(_) => {}`, for
/// the reason written out there: `NOT IN` against an operand of a kind it cannot be compared with
/// currently passes, `docs/KNOWN_ISSUES.md` records that suppression as a tracked defect, and
/// `incomparable_membership` in `eval.rs` warns rule authors before it changes. Two sites, one reading.
///
/// The other two errors `compare_eq` can raise are not alike. A NaN against a numeric range cannot
/// arrive, for the reason `compare_eq`'s own note gives -- it enumerates the four `Float` construction
/// sites that gate a non-finite one. `RegexError` splits in two. A pattern that will not compile cannot
/// arrive, because `parse_regex_inner` answers `nom::Err::Failure` unless `Regex::try_from` accepted the
/// pattern first, and no data format has a regex spelling. A pattern that compiled and then exhausted
/// `fancy_regex`'s backtracking budget does arrive here: the same panic probe fires with
/// `Vals IN [/(?!x)((a+)+)b/]` against a `Vals` holding one thirty-character string of `a`s.
///
/// That is a divergence from the scalar arm rather than a shape with no inputs, and it is open. On that
/// value `Val NOT IN [/(?!x)((a+)+)b/]` fails and reports that the regex could not be evaluated, while
/// `Vals NOT IN [/(?!x)((a+)+)b/]` passes carrying no message at all -- a denylist admitting a value it
/// could not evaluate, which is what
/// `a_regex_in_a_list_literal_fails_the_clause_instead_of_aborting` closed for the scalar spelling. No
/// cell covers it through this arm, and promoting it moves a verdict, so it is not a change to make from
/// a comment. Recorded here because `NotComparable` is what `unwrap_or(false)` is for, and this is the
/// shape to read first if the promotion is ever added.
fn is_one_of(each: &PathAwareValue, rhsl: &[PathAwareValue]) -> bool {
    rhsl.iter()
        .any(|elem| elem == each || compare_eq(each, elem).unwrap_or(false))
}

fn contained_in(lhs_value: Rc<PathAwareValue>, rhs_value: Rc<PathAwareValue>) -> ValueEvalResult {
    match &*lhs_value {
        PathAwareValue::List((_, lhsl)) => match &*rhs_value {
            PathAwareValue::List((_, rhsl)) => {
                // A list-valued left-hand side is IN a right-hand list if the whole list is one of
                // its elements, or if the left-hand side is non-empty and every left-hand element is
                // one of its elements.
                //
                // Two readings, and each right-hand element decides for itself which one it can
                // answer. Membership -- "the whole left-hand list is one of these elements" -- is what
                // `Resources IN [["a","b"], ["c","d"]]` means, and only a nested list can satisfy it.
                // Subset -- "every left-hand element is one of these" -- is what
                // `Actions IN ["s3:Get", "s3:Put"]` means. Nothing about one element changes what
                // another element answers.
                //
                // The subset test asks nothing about the depth of the element that matches, and it
                // used to require a non-list one. That requirement made two spellings of the same
                // question disagree with each other: for a `Nest` of `[1, [9]]`, `Nest IN [1, [9]]`
                // failed because `[9]` could not match the `[9]` written beside it, and
                // `Nest NOT IN [1, [9]]` failed as well -- neither polarity would admit a pair of
                // operands where every element of the left is spelled out on the right. It also let
                // this branch report a failure with an empty diff, since the diff below is computed
                // with `Vec::contains`, which has no such requirement. Dropping it makes "every
                // element matched" and "the element-wise diff is empty" the same statement, which is
                // why `flat_subset` is now written in terms of `diff` rather than beside it.
                //
                // That independence is the whole fix. Reading `rhsl[0]` let element zero answer for
                // elements 1..n: for a `Pair` of `[1, 2]`, `Pair NOT IN ["zzz", [1,2]]` exited 0 and
                // `Pair NOT IN [[1,2], "zzz"]` exited 19 -- one denylist, one value, and the order it
                // was typed in decided whether it admitted a value it verbatim contains. `IN`
                // inverted the same way and printed `was not present in [["zzz",[1,2]]]`, refuted by
                // the set beside it.
                //
                // This is `d7f01ec`'s failure shape in the arm that commit did not reach. It fixed the
                // scalar-left-hand arm below, where `rhsl.contains(rest)` could not see a range nested
                // in a list literal, by asking each element in turn. Same idiom here, in both readings:
                // `is_one_of` asks `compare_eq` as well as `PartialEq`, so a right-hand list holding a
                // range or a regex reaches the function that knows about them, and the whole-list
                // membership test asks `compare_eq` on the list itself for the same reason.
                //
                // The two are not both exercised, and it is the membership one that is not. Measured by
                // replacing each `unwrap_or(false)` with a panic on `Err` in the same build: the one
                // inside `is_one_of` fires for 58 tests, and this one -- `compare_eq(&lhs_value, elem)`
                // just below -- fires for none, anywhere in the lib suite. So its error path has no
                // coverage at all, and a reader reasoning about what this branch swallows should not
                // assume the sibling's 58 arrivals say anything about this line. `is_one_of`'s own
                // comment carries the kinds that do arrive there.
                //
                // The subset test used to stay on `PartialEq`, to match the all-flat branch below. That
                // matched the branch and left the same hole in it: a range beside a list-valued
                // left-hand side matched no element, so `Ports NOT IN [r[80,90]]` admitted a `Ports` of
                // `[85]` while `Port NOT IN [r[80,90]]` denied an 85. Both readings ask `is_one_of` now,
                // so the two agree at the level the scalar arm already worked at rather than at the one
                // neither of them did.
                //
                // Gating subset on the RIGHT-hand side holding no list was tried and rejected. It is
                // order-independent, so it closes the defect, but it keeps the shape of what caused
                // it: one nested element would suppress the subset reading for every flat element
                // beside it, so adding `[9]` to `IN [1, 2]` stopped `1` and `2` matching, with no
                // diagnostic and nothing wrong with the clause.
                //
                // The diff on failure is the unmatched ELEMENTS, which is what the flat branch below
                // reports and what the negation wrapper reads. That wrapper takes the elements of
                // `lin.lhs` and keeps the ones absent from `lin.diff`, calling those the values that
                // collide with the denylist. Reporting the whole left-hand list as a single diff
                // element -- which is what this branch did -- matches no element of itself, so every
                // element read as colliding and `NOT IN` failed for every left-hand value whenever
                // the denylist held any nested list: `Pair NOT IN [[99,98]]`, two disjoint pairs,
                // exited 19. Populating it element-wise is the whole fix, and it must land with the
                // paragraph above: a failure whose diff is empty would report every element as
                // colliding again, for the same reason and by the same route.
                //
                // Negating the verdict was tried and rejected before this commit, and the measurement
                // is a reviewer's rather than this one's. A marker field mirroring `QueryIn::diff_from`
                // would let the wrapper flip a failed membership to Success without recomputing
                // anything, and it is smaller. It admits four values the denylist names, because "the
                // whole list is not a member" says nothing about the elements: for a `Nest` of
                // `[1, [9]]`, `Nest NOT IN [[9]]` reaches exit 0 under it, and so does
                // `Deep NOT IN [["a"]]` for a `Deep` of `[["a"]]`. Both are cells of
                // `a_list_denylist_holding_a_nested_list_denies_only_what_it_names`, which is where to
                // look before trying it again.
                //
                // The `is_empty` guard keeps an empty left-hand list failing here. It is vacuously a
                // subset of anything, and `[] IN [1,2,3]` does pass through the branch below, so the
                // guard preserves an inconsistency rather than fixing one. Deliberate: an empty
                // collection passing a comparison is what `vacuous_comparison_notice` in `eval.rs` is
                // deprecating, and this is not the commit to add another one.
                if rhsl.iter().any(|elem| elem.is_list()) {
                    let diff = lhsl
                        .iter()
                        .filter(|each| !is_one_of(each, rhsl))
                        .cloned()
                        .map(Rc::new)
                        .collect::<Vec<_>>();
                    let flat_subset = !lhsl.is_empty() && diff.is_empty();
                    if flat_subset
                        || rhsl.iter().any(|elem| {
                            elem == &*lhs_value || compare_eq(&lhs_value, elem).unwrap_or(false)
                        })
                    {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                            Compare::ListIn(ListIn::new(vec![], lhs_value, rhs_value)),
                        ))
                    } else {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ListIn(
                            ListIn::new(diff, lhs_value, rhs_value),
                        )))
                    }
                } else {
                    let diff = lhsl
                        .iter()
                        .filter(|each| !is_one_of(each, rhsl))
                        .cloned()
                        .map(Rc::new)
                        .collect::<Vec<_>>();

                    if diff.is_empty() {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                            Compare::ListIn(ListIn::new(diff, lhs_value, rhs_value)),
                        ))
                    } else {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ListIn(
                            ListIn::new(diff, lhs_value, rhs_value),
                        )))
                    }
                }
            }

            _ => {
                ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(NotComparable {
                    pair: LhsRhsPair {
                        lhs: lhs_value.clone(),
                        rhs: rhs_value.clone(),
                    },
                    reason: format!("Can not compare type {}, {}", lhs_value, rhs_value),
                }))
            }
        },

        rest => match &*rhs_value {
            PathAwareValue::List((_, rhsl)) => {
                // `Vec::contains` decides membership with `PartialEq`, which answers
                // `element == rest` -- the direction that has no range arm and must not get one,
                // because `eq` has to stay symmetric while membership does not. So a range nested in
                // a list literal was never treated as a range: for a `Port` of 85,
                // `Port in [r[80,90]]` failed and `Port not in [r[80,90]]` passed, which is a
                // denylist of ranges that admits every value. Unwrapped, `Port in r[80,90]` was
                // always right, because that spelling reaches `compare_eq` below, and `compare_eq`
                // is where the range table lives.
                //
                // `eq` is consulted first, and it used to be the only one of the two that related a
                // range to an equal range, so asking `compare_eq` alone would have lost
                // `%range_literal in [r[80,90]]`. `compare_eq` now carries those three arms itself,
                // which makes this call belt and braces: there is no longer a pair `eq` answers true
                // and `compare_eq` answers false, so it could be dropped. Kept because it costs one
                // comparison on a path that already runs one, and because `eq` answering true short
                // circuits while `eq` answering false changes nothing -- `compare_eq` is asked next
                // either way. `compare_eq` can only add a match, never remove one.
                //
                // A regex `compare_eq` could not evaluate is read rather than discarded, which is
                // what makes `Port in [/re/]` answer the same way as `Port == /re/`. Both spellings
                // reach a regex that cannot be evaluated; the unwrapped one goes through
                // `match_value` and reports it, and this one used to panic inside `eq` before
                // `compare_eq` was ever asked. An element that matches still wins over an element
                // that could not be evaluated, because then the answer did not depend on the one
                // that failed.
                //
                // Only `RegexError` is promoted. `NotComparable` keeps the `unwrap_or(false)`
                // reading it has always had here, deliberately. `NOT IN` against an operand of a
                // kind it cannot be compared with currently passes; `docs/KNOWN_ISSUES.md` records
                // the silent conversion of a suppressed error to `false` as a tracked defect, and
                // `incomparable_membership` in `eval.rs` emits a deprecation notice for this
                // spelling so that rule authors hear about the change before a pipeline does.
                // Failing those cells here would land that change without its notice, and it moves
                // cells of `every_operator_and_operand_shape_agrees_with_a_stated_oracle`.
                let mut unanswerable: Option<String> = None;
                let mut found = false;
                for elem in rhsl {
                    if elem == rest {
                        found = true;
                        break;
                    }
                    match compare_eq(rest, elem) {
                        Ok(true) => {
                            found = true;
                            break;
                        }
                        Ok(false) => {}
                        Err(err @ Error::RegexError(_)) => {
                            if unanswerable.is_none() {
                                unanswerable = Some(unanswerable_reason(err));
                            }
                        }
                        Err(_) => {}
                    }
                }

                match (found, unanswerable) {
                    (true, _) => ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                        Compare::ValueIn(LhsRhsPair::new(
                            Rc::new(rest.clone()),
                            Rc::clone(&rhs_value),
                        )),
                    )),

                    (false, Some(reason)) => {
                        not_comparable_because(Rc::new(rest.clone()), Rc::clone(&rhs_value), reason)
                    }

                    (false, None) => {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ValueIn(
                            LhsRhsPair::new(Rc::new(rest.clone()), Rc::clone(&rhs_value)),
                        )))
                    }
                }
            }

            rhs_rest => match_value(Rc::new(rest.clone()), Rc::new(rhs_rest.clone()), compare_eq),
        },
    }
}

impl Comparator for InOperation {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult],
        rhs: &[QueryResult],
    ) -> crate::rules::Result<EvalResult> {
        let mut results = Vec::with_capacity(lhs.len());
        match (is_literal(lhs), is_literal(rhs)) {
            (Some(ref l), Some(ref r)) => {
                results.push(substring_or_contained_in(Rc::clone(l), Rc::clone(r)));
            }

            (Some(ref l), None) => {
                let rhs = selected(
                    rhs,
                    |ur| {
                        results.push(ValueEvalResult::ComparisonResult(
                            ComparisonResult::RhsUnresolved(ur.clone(), Rc::clone(l)),
                        ))
                    },
                    Vec::push,
                );

                if rhs.iter().any(|elem| elem.is_list()) {
                    rhs.into_iter()
                        .for_each(|r| results.push(substring_or_contained_in(Rc::clone(l), r)));
                } else if let PathAwareValue::List((_, list)) = &**l {
                    let diff = list
                        .iter()
                        .cloned()
                        .map(Rc::new)
                        .filter(|elem| !rhs.contains(elem))
                        .collect::<Vec<_>>();

                    if diff.is_empty() {
                        results.push(ValueEvalResult::ComparisonResult(
                            ComparisonResult::Success(Compare::QueryIn(QueryIn::new(
                                diff,
                                vec![Rc::clone(l)],
                                rhs,
                            ))),
                        ));
                    } else {
                        results.push(ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                            Compare::QueryIn(QueryIn::new(diff, vec![Rc::clone(l)], rhs)),
                        )));
                    }
                } else {
                    rhs.iter().for_each(|rhs_elem| {
                        results.push(substring_or_contained_in(Rc::clone(l), rhs_elem.clone()))
                    });
                }
            }

            (None, Some(r)) => {
                selected(
                    lhs,
                    |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push,
                )
                .into_iter()
                .for_each(|l| match &*r {
                    PathAwareValue::String(_) => match &*l {
                        PathAwareValue::List((_, lhsl)) => {
                            for eachl in lhsl {
                                results.push(string_in(Rc::new(eachl.clone()), Rc::clone(&r)));
                            }
                        }

                        rest => results.push(string_in(Rc::new(rest.clone()), Rc::clone(&r))),
                    },

                    rest => results.push(contained_in(l, Rc::new(rest.clone()))),
                });
            }

            (None, None) => {
                let lhs_selected = selected(
                    lhs,
                    |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push,
                );
                let rhs_selected = selected(
                    rhs,
                    |ur| {
                        results.extend(lhs_selected.iter().map(|lhs| {
                            ValueEvalResult::ComparisonResult(ComparisonResult::RhsUnresolved(
                                ur.clone(),
                                Rc::clone(lhs),
                            ))
                        }))
                    },
                    Vec::push,
                );

                // One `QueryIn` result holding the values that matched nothing, which is what makes `IN`
                // against a multi-value query mean "any of these". That shape is load-bearing and must
                // not change: expanding a left-hand value into one result per element here -- which is
                // what the literal-right-hand arm does, and the obvious way to make the two spellings
                // structurally identical -- turns "any" into "all". Measured, with `Type: gp3` and
                // `Names: ["gp2","gp3","io1"]`: `Type in Names[*]` is PASS today and FAIL under that
                // change, so every allowlist in every rules file would start rejecting the values it
                // allows. `a_long_in_comparison_is_truncated_with_a_total` and
                // `a_failing_in_comparison_against_a_plan_is_rendered_not_a_panic` are what caught it;
                // the first also pins the "and N more" summary this single result carries. Do not
                // expand here.
                let mut diff = Vec::with_capacity(lhs_selected.len());
                let mut collides = Vec::new();
                let mut unanswerable: Vec<ValueEvalResult> = Vec::new();
                'each_lhs: for eachl in &lhs_selected {
                    let mut unanswerable_against: Option<(Rc<PathAwareValue>, StringContainment)> =
                        None;
                    let mut element_collision = false;
                    for eachr in &rhs_selected {
                        // Containment first, membership second, which is the order the two arms above
                        // apply when the right-hand side is written out. This arm asked `contained_in`
                        // alone, and two scalars there fall through to `compare_eq`, so
                        // `Needle in Haystack` was equality while `Needle in "aws:arn:s3::${s3}"` was
                        // containment -- and `Needle not in Haystack` therefore PASSED on a needle the
                        // haystack verbatim contains, a denylist admitting the value it names at exit 0.
                        match found_in_string(eachl, eachr) {
                            StringContainment::All => continue 'each_lhs,

                            // Recorded, not answered. A full match against a later right-hand result
                            // still wins, which is this loop's existing "any right-hand value will do"
                            // reading, so an undecidable pairing only decides if nothing else does.
                            undecidable @ (StringContainment::Partial
                            | StringContainment::HoldsANonString
                            | StringContainment::NotAString) => {
                                if unanswerable_against.is_none() {
                                    unanswerable_against = Some((Rc::clone(eachr), undecidable));
                                }
                            }

                            StringContainment::NoneFound => {}
                        }

                        match contained_in(Rc::clone(eachl), Rc::clone(eachr)) {
                            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) => {
                                continue 'each_lhs
                            }

                            // A failed membership is not the same statement as a total miss, and this
                            // arm used to treat it as one. `contained_in` fails a list-valued left-hand
                            // side that is only *partly* present -- neither the whole list nor every
                            // element found an equal -- and reports the elements that found nothing as
                            // the `ListIn` diff. The elements missing from that diff DID find one, and
                            // those are the values a denylist names. Counting only Success as a match
                            // made a `Fail` carrying a real element collision indistinguishable from a
                            // pairing where nothing matched at all, so it joined the unmatched set and
                            // negated to a pass: with `Pair` of `[1, 2]` and `Deny` of `[1, 3]`,
                            // `Pair NOT IN Deny` exited 0 while `Pair NOT IN [1, 3]` exited 19.
                            //
                            // Recorded rather than answered, for the reason the string case above gives:
                            // a full match against a later right-hand result still wins, so a partial
                            // collision only decides when nothing else does.
                            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                                Compare::ListIn(lin),
                            )) => element_collision |= !matched_elements(&lin).is_empty(),

                            _ => {}
                        }

                        // The arm that was never written, for the pairing that produces no `ListIn` to
                        // read a collision out of.
                        //
                        // `contained_in` dispatches on the LEFT value first, so a list-valued left-hand
                        // side enters its `List` arm and a right-hand value that is not a list reaches
                        // that arm's catch-all, which answers `NotComparable`. Only two lists build a
                        // `ListIn`. So the arm above cannot see a collision when the right operand
                        // resolves to scalars, which is what `[*]` on the right does: with `Pair` of
                        // `[1, 2]` and `Deny13` of `[1, 3]`, `Pair NOT IN Deny13[*]` paired a list with
                        // `1` and then with `3`, recorded nothing either time, and exited 0 while
                        // `Pair NOT IN Deny13` exited 19. One denylist, one value, and whether the
                        // right-hand query was spelled with `[*]` decided whether the value it names was
                        // admitted.
                        //
                        // `NotComparable` is the right answer for what that arm is asked -- a list and a
                        // scalar are not comparable -- so this is an addition rather than a correction to
                        // it. The reading "a pair that cannot be compared is not a match" is stated
                        // explicitly for a scalar left-hand side, by the `Err(_) => {}` in `contained_in`'s
                        // `rest` arm and by `is_one_of`'s `unwrap_or(false)`. For a list left-hand side it
                        // was implemented by the ABSENCE of an arm here, which is the same reading applied
                        // to the whole list when the question is about its elements. What was missing is
                        // the element question, and that is what this asks.
                        //
                        // Which is also why no experiment at that `Err(_) => {}` could ever have moved
                        // this bypass, and why the unwrapped spelling was always right: both sit in the
                        // `rest` arm, guarded by the left value NOT being a list, and `Pair` is a list.
                        // The two sites are separable for the same reason -- different arms for different
                        // operand shapes -- so a change to either cannot regress the other.
                        //
                        // Keyed on the operand shapes rather than on the verdict the pairing produced,
                        // because the verdict is what was unreadable: reading `NotComparable` here would
                        // stop firing the moment that catch-all reports something else, and silently.
                        // `eachr.is_list()` is exactly the case the arm above already answers, so the two
                        // cannot both count one collision.
                        //
                        // `is_one_of`, not a fresh loop, and that is the whole point of the function --
                        // it is what `contained_in` asks for the written-out spelling, so the two
                        // spellings cannot disagree about what counts as an element collision again.
                        // Asking `PartialEq` alone here would leave a range or a regex on the right
                        // matching no element, which is the hole `d7f01ec` closed one arm at a time.
                        //
                        // Whole-list membership needs nothing added here: `compare_eq` of a list
                        // against a scalar is an error, so no scalar right-hand value can be the
                        // left-hand list itself.
                        //
                        // A right-hand result that IS a list goes to the arm above and is NOT fully
                        // answered there, which this comment used to claim it was. `contained_in` reads
                        // such a result as a set of candidate entries rather than as one entry, so
                        // `Deny[*]` over a `Deny` of `[[9]]` compares against `{9}` where the written-out
                        // and unexpanded spellings compare against `{[9]}`. For a `Nest` of `[1, [9]]`
                        // that is still exit 0 against three spellings at exit 19, and it is the same
                        // class of bypass as the one repaired here, one operand shape further in.
                        // `right_expanded_nested_entry_still_undenied` in `eval_tests.rs` pins it with
                        // its three disagreeing siblings beside it. Not repaired in this commit because
                        // it is a different mechanism -- how a list-shaped right-hand *result* is read,
                        // not whether the collision is looked for -- and landing both at once makes it
                        // impossible to say which one moved a cell.
                        if let PathAwareValue::List((_, elements)) = &**eachl {
                            if !eachr.is_list() {
                                element_collision |= elements
                                    .iter()
                                    .any(|each| is_one_of(each, std::slice::from_ref(&**eachr)));
                            }
                        }
                    }

                    // Nothing matched, and something could not be decided: the clause was posed at the
                    // wrong granularity and has no right answer in either polarity. `NotComparable` is
                    // how this arm already says that -- `%int in Haystack` and `%int not in Haystack`
                    // both fail, because an incomparable type fails closed both ways -- so these join
                    // an existing rule rather than introducing one. Failing closed is also the safe
                    // direction for a policy engine: a denylist that cannot decide must not report
                    // compliance.
                    //
                    // Three reasons, because they are three different complaints and a reader acts on
                    // them differently: a list whose elements are all strings but only some of them
                    // present, a list holding something containment cannot be asked of at all, and a
                    // value that is not a string and not a list either. The third says "is not a string"
                    // rather than "holds", because `found_in_string` decomposes only a list, so nothing
                    // examined the value's contents and a message about them would name what was never
                    // tested. A `Map` reaches this reason and does hold something, which is why the
                    // wording is about what was asked rather than about what the value contains.
                    if let Some((other, undecidable)) = unanswerable_against {
                        let reason = match undecidable {
                            StringContainment::HoldsANonString => format!(
                                "{} holds a value that is not a string, so it cannot be tested for \
                                 containment in {}",
                                eachl, other
                            ),

                            StringContainment::NotAString => format!(
                                "{} is not a string, so it cannot be tested for containment in {}",
                                eachl, other
                            ),

                            _ => format!("Some but not all of {} is contained in {}", eachl, other),
                        };

                        unanswerable.push(not_comparable_because(Rc::clone(eachl), other, reason));
                        continue;
                    }

                    if element_collision {
                        collides.push(Rc::clone(eachl));
                    }

                    diff.push(Rc::clone(eachl));
                }

                // One verdict per value, not two that disagree about the same one.
                //
                // With something unanswerable and nothing left unmatched there is no unmatched value for
                // this record to be about, and recording it anyway files a second verdict against a
                // value the loop has already reported it cannot decide. On `NOT IN` that second verdict
                // is the one a report shows: for an `Int` of `5` against a string haystack,
                // `Int not in Haystack` records the reason -- `/Int` is not a string, so containment
                // cannot be tested -- and then, without this, an `InComparison` FAIL filing `/Int` as a
                // value that WAS present in the haystack, contradicting the record beside it. On `IN` the
                // extra record is a bare `Success` carrying no message and no operands.
                //
                // Not a verdict change, and the comment here used to say it was: it claimed an empty
                // `diff` would otherwise report Success. Measured both ways, the clause exits 19 either
                // way, because a `NotComparable` result fails closed on its own and decides the verdict
                // whatever is recorded beside it. What this decides is what the report says, which is
                // why `an_unanswerable_containment_records_one_verdict_not_two` asserts on the recorded
                // clause checks rather than on the status. Nothing asserted on it before that test:
                // removing this line left 976 passed and 0 failed.
                //
                // Renamed from `every_value_was_unanswerable`, which described a narrower case than the
                // condition. Both halves hold whenever anything was unanswerable and nothing was left
                // unmatched, including when other left-hand values matched in full: with
                // `Values: ["s3", 5]`, `"s3"` is contained and so never reaches `diff`, `5` cannot be
                // asked, and the flag is true with one of the two values perfectly answerable.
                let unanswerable_and_nothing_unmatched =
                    !unanswerable.is_empty() && diff.is_empty();
                results.extend(unanswerable);
                if !unanswerable_and_nothing_unmatched {
                    results.push(if diff.is_empty() {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                            Compare::QueryIn(QueryIn::new(diff, lhs_selected, rhs_selected)),
                        ))
                    } else {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(
                            QueryIn::partly_matched(diff, collides, lhs_selected, rhs_selected),
                        )))
                    });
                }
            }
        }
        Ok(EvalResult::Result(results))
    }
}

impl Comparator for EqOperation {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult],
        rhs: &[QueryResult],
    ) -> crate::rules::Result<EvalResult> {
        let mut results = Vec::with_capacity(lhs.len());
        // `compare_eq_unwrapping_a_one_element_list` throughout, not `compare_eq`. `compare_eq`'s five
        // range arms are written scalar-on-the-left because every other caller has a subject and a
        // pattern, and `==` does not -- so with a range on the left of `==` the pair reached the
        // incomparable catch-all and `%l == Port` refused where `Port == r[80,90]` passed.
        // `compare_eq_symmetric`, which that wrapper is, puts the scalar on the left for this operator
        // only, which is why `IN` and the map key filters, for which one-directional is correct, keep
        // asking `compare_eq` directly.
        //
        // Throughout means every arm, and it did not. The unwrap that relates a scalar to a
        // one-element list was reached by the `(None, None)` arm, which asks the comparator per pair,
        // and by the `(None, Some)` list arm, which unwraps inline at `rhsl[0]`. Two arms asked
        // `compare_eq_symmetric` for a pair one of them would have unwrapped, and refused it: with
        // `Val: "Name"` and `let lit_other = ["Other"]`, `%lit_other != Val` exited 19 reading
        // "PathAwareValues are not comparable array, String" -- two values that visibly differ,
        // rejected rather than answered, where `Val != %otherkey` passed. `(Some, Some)` did the same
        // in both orientations.
        //
        // The two arms that expand rather than unwrap need no change and get none: with a literal
        // scalar against a query list, or a query list against a literal scalar, the list is walked
        // element by element and each element compared, which reaches the same verdict for a
        // one-element list by a different route. Asking the unwrapping comparator there costs nothing,
        // since by then both operands are scalars, and it means no arm of this operator can disagree
        // about the unwrap again -- which is the property that was missing, not any one arm.
        match (is_literal(lhs), is_literal(rhs)) {
            (Some(ref l), Some(ref r)) => {
                results.push(match_value(
                    Rc::clone(l),
                    Rc::clone(r),
                    compare_eq_unwrapping_a_one_element_list,
                ));
            }

            (Some(l), None) => {
                let rhs = selected(
                    rhs,
                    |ur| {
                        results.push(ValueEvalResult::ComparisonResult(
                            ComparisonResult::RhsUnresolved(ur.clone(), Rc::clone(&l)),
                        ))
                    },
                    Vec::push,
                );

                match &*l {
                    PathAwareValue::List(_) => {
                        for each in rhs {
                            results.push(match_value(
                                Rc::clone(&l),
                                each,
                                compare_eq_unwrapping_a_one_element_list,
                            ));
                        }
                    }

                    single_value => {
                        for eachr in rhs {
                            match &*eachr {
                                PathAwareValue::List((_, rhsl)) => {
                                    for each_rhs in rhsl {
                                        results.push(match_value(
                                            Rc::new(single_value.clone()),
                                            Rc::new(each_rhs.clone()),
                                            compare_eq_unwrapping_a_one_element_list,
                                        ));
                                    }
                                }

                                rest_rhs => {
                                    results.push(match_value(
                                        Rc::new(single_value.clone()),
                                        Rc::new(rest_rhs.clone()),
                                        compare_eq_unwrapping_a_one_element_list,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            (None, Some(r)) => {
                let lhs_flattened = selected(
                    lhs,
                    |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push,
                );
                match &*r {
                    PathAwareValue::List((_, rhsl)) => {
                        for each in lhs_flattened {
                            if each.is_scalar() && rhsl.len() == 1 {
                                results.push(match_value(
                                    each,
                                    Rc::new(rhsl[0].clone()),
                                    compare_eq_unwrapping_a_one_element_list,
                                ))
                            } else {
                                results.push(match_value(
                                    each,
                                    Rc::clone(&r),
                                    compare_eq_unwrapping_a_one_element_list,
                                ));
                            }
                        }
                    }

                    single_value => {
                        for each in lhs_flattened {
                            if let PathAwareValue::List((_, lhs_list)) = &*each {
                                for each_lhs in lhs_list {
                                    results.push(match_value(
                                        Rc::new(each_lhs.clone()),
                                        Rc::new(single_value.clone()),
                                        compare_eq_unwrapping_a_one_element_list,
                                    ));
                                }
                            } else {
                                results.push(match_value(
                                    each.clone(),
                                    Rc::clone(&r.clone()),
                                    compare_eq_unwrapping_a_one_element_list,
                                ));
                            }
                        }
                    }
                }
            }

            (None, None) => {
                let lhs_selected = selected(
                    lhs,
                    |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push,
                );
                let rhs_selected = selected(
                    rhs,
                    |ur| {
                        results.extend(lhs_selected.iter().map(|lhs| {
                            ValueEvalResult::ComparisonResult(ComparisonResult::RhsUnresolved(
                                ur.clone(),
                                Rc::clone(lhs),
                            ))
                        }))
                    },
                    Vec::push,
                );

                // The comparator per pair, not `Vec::contains`.
                //
                // `contains` decides with `PartialEq`, which returns `bool` and so has to turn a
                // comparison it cannot answer into `false` -- the suppression `docs/KNOWN_ISSUES.md`
                // records. On this branch that made `==` and `!=` between two queries the only
                // spellings that never reported it: with `Num: 1` and `Str: "x"`, `Num == "x"` refused
                // and named `not comparable int, String`, while `Num == Str` failed with no reason at
                // all and `Num != Str` **passed, exit 0, nothing in the report**. `<` behaved the same
                // in both forms, which is what isolates this to the two operators routed through
                // `PartialEq` here. Asking the comparator directly is what lets the error be reported.
                //
                // The reason is only consulted when the clause is going to fail. A pair that could not
                // be compared on the way to a match that was found afterwards did not decide anything,
                // so `%q == %r` over two sets that do match must not start refusing because some
                // unrelated pairing inside it had no answer.
                //
                // Promoted only once the value it is about turns out to be unmatched, which is what the
                // paragraph above is asking for and what recording it inside the inner loop did not
                // deliver. `each` can hit an incomparable pairing and then find a match against a later
                // element of `against`; the `continue 'each` skips the remaining comparisons but not the
                // error already stored. So with a left operand of `[1]` against a right of `["x", 1]` the
                // clause failed on the right-hand extra and reported that `1` is not comparable with
                // `"x"` -- a pairing that decided nothing, since `1` matched.
                let mut unanswerable: Option<(Rc<PathAwareValue>, Rc<PathAwareValue>, String)> =
                    None;
                let mut without_a_match =
                    |from: &[Rc<PathAwareValue>], against: &[Rc<PathAwareValue>]| {
                        let mut unmatched = Vec::with_capacity(from.len());
                        'each: for each in from {
                            let mut refused: Option<(Rc<PathAwareValue>, String)> = None;
                            for other in against {
                                match compare_eq_unwrapping_a_one_element_list(each, other) {
                                    Ok(true) => continue 'each,
                                    Ok(false) => {}
                                    Err(err) => {
                                        if refused.is_none() {
                                            refused =
                                                Some((Rc::clone(other), unanswerable_reason(err)));
                                        }
                                    }
                                }
                            }
                            // `each` has no equal anywhere in `against`, so it is one of the values that
                            // fails the clause, and a pairing it could not answer is now worth reporting.
                            if unanswerable.is_none() {
                                if let Some((other, reason)) = refused {
                                    unanswerable = Some((Rc::clone(each), other, reason));
                                }
                            }
                            unmatched.push(Rc::clone(each));
                        }
                        unmatched
                    };

                // Both directions, because `==` between two queries asks whether the operand sets
                // denote the same values, and one direction alone cannot see an extra value on the
                // other side. Picking the direction by operand-set size -- which is what stood here --
                // reads as set equality and is not: `A` selecting `[1, 2]` against `B` selecting
                // `[1, 1]` are the same length, so only `B \ A` was checked, it was empty, and the
                // clause passed on two operands that plainly differ.
                let lhs_unmatched = without_a_match(&lhs_selected, &rhs_selected);
                let rhs_unmatched = without_a_match(&rhs_selected, &lhs_selected);

                // The left operand's values, and `eval.rs` files every element of this diff as `from` --
                // which the reporter renders as the clause's subject: its `PropertyPath`, its `Value`,
                // the resource it groups the finding under, and the source excerpt it prints. Taking
                // the diff from the right-hand side blamed the right-hand property for every
                // one-value-against-one-value clause, the ordinary case. For
                // `Resources.R1.Properties.A == Resources.S.Properties.B` with `A: 1` and `B: 2` the
                // finding named `/Resources/S/Properties/B`, printed `Value = 2` and
                // `ComparedWith = [2]`, filed itself under `Resource = S` and quoted S's lines. `A`
                // appeared nowhere, and the reason read that `B` "was not present in" a set that
                // visibly contained `B`.
                //
                // Qualified by whether the reporter can place the value at all. A rule literal is built
                // with `Path::root()`, so its path is `""`: it has no resource to group under and no
                // line to quote, and a finding filed against one lands in "Findings that belong to no
                // resource" reading `property [[L:0,C:0]]`. When the left operand contributed only
                // literals and the right holds a value from the document -- which is what
                // `%expected == %replaced` is, with `%expected` a rule parameter -- the document value
                // is the one a reader can act on. `from_rhs` records the side, so the reporter compares
                // against the *left* operand and the message stays true; the alternative, keeping
                // `qin.rhs` as the comparison set, is what made it say "B was not present in [B]".
                //
                // Preferring the left otherwise is F10's rule, and it decides every clause where both
                // operands come from the document.
                let placeable = |values: &[Rc<PathAwareValue>]| {
                    values.iter().any(|v| !v.self_path().0.is_empty())
                };
                let take_rhs = if placeable(&lhs_unmatched) {
                    false
                } else if placeable(&rhs_unmatched) {
                    true
                } else {
                    lhs_unmatched.is_empty()
                };

                // `lhs_unmatched` travels with the diff either way, because it is what `!=` negates
                // against and the two are the same set only when the diff was taken from the left.
                let query_in = if take_rhs {
                    QueryIn::from_rhs(rhs_unmatched, lhs_unmatched, lhs_selected, rhs_selected)
                } else {
                    QueryIn::new(lhs_unmatched, lhs_selected, rhs_selected)
                };

                // A refusal replaces the diff only when the diff has nothing to add -- that is, when it
                // names exactly the one value the refusal already names. Otherwise both are reported.
                //
                // Returning `not_comparable_because` unconditionally dropped `query_in`, and with it
                // every other value that failed. For `%a.Properties.V == %c.Properties.V` over `[1, 5]`
                // against `["p", "q"]` both left values fail and the report named one: it said `A1` /
                // `Value = 1`, and `A2` / `Value = 5` appeared nowhere, so a template with N offending
                // properties took N runs to fix. The pre-round code reported one entry per failing value;
                // it named the wrong side, which is what F10 fixed, but it did not lose values.
                //
                // Two results rather than one reason carried on the diff. `InComparisonCheck` does have
                // a `message` field, and putting the reason there gives one finding per value with the
                // reason on the right one -- but `extract_name_info_from_record` maps that field to `NameInfo.message`,
                // the author's custom-message slot, where the `Comparison` variant beside it maps to
                // `NameInfo.error`. Measured: the reason then disappears from the human output *and*
                // from `--output-format json --structured`, which is `7df7617`'s whole point undone.
                // Making it render means changing that mapping, which also currently discards
                // `custom_message` for this variant -- a separate defect and a wider change than this one.
                //
                // The refusal is pushed first, and it must stay a `NotComparable`: the negation wrapper
                // passes that through untouched and inverts `Fail`, so this is what keeps `%q != %r`
                // failing on a pair it cannot compare instead of passing at exit 0.
                let refusal_says_it_all = match &unanswerable {
                    Some((value, _, _)) => {
                        query_in.diff.len() == 1 && Rc::ptr_eq(&query_in.diff[0], value)
                    }
                    None => false,
                };

                if query_in.diff.is_empty() {
                    results.push(ValueEvalResult::ComparisonResult(
                        ComparisonResult::Success(Compare::QueryIn(query_in)),
                    ));
                } else {
                    if let Some((each, other, reason)) = unanswerable {
                        results.push(not_comparable_because(each, other, reason));
                    }
                    if !refusal_says_it_all {
                        results.push(ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                            Compare::QueryIn(query_in),
                        )));
                    }
                }
            }
        }
        Ok(EvalResult::Result(results))
    }
}

impl Comparator for crate::rules::CmpOperator {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult],
        rhs: &[QueryResult],
    ) -> crate::rules::Result<EvalResult> {
        // An empty LHS means the query selected nothing, so the clause has nothing to
        // say about this input. That is genuinely inapplicable -- it is what lets one
        // ruleset run against templates that do not all contain the resource type
        // being checked (docs/QUERY_AND_FILTERING.md describes this for filters) --
        // and it stays a SKIP. Checked first so it keeps precedence when both sides
        // are empty.
        if lhs.is_empty() {
            return Ok(EvalResult::Skip);
        }

        // An empty RHS is a different situation that used to share this outcome:
        // there ARE values on the left to check, but the reference they would be
        // compared against resolved to nothing. Whether that is a pass or a failure
        // depends on the polarity of the comparison, so it cannot be answered here
        // without the not-flag. Report it and let the (CmpOperator, bool) wrapper
        // below decide.
        if rhs.is_empty() {
            return Ok(EvalResult::EmptyRhs);
        }

        match self {
            CmpOperator::Eq => EqOperation {}.compare(lhs, rhs),
            CmpOperator::In => InOperation {}.compare(lhs, rhs),
            CmpOperator::Lt => CommonOperator {
                comparator: compare_lt,
            }
            .compare(lhs, rhs),
            CmpOperator::Gt => CommonOperator {
                comparator: compare_gt,
            }
            .compare(lhs, rhs),
            CmpOperator::Le => CommonOperator {
                comparator: compare_le,
            }
            .compare(lhs, rhs),
            CmpOperator::Ge => CommonOperator {
                comparator: compare_ge,
            }
            .compare(lhs, rhs),
            _ => Err(crate::rules::Error::IncompatibleError(format!(
                "Operation {} NOT PERMITTED",
                self
            ))),
        }
    }
}

fn reverse_diff(
    diff: Vec<Rc<PathAwareValue>>,
    other: &[Rc<PathAwareValue>],
) -> Vec<Rc<PathAwareValue>> {
    other
        .iter()
        .filter(|e| !diff.contains(e))
        .map(Rc::clone)
        .collect()
}

impl Comparator for (crate::rules::CmpOperator, bool) {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult],
        rhs: &[QueryResult],
    ) -> crate::rules::Result<EvalResult> {
        let results = self.0.compare(lhs, rhs)?;
        Ok(match results {
            EvalResult::Skip => EvalResult::Skip,

            // The right-hand side resolved to no values. Polarity decides the answer,
            // which is why this is resolved here rather than in the bare comparator:
            //
            //   positive (`==`, `IN`)      -- "this value must be one of the
            //     references". With no references, nothing qualifies, so no value can
            //     satisfy the clause: FAIL. Previously this was a SKIP, which exits 0
            //     and is why an allowlist that resolved empty reported compliance.
            //
            //   negated (`!=`, `NOT IN`)   -- "this value must not be one of the
            //     references". With no references there is nothing to collide with, so
            //     the clause is vacuously satisfied: PASS. Failing here would reject
            //     compliant templates, because a denylist is legitimately empty
            //     whenever the template contains none of the denied values.
            //
            // Both answers are definite, so neither leaves the clause unenforced.
            EvalResult::EmptyRhs => {
                if self.1 {
                    EvalResult::EmptyRhsVacuouslyTrue
                } else {
                    EvalResult::EmptyRhsUnsatisfiable
                }
            }

            // Already resolved by this wrapper. The bare CmpOperator comparator only
            // ever yields EmptyRhs, so these cannot arrive here; pass them through
            // unchanged rather than double-inverting.
            resolved @ (EvalResult::EmptyRhsUnsatisfiable | EvalResult::EmptyRhsVacuouslyTrue) => {
                resolved
            }

            EvalResult::Result(r) => {
                if self.1 {
                    EvalResult::Result(
                        r.into_iter()
                            .map(|e| match e {
                                ValueEvalResult::ComparisonResult(ComparisonResult::Fail(c)) => {
                                    match c {
                                        Compare::QueryIn(qin) => {
                                            // Against `lhs_unmatched`, not against `diff`. What `!=`
                                            // reports is the left-hand values that *did* find an equal
                                            // on the right, since those are the ones that collide, and
                                            // removing the unmatched ones from the left operand is how
                                            // that set is computed.
                                            //
                                            // `diff` is not that set whenever `diff_from` is `Rhs`.
                                            // This used to read `reverse_diff(qin.diff, &qin.lhs)` on
                                            // the stated premise that a right-hand diff means "the left
                                            // had no unmatched ones", so every left value would survive
                                            // the filter. `EqOperation` also takes the right-hand diff
                                            // when the left operand's unmatched values are all rule
                                            // literals and so unreportable -- which is exactly what a
                                            // parameterized rule's `%expected != %query` is -- and then
                                            // the premise is false. `lhs \ rhs_unmatched` for two
                                            // disjoint operand sets is all of `lhs`, so `!=` reported
                                            // Fail for two values that are comparable and unequal:
                                            // `parse_int("7") != 1` failed at exit 19, and the reason
                                            // read that `[[L:0,C:0]]` "was not present in" the document
                                            // value.
                                            //
                                            // Unchanged where the premise did hold. With every left
                                            // value matched, `lhs_unmatched` is empty and the filter
                                            // keeps all of `lhs` -- the same answer the old expression
                                            // gave, because a right-hand value with no equal on the left
                                            // cannot be equal to a left-hand value either.
                                            let reverse_diff =
                                                reverse_diff(qin.lhs_unmatched, &qin.lhs);

                                            if reverse_diff.is_empty() {
                                                ValueEvalResult::ComparisonResult(
                                                    ComparisonResult::Success(Compare::QueryIn(
                                                        QueryIn::new(
                                                            reverse_diff,
                                                            qin.lhs,
                                                            qin.rhs,
                                                        ),
                                                    )),
                                                )
                                            } else {
                                                ValueEvalResult::ComparisonResult(
                                                    ComparisonResult::Fail(Compare::QueryIn(
                                                        QueryIn::new(
                                                            reverse_diff,
                                                            qin.lhs,
                                                            qin.rhs,
                                                        ),
                                                    )),
                                                )
                                            }
                                        }

                                        Compare::ListIn(lin) => {
                                            let reverse_diff = matched_elements(&lin);
                                            if reverse_diff.is_empty() {
                                                ValueEvalResult::ComparisonResult(
                                                    ComparisonResult::Success(Compare::ListIn(
                                                        ListIn::new(
                                                            reverse_diff,
                                                            lin.lhs.clone(),
                                                            lin.rhs,
                                                        ),
                                                    )),
                                                )
                                            } else {
                                                ValueEvalResult::ComparisonResult(
                                                    ComparisonResult::Fail(Compare::ListIn(
                                                        ListIn::new(
                                                            reverse_diff,
                                                            lin.lhs.clone(),
                                                            lin.rhs,
                                                        ),
                                                    )),
                                                )
                                            }
                                        }
                                        rest => ValueEvalResult::ComparisonResult(
                                            ComparisonResult::Success(rest),
                                        ),
                                    }
                                }

                                ValueEvalResult::ComparisonResult(ComparisonResult::Success(c)) => {
                                    match c {
                                        Compare::QueryIn(qin) => {
                                            let mut reverse_diff =
                                                Vec::with_capacity(qin.lhs.len());
                                            reverse_diff.extend(qin.lhs.clone());
                                            ValueEvalResult::ComparisonResult(
                                                ComparisonResult::Fail(Compare::QueryIn(
                                                    QueryIn::new(reverse_diff, qin.lhs, qin.rhs),
                                                )),
                                            )
                                        }
                                        Compare::ListIn(lin) => {
                                            // ALL elements, and `matched_elements` is deliberately
                                            // not used here. A Success means the whole left-hand
                                            // list was contained, so every element is a value
                                            // `NOT IN` has to name; the helper answers the narrower
                                            // question "which elements did the right-hand side
                                            // match", which is what the Fail arm above wants.
                                            //
                                            // The two coincide only while every `ListIn` Success
                                            // path carries an empty diff, because with an empty diff
                                            // "absent from the diff" is "all of them".
                                            // `a_successful_list_containment_carries_an_empty_diff`
                                            // pins that, and its message names the two construction
                                            // sites: `contained_in`'s nested-right-hand Success arm
                                            // passes `vec![]`, and its all-flat Success arm passes a
                                            // `diff` it has just tested `is_empty()`.
                                            //
                                            // Substituting the helper was measured byte-identical
                                            // and rejected anyway: it would turn a visible
                                            // difference between two loops into a silent dependency
                                            // on that invariant, so a third Success path carrying a
                                            // non-empty diff would make this arm under-report which
                                            // values collide instead of failing a test.
                                            let lhs = match &*lin.lhs {
                                                PathAwareValue::List((_, v)) => v,
                                                _ => unreachable!(),
                                            };
                                            let mut reverse_diff = Vec::with_capacity(lhs.len());
                                            for each in lhs {
                                                reverse_diff.push(Rc::new(each.clone()));
                                            }
                                            ValueEvalResult::ComparisonResult(
                                                ComparisonResult::Fail(Compare::ListIn(
                                                    ListIn::new(
                                                        reverse_diff,
                                                        Rc::clone(&lin.lhs),
                                                        Rc::clone(&lin.rhs),
                                                    ),
                                                )),
                                            )
                                        }

                                        rest => ValueEvalResult::ComparisonResult(
                                            ComparisonResult::Fail(rest),
                                        ),
                                    }
                                }

                                //
                                // Everything else
                                //
                                rest => rest,
                            })
                            .collect(),
                    )
                } else {
                    EvalResult::Result(r)
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "operators_tests.rs"]
mod operators_tests;
