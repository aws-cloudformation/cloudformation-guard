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
    /// The left-hand values that found no equal on the right.
    ///
    /// Equal to `diff` whenever `diff_from` is [`DiffFrom::Lhs`], which is every `IN` spelling and most
    /// of `==`. It is a separate field because `diff` answers "what should the report name" and this
    /// answers "which left-hand values failed", and [`DiffFrom::Rhs`] is the case where those two are
    /// not the same set. The negation wrapper needs the second question and only ever had the first.
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
/// Symmetric because the arm that calls it is. That arm reads `==` as equality of two operand sets and
/// folds in both directions so an extra value on either side is seen, so a one-sided unwrap would leave
/// the reverse pass unmatched and the clause still failing.
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

/// Whether `IN` finds this left-hand value inside a string on the right.
///
/// The `(None, Some)` arm applies `string_in` once per left-hand element, expanding a list-valued one,
/// so `["s3","arn"] in "aws:arn:s3::${s3}"` holds and `["s3","zzz"]` does not. `(None, None)` compares
/// a left-hand result whole and folds one answer per result into `diff`, so the expansion has to happen
/// here instead for the two spellings to agree.
///
/// The empty-list guard is `contained_in`'s, for the reason recorded there: an empty collection passing
/// a comparison is what `vacuous_comparison_notice` in `eval.rs` is deprecating, so this does not add
/// another one.
fn found_in_string(lhs: &PathAwareValue, rhs: &PathAwareValue) -> bool {
    let haystack = match rhs {
        PathAwareValue::String((_, haystack)) => haystack,
        _ => return false,
    };

    let found = |value: &PathAwareValue| match value {
        PathAwareValue::String((_, needle)) => haystack.contains(needle),
        _ => false,
    };

    match lhs {
        PathAwareValue::List((_, elements)) => !elements.is_empty() && elements.iter().all(found),
        scalar => found(scalar),
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

fn contained_in(lhs_value: Rc<PathAwareValue>, rhs_value: Rc<PathAwareValue>) -> ValueEvalResult {
    match &*lhs_value {
        PathAwareValue::List((_, lhsl)) => match &*rhs_value {
            PathAwareValue::List((_, rhsl)) => {
                // A list-valued left-hand side is IN a right-hand list if the whole list is one of
                // its elements, or if the left-hand side is non-empty and every left-hand element is
                // one of its non-list elements.
                //
                // Two readings, and each right-hand element decides for itself which one it can
                // answer. Membership -- "the whole left-hand list is one of these elements" -- is what
                // `Resources IN [["a","b"], ["c","d"]]` means, and only a nested list can satisfy it.
                // Subset -- "every left-hand element is one of these" -- is what
                // `Actions IN ["s3:Get", "s3:Put"]` means, and only a non-list element can contribute
                // to it. Nothing about one element changes what another element answers.
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
                // in a list literal, by asking each element in turn. Same idiom here, and membership
                // asks `compare_eq` as well as `PartialEq` so a list holding a range or a regex
                // reaches the function that knows about them. The subset test stays on `PartialEq`,
                // which is what the all-flat branch below uses, so one reading does not silently
                // become more permissive than the other spelling of itself.
                //
                // Gating subset on the RIGHT-hand side holding no list was tried and rejected. It is
                // order-independent, so it closes the defect, but it keeps the shape of what caused
                // it: one nested element would suppress the subset reading for every flat element
                // beside it, so adding `[9]` to `IN [1, 2]` stopped `1` and `2` matching, with no
                // diagnostic and nothing wrong with the clause. Measured over every `NOT IN` cell in
                // the grid, the two rules agree, so nothing about a denylist turns on this choice --
                // in this arm a failed membership reports the whole left-hand list as the diff, and
                // the negation wrapper counts every left-hand element as colliding either way.
                //
                // The `is_empty` guard keeps an empty left-hand list failing here. It is vacuously a
                // subset of anything, and `[] IN [1,2,3]` does pass through the branch below, so the
                // guard preserves an inconsistency rather than fixing one. Deliberate: an empty
                // collection passing a comparison is what `vacuous_comparison_notice` in `eval.rs` is
                // deprecating, and this is not the commit to add another one.
                if rhsl.iter().any(|elem| elem.is_list()) {
                    let flat_subset = !lhsl.is_empty()
                        && lhsl
                            .iter()
                            .all(|l| rhsl.iter().any(|r| !r.is_list() && r == l));
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
                            ListIn::new(
                                vec![Rc::clone(&lhs_value)],
                                Rc::clone(&lhs_value),
                                Rc::clone(&rhs_value),
                            ),
                        )))
                    }
                } else {
                    let diff = lhsl
                        .iter()
                        .filter(|each| !rhsl.contains(each))
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

                let mut diff = Vec::with_capacity(lhs_selected.len());
                'each_lhs: for eachl in &lhs_selected {
                    for eachr in &rhs_selected {
                        // Containment first, membership second, which is the order the two arms above
                        // apply when the right-hand side is written out. This arm asked `contained_in`
                        // alone, and two scalars there fall through to `compare_eq`, so
                        // `Needle in Haystack` was equality while `Needle in "aws:arn:s3::${s3}"` was
                        // containment -- and `Needle not in Haystack` therefore PASSED on a needle the
                        // haystack verbatim contains, a denylist admitting the value it names at exit 0.
                        if found_in_string(eachl, eachr) {
                            continue 'each_lhs;
                        }

                        if let ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) =
                            contained_in(Rc::clone(eachl), Rc::clone(eachr))
                        {
                            continue 'each_lhs;
                        }
                    }

                    diff.push(Rc::clone(eachl));
                }

                results.push(if diff.is_empty() {
                    ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(
                        QueryIn::new(diff, lhs_selected, rhs_selected),
                    )))
                } else {
                    ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(
                        QueryIn::new(diff, lhs_selected, rhs_selected),
                    )))
                });
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
        // `compare_eq_symmetric` throughout, not `compare_eq`. `compare_eq`'s five range arms are
        // written scalar-on-the-left because every other caller has a subject and a pattern, and `==`
        // does not -- so with a range on the left of `==` the pair reached the incomparable catch-all
        // and `%l == Port` refused where `Port == r[80,90]` passed. The wrapper puts the scalar on the
        // left for this operator only, which is why `IN` and the map key filters, for which
        // one-directional is correct, keep asking `compare_eq` directly.
        match (is_literal(lhs), is_literal(rhs)) {
            (Some(ref l), Some(ref r)) => {
                results.push(match_value(
                    Rc::clone(l),
                    Rc::clone(r),
                    compare_eq_symmetric,
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
                            results.push(match_value(Rc::clone(&l), each, compare_eq_symmetric));
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
                                            compare_eq_symmetric,
                                        ));
                                    }
                                }

                                rest_rhs => {
                                    results.push(match_value(
                                        Rc::new(single_value.clone()),
                                        Rc::new(rest_rhs.clone()),
                                        compare_eq_symmetric,
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
                                    compare_eq_symmetric,
                                ))
                            } else {
                                results.push(match_value(
                                    each,
                                    Rc::clone(&r),
                                    compare_eq_symmetric,
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
                                        compare_eq_symmetric,
                                    ));
                                }
                            } else {
                                results.push(match_value(
                                    each.clone(),
                                    Rc::clone(&r.clone()),
                                    compare_eq_symmetric,
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
                                            let lhs = match &*lin.lhs {
                                                PathAwareValue::List((_, v)) => v,
                                                _ => unreachable!(),
                                            };
                                            let mut reverse_diff = Vec::with_capacity(lhs.len());
                                            for each in lhs {
                                                let each = Rc::new(each.clone());
                                                if !lin.diff.contains(&each) {
                                                    reverse_diff.push(each)
                                                }
                                            }
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
