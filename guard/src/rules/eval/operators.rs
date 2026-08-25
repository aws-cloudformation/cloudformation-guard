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

#[derive(Clone, Debug)]
pub(crate) struct QueryIn {
    pub(crate) diff: Vec<Rc<PathAwareValue>>,
    pub(crate) lhs: Vec<Rc<PathAwareValue>>,
    pub(crate) rhs: Vec<Rc<PathAwareValue>>,
}

impl QueryIn {
    fn new(
        diff: Vec<Rc<PathAwareValue>>,
        lhs: Vec<Rc<PathAwareValue>>,
        rhs: Vec<Rc<PathAwareValue>>,
    ) -> QueryIn {
        QueryIn { lhs, rhs, diff }
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
    /// One left-hand query result was an empty collection, so it contributed no
    /// elements to compare and would otherwise leave no record at all.
    ///
    /// Carries the offending value so the reporter can name the path. Resolved by role
    /// at the `eval.rs` boundary, not here: whether "nothing to compare" is a failure
    /// depends on whether the clause is an assertion or a gate, and a comparator cannot
    /// see which.
    EmptyLhsCollection(Rc<PathAwareValue>),
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

/// Split each already-selected value into the elements to compare, recording
/// [`ValueEvalResult::EmptyLhsCollection`] for any value that was an empty collection.
///
/// This is the one place a comparator turns "there was nothing to compare" into a
/// record, so the three [`Comparator`] impls cannot drift apart on it again. They had:
/// `EqOperation` emitted `EmptyLhsCollection`, `InOperation` built an affirmative
/// `Success(ListIn)` out of an empty `diff`, and `CommonOperator` iterated an empty vec
/// and pushed nothing. Three spellings of one question, two of which certified an empty
/// collection as compliant -- `Ports <= 100` and `Ports > 100` are exact logical
/// negations and both returned PASS on `Ports: []`.
///
/// A comparator deliberately does not decide what an empty collection *means*; it only
/// refuses to stay silent about one. The role-dependent decision stays at the
/// `EmptyLhsCollection` arm of `binary_operation`, which fails it as an assertion and
/// contributes nothing for a gate -- failing a gate here would close it and drop every
/// check in the guarded body, which is how two earlier attempts regressed.
///
/// Takes the output of [`selected`], never [`flattened`]: one entry per query result is
/// what lets an empty list be attributed to the resource that had it. Testing a whole
/// flattened side for emptiness instead is defeated by any sibling resource with a
/// non-empty list, which is the common shape in real templates and exactly how an
/// earlier attempt at this fix silently did nothing.
fn elements_or_record_empty(
    results: &mut Vec<ValueEvalResult>,
    selected_values: &[Rc<PathAwareValue>],
) -> Vec<Rc<PathAwareValue>> {
    let mut elements = Vec::with_capacity(selected_values.len());
    for each in selected_values {
        match &**each {
            PathAwareValue::List((_, list)) if list.is_empty() => {
                results.push(ValueEvalResult::EmptyLhsCollection(Rc::clone(each)));
            }

            PathAwareValue::List((_, list)) => {
                elements.extend(list.iter().cloned().map(Rc::new));
            }

            _ => elements.push(Rc::clone(each)),
        }
    }
    elements
}

impl Comparator for CommonOperator {
    /// Serves `<`, `<=`, `>` and `>=` (instantiated only at the four sites near the end of
    /// this file).
    ///
    /// An empty collection on either side is recorded as
    /// [`ValueEvalResult::EmptyLhsCollection`] and resolved by role in `binary_operation`.
    /// All four operators previously certified one: `Ports <= 100` and `Ports > 100` are
    /// exact logical negations and both returned PASS on `Ports: []`, which is what made it
    /// a defect rather than defensible vacuous truth. Pre-existing in v3.2.0.
    ///
    /// Uses [`selected`] rather than [`flattened`] for both sides. `flattened` splices list
    /// elements into one flat vec, which destroys per-result provenance: an empty list
    /// leaves no entry, so the cross product below silently produces no comparison and the
    /// clause reports PASS on zero evidence. With `selected`, each entry is still one query
    /// result, so [`elements_or_record_empty`] can attribute the empty list to the resource
    /// that had it.
    ///
    /// Both sides, not just the left. These operators are asymmetric in spelling but not in
    /// meaning: `100 >= Ports` has to answer for `Ports: []` the same way `Ports <= 100`
    /// does, or the defect stays reachable by writing the clause backwards -- the same
    /// argument `EqOperation` makes for its mirrored empty-RHS guard.
    fn compare<'value>(
        &self,
        lhs: &[QueryResult],
        rhs: &[QueryResult],
    ) -> crate::rules::Result<EvalResult> {
        let mut results = Vec::with_capacity(lhs.len());
        let lhs_selected = selected(
            lhs,
            |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
            Vec::push,
        );
        // Expand the left side before reading the right, so an unresolved right-hand
        // reference is still blamed once per left-hand *element* rather than once per
        // query result. `flattened` used to make that the only available granularity;
        // keeping it means this change is confined to the empty-collection guard and does
        // not quietly alter how many blame entries an unresolved reference produces.
        let lhs_elements = elements_or_record_empty(&mut results, &lhs_selected);

        let rhs_selected = selected(
            rhs,
            |ur| {
                results.extend(lhs_elements.iter().map(|lhs| {
                    ValueEvalResult::ComparisonResult(ComparisonResult::RhsUnresolved(
                        ur.clone(),
                        Rc::clone(lhs),
                    ))
                }))
            },
            Vec::push,
        );

        let rhs_elements = elements_or_record_empty(&mut results, &rhs_selected);

        for each_lhs in &lhs_elements {
            for each_rhs in &rhs_elements {
                results.push(match_value(
                    Rc::clone(each_lhs),
                    Rc::clone(each_rhs),
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
                if !rhsl.is_empty() && rhsl[0].is_list() {
                    if rhsl.contains(&*lhs_value) {
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
                    // `diff` is "elements of the left side absent from the right", so an
                    // empty left side yields an empty `diff` and the affirmative Success
                    // below: `Tags IN ['Owner']` certified `Tags: []` as *compliant* --
                    // exit 0, `"compliant": [...]`, `not_applicable: []`. Pre-existing in
                    // v3.2.0, not a regression from the empty-collection work.
                    //
                    // Now recorded as EmptyLhsCollection and resolved by role in
                    // `binary_operation`: an assertion fails, a gate contributes nothing so
                    // it stays decided by its other conditions. Deciding it here instead
                    // would close any `when` gate built on it and drop the guarded body,
                    // which is how two earlier attempts regressed.
                    //
                    // The four ordering operators had the same wrong PASS via
                    // `CommonOperator` rather than this function; both now route through
                    // `elements_or_record_empty`. Measured before the fix, numeric
                    // fixtures, both controls correct on every row:
                    //
                    //     rule          Ports:[80]  Ports:[8080]  Ports:[]
                    //     Ports <= 100      0            19           0    <- wrong PASS
                    //     Ports >  100     19             0           0    <- wrong PASS
                    //     Ports <  100      0            19           0    <- wrong PASS
                    //     Ports >= 100     19             0           0    <- wrong PASS
                    //     Tags IN [..]      0            19           0    <- this arm
                    //     Tags not in [..] 19             0          19
                    //
                    // `<= 100` and `> 100` are exact logical negations and BOTH certified
                    // the same empty list. That is the argument for treating this as a defect
                    // rather than defensible vacuous truth: universal quantification over an
                    // empty set defends "every element satisfies P" for both P and not-P,
                    // but it cannot defend certifying `x <= 100` and `x > 100` for the same
                    // x. It was also inconsistent by spelling -- the same template under
                    // `==` failed (19), so one way of writing "the tag must be Owner"
                    // blocked a deployment and another certified it.
                    //
                    // `Tags not in ['Owner']` moves the other way, from 19 to 0. That is the
                    // vacuous-truth reading and it is correct: no element of `[]` is in
                    // `['Owner']`, and the old FAIL rejected a compliant template. It routes
                    // through the same "negated clauses contribute nothing" path that `!=`
                    // already uses, so it inherits that path's known disjunction-absorption
                    // hazard rather than introducing one -- see the `EmptyLhsCollection` arm
                    // in eval.rs.
                    //
                    // docs/CLAUSES.md shows only scalar left-hand sides for `IN`, so the
                    // documentation does not settle the list case.
                    if lhsl.is_empty() {
                        return ValueEvalResult::EmptyLhsCollection(Rc::clone(&lhs_value));
                    }

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
                // `eq` is still consulted first, and not for belt and braces: it is the only one of
                // the two that relates a range to an equal range, so asking `compare_eq` alone would
                // lose `%range_literal in [r[80,90]]`. Everything `eq` decides, it decides the same
                // way as before; `compare_eq` can only add a match, never remove one.
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
                results.push(
                    string_in(Rc::clone(l), Rc::clone(r))
                        .fail(|_| contained_in(Rc::clone(l), Rc::clone(r))),
                );
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
                        .for_each(|r| results.push(contained_in(Rc::clone(l), r)));
                } else if let PathAwareValue::List((_, list)) = &**l {
                    // Same empty-`diff` trap as the one in `contained_in`, reached when the
                    // left side is a literal empty list rather than a queried one.
                    if list.is_empty() {
                        results.push(ValueEvalResult::EmptyLhsCollection(Rc::clone(l)));
                        return Ok(EvalResult::Result(results));
                    }

                    let diff = list
                        .iter()
                        .cloned()
                        .map(Rc::new)
                        .filter(|elem| !rhs.contains(elem))
                        .collect::<Vec<_>>();

                    if diff.is_empty() {
                        results.push(ValueEvalResult::ComparisonResult(
                            ComparisonResult::Success(Compare::QueryIn(QueryIn {
                                diff,
                                rhs,
                                lhs: vec![Rc::clone(l)],
                            })),
                        ));
                    } else {
                        results.push(ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                            Compare::QueryIn(QueryIn {
                                diff,
                                rhs,
                                lhs: vec![Rc::clone(l)],
                            }),
                        )));
                    }
                } else {
                    rhs.iter().for_each(|rhs_elem| {
                        results.push(contained_in(Rc::clone(l), rhs_elem.clone()))
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
                            // Zero elements would push nothing and the clause would vanish
                            // into a PASS on no evidence, the same way the ordering
                            // operators did before `elements_or_record_empty`.
                            if lhsl.is_empty() {
                                results.push(ValueEvalResult::EmptyLhsCollection(Rc::clone(&l)));
                            }
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
        match (is_literal(lhs), is_literal(rhs)) {
            (Some(ref l), Some(ref r)) => {
                results.push(match_value(Rc::clone(l), Rc::clone(r), compare_eq));
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
                            results.push(match_value(Rc::clone(&l), each, compare_eq));
                        }
                    }

                    single_value => {
                        for eachr in rhs {
                            match &*eachr {
                                PathAwareValue::List(_) => {
                                    // The mirror image of the empty-collection case handled
                                    // in the `(None, Some(_))` arm below: here it is the
                                    // *right* side that is an empty list, so without the
                                    // guard in `elements_or_record_empty` this loop pushes
                                    // nothing and the comparison vanishes.
                                    //
                                    // `'Owner' == Properties.Tags` with `Tags: []` has to
                                    // fail for the same reason `Properties.Tags ==
                                    // 'Owner'` does. Fixing only one of the two leaves the
                                    // defect reachable by writing the clause backwards,
                                    // which is legal Guard and which a rule author has no
                                    // reason to think differs.
                                    for each_rhs in elements_or_record_empty(
                                        &mut results,
                                        std::slice::from_ref(&eachr),
                                    ) {
                                        results.push(match_value(
                                            Rc::new(single_value.clone()),
                                            each_rhs,
                                            compare_eq,
                                        ));
                                    }
                                }

                                rest_rhs => {
                                    results.push(match_value(
                                        Rc::new(single_value.clone()),
                                        Rc::new(rest_rhs.clone()),
                                        compare_eq,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            (None, Some(r)) => {
                // `selected`, not `flattened`: each query result stays one element, which
                // is what lets the empty-collection guard below attribute an empty list to
                // the specific resource that had it. Named to match, because the
                // distinction is the correctness argument for that guard.
                let lhs_selected = selected(
                    lhs,
                    |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push,
                );
                match &*r {
                    PathAwareValue::List((_, rhsl)) => {
                        // No empty-collection guard needed here, and it is worth saying
                        // why rather than leaving a reader to re-open the question: this
                        // loop pushes unconditionally for every element of
                        // `lhs_selected`, and iterates that rather than a nested list, so
                        // it has no path that pushes zero results.
                        for each in lhs_selected {
                            if each.is_scalar() && rhsl.len() == 1 {
                                results.push(match_value(
                                    each,
                                    Rc::new(rhsl[0].clone()),
                                    compare_eq,
                                ))
                            } else {
                                results.push(match_value(each, Rc::clone(&r), compare_eq));
                            }
                        }
                    }

                    single_value => {
                        for each in lhs_selected {
                            if each.is_list() {
                                // An empty list contributes no elements, so without the
                                // guard in `elements_or_record_empty` this loop would push
                                // nothing and the clause would vanish: the enclosing fold
                                // reads zero results as "nothing to check" and reports
                                // PASS. `Tags == 'Owner'` against `Tags: []` then claims to
                                // have verified a property that was never compared, while
                                // the same rule against a *missing* Tags correctly fails.
                                //
                                // `each` is one query result -- one resource's value --
                                // because this arm uses `selected`, not `flattened`. That
                                // is what the helper needs to attribute the empty list to
                                // the resource that had it; a whole-LHS emptiness test
                                // would be defeated by any sibling resource with a
                                // non-empty list, which is the common shape in real
                                // templates and exactly how an earlier attempt at this fix
                                // silently did nothing.
                                for each_lhs in elements_or_record_empty(
                                    &mut results,
                                    std::slice::from_ref(&each),
                                ) {
                                    results.push(match_value(
                                        each_lhs,
                                        Rc::new(single_value.clone()),
                                        compare_eq,
                                    ));
                                }
                            } else {
                                results.push(match_value(
                                    each.clone(),
                                    Rc::clone(&r.clone()),
                                    compare_eq,
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

                let diff = if lhs_selected.len() > rhs_selected.len() {
                    lhs_selected
                        .iter()
                        .filter(|e| !rhs_selected.contains(*e))
                        .cloned()
                        .collect::<Vec<_>>()
                } else {
                    rhs_selected
                        .iter()
                        .filter(|e| !lhs_selected.contains(*e))
                        .cloned()
                        .collect::<Vec<_>>()
                };

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
        // Known gap, and it is a documented-behaviour question rather than a comparator
        // bug, so it is recorded here rather than patched.
        //
        // The rule above is stated *positionally*, and that is deliberate rather than an
        // oversight. Written the other way round --
        // `%expected == Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags` -- the
        // literal is the non-empty left side, so a template containing no S3 bucket reaches
        // the empty-RHS path below and FAILs, while the forward spelling skips. Measured on a
        // template holding only an SQS queue: mirrored 19, forward 0. The disagreement is
        // confined to the positive spelling; both negated forms already agree at SKIP.
        //
        // An earlier version of this comment called that a contradiction of
        // docs/QUERY_AND_FILTERING.md:222 -- "the query will return empty results and the
        // block level clauses will be skipped". That reading was too strong. The doc sentence
        // is about clauses whose *subject* is the empty query, and a Guard comparison is not
        // operand-symmetric even when its operator is: the left side is the subject being
        // checked, the right side the reference it is checked against.
        //
        // Under that reading both cells are right. No subject values means nothing to assert,
        // so the rule does not apply -- which is what lets one ruleset run against templates
        // that do not all contain the resource type, the case the doc describes. No reference
        // values means the assertion cannot hold, because nothing is among zero references;
        // making that a SKIP is how an empty allowlist used to report compliance.
        //
        // Pinned rather than changed by `zero_selection_is_asymmetric_by_operand_role`, which
        // asserts all four cells with liveness rows. "Fixing the asymmetry" means choosing one
        // of the two to break: SKIP for the mirrored form reintroduces the empty-allowlist
        // wrong PASS, FAIL for the forward form breaks every ruleset run against a template
        // lacking the resource type. v3.2.0 exits 0 for both, so it had the wrong PASS twice.
        //
        // What makes this not simply fixable: `%lit IN %empt` where `%empt` filters on an
        // absent resource type is *the same documented case*, and
        // `literal_lhs_against_empty_reference_fails_without_panicking` asserts it FAILs.
        // Measured across three baselines -- v3.2.0 exits 0 for both spellings, and both
        // became 19 in the EmptyRhs work. So that test pins a behaviour change rather than
        // ratifying the documented one, and "fixing" the mirrored spelling in isolation
        // would make two shapes with identical documented semantics disagree in the other
        // direction.
        //
        // Whether empty-reference comparisons should fail closed at all is a real design
        // question -- failing closed is defensible for a policy gate, and the doc predates
        // that reasoning -- but it is upstream's to answer, and answering it in a comparator
        // that cannot see whether the emptiness came from a filter matching nothing or from
        // a reference resolving to nothing would be guessing.
        if lhs.is_empty() {
            return Ok(EvalResult::Skip);
        }

        // KNOWN GAP, deliberately not fixed here -- see the note below on the mirrored
        // zero-selection asymmetry.
        //
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
                                            let reverse_diff = if rhs.len() >= lhs.len()
                                                && matches!(self.0, crate::rules::CmpOperator::Eq)
                                            {
                                                reverse_diff(qin.diff, &qin.rhs)
                                            } else {
                                                reverse_diff(qin.diff, &qin.lhs)
                                            };

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
