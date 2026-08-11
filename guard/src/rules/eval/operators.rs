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

        Err(Error::NotComparable(reason)) => {
            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(NotComparable {
                reason,
                pair: LhsRhsPair {
                    lhs: each_lhs,
                    rhs: each_rhs,
                },
            }))
        }

        _ => unreachable!(),
    }
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
                if rhsl
                    .iter()
                    .any(|elem| elem == rest || compare_eq(rest, elem).unwrap_or(false))
                {
                    ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ValueIn(
                        LhsRhsPair::new(Rc::new(rest.clone()), Rc::clone(&rhs_value)),
                    )))
                } else {
                    ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ValueIn(
                        LhsRhsPair::new(Rc::new(rest.clone()), Rc::clone(&rhs_value)),
                    )))
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
                                PathAwareValue::List((_, rhsl)) => {
                                    for each_rhs in rhsl {
                                        results.push(match_value(
                                            Rc::new(single_value.clone()),
                                            Rc::new(each_rhs.clone()),
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
                                    compare_eq,
                                ))
                            } else {
                                results.push(match_value(each, Rc::clone(&r), compare_eq));
                            }
                        }
                    }

                    single_value => {
                        for each in lhs_flattened {
                            if let PathAwareValue::List((_, lhs_list)) = &*each {
                                // An empty list contributes no elements, so this loop
                                // would push nothing and the clause would vanish: the
                                // enclosing fold reads zero results as "nothing to
                                // check" and reports PASS. `Tags == 'Owner'` against
                                // `Tags: []` then claims to have verified a property
                                // that was never compared, while the same rule against
                                // a *missing* Tags correctly fails.
                                //
                                // Recorded per element rather than by testing the whole
                                // flattened LHS. This arm uses `selected`, not
                                // `flattened`, so `each` is still one query result --
                                // one resource's value. A whole-LHS emptiness test would
                                // be defeated by any sibling resource with a non-empty
                                // list, which is the common shape in real templates and
                                // exactly how an earlier attempt at this fix silently
                                // did nothing.
                                if lhs_list.is_empty() {
                                    results.push(ValueEvalResult::EmptyLhsCollection(
                                        Rc::clone(&each),
                                    ));
                                }
                                for each_lhs in lhs_list {
                                    results.push(match_value(
                                        Rc::new(each_lhs.clone()),
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
