use crate::rules::{QueryResult, UnResolved, CmpOperator};
use crate::rules::path_value::*;
use crate::rules::errors::{ErrorKind, Error};

#[derive(Clone, Debug)]
pub(crate) enum UnaryResult<'r> {
    Success,
    Fail,
    SuccessWith(&'r PathAwareValue),
    FailWith(&'r PathAwareValue),
}

#[derive(Clone, Debug)]
pub(crate) struct LhsRhsPair<'value> {
   pub(crate) lhs: &'value PathAwareValue,
   pub(crate) rhs: &'value PathAwareValue,
}

impl<'value> LhsRhsPair<'value> {
    fn new<'r>(lhs: &'r PathAwareValue, rhs: &'r PathAwareValue) -> LhsRhsPair<'r> {
        LhsRhsPair{lhs, rhs}
    }
}

#[derive(Clone, Debug)]
pub(crate) struct QueryIn<'value> {
   pub(crate) diff: Vec<&'value PathAwareValue>,
   pub(crate) lhs: Vec<&'value PathAwareValue>,
   pub(crate) rhs: Vec<&'value PathAwareValue>,
}

impl<'value> QueryIn<'value> {
    fn new<'r>(diff: Vec<&'r PathAwareValue>, lhs: Vec<&'r PathAwareValue>, rhs: Vec<&'r PathAwareValue>) -> QueryIn<'r> {
        QueryIn {
            lhs, rhs, diff
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ListIn<'value> {
    pub(crate) diff: Vec<&'value PathAwareValue>,
    pub(crate) lhs: &'value PathAwareValue,
    pub(crate) rhs: &'value PathAwareValue,
}

impl<'value> ListIn<'value> {
    fn new<'r>(diff: Vec<&'r PathAwareValue>, lhs: &'r PathAwareValue, rhs: &'r PathAwareValue) -> ListIn<'r> {
        ListIn {
            lhs, rhs, diff
        }
    }
}


#[derive(Clone, Debug)]
pub(crate) enum Compare<'r> {
    Value(LhsRhsPair<'r>),
    QueryIn(QueryIn<'r>),
    ListIn(ListIn<'r>),
    ValueIn(LhsRhsPair<'r>),
}

#[derive(Clone, Debug)]
pub(crate) enum ComparisonResult<'r> {
    Success(Compare<'r>),
    Fail(Compare<'r>),
    NotComparable(NotComparable<'r>),
    RhsUnresolved(UnResolved<'r>, &'r PathAwareValue),
}

#[derive(Clone, Debug)]
pub(crate) enum ValueEvalResult<'value> {
    LhsUnresolved(UnResolved<'value>),
    UnaryResult(UnaryResult<'value>),
    ComparisonResult(ComparisonResult<'value>)
}

impl<'value> ValueEvalResult<'value> {
    pub(crate) fn success<C>(self, c: C) -> ValueEvalResult<'value>
        where C: FnOnce(ValueEvalResult<'value>) -> ValueEvalResult<'value>
    {
        if let ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))= &self {
            c(self)
        }
        else {
            self
        }
    }

    pub(crate) fn fail<C>(self, c: C) -> ValueEvalResult<'value>
        where C: FnOnce(ValueEvalResult<'value>) -> ValueEvalResult<'value>
    {
        if let ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))= &self {
            self
        }
        else {
            c(self)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum EvalResult<'value> {
    Skip,
    Result(Vec<ValueEvalResult<'value>>)
}

#[derive(Clone, Debug)]
pub(crate) struct NotComparable<'r> {
    pub(crate) reason: String,
    pub(crate) pair: LhsRhsPair<'r>,
}

pub(super) fn resolved<'value, E, R>(
    qr: &QueryResult<'value>,
    err: E) -> std::result::Result<&'value PathAwareValue, R>
    where E: Fn(UnResolved<'value>) -> R
{
    match qr {
        QueryResult::Resolved(r) |
        QueryResult::Literal(r) => Ok(*r),
        QueryResult::UnResolved(ur) => Err(err(ur.clone())),
    }
}

pub(crate) trait Comparator {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult<'value>],
        rhs: &[QueryResult<'value>]) -> crate::rules::Result<EvalResult<'value>>;
}

pub(crate) trait UnaryComparator {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult<'value>]) -> crate::rules::Result<EvalResult<'value>>;
}

struct CommonOperator {
    comparator: fn (&PathAwareValue, &PathAwareValue) -> crate::rules::Result<bool>
}

struct EqOperation{}
struct InOperation{}

fn selected<'value, U, R>(
    query_results: &[QueryResult<'value>],
    mut c: U,
    mut r: R) -> Vec<&'value PathAwareValue>
    where U: FnMut(&UnResolved<'value>) -> (),
          R: FnMut(&mut Vec<&'value PathAwareValue>, &'value PathAwareValue) -> ()
{
    let mut aggregated = Vec::with_capacity(query_results.len());
    for each in query_results {
        match each {
            QueryResult::Literal(l) |
            QueryResult::Resolved(l) => r(&mut aggregated, *l),
            QueryResult::UnResolved(ur) => c(ur),
        }
    }
    aggregated
}

fn flattened<'value, U>(
    query_results: &[QueryResult<'value>],
    c: U) -> Vec<&'value PathAwareValue>
    where U: FnMut(&UnResolved<'value>) -> ()
{
    selected(
        query_results,
        c,
            |into, p| {
                match p {
                    PathAwareValue::List((_, list)) => {
                        into.extend(
                            list.iter().collect::<Vec<&PathAwareValue>>()
                        );
                    },

                    rest => into.push(rest),
                }

            }
    )
}

impl Comparator for CommonOperator {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult<'value>],
        rhs: &[QueryResult<'value>]) -> crate::rules::Result<EvalResult<'value>> {
        let mut results = Vec::with_capacity(lhs.len());
        let lhs_flattened = flattened(
            lhs, |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())));
        let rhs_flattened =
            flattened(
            rhs, |ur| results.extend(
                lhs_flattened.iter().map(|lhs|
                    ValueEvalResult::ComparisonResult(
                    ComparisonResult::RhsUnresolved(ur.clone(), *lhs))))
            );
        let rhs = &rhs_flattened;
        for each_lhs in lhs_flattened {
            for each_rhs in rhs {
                results.push(
                    match_value(each_lhs, each_rhs, self.comparator)
                );
            }
        }
        Ok(EvalResult::Result(results))
    }
}

fn match_value<'value, C>(
    each_lhs: &'value PathAwareValue,
    each_rhs: &'value PathAwareValue,
    comparator: C) -> ValueEvalResult<'value>
    where C: Fn(&PathAwareValue, &PathAwareValue) -> crate::rules::Result<bool>
{
    match comparator(each_lhs, each_rhs) {
        Ok(cmp) => {
            if cmp {
                success(each_lhs, each_rhs)
            }
            else {
                fail(each_lhs, each_rhs)
            }
        },

        Err(Error(ErrorKind::NotComparable(reason))) => {
            ValueEvalResult::ComparisonResult(
                ComparisonResult::NotComparable(
                    NotComparable {
                        reason,
                        pair: LhsRhsPair {
                            lhs: each_lhs,
                            rhs: each_rhs
                        }
                    }
                )
            )
        },

        _ => unreachable!()

    }
}


fn is_literal<'value>(query_results: &[QueryResult<'value>]) -> Option<&'value PathAwareValue> {
    if query_results.len() == 1 {
        if let QueryResult::Literal(p) = query_results[0] {
            return Some(p)
        }
    }
    None
}

fn string_in<'value>(
    lhs_value: &'value PathAwareValue,
    rhs_value: &'value PathAwareValue) -> ValueEvalResult<'value>
{
    match (lhs_value, rhs_value) {
        (PathAwareValue::String((_, lhs)),
         PathAwareValue::String((_, rhs))) => {
            if rhs.contains(lhs) {
                success(lhs_value, rhs_value)
            }
            else {
                fail(lhs_value, rhs_value)
            }
         },

        _ => not_comparable(lhs_value, rhs_value)
    }
}

fn not_comparable<'value>(
    lhs: &'value PathAwareValue,
    rhs: &'value PathAwareValue) -> ValueEvalResult<'value>
{
    ValueEvalResult::ComparisonResult(
        ComparisonResult::NotComparable(
            NotComparable {
                pair: LhsRhsPair{lhs, rhs},
                reason: format!("Type not comparable, {}, {}", lhs, rhs)
            }
        )
    )
}

fn success<'value>(
    lhs: &'value PathAwareValue,
    rhs: &'value PathAwareValue) -> ValueEvalResult<'value>
{
    ValueEvalResult::ComparisonResult(
        ComparisonResult::Success(
            Compare::Value(LhsRhsPair{lhs, rhs})
        )
    )
}

fn fail<'value>(
    lhs: &'value PathAwareValue,
    rhs: &'value PathAwareValue) -> ValueEvalResult<'value>
{
    ValueEvalResult::ComparisonResult(
        ComparisonResult::Fail(
            Compare::Value(LhsRhsPair{lhs, rhs})
        )
    )
}

fn contained_in<'value>(
    lhs_value: &'value PathAwareValue,
    rhs_value: &'value PathAwareValue) -> ValueEvalResult<'value>
{
    match lhs_value {
        PathAwareValue::List((_, lhsl)) =>
            match rhs_value {
                PathAwareValue::List((_, rhsl)) => {
                    if rhsl.len() > 0 && rhsl[0].is_list() {
                        if rhsl.contains(lhs_value) {
                            ValueEvalResult::ComparisonResult(
                                ComparisonResult::Success(
                                    Compare::ListIn(ListIn::new(vec![], lhs_value, rhs_value))
                                )
                            )
                        }
                        else {
                            ValueEvalResult::ComparisonResult(
                                ComparisonResult::Success(
                                    Compare::ListIn(ListIn::new(vec![lhs_value], lhs_value, rhs_value))
                                )
                            )
                        }
                    }
                    else {
                        let diff = lhsl.iter().filter(|each| !rhsl.contains(*each))
                            .collect::<Vec<_>>();
                        if diff.is_empty() {
                            ValueEvalResult::ComparisonResult(
                                ComparisonResult::Success(
                                    Compare::ListIn(ListIn::new(diff, lhs_value, rhs_value))
                                )
                            )
                        } else {
                            ValueEvalResult::ComparisonResult(
                                ComparisonResult::Fail(
                                    Compare::ListIn(
                                        ListIn::new(diff, lhs_value, rhs_value)
                                    )
                                )
                            )
                        }
                    }
                },

                _ =>
                    ValueEvalResult::ComparisonResult(
                        ComparisonResult::NotComparable(
                            NotComparable {
                                pair: LhsRhsPair{lhs: lhs_value, rhs: rhs_value},
                                reason: format!("Can not compare type {}, {}", lhs_value, rhs_value)
                            }
                        )
                    )
            },

        rest => {
            match rhs_value {
                PathAwareValue::List((_, rhsl)) => if rhsl.contains(rest) {
                    ValueEvalResult::ComparisonResult(
                        ComparisonResult::Success(
                            Compare::ValueIn(
                                LhsRhsPair::new(rest, rhs_value)
                            )
                        )
                    )
                } else {
                    ValueEvalResult::ComparisonResult(
                        ComparisonResult::Fail(
                            Compare::ValueIn(
                                LhsRhsPair::new(rest, rhs_value)
                            )
                        )
                    )
                },

                rhs_rest=> match_value(rest, rhs_rest, compare_eq)
            }
        }
    }
}

impl Comparator for InOperation {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult<'value>],
        rhs: &[QueryResult<'value>]) -> crate::rules::Result<EvalResult<'value>> {
        let mut results = Vec::with_capacity(lhs.len());
        match (is_literal(lhs), is_literal(rhs)) {
            (Some(l), Some(r)) => {
                results.push( string_in(l, r)
                    .fail(|_| contained_in(l, r)));
            },

            (Some(l), None) => {
                let rhs = selected(
                    rhs, |ur| results.push(
                        ValueEvalResult::ComparisonResult(
                            ComparisonResult::RhsUnresolved(ur.clone(), l))),
                    Vec::push
                );

                if rhs.iter().any(|elem| elem.is_list()) {
                    rhs.into_iter().for_each(|r|
                        results.push(contained_in(l, r))
                    );
                }
                else if l.is_list() {

                }

            },

            (None, Some(r)) => {
                selected(
                    lhs, |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push
                ).into_iter().for_each(|l|
                    match r {
                        PathAwareValue::String(_) => {
                            match l {
                                PathAwareValue::List((_, lhsl)) => {
                                    for eachl in lhsl {
                                        results.push(string_in(eachl, r));
                                    }
                                },

                                rest => results.push(
                                    string_in(rest, r)
                                )
                            }
                        },

                        rest => results.push(
                            contained_in(l, rest)
                        ),
                    }
                );
            },

            (None, None) => {
                let lhs_selected = selected(
                    lhs,
                    |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push
                );
                let rhs_selected = selected(
                    rhs, |ur| results.extend(
                        lhs_selected.iter().map(|lhs|
                            ValueEvalResult::ComparisonResult(
                                ComparisonResult::RhsUnresolved(ur.clone(), *lhs)))),
                    Vec::push
                );

                let mut diff = Vec::with_capacity(lhs_selected.len());
                'each_lhs: for eachl in &lhs_selected {
                    for eachr in &rhs_selected {
                        match contained_in(*eachl, *eachr) {
                            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) => {
                                continue 'each_lhs
                            },
                            _ => {}
                        }
                    }
                    diff.push(*eachl);
                }

                results.push(if diff.is_empty() {
                    ValueEvalResult::ComparisonResult(
                        ComparisonResult::Success(
                            Compare::QueryIn(QueryIn::new(diff, lhs_selected, rhs_selected))
                        )
                    )
                }
                else {
                    ValueEvalResult::ComparisonResult(
                        ComparisonResult::Fail(
                            Compare::QueryIn(QueryIn::new(diff, lhs_selected, rhs_selected))
                        )
                    )
                });
            }
        }
        Ok(EvalResult::Result(results))
    }

}

impl Comparator for EqOperation {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult<'value>],
        rhs: &[QueryResult<'value>]) -> crate::rules::Result<EvalResult<'value>> {
        let mut results = Vec::with_capacity(lhs.len());
        match (is_literal(lhs), is_literal(rhs)) {
            (Some(l), Some(r)) => {
                results.push(
                    match_value(l, r, compare_eq)
                );
            },

            (Some(l), None) => {
                let rhs = selected(
                    rhs,
                    |ur| results.push(
                        ValueEvalResult::ComparisonResult(
                            ComparisonResult::RhsUnresolved(
                                ur.clone(), l))),
                    Vec::push
                );

                match l {
                    PathAwareValue::List(_) => {
                        for each in rhs {
                            results.push(
                                match_value(l, each, compare_eq)
                            );
                        }
                    },

                    single_value => {
                        for eachr in rhs {
                            match eachr {
                                PathAwareValue::List((_, rhsl)) => {
                                    for each_rhs in rhsl {
                                        results.push(
                                            match_value(single_value, each_rhs, compare_eq)
                                        );
                                    }
                                },

                                rest_rhs => {
                                    results.push(
                                        match_value(single_value, rest_rhs, compare_eq)
                                    );
                                }
                            }
                        }
                    }
                }
            },

            (None, Some(r)) => {
                let lhs_flattened = selected(
                    lhs, |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())), Vec::push);
                match r {
                    PathAwareValue::List((_, rhsl)) => {
                        for each in lhs_flattened {
                            if each.is_scalar() && rhsl.len() == 1 {
                                results.push(
                                    match_value(each, &rhsl[0], compare_eq)
                                )
                            }
                            else {
                                results.push(
                                    match_value(each, r, compare_eq)
                                );
                            }
                        }
                    },

                    single_value => {
                        for each in lhs_flattened {
                            if let PathAwareValue::List((_, lhs_list)) = each {
                                for each_lhs in lhs_list {
                                    results.push(match_value(each_lhs, single_value, compare_eq));
                                }
                            }
                            else {
                                results.push(
                                    match_value(each, r, compare_eq)
                                );
                            }
                        }
                    },
                }
            },

            (None, None) => {
                let lhs_selected = selected(
                    lhs,
                    |ur| results.push(ValueEvalResult::LhsUnresolved(ur.clone())),
                    Vec::push
                );
                let rhs_selected = selected(
                    rhs, |ur| results.extend(
                        lhs_selected.iter().map(|lhs|
                            ValueEvalResult::ComparisonResult(
                                ComparisonResult::RhsUnresolved(ur.clone(), *lhs)))),
                    Vec::push
                );

                let diff = if lhs_selected.len() > rhs_selected.len() {
                    lhs_selected.iter().filter(|e| !rhs_selected.contains(*e))
                        .map(|e| *e)
                        .collect::<Vec<_>>()
                } else {
                    rhs_selected.iter().filter(|e| !lhs_selected.contains(*e))
                        .map(|e| *e)
                        .collect::<Vec<_>>()
                };

                results.push(
                    if diff.is_empty() {
                        ValueEvalResult::ComparisonResult(
                            ComparisonResult::Success(
                                Compare::QueryIn(
                                    QueryIn::new(diff, lhs_selected, rhs_selected)
                                )
                            )
                        )
                    } else {
                        ValueEvalResult::ComparisonResult(
                            ComparisonResult::Fail(
                                Compare::QueryIn(
                                    QueryIn::new(diff, lhs_selected, rhs_selected)
                                )
                            )
                        )
                    }
                );
            }
        }
        Ok(EvalResult::Result(results))
    }
}

impl Comparator for crate::rules::CmpOperator {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult<'value>],
        rhs: &[QueryResult<'value>]) -> crate::rules::Result<EvalResult<'value>> {
        if lhs.is_empty() || rhs.is_empty() {
            return Ok(EvalResult::Skip)
        }

        match self {
            CmpOperator::Eq => EqOperation{}.compare(lhs, rhs),
            CmpOperator::In => InOperation{}.compare(lhs, rhs),
            CmpOperator::Lt => CommonOperator{ comparator: compare_lt }.compare(lhs, rhs),
            CmpOperator::Gt => CommonOperator{ comparator: compare_gt }.compare(lhs, rhs),
            CmpOperator::Le => CommonOperator{ comparator: compare_le }.compare(lhs, rhs),
            CmpOperator::Ge => CommonOperator{ comparator: compare_ge }.compare(lhs, rhs),
            _ => return Err(crate::rules::Error::new(ErrorKind::IncompatibleError(
                format!("Operation {} NOT PERMITTED", self)
            ))),
        }
    }
}

impl Comparator for (crate::rules::CmpOperator, bool) {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult<'value>],
        rhs: &[QueryResult<'value>]) -> crate::rules::Result<EvalResult<'value>> {
        let results = self.0.compare(lhs, rhs)?;
        Ok(match results {
            EvalResult::Skip => EvalResult::Skip,
            EvalResult::Result(r) => {
                if self.1 {
                    EvalResult::Result(r.into_iter().map(|e| match e {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(c)) =>
                            match c {
                                Compare::QueryIn(qin) => {
                                    let mut reverse_diff = Vec::with_capacity(qin.lhs.len());
                                    for each in &qin.lhs {
                                        if !qin.diff.contains(each) {
                                            reverse_diff.push(*each)
                                        }
                                    }
                                    if reverse_diff.is_empty() {
                                        ValueEvalResult::ComparisonResult(
                                            ComparisonResult::Success(
                                                Compare::QueryIn(QueryIn::new(reverse_diff, qin.lhs, qin.rhs))
                                            )
                                        )
                                    }
                                    else {
                                        ValueEvalResult::ComparisonResult(
                                            ComparisonResult::Fail(
                                                Compare::QueryIn(QueryIn::new(reverse_diff, qin.lhs, qin.rhs))
                                            )
                                        )
                                    }
                                },

                                Compare::ListIn(lin) => {
                                    let lhs = match lin.lhs {
                                        PathAwareValue::List((_, v)) => v,
                                        _ => unreachable!()
                                    };
                                    let mut reverse_diff = Vec::with_capacity(lhs.len());
                                    for each in lhs {
                                        if !lin.diff.contains(&each) {
                                            reverse_diff.push(each)
                                        }
                                    }
                                    if reverse_diff.is_empty() {
                                        ValueEvalResult::ComparisonResult(
                                            ComparisonResult::Success(
                                                Compare::ListIn(ListIn::new(reverse_diff, lin.lhs, lin.rhs))
                                            )
                                        )
                                    }
                                    else {
                                        ValueEvalResult::ComparisonResult(
                                            ComparisonResult::Fail(
                                                Compare::ListIn(ListIn::new(reverse_diff, lin.lhs, lin.rhs))
                                            )
                                        )
                                    }
                                },
                                rest => ValueEvalResult::ComparisonResult(ComparisonResult::Success(rest))
                            }

                        ValueEvalResult::ComparisonResult(ComparisonResult::Success(c)) =>
                            match c {
                                Compare::QueryIn(qin) => {
                                    let mut reverse_diff = Vec::with_capacity(qin.lhs.len());
                                    reverse_diff.extend(qin.lhs.clone());
                                    ValueEvalResult::ComparisonResult(
                                        ComparisonResult::Fail(
                                            Compare::QueryIn(
                                                QueryIn::new(
                                                reverse_diff,
                                                qin.lhs,
                                                qin.rhs)
                                            )
                                        )
                                    )
                                },

                                Compare::ListIn(lin) => {
                                    let lhs = match lin.lhs {
                                        PathAwareValue::List((_, v)) => v,
                                        _ => unreachable!()
                                    };
                                    let mut reverse_diff = Vec::with_capacity(lhs.len());
                                    for each in lhs {
                                        reverse_diff.push(each);
                                    }
                                    ValueEvalResult::ComparisonResult(
                                        ComparisonResult::Fail(
                                            Compare::ListIn(
                                                ListIn::new(reverse_diff, lin.lhs, lin.rhs)
                                            )
                                        )
                                    )
                                },

                                rest =>
                                    ValueEvalResult::ComparisonResult(ComparisonResult::Fail(rest)),
                            }

                        //
                        // Everything else
                        //
                        rest => rest,
                    }).collect())
                }
                else {
                    EvalResult::Result(r)
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "operators_tests.rs"]
mod operators_tests;