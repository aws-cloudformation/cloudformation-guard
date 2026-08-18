use super::exprs::*;
use super::*;
use crate::rules::eval::operators::Comparator;
use crate::rules::eval_context::{block_scope, resolve_function, ValueScope};
use crate::rules::path_value::compare_eq;
use std::collections::HashMap;

mod operators;

fn exists_operation(value: &QueryResult) -> Result<bool> {
    Ok(match value {
        QueryResult::Resolved(_) | QueryResult::Literal(_) => true,
        QueryResult::UnResolved(_) => false,
    })
}

fn element_empty_operation(value: &QueryResult) -> Result<bool> {
    let result = match value {
        QueryResult::Literal(value) | QueryResult::Resolved(value) => match &**value {
            PathAwareValue::List((_, list)) => list.is_empty(),
            PathAwareValue::Map((_, map)) => map.is_empty(),
            PathAwareValue::String((_, string)) => string.is_empty(),
            // No Bool arm. It computed `(*boolean).to_string().is_empty()`, and neither
            // "true" nor "false" is ever the empty string, so EMPTY on a boolean was
            // unconditionally false and `!EMPTY` unconditionally true -- a clause that reads
            // like a check and cannot fail for any input.
            //
            // Falling through to the incompatible-type error below is the same treatment
            // every other unsupported type gets, and it turns a silent always-pass into a
            // diagnostic naming the path. `boolean_empty_is_an_incompatible_type` covers all
            // four combinations of value and polarity.
            _ => {
                return Err(Error::IncompatibleError(format!(
                    "Attempting EMPTY operation on type {} that does not support it at {}",
                    value.type_info(),
                    value.self_path()
                )))
            }
        },

        //
        // !EXISTS is the same as EMPTY
        //
        QueryResult::UnResolved(_) => true,
    };
    Ok(result)
}

macro_rules! is_type_fn {
    ($name: ident, $type_: pat) => {
        fn $name(value: &QueryResult) -> Result<bool> {
            Ok(match value {
                QueryResult::Literal(resolved) | QueryResult::Resolved(resolved) => {
                    match **resolved {
                        $type_ => true,
                        _ => false,
                    }
                }
                QueryResult::UnResolved(_) => false,
            })
        }
    };
}

is_type_fn!(is_string_operation, PathAwareValue::String(_));
is_type_fn!(is_list_operation, PathAwareValue::List(_));
is_type_fn!(is_struct_operation, PathAwareValue::Map(_));
is_type_fn!(is_int_operation, PathAwareValue::Int(_));
is_type_fn!(is_float_operation, PathAwareValue::Float(_));
is_type_fn!(is_bool_operation, PathAwareValue::Bool(_));
#[cfg(test)]
is_type_fn!(is_char_range_operation, PathAwareValue::RangeChar(_));
#[cfg(test)]
is_type_fn!(is_int_range_operation, PathAwareValue::RangeInt(_));
#[cfg(test)]
is_type_fn!(is_float_range_operation, PathAwareValue::RangeFloat(_));
is_type_fn!(is_null_operation, PathAwareValue::Null(_));

fn not_operation<O>(operation: O) -> impl Fn(&QueryResult) -> Result<bool>
where
    O: Fn(&QueryResult) -> Result<bool>,
{
    move |value: &QueryResult| {
        Ok(match operation(value)? {
            true => false,
            false => true,
        })
    }
}

fn inverse_operation<O>(operation: O, inverse: bool) -> impl Fn(&QueryResult) -> Result<bool>
where
    O: Fn(&QueryResult) -> Result<bool>,
{
    move |value: &QueryResult| {
        Ok(match inverse {
            true => !operation(value)?,
            false => operation(value)?,
        })
    }
}

#[allow(clippy::type_complexity)]
fn record_unary_clause<'eval, 'value, 'loc: 'value, O>(
    operation: O,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'eval mut dyn EvalContext<'value, 'loc>,
) -> Box<dyn FnMut(&QueryResult) -> Result<bool> + 'eval>
where
    O: Fn(&QueryResult) -> Result<bool> + 'eval,
{
    Box::new(move |value: &QueryResult| {
        eval_context.start_record(&context)?;
        let mut check = ValueCheck {
            custom_message: custom_message.clone(),
            message: None,
            status: Status::PASS,
            from: value.clone(),
        };
        match operation(value) {
            Ok(result) => {
                if !result {
                    check.status = Status::FAIL;
                    eval_context.end_record(
                        &context,
                        RecordType::ClauseValueCheck(ClauseCheck::Unary(UnaryValueCheck {
                            value: check,
                            comparison: cmp,
                        })),
                    )?;
                } else {
                    eval_context
                        .end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                }
                Ok(result)
            }

            Err(e) => {
                check.status = Status::FAIL;
                check.message = Some(format!("{}", e));
                eval_context.end_record(
                    &context,
                    RecordType::ClauseValueCheck(ClauseCheck::Unary(UnaryValueCheck {
                        value: check,
                        comparison: cmp,
                    })),
                )?;
                Err(e)
            }
        }
    })
}

macro_rules! box_create_func {
    ($name: ident, $not: expr, $inverse: expr, $cmp: ident, $eval: ident, $cxt: ident, $msg: ident) => {{
        {
            match $not {
                true => record_unary_clause(
                    inverse_operation(not_operation($name), $inverse),
                    $cmp,
                    $cxt,
                    $msg,
                    $eval,
                ),

                false => {
                    record_unary_clause(inverse_operation($name, $inverse), $cmp, $cxt, $msg, $eval)
                }
            }
        }
    }};
}

pub(super) enum EvaluationResult {
    /// An overall status with no per-value results, plus an optional explanation.
    ///
    /// The message is threaded into the `BlockCheck` the clause reports, which is the only
    /// place a rule author sees it. It matters for the empty-reference cases: a clause that
    /// fails because the thing it compares against resolved to no values needs to say so,
    /// or the author is left looking for a fault in the template rather than in the ruleset.
    EmptyQueryResult(Status, Option<String>),
    QueryValueResult(Vec<(QueryResult, Status)>),
}

/// Explanation attached to a clause that could not compare because its right-hand reference
/// resolved to no values.
///
/// Names the remedy as well as the cause. An author who genuinely expects a possibly-empty
/// reference can wrap the clause in `when <reference> !empty { ... }`: the gate's own
/// `!empty` check fails when the reference is empty, so the block is skipped rather than
/// failed, and the comparison never runs.
fn empty_reference_message(negated: bool) -> String {
    let clause = if negated {
        "negated comparison"
    } else {
        "comparison"
    };
    format!(
        "The {clause} could not be performed: the reference on the right-hand side resolved \
         to no values. If an empty reference is expected here, guard the clause with `when \
         <reference> !empty {{ ... }}` so it is skipped rather than failed."
    )
}

/// Why a clause is being evaluated, which decides what an unevaluatable clause
/// should report.
///
/// The distinction is load-bearing, not cosmetic. `eval_rule` and
/// `eval_when_condition_block` treat any non-PASS *condition* as "this rule does not
/// apply" and skip the guarded body entirely. So a clause that fails as an assertion
/// must only SKIP as a gate -- failing a gate silently disarms every check inside it
/// and the file still exits 0.
///
/// Carried as an enum rather than a `bool` deliberately. A boolean parameter reads as
/// `f(x, resolver, true)` at the call site, which says nothing about intent and is
/// easy to omit: an earlier version of this threading passed booleans and left
/// `WhenGuardClause::ParameterizedNamedRule` unthreaded, so a parameterized rule
/// invoked from a `when` condition evaluated its body with assertion strictness and
/// produced exactly the wrong-PASS described above. With an explicit parameter type
/// every construction site has to name which case it is.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum ClauseRole {
    /// The clause is an assertion in a rule body. An unevaluatable clause is a
    /// failure: the rule claimed something it could not establish.
    Assertion,
    /// The clause is a `when` condition gating a block. An unevaluatable clause is
    /// not applicable, never a failure, so the block it guards is still decided by
    /// the remaining conditions.
    Gate,
}

impl ClauseRole {
    /// True when an unevaluatable clause in this role should FAIL rather than SKIP.
    fn is_strict(self) -> bool {
        matches!(self, ClauseRole::Assertion)
    }
}

#[allow(clippy::type_complexity)]
fn unary_operation<'r, 'l: 'r, 'loc: 'l>(
    lhs_query: &'l [QueryPart<'loc>],
    cmp: (CmpOperator, bool),
    inverse: bool,
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'l, 'loc>,
) -> Result<EvaluationResult> {
    let lhs = eval_context.query(lhs_query)?;

    //
    // Take care of the !empty clause without view projection, e.g. when checking %result !empty
    // That would translated to checking if each value was Resolved or UnResolved. If Resolved
    // then it is NOT EMPTY, if UnResolved it is EMPTY.
    //
    // NOTE: the check will pass the query for only one value resolved. Which is the correct behavior
    // For all the unresolved ones the individual clause associated will FAIL, this is the right
    // outcome. The earlier engine would suppress such a error and skip
    //
    let empty_on_expr = match &lhs_query[lhs_query.len() - 1] {
        QueryPart::Filter(_, _) | QueryPart::MapKeyFilter(_, _) => true,
        rest => rest.is_variable() && lhs_query.len() == 1,
    };

    if empty_on_expr && cmp.0 == CmpOperator::Empty {
        return Ok({
            if !lhs.is_empty() {
                let mut results = Vec::with_capacity(lhs.len());
                for each in lhs {
                    eval_context.start_record(&context)?;
                    let (result, status) = match each {
                        QueryResult::Literal(res) | QueryResult::Resolved(res) => {
                            //
                            // NULL == EMPTY
                            //
                            let status = if cmp.1 {
                                // Not empty
                                !res.is_null()
                            } else {
                                res.is_null()
                            };
                            (
                                QueryResult::Resolved(res),
                                match status {
                                    true => Status::PASS,  // not_empty
                                    false => Status::FAIL, // fail not_empty
                                },
                            )
                        }

                        QueryResult::UnResolved(ur) => {
                            (
                                QueryResult::UnResolved(ur),
                                match cmp.1 {
                                    true => Status::FAIL,  // !EXISTS == EMPTY, so !EMPTY == FAIL
                                    false => Status::PASS, // !EXISTS == EMPTY so PASS
                                },
                            )
                        }
                    };
                    let status = if inverse {
                        match status {
                            Status::PASS => Status::FAIL,
                            Status::FAIL => Status::PASS,
                            _ => unreachable!(),
                        }
                    } else {
                        status
                    };

                    match status {
                        Status::PASS => {
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Success),
                            )?;
                        }
                        Status::FAIL => {
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Unary(UnaryValueCheck {
                                    comparison: cmp,
                                    value: ValueCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        from: result.clone(),
                                    },
                                })),
                            )?;
                        }
                        _ => unreachable!(),
                    }

                    results.push((result, status));
                }
                EvaluationResult::QueryValueResult(results)
            } else {
                EvaluationResult::EmptyQueryResult(
                    {
                        let result = !cmp.1;
                        let result = if inverse { !result } else { result };
                        match result {
                            true => {
                                eval_context.start_record(&context)?;
                                eval_context.end_record(
                                    &context,
                                    RecordType::ClauseValueCheck(ClauseCheck::Success),
                                )?;
                                Status::PASS
                            }
                            false => {
                                eval_context.start_record(&context)?;
                                eval_context.end_record(
                                    &context,
                                    RecordType::ClauseValueCheck(
                                        ClauseCheck::NoValueForEmptyCheck(custom_message),
                                    ),
                                )?;
                                Status::FAIL
                            }
                        }
                    },
                    // The unary EMPTY path already records its own ClauseValueCheck above,
                    // including NoValueForEmptyCheck for the failing case, so there is
                    // nothing an extra block-level message would add here.
                    None,
                )
            }
        });
    }

    //
    // This only happens when the query has filters in them
    //
    if lhs.is_empty() {
        return Ok(EvaluationResult::EmptyQueryResult(Status::SKIP, None));
    }

    use CmpOperator::*;
    let mut operation: Box<dyn FnMut(&QueryResult) -> Result<bool>> = match cmp {
        (CmpOperator::Exists, not_exists) => box_create_func!(
            exists_operation,
            not_exists,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::Empty, not_empty) => box_create_func!(
            element_empty_operation,
            not_empty,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsString, is_not_string) => box_create_func!(
            is_string_operation,
            is_not_string,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsMap, is_not_map) => box_create_func!(
            is_struct_operation,
            is_not_map,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsList, is_not_list) => box_create_func!(
            is_list_operation,
            is_not_list,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsBool, is_not_bool) => box_create_func!(
            is_bool_operation,
            is_not_bool,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsInt, is_not_int) => box_create_func!(
            is_int_operation,
            is_not_int,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsNull, is_not_null) => box_create_func!(
            is_null_operation,
            is_not_null,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsFloat, is_not_float) => box_create_func!(
            is_float_operation,
            is_not_float,
            inverse,
            cmp,
            eval_context,
            context,
            custom_message
        ),
        (Eq | Gt | Ge | Lt | Le | In, _) => unreachable!(),
    };
    let mut status = Vec::with_capacity(lhs.len());
    for each in lhs {
        match (*operation)(&each)? {
            true => {
                status.push((each, Status::PASS));
            }

            false => {
                status.push((each, Status::FAIL));
            }
        }
    }
    Ok(EvaluationResult::QueryValueResult(status))
}

enum ComparisonResult {
    Comparable(ComparisonWithRhs),
    NotComparable(NotComparableWithRhs),
    UnResolvedRhs(UnResolvedRhs),
}

struct LhsRhsPair {
    lhs: Rc<PathAwareValue>,
    rhs: Rc<PathAwareValue>,
}

struct ComparisonWithRhs {
    outcome: bool,
    pair: LhsRhsPair,
}

#[allow(dead_code)]
struct NotComparableWithRhs {
    reason: String,
    pair: LhsRhsPair,
}

struct UnResolvedRhs {
    rhs: QueryResult,
    lhs: Rc<PathAwareValue>,
}

fn each_lhs_compare<C>(
    cmp: C,
    lhs: Rc<PathAwareValue>,
    rhs: &[QueryResult],
) -> Result<Vec<ComparisonResult>>
where
    C: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>,
{
    let mut statues = Vec::with_capacity(rhs.len());
    for each_rhs in rhs {
        match each_rhs {
            QueryResult::Literal(each_rhs_resolved) | QueryResult::Resolved(each_rhs_resolved) => {
                match cmp(&lhs, each_rhs_resolved) {
                    Ok(outcome) => {
                        statues.push(ComparisonResult::Comparable(ComparisonWithRhs {
                            outcome,
                            pair: LhsRhsPair {
                                lhs: Rc::clone(&lhs),
                                rhs: Rc::clone(each_rhs_resolved),
                            },
                        }));
                    }

                    Err(Error::NotComparable(reason)) => {
                        if lhs.is_list() {
                            // && each_rhs_resolved.is_scalar() {
                            if let PathAwareValue::List((_, inner)) = &*lhs {
                                for each in inner {
                                    match cmp(each, each_rhs_resolved) {
                                        Ok(outcome) => {
                                            statues.push(ComparisonResult::Comparable(
                                                ComparisonWithRhs {
                                                    outcome,
                                                    pair: LhsRhsPair {
                                                        lhs: Rc::new(each.clone()),
                                                        rhs: Rc::clone(each_rhs_resolved),
                                                    },
                                                },
                                            ));
                                        }

                                        Err(Error::NotComparable(reason)) => {
                                            statues.push(ComparisonResult::NotComparable(
                                                NotComparableWithRhs {
                                                    reason,
                                                    pair: LhsRhsPair {
                                                        lhs: Rc::new(each.clone()),
                                                        rhs: Rc::clone(each_rhs_resolved),
                                                    },
                                                },
                                            ));
                                        }

                                        Err(e) => return Err(e),
                                    }
                                }
                                continue;
                            }
                        }

                        if lhs.is_scalar() {
                            if let QueryResult::Literal(_) = each_rhs {
                                if let PathAwareValue::List((_, rhs)) = &**each_rhs_resolved {
                                    if rhs.len() == 1 {
                                        let rhs_inner_single_element = &rhs[0];
                                        match cmp(&lhs, rhs_inner_single_element) {
                                            Ok(outcome) => {
                                                statues.push(ComparisonResult::Comparable(
                                                    ComparisonWithRhs {
                                                        outcome,
                                                        pair: LhsRhsPair {
                                                            lhs: Rc::clone(&lhs),
                                                            rhs: Rc::new(
                                                                rhs_inner_single_element.clone(),
                                                            ),
                                                        },
                                                    },
                                                ));
                                            }

                                            Err(Error::NotComparable(reason)) => {
                                                statues.push(ComparisonResult::NotComparable(
                                                    NotComparableWithRhs {
                                                        reason,
                                                        pair: LhsRhsPair {
                                                            lhs: Rc::clone(&lhs),
                                                            rhs: Rc::new(
                                                                rhs_inner_single_element.clone(),
                                                            ),
                                                        },
                                                    },
                                                ));
                                            }

                                            Err(e) => return Err(e),
                                        }
                                        continue;
                                    }
                                }
                            }
                        }

                        statues.push(ComparisonResult::NotComparable(NotComparableWithRhs {
                            reason,
                            pair: LhsRhsPair {
                                lhs: Rc::clone(&lhs),
                                rhs: Rc::clone(each_rhs_resolved),
                            },
                        }));
                    }

                    Err(e) => return Err(e),
                }
            }

            QueryResult::UnResolved(_ur) => {
                statues.push(ComparisonResult::UnResolvedRhs(UnResolvedRhs {
                    rhs: each_rhs.clone(),
                    lhs: Rc::clone(&lhs),
                }));
            }
        }
    }
    Ok(statues)
}

fn in_cmp(not_in: bool) -> impl Fn(&PathAwareValue, &PathAwareValue) -> Result<bool> {
    move |lhs, rhs| match (lhs, rhs) {
        (PathAwareValue::String((_, lhs_value)), PathAwareValue::String((_, rhs_value))) => {
            let result = rhs_value.contains(lhs_value);
            Ok(if not_in { !result } else { result })
        }

        (_, PathAwareValue::List((_, rhs_list))) => Ok({
            let mut tracking = Vec::with_capacity(rhs_list.len());
            for each_rhs in rhs_list {
                tracking.push(compare_eq(lhs, each_rhs)?);
            }
            match tracking.iter().find(|s| **s) {
                Some(_) => !not_in,
                None => not_in,
            }
        }),

        (_, _) => {
            let result = compare_eq(lhs, rhs)?;
            Ok(if not_in { !result } else { result })
        }
    }
}

fn report_value<'r, 'value: 'r, 'loc: 'value>(
    each_res: &ComparisonResult,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<(QueryResult, Status)> {
    let (lhs_value, rhs_value, outcome, reason) = match each_res {
        ComparisonResult::Comparable(ComparisonWithRhs {
            outcome,
            pair:
                LhsRhsPair {
                    lhs: lhs_value,
                    rhs: rhs_value,
                },
        }) => (
            QueryResult::Resolved(Rc::clone(lhs_value)),
            Some(QueryResult::Resolved(Rc::clone(rhs_value))),
            *outcome,
            None,
        ),
        //},
        ComparisonResult::NotComparable(NotComparableWithRhs {
            pair:
                LhsRhsPair {
                    rhs: rhs_value,
                    lhs: lhs_value,
                },
            ..
        }) => (
            QueryResult::Resolved(Rc::clone(lhs_value)),
            Some(QueryResult::Resolved(Rc::clone(rhs_value))),
            false,
            None,
        ),
        //            },
        ComparisonResult::UnResolvedRhs(UnResolvedRhs {
            lhs: lhs_value,
            rhs: rhs_query_result,
        }) => (
            QueryResult::Resolved(Rc::clone(lhs_value)),
            Some(rhs_query_result.clone()),
            false,
            None,
        ), //            }
    };

    Ok(if outcome {
        eval_context.start_record(&context)?;
        eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
        (lhs_value, Status::PASS)
    } else {
        eval_context.start_record(&context)?;
        eval_context.end_record(
            &context,
            RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
                from: lhs_value.clone(),
                comparison: cmp,
                to: rhs_value,
                custom_message,
                message: reason,
                status: Status::FAIL,
            })),
        )?;
        (lhs_value, Status::FAIL)
    })
}

fn report_all_values<'r, 'value: 'r, 'loc: 'value>(
    comparisons: Vec<ComparisonResult>,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<(QueryResult, Status)>> {
    let mut status = Vec::with_capacity(comparisons.len());
    for each_res in comparisons {
        status.push(report_value(
            &each_res,
            cmp,
            context.clone(),
            custom_message.clone(),
            eval_context,
        )?);
    }
    Ok(status)
}

fn report_at_least_one<'r, 'value: 'r, 'loc: 'value>(
    rhs_comparisons: Vec<ComparisonResult>,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<(QueryResult, Status)>> {
    let mut statues = Vec::with_capacity(rhs_comparisons.len());
    let mut by_lhs_value = HashMap::new();
    for each in &rhs_comparisons {
        match each {
            ComparisonResult::Comparable(ComparisonWithRhs {
                pair: LhsRhsPair { lhs, rhs },
                ..
            }) => {
                by_lhs_value
                    .entry(lhs)
                    .or_insert(vec![])
                    .push((each, QueryResult::Resolved(Rc::clone(rhs))));
            }

            ComparisonResult::NotComparable(NotComparableWithRhs {
                pair: LhsRhsPair { lhs, rhs },
                ..
            }) => {
                by_lhs_value
                    .entry(lhs)
                    .or_insert(vec![])
                    .push((each, QueryResult::Resolved(Rc::clone(rhs))));
            }

            ComparisonResult::UnResolvedRhs(UnResolvedRhs { rhs, lhs }) => {
                if let QueryResult::UnResolved(..) = rhs {
                    by_lhs_value
                        .entry(lhs)
                        .or_insert(vec![])
                        .push((each, rhs.clone()));
                }
            }
        }
    }

    for (lhs, results) in by_lhs_value.iter() {
        let found = results.iter().find(|(r, _rhs)| {
            matches!(
                r,
                ComparisonResult::Comparable(ComparisonWithRhs { outcome: true, .. })
            )
        });
        match found {
            Some(_) => {
                eval_context.start_record(&context)?;
                eval_context
                    .end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                statues.push((QueryResult::Resolved(Rc::clone(lhs)), Status::PASS))
            }
            None => {
                eval_context.start_record(&context)?;

                let to_collected = results
                    .iter()
                    .map(|(_, rhs)| rhs.clone())
                    .collect::<Vec<QueryResult>>();

                eval_context.end_record(
                    &context,
                    RecordType::ClauseValueCheck(ClauseCheck::InComparison(InComparisonCheck {
                        from: QueryResult::Resolved(Rc::clone(lhs)),
                        to: to_collected,
                        message: None,
                        custom_message: custom_message.clone(),
                        status: Status::FAIL,
                        comparison: cmp,
                    })),
                )?;
                statues.push((QueryResult::Resolved(Rc::clone(lhs)), Status::FAIL))
            }
        }
    }
    Ok(statues)
}

fn not_compare<O>(cmp: O, invert: bool) -> impl Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
where
    O: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>,
{
    move |lhs, rhs| {
        let r = cmp(lhs, rhs)?;
        Ok(if invert { !r } else { r })
    }
}

/// `role` decides what a positive comparison against an empty reference reports: it
/// is unsatisfiable, so it fails as an [`ClauseRole::Assertion`] but must stay a SKIP
/// as a [`ClauseRole::Gate`]. See [`ClauseRole`] for why failing a gate is unsafe.
fn binary_operation<'value, 'loc: 'value>(
    lhs_query: &'value [QueryPart<'loc>],
    rhs: &[QueryResult],
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<EvaluationResult> {
    let lhs = eval_context.query(lhs_query)?;
    let results = cmp.compare(&lhs, rhs)?;
    match results {
        operators::EvalResult::Skip => Ok(EvaluationResult::EmptyQueryResult(Status::SKIP, None)),

        // Positive comparison against a reference that resolved to nothing. No value
        // can be one of zero references, so the clause is unsatisfiable and every
        // left-hand value fails. Returning a definite status keeps the clause
        // enforced instead of exiting 0 unevaluated.
        //
        // A status is emitted rather than a per-value comparison record because there
        // is no right-hand value to report against, and `from:` must not be built
        // from a raw lhs entry -- an lhs can be QueryResult::Literal (a `let`
        // literal), which every reporter treats as unreachable in a comparison.
        //
        // In a `when` condition this stays a SKIP, because of how the condition fold
        // treats the two statuses. `eval_conjunction_clauses` absorbs a SKIP (`Status::SKIP
        // => {}`) but counts a FAIL, and it answers FAIL before PASS. So a FAIL here
        // overrides sibling conditions that passed and drops a body those siblings would
        // have enforced, at exit 0; a SKIP is absorbed and lets them decide.
        // `empty_reference_in_a_when_condition_does_not_disarm_the_block` pins that.
        //
        // With a single condition the two statuses are indistinguishable -- `eval_rule` maps
        // every non-PASS condition to `Status::SKIP` for the rule either way -- so the
        // difference is only observable alongside a condition that passes.
        operators::EvalResult::EmptyRhsUnsatisfiable => Ok(EvaluationResult::EmptyQueryResult(
            if role.is_strict() {
                Status::FAIL
            } else {
                Status::SKIP
            },
            Some(empty_reference_message(false)),
        )),

        // Negated comparison against a reference that resolved to nothing. Fails closed as
        // an assertion.
        //
        // The tempting reading is that this is vacuously satisfied -- there is nothing to
        // collide with, and an empty denylist is the normal state whenever a template
        // contains none of the denied values. That reading is what the previous SKIP
        // encoded, and the comment here used to claim "the weaker status costs nothing in
        // the standalone case". What it costs is the enforcement of the clause: a rule whose
        // only check is `Property != %empty_reference` exited 0 having compared nothing,
        // which is a denylist bypass rather than a compliant result.
        //
        // The two error modes are not symmetric, which is what settles it. A wrong FAIL is
        // visible and gets investigated. A wrong SKIP exits 0 and is indistinguishable from
        // PASS in CI, so nobody ever looks. Requiring the author to declare the expectation
        // instead -- an accompanying `!empty` guard -- was considered and rejected: it leaves
        // every existing ruleset that lacks such a guard silently defeatable, which is the
        // state being fixed.
        //
        // The legitimate empty-reference case keeps an escape hatch, and it needs no new
        // machinery: `when <reference> !empty { ... }` closes on an empty reference, because
        // the gate's own `!empty` check fails, so the block is skipped and the comparison
        // never runs. `an_empty_reference_can_be_guarded_with_a_when_not_empty_gate` pins it.
        //
        // Role-aware for the same reason as the arm above rather than failing unconditionally:
        // a FAIL on a `when` condition is counted by the condition fold and outranks sibling
        // conditions that passed, so it would drop a body those siblings would have enforced.
        // `negated_empty_reference_in_a_when_condition_does_not_disarm_the_block` pins that.
        operators::EvalResult::EmptyRhsVacuouslyTrue => Ok(EvaluationResult::EmptyQueryResult(
            if role.is_strict() {
                Status::FAIL
            } else {
                Status::SKIP
            },
            Some(empty_reference_message(true)),
        )),

        // Unreached in practice: `cmp` here is a (CmpOperator, bool) pair, and that
        // wrapper always resolves EmptyRhs into one of the two variants above. Fail
        // closed rather than panicking, so a future refactor that routes around the
        // wrapper cannot turn this into a silent pass.
        operators::EvalResult::EmptyRhs => Ok(EvaluationResult::EmptyQueryResult(
            if role.is_strict() {
                Status::FAIL
            } else {
                Status::SKIP
            },
            Some(empty_reference_message(cmp.1)),
        )),

        operators::EvalResult::Result(results) => {
            let mut statues: Vec<(QueryResult, Status)> = Vec::with_capacity(lhs.len());
            for each in results {
                match each {
                    operators::ValueEvalResult::LhsUnresolved(ur) => {
                        eval_context.start_record(&context)?;
                        eval_context.end_record(
                            &context,
                            RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                ComparisonClauseCheck {
                                    status: Status::FAIL,
                                    message: None,
                                    custom_message: custom_message.clone(),
                                    comparison: cmp,
                                    from: QueryResult::UnResolved(ur.clone()),
                                    to: None,
                                },
                            )),
                        )?;
                        statues.push((QueryResult::UnResolved(ur), Status::FAIL));
                    }

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::RhsUnresolved(urhs, lhs),
                    ) => {
                        eval_context.start_record(&context)?;
                        eval_context.end_record(
                            &context,
                            RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                ComparisonClauseCheck {
                                    status: Status::FAIL,
                                    message: None,
                                    custom_message: custom_message.clone(),
                                    comparison: cmp,
                                    from: QueryResult::Resolved(Rc::clone(&lhs)),
                                    to: Some(QueryResult::UnResolved(urhs)),
                                },
                            )),
                        )?;
                        statues.push((QueryResult::Resolved(Rc::clone(&lhs)), Status::FAIL));
                    }

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::NotComparable(nc),
                    ) => {
                        eval_context.start_record(&context)?;
                        eval_context.end_record(
                            &context,
                            RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                ComparisonClauseCheck {
                                    status: Status::FAIL,
                                    message: Some(nc.reason),
                                    custom_message: custom_message.clone(),
                                    comparison: cmp,
                                    from: QueryResult::Resolved(Rc::clone(&nc.pair.lhs)),
                                    to: Some(QueryResult::Resolved(nc.pair.rhs)),
                                },
                            )),
                        )?;
                        statues.push((QueryResult::Resolved(nc.pair.lhs), Status::FAIL));
                    }

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::Success(cmp),
                    ) => match cmp {
                        operators::Compare::ListIn(lin) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Success),
                            )?;
                            statues.push((QueryResult::Resolved(lin.lhs), Status::PASS));
                        }

                        operators::Compare::QueryIn(qin) => {
                            for each in qin.lhs {
                                eval_context.start_record(&context)?;
                                eval_context.end_record(
                                    &context,
                                    RecordType::ClauseValueCheck(ClauseCheck::Success),
                                )?;
                                statues.push((QueryResult::Resolved(each), Status::PASS));
                            }
                        }

                        operators::Compare::Value(pair) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Success),
                            )?;
                            statues.push((QueryResult::Resolved(pair.lhs), Status::PASS));
                        }

                        operators::Compare::ValueIn(val) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Success),
                            )?;
                            statues.push((QueryResult::Resolved(val.lhs), Status::PASS));
                        }
                    },

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::Fail(cmpr),
                    ) => match cmpr {
                        operators::Compare::Value(pair) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                    ComparisonClauseCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        comparison: cmp,
                                        from: QueryResult::Resolved(Rc::clone(&pair.lhs)),
                                        to: Some(QueryResult::Resolved(pair.rhs)),
                                    },
                                )),
                            )?;
                            statues
                                .push((QueryResult::Resolved(Rc::clone(&pair.lhs)), Status::FAIL));
                        }

                        operators::Compare::ValueIn(pair) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::InComparison(
                                    InComparisonCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        comparison: cmp,
                                        from: QueryResult::Resolved(Rc::clone(&pair.lhs)),
                                        to: vec![QueryResult::Resolved(pair.rhs)],
                                    },
                                )),
                            )?;
                            statues
                                .push((QueryResult::Resolved(Rc::clone(&pair.lhs)), Status::FAIL));
                        }

                        operators::Compare::ListIn(lin) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::InComparison(
                                    InComparisonCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        comparison: cmp,
                                        from: QueryResult::Resolved(Rc::clone(&lin.lhs)),
                                        to: vec![QueryResult::Resolved(lin.rhs)],
                                    },
                                )),
                            )?;
                            statues
                                .push((QueryResult::Resolved(Rc::clone(&lin.lhs)), Status::FAIL));
                        }

                        operators::Compare::QueryIn(qin) => {
                            let rhs = qin
                                .rhs
                                .iter()
                                .cloned()
                                .map(QueryResult::Resolved)
                                .collect::<Vec<_>>();

                            for lhs in qin.diff {
                                eval_context.start_record(&context)?;
                                eval_context.end_record(
                                    &context,
                                    RecordType::ClauseValueCheck(ClauseCheck::InComparison(
                                        InComparisonCheck {
                                            status: Status::FAIL,
                                            message: None,
                                            custom_message: custom_message.clone(),
                                            comparison: cmp,
                                            from: QueryResult::Resolved(Rc::clone(&lhs)),
                                            to: rhs.clone(),
                                        },
                                    )),
                                )?;
                                statues
                                    .push((QueryResult::Resolved(Rc::clone(&lhs)), Status::FAIL));
                            }
                        }
                    },
                }
            }
            Ok(EvaluationResult::QueryValueResult(statues))
        }
    }
}

/// Compares the keys of a map against a right-hand side, for `[ keys <op> ... ]` filters.
///
/// The narrowed `MapKeyComparator` rather than a `(CmpOperator, bool)` pair: this function's only
/// caller is `QueryPart::MapKeyFilter`, the parser admits four comparators there, and the wider
/// type left four arms here that nothing could reach. See the type's own comment for why that
/// mattered.
pub(super) fn real_binary_operation<'value, 'loc: 'value>(
    lhs: &[QueryResult],
    rhs: &[QueryResult],
    cmp: MapKeyComparator,
    context: String,
    custom_message: Option<String>,
    eval_context: &mut dyn EvalContext<'value, 'loc>,
) -> Result<EvaluationResult> {
    let mut statues: Vec<(QueryResult, Status)> = Vec::with_capacity(lhs.len());

    let cmp = cmp.widened_for(rhs.len());
    let recorded_cmp = cmp.as_cmp_operator();

    for each in lhs.iter() {
        match each {
            QueryResult::UnResolved(_ur) => {
                eval_context.start_record(&context)?;
                eval_context.end_record(
                    &context,
                    RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
                        status: Status::FAIL,
                        message: None,
                        custom_message: custom_message.clone(),
                        comparison: recorded_cmp,
                        from: each.clone(),
                        to: None,
                    })),
                )?;
                statues.push((each.clone(), Status::FAIL));
            }

            QueryResult::Literal(l) | QueryResult::Resolved(l) => {
                let r = match cmp {
                    MapKeyComparator::Eq | MapKeyComparator::NotEq => each_lhs_compare(
                        not_compare(
                            crate::rules::path_value::compare_eq,
                            cmp == MapKeyComparator::NotEq,
                        ),
                        Rc::clone(l),
                        rhs,
                    )?,

                    MapKeyComparator::In | MapKeyComparator::NotIn => {
                        each_lhs_compare(in_cmp(cmp == MapKeyComparator::NotIn), Rc::clone(l), rhs)?
                    }
                };

                match cmp {
                    // Membership is satisfied by one match, so the report folds that way.
                    MapKeyComparator::In | MapKeyComparator::NotIn => {
                        statues.extend(report_at_least_one(
                            r,
                            recorded_cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context,
                        )?);
                    }

                    MapKeyComparator::Eq | MapKeyComparator::NotEq => {
                        let status = report_all_values(
                            r,
                            recorded_cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context,
                        )?;
                        statues.extend(status);
                    }
                }
            }
        };
    }
    Ok(EvaluationResult::QueryValueResult(statues))
}

#[allow(clippy::never_loop)]
/// `role` is [`ClauseRole::Gate`] when this clause is a `when` condition; see
/// [`binary_operation`].
pub(in crate::rules) fn eval_guard_access_clause<'value, 'loc: 'value>(
    gac: &'value GuardAccessClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    let all = gac.access_clause.query.match_all;
    let blk_context = format!("GuardAccessClause#block{}", gac);
    resolver.start_record(&blk_context)?;

    let statues = if gac.access_clause.comparator.0.is_unary() {
        unary_operation(
            &gac.access_clause.query.query,
            gac.access_clause.comparator,
            gac.negation,
            format!("{}", gac),
            gac.access_clause.custom_message.clone(),
            resolver,
        )
    } else {
        let (rhs, _) = match &gac.access_clause.compare_with {
            Some(val) => match val {
                LetValue::Value(rhs_val) => {
                    (vec![QueryResult::Literal(Rc::new(rhs_val.clone()))], true)
                }
                LetValue::AccessClause(acc_querty) => match resolver.query(&acc_querty.query) {
                    Ok(result) => (result, false),
                    Err(e) => {
                        resolver.end_record(
                            &blk_context,
                            RecordType::GuardClauseBlockCheck(BlockCheck {
                                status: Status::FAIL,
                                at_least_one_matches: !all,
                                message: Some(format!("Error {e} when handling clause, bailing")),
                            }),
                        )?;
                        return Err(e);
                    }
                },
                LetValue::FunctionCall(FunctionExpr {
                    parameters, name, ..
                }) => match resolve_function(name, parameters, resolver) {
                    Ok(result) => (result, false),
                    Err(e) => {
                        resolver.end_record(
                            &blk_context,
                            RecordType::GuardClauseBlockCheck(BlockCheck {
                                status: Status::FAIL,
                                at_least_one_matches: !all,
                                message: Some(format!("Error {e} when handling clause, bailing")),
                            }),
                        )?;
                        return Err(e);
                    }
                },
            },
            None => {
                resolver.end_record(
                    &blk_context,
                    RecordType::GuardClauseBlockCheck(BlockCheck {
                        status: Status::FAIL,
                        at_least_one_matches: !all,
                        message: Some(
                            "Error not RHS for binary clause when handling clause, bailing"
                                .to_string(),
                        ),
                    }),
                )?;
                return Err(Error::NotComparable(format!(
                    "GuardAccessClause {}, did not have a RHS for compare operation",
                    blk_context
                )));
            }
        };
        // Clause-level negation (a leading `not`/`!`, parser.rs:969) must be applied
        // here. The unary path takes it as an argument, but this path previously
        // dropped it entirely, so `not <query> == <value>` evaluated as plain
        // `== <value>` -- the exact inverse of the author's intent -- while the
        // report still displayed the `not`.
        //
        // `comparator.1` is the operator's own not-flag (from `!=` / `not in`).
        // The two negations compose by XOR, matching invert_closure in the
        // superseded evaluator (evaluate.rs:293-307), which applies `clause_not`
        // and `not` as independent flips.
        let comparator = (
            gac.access_clause.comparator.0,
            gac.access_clause.comparator.1 ^ gac.negation,
        );
        binary_operation(
            &gac.access_clause.query.query,
            &rhs,
            comparator,
            format!("{}", gac),
            gac.access_clause.custom_message.clone(),
            resolver,
            role,
        )
    };

    match statues {
        Ok(statues) => match statues {
            EvaluationResult::EmptyQueryResult(status, message) => {
                resolver.end_record(
                    &blk_context,
                    RecordType::GuardClauseBlockCheck(BlockCheck {
                        status,
                        message,
                        at_least_one_matches: all,
                    }),
                )?;
                Ok(status)
            }
            EvaluationResult::QueryValueResult(result) => {
                let outcome = loop {
                    let mut fails = 0;
                    let mut pass = 0;
                    for (_value, status) in result {
                        match status {
                            Status::PASS => {
                                pass += 1;
                            }
                            Status::FAIL => {
                                fails += 1;
                            }
                            Status::SKIP => unreachable!(),
                        }
                    }
                    if all {
                        if fails > 0 {
                            break Status::FAIL;
                        }
                        break Status::PASS;
                    } else {
                        if pass > 0 {
                            break Status::PASS;
                        }
                        break Status::FAIL;
                    }
                };
                resolver.end_record(
                    &blk_context,
                    RecordType::GuardClauseBlockCheck(BlockCheck {
                        message: None,
                        status: outcome,
                        at_least_one_matches: !all,
                    }),
                )?;
                Ok(outcome)
            }
        },

        Err(e) => {
            resolver.end_record(
                &blk_context,
                RecordType::GuardClauseBlockCheck(BlockCheck {
                    status: Status::FAIL,
                    at_least_one_matches: !all,
                    message: Some(format!("Error {} when handling clause, bailing", e)),
                }),
            )?;

            Err(e)
        }
    }
}

/// Evaluates a reference to another rule by name.
///
/// `role` distinguishes the two contexts this is reached from:
///
/// - [`ClauseRole::Assertion`] — the reference is in a rule body, so a SKIPped
///   dependent rule must not satisfy it in either polarity. Failing closed here is
///   what stops `not <rule>` from reporting compliance for a check that never ran.
/// - [`ClauseRole::Gate`] — the reference is a `when` condition, where gating on a
///   rule that did not apply is deliberate and covered by existing tests.
pub(in crate::rules) fn eval_guard_named_clause<'value, 'loc: 'value>(
    gnc: &'value GuardNamedRuleClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    let context = format!("{}", gnc);
    resolver.start_record(&context)?;

    match resolver.rule_status(&gnc.dependent_rule) {
        Ok(status) => {
            let status = match status {
                Status::PASS => {
                    if gnc.negation {
                        Status::FAIL
                    } else {
                        Status::PASS
                    }
                }

                // A dependent rule that SKIPped never ran, so it is not evidence in
                // either direction. Where this reference is an assertion in a rule
                // body, a negated reference to it must not report compliance on the
                // strength of a check that was never performed: `not <rule>` used to
                // fall into the `_` arm below and yield PASS, and because the
                // enclosing rule then reported PASS rather than SKIP, nothing in the
                // output hinted at the omission.
                //
                // In a `when` condition the same shape is deliberate and tested --
                // `rule r when !other { ... }` is how a ruleset says "apply this
                // when that other rule did not apply" (see
                // cross_rule_clause_when_checks). Gating on a SKIP there is not a
                // compliance claim, so it keeps the existing behavior.
                Status::SKIP if role.is_strict() => Status::FAIL,

                // A gate whose dependent rule did not apply stays SKIP rather than
                // falling into the `_` arm below, which turns a non-negated reference
                // into FAIL. `eval_conjunction_clauses` counts a FAIL and absorbs a
                // SKIP, and answers FAIL before PASS, so one inapplicable gate
                // condition returning FAIL outranks the sibling conditions that passed
                // and drops a body those siblings would have enforced -- at exit 0,
                // which is precisely what `ClauseRole::Gate` exists to prevent.
                //
                // `eval_parameterized_rule_call` already does this and its comment
                // claims to mirror this function, but the two spellings of the same
                // gate disagreed: `when skipper` plus a passing sibling condition
                // reported SKIP for the whole file and enforced nothing, while
                // `when skipper(...)` plus the same sibling reported FAIL and exited
                // 19. Pinned by
                // `a_named_rule_gate_on_a_skipped_rule_does_not_disarm_the_block`.
                //
                // Negated references keep falling through: `not <rule>` where the rule
                // did not apply must not report PASS on the strength of a check that
                // never ran.
                Status::SKIP if !gnc.negation => Status::SKIP,

                _ => {
                    if gnc.negation {
                        Status::PASS
                    } else {
                        Status::FAIL
                    }
                }
            };
            match status {
                Status::PASS => {
                    resolver
                        .end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                }
                Status::FAIL => {
                    resolver.end_record(
                        &context,
                        RecordType::ClauseValueCheck(ClauseCheck::DependentRule(
                            MissingValueCheck {
                                rule: &gnc.dependent_rule,
                                status: Status::FAIL,
                                message: None,
                                custom_message: gnc.custom_message.clone(),
                            },
                        )),
                    )?;
                }

                // Recorded as a childless block check, which is the shape a gate
                // comparison already uses when it SKIPs. That matters twice over: the
                // report walkers collect block checks only at `Status::FAIL`, so this
                // contributes nothing to the failure report, and `find_skip_reason`
                // reads the message off it, so the rule-level SKIP it produces is
                // explained rather than bare. A `DependentRule` record would have been
                // reported as a failing clause -- that arm has no status guard.
                Status::SKIP => {
                    resolver.end_record(
                        &context,
                        RecordType::GuardClauseBlockCheck(BlockCheck {
                            status: Status::SKIP,
                            at_least_one_matches: false,
                            message: Some(format!(
                                "the rule did not apply because a condition referenced rule [{}], which did not apply to this input",
                                gnc.dependent_rule
                            )),
                        }),
                    )?;
                }
            }
            Ok(status)
        }

        Err(e) => {
            resolver.end_record(
                &context,
                RecordType::ClauseValueCheck(ClauseCheck::DependentRule(MissingValueCheck {
                    rule: &gnc.dependent_rule,
                    status: Status::FAIL,
                    message: Some(format!("{} failed due to error {}", context, e)),
                    custom_message: gnc.custom_message.clone(),
                })),
            )?;
            Err(e)
        }
    }
}

pub(in crate::rules) fn eval_general_block_clause<'value, 'loc: 'value, T, E>(
    block: &'value Block<'loc, T>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    eval_fn: E,
) -> Result<Status>
where
    E: Fn(&'value T, &mut dyn EvalContext<'value, 'loc>) -> Result<Status>,
{
    let mut block_scope = block_scope(block, resolver.root(), resolver);
    eval_conjunction_clauses(&block.conjunctions, &mut block_scope, eval_fn)
}

/// `role` is inherited from the enclosing clause; a block clause is not itself a
/// gate or an assertion, it just groups the clauses inside it.
pub(in crate::rules) fn eval_guard_block_clause<'value, 'loc: 'value>(
    block_clause: &'value BlockGuardClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    let context = format!("BlockGuardClause#{}", block_clause.location);
    let match_all = block_clause.query.match_all;
    resolver.start_record(&context)?;
    let block_values = match resolver.query(&block_clause.query.query) {
        Ok(values) => values,
        Err(e) => {
            resolver.end_record(
                &context,
                RecordType::BlockGuardCheck(BlockCheck {
                    status: Status::FAIL,
                    at_least_one_matches: !match_all,
                    message: None,
                }),
            )?;
            return Err(e);
        }
    };
    if block_values.is_empty() {
        let status = if block_clause.not_empty {
            Status::FAIL
        } else {
            Status::SKIP
        };
        resolver.end_record(
            &context,
            RecordType::BlockGuardCheck(BlockCheck {
                status,
                at_least_one_matches: !match_all,
                message: None,
            }),
        )?;
        return Ok(status);
    }
    let mut fails = 0;
    let mut passes = 0;
    for each in block_values {
        match each {
            QueryResult::UnResolved(ur) => {
                fails += 1;
                let guard_cxt = format!("GuardBlockAccessClause#{}", block_clause.location);
                resolver.start_record(&guard_cxt)?;
                resolver.end_record(
                    &guard_cxt,
                    RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(ValueCheck {
                        message: Some(format!(
                            "Query {} did not resolve to correct value, reason {}",
                            SliceDisplay(&block_clause.query.query),
                            ur.reason.as_ref().map_or("", |s| s)
                        )),
                        status: Status::FAIL,
                        custom_message: None,
                        from: QueryResult::UnResolved(ur),
                    })),
                )?;
            }

            QueryResult::Literal(rv) | QueryResult::Resolved(rv) => {
                let mut val_resolver = ValueScope {
                    root: rv,
                    parent: resolver,
                };
                match eval_general_block_clause(&block_clause.block, &mut val_resolver, |gc, r| {
                    eval_guard_clause(gc, r, role)
                }) {
                    Ok(status) => match status {
                        Status::PASS => {
                            passes += 1;
                        }
                        Status::FAIL => {
                            fails += 1;
                        }
                        Status::SKIP => {}
                    },

                    Err(e) => {
                        resolver.end_record(
                            &context,
                            RecordType::BlockGuardCheck(BlockCheck {
                                status: Status::FAIL,
                                at_least_one_matches: !match_all,
                                message: Some(format!(
                                    "Error {} when handling block clause, bailing",
                                    e
                                )),
                            }),
                        )?;
                        return Err(e);
                    }
                }
            }
        }
    }

    let status = if match_all {
        if fails > 0 {
            Status::FAIL
        } else if passes > 0 {
            Status::PASS
        } else {
            Status::SKIP
        }
    } else if passes > 0 {
        Status::PASS
    } else if fails > 0 {
        Status::FAIL
    } else {
        Status::SKIP
    };
    resolver.end_record(
        &context,
        RecordType::BlockGuardCheck(BlockCheck {
            status,
            at_least_one_matches: !match_all,
            message: None,
        }),
    )?;
    Ok(status)
}

/// `role` is the role of the context this `when` block appears in, and it is inherited by the
/// guarded body.
///
/// Required rather than defaulted on purpose. This function used to take no role and hardcode
/// [`ClauseRole::Assertion`] for the body, on the reasoning that a guarded block holds the rule's
/// own assertions however its conditions were evaluated. That is true of a rule evaluated as an
/// assertion and false of one evaluated as a gate: the body of a gate is part of deciding whether
/// the gate applies, so an unevaluatable clause in it has to SKIP rather than fail closed.
///
/// Getting it wrong produced the exact wrong-PASS this module exists to prevent. A parameterized
/// rule used as a gate, whose body wrapped an empty-reference clause in `when { ... }`, failed that
/// clause as an assertion; `eval_conjunction_clauses` counts a FAIL and absorbs a SKIP, and answers
/// FAIL before PASS, so the failure outranked a passing sibling condition, the enclosing rule was
/// treated as inapplicable, and its guarded checks were dropped at exit 0. Spelling the same rule
/// without the inner `when` exited 19.
///
/// Taking it as a parameter with no default means a caller that forgets to thread it does not
/// compile, which is a stronger guarantee than any test:
/// `nested_when_inherits_the_enclosing_role` and the generated matrix in
/// `the_role_reaching_a_leaf_clause_survives_every_nesting` pin the behaviour, but only this
/// signature prevents the omission being reintroduced silently.
fn eval_when_condition_block<'value, 'loc: 'value>(
    context: String,
    conditions: &'value WhenConditions<'loc>,
    block: &'value Block<'loc, GuardClause<'loc>>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    resolver.start_record(&context)?;
    let when_context = format!("{}/When", context);
    resolver.start_record(&when_context)?;
    let block = match eval_conjunction_clauses(conditions, resolver, eval_when_clause) {
        Ok(status) => {
            if status != Status::PASS {
                resolver.end_record(&when_context, RecordType::WhenCondition(status))?;
                resolver.end_record(
                    &context,
                    RecordType::WhenCheck(BlockCheck {
                        status: Status::SKIP,
                        at_least_one_matches: false,
                        message: None,
                    }),
                )?;
                return Ok(Status::SKIP);
            }
            resolver.end_record(&when_context, RecordType::WhenCondition(Status::PASS))?;
            block
        }

        Err(e) => {
            resolver.end_record(&when_context, RecordType::WhenCondition(Status::FAIL))?;
            resolver.end_record(
                &context,
                RecordType::WhenCheck(BlockCheck {
                    status: Status::FAIL,
                    message: Some(format!(
                        "Error {} during type condition evaluation, bailing",
                        e
                    )),
                    at_least_one_matches: false,
                }),
            )?;
            return Err(e);
        }
    };

    Ok(
        // The guarded body inherits the role of the context the `when` block sits in, rather than
        // assuming it is an assertion. Its own conditions were evaluated as gates above -- that is
        // what `eval_when_clause` does and it is unconditional -- but the body is only assertions
        // when the enclosing context is one. See this function's doc comment for what assuming
        // otherwise cost.
        match eval_general_block_clause(block, resolver, |gc, r| eval_guard_clause(gc, r, role)) {
            Ok(status) => {
                resolver.end_record(
                    &context,
                    RecordType::WhenCheck(BlockCheck {
                        status,
                        message: None,
                        at_least_one_matches: false,
                    }),
                )?;
                status
            }

            Err(e) => {
                resolver.end_record(
                    &context,
                    RecordType::WhenCheck(BlockCheck {
                        status: Status::FAIL,
                        message: Some(format!(
                            "Error {} during type condition evaluation, bailing",
                            e
                        )),
                        at_least_one_matches: false,
                    }),
                )?;
                return Err(e);
            }
        },
    )
}

struct ResolvedParameterContext<'eval, 'value, 'loc: 'value> {
    call_rule: &'value ParameterizedNamedRuleClause<'loc>,
    resolved_parameters: HashMap<&'value str, Vec<QueryResult>>,
    parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

impl<'eval, 'value, 'loc: 'value> EvalContext<'value, 'loc>
    for ResolvedParameterContext<'eval, 'value, 'loc>
{
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        self.parent.query(query)
    }

    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        self.parent.root()
    }

    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        match self.resolved_parameters.get(variable_name) {
            Some(res) => Ok(res.clone()),
            None => self.parent.resolve_variable(variable_name),
        }
    }

    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.parent.add_variable_capture_key(variable_name, key)
    }
}

impl<'eval, 'value, 'loc: 'value> RecordTracer<'value>
    for ResolvedParameterContext<'eval, 'value, 'loc>
{
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        let record = match record {
            RecordType::RuleCheck(ns) => {
                if ns.name == self.call_rule.named_rule.dependent_rule {
                    RecordType::RuleCheck(NamedStatus {
                        name: ns.name,
                        status: ns.status,
                        message: self.call_rule.named_rule.custom_message.clone(),
                    })
                } else {
                    RecordType::RuleCheck(ns)
                }
            }
            rest => rest,
        };
        self.parent.end_record(context, record)
    }
}

/// `role` is the role of the *call site*, not of the clauses inside the invoked rule.
/// A parameterized rule invoked from a `when` condition is a gate, so its body must
/// evaluate with gate semantics: an unevaluatable clause inside it makes the gate
/// inapplicable rather than failed, which leaves the guarded block enforced.
pub(in crate::rules) fn eval_parameterized_rule_call<'value, 'loc: 'value>(
    call_rule: &'value ParameterizedNamedRuleClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    let param_rule = resolver.find_parameterized_rule(&call_rule.named_rule.dependent_rule)?;

    if param_rule.parameter_names.len() != call_rule.parameters.len() {
        return Err(Error::IncompatibleError(format!(
            "Arity mismatch for called parameter rule {}, expected {}, got {}",
            call_rule.named_rule.dependent_rule,
            param_rule.parameter_names.len(),
            call_rule.parameters.len()
        )));
    }

    let mut resolved_parameters = HashMap::with_capacity(call_rule.parameters.len());
    for (idx, each) in call_rule.parameters.iter().enumerate() {
        match each {
            LetValue::Value(val) => {
                resolved_parameters.insert(
                    (param_rule.parameter_names[idx]).as_str(),
                    vec![QueryResult::Resolved(Rc::new(val.clone()))],
                );
            }
            LetValue::AccessClause(query) => {
                resolved_parameters.insert(
                    (param_rule.parameter_names[idx]).as_str(),
                    resolver.query(&query.query)?,
                );
            }
            LetValue::FunctionCall(FunctionExpr {
                parameters, name, ..
            }) => {
                let result = resolve_function(name, parameters, resolver)?;
                resolved_parameters.insert((param_rule.parameter_names[idx]).as_str(), result);
            }
        }
    }
    let mut eval = ResolvedParameterContext {
        parent: resolver,
        resolved_parameters,
        call_rule,
    };
    // Propagate the call site's role: a parameterized rule used as a `when` gate
    // must evaluate its body with gate semantics, or an unevaluatable clause inside
    // it fails the gate and silently disarms the block it guards.
    let status = eval_rule(&param_rule.rule, &mut eval, role)?;

    // Apply the clause-level negation of the *call*. The parser accepts and stores a
    // leading `not` on a parameterized invocation (`not is_relevant("x")`) exactly as
    // it does for a plain named-rule reference, but this arm used to return the
    // invoked rule's status unchanged, so the `not` was silently discarded and
    // `not r(...)` behaved identically to `r(...)`.
    //
    // Mirrors eval_guard_named_clause so both spellings agree: PASS inverts to FAIL
    // under negation, a SKIPped rule fails closed where the reference is an assertion
    // (a rule that never ran is not evidence for a negated claim), and otherwise the
    // negation flips the outcome.
    Ok(match status {
        Status::PASS => {
            if call_rule.named_rule.negation {
                Status::FAIL
            } else {
                Status::PASS
            }
        }

        Status::SKIP if role.is_strict() => Status::FAIL,

        // A gate whose invoked rule did not apply stays SKIP rather than falling into the
        // `_` arm below, which would turn a non-negated call into FAIL.
        //
        // Both are non-PASS, so with a single condition the two are indistinguishable --
        // `eval_rule` drops the guarded body either way. The difference shows up with more
        // than one condition: `eval_conjunction_clauses` absorbs SKIP (`Status::SKIP => {}`)
        // but counts a FAIL, so one inapplicable gate condition returning FAIL poisons the
        // whole `when` and drops a body that the remaining conditions would have enforced.
        //
        // That is exactly what `ClauseRole::Gate` is documented to prevent -- "the block it
        // guards is still decided by the remaining conditions" -- so returning FAIL here
        // defeated the role propagation this branch added for parameterized calls.
        //
        // Negated calls deliberately keep falling through: `not r(...)` where `r` did not
        // apply must not report PASS on the strength of a check that never ran, which is the
        // same fail-closed reasoning `eval_guard_named_clause` uses for its assertion case.
        Status::SKIP if !call_rule.named_rule.negation => Status::SKIP,

        _ => {
            if call_rule.named_rule.negation {
                Status::PASS
            } else {
                Status::FAIL
            }
        }
    })
}

/// `role` propagates the assertion-vs-gate distinction to the leaf clauses. Callers
/// evaluating a rule body pass [`ClauseRole::Assertion`]; callers evaluating the
/// conditions of a `when` block or a parameterized gate pass [`ClauseRole::Gate`].
pub(in crate::rules) fn eval_guard_clause<'value, 'loc: 'value>(
    gc: &'value GuardClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    match gc {
        GuardClause::Clause(gac) => eval_guard_access_clause(gac, resolver, role),
        GuardClause::NamedRule(gnc) => eval_guard_named_clause(gnc, resolver, role),
        GuardClause::BlockClause(bc) => eval_guard_block_clause(bc, resolver, role),
        GuardClause::WhenBlock(conditions, block) => eval_when_condition_block(
            "GuardConditionClause".to_string(),
            conditions,
            block,
            resolver,
            role,
        ),
        GuardClause::ParameterizedNamedRule(prc) => {
            eval_parameterized_rule_call(prc, resolver, role)
        }
    }
}

pub(in crate::rules) fn eval_when_clause<'value, 'loc: 'value>(
    when_clause: &'value WhenGuardClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
) -> Result<Status> {
    match when_clause {
        // Every arm is a gate. A clause whose reference did not resolve, or a
        // reference to a rule that did not apply, must not disarm the block being
        // guarded: a FAIL here makes the gate not-PASS and eval_rule skips the whole
        // body.
        //
        // The parameterized arm needs the role threaded through the rule it invokes.
        // It previously called eval_parameterized_rule_call with no role, and
        // everything downstream defaulted to assertion strictness, so a parameterized
        // rule used as a gate failed instead of skipping and silently disarmed the
        // block it guarded.
        WhenGuardClause::Clause(gac) => eval_guard_access_clause(gac, resolver, ClauseRole::Gate),
        WhenGuardClause::NamedRule(gnr) => eval_guard_named_clause(gnr, resolver, ClauseRole::Gate),
        WhenGuardClause::ParameterizedNamedRule(prc) => {
            eval_parameterized_rule_call(prc, resolver, ClauseRole::Gate)
        }
    }
}

/// `role` is inherited by the clauses in the type block's body. Its own `when`
/// conditions are always evaluated as [`ClauseRole::Gate`].
pub(in crate::rules) fn eval_type_block_clause<'value, 'loc: 'value>(
    type_block: &'value TypeBlock<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    let context = format!("TypeBlock#{}", type_block.type_name);
    resolver.start_record(&context)?;
    let block = &type_block.block;

    let values = match resolver.query(&type_block.query) {
        Ok(values) => values,
        Err(e) => {
            resolver.end_record(
                &context,
                RecordType::TypeCheck(TypeBlockCheck {
                    type_name: &type_block.type_name,
                    block: BlockCheck {
                        status: Status::FAIL,
                        at_least_one_matches: false,
                        message: None,
                    },
                }),
            )?;
            return Err(e);
        }
    };
    if values.is_empty() {
        resolver.end_record(
            &context,
            RecordType::TypeCheck(TypeBlockCheck {
                type_name: &type_block.type_name,
                block: BlockCheck {
                    status: Status::SKIP,
                    at_least_one_matches: false,
                    // Reaches the reader now that a skipped rule carries its reason through to the
                    // reporters. Naming which of the two skips happened is the whole point: an
                    // absent resource type is the ordinary, correct reason for a rule not to
                    // apply, and a condition that matched nothing is the one worth a second look,
                    // because a rule that never fires looks exactly like a rule that passes.
                    message: Some(format!(
                        "no {} in the input, so the type block had nothing to check",
                        type_block.type_name
                    )),
                },
            }),
        )?;
        return Ok(Status::SKIP);
    }

    let mut fails = 0;
    let mut passes = 0;
    // Tracked only so the SKIP below can name the right cause. A block that selected nothing and a
    // block whose condition exempted everything both report SKIP, and telling a reader the wrong
    // one of those is worse than telling them nothing -- which is the defect this branch spent most
    // of its commits removing.
    let mut unresolved = 0;
    for (idx, each) in values.iter().enumerate() {
        match each {
            QueryResult::Literal(rv) | QueryResult::Resolved(rv) => {
                let block_context = format!("{}/{}", context, idx);
                resolver.start_record(&block_context)?;

                let mut val_resolver = ValueScope {
                    root: Rc::clone(rv),
                    parent: resolver,
                };

                // Conditions are evaluated per resource, against the same scope as the clauses
                // they guard.
                //
                // They used to be evaluated once, before this loop, against the enclosing
                // resolver -- so a condition resolved from the file root while the block's
                // clauses resolved from each resource. That split made the natural spelling a
                // trap: `AWS::EC2::Volume when Properties.Size > 10 { ... }` reads as "every
                // volume over 10 GiB must ..." and instead looked for `Properties` at the file
                // root, found nothing, and skipped every template it was ever run against --
                // reporting `not_applicable` at exit 0, including for the templates it was
                // written to catch.
                //
                // The cost is the mirror image, and it is real: a condition written as a literal
                // root-anchored path (`when Resources.A.Properties.Size > 10`) resolved before
                // and does not now, because `ValueScope::query` starts at the resource. Accepted
                // for two reasons. A condition over one named resource does not belong on a
                // block that iterates all of them, and the variable idiom that real rulesets use
                // is unaffected -- `ValueScope::resolve_variable` delegates to the parent, so
                // `let vols = ...` followed by `when %vols !empty` still resolves at the root.
                // `a_type_block_condition_is_evaluated_against_each_resource` asserts all three
                // spellings so the trade is visible rather than inferred.
                if let Some(conditions) = &type_block.conditions {
                    let when_context = format!("{}/When", block_context);
                    val_resolver.start_record(&when_context)?;
                    match eval_conjunction_clauses(conditions, &mut val_resolver, eval_when_clause)
                    {
                        Ok(status) => {
                            val_resolver
                                .end_record(&when_context, RecordType::TypeCondition(status))?;
                            if status != Status::PASS {
                                // Not applicable to this resource, so it contributes to neither
                                // count. If that holds for every resource the fold below answers
                                // SKIP, which is the honest answer: the block applied to nothing.
                                val_resolver.end_record(
                                    &block_context,
                                    RecordType::TypeBlock(Status::SKIP),
                                )?;
                                continue;
                            }
                        }

                        Err(e) => {
                            val_resolver.end_record(
                                &when_context,
                                RecordType::TypeCondition(Status::FAIL),
                            )?;
                            val_resolver
                                .end_record(&block_context, RecordType::TypeBlock(Status::FAIL))?;
                            val_resolver.end_record(
                                &context,
                                RecordType::TypeCheck(TypeBlockCheck {
                                    type_name: &type_block.type_name,
                                    block: BlockCheck {
                                        status: Status::FAIL,
                                        message: Some(format!(
                                            "Error {} during type condition evaluation, bailing",
                                            e
                                        )),
                                        at_least_one_matches: false,
                                    },
                                }),
                            )?;
                            return Err(e);
                        }
                    }
                }

                match eval_general_block_clause(block, &mut val_resolver, |gc, r| {
                    eval_guard_clause(gc, r, role)
                }) {
                    Ok(status) => {
                        match status {
                            Status::PASS => {
                                passes += 1;
                            }
                            Status::FAIL => {
                                fails += 1;
                            }
                            Status::SKIP => {}
                        }
                        resolver.end_record(&block_context, RecordType::TypeBlock(status))?;
                    }

                    Err(e) => {
                        resolver.end_record(&block_context, RecordType::TypeBlock(Status::FAIL))?;
                        resolver.end_record(
                            &context,
                            RecordType::TypeCheck(TypeBlockCheck {
                                type_name: &type_block.type_name,
                                block: BlockCheck {
                                    status: Status::FAIL,
                                    message: Some(format!(
                                        "Error {} during type block evaluation, bailing",
                                        e
                                    )),
                                    at_least_one_matches: false,
                                },
                            }),
                        )?;
                        return Err(e);
                    }
                }
            }
            // A slot the type block's query could not resolve is not applicable, not an error.
            //
            // This used to return `Err`, which aborts the whole rules file: a document with no
            // `Resources` at its root took every other rule in the file down with it, so a
            // violation an unrelated rule had already found stopped being reported. The exit code
            // went from 19 to 255 and the finding vanished.
            //
            // The situation is the one the `values.is_empty()` branch above already answers with
            // SKIP -- the document does not contain the type being checked -- so it gets the same
            // answer here, and `ur.reason` is carried onto the record rather than into an error, so
            // the explanation still reaches the reader through `find_skip_reason`. Counting it as
            // neither a pass nor a fail leaves the fold below to decide: if no slot resolved, the
            // block applied to nothing and reports SKIP.
            //
            // Found by differential against the merge-base rather than by reading. Moving the type
            // block's conditions per-resource removed an early return that had been masking this
            // for the `when` form, so a latent abort became a reachable one. The plain form aborted
            // on the merge-base too, which is how the pre-existing half was confirmed. Pinned by
            // `an_unresolved_type_block_query_skips_without_aborting_the_file`.
            QueryResult::UnResolved(ur) => {
                unresolved += 1;
                let block_context = format!("{}/{}", context, idx);
                resolver.start_record(&block_context)?;
                resolver.end_record(
                    &block_context,
                    RecordType::TypeCheck(TypeBlockCheck {
                        type_name: &type_block.type_name,
                        block: BlockCheck {
                            at_least_one_matches: false,
                            status: Status::SKIP,
                            message: Some(match &ur.reason {
                                Some(reason) => format!(
                                    "no {} could be selected from the input: {}",
                                    type_block.type_name, reason
                                ),
                                None => format!(
                                    "no {} could be selected from the input",
                                    type_block.type_name
                                ),
                            }),
                        },
                    }),
                )?;
            }
        }
    }

    let status = if fails > 0 {
        Status::FAIL
    } else if passes > 0 {
        Status::PASS
    } else {
        Status::SKIP
    };

    resolver.end_record(
        &context,
        RecordType::TypeCheck(TypeBlockCheck {
            type_name: &type_block.type_name,
            block: BlockCheck {
                status,
                // Only the SKIP needs explaining. Reaching here with neither a pass nor a fail
                // means the input did contain resources of this type and not one of them was
                // checked -- every one was exempted by the block's own `when` condition. That is
                // a legitimate outcome and also the shape of a rule that silently never fires, and
                // the reader cannot tell which from a bare "not applicable".
                message: match status {
                    // Two ways to reach SKIP with resources in hand, and they mean different
                    // things to whoever is reading the output: the query selected nothing, or it
                    // selected resources and the condition exempted all of them.
                    Status::SKIP if unresolved > 0 => Some(format!(
                        "no {} could be selected from the input, so the type block had nothing to check",
                        type_block.type_name
                    )),
                    Status::SKIP => Some(format!(
                        "every {} in the input was exempted by the type block's `when` condition, so none was checked",
                        type_block.type_name
                    )),
                    _ => None,
                },
                at_least_one_matches: false,
            },
        }),
    )?;
    Ok(status)
}

/// `role` is inherited by the clauses of this rule clause.
pub(in crate::rules) fn eval_rule_clause<'value, 'loc: 'value>(
    rule_clause: &'value RuleClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    match rule_clause {
        RuleClause::Clause(gc) => eval_guard_clause(gc, resolver, role),
        RuleClause::TypeBlock(tb) => eval_type_block_clause(tb, resolver, role),
        RuleClause::WhenBlock(conditions, block) => {
            eval_when_condition_block("RuleClause".to_string(), conditions, block, resolver, role)
        }
    }
}

/// `role` is the role of the context that *invoked* this rule, not the role of the
/// clauses it contains.
///
/// A rule evaluated as a top-level entry in a rules file, or referenced from another
/// rule's body, is an [`ClauseRole::Assertion`]: its clauses are claims and an
/// unevaluatable one is a failure.
///
/// A rule invoked as a gate -- `rule x when some_gate("p") { ... }` -- is a
/// [`ClauseRole::Gate`]. Its clauses must then SKIP rather than FAIL when they cannot
/// be evaluated, because a failing gate makes the guarded block inapplicable and
/// silently drops every check inside it.
pub(in crate::rules) fn eval_rule<'value, 'loc: 'value>(
    rule: &'value Rule<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    let context = rule.rule_name.to_string();
    resolver.start_record(&context)?;
    let block = if let Some(conditions) = &rule.conditions {
        let when_context = format!("Rule#{}/When", context);
        resolver.start_record(&when_context)?;
        match eval_conjunction_clauses(conditions, resolver, eval_when_clause) {
            Ok(status) => {
                if status != Status::PASS {
                    resolver.end_record(&when_context, RecordType::RuleCondition(status))?;
                    resolver.end_record(
                        &context,
                        RecordType::RuleCheck(NamedStatus {
                            status: Status::SKIP,
                            name: &rule.rule_name,
                            ..Default::default()
                        }),
                    )?;
                    return Ok(Status::SKIP);
                }
                resolver.end_record(&when_context, RecordType::RuleCondition(Status::PASS))?;
                &rule.block
            }

            Err(e) => {
                resolver.end_record(&when_context, RecordType::RuleCondition(Status::FAIL))?;
                resolver.end_record(
                    &context,
                    RecordType::RuleCheck(NamedStatus {
                        status: Status::FAIL,
                        name: &rule.rule_name,
                        ..Default::default()
                    }),
                )?;
                return Err(e);
            }
        }
    } else {
        &rule.block
    };

    match eval_general_block_clause(block, resolver, |rc, r| eval_rule_clause(rc, r, role)) {
        Ok(status) => {
            resolver.end_record(
                &context,
                RecordType::RuleCheck(NamedStatus {
                    status,
                    name: &rule.rule_name,
                    ..Default::default()
                }),
            )?;
            Ok(status)
        }

        Err(e) => {
            resolver.end_record(
                &context,
                RecordType::RuleCheck(NamedStatus {
                    status: Status::FAIL,
                    name: &rule.rule_name,
                    ..Default::default()
                }),
            )?;
            Err(e)
        }
    }
}

impl<'loc> std::fmt::Display for RulesFile<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("File(rules={})", self.guard_rules.len()))?;
        Ok(())
    }
}

pub(crate) fn eval_rules_file<'value, 'loc: 'value>(
    rule: &'value RulesFile<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    data_file_name: Option<&'value str>,
) -> Result<Status> {
    let context = format!("{}", rule);
    resolver.start_record(&context)?;
    let mut fails = 0;
    let mut passes = 0;
    for each_rule in &rule.guard_rules {
        // Top-level rule in a rules file: its clauses are assertions.
        match eval_rule(each_rule, resolver, ClauseRole::Assertion) {
            Ok(status) => match status {
                Status::PASS => {
                    passes += 1;
                }
                Status::FAIL => {
                    fails += 1;
                }
                Status::SKIP => {}
            },

            Err(e) => {
                resolver.end_record(
                    &context,
                    RecordType::RuleCheck(NamedStatus {
                        status: Status::FAIL,
                        name: &each_rule.rule_name,
                        ..Default::default()
                    }),
                )?;
                return Err(e);
            }
        }
    }

    let overall = if fails > 0 {
        Status::FAIL
    } else if passes > 0 {
        Status::PASS
    } else {
        Status::SKIP
    };

    resolver.end_record(
        &context,
        RecordType::FileCheck(NamedStatus {
            status: overall,
            name: data_file_name.unwrap_or_default(),
            ..Default::default()
        }),
    )?;

    Ok(overall)
}

/// The clause type a disjunction is over, spelled the same way by every compiler.
///
/// `std::any::type_name` is documented as being for diagnostics only, with no guarantee of
/// stability across versions, and this one is not confined to diagnostics: it goes into a record
/// context, which reaches verbose output and is compared byte for byte by four golden-file tests.
/// rustc 1.77.2 renders `cfn_guard::rules::exprs::GuardClause<'_>` and later versions render the
/// path without the elided lifetime, so those tests fail on any newer toolchain -- they had to be
/// skipped to measure coverage on nightly at all, which is how this surfaced.
///
/// Taking the path before the generic arguments is stable on both and keeps what the context is
/// for: saying which kind of clause the disjunction holds. Dropping the name entirely and writing
/// `disjunction` would also be stable, and was rejected because the type is the only thing
/// distinguishing one disjunction record from another in a nested rule.
fn disjunction_type_name<T>() -> &'static str {
    let name = std::any::type_name::<T>();
    match name.find('<') {
        Some(generics_start) => &name[..generics_start],
        None => name,
    }
}

#[allow(clippy::never_loop)]
pub(in crate::rules) fn eval_conjunction_clauses<'value, 'loc: 'value, T, E>(
    conjunctions: &'value Conjunctions<T>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    eval_fn: E,
) -> Result<Status>
where
    E: Fn(&'value T, &mut dyn EvalContext<'value, 'loc>) -> Result<Status>,
{
    Ok(loop {
        let mut num_passes = 0;
        let mut num_fails = 0;
        let context = format!("{}#disjunction", disjunction_type_name::<T>());
        'conjunction: for conjunction in conjunctions {
            let mut num_of_disjunction_fails = 0;
            let multiple_ors_present = conjunction.len() > 1;
            if multiple_ors_present {
                resolver.start_record(&context)?;
            }
            for disjunction in conjunction {
                match eval_fn(disjunction, resolver) {
                    Ok(status) => match status {
                        Status::PASS => {
                            num_passes += 1;
                            if multiple_ors_present {
                                resolver.end_record(
                                    &context,
                                    RecordType::Disjunction(BlockCheck {
                                        message: None,
                                        at_least_one_matches: true,
                                        status: Status::PASS,
                                    }),
                                )?;
                            }
                            continue 'conjunction;
                        }
                        Status::SKIP => {}
                        Status::FAIL => {
                            num_of_disjunction_fails += 1;
                        }
                    },

                    Err(e) => {
                        if multiple_ors_present {
                            resolver.end_record(
                                &context,
                                RecordType::Disjunction(BlockCheck {
                                    message: Some(format!(
                                        "Disjunction failed due to error {}, bailing",
                                        e
                                    )),
                                    status: Status::FAIL,
                                    at_least_one_matches: true,
                                }),
                            )?;
                        }
                        return Err(e);
                    }
                }
            }

            if num_of_disjunction_fails > 0 {
                num_fails += 1;
            }

            if multiple_ors_present {
                if num_of_disjunction_fails > 0 {
                    resolver.end_record(
                        &context,
                        RecordType::Disjunction(BlockCheck {
                            message: None,
                            status: Status::FAIL,
                            at_least_one_matches: true,
                        }),
                    )?;
                } else {
                    resolver.end_record(
                        &context,
                        RecordType::Disjunction(BlockCheck {
                            message: None,
                            status: Status::SKIP,
                            at_least_one_matches: true,
                        }),
                    )?;
                }
            }
        }
        if num_fails > 0 {
            break Status::FAIL;
        }
        if num_passes > 0 {
            break Status::PASS;
        }
        break Status::SKIP;
    })
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod eval_tests;
