use super::exprs::*;
use super::*;
use crate::rules::eval_context::{block_scope, ValueScope};
use crate::rules::path_value::compare_eq;
use itertools::misc::Slice;
use crate::rules::values::WithinRange;
use std::collections::HashMap;

fn exists_operation(value: &QueryResult<'_>) -> Result<bool> {
    Ok(match value {
        QueryResult::Resolved(_) => true,
        QueryResult::UnResolved(_) => false,
    })
}

fn element_empty_operation(value: &QueryResult<'_>) -> Result<bool>
{
    let result = match value {
        QueryResult::Resolved(value) =>
            match value {
                PathAwareValue::List((_, list)) => list.is_empty(),
                PathAwareValue::Map((_, map)) => map.is_empty(),
                PathAwareValue::String((_, string)) => string.is_empty(),
                _ => return Err(Error::new(ErrorKind::IncompatibleError(
                    format!("Attempting EMPTY operation on type {} that does not support it at {}",
                            value.type_info(), value.self_path())
                )))
            },

        //
        // !EXISTS is the same as EMPTY
        //
        QueryResult::UnResolved(_) => true
    };
    Ok(result)
}

macro_rules! is_type_fn {
    ($name: ident, $type_: pat) => {
        fn $name(value: &QueryResult<'_>) -> Result<bool> {
            Ok(match value {
                QueryResult::Resolved(resolved) =>
                    match resolved {
                        $type_ => true,
                        _ => false,
                    },

                QueryResult::UnResolved(_) => false
            })
        }
    }
}

is_type_fn!(is_string_operation, PathAwareValue::String(_));
is_type_fn!(is_list_operation, PathAwareValue::List(_));
is_type_fn!(is_struct_operation, PathAwareValue::Map(_));
is_type_fn!(is_int_operation, PathAwareValue::Int(_));
is_type_fn!(is_float_operation, PathAwareValue::Float(_));
is_type_fn!(is_bool_operation, PathAwareValue::Bool(_));
is_type_fn!(is_char_range_operation, PathAwareValue::RangeChar(_));
is_type_fn!(is_int_range_operation, PathAwareValue::RangeInt(_));
is_type_fn!(is_float_range_operation, PathAwareValue::RangeFloat(_));

fn not_operation<O>(operation: O) -> impl Fn(&QueryResult<'_>) -> Result<bool>
    where O: Fn(&QueryResult<'_>) -> Result<bool>
{
    move |value: &QueryResult<'_>| {
        Ok(match operation(value)? {
            true => false,
            false => true
        })
    }
}

fn inverse_operation<O>(operation: O, inverse: bool) -> impl Fn(&QueryResult<'_>) -> Result<bool>
    where O: Fn(&QueryResult<'_>) -> Result<bool>
{
    move |value: &QueryResult<'_>| {
        Ok(match inverse {
            true => !operation(value)?,
            false => operation(value)?
        })
    }
}

fn record_unary_clause<'eval, 'value, O>(operation: O,
                                   cmp: (CmpOperator, bool),
                                   context: String,
                                   custom_message: Option<String>,
                                   eval_context: &'eval dyn EvalContext<'value>) -> Box<dyn Fn(&QueryResult<'value>) -> Result<bool> + 'eval>
    where O: Fn(&QueryResult<'value>) -> Result<bool> + 'eval
{
    Box::new(move |value: &QueryResult<'value>| {
        eval_context.start_record(&context)?;
        let mut check = ValueCheck {
            custom_message: custom_message.clone(),
            message: None,
            status: Status::PASS,
            from: value.clone()
        };
        match operation(value) {
            Ok(result) => {
                if !result {
                    check.status = Status::FAIL;
                    eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Unary(UnaryValueCheck {
                        value: check, comparison: cmp
                    })))?;
                }
                else {
                    eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                }
                Ok(result)
            },

            Err(e) => {
                check.status = Status::FAIL;
                check.message = Some(format!("{}", e));
                eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Unary(
                    UnaryValueCheck {
                        value:check, comparison: cmp
                    }
                )))?;
                Err(e)
            }
        }
    })
}

macro_rules! box_create_func {
    ($name: ident, $not: expr, $inverse: expr, $cmp: ident, $eval: ident, $cxt: ident, $msg: ident) => {
        {{
            match $not {
                true => {
                    record_unary_clause(inverse_operation(not_operation($name), $inverse), $cmp, $cxt, $msg, $eval)
                },

                false => {
                    record_unary_clause(inverse_operation($name, $inverse), $cmp, $cxt, $msg, $eval)
                }
            }
        }}
    }
}

enum EvaluationResult<'value> {
    EmptyQueryResult(Status),
    QueryValueResult(Vec<(QueryResult<'value>, Status)>),
}

fn unary_operation<'r, 'l: 'r>(lhs_query: &'l [QueryPart<'_>],
                   cmp: (CmpOperator, bool),
                   inverse: bool,
                   context: String,
                   custom_message: Option<String>,
                   eval_context: &'r dyn EvalContext<'l>) -> Result<EvaluationResult<'l>> {
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
    let empty_on_expr = match &lhs_query[lhs_query.len()-1] {
        QueryPart::Filter(_) |
        QueryPart::MapKeyFilter(_) => true,
        rest => rest.is_variable() && lhs_query.len() == 1
    };

    if empty_on_expr && cmp.0 == CmpOperator::Empty {
        return Ok({
            if !lhs.is_empty() {
                let mut results = Vec::with_capacity(lhs.len());
                for each in lhs {
                    eval_context.start_record(&context)?;
                    let (result, status) = match each {
                        QueryResult::Resolved(res) => {
                            (QueryResult::Resolved(res), match cmp.1 {
                                true => Status::PASS, // not_empty
                                false => Status::FAIL // fail not_empty
                            })
                        }

                        QueryResult::UnResolved(ur) => {
                            (QueryResult::UnResolved(ur), match cmp.1 {
                                true => Status::FAIL, // !EXISTS == EMPTY, so !EMPTY == FAIL
                                false => Status::PASS // !EXISTS == EMPTY so PASS
                            })
                        }
                    };
                    let status = if inverse {
                        match status {
                            Status::PASS => Status::FAIL,
                            Status::FAIL => Status::PASS,
                            _ => unreachable!()
                        }
                    } else { status };

                    match status {
                        Status::PASS => {
                            eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                        },
                        Status::FAIL => {
                            eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Unary(
                                UnaryValueCheck {
                                    comparison: cmp,
                                    value: ValueCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        from: result.clone()
                                    }
                                }
                            )))?;
                        },
                        _ => unreachable!()
                    }

                    results.push((result, status));
                }
                EvaluationResult::QueryValueResult(results)
            } else {
                EvaluationResult::EmptyQueryResult({
                    let result = if cmp.1 { false } else { true };
                    let result = if inverse { !result } else { result };
                    match result {
                        true => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                            Status::PASS
                        },
                        false => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::NoValueForEmptyCheck))?;
                            Status::FAIL
                        }
                    }
                })
            }
        })
    }

    //
    // This only happens when the query has filters in them
    //
    if lhs.is_empty() {
        return Ok(EvaluationResult::EmptyQueryResult(Status::SKIP))
    }

    let operation: Box<dyn Fn(&QueryResult<'l>) -> Result<bool>> =
        match cmp {
            (CmpOperator::Exists, not_exists) =>
                box_create_func!(
                    exists_operation,
                    not_exists,
                    inverse,
                    cmp,
                    eval_context,
                    context,
                    custom_message
                ),
            (CmpOperator::Empty, not_empty) =>
                box_create_func!(
                    element_empty_operation,
                    not_empty,
                    inverse,
                    cmp,
                    eval_context,
                    context,
                    custom_message
                ),
            (CmpOperator::IsString, is_not_string) =>
                box_create_func!(
                    is_string_operation,
                    is_not_string,
                    inverse,
                    cmp,
                    eval_context,
                    context,
                    custom_message),
            (CmpOperator::IsMap, is_not_map) =>
                box_create_func!(
                    is_struct_operation,
                    is_not_map,
                    inverse,
                    cmp,
                    eval_context,
                    context,
                    custom_message),
            (CmpOperator::IsList, is_not_list) =>
                box_create_func!(
                    is_list_operation,
                    is_not_list,
                    inverse,
                    cmp,
                    eval_context,
                    context,
                    custom_message),
            //
            // TODO: add parser updates to check for int, bool, float, char and range types
            //

            _ => unreachable!()
        };
    let mut status = Vec::with_capacity(lhs.len());
    for each in lhs {
        match (*operation)(&each)? {
            true => {
                status.push((each, Status::PASS));
            },

            false => {
                status.push((each, Status::FAIL));
            }
        }
    }
    Ok(EvaluationResult::QueryValueResult(status))
}

enum ComparisonResult<'r> {
    Comparable(ComparisonCheckResult<'r>),
    NotComparable(NotComparableResult<'r>),
}

struct ComparisonCheckResult<'r> {
    outcome: bool,
    lhs: &'r PathAwareValue,
    rhs: QueryResult<'r>,
}

struct NotComparableResult<'r> {
    lhs: &'r PathAwareValue,
    rhs: &'r PathAwareValue,
    reason: String,
}

fn each_lhs_compare<'r, 'value: 'r, C>(cmp: C, lhs: &'value PathAwareValue, rhs: &'r[QueryResult<'value>])
    -> Result<Vec<ComparisonResult<'value>>>
    where C: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
{
    let mut statues = Vec::with_capacity(rhs.len());
    for each_rhs in rhs {
        match each_rhs {
            QueryResult::Resolved(each_rhs_resolved) => {
                match cmp(lhs, *each_rhs_resolved) {
                    Ok(outcome) => {
                        statues.push(ComparisonResult::Comparable(
                            ComparisonCheckResult {
                                outcome, lhs, rhs: each_rhs.clone()
                            }
                        ));
                    },

                    Err(Error(ErrorKind::NotComparable(reason))) => {
                        if lhs.is_list() { // && each_rhs_resolved.is_scalar() {
                            if let PathAwareValue::List((_, inner)) = lhs {
                                for each in inner {
                                    match cmp(each, *each_rhs_resolved) {
                                        Ok(outcome) => {
                                            statues.push(ComparisonResult::Comparable(
                                                ComparisonCheckResult {
                                                    outcome, lhs: each, rhs: each_rhs.clone()
                                                }
                                            ));
                                        },

                                        Err(Error(ErrorKind::NotComparable(reason))) => {
                                            statues.push(ComparisonResult::NotComparable(
                                                NotComparableResult {
                                                    reason, rhs: *each_rhs_resolved, lhs: each
                                                }
                                            ));

                                        },

                                        Err(e) => return Err(e)
                                    }
                                }
                                continue;
                            }
                        }

                        if lhs.is_scalar() && each_rhs_resolved.is_list() {
                            if let PathAwareValue::List((_, rhs)) = each_rhs_resolved {
                                if rhs.len() == 1 {
                                    let rhs_inner_single_element = &rhs[0];
                                    match cmp(lhs, rhs_inner_single_element) {
                                        Ok(outcome) => {
                                            statues.push(ComparisonResult::Comparable(
                                                ComparisonCheckResult {
                                                    outcome, lhs, rhs: each_rhs.clone()
                                                }
                                            ));
                                        },

                                        Err(Error(ErrorKind::NotComparable(reason))) => {
                                            statues.push(ComparisonResult::NotComparable(
                                                NotComparableResult {
                                                    reason, rhs: rhs_inner_single_element, lhs,
                                                }
                                            ));

                                        },

                                        Err(e) => return Err(e)
                                    }
                                    continue;
                                }
                            }
                        }

                        statues.push(ComparisonResult::NotComparable(
                            NotComparableResult {
                                reason,
                                rhs: *each_rhs_resolved,
                                lhs
                            }
                        ));
                    },

                    Err(e) => return Err(e)
                }
            },

            QueryResult::UnResolved(_ur) => {
                statues.push(ComparisonResult::Comparable(ComparisonCheckResult {
                    outcome: false,
                    lhs,
                    rhs: each_rhs.clone(),
                }));
            }
        }
    }
    Ok(statues)
}

fn not_cmp<F>(cmp: F) -> impl Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
    where F: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
{
    move |left, right| {
        Ok(match cmp(left, right)? {
            true => false,
            false => true
        })
    }
}

fn in_cmp(not_in: bool)
          -> impl Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
{
    move |lhs, rhs| {
        match rhs {
            PathAwareValue::List((_, rhs_list)) => {
                Ok({
                    let mut tracking = Vec::with_capacity(rhs_list.len());
                    for each_rhs in rhs_list {
                        tracking.push(compare_eq(lhs, each_rhs)?);
                    }
                    match  tracking.iter().find(|s| **s) {
                        Some(_) => if not_in { false } else { true },
                        None => if not_in { true } else { false }
                    }
                })
            },

            PathAwareValue::RangeInt(_)   |
            PathAwareValue::RangeFloat(_) |
            PathAwareValue::RangeChar(_)=> {
                compare_eq(lhs, rhs)
            },

            _ => return Err(Error::new(ErrorKind::NotComparable(
                    format!("IN operator can be compared with a list or range type, found {}", rhs.type_info())
                )))
        }
    }
}

fn report_all_operation<'r, 'value: 'r, C, E>(
    comparison: E,
    cmp_fn: C,
    inverse: bool,
    lhs: &'value PathAwareValue,
    rhs: &'r [QueryResult<'value>],
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r dyn EvalContext<'value>)
    -> Result<HashMap<&'value PathAwareValue, bool>>
    where C: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>,
          E: Fn(C, &'value PathAwareValue, &'r[QueryResult<'value>]) -> Result<Vec<ComparisonResult<'value>>>
{
    let mut overall = HashMap::new();
    let results = comparison(cmp_fn, lhs, rhs)?;
    for outcome in results {
        match outcome {
            ComparisonResult::NotComparable(NotComparableResult{lhs, rhs, reason}) => {
                eval_context.start_record(&context)?;
                eval_context.end_record(&context, RecordType::ClauseValueCheck(
                    ClauseCheck::Comparison(ComparisonClauseCheck {
                        from: QueryResult::Resolved(lhs),
                        comparison: cmp,
                        to: Some(QueryResult::Resolved(rhs)),
                        custom_message: custom_message.clone(),
                        message: Some(reason),
                        status: Status::FAIL
                    })
                ))?;
                overall.insert(lhs, false);
            },

            ComparisonResult::Comparable(ComparisonCheckResult{outcome, lhs, rhs}) => {
                if outcome {
                    eval_context.start_record(&context)?;
                    eval_context.end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                }
                else {
                    eval_context.start_record(&context)?;
                    eval_context.end_record(&context, RecordType::ClauseValueCheck(
                        ClauseCheck::Comparison(ComparisonClauseCheck {
                            from: QueryResult::Resolved(lhs),
                            comparison: cmp,
                            to: Some(rhs),
                            custom_message: custom_message.clone(),
                            message: None,
                            status: Status::FAIL
                        })
                    ))?;
                }
                overall.insert(lhs, outcome);
            }
        }
    }
    Ok(overall)
}

fn not_compare<O>(cmp: O, invert: bool) -> impl Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
    where O: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
{
    move |lhs, rhs| {
        let r = cmp(lhs, rhs)?;
        Ok(if invert { !r } else { r })
    }
}

fn binary_operation<'value>(lhs_query: &'value [QueryPart<'_>],
                            rhs: &[QueryResult<'value>],
                            cmp: (CmpOperator, bool),
                            inverse: bool,
                            context: String,
                            custom_message: Option<String>,
                            eval_context: &dyn EvalContext<'value>) -> Result<EvaluationResult<'value>> {
    let lhs = eval_context.query(lhs_query)?;
    if lhs.is_empty() || rhs.is_empty() {
        return Ok(EvaluationResult::EmptyQueryResult(Status::SKIP))
    }

    let mut statues = Vec::with_capacity(lhs.len());
    for each in lhs {
        match &each {
            QueryResult::UnResolved(_ur) => {
                eval_context.start_record(&context)?;
                eval_context.end_record(&context, RecordType::ClauseValueCheck(
                    ClauseCheck::Comparison(ComparisonClauseCheck {
                        status: Status::FAIL,
                        message: None,
                        custom_message: custom_message.clone(),
                        comparison: cmp,
                        from: each.clone(),
                        to: None,
                    })
                ))?;
                statues.push((each, Status::FAIL));
            },

            QueryResult::Resolved(l) => {
                let r = match cmp {
                    (CmpOperator::Eq, is_not) => {
                        report_all_operation(
                            each_lhs_compare,
                                not_compare(crate::rules::path_value::compare_eq, is_not),
                            inverse,
                            *l,
                            rhs,
                            cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context
                        )?
                    },

                    (CmpOperator::Ge, is_not) => {
                        report_all_operation(
                            each_lhs_compare,
                            not_compare(crate::rules::path_value::compare_ge, is_not),
                            inverse,
                            *l,
                            rhs,
                            cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context
                        )?
                    },

                    (CmpOperator::Gt, is_not) => {
                        report_all_operation(
                            each_lhs_compare,
                            not_compare(crate::rules::path_value::compare_gt, is_not),
                            inverse,
                            *l,
                            rhs,
                            cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context
                        )?
                    },

                    (CmpOperator::Lt, is_not) => {
                        report_all_operation(
                            each_lhs_compare,
                            not_compare(crate::rules::path_value::compare_lt, is_not),
                            inverse,
                            *l,
                            rhs,
                            cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context
                        )?
                    },

                    (CmpOperator::Le, is_not) => {
                        report_all_operation(
                            each_lhs_compare,
                            not_compare(crate::rules::path_value::compare_le, is_not),
                            inverse,
                            *l,
                            rhs,
                            cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context
                        )?
                    },

                    (CmpOperator::In, is_not) => {
                        report_all_operation(
                            each_lhs_compare,
                            in_cmp(is_not),
                            inverse,
                            *l,
                            rhs,
                            cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context
                        )?
                    }

                    _ => unreachable!()
                };
                for (each, res) in r {
                    statues.push((QueryResult::Resolved(each), if res { Status::PASS } else { Status::FAIL }));
                }
            }
        };
    }
    Ok(EvaluationResult::QueryValueResult(statues))
}

pub(in crate::rules) fn eval_guard_access_clause<'value, 'loc: 'value>(
    gac: &'value GuardAccessClause<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    let all = gac.access_clause.query.match_all;
    let blk_context = format!("GuardAccessClause#block{}", gac);
    resolver.start_record(&blk_context)?;

    let statues = if gac.access_clause.comparator.0.is_unary() {
        unary_operation(&gac.access_clause.query.query,
                        gac.access_clause.comparator,
                        gac.negation,
                        format!("{}", gac),
                        gac.access_clause.custom_message.clone(),
                        resolver)?
    }
    else {
        let rhs = match &gac.access_clause.compare_with {
            Some(val) => {
                match val {
                    LetValue::Value(rhs_val) =>
                        vec![QueryResult::Resolved(rhs_val)],
                    LetValue::AccessClause(acc_querty) =>
                        resolver.query(&acc_querty.query)?
                }
            },

            None => return Err(Error::new(ErrorKind::NotComparable(
                format!("GuardAccessClause {}, did not have a RHS for compare operation", blk_context)
            )))
        };
        binary_operation(
            &gac.access_clause.query.query,
            &rhs,
            gac.access_clause.comparator,
            gac.negation,
            format!("{}", gac),
            gac.access_clause.custom_message.clone(),
            resolver
        )?
    };

    match statues {
        EvaluationResult::EmptyQueryResult(status) => {
            resolver.end_record(&blk_context, RecordType::GuardClauseBlockCheck(BlockCheck {
                status, message: None, at_least_one_matches: all,
            }))?;
            Ok(status)
        },
        EvaluationResult::QueryValueResult(result) => {
            let outcome = loop {
                let mut fails = 0;
                let mut pass = 0;
                for (_value, status) in result {
                    match status {
                        Status::PASS => { pass += 1; },
                        Status::FAIL => { fails += 1; },
                        Status::SKIP => unreachable!()
                    }
                }
                if all {
                    if fails > 0 { break Status::FAIL }
                    break Status::PASS
                }
                else {
                    if pass > 0 { break Status::PASS }
                    break Status::FAIL
                }
            };
            resolver.end_record(&blk_context, RecordType::GuardClauseBlockCheck(BlockCheck {
                message: None,
                status: outcome,
                at_least_one_matches: !all,
            }))?;
            Ok(outcome)
        }
    }

}

pub(in crate::rules) fn eval_guard_named_clause<'value, 'loc: 'value>(
    gnc: &'value GuardNamedRuleClause<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    let context = format!("{}", gnc);
    resolver.start_record(&context)?;

    match resolver.rule_status(&gnc.dependent_rule) {
        Ok(status) => {
            let status = match status {
                Status::PASS => if gnc.negation { Status::FAIL } else { Status::PASS },
                _ => if gnc.negation { Status::PASS } else { Status::FAIL }
            };
            match status {
                Status::PASS => {
                    resolver.end_record(
                        &context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                },
                Status::FAIL => {
                    resolver.end_record(
                        &context,
                        RecordType::ClauseValueCheck(
                            ClauseCheck::DependentRule(
                                MissingValueCheck {
                                    rule: &gnc.dependent_rule,
                                    status: Status::FAIL,
                                    message: None,
                                    custom_message: gnc.custom_message.clone()
                                }
                            )
                        )
                    )?;
                },

                _ => unreachable!()
            }
            Ok(status)
        },

        Err(e) => {
            resolver.end_record(
                &context,
                RecordType::ClauseValueCheck(
                    ClauseCheck::DependentRule(
                        MissingValueCheck {
                            rule: &gnc.dependent_rule,
                            status: Status::FAIL,
                            message: Some(format!("{} failed due to error {}", context, e)),
                            custom_message: gnc.custom_message.clone(),
                        }
                    )
                )
            )?;
            Err(e)
        }
    }
}


pub(in crate::rules) fn eval_general_block_clause<'value, 'loc: 'value, T, E>(
    block: &'value Block<'loc, T>,
    resolver: &dyn EvalContext<'value>,
    eval_fn: E) -> Result<Status>
    where E: Fn(&'value T, &dyn EvalContext<'value>) -> Result<Status>
{
    let block_scope = block_scope(block, resolver.root(), resolver)?;
    eval_conjunction_clauses(&block.conjunctions, &block_scope, eval_fn)
}

pub(in crate::rules) fn eval_guard_block_clause<'value, 'loc: 'value>(
    block_clause: &'value BlockGuardClause<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    let block_values = resolver.query(&block_clause.query.query)?;
    if block_values.is_empty() {
        return Ok(if block_clause.not_empty { Status::FAIL } else { Status::SKIP })
    }
    let match_all = block_clause.query.match_all;
    let context = format!("BlockGuardClause#{}", block_clause.location);
    resolver.start_record(&context)?;
    let mut fails = 0;
    let mut passes = 0;
    for each in block_values {
        match each {
            QueryResult::UnResolved(ur) => {
                fails += 1;
                let guard_cxt = format!("GuardBlockAccessClause#{}", block_clause.location);
                resolver.start_record(&guard_cxt)?;
                resolver.end_record(&guard_cxt, RecordType::ClauseValueCheck(
                    ClauseCheck::MissingBlockValue(ValueCheck {
                        message: Some(format!("Query {} did not resolve to correct value, reason {}",
                                              SliceDisplay(&block_clause.query.query), ur.reason.as_ref().map_or("", |s| s))),
                        status: Status::FAIL,
                        custom_message: None,
                        from: QueryResult::UnResolved(ur)
                    })
                ))?;
            },

            QueryResult::Resolved(rv) => {
                let val_resolver = ValueScope { root: rv, parent: resolver };
                match eval_general_block_clause(&block_clause.block, &val_resolver, eval_guard_clause) {
                    Ok(status) => {
                        match status {
                            Status::PASS => { passes += 1; },
                            Status::FAIL => { fails += 1; },
                            Status::SKIP => {}
                        }
                    },

                    Err(e) => {
                        resolver.end_record(&context, RecordType::BlockGuardCheck(BlockCheck {
                            status: Status::FAIL,
                            at_least_one_matches: !match_all,
                            message: Some(format!("Error {} when handling block clause, bailing", e))
                        }))?;
                        return Err(e)
                    }
                }
            }
        }
    }

    let status = if match_all {
        if fails > 0 { Status::FAIL }
        else if passes > 0 { Status::PASS }
        else { Status::SKIP }
    } else {
        if passes > 0 { Status::PASS }
        else if fails > 0 { Status::FAIL }
        else { Status::SKIP }
    };
    resolver.end_record(&context, RecordType::BlockGuardCheck(BlockCheck {
        status, at_least_one_matches: !match_all, message: None
    }))?;
    Ok(status)
}

fn eval_when_condition_block<'value, 'loc: 'value>(
    context: String,
    conditions: &'value WhenConditions,
    block: &'value Block<GuardClause<'loc>>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    resolver.start_record(&context)?;
    let when_context = format!("{}/When", context);
    resolver.start_record(&when_context)?;
    let block = match eval_conjunction_clauses(conditions, resolver, eval_when_clause) {
        Ok(status) => {
            if status != Status::PASS {
                resolver.end_record(&when_context, RecordType::WhenCondition(status))?;
                resolver.end_record(&context, RecordType::WhenCheck(BlockCheck {
                    status: Status::SKIP,
                    at_least_one_matches: false,
                    message: None
                }))?;
                return Ok(Status::SKIP)
            }
            resolver.end_record(&when_context, RecordType::WhenCondition(Status::PASS))?;
            block
        },

        Err(e) => {
            resolver.end_record(&when_context, RecordType::WhenCondition(Status::FAIL))?;
            resolver.end_record(&context, RecordType::WhenCheck(BlockCheck {
                status: Status::FAIL,
                message: Some(format!("Error {} during type condition evaluation, bailing", e)),
                at_least_one_matches: false
            }))?;
            return Err(e)
        }
    };

    Ok(match eval_general_block_clause(block, resolver, eval_guard_clause) {
        Ok(status) => {
            resolver.end_record(&context, RecordType::WhenCheck(BlockCheck {
                status, message: None, at_least_one_matches: false
            }))?;
            status
        },

        Err(e) => {
            resolver.end_record(&context, RecordType::WhenCheck(BlockCheck {
                status: Status::FAIL,
                message: Some(format!("Error {} during type condition evaluation, bailing", e)),
                at_least_one_matches: false
            }))?;
            return Err(e)
        }
    })
}

pub(in crate::rules) fn eval_guard_clause<'value, 'loc: 'value>(
    gc: &'value GuardClause<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    match gc {
        GuardClause::Clause(gac) => eval_guard_access_clause(gac, resolver),
        GuardClause::NamedRule(gnc) => eval_guard_named_clause(gnc, resolver),
        GuardClause::BlockClause(bc) => eval_guard_block_clause(bc, resolver),
        GuardClause::WhenBlock(conditions, block) => eval_when_condition_block(
            "GuardConditionClause".to_string(), conditions, block, resolver)
    }
}

pub (in crate::rules) fn eval_when_clause<'value, 'loc: 'value>(
    when_clause: &'value WhenGuardClause<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    match when_clause {
        WhenGuardClause::Clause(gac) => eval_guard_access_clause(gac, resolver),
        WhenGuardClause::NamedRule(gnr) => eval_guard_named_clause(gnr, resolver)
    }
}

pub (in crate::rules) fn eval_type_block_clause<'value, 'loc: 'value>(
    type_block: &'value TypeBlock<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    let context = format!("TypeBlock#{}", type_block.type_name);
    resolver.start_record(&context)?;
    let block = if let Some(conditions) = &type_block.conditions {
        let when_context = format!("TypeBlock#{}/When", type_block.type_name);
        resolver.start_record(&when_context)?;
        match eval_conjunction_clauses(conditions, resolver, eval_when_clause) {
            Ok(status) => {
                if status != Status::PASS {
                    resolver.end_record(&when_context, RecordType::TypeCondition(status))?;
                    resolver.end_record(&context, RecordType::TypeCheck(
                        TypeBlockCheck {
                            type_name: &type_block.type_name,
                            block: BlockCheck {
                                status: Status::SKIP,
                                at_least_one_matches: false,
                                message: None
                            }
                        }
                    ))?;
                    return Ok(Status::SKIP)
                }
                resolver.end_record(&when_context, RecordType::TypeCondition(Status::PASS))?;
                &type_block.block
            },

            Err(e) => {
                resolver.end_record(&when_context, RecordType::TypeCondition(Status::FAIL))?;
                resolver.end_record(&context, RecordType::TypeCheck(
                    TypeBlockCheck {
                        type_name: &type_block.type_name,
                        block: BlockCheck {
                            status: Status::FAIL,
                            message: Some(format!("Error {} during type condition evaluation, bailing", e)),
                            at_least_one_matches: false
                        }
                    }
                ))?;
                return Err(e)
            }
        }
    } else { &type_block.block };

    let values = resolver.query(&type_block.query)?;
    if values.is_empty() {
        resolver.end_record(&context, RecordType::TypeCheck(
            TypeBlockCheck {
                type_name: &type_block.type_name,
                block: BlockCheck {
                    status: Status::SKIP,
                    at_least_one_matches: false,
                    message: None
                }
            }))?;
        return Ok(Status::SKIP)
    }

    let mut fails = 0;
    let mut passes = 0;
    for (idx, each) in values.iter().enumerate() {
        match each {
            QueryResult::Resolved(rv) => {
                let block_context = format!("{}/{}", context, idx);
                resolver.start_record(&block_context)?;
                let val_resolver = ValueScope { root: *rv, parent: resolver };
                match eval_general_block_clause(&type_block.block, &val_resolver, eval_guard_clause) {
                    Ok(status) => {
                        match status {
                            Status::PASS => { passes += 1; },
                            Status::FAIL => { fails += 1; },
                            Status::SKIP => {}
                        }
                        resolver.end_record(&block_context, RecordType::TypeBlock(status))?;
                    },

                    Err(e) => {
                        resolver.end_record(&block_context, RecordType::TypeBlock(Status::FAIL))?;
                        resolver.end_record(&context, RecordType::TypeCheck(
                            TypeBlockCheck {
                                type_name: &type_block.type_name,
                                block: BlockCheck {
                                    status: Status::FAIL,
                                    message: Some(format!("Error {} during type block evaluation, bailing", e)),
                                    at_least_one_matches: false
                                }
                            }))?;
                        return Err(e)
                    }
                }
            },

            QueryResult::UnResolved(_) => unreachable!()
        }
    }

    let status =
        if fails > 0 { Status::FAIL }
        else if passes > 0 { Status::PASS }
        else { Status::SKIP };

    resolver.end_record(&context, RecordType::TypeCheck(
        TypeBlockCheck {
            type_name: &type_block.type_name,
            block: BlockCheck {
                status,
                message: None,
                at_least_one_matches: false
            }
        }))?;
    Ok(status)
}

pub(in crate::rules) fn eval_rule_clause<'value, 'loc: 'value>(
    rule_clause: &'value RuleClause<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    match rule_clause {
        RuleClause::Clause(gc) => eval_guard_clause(gc, resolver),
        RuleClause::TypeBlock(tb) => eval_type_block_clause(tb, resolver),
        RuleClause::WhenBlock(conditions, block) => eval_when_condition_block(
            "RuleClause".to_string(), conditions, block, resolver)
    }
}

pub(in crate::rules) fn eval_rule<'value, 'loc: 'value>(
    rule: &'value Rule<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    let context = format!("{}", rule.rule_name);
    resolver.start_record(&context)?;
    let block = if let Some(conditions) = &rule.conditions {
        let when_context = format!("Rule#{}/When", context);
        resolver.start_record(&when_context)?;
        match eval_conjunction_clauses(conditions, resolver, eval_when_clause) {
            Ok(status) => {
                if status != Status::PASS {
                    resolver.end_record(&when_context, RecordType::RuleCondition(status))?;
                    resolver.end_record(&context, RecordType::RuleCheck(NamedStatus {
                        status: Status::SKIP,
                        name: &rule.rule_name,
                    }))?;
                    return Ok(Status::SKIP)
                }
                resolver.end_record(&when_context, RecordType::RuleCondition(Status::PASS))?;
                &rule.block
            },

            Err(e) => {
                resolver.end_record(&when_context, RecordType::RuleCondition(Status::FAIL))?;
                resolver.end_record(&context, RecordType::RuleCheck(NamedStatus {
                    status: Status::FAIL,
                    name: &rule.rule_name,
                }))?;
                return Err(e)
            }
        }
    } else { &rule.block };

    match eval_general_block_clause(&rule.block, resolver, eval_rule_clause) {
        Ok(status) => {
            resolver.end_record(&context, RecordType::RuleCheck(NamedStatus {
                status, name: &rule.rule_name
            }))?;
            Ok(status)
        },

        Err(e) => {
            resolver.end_record(&context, RecordType::RuleCheck(NamedStatus {
                status: Status::FAIL,
                name: &rule.rule_name
            }))?;
            return Err(e)
        }
    }
}

impl<'loc> std::fmt::Display for RulesFile<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("File(rules={})", self.guard_rules.len()))?;
        Ok(())
    }
}

pub(in crate) fn eval_rules_file<'value, 'loc: 'value>(
    rule: &'value RulesFile<'loc>,
    resolver: &dyn EvalContext<'value>) -> Result<Status>
{
    let context = format!("{}", rule);
    resolver.start_record(&context)?;
    let mut fails = 0;
    let mut passes = 0;
    for each_rule in &rule.guard_rules {
        match eval_rule(each_rule, resolver) {
            Ok(status) => {
                match status {
                    Status::PASS => { passes += 1; },
                    Status::FAIL => { fails += 1; },
                    Status::SKIP => {}
                }
            },

            Err(e) => {
                resolver.end_record(&context, RecordType::RuleCheck(NamedStatus {
                    status: Status::FAIL,
                    name: ""
                }))?;
                return Err(e)
            }
        }
    }

    let overall =
        if fails > 0 { Status::FAIL }
        else if passes > 0 { Status::PASS }
        else { Status::SKIP };

    resolver.end_record(&context, RecordType::FileCheck(NamedStatus {
        status: overall, name: ""
    }))?;
    Ok(overall)
}

pub(in crate::rules) fn eval_conjunction_clauses<'value, 'loc: 'value, T, E>(
    conjunctions: &'value Conjunctions<T>,
    resolver: &dyn EvalContext<'value>,
    eval_fn: E) -> Result<Status>
    where E: Fn(&'value T, &dyn EvalContext<'value>) -> Result<Status>
{
    Ok(loop {
        let mut num_passes = 0;
        let mut num_fails = 0;
        let context = format!("{}#disjunction", std::any::type_name::<T>());
        'conjunction: for conjunction in conjunctions {
            let mut num_of_disjunction_fails = 0;
            let multiple_ors_present = conjunction.len() > 1;
            if multiple_ors_present {
                resolver.start_record(&context)?;
            }
            for disjunction in conjunction {
                match eval_fn(disjunction, resolver) {
                    Ok(status) => {
                        match status {
                            Status::PASS => {
                                num_passes += 1;
                                if multiple_ors_present {
                                    resolver.end_record(
                                        &context,
                                        RecordType::Disjunction(BlockCheck {
                                            message: None, at_least_one_matches: true, status: Status::PASS
                                        })
                                    )?;
                                }
                                continue 'conjunction;
                            },
                            Status::SKIP => {},
                            Status::FAIL => { num_of_disjunction_fails += 1; }
                        }
                    },

                    Err(e) => {
                        if multiple_ors_present {
                            resolver.end_record(
                                &context,
                                RecordType::Disjunction(BlockCheck {
                                    message: Some(format!("Disjunction failed due to error {}, bailing", e)),
                                    status: Status::FAIL,
                                    at_least_one_matches: true
                                })
                            )?;
                        }
                        return Err(e)
                    }
                }
            }

            if num_of_disjunction_fails > 0 {
                num_fails += 1;
                if multiple_ors_present {
                    resolver.end_record(
                        &context,
                        RecordType::Disjunction(BlockCheck {
                            message: None,
                            status: Status::FAIL,
                            at_least_one_matches: true
                        })
                    )?;
                }
                continue;
            }
        }
        if num_fails > 0 { break Status::FAIL }
        if num_passes > 0 { break Status::PASS }
        break Status::SKIP
    })
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod eval_tests;
