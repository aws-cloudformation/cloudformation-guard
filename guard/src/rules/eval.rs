use super::exprs::*;
use super::*;
use crate::rules::eval::operators::Comparator;
use crate::rules::eval_context::{block_scope, resolve_function, ValueScope};
use crate::rules::path_value::compare_eq;
use std::collections::HashMap;

mod operators;
mod outcome;

#[cfg(test)]
mod outcome_tests;

#[allow(unused_imports)]
pub(super) use outcome::Outcome;

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

/// Emptiness for the `EMPTY` shortcut, which is reached by two different questions.
///
/// `by_value` is true for a lone variable, where the clause asks about the value the variable is
/// bound to, and `element_empty_operation` is the same function the non-shortcut path uses. It is
/// false for a query ending in a filter, where the clause asks whether the selection produced
/// anything and the selected value's own type is beside the point -- `Condition[ keys == 'x' ]
/// !empty` means "the key is present", and the value behind it may be a boolean.
///
/// Both used to be answered by `is_null`, which is right for neither: it reported an empty list and
/// an empty string as non-empty, and it could not fail at all on a number or a boolean.
fn empty_of(value: &QueryResult, by_value: bool) -> Result<bool> {
    match by_value {
        true => element_empty_operation(value),
        false => Ok(match value {
            QueryResult::Literal(res) | QueryResult::Resolved(res) => res.is_null(),
            // !EXISTS is the same as EMPTY.
            QueryResult::UnResolved(_) => true,
        }),
    }
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
                // FAIL in both roles, because an unevaluatable clause now fails closed in both: as an
                // assertion the clause itself fails, and as a gate the enclosing rule does. An earlier
                // version recorded SKIP for the gate case to match the status it returned, which was
                // the bug -- the record agreed with a verdict that let a guarded violation through.
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
    ///
    /// Still `Status` rather than `Outcome`: this variant carries the clause's whole answer
    /// straight to `end_record`, so there is no fold to lose information in, which is what
    /// the sibling variant's migration was for.
    EmptyQueryResult(Status, Option<String>),
    /// One entry per left-hand value, carrying why that value reached its answer.
    ///
    /// [`Outcome`] rather than [`Status`] so the fold in `eval_guard_access_clause` can
    /// distinguish "not applicable" from "satisfied" without a lossy lift. `Status` has
    /// no way to say "nothing to compare", which is what made an empty `statues` vector
    /// indistinguishable from "everything passed".
    QueryValueResult(Vec<(QueryResult, Outcome)>),
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

/// A notice when no left-hand value can be compared with any element of the right-hand list.
///
/// Returns `None` the moment one pair is comparable, so a mixed list that contains anything of the
/// right kind is left alone -- that case decides on the comparable element and is not changing.
fn incomparable_membership(
    lhs: &[QueryResult],
    rhs: &[QueryResult],
    context: &str,
) -> Option<String> {
    let values = |results: &[QueryResult]| -> Vec<Rc<PathAwareValue>> {
        results
            .iter()
            .filter_map(|r| match r {
                QueryResult::Resolved(v) | QueryResult::Literal(v) => Some(Rc::clone(v)),
                QueryResult::UnResolved(_) => None,
            })
            .collect()
    };
    let lhs_values = values(lhs);
    if lhs_values.is_empty() {
        return None;
    }
    let mut elements = Vec::new();
    for each in values(rhs) {
        match &*each {
            PathAwareValue::List((_, list)) => {
                elements.extend(list.iter().cloned().map(Rc::new));
            }
            _ => elements.push(Rc::clone(&each)),
        }
    }
    if elements.is_empty() {
        return None;
    }
    for value in &lhs_values {
        for element in &elements {
            if compare_eq(value, element).is_ok() {
                return None;
            }
        }
    }
    Some(incomparable_membership_notice(context))
}

/// Notice for `NOT IN` against a list holding nothing the value can be compared with.
///
/// `docs/CLAUSES.md` says a comparison across kinds that are not both numeric "cannot be decided, and
/// the clause fails rather than guessing", and `docs/KNOWN_ISSUES.md` records the silent conversion to
/// `false` as a tracked defect. `!=` already fails closed on the same operands; `NOT IN` does not.
///
/// Not changed in this release, and the reason is specific rather than caution: five rules in
/// aws-guard-rules-registry use `NOT IN` inside a filter predicate to catch a `!Ref`-shaped value, and
/// failing closed makes the filter select fewer resources, which turns a reported violation into a
/// pass. Those rules have to change first.
fn incomparable_membership_notice(context: &str) -> String {
    format!(
        "DEPRECATION: {} passed because the value could not be compared with any element of the list, \
         which is currently read as \"not a member\". A future release fails closed here, as `!=` \
         already does. Compare against values of the same kind, or use `!=` if that is the intent.",
        context
    )
}

/// Note for a gate that closed on one condition while another could not be evaluated at all.
///
/// Written as a note and not as a failure, because the verdict it accompanies is correct: the author
/// asked for every condition, one of them decidably did not match, so the gate is shut and the checks
/// it guards were rightly not run. What is wrong is the rule text, which only the author can fix, and
/// the reason for it is the half [`Outcome::and`] discards on the way to the right answer. Saying
/// "failed" would send the reader looking for a violation that is not there.
///
/// `subject` names what did not apply. A rule's own gate names the rule; a nested `when` block names
/// only itself, because reaching that site with a rule name would mean threading one through
/// `eval_guard_clause` and every clause evaluator under it. Little is lost: `reason` carries the path
/// and position of the value the clause could not read, which locates it more precisely than a name.
fn absorbed_condition_notice(subject: &str, reason: Option<String>) -> String {
    let undecided = match reason {
        Some(reason) => format!("One of its conditions could not be evaluated: {reason}"),
        None => String::from("One of its conditions could not be evaluated"),
    };
    format!(
        "NOTE: {subject} was not applicable because another condition did not match, so nothing in \
         it was checked. {undecided}"
    )
}

/// Explanation attached to a clause whose left-hand variable resolved to no values.
///
/// Distinct from [`empty_reference_message`], which is about the right-hand side. Both say the same
/// thing about enforcement -- nothing was compared -- but the remedy differs: the author has to decide
/// whether an empty selection is expected, and if it is, guard the clause rather than rely on it
/// silently passing.
fn empty_lhs_message() -> String {
    "The comparison could not be performed: the variable on the left-hand side resolved to no \
     values, so there was nothing to compare. If an empty selection is expected here, guard the \
     clause with `when <variable> !empty { ... }` so it is skipped rather than failed."
        .to_string()
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
// `Eq`/`Hash` are here because the role is half of the `rules_status` cache key in
// `eval_context.rs`. Keying that cache on the rule name alone is what previously made a
// named rule's status role-blind: the first reference to reach it decided the cached
// value, and every later reference reused it whatever role it was in.
// `pub(crate)`, not `pub(super)`: `EvalContext::rule_status` takes a `ClauseRole` and that
// trait is `pub(crate)`, so a narrower visibility here makes the trait method expose a more
// private type than itself. `cargo clippy -- -D warnings` rejects that as
// `private_interfaces`, once for the trait and once per implementor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ClauseRole {
    /// The clause is an assertion in a rule body. An unevaluatable clause is a
    /// failure: the rule claimed something it could not establish.
    Assertion,
    /// The clause is a `when` condition gating a block. An unevaluatable clause is
    /// not applicable, never a failure, so the block it guards is still decided by
    /// the remaining conditions.
    Gate,
}

/// An error meaning the clause could not be evaluated at all, as opposed to the evaluation
/// machinery having gone wrong.
///
/// Only `EMPTY` against a type that cannot be empty produces this today. It is matched rather than
/// propagated because the two are answered differently: an unevaluatable clause is a verdict about
/// that clause, while a genuine failure of the machinery should still stop the run.
/// Whether an error from the comparator layer means "could not be answered" rather than "went
/// wrong".
///
/// One caller left, and it is the boundary rather than a leftover. The comparators in
/// `operators.rs` still signal an unsupported operand by returning an error, so something has to
/// translate that into the lattice; every consumer above that point now asks an [`Outcome`] instead
/// of asking an error what kind it is.
fn is_unevaluatable(e: &Error) -> bool {
    matches!(e, Error::IncompatibleError(_))
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
    // Two different questions reach this shortcut, and they are not the same question.
    //
    // A query ending in a filter asks whether the *selection* produced anything:
    // `Condition[ keys == 'aws:IsSecure' ] !empty` means "that key is present", and the value it
    // selected may be a boolean, which has no emptiness of its own. Resolution is the right test.
    //
    // A lone variable asks about the *value* it is bound to. `docs/CLAUSES.md` says a unary operator
    // does not expand a list, so `%tags !empty` is a question about the list, and answering it by
    // resolution reports an empty list as non-empty.
    let selection_empty = matches!(
        &lhs_query[lhs_query.len() - 1],
        QueryPart::Filter(_, _) | QueryPart::MapKeyFilter(_, _)
    );
    let lone_variable = lhs_query.len() == 1 && lhs_query[0].is_variable();
    let empty_on_expr = selection_empty || lone_variable;

    if empty_on_expr && cmp.0 == CmpOperator::Empty {
        return Ok({
            if !lhs.is_empty() {
                let mut results = Vec::with_capacity(lhs.len());
                for each in lhs {
                    eval_context.start_record(&context)?;
                    // `element_empty_operation`, which is the question the operator asks. This arm
                    // used to ask a different one: `res.is_null()`, on the reasoning that NULL is
                    // EMPTY. Null is empty, but so are other things, and nothing else was consulted.
                    //
                    // So a lone variable bound to an empty list or an empty string reported itself
                    // *not* empty, and `EMPTY` on it reported false -- both polarities wrong, on a
                    // value whose emptiness is the whole question. A variable bound to a number or a
                    // boolean could not fail either clause for any input, which is the same silent
                    // always-pass that `element_empty_operation` removed for the direct path and
                    // that this shortcut kept for `%variable`.
                    //
                    // The shortcut itself has to stay. It is what makes the selection idiom work:
                    // for `%vols !empty` an empty selection resolves to zero values and is answered
                    // by the branch below, and dropping this arm would send that to the SKIP further
                    // down instead -- turning the most common gate in the registry from a failure
                    // into a silent skip. Only the decision inside it was wrong.
                    let empty = match empty_of(&each, lone_variable) {
                        Ok(empty) => empty,

                        // A type that cannot be empty is undecided, not failed, and says so as a
                        // value. No role split here: on this branch the consumers ask, so the leaf
                        // answers the same way however it was reached.
                        Err(ref e) if is_unevaluatable(e) => {
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Unary(UnaryValueCheck {
                                    comparison: cmp,
                                    value: ValueCheck {
                                        status: Outcome::Unevaluatable
                                            .to_status(ClauseRole::Assertion),
                                        message: Some(e.to_string()),
                                        custom_message: custom_message.clone(),
                                        from: each.clone(),
                                    },
                                })),
                            )?;
                            results.push((each, Outcome::Unevaluatable));
                            continue;
                        }

                        Err(e) => return Err(e),
                    };

                    let (result, status) = {
                        let holds = match cmp.1 {
                            true => !empty, // not_empty
                            false => empty,
                        };
                        let result = match each {
                            // Rewrapped as `Resolved` exactly as before, so the record a reporter
                            // reads is unchanged.
                            QueryResult::Literal(res) | QueryResult::Resolved(res) => {
                                QueryResult::Resolved(res)
                            }
                            QueryResult::UnResolved(ur) => QueryResult::UnResolved(ur),
                        };
                        (
                            result,
                            match holds {
                                true => Status::PASS,
                                false => Status::FAIL,
                            },
                        )
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

                    // Lifted here rather than at the fold: the unary path decides a
                    // plain pass/fail per value, so the reason is exactly what `Status`
                    // already carries and `from_status` loses nothing.
                    results.push((result, Outcome::from_status(status)));
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
        match (*operation)(&each) {
            Ok(true) => {
                status.push((each, Outcome::Satisfied));
            }

            Ok(false) => {
                status.push((each, Outcome::Violated));
            }

            // `EMPTY` against a type that cannot be empty. Returning this error unconditionally
            // aborted the whole rules file, discarding every other rule's verdict; one unanswerable
            // clause is a verdict about that clause, not about the file.
            //
            // Uniform across roles, which it was not until the condition sites learned to ask.
            //
            // The split version pushed `Unevaluatable` for an assertion and returned the error for a
            // gate, and the error was doing real work: `to_status(Gate)` maps `Unevaluatable` to
            // SKIP, and every non-PASS condition became a rule-level SKIP, so answering a gate with
            // the lattice value silently dropped the guarded body. `rule r when Enabled !EMPTY {
            // MustBeTrue == true }` exited 0 with the violation inside it unreported. That is the
            // case a reviewer found against #717, and it returned once when this arm was made
            // uniform on its own.
            //
            // What made the split unnecessary is that `eval_rule` and `eval_when_condition_block`
            // now distinguish `Unevaluatable` from a condition that merely did not match, so the
            // undecided answer travels as a value and is failed closed where it is consumed. The
            // regression test for that shape is
            // `an_unevaluatable_gate_fails_the_rule_closed`, which is why this can be uniform now
            // and could not be before.
            //
            // `record_unary_clause` has already recorded this value with the matching status and the
            // message naming the offending path, so nothing is lost by not propagating.
            Err(ref e) if is_unevaluatable(e) => status.push((each, Outcome::Unevaluatable)),

            Err(e) => return Err(e),
        }
    }
    Ok(EvaluationResult::QueryValueResult(status))
}

/// One left-hand value compared against one right-hand value, staged for reporting.
///
/// Distinct from [`operators::ComparisonResult`], which it was called `ComparisonResult` to
/// match until this rename. Two types with one name in a parent module and its child is a
/// reading hazard rather than a convenience: `each_lhs_compare` builds these and hands them
/// to `report_value`, while the comparators in `operators.rs` build the other kind, and the
/// only way to tell which a given `ComparisonResult` meant was to check whether the mention
/// carried an `operators::` prefix.
///
/// The two are not interchangeable. This one pairs resolved values and records whether the
/// comparison held as a plain `bool`; the operators one carries the verdict in its
/// `Success`/`Fail` constructor together with the evidence payload the reporter needs.
enum RhsComparison {
    Comparable(ComparisonWithRhs),
    NotComparable(NotComparableWithRhs),
    UnResolvedRhs(UnResolvedRhs),
}

/// The two values a [`RhsComparison`] compared.
///
/// Renamed from `LhsRhsPair`, which [`operators::LhsRhsPair`] also uses.
struct ComparedPair {
    lhs: Rc<PathAwareValue>,
    rhs: Rc<PathAwareValue>,
}

struct ComparisonWithRhs {
    outcome: bool,
    pair: ComparedPair,
}

#[allow(dead_code)]
struct NotComparableWithRhs {
    reason: String,
    pair: ComparedPair,
}

struct UnResolvedRhs {
    rhs: QueryResult,
    lhs: Rc<PathAwareValue>,
}

fn each_lhs_compare<C>(
    cmp: C,
    lhs: Rc<PathAwareValue>,
    rhs: &[QueryResult],
) -> Result<Vec<RhsComparison>>
where
    C: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>,
{
    let mut statues = Vec::with_capacity(rhs.len());
    for each_rhs in rhs {
        match each_rhs {
            QueryResult::Literal(each_rhs_resolved) | QueryResult::Resolved(each_rhs_resolved) => {
                match cmp(&lhs, each_rhs_resolved) {
                    Ok(outcome) => {
                        statues.push(RhsComparison::Comparable(ComparisonWithRhs {
                            outcome,
                            pair: ComparedPair {
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
                                            statues.push(RhsComparison::Comparable(
                                                ComparisonWithRhs {
                                                    outcome,
                                                    pair: ComparedPair {
                                                        lhs: Rc::new(each.clone()),
                                                        rhs: Rc::clone(each_rhs_resolved),
                                                    },
                                                },
                                            ));
                                        }

                                        Err(Error::NotComparable(reason)) => {
                                            statues.push(RhsComparison::NotComparable(
                                                NotComparableWithRhs {
                                                    reason,
                                                    pair: ComparedPair {
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
                                                statues.push(RhsComparison::Comparable(
                                                    ComparisonWithRhs {
                                                        outcome,
                                                        pair: ComparedPair {
                                                            lhs: Rc::clone(&lhs),
                                                            rhs: Rc::new(
                                                                rhs_inner_single_element.clone(),
                                                            ),
                                                        },
                                                    },
                                                ));
                                            }

                                            Err(Error::NotComparable(reason)) => {
                                                statues.push(RhsComparison::NotComparable(
                                                    NotComparableWithRhs {
                                                        reason,
                                                        pair: ComparedPair {
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

                        statues.push(RhsComparison::NotComparable(NotComparableWithRhs {
                            reason,
                            pair: ComparedPair {
                                lhs: Rc::clone(&lhs),
                                rhs: Rc::clone(each_rhs_resolved),
                            },
                        }));
                    }

                    Err(e) => return Err(e),
                }
            }

            QueryResult::UnResolved(_ur) => {
                statues.push(RhsComparison::UnResolvedRhs(UnResolvedRhs {
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
    each_res: &RhsComparison,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<(QueryResult, Outcome)> {
    let (lhs_value, rhs_value, outcome, reason) = match each_res {
        RhsComparison::Comparable(ComparisonWithRhs {
            outcome,
            pair:
                ComparedPair {
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
        RhsComparison::NotComparable(NotComparableWithRhs {
            pair:
                ComparedPair {
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
        RhsComparison::UnResolvedRhs(UnResolvedRhs {
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
        (lhs_value, Outcome::Satisfied)
    } else {
        // Locate the finding on whichever side actually points into the input.
        //
        // Reporters read `from` for `PropertyPath`, for `Value`, and to centre the context
        // window they print around the offending line. A literal written in the rule text
        // carries `Path::root()`, so when it lands in `from` the path renders as `[L:0,C:0]`
        // and the context window centres on line 0 -- the finding shows the top of the
        // template instead of the resource that failed.
        //
        // That is reachable through an ordinary rule, not a contrived one:
        //
        //     rule r(replaced, expected) { %expected == %replaced }
        //     rule main { r(regex_replace(%arn, ..), "random_str") }
        //
        // puts the literal on the left. Before `5e83239` bound literal arguments as
        // `Literal`, this clause took the query-vs-query arm and reported against the
        // resource by accident; recognising the literal fixed the verdict and moved the
        // report onto the literal, which located nothing.
        //
        // Only swapped when the left side is unlocated *and* the right side is not, so a
        // comparison between two real values keeps reporting against its left side, which is
        // the subject the clause is written about. `to` keeps the literal, so `ComparedWith`
        // still names what the value was checked against; nothing is dropped, the two are
        // ordered by which one an operator can act on.
        let swap_for_reporting =
            !locates_input(&lhs_value) && rhs_value.as_ref().is_some_and(locates_input);
        let (from, to) = if swap_for_reporting {
            (rhs_value.unwrap(), Some(lhs_value.clone()))
        } else {
            (lhs_value.clone(), rhs_value)
        };

        eval_context.start_record(&context)?;
        eval_context.end_record(
            &context,
            RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
                from,
                comparison: cmp,
                to,
                custom_message,
                message: reason,
                status: Status::FAIL,
            })),
        )?;
        (lhs_value, Outcome::Violated)
    })
}

/// True when this result points at a position in the input rather than at rule text.
///
/// Used to decide which side of a failed comparison a finding should be reported against;
/// see the note in [`report_value`].
fn locates_input(result: &QueryResult) -> bool {
    match result {
        QueryResult::Literal(value) | QueryResult::Resolved(value) => {
            !value.self_path().is_unlocated()
        }
        QueryResult::UnResolved(unresolved) => !unresolved.traversed_to.self_path().is_unlocated(),
    }
}

/// Order a failed comparison's two values so the finding is reported against whichever one
/// locates a position in the input.
///
/// Same reasoning as the note in [`report_value`], applied to the comparator results that
/// reach `binary_operation` directly: reporters take `PropertyPath`, `Value` and the printed
/// context window from the first of the pair, so putting a rule-text literal there costs the
/// operator the line that actually failed.
fn locate_report(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> (QueryResult, QueryResult) {
    if lhs.self_path().is_unlocated() && !rhs.self_path().is_unlocated() {
        (QueryResult::Resolved(rhs), QueryResult::Resolved(lhs))
    } else {
        (QueryResult::Resolved(lhs), QueryResult::Resolved(rhs))
    }
}

fn report_all_values<'r, 'value: 'r, 'loc: 'value>(
    comparisons: Vec<RhsComparison>,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<(QueryResult, Outcome)>> {
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
    rhs_comparisons: Vec<RhsComparison>,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<(QueryResult, Outcome)>> {
    let mut statues = Vec::with_capacity(rhs_comparisons.len());
    let mut by_lhs_value = HashMap::new();
    for each in &rhs_comparisons {
        match each {
            RhsComparison::Comparable(ComparisonWithRhs {
                pair: ComparedPair { lhs, rhs },
                ..
            }) => {
                by_lhs_value
                    .entry(lhs)
                    .or_insert(vec![])
                    .push((each, QueryResult::Resolved(Rc::clone(rhs))));
            }

            RhsComparison::NotComparable(NotComparableWithRhs {
                pair: ComparedPair { lhs, rhs },
                ..
            }) => {
                by_lhs_value
                    .entry(lhs)
                    .or_insert(vec![])
                    .push((each, QueryResult::Resolved(Rc::clone(rhs))));
            }

            RhsComparison::UnResolvedRhs(UnResolvedRhs { rhs, lhs }) => {
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
                RhsComparison::Comparable(ComparisonWithRhs { outcome: true, .. })
            )
        });
        match found {
            Some(_) => {
                eval_context.start_record(&context)?;
                eval_context
                    .end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                statues.push((QueryResult::Resolved(Rc::clone(lhs)), Outcome::Satisfied))
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
                statues.push((QueryResult::Resolved(Rc::clone(lhs)), Outcome::Violated))
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
///
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
    // Checked before the comparison rather than after, because the answer is not recoverable from the
    // result: the not-flag has already turned "no element matched" into a success by then, and a
    // success from an incomparable operand looks exactly like a real one. Only `NOT IN` reaches this,
    // so the extra comparisons cost nothing on any other clause.
    if cmp.1 && cmp.0 == CmpOperator::In {
        if let Some(notice) = incomparable_membership(&lhs, rhs, &context) {
            eval_context.record_diagnostic(notice);
        }
    }
    let results = cmp.compare(&lhs, rhs)?;
    match results {
        // The left-hand query selected nothing, so there was nothing to compare. Which answer that
        // deserves depends on the shape of the query, and the two cases are not alike.
        //
        // A filtered query that matched nothing -- `Resources.*[ Type == 'AWS::S3::Bucket' ]` against a
        // template with no buckets -- is the idiom that lets one ruleset run over templates that do not
        // all contain the resource being checked. It is documented in `docs/QUERY_AND_FILTERING.md` and
        // has to stay a SKIP; failing it would fail every template that omits the resource type.
        //
        // A lone variable that resolved to nothing is the mirror of the empty *right*-hand reference
        // closed earlier on this branch. `%x == 'abc'`, `%x != 'abc'` and `%x > 5` all exited 0 when `%x` held
        // no values, so a rule whose only check was one of those reported compliance having compared
        // nothing -- the same bypass, on the other operand. It fails closed as an assertion, and stays
        // a SKIP as a gate for the reason given on the `EmptyRhsUnsatisfiable` arm below: a FAIL on a
        // condition is counted by the fold and outranks siblings that passed.
        //
        // The distinction is drawn the same way `unary_operation` already draws it for `EMPTY`, so
        // there is one definition of "the query is just a variable" rather than two.
        operators::EvalResult::Skip => {
            let lone_variable = lhs_query.len() == 1 && lhs_query[0].is_variable();
            Ok(match lone_variable {
                true => EvaluationResult::EmptyQueryResult(
                    match role.is_strict() {
                        true => Status::FAIL,
                        false => Status::SKIP,
                    },
                    Some(empty_lhs_message()),
                ),
                false => EvaluationResult::EmptyQueryResult(Status::SKIP, None),
            })
        }

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
            let mut statues: Vec<(QueryResult, Outcome)> = Vec::with_capacity(lhs.len());
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
                        statues.push((QueryResult::UnResolved(ur), Outcome::Violated));
                    }

                    // One left-hand value was an empty collection, so there was nothing
                    // to compare it against. Reported here rather than in the
                    // comparator because the correct status depends on the role, which
                    // a comparator cannot see.
                    //
                    // As an assertion this fails: the rule claimed a property of every
                    // element and cannot establish it over none, and treating it as
                    // satisfied is the wrong PASS being fixed -- `Tags == 'Owner'`
                    // against `Tags: []` reported "compliant", not "not applicable".
                    //
                    // As a gate it must stay SKIP, for the same reason as
                    // EmptyRhsUnsatisfiable above: eval_rule treats a non-PASS
                    // condition as "rule does not apply" and drops the guarded body, so
                    // failing here would disarm every check inside it and still exit 0.
                    // Note that SKIP does not open the gate either -- it closes it
                    // quietly. That is a known and unfixed hazard, recorded in
                    // outcome.rs; it is pre-existing for every non-PASS condition and
                    // is not made worse here.
                    operators::ValueEvalResult::EmptyLhsCollection(value) => {
                        // Only an assertion produces an entry here. `statues` is a
                        // per-value PASS/FAIL vector -- the fold in
                        // `eval_guard_access_clause` treats SKIP as `unreachable!()`,
                        // because "nothing to report" is carried by
                        // EvaluationResult::EmptyQueryResult instead. So a
                        // gate must contribute no entry at all rather than a SKIP entry,
                        // which leaves the gate decided by its other conditions exactly
                        // as before this fix.
                        //
                        // Failing as an assertion is the fix: the rule claimed a
                        // property of every element and cannot establish it over none.
                        // `Tags == 'Owner'` against `Tags: []` reported "compliant" --
                        // not "not applicable" -- so it actively asserted a check it
                        // never performed.
                        //
                        // A negated clause must NOT fail here. `cmp.1` is the operator's
                        // own not-flag already composed with the clause-level `not` --
                        // see the `let comparator = (...)` XOR in
                        // `eval_guard_access_clause` -- and `not (Tags == 'Owner')` over nothing is
                        // vacuously true. This arm runs before the per-value inversion,
                        // so a FAIL emitted here is one the `not` can never reach; it has
                        // to opt out instead.
                        //
                        // Opting out means "push nothing", and that is NOT neutral: an empty
                        // `statues` reaches the fold with `fails == 0`, which breaks
                        // `Status::PASS`. PASS short-circuits `eval_conjunction_clauses`, so
                        //
                        //     Tags != 'Owner'  or  Name == 'safebucket'
                        //
                        // reports a violating template as *compliant* -- the vacuous first
                        // disjunct satisfies the whole `or` and the real check never runs.
                        // Pre-existing: v3.2.0 exits 0 for that ruleset too.
                        //
                        // Returning SKIP instead is the resolution the
                        // `EmptyRhsVacuouslyTrue` arm of `binary_operation` uses for the
                        // identical hazard. It was implemented
                        // here twice and reverted twice (see fb64016); the reproduction is
                        // parked as `a_vacuous_negated_clause_does_not_absorb_a_disjunction`.
                        // A `vacuously_satisfied` flag carried that state in the reverted
                        // version and no longer exists -- the only thing keeping the
                        // *positive* case out of this trap is the FAIL pushed below, which
                        // puts an entry in `statues` so the fold never sees `fails == 0`.
                        //
                        // `some` needs no handling here, which is worth saying because it
                        // is not obvious. Block-level `some` is decided in
                        // `eval_guard_block_clause`, where `passes > 0` outranks any
                        // number of fails, so a FAIL contributed here
                        // cannot sink a block that has a real witness elsewhere. An
                        // earlier version of this fix threaded `match_all` down to guard
                        // that case; removing it changed no measured behaviour on any
                        // fixture, so it was dropped rather than kept as a
                        // plausible-looking safeguard.
                        // `Unevaluatable.blocks(role)` rather than `role.is_strict()`.
                        // Equivalent by construction -- `to_status` maps Unevaluatable to
                        // FAIL for an assertion and SKIP for a gate -- but it states the
                        // premise: this value is an unevaluatable clause, and the question
                        // is whether an unevaluatable clause blocks in this role.
                        //
                        // `blocks`, not `closes_gate`: here the clause is being reported,
                        // and a FAIL is what blocks a deployment. `closes_gate` answers a
                        // different question -- whether a condition silences the block it
                        // guards -- and the gate branch below deliberately does not fail.
                        if Outcome::Unevaluatable.blocks(role) && !cmp.1 {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                    ComparisonClauseCheck {
                                        status: Status::FAIL,
                                        message: Some(format!(
                                            "Comparison had nothing to compare: the value at {} is an empty collection",
                                            value.self_path()
                                        )),
                                        custom_message: custom_message.clone(),
                                        comparison: cmp,
                                        from: QueryResult::Resolved(Rc::clone(&value)),
                                        to: None,
                                    },
                                )),
                            )?;
                            statues.push((QueryResult::Resolved(value), Outcome::Violated));
                        } else if Outcome::Unevaluatable.blocks(role) {
                            // A negated assertion over nothing. Vacuously true, but not
                            // evidence of anything, so it must not satisfy a disjunction.
                            //
                            // This used to push nothing at all, which is exactly what let the
                            // vacuous disjunct absorb an `or`: an empty `statues` reached the
                            // fold indistinguishable from "everything passed". The fold now
                            // reads this SKIP as `Outcome::NotApplicable`, which does not
                            // absorb under `or`, so the sibling disjuncts still run.
                            //
                            // No record is emitted deliberately. The entry carries the fold,
                            // but reporting a clause the author negated over an empty
                            // collection as a finding would be noise -- nothing is wrong with
                            // the template.
                            statues.push((QueryResult::Resolved(value), Outcome::NotApplicable));
                        } else {
                            // A gate. The vacuous PASS here is load-bearing and cannot be
                            // replaced with SKIP, which is what sank the two earlier attempts
                            // at this fix and a third one made while writing this arm.
                            //
                            // `eval_rule` treats any non-PASS condition as "this rule does not
                            // apply" and drops every check in the guarded block. So a gate
                            // whose condition has nothing to compare has to report PASS and
                            // leave the block to its other conditions; returning SKIP closes
                            // the gate quietly and trades one unenforced clause for a whole
                            // disarmed body, while still exiting 0.
                            //
                            // Measured, not reasoned: pushing SKIP here fails
                            // `a_vacuous_negated_gate_still_opens_and_runs_its_body`,
                            // `an_empty_collection_in_a_when_condition_does_not_disarm_the_guarded_block`,
                            // `an_empty_collection_in_an_ordering_gate_does_not_disarm_the_block`,
                            // `a_mirrored_empty_collection_in_a_when_condition_does_not_disarm_the_block`
                            // and `a_vacuous_negation_nested_in_a_when_block_still_runs_the_inner_body`.
                            //
                            // That SKIP does not open a gate either is a real design wart,
                            // recorded on `Outcome::closes_gate`. It is pre-existing for every
                            // non-PASS condition and is not made worse here.
                            statues.push((QueryResult::Resolved(value), Outcome::Satisfied));
                        }
                        // A negated comparison contributes nothing, and that is a known
                        // defect rather than a decision. Read on before "fixing" it.
                        //
                        // Contributing nothing leaves `statues` empty, which the fold at
                        // eval.rs reads as `fails == 0` and reports PASS. PASS
                        // short-circuits `eval_conjunction_clauses`, so
                        //
                        //     Tags != 'Owner'  or  Name == 'safebucket'
                        //
                        // reports a violating template as *compliant* -- the vacuous first
                        // disjunct satisfies the whole `or` and the real check never runs.
                        // This is the hazard EmptyRhsVacuouslyTrue returns SKIP to avoid,
                        // and it is pre-existing here: v3.2.0 exits 0 for that ruleset too.
                        //
                        // Returning SKIP instead was implemented and reverted, twice. The
                        // second attempt narrowed it to `role.is_strict()`, which fixed the
                        // direct gate spelling and still regressed this:
                        //
                        //     rule vac_ne { ...Tags != 'Owner' }
                        //     rule body when vac_ne { ...Name == 'privatebucket' }
                        //
                        // measured 19 -> 0 against a template with `Tags: []` and a
                        // violating Name. The cause was the named-rule boundary: `rule_status`
                        // evaluated a referenced rule's body with ClauseRole::Assertion
                        // whatever the reference site was, so `role` here said "assertion"
                        // even when the rule was being used as a gate, and the SKIP then made
                        // eval_rule treat the guarded rule as inapplicable and drop its body.
                        // The status was also cached per rule name, so one gate-poisoned SKIP
                        // was reused by every later reference.
                        //
                        // THAT BLOCKER IS GONE. `rule_status` now carries the reference site's
                        // role into `eval_rule` and keys `rules_status` on `(rule, role)`, so
                        // ClauseRole reaches across the named-rule boundary and `role` here is
                        // the role of the actual reference. `a_named_rule_gate_does_not_drop_a
                        // _satisfiable_body` and `the_same_named_rule_answers_both_roles
                        // _independently` pin it.
                        //
                        // So the reverted SKIP is worth attempting again, and the two
                        // reproductions above are the oracle for whether it regresses gates
                        // this time. It is not attempted here because it is not a local edit:
                        // `statues` is a per-value PASS/FAIL vector and the fold in
                        // `eval_guard_access_clause` treats a SKIP entry as `unreachable!()`,
                        // so a third attempt has to change the fold's vocabulary rather than
                        // this arm -- which is the `Outcome` conversion in `eval/outcome.rs`,
                        // still unwired.
                        //
                        // Net effect of leaving it for now: a pre-existing wrong PASS survives
                        // in disjunctions, reproduced by the still-ignored
                        // `a_vacuous_negated_clause_does_not_absorb_a_disjunction`.
                        //
                        // MEASURED CORRECTION, and it is about the FAIL path above rather
                        // than the reverted SKIP.
                        //
                        // At a *syntactic* `when`, failing here does NOT close the gate.
                        // `role.is_strict()` is false for a gate, so this arm contributes
                        // nothing and the gate is left to its other conditions. Verified:
                        // `rule r when ...Tags == 'Owner' { ...Name == 'safe' }` against
                        // `Tags: []` exits 19 with the failure on `/Properties/Name` and
                        // `not_applicable: []` -- the gate opened and the body ran. Same for
                        // an `IN` gate, and the negated pair inverts correctly. So "it would
                        // close the gate" is not the reason `IN` and the ordering operators
                        // are unfixed; the reason is only that they never emit
                        // EmptyLhsCollection and so never reach this arm.
                        //
                        // Across a NAMED-RULE boundary the FAIL pushed below used to drop the
                        // body, a regression this branch introduced and has since fixed:
                        //
                        //     rule vac_eq { ...Tags == 'Owner' }
                        //     rule body when vac_eq { ...Name == 'publicbucket' }
                        //
                        // with `Tags: []` and `Name: publicbucket`, so the body is
                        // *satisfiable*. v3.2.0 exits 0 with both rules compliant. Between
                        // 2224cb1 and the (rule, role) keying this exited 19 with
                        // `not_compliant: [vac_eq]` and `not_applicable: [body]` -- the body's
                        // verdict destroyed. `role.is_strict()` was true even when the rule was
                        // used as a gate, this arm fired, `vac_eq` became FAIL, and eval_rule
                        // read the non-PASS condition as "does not apply".
                        //
                        // Now that `rule_status` propagates the reference site's role, a gate
                        // reference evaluates the body with ClauseRole::Gate, `role.is_strict()`
                        // is false, this arm contributes nothing, and the gate is left to its
                        // other conditions -- the same behaviour a syntactic `when` already
                        // had. Pinned by `a_named_rule_gate_does_not_drop_a_satisfiable_body`.
                        //
                        // Reverting this arm was rejected rather than untried: it restores the
                        // original wrong PASS (`Tags == 'Owner'` certifying `Tags: []`), and a
                        // wrong PASS on a policy gate is worse than a wrong FAIL.
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
                        statues.push((QueryResult::Resolved(Rc::clone(&lhs)), Outcome::Violated));
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
                        statues.push((QueryResult::Resolved(nc.pair.lhs), Outcome::Violated));
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
                            statues.push((QueryResult::Resolved(lin.lhs), Outcome::Satisfied));
                        }

                        operators::Compare::QueryIn(qin) => {
                            for each in qin.lhs {
                                eval_context.start_record(&context)?;
                                eval_context.end_record(
                                    &context,
                                    RecordType::ClauseValueCheck(ClauseCheck::Success),
                                )?;
                                statues.push((QueryResult::Resolved(each), Outcome::Satisfied));
                            }
                        }

                        operators::Compare::Value(pair) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Success),
                            )?;
                            statues.push((QueryResult::Resolved(pair.lhs), Outcome::Satisfied));
                        }

                        operators::Compare::ValueIn(val) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Success),
                            )?;
                            statues.push((QueryResult::Resolved(val.lhs), Outcome::Satisfied));
                        }
                    },

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::Fail(cmpr),
                    ) => match cmpr {
                        operators::Compare::Value(pair) => {
                            // Reported against whichever side locates something in the
                            // input; see `locate_report`. The per-value entry below keeps
                            // the left side regardless, since the fold reads only the
                            // outcome and the map-key filter matches on it.
                            let (from, to) =
                                locate_report(Rc::clone(&pair.lhs), Rc::clone(&pair.rhs));
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                    ComparisonClauseCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        comparison: cmp,
                                        from,
                                        to: Some(to),
                                    },
                                )),
                            )?;
                            statues.push((
                                QueryResult::Resolved(Rc::clone(&pair.lhs)),
                                Outcome::Violated,
                            ));
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
                            statues.push((
                                QueryResult::Resolved(Rc::clone(&pair.lhs)),
                                Outcome::Violated,
                            ));
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
                            statues.push((
                                QueryResult::Resolved(Rc::clone(&lin.lhs)),
                                Outcome::Violated,
                            ));
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
                                statues.push((
                                    QueryResult::Resolved(Rc::clone(&lhs)),
                                    Outcome::Violated,
                                ));
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
    let mut statues: Vec<(QueryResult, Outcome)> = Vec::with_capacity(lhs.len());

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
                statues.push((each.clone(), Outcome::Violated));
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
) -> Result<Outcome> {
    let all = gac.access_clause.query.match_all;
    let blk_context = format!("GuardAccessClause#block{}", gac);
    resolver.start_record(&blk_context)?;

    let statues = if gac.access_clause.comparator.0.is_unary() {
        // No role. A unary clause's *answer* does not depend on whether it was reached as an
        // assertion or as a gate; only the status that answer maps to does, and that mapping now
        // happens at the consumer. The parameter was threaded here to choose between a value and an
        // error for the same undecided answer, and there is one representation of it now.
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
                // The empty-collection arms decide by polarity rather than by role, so the status
                // they chose is lifted rather than re-derived: FAIL is a violation and SKIP is
                // inapplicable. `from_status` is exact for those two.
                let outcome = Outcome::from_status(status);
                resolver.end_record(
                    &blk_context,
                    RecordType::GuardClauseBlockCheck(BlockCheck {
                        status,
                        message,
                        // `!all`, matching the other five sites that build this record in this
                        // function: the field records whether the block was satisfied by any one
                        // value rather than by all of them, so it is the negation of `all`. This
                        // arm alone had `all`. Nothing outside the tests reads the field today, so
                        // the disagreement was invisible; it would become a wrong branch the first
                        // time a reporter consumed it.
                        at_least_one_matches: !all,
                    }),
                )?;
                Ok(outcome)
            }
            EvaluationResult::QueryValueResult(result) => {
                // Folded through `Outcome` rather than by counting passes and fails.
                //
                // The counting version could not represent a third answer. It matched
                // `Status::SKIP => unreachable!()`, so a clause that was neither satisfied
                // nor violated -- a negated comparison with nothing to compare -- had no way
                // to say so and had to contribute no entry at all. Contributing nothing is
                // not neutral here: with `match_all` the fold then saw `fails == 0` and
                // returned PASS, and PASS short-circuits `eval_conjunction_clauses`, so
                //
                //     Tags != 'Owner'  or  Name == 'safebucket'
                //
                // reported a violating template as compliant -- the vacuous first disjunct
                // satisfied the whole `or` and the real check never ran.
                //
                // `Outcome::all`/`Outcome::any` fix that structurally rather than by adding
                // another counter. They fold from `Outcome::identity()`, which is
                // `NotApplicable`, so a fold over zero elements returns "did not apply"
                // instead of "satisfied" -- the rule `outcome.rs` states as the one that
                // closes the empty-input defects. And only `Satisfied` absorbs under `or`, so
                // an inapplicable disjunct cannot stand in for one that passed.
                //
                // `from_status` is lossy in the direction that matters least here: it maps
                // SKIP to `NotApplicable`, discarding *why* it was skipped. The entries being
                // lifted are per-value PASS/FAIL/SKIP produced a few lines above, and SKIP has
                // two sources there: nothing to compare, and an incompatible type met while
                // evaluating a `when` condition. Both mean the clause could not answer for that
                // value, so the collapse is faithful for this call site either way. Producing
                // `Outcome` directly from the comparators is the next step, not this one.
                //
                // The counting version this replaced had grown a `skips` counter for the second
                // source, with a guard so that a fold over zero elements kept its old answer.
                // `Outcome::identity()` is `NotApplicable`, so that guard is not needed here --
                // which is the argument for the lattice in miniature: the third answer is a value
                // rather than a special case each fold has to remember.
                let outcome = {
                    let outcomes = result.into_iter().map(|(_value, outcome)| outcome);
                    match all {
                        true => Outcome::all(outcomes),
                        false => Outcome::any(outcomes),
                    }
                };
                resolver.end_record(
                    &blk_context,
                    RecordType::GuardClauseBlockCheck(BlockCheck {
                        message: None,
                        // The record keeps a status, because that is what a reporter reads. The role
                        // is applied here and only here, so the clause itself can still be handed
                        // to its caller undecided.
                        status: outcome.to_status(role),
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

            // A clause whose own value could not be produced fails, and the rest of the file still
            // reports. Errors reach here from resolving the clause's query, which includes a `let`
            // whose function call could not convert its input: `let n = parse_int(Properties.Name)`
            // on a non-numeric name used to abort the run at exit 255 and discard every other rule's
            // verdict, including real violations an unrelated rule had already found. Same shape as
            // the incompatible-type abort fixed earlier on this branch, reached through a function
            // instead of an operator.
            //
            // Role-free, like the per-value arm above. An unevaluatable clause answers
            // `Unevaluatable` and the consumer decides what that means for it.
            //
            // This arm used to split on `role.is_strict()` and hand a gate the error instead, so the
            // enclosing condition site could tell "could not be answered" apart from "did not match".
            // That is the job the lattice now does with a value, and `to_status` and `closes_gate` at
            // the consumer are where the role is applied.
            match is_unevaluatable(&e) {
                true => Ok(Outcome::Unevaluatable),
                false => Err(e),
            }
        }
    }
}

/// Evaluates a reference to another rule by name.
///
/// `role` distinguishes the two contexts this is reached from:
///
/// - [`ClauseRole::Assertion`] -- the reference is in a rule body, so a SKIPped
///   dependent rule must not satisfy it in either polarity. Failing closed here is
///   what stops `not <rule>` from reporting compliance for a check that never ran.
/// - [`ClauseRole::Gate`] -- the reference is a `when` condition, where gating on a
///   rule that did not apply is deliberate and covered by existing tests.
pub(in crate::rules) fn eval_guard_named_clause<'value, 'loc: 'value>(
    gnc: &'value GuardNamedRuleClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Outcome> {
    let context = format!("{}", gnc);
    resolver.start_record(&context)?;

    match resolver.rule_status(&gnc.dependent_rule, role) {
        Ok(outcome) => {
            // The same table as `eval_parameterized_rule_call`, which is the point: the two
            // spellings of one gate had drifted apart, and the comment there claimed to mirror this
            // function while the arms disagreed.
            let outcome = match (outcome, gnc.negation) {
                (Outcome::Satisfied, false) => Outcome::Satisfied,
                (Outcome::Satisfied, true) => Outcome::Violated,

                // A dependent rule that could not be evaluated leaves this reference undecided too.
                // The reference cannot know more than the rule did, and this is exactly the
                // distinction the cache used to lose: it stored `to_status(role)`, so a gate saw
                // SKIP, read it as "the rule did not apply", and reported the enclosing rule
                // inapplicable while a guarded check went unrun. Measured on
                // `undecidable_nested_gate_named.guard`, where the merge-base fails the rule and
                // this branch reported it skipped.
                (Outcome::Unevaluatable, _) => Outcome::Unevaluatable,

                // A rule that did not apply never ran, so it is not evidence in either direction.
                // Where the reference is an assertion in a rule body, a negated reference to it must
                // not report compliance on the strength of a check that never happened.
                (Outcome::NotApplicable, _) if role.is_strict() => Outcome::Violated,

                // A gate whose dependent rule did not apply stays inapplicable rather than becoming
                // a violation, which one inapplicable condition would otherwise spread to a `when`
                // its siblings would have decided. Pinned by
                // `a_named_rule_gate_on_a_skipped_rule_does_not_disarm_the_block`.
                (Outcome::NotApplicable, false) => Outcome::NotApplicable,

                // `rule r when not other { ... }` is how a ruleset says "apply this when that other
                // rule did not apply", so the gate opens. Pinned by
                // `negated_reference_to_skipped_rule_still_gates_a_when_condition`. A negated
                // assertion never reaches here, because the fail-closed arm above took it.
                (Outcome::NotApplicable, true) => Outcome::Satisfied,

                (Outcome::Violated, false) => Outcome::Violated,
                (Outcome::Violated, true) => Outcome::Satisfied,
            };

            let status = outcome.to_status(role);
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
            // The rule's answer, unflattened. `status` above exists only for the records a reporter
            // reads; the caller gets the value and applies its own role.
            Ok(outcome)
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
) -> Result<Outcome>
where
    E: Fn(&'value T, &mut dyn EvalContext<'value, 'loc>) -> Result<Outcome>,
    T: CaptureNames<'value>,
{
    let mut block_scope = block_scope(block, resolver.root(), resolver);
    let status = eval_conjunction_clauses(&block.conjunctions, &mut block_scope, eval_fn);
    // Captures are handed up whatever the block's verdict: a clause after the block reads them, and it
    // reads them just the same when the block failed. See `merge_captures_into_parent`.
    block_scope.merge_captures_into_parent()?;
    status
}

/// `role` is inherited from the enclosing clause; a block clause is not itself a
/// gate or an assertion, it just groups the clauses inside it.
pub(in crate::rules) fn eval_guard_block_clause<'value, 'loc: 'value>(
    block_clause: &'value BlockGuardClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Outcome> {
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
        // An empty selection is a violation when the block asked for one and inapplicable otherwise,
        // which is the same pair of answers as before rather than a new reading of emptiness.
        let outcome = match block_clause.not_empty {
            true => Outcome::Violated,
            false => Outcome::NotApplicable,
        };
        resolver.end_record(
            &context,
            RecordType::BlockGuardCheck(BlockCheck {
                status: outcome.to_status(role),
                at_least_one_matches: !match_all,
                message: None,
            }),
        )?;
        return Ok(outcome);
    }
    // `match_all` conjoins and its absence disjoins, which is what the two counter orderings said:
    // the all-form answered FAIL before PASS and the any-form PASS before FAIL, and `Outcome::and`
    // absorbs `Violated` while `Outcome::or` absorbs `Satisfied`.
    let combine = match match_all {
        true => Outcome::and,
        false => Outcome::or,
    };
    let mut combined = Outcome::identity();
    for each in block_values {
        match each {
            QueryResult::UnResolved(ur) => {
                combined = combine(combined, Outcome::Violated);
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
                    Ok(outcome) => combined = combine(combined, outcome),

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

    resolver.end_record(
        &context,
        RecordType::BlockGuardCheck(BlockCheck {
            status: combined.to_status(role),
            at_least_one_matches: !match_all,
            message: None,
        }),
    )?;
    Ok(combined)
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
) -> Result<Outcome> {
    resolver.start_record(&context)?;
    let when_context = format!("{}/When", context);
    resolver.start_record(&when_context)?;
    let block = match conjunction_outcome(conditions, resolver, eval_when_clause) {
        // A condition that could not be answered is not a condition that did not match. This is the
        // distinction the error channel used to carry: skipping here disarms every check inside the
        // block, which is the direction that turns a violation into exit 0, so the block is answered
        // `Unevaluatable` and whoever asked applies the role once.
        //
        // Not `Violated`, which is what the error channel produced. A violation says the input is
        // wrong; this says nothing was established about the input. The two differ where it matters:
        // a rule reached as a gate sees `Unevaluatable` and fails closed, where `Violated` would
        // read as an ordinary non-matching condition and make the rule inapplicable.
        Ok(ConditionOutcome {
            outcome: Outcome::Unevaluatable,
            ..
        }) => {
            resolver.end_record(
                &when_context,
                RecordType::WhenCondition(Outcome::Unevaluatable.to_status(role)),
            )?;
            resolver.end_record(
                &context,
                RecordType::WhenCheck(BlockCheck {
                    status: Outcome::Unevaluatable.to_status(role),
                    // No message. Verified rather than assumed: a rule whose inner `when` condition
                    // cannot be evaluated prints the clause's own explanation -- "Attempting EMPTY
                    // operation on type bool ... at /Enabled" -- and nothing on this record reaches
                    // the output. `every_recorded_explanation_has_a_rendering_path` refused the
                    // sentence that was here first, which is what that test is for: a message
                    // recorded and discarded reads like a diagnostic in the source and is invisible
                    // to the person the diagnostic was for.
                    message: None,
                    at_least_one_matches: false,
                }),
            )?;
            return Ok(Outcome::Unevaluatable);
        }

        Ok(answered) => {
            let outcome = answered.outcome;
            // `closes_gate`, not `status != PASS`. This is the branch that makes a block
            // inapplicable and drops every check inside it, so "did the gate close" is the
            // question being asked, and it is deliberately not `Outcome::blocks`: a gate that
            // closes blocks nothing and still silences everything it guarded, which is the hazard
            // the two predicates exist to keep apart.
            if outcome.closes_gate() {
                // Same absorbed condition as the one `eval_rule` reports, one nesting level in. The
                // loss was measured here too: the same conjunction spelled inside `when { }` exits
                // 19 on this branch's base and 0 here, and only the base names the type error.
                if answered.had_unevaluatable_conjunct {
                    resolver.record_diagnostic(absorbed_condition_notice(
                        "A `when` block",
                        answered.unevaluatable_reason,
                    ));
                }
                resolver.end_record(
                    &when_context,
                    RecordType::WhenCondition(outcome.to_status(role)),
                )?;
                resolver.end_record(
                    &context,
                    RecordType::WhenCheck(BlockCheck {
                        status: Status::SKIP,
                        at_least_one_matches: false,
                        message: None,
                    }),
                )?;
                return Ok(Outcome::NotApplicable);
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
                    message: Some(format!("Error {} during condition evaluation, bailing", e)),
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
            Ok(outcome) => {
                resolver.end_record(
                    &context,
                    RecordType::WhenCheck(BlockCheck {
                        status: outcome.to_status(role),
                        message: None,
                        at_least_one_matches: false,
                    }),
                )?;
                outcome
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

    fn rule_status(&mut self, rule_name: &'value str, role: ClauseRole) -> Result<Outcome> {
        self.parent.rule_status(rule_name, role)
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
) -> Result<Outcome> {
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
                // `Literal`, not `Resolved`: this is a literal argument written at the
                // call site, exactly like a `let` binding, and `resolve_variable`'s
                // `scope.literals` branch returns those as `QueryResult::Literal`.
                //
                // Binding it as `Resolved` made two spellings of the same literal take
                // different comparator arms, because `is_literal` only recognises
                // `Literal`. A parameter therefore reached the `(None, None)` arm, which
                // compares whole query results via `diff` rather than element-wise, so a
                // list-valued left side was compared against the scalar as a list and
                // never matched:
                //
                //     rule no_banned_tag(banned) { ...Properties.Tags != %banned }
                //     rule main { no_banned_tag("PublicRead") }
                //
                // passed a bucket tagged exactly `["PublicRead"]`, while the same policy
                // with the value inlined, or bound with `let`, correctly failed. `==` was
                // inverted the same way: it failed the template that did match.
                //
                // Binding it as `Literal` also moves where a failed comparison is reported.
                // That interaction is not obvious, so it is recorded here beside its cause.
                //
                // For `rule r(replaced, expected) { %expected == %replaced }` called with a
                // literal, recognising the literal moves the clause off the `(None, None)`
                // diff arm onto the equality arm. The verdict becomes right, but the literal
                // carries `Path::root()`, so the record's `from` renders as `[L:0,C:0]`, and
                // reporters centre their context window on the reported path -- a finding that
                // should point at the offending `Arn:` line pointed at the top of the template
                // instead. It went unnoticed because the test path sanitisation was broken at
                // the time, which kept `test_validate_with_failing_complex_rule` from showing
                // the difference.
                //
                // `locate_report` resolves it by ordering a failed comparison's two values so
                // the finding lands on whichever one points into the input. The fixture accepts
                // the corrected comparison semantics -- an equality message, and `ComparedWith`
                // naming the literal rather than the value compared against itself -- with the
                // original path and context window intact.
                resolved_parameters.insert(
                    (param_rule.parameter_names[idx]).as_str(),
                    vec![QueryResult::Literal(Rc::new(val.clone()))],
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
    let outcome = eval_rule(&param_rule.rule, &mut eval, role)?;

    // Apply the clause-level negation of the *call*. The parser accepts and stores a
    // leading `not` on a parameterized invocation (`not is_relevant("x")`) exactly as
    // it does for a plain named-rule reference, but this arm used to return the
    // invoked rule's status unchanged, so the `not` was silently discarded and
    // `not r(...)` behaved identically to `r(...)`.
    //
    // Mirrors eval_guard_named_clause so both spellings agree: PASS inverts to FAIL
    // under negation, a SKIPped rule fails closed wherever the reference is an
    // assertion, and otherwise the negation flips the outcome.
    //
    // The fail-closed arm has no negation guard, so it covers both polarities, and for a
    // plain `r(...)` that is a change in outcome rather than a fix to the negation: main
    // returned the invoked rule's SKIP and exited 0, this returns FAIL and exits 19. That
    // is deliberate -- a rule body asserting `r(...)` claims that `r` holds, and a rule
    // that never ran is not evidence that it does -- but it is the arm to look at first if
    // a ruleset starts failing on a rule it used to skip. Gate references are unaffected;
    // they take the SKIP arm below.
    Ok(match (outcome, call_rule.named_rule.negation) {
        (Outcome::Satisfied, false) => Outcome::Satisfied,
        (Outcome::Satisfied, true) => Outcome::Violated,

        // An invoked rule that could not be evaluated stays undecided, and the call site's role
        // settles it: `to_status` fails an assertion closed and leaves a gate inapplicable, which
        // is what the two SKIP arms below used to do by hand.
        //
        // This is also a change of outcome for `not r(...)`. Before the lattice, an unevaluatable
        // rule arrived here as FAIL, indistinguishable from a rule the input violated, so the
        // negation inverted it and `not r(...)` reported PASS for a rule that never decided
        // anything. Negating an undecided answer does not produce a decided one.
        (Outcome::Unevaluatable, _) => Outcome::Unevaluatable,

        // A rule that did not apply is not evidence that it holds, so an assertion on it fails
        // closed. Deliberate, and the arm to look at first if a ruleset starts failing on a rule it
        // used to skip: `rule main { r(...) }` claims `r` holds, and `r` never ran.
        (Outcome::NotApplicable, _) if role.is_strict() => Outcome::Violated,

        // A gate whose invoked rule did not apply stays inapplicable rather than becoming a
        // violation. With one condition the two are indistinguishable, since either way the guarded
        // body is dropped; with more than one, `Outcome::and` absorbs `Violated` but treats
        // `NotApplicable` as the identity, so one inapplicable gate condition would otherwise
        // poison a `when` that its siblings would have decided.
        (Outcome::NotApplicable, false) => Outcome::NotApplicable,

        // `when not r(...)` opens the gate when `r` did not apply. A negated assertion never
        // reaches here, because the fail-closed arm above already took it.
        (Outcome::NotApplicable, true) => Outcome::Satisfied,

        (Outcome::Violated, false) => Outcome::Violated,
        (Outcome::Violated, true) => Outcome::Satisfied,
    })
}

/// `role` propagates the assertion-vs-gate distinction to the leaf clauses. Callers
/// evaluating a rule body pass [`ClauseRole::Assertion`]; callers evaluating the
/// conditions of a `when` block or a parameterized gate pass [`ClauseRole::Gate`].
pub(in crate::rules) fn eval_guard_clause<'value, 'loc: 'value>(
    gc: &'value GuardClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Outcome> {
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
) -> Result<Outcome> {
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
) -> Result<Outcome> {
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
        return Ok(Outcome::NotApplicable);
    }

    // A type block conjoins over its resources: every one of them must satisfy it. The counters are
    // that conjunction written out, and `undecided` is the value the pair could not hold -- a
    // resource whose condition could not be answered is neither a pass nor a failure, and treating
    // it as either is what the error channel was doing.
    let mut fails = 0;
    let mut passes = 0;
    let mut undecided = 0;
    // Tracked only so the SKIP below can name the right cause. Three different things reach SKIP
    // here and they call for three different sentences; telling a reader the wrong one of them is
    // worse than telling them nothing, which is the defect this branch spent most of its commits
    // removing. `selected` counts the slots that resolved to a resource, `exempted` the ones the
    // block's own `when` condition declined, and `unresolved_reason` keeps the first retrieval
    // failure so the "selected nothing" sentence can name it.
    let mut selected = 0;
    let mut exempted = 0;
    let mut unresolved_reason: Option<String> = None;
    for (idx, each) in values.iter().enumerate() {
        match each {
            QueryResult::Literal(rv) | QueryResult::Resolved(rv) => {
                selected += 1;
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
                        // A condition this resource cannot answer leaves the resource undecided,
                        // rather than exempting it or aborting the file. Exempting is the dangerous
                        // direction: the block's clauses would never run and the rule could report
                        // compliance for a resource nothing checked. It arrived as an error before
                        // the lattice and was counted as a failure, which said the resource was
                        // non-compliant when what was true is that nothing was established about it.
                        Ok(Outcome::Unevaluatable) => {
                            val_resolver.end_record(
                                &when_context,
                                RecordType::TypeCondition(
                                    Outcome::Unevaluatable.to_status(ClauseRole::Assertion),
                                ),
                            )?;
                            val_resolver
                                .end_record(&block_context, RecordType::TypeBlock(Status::FAIL))?;
                            undecided += 1;
                            continue;
                        }

                        Ok(outcome) => {
                            let status = outcome.to_status(ClauseRole::Gate);
                            val_resolver
                                .end_record(&when_context, RecordType::TypeCondition(status))?;
                            // `closes_gate`, not `status != PASS`. Identical in behaviour --
                            // `from_status` maps PASS to Satisfied and both FAIL and SKIP to
                            // variants that close -- but it names the decision being made. This
                            // is the branch that exempts a resource from the block guarding it,
                            // and it is deliberately not `Outcome::blocks`: a gate that closes
                            // blocks nothing and still silences everything it guarded, which is
                            // the hazard the two predicates exist to keep apart.
                            if outcome.closes_gate() {
                                // Not applicable to this resource, so it contributes to neither
                                // count. If that holds for every resource the fold below answers
                                // SKIP, which is the honest answer: the block applied to nothing.
                                exempted += 1;
                                val_resolver.end_record(
                                    &block_context,
                                    RecordType::TypeBlock(Status::SKIP),
                                )?;
                                continue;
                            }
                        }

                        // A condition this resource cannot answer fails closed for that resource,
                        // rather than aborting the file or exempting the resource. Exempting it is the
                        // dangerous direction: the block's clauses would never run and the rule could
                        // report compliance for a resource nothing checked.
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
                    Ok(outcome) => {
                        match outcome {
                            Outcome::Satisfied => passes += 1,
                            Outcome::Violated => fails += 1,
                            Outcome::Unevaluatable => undecided += 1,
                            Outcome::NotApplicable => {}
                        }
                        resolver.end_record(
                            &block_context,
                            RecordType::TypeBlock(outcome.to_status(role)),
                        )?;
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
            // answer here, and `ur.reason` is kept for the block's own message rather than turned
            // into an error. Counting it as neither a pass nor a fail leaves the fold below to
            // decide: if no slot resolved, the block applied to nothing and reports SKIP.
            //
            // Found by differential against the merge-base rather than by reading. Moving the type
            // block's conditions per-resource removed an early return that had been masking this
            // for the `when` form, so a latent abort became a reachable one. The plain form aborted
            // on the merge-base too, which is how the pre-existing half was confirmed. Pinned by
            // `an_unresolved_type_block_query_skips_without_aborting_the_file`.
            //
            // Recorded as `TypeBlock`, matching what every resolved slot in this loop emits. An
            // earlier version recorded a second `TypeCheck` here, which broke the record shape
            // display.rs documents and relies on -- "has one TypeBlock for the block associated" --
            // so a `-v` run rendered one type block as two nested identical `Type(...)` nodes with
            // the slot's own node missing. The reason travels in `unresolved_reason` instead, which
            // is where it belongs: it explains the block's verdict, not one slot's.
            QueryResult::UnResolved(ur) => {
                if unresolved_reason.is_none() {
                    unresolved_reason = ur.reason.clone();
                }
                let block_context = format!("{}/{}", context, idx);
                resolver.start_record(&block_context)?;
                resolver.end_record(&block_context, RecordType::TypeBlock(Status::SKIP))?;
            }
        }
    }

    // The conjunction, in the order `Outcome::and` gives: a violation anywhere absorbs, an
    // undecided resource then dominates a satisfied one, and no resource at all is the identity.
    let outcome = if fails > 0 {
        Outcome::Violated
    } else if undecided > 0 {
        Outcome::Unevaluatable
    } else if passes > 0 {
        Outcome::Satisfied
    } else {
        Outcome::NotApplicable
    };
    let status = outcome.to_status(role);

    resolver.end_record(
        &context,
        RecordType::TypeCheck(TypeBlockCheck {
            type_name: &type_block.type_name,
            block: BlockCheck {
                status,
                // Only the SKIP needs explaining, and it has three causes that call for three
                // different sentences. A rule that never fires looks exactly like a rule that
                // passes, so the reader needs to know which one happened -- and naming the wrong
                // cause sends them to the wrong place.
                //
                // The `when` sentence is guarded on `exempted == selected` rather than being the
                // default. It used to be the default, so a block with no `when` condition at all
                // reported that its `when` condition had exempted every resource -- reachable
                // whenever the body's own clauses are inapplicable, which a filter selecting
                // nothing or an inner `when` that does not fire both do.
                //
                // The last arm covers the mixed case, where some resources were exempted and the
                // rest had nothing applicable to check. It names both possibilities rather than
                // picking one, because at block level they are indistinguishable and the specific
                // account lives on the slot records that `find_skip_reason` now reaches first.
                // Pinned by `a_type_block_skip_names_the_cause_it_can_support`.
                message: match status {
                    Status::SKIP if selected == 0 => Some(match &unresolved_reason {
                        Some(reason) => format!(
                            "no {} could be selected from the input: {}",
                            type_block.type_name, reason
                        ),
                        None => format!(
                            "no {} could be selected from the input, so the type block had nothing to check",
                            type_block.type_name
                        ),
                    }),
                    Status::SKIP if exempted == selected => Some(format!(
                        "every {} in the input was exempted by the type block's `when` condition, so none was checked",
                        type_block.type_name
                    )),
                    // A block with no `when` of its own cannot have exempted anything, so naming
                    // one would send the reader to look for a condition the rule does not contain
                    // -- the mistake this arm was added to fix, in a narrower form.
                    Status::SKIP if type_block.conditions.is_none() => Some(format!(
                        "no {} in the input was checked: no clause in the type block applied to any of them",
                        type_block.type_name
                    )),
                    Status::SKIP => Some(format!(
                        "no {} in the input was checked: every one was either exempted by the type block's `when` condition or had no clause that applied to it",
                        type_block.type_name
                    )),
                    _ => None,
                },
                at_least_one_matches: false,
            },
        }),
    )?;
    Ok(outcome)
}

/// `role` is inherited by the clauses of this rule clause.
pub(in crate::rules) fn eval_rule_clause<'value, 'loc: 'value>(
    rule_clause: &'value RuleClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Outcome> {
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
) -> Result<Outcome> {
    let context = rule.rule_name.to_string();
    resolver.start_record(&context)?;
    let block = if let Some(conditions) = &rule.conditions {
        let when_context = format!("Rule#{}/When", context);
        resolver.start_record(&when_context)?;
        match conjunction_outcome(conditions, resolver, eval_when_clause) {
            // The distinction this PR exists to make. A condition that could not be answered is not
            // a condition that did not match, and only one of the two may leave the guarded body
            // unevaluated at exit 0.
            //
            // Before the lattice these were the same value: every non-PASS condition became a
            // rule-level SKIP, so an undecidable gate silenced its body exactly as a non-matching
            // one does. The fix was to route the undecidable case through the error channel and
            // catch it here, which worked and cost a channel. Now the condition says which it is.
            Ok(ConditionOutcome {
                outcome: Outcome::Unevaluatable,
                unevaluatable_reason,
                ..
            }) => {
                resolver.end_record(
                    &when_context,
                    RecordType::RuleCondition(Outcome::Unevaluatable.to_status(role)),
                )?;
                // Which clause, and why. The sentence explains the *verdict* -- that this is a failure
                // rather than an inapplicable rule -- and says nothing about the cause, so on its own it
                // sends the reader looking for a clause it does not name. The parent branch appended the
                // cause by interpolating the error, because there the answer was the error. Here the answer
                // is a value and `Outcome` is `Copy`, so the cause travels beside it: the fold read it at
                // the point the undecidable branch's own record closed, and that is the reason bound here.
                //
                // Not `reason_from_last_closed_record` at this site, which is what it was. That reads the
                // whole condition's record and returns the first explanation anywhere underneath, which is
                // whichever clause was written first rather than whichever clause could not be evaluated.
                // `Violated or Unevaluatable` answers `Unevaluatable`, and two `Violated` producers record
                // an explanation of their own -- an incomparable pair and a non-negated assertion over an
                // empty collection -- so a decided sibling's reason was attached to the undecidable
                // verdict. Measured over `violated_disjunct_first.guard` and its mirror image: the same two
                // branches in opposite order, same exit code, and only one of the two reasons named the
                // clause the sentence was about.
                //
                // The positional read stays as the fallback, for a condition that answered `Unevaluatable`
                // with no branch having recorded a reason -- a clause whose query itself failed records its
                // message on a block rather than on a comparison, and the walk still finds the leaf
                // underneath it. There is nothing better to say in that case and this is what was said
                // before.
                //
                // Dropping it was a real loss and not only in the console: the text was absent from the
                // JSON as well, so nothing downstream could recover it. Found by differencing this branch
                // against its base over the fixture corpus -- same exit code, three outputs with less in
                // them.
                let verdict =
                    "The rule's condition could not be evaluated, so the rule fails rather \
                               than being treated as not applicable";
                let message = match unevaluatable_reason
                    .or_else(|| resolver.reason_from_last_closed_record())
                {
                    Some(reason) => format!("{verdict}: {reason}"),
                    None => String::from(verdict),
                };
                resolver.end_record(
                    &context,
                    RecordType::RuleCheck(NamedStatus {
                        status: Outcome::Unevaluatable.to_status(role),
                        name: &rule.rule_name,
                        message: Some(message),
                    }),
                )?;
                return Ok(Outcome::Unevaluatable);
            }

            Ok(answered) => {
                let outcome = answered.outcome;
                let status = outcome.to_status(role);
                // `closes_gate`, not `status != PASS`. Identical in behaviour --
                // `from_status` maps PASS to Satisfied and both FAIL and SKIP to variants
                // that close -- but it names the decision. This is the branch that makes a
                // rule inapplicable and drops every check in its body, so "did the gate
                // close" is the question being asked, and it is deliberately not
                // `Outcome::blocks`: a gate that closes blocks nothing and still silences
                // everything it guarded, which is the hazard the two predicates exist to
                // keep apart.
                if outcome.closes_gate() {
                    // The arm above has already taken every answer that *is* undecidable, so a
                    // conjunct that was undecidable and an answer that is not means the answer
                    // absorbed it. SKIP is still right and stays; the reason goes to stderr, which
                    // moves neither the exit code nor the report.
                    if answered.had_unevaluatable_conjunct {
                        resolver.record_diagnostic(absorbed_condition_notice(
                            &format!("Rule {}", rule.rule_name),
                            answered.unevaluatable_reason,
                        ));
                    }
                    resolver.end_record(&when_context, RecordType::RuleCondition(status))?;
                    resolver.end_record(
                        &context,
                        RecordType::RuleCheck(NamedStatus {
                            status: Status::SKIP,
                            name: &rule.rule_name,
                            ..Default::default()
                        }),
                    )?;
                    return Ok(Outcome::NotApplicable);
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
                // Only real errors reach here now. The undecidable case used to arrive as one and be
                // sorted out by `is_unevaluatable`, which meant the channel carried two unrelated
                // things and every consumer had to ask which it was holding.
                return Err(e);
            }
        }
    } else {
        &rule.block
    };

    match eval_general_block_clause(block, resolver, |rc, r| eval_rule_clause(rc, r, role)) {
        Ok(outcome) => {
            resolver.end_record(
                &context,
                RecordType::RuleCheck(NamedStatus {
                    // The role is applied for the record and for whoever asked the rule's status,
                    // and the rule keeps its own answer. That is what lets a caller reached as a
                    // gate see "could not tell" where a caller reached as an assertion sees FAIL,
                    // without either of them inspecting an error.
                    status: outcome.to_status(role),
                    name: &rule.rule_name,
                    ..Default::default()
                }),
            )?;
            Ok(outcome)
        }

        Err(e) => {
            resolver.end_record(
                &context,
                RecordType::RuleCheck(NamedStatus {
                    status: Status::FAIL,
                    name: &rule.rule_name,
                    // No message here on purpose. The clause that could not be evaluated records its
                    // own explanation, and that is what both the console and the JSON view render --
                    // naming the clause, which a rule-level restatement cannot. A message added here
                    // reached the JSON only, beside the clause's, and
                    // `every_recorded_explanation_has_a_rendering_path` is what caught it.
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
    let mut first_error = None;
    for each_rule in &rule.guard_rules {
        // A capture is scoped to the rule that made it. A rule condition is evaluated against the
        // enclosing scope, so without this a capture in one rule's `when` outlived it and the next
        // rule using the same name saw the previous rule's keys.
        resolver.reset_captures();
        // Top-level rule in a rules file: its clauses are assertions.
        match eval_rule(each_rule, resolver, ClauseRole::Assertion) {
            // The file is the boundary where the lattice becomes an exit code, so the role is
            // applied here: a top-level rule is an assertion, and an undecided one is a failure
            // rather than a rule that did not apply.
            Ok(outcome) => match outcome.to_status(ClauseRole::Assertion) {
                Status::PASS => {
                    passes += 1;
                }
                Status::FAIL => {
                    fails += 1;
                }
                Status::SKIP => {}
            },

            // A rule that cannot be evaluated costs its own finding, not the file's.
            //
            // What was here closed the *file's* record with a rule-check payload -- `eval_rule` has
            // already closed the rule's own record as a failure by the time this is reached -- and
            // then returned, so the file's record was both mislabelled and truncated and every rule
            // after this one went unevaluated. A file whose second rule read a variable that does not
            // exist in it printed one error line and nothing else, discarding five real findings that
            // its third rule had already produced.
            //
            // The error is still returned, after the loop rather than instead of it: a variable that
            // resolves nowhere is a broken ruleset rather than a non-compliant template, and the exit
            // code has to keep saying so. What changes is that there is a report to read alongside it.
            Err(e) => {
                fails += 1;
                if first_error.is_none() {
                    first_error = Some(e);
                }
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

    match first_error {
        Some(e) => Err(e),
        None => Ok(overall),
    }
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

/// What a conjunction answered, and whether that answer buried a conjunct nothing could decide.
///
/// [`Outcome::and`] absorbs [`Outcome::Violated`], which is right and is not changing: Kleene has the
/// same table, and a gate whose author asked for two conditions where one decidably did not match
/// does not apply. But absorption discards the other conjunct, and when that conjunct was
/// [`Outcome::Unevaluatable`] the discarded thing was the explanation of a defect in the rule text:
///
/// ```text
/// rule r when Enabled !EMPTY
///             Name == "nope" {
/// ```
///
/// `Enabled !EMPTY` against `Enabled: true` is a type error in the rule -- EMPTY does not apply to a
/// bool -- and says so. Against a template with `Name: nope` the fold answers `Unevaluatable`, the
/// rule fails, and the author reads the type error. Against one with any other `Name` the second
/// conjunct answers `Violated`, absorbs the first, and the author reads nothing at exit 0. Whether a
/// malformed rule is reported should not depend on which template it was run against, so the fact and
/// the reason are carried out here and go to stderr, leaving both the verdict and the report alone.
///
/// Carried beside [`Outcome`] rather than inside it, for the reason recorded on
/// [`RecordTracer::reason_from_last_closed_record`]: a payload would break `Copy` and force `and` and
/// `or` to choose between two reasons.
#[derive(Debug)]
struct ConditionOutcome {
    /// The fold's answer. Nothing else on this struct changes it.
    outcome: Outcome,

    /// True when some conjunct answered [`Outcome::Unevaluatable`].
    ///
    /// Read only by the gate branches, and there it means the answer buried it: every pairing of an
    /// unevaluatable conjunct with something other than `Violated` maps to `Unevaluatable` itself, so
    /// a caller that has already matched that arm away and still sees this flag is looking at a
    /// `Violated` answer standing in for a condition nothing could decide.
    had_unevaluatable_conjunct: bool,

    /// The first such conjunct's own recorded explanation, when it recorded one.
    unevaluatable_reason: Option<String>,
}

/// Conjunctions of disjunctions, folded through [`Outcome`] rather than counted.
///
/// The counting version could not express one of the four answers. It tallied passes and fails, read
/// `Status::SKIP` as "no information" and dropped it, and answered FAIL, then PASS, then SKIP. That is
/// [`Outcome::and`] over [`Outcome::or`] for three of the four values, and for the fourth it had no
/// representation at all: a clause that could not be evaluated arrived here as `Err` and left as
/// `Err`, which is why the error channel existed.
///
/// Two consequences of the fold that the counters did not have:
///
/// One is that `A or B` is now evaluated to the end when `A` cannot be answered. The counting version
/// returned the error from the first unevaluatable disjunct, so `B` never ran even when `B` would
/// have satisfied the disjunction outright. `Outcome::or` absorbs only `Satisfied`, so a decidable
/// branch decides and an undecidable one only survives when nothing else answered. For a gate that
/// narrows failing closed to the cases that genuinely cannot be decided, rather than to the cases
/// where the first branch could not be.
///
/// The other is that a disjunction of undecidable branches is `Unevaluatable` rather than `FAIL`.
/// Reporting a violation there blames the input for a reference that never resolved.
///
/// Callers that gate a block on the answer want [`conjunction_outcome`] instead, which is this fold
/// and also says whether the answer absorbed a conjunct nothing could decide.
pub(in crate::rules) fn eval_conjunction_clauses<'value, 'loc: 'value, T, E>(
    conjunctions: &'value Conjunctions<T>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    eval_fn: E,
) -> Result<Outcome>
where
    E: Fn(&'value T, &mut dyn EvalContext<'value, 'loc>) -> Result<Outcome>,
{
    conjunction_outcome(conjunctions, resolver, eval_fn).map(|answered| answered.outcome)
}

/// [`eval_conjunction_clauses`], keeping what the fold absorbed on the way to its answer.
///
/// See [`ConditionOutcome`] for why the extra half exists and who reads it.
#[allow(clippy::never_loop)]
fn conjunction_outcome<'value, 'loc: 'value, T, E>(
    conjunctions: &'value Conjunctions<T>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    eval_fn: E,
) -> Result<ConditionOutcome>
where
    E: Fn(&'value T, &mut dyn EvalContext<'value, 'loc>) -> Result<Outcome>,
{
    let context = format!("{}#disjunction", disjunction_type_name::<T>());
    let mut conjoined = Outcome::identity();
    let mut had_unevaluatable_conjunct = false;
    let mut unevaluatable_reason = None;

    for conjunction in conjunctions {
        let multiple_ors_present = conjunction.len() > 1;
        if multiple_ors_present {
            resolver.start_record(&context)?;
        }

        let mut disjoined = Outcome::identity();
        let mut disjoined_reason = None;
        for disjunction in conjunction {
            match eval_fn(disjunction, resolver) {
                Ok(outcome) => {
                    // Read here rather than once after the fold, because
                    // `reason_from_last_closed_record` answers about the record just closed and this
                    // is the only point at which that record is *this* branch's. Asking afterwards
                    // returns the first explanation anywhere under the condition, and a violated
                    // sibling carries one of its own -- an incomparable pair and an empty collection
                    // both record a reason while answering `Violated` -- so on the conjunction this
                    // exists for it would quote the wrong clause and call a violation undecidable.
                    if let Outcome::Unevaluatable = outcome {
                        if disjoined_reason.is_none() {
                            disjoined_reason = resolver.reason_from_last_closed_record();
                        }
                    }
                    disjoined = disjoined.or(outcome);
                    // Satisfied absorbs, so the remaining branches cannot change the answer. The
                    // counting version stopped here too, and stopping keeps the records to the
                    // branches that were actually consulted.
                    if let Outcome::Satisfied = disjoined {
                        break;
                    }
                }

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

        if multiple_ors_present {
            // The record keeps its three statuses, because a reporter reads them and an
            // undecidable disjunction is reported the way an assertion would see it.
            resolver.end_record(
                &context,
                RecordType::Disjunction(BlockCheck {
                    message: None,
                    status: disjoined.to_status(ClauseRole::Assertion),
                    at_least_one_matches: true,
                }),
            )?;
        }

        // Judged on the conjunct's answer, not on any branch's. A disjunction holding an undecidable
        // branch beside a satisfied one *was* decided -- `or` absorbs only `Satisfied`, deliberately --
        // and nothing about it was buried, so the flag stays down and the guarded block still runs.
        if let Outcome::Unevaluatable = disjoined {
            had_unevaluatable_conjunct = true;
            if unevaluatable_reason.is_none() {
                unevaluatable_reason = disjoined_reason;
            }
        }

        conjoined = conjoined.and(disjoined);
    }

    Ok(ConditionOutcome {
        outcome: conjoined,
        had_unevaluatable_conjunct,
        unevaluatable_reason,
    })
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod eval_tests;
