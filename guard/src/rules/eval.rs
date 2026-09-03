use super::exprs::*;
use super::*;
use crate::rules::eval::operators::Comparator;
use crate::rules::eval_context::{
    block_scope, interpolated_keys, query_retrieval, resolve_function, ValueScope,
};
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
    EmptyQueryResult(Status, Option<String>),
    QueryValueResult(Vec<(QueryResult, Status)>),
}

/// Explanation attached to a clause that could not compare because its right-hand reference
/// resolved to no values.
///
/// Points at what binds the reference, which is where the fault is. It used to name `when
/// <reference> !empty { ... }` as the remedy, and that is not one: the gate's own `!empty` check
/// fails when the reference is empty, so the block is skipped and the comparison never runs. An
/// author following the advice turned a check that was failing for a reason into a check that does
/// not run, at exit 0, which is the outcome this message exists to prevent. Saying so is worth the
/// extra sentence, because the advice was there for two releases.
fn empty_reference_message(negated: bool) -> String {
    let clause = if negated {
        "negated comparison"
    } else {
        "comparison"
    };
    format!(
        "The {clause} could not be performed: the reference on the right-hand side resolved to no \
         values, so the clause fails. Look at what binds the reference -- a `let` or a filter \
         capture that selected nothing. `when <reference> !empty {{ ... }}` skips the clause rather \
         than satisfying it."
    )
}

/// Notice for a comparison that passed without comparing anything, because the value it selected was
/// an empty collection.
///
/// `docs/QUERY_AND_FILTERING.md` lists `Tags: []` alongside a missing key and an empty map as a
/// retrieval error, and says all retrieval errors are failures. The other two do fail; this one passes,
/// which makes it the odd one out rather than a design choice. It is not changed in this release
/// because the change turns a passing run into a failing one, and a rule author deserves to hear about
/// that before a pipeline does.
/// True when no left-hand value can be compared with any element of the right-hand list.
///
/// False the moment one pair is comparable, so a mixed list that contains anything of the right kind is
/// left alone -- that case decides on the comparable element and is not changing.
///
/// Half of the condition, not all of it. True here means the clause's answer *could* have come from the
/// incomparability, and the caller still has to read the verdict. See `binary_operation`, which uses the
/// verdict to pick between two notice bodies, or to emit neither.
///
/// # This predicate is wrong, in both directions, and known to be
///
/// It decides on the comparability of the **whole left-hand value** against each flattened right-hand
/// element. `is_one_of` and `contained_in` decide a list-valued left-hand side by comparing its
/// **elements**. The two have diverged, and the consequence is not academic: **this emits a
/// DEPRECATION on ordinary, well-typed, compliant denylist checks, telling the author a passing rule
/// will fail closed in a future release when it will not.**
///
/// The concrete case, and the shape most real rules take:
///
/// ```text
/// Actions: ["s3:GetObject", "s3:PutObject"]
/// rule r { Actions NOT IN ["s3:DeleteBucket", "s3:PutBucketPolicy"] }   # exit 0 + DEPRECATION
/// ```
///
/// Every pair the operator compared is string against string, all answerable, nothing suppressed. The
/// element comparisons demonstrably worked: change one action to a denied one and the clause exits 19
/// naming it, which an incomparable operand pair could not do.
///
/// The discriminator is one variable, and it is what makes the diagnosis certain rather than plausible:
/// `Strs NOT IN ["x","y"]` emits the notice and `Strs NOT IN ["x","y",["p"]]` does not, both passing,
/// element-wise facts identical. Adding an irrelevant nested list flips
/// `compare_eq(whole_lhs_list, element)` from `Err` to `Ok`, because of which arm each pair lands on.
/// `compare_eq` answers `(List, List)` itself and always returns `Ok` -- `false` on a length mismatch,
/// never a refusal. It has no `(List, String)` arm at all, so that pair falls through its `(_, _)` arm
/// into `compare_values`, whose own catch-all refuses with `NotComparable`. So the notice's trigger is
/// decided by the *kind* of an unrelated denylist element rather than by anything about the comparison
/// the clause performs.
///
/// Wrong in the other direction too, from the early return above: `Str NOT IN Haystack` over
/// `["zzz", 7, false]` stays silent because `"a"` and `"zzz"` are comparable, though `"a"` against `7`
/// is exactly the pair a fail-closed release will refuse. Measured over 132 clause shapes at this
/// commit, against the oracle the notice's own text implies -- true iff the clause passed AND at least
/// one pair the operator actually compared raised `NotComparable` -- 73 cells are true positives,
/// **7 are false alarms of the kind above, and 10 are notices that should have been emitted and were
/// not.** Zero remain where the notice contradicts a failing verdict; that class is what the
/// verdict gate in `binary_operation` closed.
///
/// Two things about those counts after the gate stopped being verdict-only. A clause that did not pass
/// can be noticed again where nothing reports it, so the classification above no longer covers every
/// emission -- but the contradiction stays closed by construction rather than by suppression, because
/// that case gets [`absorbed_incomparable_membership_notice`], which does not claim the clause passed.
/// And the 7 false alarms are a property of this predicate, not of the wording it feeds, so a false
/// alarm can now reach an unreported failing clause too. That widens the noise this section describes;
/// it does not add a new kind of it. Both bodies are worded to survive it: neither says the
/// incomparability *caused* the clause's answer, because on a failing clause it did not.
///
/// # Aligning it is the right fix, and must wait for the `[*]` bypass
///
/// **Do not flatten the left-hand side here while the `[*]` membership bypass is open**, however
/// obviously correct it looks. Measured on a tree with that change and nothing else: the suite stays
/// green at 2503 passed / 0 failed, all five aws-guard-rules-registry notices survive, the seven false
/// alarms go -- and `Pair NOT IN Deny13[*]`, with `{"Pair":[1,2],"Deny13":[1,3]}`, goes from exit 0
/// *with* the notice to exit 0 **silent**. That clause admits a value its denylist names. Element-wise
/// `1` and `1` are perfectly comparable, so the aligned predicate correctly reports nothing
/// undecidable, while the pass still comes from the suppressed error a layer down. No test in the suite
/// fails when that happens.
///
/// So this is a temporary constraint with a real cost, not a design position. Leaving the predicate
/// unaligned means shipping false alarms on compliant rules, which is a genuine harm -- it tells
/// authors to rewrite policy that works. It is accepted only because one true positive on a live
/// bypass at exit 0 is worth more than the noise, and only until the bypass closes.
///
/// What unblocks alignment: closing the bypass in `InOperation::compare`'s two-query `(None, None)`
/// arm, where the `element_collision` tracking around `operators.rs:1006` already fixed the unwrapped
/// `Pair NOT IN Deny13` spelling and the `[*]` spelling still reaches exit 0. Not the not-comparable
/// suppression in `contained_in` -- closing that leaves the clause at exit 0, measured.
///
/// Not established: that alignment is correct once the bypass closes. It is untested because that fix
/// did not exist when this was written. Re-measure `Pair NOT IN Deny13[*]` against whatever closes it,
/// and re-run the 132-cell classification, rather than assuming this note expires on its own.
fn incomparable_membership(lhs: &[QueryResult], rhs: &[QueryResult]) -> bool {
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
        return false;
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
        return false;
    }
    for value in &lhs_values {
        for element in &elements {
            if compare_eq(value, element).is_ok() {
                return false;
            }
        }
    }
    true
}

fn vacuous_comparison_notice(context: &str) -> String {
    format!(
        "DEPRECATION: {} passed without comparing anything, because the query selected an empty \
         collection. From the next release this reports a failure, matching a missing key and an empty \
         map. Guard the clause with `when <query> !empty {{ ... }}` if an empty collection is expected.",
        context
    )
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

/// The same notice for a clause that did *not* pass and that nothing in the report names.
///
/// A second wording rather than the one above, because the one above says the clause passed and this one
/// goes out where it did not. Printing "passed because ..." next to a failure is the defect that put the
/// verdict in this gate to begin with, and reaching the same sentence by a wider route would reinstate
/// it. Reached only as a [`ClauseRole::Gate`], so the file is not reporting this clause at all; see
/// `binary_operation` for why that is the line the suppression is drawn on.
///
/// Says nothing about *why* the clause failed, deliberately. The incomparability did not cause it: this
/// notice's premise is a whole-value comparison, while `contained_in` decides a list element by element,
/// and a clause that fails there fails on an element the denylist names or on one of the guards around
/// it. What is true, and all this claims, is that the clause holds an incomparable pair, that its answer
/// is not in the report, and that the read of such a pair is changing.
fn absorbed_incomparable_membership_notice(context: &str) -> String {
    format!(
        "DEPRECATION: {} did not pass, and it holds a value that could not be compared with any \
         element of the list -- a pair `NOT IN` currently reads as \"not a member\". Nothing in the \
         report says so: a `when` condition or filter predicate that fails skips what it guards, so \
         the file can still exit 0. A future release fails closed here, as `!=` already does. Compare \
         against values of the same kind, or use `!=` if that is the intent.",
        context
    )
}

/// Explanation attached to a clause whose left-hand variable resolved to no values.
///
/// Distinct from [`empty_reference_message`] only in which side it is about; both point at what binds
/// the name and both say what guarding the clause would actually do.
///
/// This is the message a capture that matched no entry produces, and the reason the old wording
/// mattered so much: it told the author to write `when %name !empty { ... }`, which skips the block, so
/// the reading that looks like "make the rule tolerate an empty selection" is "stop checking". The
/// clause is failing because nothing was compared, and the thing to change is the query or filter that
/// was supposed to bind the name.
fn empty_lhs_message() -> String {
    "The comparison could not be performed: the variable on the left-hand side resolved to no \
     values, so the clause fails. Look at what binds the variable -- a `let` or a filter capture \
     that selected nothing. `when <variable> !empty { ... }` skips the clause rather than \
     satisfying it."
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
    role: ClauseRole,
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

                        // A type that cannot be empty. Treated exactly as the non-variable path
                        // treats it, role split included: an assertion fails closed here, and a gate
                        // keeps the error so the enclosing condition fails its own rule closed
                        // rather than reading this as a condition that did not match.
                        Err(e) if is_unevaluatable(&e) => {
                            // The record is closed on both paths. `start_record` ran at the top of
                            // this loop, and returning without ending it leaves the recorder
                            // unbalanced -- `extract` then fails with "context start and end does
                            // not match" and takes the whole run with it. Caught by
                            // `an_unanswerable_clause_never_silences_the_rule_it_guards`, which
                            // exercises this arm as a gate; the strict path alone never returned
                            // early, so the imbalance arrived with this arm.
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Unary(UnaryValueCheck {
                                    comparison: cmp,
                                    value: ValueCheck {
                                        status: Status::FAIL,
                                        message: Some(e.to_string()),
                                        custom_message: custom_message.clone(),
                                        from: each.clone(),
                                    },
                                })),
                            )?;

                            // An assertion fails closed here; a gate keeps the error so the
                            // enclosing condition fails its own rule closed rather than reading this
                            // as a condition that did not match.
                            match role.is_strict() {
                                true => {
                                    results.push((each, Status::FAIL));
                                    continue;
                                }
                                false => return Err(e),
                            }
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
        match (*operation)(&each) {
            Ok(true) => {
                status.push((each, Status::PASS));
            }

            Ok(false) => {
                status.push((each, Status::FAIL));
            }

            // `EMPTY` against a type that cannot be empty. Returning this error unconditionally
            // aborted the whole rules file, discarding every other rule's verdict; one unanswerable
            // clause is a verdict about that clause, not about the file.
            //
            // An assertion is answered here, as a fail-closed per-value verdict. A *gate* cannot be,
            // and the reason is worth stating because the obvious fix is wrong: `eval_rule` collapses
            // both FAIL and SKIP on a condition to a rule-level SKIP, so neither status makes an
            // unevaluatable gate fail closed -- returning either one silently disarms the block it
            // guards and the file exits 0. `Status` has no third value to say "could not tell", so the
            // error is the channel, and the three condition sites catch it and fail their own rule or
            // block rather than letting it escape. #720's `Outcome` lattice replaces this with a value.
            Err(e) if is_unevaluatable(&e) => match role.is_strict() {
                true => status.push((each, Status::FAIL)),
                false => return Err(e),
            },

            Err(e) => return Err(e),
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

/// How several right-hand comparisons about ONE left-hand value fold into that value's verdict.
///
/// Membership and negated membership are not the same fold, and treating them as one is what made a
/// denylist of two or more elements select the keys it denies. `keys IN [a, b]` holds when the key
/// matches either, so one true answer settles it. `keys NOT IN [a, b]` holds only when the key
/// differs from both -- `Name` against `[Name, Zebra]` answers false then true, and taking either
/// one admitted a key that is verbatim in the list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum SameLhsFold {
    /// One comparison satisfies the clause. `IN`.
    AtLeastOne,
    /// Every comparison must. `NOT IN`, and the reason it is not the negation of `AtLeastOne`
    /// applied afterwards: `in_cmp` has already inverted each pair, so what is left to do is require
    /// all of them rather than any.
    All,
}

/// One verdict per left-hand value, folding that value's comparisons with `fold`.
///
/// Groups by left-hand value in a `HashMap` and iterates it, so the order statuses come out in is
/// not defined. That is not observable today because `real_binary_operation` calls this once per key
/// and each call therefore yields one status. Do not widen a caller to hand it several left-hand
/// values at once without sorting the groups first.
fn report_by_lhs<'r, 'value: 'r, 'loc: 'value>(
    rhs_comparisons: Vec<ComparisonResult>,
    fold: SameLhsFold,
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
        // A comparison satisfies the clause only when it was answerable AND came out true, so a
        // `NotComparable` or an unresolved right-hand side never counts as one. That is what keeps
        // `All` from passing on a pairing nothing could decide, the way `!=` already refuses to.
        let satisfies = |(r, _rhs): &(&ComparisonResult, QueryResult)| {
            matches!(
                r,
                ComparisonResult::Comparable(ComparisonWithRhs { outcome: true, .. })
            )
        };
        let satisfied = match fold {
            SameLhsFold::AtLeastOne => results.iter().any(satisfies),
            SameLhsFold::All => results.iter().all(satisfies),
        };
        match satisfied {
            true => {
                eval_context.start_record(&context)?;
                eval_context
                    .end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                statues.push((QueryResult::Resolved(Rc::clone(lhs)), Status::PASS))
            }
            false => {
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
    // Computed here and emitted at the bottom, because neither end of the comparison has both halves
    // of the condition.
    //
    // It has to be computed before, because the incomparability is not recoverable from the result:
    // the not-flag has already turned "no element matched" into a success by then, and a success from
    // an incomparable operand looks exactly like a real one. Only `NOT IN` reaches this, so the extra
    // comparisons cost nothing on any other clause.
    //
    // It has to be emitted after, because the verdict decides which notice this is. One of the two
    // wordings says the clause *passed* on the incomparability, and gated on the incomparability alone
    // it printed that beside a FAIL, which is the opposite of what happened. Measured across 231
    // `NOT IN` shapes: 177 reach the notice, 146 pass and 31 fail, and every one of the 31 printed the
    // passed wording.
    let membership_is_incomparable =
        cmp.1 && cmp.0 == CmpOperator::In && incomparable_membership(&lhs, rhs);
    let results = cmp.compare(&lhs, rhs)?;
    // Annotated, and bound before it is unwrapped. Every arm below is an `Ok(..)`, and the function's
    // return type used to pin their error type because the match was the tail expression. It is not
    // any more, and `?` erases the error type through `From`, so without the annotation the arms infer
    // nothing.
    let outcome: Result<EvaluationResult> = match results {
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
                            // The diff is compared against the operand it did *not* come from. Every
                            // element of it is filed below as `from`, and the message reads
                            // "property [from] was not present in [to]" -- so with the diff taken from
                            // the right-hand operand and `to` also the right-hand operand, the finding
                            // asserted that a value was absent from a set that visibly contained it.
                            // `==` between two queries can produce either side, so which one this is
                            // has to be read from the result rather than assumed.
                            let compared_with = match qin.diff_from {
                                operators::DiffFrom::Lhs => &qin.rhs,
                                operators::DiffFrom::Rhs => &qin.lhs,
                            };
                            let rhs = compared_with
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
    };
    let outcome = outcome?;

    // Which notice, or none: the verdict picks the wording, and the role decides whether a failure is
    // worth a notice at all.
    //
    // The question is not what the clause answered, it is whether the file reports that answer. A
    // notice on a clause the report already names as failing contradicts the line the author greps,
    // which is why the failing case was suppressed. But that suppression was justified with "a clause
    // with a failing value already exits the file 19", and that is only true of an assertion. A `when`
    // condition or a filter predicate that fails does not fail the file: `eval_conjunction_clauses`
    // counts the FAIL, `eval_rule` maps every non-PASS condition to SKIP, and the rule or the selection
    // it guards is dropped at exit 0. Measured on `Ports: [1, 2]`: `when Ports NOT IN [1, 3]` exits 0
    // with an empty stdout and an empty stderr, while the same clause asserted exits 19. So the one
    // shape the notice exists for -- a green file that quietly stopped checking -- was the shape it did
    // not reach.
    //
    // `ClauseRole` is exactly the right question to ask, and not by coincidence: it is threaded to every
    // leaf clause so that a clause whose failure would be absorbed carries `Gate`. That makes
    // "unreported" a property already in hand rather than one inferred here.
    //
    // The mixed clause decides the two directions apart, and it is reachable rather than hypothetical:
    // `Resources.*.Properties.Ports NOT IN [1, 3]` over `A: [1, 2]` and `B: [7, 8]` fails on one value
    // and passes on the other. Asserted, the report names it at exit 19 and the notice would land
    // beside a failure it contradicts. As a condition, nothing names it at all. Same clause, opposite
    // answers, and visibility is what separates them.
    //
    // Matched on the pair rather than short-circuited, so adding a role forces this decision to be made
    // for it instead of falling into whichever branch was written first.
    if membership_is_incomparable {
        match (clause_passed(&outcome), role) {
            (true, _) => eval_context.record_deprecation(incomparable_membership_notice(&context)),
            (false, ClauseRole::Gate) => {
                eval_context.record_deprecation(absorbed_incomparable_membership_notice(&context))
            }
            (false, ClauseRole::Assertion) => {}
        }
    }

    Ok(outcome)
}

/// True when the clause reached PASS on every value it decided.
///
/// The whole clause rather than any one value, because the notice this feeds makes a claim about the
/// clause -- "<clause> passed" -- and a clause with one failing value has not passed. So a mixed clause
/// is not a passing one here, and it gets the other wording or no notice at all depending on whether
/// anything reports it; `binary_operation` decides that and says why.
///
/// A mixed clause is reachable, and the sweep this predicate was written against did not reach one:
/// across 231 `NOT IN` shapes, the 177 that reach the notice each recorded either all PASS or all FAIL.
/// `Resources.*.Properties.Ports NOT IN [1, 3]` over `A: [1, 2]` and `B: [7, 8]` is one -- the
/// collision fails `A` and the incomparability passes `B` -- and
/// `the_incomparable_membership_notice_survives_a_failure_the_file_does_not_report` carries it in both
/// roles. What the sweep established is narrower than "no mixed clause exists": it is that none of
/// those 177 shapes was mixed.
///
/// An empty result is not a pass. Nothing decided means nothing passed, and a notice saying otherwise
/// would be the same defect with a different cause. Unreachable from the notice as things stand --
/// `incomparable_membership` answers false unless some left-hand value resolved, and a resolved value
/// produces a status -- so it is a guard against a future caller rather than a case in play.
fn clause_passed(result: &EvaluationResult) -> bool {
    match result {
        EvaluationResult::EmptyQueryResult(status, _) => *status == Status::PASS,
        EvaluationResult::QueryValueResult(values) => {
            !values.is_empty() && values.iter().all(|(_, status)| *status == Status::PASS)
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

    // One key per right-hand value, before anything counts them or compares against them.
    //
    // `resolve_variable` answers with the results a query produced, and one result can hold a list:
    // `let names = Cfg.KeyList` over `KeyList: [Name, Owner]` is a single `Resolved` naming two keys.
    // `widened_for` was handed `rhs.len()`, so that counted as one and `keys == %names` stayed strict
    // equality. `compare_eq` then refused every key-against-list pairing, the filter selected nothing,
    // and the clause SKIPped -- the run exited 0 with nothing in the report, while the same key names
    // spelled `%names[*]` widened to membership and failed at 19. Two spellings of one clause, and the
    // silent one was wrong.
    //
    // Flattened rather than counted. A count alone fixes the widening and leaves `each_lhs_compare`
    // below reading the unflattened `rhs` one line later, so "the right-hand values" would mean two
    // different things inside one function. `interpolated_keys` is the same one-level expansion the
    // variable-key path already does for the same reason, reused rather than written twice.
    let rhs = &interpolated_keys(rhs);

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
                    // Membership is satisfied by one match. Negated membership is not: a key is
                    // outside a set only if it differs from every element, so `NOT IN` folds with
                    // ALL. Both shared the one-match fold, which is why any denylist of two or more
                    // distinct elements selected the keys it denies -- `Name` against
                    // `[Name, Zebra]` answers false then true, and one true was enough. `NotEq`
                    // below already folds with ALL and is correct, so this brings the two negated
                    // comparators into line rather than inventing a rule for one of them.
                    MapKeyComparator::In | MapKeyComparator::NotIn => {
                        statues.extend(report_by_lhs(
                            r,
                            match cmp {
                                MapKeyComparator::NotIn => SameLhsFold::All,
                                _ => SameLhsFold::AtLeastOne,
                            },
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
            role,
        )
    } else {
        let (rhs, _) = match &gac.access_clause.compare_with {
            Some(val) => match val {
                LetValue::Value(rhs_val) => {
                    (vec![QueryResult::Literal(Rc::new(rhs_val.clone()))], true)
                }
                // The same treatment the clause's own query gets further down, for the same reason.
                //
                // Both arms recorded the clause as failing and then propagated the error regardless, so
                // an unevaluatable right-hand side aborted the run at 255 while the identical error on
                // the left exited 19. `%fine == %too_big` and `%too_big == %fine` disagreed about
                // whether a template that does not fit an i64 is a policy failure or a broken tool.
                //
                // Only for an assertion, and a gate still keeps the error, which is the split the
                // left-hand side and `eval_when_condition_block` already use.
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
                        return match (is_unevaluatable(&e), role.is_strict()) {
                            (true, true) => Ok(Status::FAIL),
                            _ => Err(e),
                        };
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
                        return match (is_unevaluatable(&e), role.is_strict()) {
                            (true, true) => Ok(Status::FAIL),
                            _ => Err(e),
                        };
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
        // Clause-level negation (a leading `not`/`!`, read by `parser::clause_with_map`) must be applied
        // here. The unary path takes it as an argument, but this path previously
        // dropped it entirely, so `not <query> == <value>` evaluated as plain
        // `== <value>` -- the exact inverse of the author's intent -- while the
        // report still displayed the `not`.
        //
        // `comparator.1` is the operator's own not-flag (from `!=` / `not in`).
        // The two negations compose by XOR, matching `invert_closure` in the
        // superseded evaluator, which applies `clause_not`
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
                        // `!all`, matching the other five sites that build this record in this
                        // function: the field records whether the block was satisfied by any one
                        // value rather than by all of them, so it is the negation of `all`. This
                        // arm alone had `all`. Nothing outside the tests reads the field today, so
                        // the disagreement was invisible; it would become a wrong branch the first
                        // time a reporter consumed it.
                        at_least_one_matches: !all,
                    }),
                )?;
                Ok(status)
            }
            EvaluationResult::QueryValueResult(result) => {
                // Taken before the fold below consumes the vector.
                let compared_nothing = result.is_empty();
                let outcome = loop {
                    let mut fails = 0;
                    let mut pass = 0;
                    let mut skips = 0;
                    for (_value, status) in result {
                        match status {
                            Status::PASS => {
                                pass += 1;
                            }
                            Status::FAIL => {
                                fails += 1;
                            }
                            // A value the clause could not answer at all, which today means an
                            // incompatible type met while evaluating a `when` condition. Only a gate
                            // produces it -- an assertion fails closed instead -- so this arm cannot
                            // change a verdict that existed before it: `unary_operation` pushed
                            // nothing but PASS and FAIL, which is why what it replaces was an
                            // `unreachable!()` rather than a case anyone had considered.
                            Status::SKIP => {
                                skips += 1;
                            }
                        }
                    }
                    // Nothing was decided either way. Saying so leaves the gate's remaining
                    // conditions free to decide it, where reporting FAIL would disarm the block they
                    // guard and reporting PASS would claim a condition held on the strength of a
                    // check that never ran. Guarded on `skips > 0` so an empty result set keeps
                    // whatever the two branches below already gave it.
                    if pass == 0 && fails == 0 && skips > 0 {
                        break Status::SKIP;
                    }
                    // A comparison that produced no per-value result at all, and is about to answer
                    // PASS on the strength of it. An empty *query* does not reach here -- that returns
                    // SKIP earlier -- so this is specifically a query that resolved to a collection
                    // which then expanded to nothing.
                    //
                    // Gated on the answer being PASS, not merely on the vector being empty: under
                    // `some` the same emptiness already answers FAIL, and that answer is not changing,
                    // so warning there would train the reader to ignore the notice.
                    if compared_nothing && all {
                        resolver.record_deprecation(vacuous_comparison_notice(&blk_context));
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

            // A clause whose own value could not be produced fails, and the rest of the file still
            // reports. Errors reach here from resolving the clause's query, which includes a `let`
            // whose function call could not convert its input: `let n = parse_int(Properties.Name)`
            // on a non-numeric name used to abort the run at exit 255 and discard every other rule's
            // verdict, including real violations an unrelated rule had already found. Same shape as
            // the incompatible-type abort fixed earlier on this branch, reached through a function
            // instead of an operator.
            //
            // Only for an assertion. A gate keeps the error so the enclosing condition site fails its
            // own rule closed rather than reading this as a condition that did not match, which is
            // the same split the per-value arm and `eval_when_condition_block` use.
            match (is_unevaluatable(&e), role.is_strict()) {
                (true, true) => Ok(Status::FAIL),
                _ => Err(e),
            }
        }
    }
}

/// Evaluates a reference to another rule by name.
///
/// A dependent rule that did not apply contributes nothing to the referencing rule's
/// verdict: the reference answers SKIP and `eval_conjunction_clauses` absorbs it, which
/// is what an inapplicable clause already does one level down. `role` changes that for
/// exactly one shape -- a negated `when` condition -- and the `Status::SKIP` arm below
/// says why.
pub(in crate::rules) fn eval_guard_named_clause<'value, 'loc: 'value>(
    gnc: &'value GuardNamedRuleClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
) -> Result<Status> {
    let context = format!("{}", gnc);
    resolver.start_record(&context)?;

    match resolver.rule_status(&gnc.dependent_rule, role) {
        Ok(status) => {
            let status = match status {
                Status::PASS => {
                    if gnc.negation {
                        Status::FAIL
                    } else {
                        Status::PASS
                    }
                }

                Status::FAIL => {
                    if gnc.negation {
                        Status::PASS
                    } else {
                        Status::FAIL
                    }
                }

                // A dependent rule that SKIPped never ran, so it is evidence in neither
                // direction and the reference contributes nothing. That is the answer an
                // inapplicable clause already gives one level down, and the answer that keeps
                // "not applicable" the identity it is in a conjunction rather than something a
                // rule can fail on.
                //
                // Both arms this replaces answered FAIL for an assertion, which manufactured a
                // violation out of an absence. Decomposing a ruleset over disjoint resource types
                // is the natural way to write one; each helper is guarded by a `when` on its own
                // type, so on any real template most helpers do not apply -- and the aggregate
                // failed once per inapplicable helper. `rule MAIN { H_A H_B }` against a clean
                // IAM role and no DynamoDB table exited 19 reporting "dependent rule [H_B] did
                // not PASS" for a template that violates nothing. Pinned by
                // `an_inapplicable_dependent_rule_does_not_fail_the_reference`.
                //
                // Negation does not change it. `not R` asks whether R does not hold; if R never
                // ran then "R holds" is neither true nor false, so neither is its negation. The
                // arm this replaces failed a negated assertion closed, reasoning that `not R`
                // must not report compliance for a check that never ran -- true, and a SKIP is
                // not compliance: the referencing rule reports SKIP, so the omission is visible.
                // FAIL went a step further and reported a violation instead, so
                // `rule deny when Resources.*.Type exists { not inner }` failed on a template
                // holding one S3 bucket and no KMS key. Same false positive, with a `not` in
                // front of it. Pinned by
                // `negated_reference_to_skipped_rule_does_not_pass_in_rule_body`.
                //
                // The single carve-out is a negated gate. `rule r when not other { ... }` is how
                // a ruleset says "apply this when that other rule did not apply", so the gate has
                // to open; answering SKIP there closes a gate that currently opens and silently
                // disables the guarded rule. A gate is not making a compliance claim, so it may
                // read "did not apply" as a condition that is met; an assertion is, so it may not.
                // Pinned by `negated_reference_to_skipped_rule_still_gates_a_when_condition` and
                // `cross_rule_clause_when_checks`.
                //
                // A non-negated gate takes the SKIP branch for its own reason:
                // `eval_conjunction_clauses` counts a FAIL and absorbs a SKIP, and answers FAIL
                // before PASS, so one inapplicable gate condition returning FAIL would outrank
                // the sibling conditions that passed and drop a body those siblings would have
                // enforced -- at exit 0, which is what `ClauseRole::Gate` exists to prevent.
                // Pinned by `a_named_rule_gate_on_a_skipped_rule_does_not_disarm_the_block`.
                Status::SKIP => match (role, gnc.negation) {
                    (ClauseRole::Gate, true) => Status::PASS,
                    _ => Status::SKIP,
                },
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
                //
                // The wording says "referenced" rather than "a condition referenced": this arm is
                // now reached from a rule body as well as from a `when`, and naming the wrong one
                // is worse than naming neither.
                Status::SKIP => {
                    resolver.end_record(
                        &context,
                        RecordType::GuardClauseBlockCheck(BlockCheck {
                            status: Status::SKIP,
                            at_least_one_matches: false,
                            message: Some(format!(
                                "the rule did not apply because it referenced rule [{}], which did not apply to this input",
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
            let unevaluatable = is_unevaluatable(&e);
            resolver.end_record(
                &context,
                RecordType::WhenCheck(BlockCheck {
                    status: Status::FAIL,
                    message: Some(match unevaluatable {
                        true => format!("The condition could not be evaluated, so the block it guards is not checked: {}", e),
                        false => format!("Error {} during type condition evaluation, bailing", e),
                    }),
                    at_least_one_matches: false,
                }),
            )?;
            // A condition that cannot be evaluated fails the block it guards rather than aborting
            // the file. Skipping it would disarm every check inside, which is the direction that
            // turns a violation into exit 0.
            //
            // Split by role, and the split is the whole fix. Answering FAIL is right for an
            // assertion: the block fails, the rule fails, and the rest of the file still reports.
            // It is wrong for a gate, because one level out a FAIL on a condition is
            // indistinguishable from a condition that was decided and did not match, and `eval_rule`
            // maps that to a rule-level SKIP. So
            //
            //     rule inner_gate(unused) {
            //         when Resources.Vol.Properties.Enabled !EMPTY { ... }
            //     }
            //     rule guarded when inner_gate("x") { Encrypted == true }
            //
            // exited 0 with the `Encrypted` violation unreported, where the merge-base exited 19.
            // Reported by a reviewer, and the diagnosis was exact: converting the undecidable answer
            // to a status here loses the information the outer rule needs to fail closed. Keeping
            // the error for a gate carries it to the enclosing condition site, which fails its own
            // rule closed instead of deciding the rule does not apply.
            //
            // `an_undecidable_nested_gate_does_not_silence_the_outer_rule` is the regression test,
            // and it asserts the reported violation rather than only the exit code, because the
            // merge-base and the fix agree on 19 and disagree on what they say.
            return match (unevaluatable, role.is_strict()) {
                // A gate: keep the error, so the enclosing condition site fails its own rule closed
                // rather than reading this as a condition that did not match.
                (true, false) => Err(e),
                // An assertion: the block fails and every other rule in the file still reports.
                (true, true) => Ok(Status::FAIL),
                (false, _) => Err(e),
            };
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
    /// Retrieved with this scope as the resolver rather than the parent's, or the arguments the call
    /// site passed are invisible to the query.
    ///
    /// `RootScope::query` and `BlockScope::query` both pass themselves; this one delegated, which put
    /// the parent in charge of resolving `%name` and the parent does not hold the parameters. It was
    /// unreachable while a parameterized rule could not carry a `when`, because `eval_rule` is the only
    /// caller that queries this scope directly -- for a rule's conditions -- and everything else it
    /// does goes through `eval_general_block_clause`, which interposes a `BlockScope` that passes
    /// itself and therefore reaches `resolve_variable` below. That is why a `%parameter` in the *body*
    /// has always worked.
    ///
    /// Measured rather than argued: with a `panic!` in place of the delegation, 1495 tests and 318
    /// rules files across this repository and the AWS rule registry reached it zero times.
    ///
    /// So the rule-level `when` is the one path that queries this scope, and
    /// `rule r(t) when %t == "x" { ... }` reported `Could not resolve variable by name t across
    /// scopes` until this stopped delegating.
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        let root = self.root();
        query_retrieval(0, query, root, self)
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

    fn rule_status(&mut self, rule_name: &'value str, role: ClauseRole) -> Result<Status> {
        self.parent.rule_status(rule_name, role)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        match self.resolved_parameters.get(variable_name) {
            Some(res) => Ok(res.clone()),
            None => self.parent.resolve_variable(variable_name),
        }
    }

    /// An argument the call site passed is the same binding whichever depth of block reads it, so this
    /// answers as `resolve_variable` does and only the onward deferral differs.
    ///
    /// Answering here is what makes the parameter half of the shadowing fix work: a block inside the
    /// rule declaring a capture of the parameter's name used to end the lookup before it reached this
    /// scope, so the argument the call site passed was unreadable for that whole block.
    fn resolve_variable_from_nested_block(
        &mut self,
        variable_name: &'value str,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        match self.resolved_parameters.get(variable_name) {
            Some(res) => Ok(res.clone()),
            None => self
                .parent
                .resolve_variable_from_nested_block(variable_name, unbound),
        }
    }

    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.parent.add_variable_capture_key(variable_name, key)
    }

    fn add_merged_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.parent.add_merged_capture_key(variable_name, key)
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

    // An invariant check rather than the diagnostic for the mistake. `rules_file` compares every call
    // site against the definition it names and rejects the file at exit 5, so a parsed file cannot
    // reach here with the counts unequal; the check stays because the indexing below would otherwise
    // panic, and because a `RulesFile` assembled some other way has no parser to have checked it.
    //
    // Reaching this therefore means cfn-guard let through a file it said it had validated, and the
    // message says so: `Err` from a command propagates to `main`, which exits -1, and -1 --
    // `INTERNAL_FAILURE` in `guard/tests/utils.rs` -- is the right code for a broken invariant. It was
    // the wrong code while this was the *only* check, because then it was reporting an ordinary
    // authoring mistake, and an unknown rule name on this same code path exited 5.
    if param_rule.parameter_names.len() != call_rule.parameters.len() {
        return Err(Error::IncompatibleError(format!(
            "Arity mismatch for called parameter rule {}, expected {}, got {}. The rules file was \
             accepted with a call this malformed, which is a defect in cfn-guard rather than in the \
             file.",
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
    // Mirrors eval_guard_named_clause arm for arm, and the mirroring is the property: the two
    // spellings of one reference must not disagree, and they have already drifted apart once
    // (see `a_named_rule_gate_on_a_skipped_rule_does_not_disarm_the_block`). Read the SKIP arm
    // in that function for the reasoning; only the differences are noted here.
    Ok(match status {
        Status::PASS => {
            if call_rule.named_rule.negation {
                Status::FAIL
            } else {
                Status::PASS
            }
        }

        Status::FAIL => {
            if call_rule.named_rule.negation {
                Status::PASS
            } else {
                Status::FAIL
            }
        }

        // An invoked rule that did not apply contributes nothing, in both polarities, except for
        // a negated gate -- `when not r(...)` opens when `r` did not apply, same idiom as the
        // unparameterized spelling.
        //
        // The arm this replaces failed an assertion call closed, and its comment said so
        // deliberately: "main returned the invoked rule's SKIP and exited 0, this returns FAIL
        // and exits 19". That was the same false positive the plain spelling had, reached through
        // `r(...)`: `rule MAIN { H_A skipper(1) }` on a template with a clean IAM role and no
        // DynamoDB table exited 19 with nothing violated. Pinned alongside the plain spelling by
        // `an_inapplicable_dependent_rule_does_not_fail_the_reference`, which asserts both so a
        // future change to one of them cannot pass on a single-spelling test.
        Status::SKIP => match (role, call_rule.named_rule.negation) {
            (ClauseRole::Gate, true) => Status::PASS,
            _ => Status::SKIP,
        },
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
                        Ok(status) => {
                            val_resolver
                                .end_record(&when_context, RecordType::TypeCondition(status))?;
                            if status != Status::PASS {
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
                        Err(e) if is_unevaluatable(&e) => {
                            val_resolver.end_record(
                                &when_context,
                                RecordType::TypeCondition(Status::FAIL),
                            )?;
                            val_resolver
                                .end_record(&block_context, RecordType::TypeBlock(Status::FAIL))?;

                            // Split by role, like the other two condition sites. Counting this as a
                            // failure is right for an assertion; for a gate it makes the type block
                            // FAIL, and one level out a FAIL on a condition is a condition that was
                            // decided and did not match, which `eval_rule` maps to a rule-level SKIP.
                            // So an undecidable type-block condition behind a gate dropped the rule it
                            // guarded at exit 0:
                            //
                            //     rule inner_gate(unused) {
                            //         AWS::EC2::Volume when Properties.Encrypted !EMPTY {
                            //             Properties.Size > 10
                            //         }
                            //     }
                            //     rule guarded when inner_gate("x") { Vol.Properties.Size == 100 }
                            //
                            // exited 0 against `Size: 5` with the violation unreported. Keeping the
                            // error for a gate carries it to the enclosing condition, which fails its
                            // own rule closed.
                            if !role.is_strict() {
                                // The type block's own record has to be closed before returning, or
                                // `extract` fails with "context start and end does not match" and
                                // takes the run down at exit 255 instead of reporting anything. Same
                                // trap as the lone-variable arm in `unary_operation`: `start_record`
                                // ran above, and an early return has to end it.
                                val_resolver.end_record(
                                    &context,
                                    RecordType::TypeCheck(TypeBlockCheck {
                                        type_name: &type_block.type_name,
                                        block: BlockCheck {
                                            status: Status::FAIL,
                                            // No message. Measured: the enclosing rule's own
                                            // explanation is what reaches the console for this shape,
                                            // naming the operation and the path, and nothing on this
                                            // record is rendered. A sentence here would be recorded
                                            // and discarded, which is what
                                            // `every_recorded_explanation_has_a_rendering_path`
                                            // exists to refuse -- it caught this one.
                                            message: None,
                                            at_least_one_matches: false,
                                        },
                                    }),
                                )?;
                                return Err(e);
                            }
                            fails += 1;
                            continue;
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
                        message: match is_unevaluatable(&e) {
                            true => Some(format!(
                                "The rule's condition could not be evaluated, so the rule fails \
                                 rather than being treated as not applicable: {}",
                                e
                            )),
                            false => None,
                        },
                    }),
                )?;
                // The rule fails closed. Returning SKIP -- which is what every *status* on a condition
                // collapses to a few lines above -- would leave the body unevaluated and the file at
                // exit 0, so an unevaluatable condition cannot be expressed as a status here.
                //
                // Split by role for the same reason as the other two condition sites. FAIL is right
                // when this rule is the assertion; when the rule is itself a gate, that FAIL becomes
                // a condition that was decided and did not match one level out, and the rule it gates
                // is dropped. Three spellings of one condition disagreed until this split:
                //
                //     rule guarded when Enabled !EMPTY { ... }              inline    FAIL
                //     rule inner { when Enabled !EMPTY { ... } } + gate     block     FAIL
                //     rule inner when Enabled !EMPTY { ... }    + gate      rule      SKIP
                //
                // and the third also misattributed itself, reporting that the referenced rule "did not
                // apply to this input" for a rule whose condition could not be evaluated at all.
                return match (is_unevaluatable(&e), role.is_strict()) {
                    (true, true) => Ok(Status::FAIL),
                    _ => Err(e),
                };
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
            Ok(status) => match status {
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
            // Held rather than returned. A disjunct with no answer must not stop a later disjunct
            // that has one -- see the `Err` arm below and the check after the loop.
            let mut undecided: Option<Error> = None;
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

                    // An `or` is decided by whichever disjunct can decide it. Returning here
                    // instead meant the first disjunct with no answer ended the whole disjunction,
                    // so `A or B` and `B or A` were not the same clause: with `A` undecidable and
                    // `B` true, the second spelling opened its gate and evaluated the body, and the
                    // first reported that the condition could not be evaluated and dropped the body.
                    // Both exited 19 on a failing document -- the rule fails either way -- so the
                    // exit code hid it, and only the reported reason differed.
                    //
                    // So the error waits until every disjunct has had its turn. If a later one
                    // passes, the `continue 'conjunction` above leaves this behind, which is what
                    // "undecidable or true is true" means. If none does, it is returned below and
                    // the caller decides: an assertion fails closed, a gate keeps the error and
                    // fails its own rule closed. Only the first is kept, because that is the one
                    // whose path the reporter names, and reporting one reason is what the console
                    // does for a clause anyway.
                    Err(e) => {
                        if undecided.is_none() {
                            undecided = Some(e);
                        }
                    }
                }
            }

            if let Some(e) = undecided {
                if multiple_ors_present {
                    resolver.end_record(
                        &context,
                        RecordType::Disjunction(BlockCheck {
                            message: Some(format!(
                                "Disjunction could not be decided: no disjunct answered, and one \
                                 could not be evaluated: {}",
                                e
                            )),
                            status: Status::FAIL,
                            at_least_one_matches: true,
                        }),
                    )?;
                }
                return Err(e);
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
