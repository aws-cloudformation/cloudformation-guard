use super::exprs::*;
use super::*;
use crate::rules::eval::operators::{Comparator, InOperation};
use crate::rules::eval_context::{
    bare_variable_root, block_scope, capture_scope, clause_as_written, function_result_alias_root,
    interpolated_keys, is_refusal, keys_of_projection, let_value_as_written, names_the_population,
    query_retrieval, query_retrieval_shaped, refuse, resolve_function_with_shape, without_entries,
    without_unresolved, Asked, BindingId, BindingStep, CaptureFrames, CaptureHome, EmptySelection,
    EntryCaptures, FunctionChain, FunctionEntries, PassedOn, ProjectionKeys, QueryStart,
    RhsEnumeration, ValueScope,
};
use crate::rules::path_value::Path;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Map key filters, decided in one place for the evaluator and the legacy resolver alike. The legacy
/// resolver in `path_value.rs` reaches it as `crate::rules::eval::key_filter`.
pub(crate) mod key_filter;
mod operators;

/// The entry sets of an enumerating `IN` right-hand side, re-exported for the `EvalContext` cache
/// (`entry_candidates`) that hands them to `binary_operation` once per distinct right-hand side.
pub(crate) use operators::EntryCandidates;

/// The error a unary operator raises for a value whose selection could not be decided, and `None` for
/// every other value.
///
/// A key filter whose right-hand side did not resolve, or whose comparison the engine could not finish,
/// leaves the map it ran over marked `UnResolvedKind::Undecidable` with the reason, so that the query
/// goes on to its other maps and they are reported. Read as the ordinary unresolved marker, that would
/// be "absent": `exists` false, `!exists` and `empty` true, so `Map[ keys == %exempt ] !exists` over a
/// map whose exemption list the document lacks would pass. It is not absent; nobody knows what the
/// filter selects there. So every unary operator asks this first and raises `UndecidableComparison`,
/// which the clause reads as unevaluatable: an assertion fails closed for that value, in either
/// polarity, and goes on to the next value; a gate hands the error up and fails its rule closed. The
/// binary operators read the same marker in `binary_operation`'s unresolved arms, as undecided rather
/// than as the decided absence an ordinary unresolved value is, so a `when` gate over `Map[ keys ==
/// %exempt ].Enabled == true` fails closed too instead of reporting not applicable; and
/// `resolved_only_under_some` keeps the marker, so a `some` binding over such a filter is not read as
/// empty. Inside a filter predicate the marker is read the same way, whether the key filter is evaluated
/// there or bound outside and read through a `let` (`let cfg = Resources.Cfg[ keys NOT IN %missing ]`,
/// then `Resources.*[ %cfg exists ]`): the predicate's clause raises on it, no entry is selected or
/// deselected on a selection nobody could decide, and the enclosing clause fails closed with the
/// filter's reason, in either polarity (measured: the rule reads FAIL at the validation failure code,
/// the reason under "Could not be evaluated", the run goes on to the other rules). The raise is that
/// one entry's answer: the filter loops answer the entry with the same marker
/// (`eval_context::to_undecidable_result`) and go on, so its siblings are tested and reported and
/// every undecidable entry is named, where the raise handed up as an error ended the whole selection
/// at the first such entry and named it alone. The key-filter arm does not
/// downgrade the marker to an ordinary absence inside a predicate, the reading a scalar met under a
/// key takes there: that downgrade would make a positive predicate (`!empty`, `exists`) deselect every
/// entry, so `Resources.*[ Tags[ keys NOT IN %allowed ] !empty ] empty` would pass at exit 0 with the
/// allowlist missing while the predicate-free spelling fails closed, and would make a negated predicate
/// (`empty`, `!exists`) hold and select every entry. A scalar met under a key keeps its reading inside a
/// predicate; a key filter nobody can decide does not. A capture refused inside a predicate leaves the
/// same marker for the entry under test (`eval_context::to_undecidable_result`; a wildcard filter's
/// refusal leaves it with `refused` set, `eval_context::to_refusal_result`, and a capture can hold that
/// one after the walk that met it was refused, so a `%x` compared anywhere may hold it: under `==`, `!=`
/// and the orderings the `refused` marker takes the pre-pass over a comparison's right-hand values,
/// `refused_read_reason`, and the other two are read pair by pair; under `IN` and `NOT IN`, and for `==`
/// between two value sets, every kind takes it, `undecidable_reason`) and is read the same
/// way: the enclosing clause fails closed whatever the operator, with the reason naming the capture, the
/// entry neither selected nor deselected, unless a sibling settles the clause: the marker is one
/// entry's answer, so under `some` a sibling entry that passes decides the clause past it, and in a
/// `when` gate a sibling that is a decided failure settles the gate (`undecided_gate`), the undecided
/// entry named in the report and, for a capture, on the warning channel.
fn undecidable_selection(value: &QueryResult) -> Option<Error> {
    match value {
        QueryResult::UnResolved(unresolved) => {
            undecidable_reason(unresolved).map(Error::UndecidableComparison)
        }
        QueryResult::Literal(_) | QueryResult::Resolved(_) => None,
    }
}

/// The reason an unresolved result cannot be decided, when it is the undecidable marker
/// (`UnResolvedKind::Undecidable`: a key filter's for a map it could not decide, or a refusal's delivered
/// inside a predicate, `refused` set, read alike here): the reason the filter recorded, or the path when
/// it recorded none. `None` for every other kind, which is a value the document lacks or an enumeration
/// over an empty collection, both decided.
///
/// The one place the marker's kind is read: for the unary operators through `undecidable_selection`,
/// for `binary_operation`'s two unresolved arms directly, for the block clause's unresolved arm, and
/// for the function dispatch through `eval_context::undecidable_argument_reason`. Those arms branch
/// on the kind directly, with no clone and no wildcard. Cloning the whole `UnResolved` (an `Rc` and
/// two `String`s) into a fresh `QueryResult` to ask `undecidable_selection`, and then matching
/// `Some(Error::UndecidableComparison(reason))` against a catch-all, would read every other answer as
/// a DECIDED failure. Such a catch-all could not fire on anything but `None` today, since this is the
/// only error the helper builds, but a second variant added there one day would be read as decided,
/// and a decided failure on a gate is "not applicable" at exit 0. Branching on the kind leaves no such
/// arm.
pub(crate) fn undecidable_reason(unresolved: &UnResolved) -> Option<String> {
    match unresolved.kind {
        UnResolvedKind::Undecidable { .. } => {
            Some(unresolved.reason.clone().unwrap_or_else(|| {
                format!(
                    "the selection at {} could not be decided",
                    unresolved.traversed_to.self_path()
                )
            }))
        }
        UnResolvedKind::Absent | UnResolvedKind::EmptyEnumeration => None,
    }
}

/// The reason a refusal carries when `unresolved` is its marker (`UnResolvedKind::is_refusal`: the
/// `refused` flag `LacksKeysNote::marker_with` and `to_refusal_result` set), whether the marker was
/// delivered inside a filter predicate or held in a capture by the enumeration whose walk was refused
/// (`enumerate_under_an_own_key_filter`, `captures_after_a_refused_walk`) and read through `%x` wherever
/// that name is compared, an assertion included; `None` for every other result, the marker a key filter
/// leaves and a capture refused inside a predicate (`to_undecidable_result`, `refused` unset) included:
/// under `==`, `!=` and the orderings those are read pair by pair by the `RhsUnresolved` arm of
/// `binary_operation`, and the pre-pass over the right-hand side there is for the refusal alone, whose
/// bare read never reached a pair. Membership (`IN`, `NOT IN`) and `==` between two value sets read both
/// kinds alike (`undecidable_reason`): there the question is whether an unknown value may hold the
/// match, and the kind of unknown does not change the answer.
pub(crate) fn refused_read_reason(unresolved: &UnResolved) -> Option<String> {
    if unresolved.kind.is_refusal() {
        undecidable_reason(unresolved)
    } else {
        None
    }
}

/// True for a pair under a POSITIVE `IN` whose right-hand value is an undecidable marker of either kind
/// (`undecidable_reason`: a refusal's marker, or the marker a key filter leaves for a map it could not
/// decide): the one per-value result `binary_operation` files neither a status nor a record for
/// (`value_statuses` maps it to no status; the `RhsUnresolved` arm writes no record), because membership
/// is decided by any one listed value, so the marker's pair says nothing about a value a listed entry
/// matched, and a failing status or record for it read a clause that passed as one with a failing value.
/// Either kind, because `Y IN {x, ?}` with `Y` equal to the resolved `x` is a YES whichever kind of
/// unknown `?` is; read for the refusal's marker alone, the same clause failed closed under the key
/// filter's marker where it passed under the refusal's. `NOT IN` is NOT read here (the whole comparator
/// is tested, flag included): under it the marker's pair keeps its FAIL status, which denies a pass under
/// `match_all` in every role and fails a `match_all` clause that reaches the comparison as an assertion
/// (a marker held by a capture), as every other comparator's marker pair does; the pre-pass over the
/// marker judges the resolved pairs beside it (`passes_are_unknown`, `every_value_decided_no`), and
/// `undecided_gate` raises on a `some` assertion whose passes are unknown, the one assertion its statuses
/// alone would pass.
fn marker_pair_under_in(cmp: (CmpOperator, bool), result: &operators::ValueEvalResult) -> bool {
    cmp == (CmpOperator::In, false)
        && matches!(
            result,
            operators::ValueEvalResult::ComparisonResult(
                operators::ComparisonResult::RhsUnresolved(urhs, _)
            ) if undecidable_reason(urhs).is_some()
        )
}

fn exists_operation(value: &QueryResult) -> Result<bool> {
    if let Some(undecidable) = undecidable_selection(value) {
        return Err(undecidable);
    }
    Ok(match value {
        QueryResult::Resolved(_) | QueryResult::Literal(_) => true,
        QueryResult::UnResolved(_) => false,
    })
}

fn element_empty_operation(value: &QueryResult) -> Result<bool> {
    if let Some(undecidable) = undecidable_selection(value) {
        return Err(undecidable);
    }
    // Kept for the incompatible-type arm below, which classifies its error by whether the value came
    // from the template or was written in the rules file; the arm's own `value` is the inner value.
    let provenance = value;
    let result = match value {
        QueryResult::Literal(value) | QueryResult::Resolved(value) => match &**value {
            PathAwareValue::List((_, list)) => list.is_empty(),
            PathAwareValue::Map((_, map)) => map.is_empty(),
            PathAwareValue::String((_, string)) => string.is_empty(),
            // A null is empty. It is the value a key holds when it holds nothing, which is the
            // reading `exists` already takes (a resolved null is present) and the one the
            // filter-ending `EMPTY` shortcut already takes through `is_null`. Without this arm a null
            // fell through to the incompatible-type error below, so `N EMPTY` and `N !EMPTY` both
            // failed with "Attempting EMPTY operation on type null" and neither polarity could be
            // asked, while `N exists` passed on the same value. A number or a boolean still cannot
            // be empty; this arm is specific to null.
            PathAwareValue::Null(_) => true,
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
                return Err(Error::unanswerable(
                    provenance,
                    format!(
                        "Attempting EMPTY operation on type {} that does not support it at {}",
                        value.type_info(),
                        value.self_path()
                    ),
                ))
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
/// The by-value question is not answered by `is_null`, which reports an empty list and an empty
/// string as non-empty and cannot fail at all on a number or a boolean.
fn empty_of(value: &QueryResult, by_value: bool) -> Result<bool> {
    if let Some(undecidable) = undecidable_selection(value) {
        return Err(undecidable);
    }
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
            if let Some(undecidable) = undecidable_selection(value) {
                return Err(undecidable);
            }
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
            refusal: false,
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
                check.refusal = is_refusal(&e);
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
/// Points at what binds the reference, which is where the fault is, and says that `when
/// <reference> !empty { ... }` is not a remedy: the gate's own `!empty` check fails when the
/// reference is empty, so the block is skipped and the comparison never runs. An author following
/// that advice turns a check that is failing for a reason into a check that does not run, at exit 0,
/// which is the outcome this message exists to prevent. Saying so is worth the extra sentence, because
/// the released message carried that advice for two releases.
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

/// True when some pair the membership comparison builds cannot be compared at all.
///
/// The pairs are the ones `contained_in` builds, at every granularity it decides at, asked per pair of
/// operand VALUES rather than over one flattened cross product. Three cases and each arm below names its
/// own: two lists are decided element by element, and also whole-list against each entry when the denylist
/// holds a list; a list against anything else is refused on the SHAPES with no comparison performed at
/// all; and a value that does not decompose is compared as itself. One refusal is enough and an answered
/// pair cancels nothing: a clause that matched nothing passed on every pair it built, so a pair it could
/// not decide is part of what its answer rests on.
///
/// Flattening both operands one level and taking the cross product was the previous shape, and it reaches
/// the element pairs correctly. What it cannot reach is the other two: a flattened pair set has no whole
/// value left in it to carry the second granularity, and a refusal that never calls `compare_eq` leaves no
/// result for a predicate built on `compare_eq` answers to read. Both were measured as missing rather than
/// argued -- see the grid below.
///
/// `RegexError` is not a refusal here -- see the arm below, which says why an exhausted backtracking budget
/// is a comparable pair the engine gave up on.
///
/// Half of the condition, not all of it. True here means the clause's answer *could* have come from the
/// incomparability, and the caller still has to read the verdict, because only a clause that passed on
/// such a pair is one the coming fail-closed release moves. See `binary_operation`.
///
/// # The two questions a flattened cross product answers wrong
///
/// Fault (a), granularity. It decided on the comparability of the **whole left-hand value** against each
/// flattened right-hand element, while `is_one_of` and `contained_in` decide a list-valued left-hand side
/// by comparing its elements. The consequence was not academic: it emitted a DEPRECATION on ordinary,
/// well-typed, compliant denylist checks, telling the author a passing rule would fail closed in a future
/// release when it will not.
///
/// ```text
/// Actions: ["s3:GetObject", "s3:PutObject"]
/// rule r { Actions NOT IN ["s3:DeleteBucket", "s3:PutBucketPolicy"] }   # exit 0 + DEPRECATION
/// ```
///
/// Every pair the operator compared there is string against string, all answerable, nothing suppressed.
/// The discriminator that made the diagnosis certain rather than plausible was one variable:
/// `Strs NOT IN ["x","y"]` emitted and `Strs NOT IN ["x","y",["p"]]` did not, both passing, element-wise
/// facts identical. Adding an irrelevant nested list flipped `compare_eq(whole_lhs_list, element)` from
/// `Err` to `Ok`, because of which arm each pair lands on. `compare_eq` answers `(List, List)` itself, and
/// for that pair the length decides: a two-element `Strs` against the one-element `["p"]` mismatches, so
/// the arm returns `Ok(false)` without looking at an element. It is not always `Ok` -- on EQUAL lengths it
/// zips and propagates with `?`, so an element that refuses refuses for the whole pair, and
/// `two_equal_length_lists_propagate_what_their_elements_raise` in `path_value_tests.rs` pins both exits.
/// `compare_eq` has no `(List, String)` arm at all, so that pair falls through its `(_, _)` arm into
/// `compare_values`, whose own catch-all refuses with `NotComparable`. So the trigger was decided by the
/// *kind* of an unrelated denylist element rather than by anything about the comparison the clause
/// performed. Under the element-wise reading the same pair of clauses inverts, and both answers are now
/// about pairs the operator built: `["p"]` is an element every element of `Strs` is compared against and
/// cannot be compared with, and `"x"` and `"y"` are elements it compares fine.
///
/// Fault (b), the early return. The loop answered false on the first pair `compare_eq` answered, which
/// decided the whole cross product on one pair's evidence. `Str NOT IN Haystack` over `["zzz", 7, false]`
/// stayed silent because `"a"` and `"zzz"` are comparable, though `"a"` against `7` is exactly the pair a
/// fail-closed release will refuse. The defense of that return -- "a mixed list that contains anything
/// of the right kind is left alone" -- is a statement about which pair is convenient to stop at, not about
/// what the clause's answer rested on.
///
/// # The two faults are one fix, measured rather than argued
///
/// Fixing (a) alone makes the predicate worse. The element-wise pairs it exposes are walked in the order
/// the denylist is written, so an answered pair anywhere ahead of a refusing one hits (b) and discards a
/// refusal that had already been seen. Over 132 clause shapes, classified against an oracle taken from
/// `compare_eq`'s own answers over the pairs the OPERATOR built -- recorded by instrumenting `compare_eq`
/// with this predicate's own calls suppressed, so the measurement cannot confirm itself:
///
/// ```text
///                        true positives   false alarms   beside a FAIL   false negatives   agreeing
/// before                             72              4               0                17         39
/// alignment alone                    69              0               0                20         43
/// alignment + no early return        88              0               0                 1         43
/// ```
///
/// Eleven true positives went with the four false alarms under alignment alone, which is why the two
/// arrived together. The 132-shape grid is a reconstruction: it is twelve left-hand shapes against eleven
/// right-hand ones over one document, chosen to cover both fault classes and the discriminator above, and
/// it is not the enumeration the earlier 73/7/0/10/42 figures came from -- that one was never committed, so
/// its counts and these are not comparable cell for cell. What is comparable is the before-and-after on one
/// grid, which is the row pair above.
///
/// # The alignment took thirteen owed notices with it, and this is the count
///
/// **Corrected on 2026-09-03, and it is a correction of a number rather than a disagreement about a
/// reading.** The paragraph here said the one remaining false negative was `EmptyList NOT IN Str`, and that
/// it was the only cell whose notice the alignment took away rather than corrected. Wrong by twelve. The
/// oracle above is `compare_eq`'s own answers over the pairs the operator built, which is the very thing
/// the alignment changed, so it could not see a pair the operator builds and the predicate does not.
///
/// Re-measured against an oracle that does not depend on this predicate at all: a release binary built with
/// the four `NotComparable` suppressions promoted the way `RegexError` already is -- `is_one_of`,
/// `contained_in`'s whole-list loop, `contained_in`'s scalar loop, and the `(None, None)` arm's dropped
/// result -- and the notice taken as owed exactly where the clause PASSES today and answers differently
/// under that binary. That is the notice's own sentence, "a future release fails closed here", read off the
/// language. Over 1080 clause shapes, eighteen left-hand values against thirty right-hand spellings in both
/// polarities over one document.
///
/// **Those are four sites as the table counts them and THREE in the code:** `contained_in`'s whole-list
/// loop is a call to `is_one_of`, so the first two are one site; the
/// oracle binary cannot be rebuilt with them promoted independently. `operators.rs`'s own price table
/// carries the same correction and the measurement behind it.
///
/// ```text
///                              true positives   false alarms   beside a non-PASS   false negatives   agreeing
/// before the alignment                    289             16                   0                81        694
/// the alignment                           355              0                   0                15        710
/// both granularities and the shape        370              0                   0                 0        710
/// ```
///
/// Measured against the oracle described above; the empty-left-hand skip leaves four `[]`-against-a-string
/// cells owing no notice. That is the whole caveat on the third row, and it is bounded rather than vague: the empty-left-hand skip
/// is the only change since the oracle's base that removes a path into the four promoted sites, and it
/// is gated on the left-hand VALUE being a zero-element `List` and the right-hand RESULT being a
/// `String`, so the affected set is exactly {left resolving to `[]`} x {right resolving to a String} x {both
/// polarities}. Of those, only the `NOT IN` half was ever owed: the `IN` half FAILs, so `clause_passed`
/// suppresses the notice and nothing is owed there.
///
/// `EmptyOuter`, spelled `[[]]`, is NOT in that set and its two rows stand. It is a ONE-element list, so
/// `elements.is_empty()` is false and the skip never fires; the 120-cell sweep names `[]` and `[[]]` as two
/// left-hand shapes and only the first is affected. Do not read the caveat as covering both.
///
/// **Like the 132-shape grid above, this one is not reproducible from the tree.** Its clause list -- the
/// eighteen left-hand values and thirty right-hand spellings -- was never committed, so the other rows cannot
/// be re-derived or falsified from a checkout, and no figure in them should be restated as a property of
/// this tree. The 94-clause sweep in `eval_tests.rs` and the 140-clause grid in `operators.rs` both carry
/// this admission; this table did not, which is how the third row's zeros came to read as current. If the
/// question comes up again, commit the clause list.
///
/// **The third row's `0` false alarms was a property of those 1080 shapes and not of the predicate, and a
/// hand-built clause outside the population refuted it.** `some Iso[*] NOT IN [["a"], [1]]` over an `Iso`
/// of `[[[1]], [[9,9],[8,8]]]` passed and emitted the notice, and answers PASS under the promoted oracle
/// too -- the matched element's discarded refusal cannot move a verdict, because `Matched` outranks
/// `Unanswerable` inside `is_one_of`. So it was a false alarm by this table's own definition, at all
/// three `membership_pairing_refused` granularities, closed by withholding the flag on the `Matched`
/// exits and pinned by `a_refusal_seen_before_a_match_earns_no_notice`. A grid explores the space its
/// author imagined; the shape it missed is a denylist whose incomparable entry precedes its matching one.
///
/// One further reason a row here may have moved, recorded rather than resolved: the `[ keys <op> ... ]`
/// path exits 19 where it exited 255. Any such clause in the uncommitted list moved for that reason and
/// not for anything about the notice. The grid is described as membership spellings, so none is expected --
/// but that is an expectation about a list nobody can read, so the staleness should not be attributed to a
/// single cause.
///
/// So the alignment removed 29 notices: the 16 false alarms, which is the win, and 13 that were owed. The
/// 13 are what "wrong by twelve" counts. The 15 false negatives are the 13 plus two that were never emitted
/// in either release -- `EmptyOuter NOT IN [[2], [7, 8]]` and `Nest NOT IN [[2], [7, 8]]`, whose whole-value
/// pair the old predicate did build and did get an answer for, because two lists of equal length zip.
///
/// Of the 15, seven are the second granularity and eight are the shape refusal. Attributed by measurement
/// rather than by reading: a build carrying each half alone notices its own seven or eight, neither notices
/// the other's, and no cell needed both. The smallest of each is worth carrying, because neither is exotic.
/// The granularity one is an `EmptyOuter` of `[[]]` against `[[1]]`, where every element pair is answered --
/// `compare_eq([], [1])` mismatches on length -- and the whole-value pair has equal lengths, so it zips and
/// `compare_eq([], 1)` refuses. The shape one is a `Ports` of `[85]` against a `D13[*]` of `1` and `3`,
/// where the element pairs are int against int and the operator never compared them: it paired the whole
/// list with a scalar and refused on the kinds.
///
/// `EmptyList NOT IN Str` is not a shape refusal, `([], "abc")`, whether or not anything flattens: the
/// `(None, None)` arm has its own skip for a string right operand paired with an empty left-hand list, and
/// the arm answers an empty left-hand collection above its loop altogether, so the pair is never built and
/// there is no refusal for the clause to pass on. The diagnosis that does hold is of reaching "not
/// repairable" from the element pairs, of which there are indeed none, and stating it of the clause.
///
/// The VERDICT question that cell also sits in is a different one and is untouched: `Empty NOT IN Str`
/// against `Empty NOT IN Strs[*]` owe opposite answers from operands no predicate can tell apart, which the
/// empty-left-hand cells in `eval_tests.rs` prove and which nothing here moves. A notice is not a verdict,
/// and the impossibility is about the verdict.
///
/// The empty-left-hand family is two clauses rather than one, and neither owes a notice: `Empty NOT IN
/// Ustr` and `Empty NOT IN Strs[*]`, the second easy to read past because it looks like a different shape
/// -- the right operand is a query that EXPANDS to strings rather than a string, so it reaches the same
/// `(None, None)` arm with the same `([], "a")` shape pair, and it is not a `Str`. The 120-cell sweep behind
/// "the pair is the whole family" -- 30 right-operand kinds in both polarities for a `[]` and a `[[]]` --
/// established the family, and the family is what the skip above takes out in one go.
///
/// What they get instead, measured with the release binary over
/// `{Empty: [], Str: "abc", Ustr: "abc", Strs: ["abc"]}`: `Empty NOT IN Ustr`, `Empty NOT IN Str`,
/// `Empty NOT IN Strs[*]` and `Empty IN Ustr` each exited 0 printing the empty-collection deprecation
/// notice -- "passed without comparing anything" -- and none of the four printed "could not be compared
/// with any element of the list". The literal `Empty NOT IN "abc"` printed that same notice, so the query
/// spellings joined their literal rather than losing a diagnostic. That notice has since been retired:
/// every operator, `IN` included, now fails an empty left-hand collection as the retrieval error it is,
/// so the whole family exits 19 naming the empty collection, with nothing on stderr.
///
/// This predicate had not been told, and the shape arm below has been told now: its `empty_left` is
/// `lhsl.is_empty()` alone, because the operator answers an empty left-hand list before pairing it with
/// any right-hand kind and the condition named only the string.
///
/// It was described here as latent rather than live, on the reasoning that the verdict gate reads
/// `clause_passed` and a clause whose only pairing was skipped compared nothing. That reasoning is sound
/// and its scope was not: it holds for a left operand whose SOLE value is the empty list, which is the
/// population the sentence was checked against, and `refused` is ORed over the whole cross product. Give
/// the empty list a sibling that IS compared and the skipped pairing's refusal rides out on it. With `Mix`
/// of `[[], "q"]` against a `Ustr` of `"abc"`, `Mix[*] NOT IN Ustr` exited 0 and printed "could not be
/// compared with any element of the list" -- decided by `"q"` against `"abc"`, String against String,
/// while the `[]` that produced the refusal was compared with nothing. So it was live, and the sole-value
/// population is what hid it.
///
/// The family is narrow because the sibling has to do three things at once: be compared, contribute no
/// refusal of its own, and still let the clause pass. A non-string sibling refuses on its own pairing and
/// the clause fails closed, and a sibling the haystack contains fails it on the match; either way the
/// verdict gate suppresses whatever this answered. Measured over a 210-clause grid of the mixed-left
/// shapes, three reach it -- `Mix[*]`, `MixRev[*]` and `MixTwoStr[*]` against a queried string -- and the
/// fix moves exactly those three and no verdict anywhere.
/// `a_skipped_pairing_does_not_earn_a_sibling_a_membership_notice` carries them.
///
/// Strengthening `clause_passed` is NOT the repair, and that path is closed rather than merely
/// unattractive: a clause that compared nothing cannot reach `clause_passed = true` by either route.
/// Through `QueryValueResult`, `nothing_was_compared` in the two-query arm suppresses the only push, so
/// the vector is empty and the `!values.is_empty()` test rejects it; through `EmptyQueryResult`, all five
/// constructions in `binary_operation` yield FAIL or SKIP and none can be PASS. The defect is entirely
/// that this predicate answers `refused` for a pairing the operator declined to build.
///
/// Worth knowing for the next reader of an empty per-value vector, because it looks like a contradiction
/// and is not one. A vacuous clause exits 0 while `clause_passed` is false, and both readers compute from
/// the same vector at the same moment -- they ask different questions of emptiness. `clause_passed` asks
/// whether a value passed and gets no; the reporting fold asks whether a value FAILED, also gets no, and
/// `match_all` turns that into PASS. There is no race and no bug here. That the two answers happen to fail
/// safe is a property of this call site rather than of the pattern, so a new reader of an empty vector has
/// to establish its own direction rather than inherit this one.
///
/// # The literal-left branch
///
/// `InOperation::compare`'s `(Some, None)` arm decides a list-valued LITERAL against right-hand scalars
/// with `Vec::contains`, which is `PartialEq` and cannot refuse, so the operator produces nothing this
/// predicate could read there and `contained_in` is never called. The predicate answers for the branch
/// anyway, with `pair_refused` over each literal element against each right-hand value, through the
/// `(List, right)` arm below gated by `element_pairings_built`, and the answer is consulted whenever such
/// a clause passes, which `NOT IN` does when no element is on the right.
///
/// Same-kind operands owe nothing: `[85] NOT IN D13[*]` over `[1, 3]` passes on `compare_eq` answering
/// `Ok(false)` for every pairing, the same answer `Vec::contains` gave, so no refusal was read as "not a
/// member" (`a_membership_decided_by_partial_eq_owes_no_notice`). Mixed-kind operands owe the notice,
/// and its text is true of them: `["x"] NOT IN D13[*]` over `[1, 3]` passes because `"x"` could not be
/// compared with any element -- `Vec::contains` answers `false` for a `String` against an `Int` where
/// `compare_eq` refuses -- and the coming fail-closed release reads that pairing differently
/// (`a_membership_decided_by_partial_eq_over_mixed_kinds_owes_the_notice`), as the literal-right spelling
/// `Str NOT IN [1, 3]` already does.
///
/// # The `[*]` bypass and the alignment
///
/// The alignment depends on the right-expanded denylist arm being closed. Measured on a tree carrying the
/// granularity change and nothing else: the suite stays green, all five aws-guard-rules-registry
/// notices survive, the false alarms go -- and `Pair NOT IN Deny13[*]`, with `{"Pair":[1,2],"Deny13":[1,3]}`,
/// reads exit 0 **silent** where the unaligned predicate reads exit 0 *with* the notice. That clause admits a
/// value its denylist names, and no test in the suite fails when it does: on such a tree the noise is the one
/// warning left on a live bypass at exit 0, which is why the arm is closed first.
///
/// With the right-expanded denylist arm closed, measured rather than assumed: `Pair NOT IN
/// Deny13[*]` over the same document is **exit 19 and silent**, across six spellings.
///
/// Why it is silent depends on the spelling. Asserted (the clause `Pair NOT IN Deny13[*]` in a rule's body,
/// the spelling measured) the verdict
/// gate suppresses it and the report does name the clause: exit 19, `provided value [[1,2]] did match
/// expected value in [[1,3]]`. As a `when` condition the verdict gate still suppresses it and the report
/// names nothing at all: exit 0, empty stdout. Both are silent, each for its own reason. Every spelling of
/// that clause is silent, in either role.
///
/// # What this does not fix
///
/// The kind-mismatch half of the underlying defect. `NOT IN` still reads a pair it cannot compare as "not
/// a member" and passes, which `docs/KNOWN_ISSUES.md` records and which `!=` already refuses. Failing
/// closed here needs five aws-guard-rules-registry rules changed first, for the reasons
/// [`incomparable_membership_notice`] sets out, and this predicate is the warning that goes out meanwhile.
/// Those five notices are what the granularity fix had to leave alone, and it does: four are a `!Ref`-shaped
/// MAP against a regex denylist and the fifth a MAP against a plain `String`, and a map is not a list, so
/// nothing about them flattens. The same fact keeps them clear of both arms added since: the second
/// granularity needs a list on the left, and so does the shape refusal, so all five stay on the
/// does-not-decompose arm they were always answered by. Measured rather than inferred -- the five notice
/// bodies before their `Location[...]` tails are byte-identical with the list-only arms in place and
/// without them.
/// `a_left_hand_value_that_is_not_a_list_is_not_flattened` pins that shape as a unit cell and the registry
/// corpus pins the five themselves.
///
/// `rhs_enumerates` is the shape of the right-hand query, as `binary_operation` was told it: where it
/// enumerates a collection. When it does, `InOperation::compare` reads the resolved right-hand values as
/// ONE entry set (list-valued results flattened one level for a scalar on the left, and for a list on the
/// left when the enumeration is not the last part) and
/// asks `contained_in` of it once per left-hand value, in both the `(None, None)` and the `(Some, None)`
/// arm, exactly as the written-out list is asked. So the right operand this walks is that same
/// `operators::entry_set`, and the arm-specific rules below -- the stop at a match, the dropped shape
/// refusal -- are the pairing loop's and do not apply, which `both_queried` says. Carried rather than
/// re-derived, for the reason `both_queried` is read from `operators::is_literal`.
#[cfg(test)]
fn incomparable_membership(
    lhs: &[QueryResult],
    rhs: &[QueryResult],
    rhs_enumerates: RhsEnumeration,
) -> bool {
    incomparable_membership_in(
        lhs,
        rhs,
        &operators::InOperation::shaped(rhs_enumerates, rhs),
    )
}

/// `incomparable_membership` against the operator `binary_operation` built, so the entry sets it walks
/// are the ones the comparison reads and are built once per clause.
fn incomparable_membership_in(
    lhs: &[QueryResult],
    rhs: &[QueryResult],
    operator: &operators::InOperation,
) -> bool {
    let rhs_enumerates = operator.rhs_enumerates;
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
    let rhs_values = values(rhs);
    // Nothing on one side is nothing compared, and nothing compared is nothing to warn about. About the
    // VALUES and not their elements: an empty list is a value `contained_in` receives and answers for,
    // and the arms below say what it answers.
    if lhs_values.is_empty() || rhs_values.is_empty() {
        return false;
    }

    // The right operand as the operator compared it: an enumerating query's values are the sets the
    // operator's `operators::EntryCandidates` holds, built once per clause, and `sets_compared` replays
    // the operator's own walk for the value -- the sets in its order, stopping where it stopped -- so
    // the pairs walked below are the pairs `membership_in_entries` built and no others.
    let candidate_sets = |value: &Rc<PathAwareValue>| -> Vec<Rc<PathAwareValue>> {
        match operator.candidates() {
            Some(candidates) => candidates.sets_compared(value),
            None => rhs_values.clone(),
        }
    };

    // Whether `InOperation::compare` will take its `(None, None)` arm's PAIRING LOOP, which is the one
    // thing here that is about the call rather than about the values. That loop drops the refusal the
    // shape arm below is about; every other path reports it and the clause fails closed on it already.
    // Asked of `operators::is_literal` rather than re-derived, so the two cannot drift; and not taken
    // for an enumerating right-hand query, which that arm answers as one `contained_in` against the set
    // before its loop, the way the literal arm does.
    let both_queried = operators::is_literal(lhs).is_none()
        && operators::is_literal(rhs).is_none()
        && !rhs_enumerates.is_entry_set();

    // Some pair refused for a reason that is an incomparability. Tracked rather than returned, because
    // the answer is a property of every pair the clause was decided on: one refusal is enough, and no
    // refusal at all means there is nothing here to warn about.
    //
    // An answered pair cancels nothing. A `return false` on the first comparable pair, on the reading
    // that a clause with anything comparable in it decided on that pair, is false of `NOT IN`: a value
    // passes it by matching NOTHING, so every pair is built and an answered one says only that this
    // element was not the collision.
    //
    // ONE answered pair anywhere silenced the whole predicate, and position had nothing to do with it.
    // That `return false` returned from the FUNCTION rather than from the element loop, so the first pair
    // `compare_eq` could answer ended the walk wherever it sat; walking order had nothing to do with it.
    // Measured with that `return false` in place and with it removed: `["zzz", 7, false]`,
    // `[false, 7, "zzz"]` and `[7, false, "zzz"]` are ALL silent with it and all noticed without it, so
    // rewriting the denylist so the answerable element comes last changes nothing. The
    // substance stands -- an answered pair discarded a refusal that had already been seen -- and only the
    // order framing was false. Worth spelling out because "reorder the denylist" is a plausible thing for a
    // reader to try, and it would tell them the predicate was fixed when it was not.
    let mut refused = false;
    for value in &lhs_values {
        let rhs_values = candidate_sets(value);
        for element in rhs_values_paired_with(value, &rhs_values, both_queried) {
            match (&**value, &**element) {
                // `contained_in`'s list-against-list arm, which decides at TWO granularities.
                //
                // The element pairs are built by `elements_not_matched` asking `is_one_of` per
                // left-hand element. Not recursively -- for a `Deep` of `[["a"]]` the element is
                // `["a"]`, and that is the operand `is_one_of` is handed, so a second level would
                // compare something no clause compares.
                //
                // NOT ALL OF THEM, which this arm asserted for two commits. `is_one_of` returns
                // `Matched` on the first right-hand element that matches, so the pairings after a
                // match are never built for that element. A nested `for left in lhsl { for right in
                // rhsl { .. } }` here walked the whole cross product and counted the rest -- the same
                // class as the whole-value residual below, one granularity down.
                //
                // PRE-EXISTING before the repair of the message rendering below, and not a regression
                // of it. The nested walk sat three lines above the lines that repair changed, which is
                // close enough to read as introduced by it, so the provenance is stated rather than
                // left to a reader's inference. Cited by construct -- `elements_not_matched` asking
                // `is_one_of` per element -- because line coordinates move.
                //
                // `operators::membership_pairing_refused` is the fix, and the shape is the point: it
                // runs `is_one_of`'s OWN loop and reports what the pairings that loop built said. The
                // obvious alternative is to copy the walk's stop condition into this arm -- `if right
                // == left || compare_eq(left, right) == Ok(true) { break }` -- which reproduces the
                // defect's cause while fixing its symptom, and is what the prohibition on
                // `membership_stops_after` in `operators.rs` forbids. Both helpers this arm now calls
                // observe the operator instead of imitating it.
                //
                // Its classification cannot drift from `pair_refused`'s, which is what it replaces:
                // the flag is set on `is_one_of`'s `Err(_)` arm, and that arm receives everything
                // except the `RegexError` taken above it -- exactly the partition `pair_refused`
                // makes.
                //
                // STOPPING WHERE THE OPERATOR STOPS IS NOT THE SAME AS COUNTING ONLY WHAT DECIDED,
                // and this arm reported a refusal seen on the way to a MATCH for three commits. The
                // walk was right about which pairings exist; a pairing whose refusal the operator
                // discarded and then matched past decided nothing, and the value it belongs to fails
                // `NOT IN`. `is_one_of_observed` withholds the flag on its `Matched` exits, which is
                // the rule `rhs_values_paired_with` already applies one granularity up. That
                // function's exclusion is gated on `both_queried`, so it does not cover a literal
                // denylist and cannot stand in for this. All three call sites of
                // `membership_pairing_refused` were live; `a_refusal_seen_before_a_match_earns_no_notice`
                // pins one cell per site with the controls that attribute each.
                (PathAwareValue::List((_, lhsl)), PathAwareValue::List((_, rhsl))) => {
                    refused |= operators::membership_pairing_refused(lhsl, rhsl);

                    // And the WHOLE left-hand list against each entry, which that arm walks when no
                    // element matched and the denylist holds a list. Keyed on the same two conditions the
                    // operator branches on, because those are what decide whether the loop exists to
                    // refuse in: a flat denylist never reaches it, and reinstating the whole-value pair
                    // there is exactly the false-alarm class the alignment removed --
                    // `Strs NOT IN ["x", "y"]` is `(List, String)`, which has no arm, on a clause every
                    // pair of which is string against string.
                    //
                    // Gated on the elements having failed to match, because the operator's loop is. The
                    // operator gates this loop TWICE and the predicate mirrored only the first: the
                    // `any(is_list)` condition is the outer `if` of `contained_in`'s list-against-list
                    // arm, and `if !flat_subset` inside it is the second, where `flat_subset` is
                    // `elements_not_matched(lhsl, rhsl)`'s diff being empty. Both are cited by construct
                    // rather than by line, because this comment sits in a file later commits insert into
                    // and line numbers move.
                    //
                    // `operators::whole_value_pairing_built` is the second gate, and it OBSERVES the
                    // diff rather than re-deriving it -- it calls the same `elements_not_matched` the arm
                    // calls. That is the distinction this arm insists on everywhere else, and it is the
                    // reason a re-derivation would have been the wrong fix while this is the right one:
                    // a condition spelled out here can drift from the one the operator branches on, and
                    // a call cannot. `both_queried` above is read from `operators::is_literal` for the
                    // same reason.
                    //
                    // It covers the empty list too, so no `lhsl.is_empty()` guard stands beside it: an
                    // empty `lhsl` has nothing to leave unmatched, so its diff is empty, so the operator
                    // builds no whole-value pairing for it either. Adding one would be two guards where
                    // one answers, and neither would then be tested on its own. Measurable from outside:
                    // `Empty IN [[9], 5]` exits 0, which is `contained_in` answering `Success`.
                    //
                    // UNGATED by `both_queried`. The QUERIED path
                    // needs no guard here: `membership_stops_after(empty, X)` is true for every
                    // non-String X, so any list element is a stop and the exclusive prefix drops it,
                    // leaving only Strings inside `[0..at)` -- and a String is not a list, so this arm is
                    // unreachable. The LITERAL path is the one that reaches it, because
                    // `rhs_values_paired_with` returns its whole slice from the `!both_queried` early
                    // return before the endpoint is ever consulted, so the prefix cannot help there.
                    //
                    // THE RESIDUAL THIS CLOSES was left open here as latent, and the argument for that
                    // was false. It ran: every element matching means `contained_in` returns `Success`,
                    // which is a match, which fails `NOT IN`, so the verdict gate shuts. That is
                    // per-value, and the gate is not. `clause_passed` reads the query's own `match_all`,
                    // and for `some` it is `any(status == PASS)` -- so one failing value does not shut
                    // it. A passing sibling holds it open while the residual value's refusal sets
                    // `refused`, and the notice goes out naming a reason that is false about the value
                    // that actually passed.
                    //
                    // Measured with `Iso` of `[[[1]], [[7], [8]]]`: `some Iso[*] NOT IN [[1], [9]]`
                    // exits 0 and printed the notice, whose subject is `[[7], [8]]` -- every element of
                    // it compared int against int and decided false. Dropping the residual value leaves
                    // exit 0 and no notice, which attributes it; keeping only the residual value exits
                    // 19, which is the sole-value population the false argument was checked against. The
                    // filter spelling `Resources.*[ some Props.V[*] NOT IN [[1], [9]] ]` does it too,
                    // and that is the shape the registry rules are written in.
                    //
                    // Its own precedent is one arm down, and reading it would have caught this. The
                    // `(List, right)` arm below records the same failure mode about its own repair: an
                    // argument true of a left operand whose ONLY value is the empty list, and false as
                    // soon as the empty list has a sibling, because `refused` ORs over the whole cross
                    // product. Substitute "every element matched" for "the empty list" and that
                    // paragraph is this finding verbatim. The argument holds only over a left operand
                    // with no passing sibling; the gate asks the operator's own functions instead.
                    //
                    // THE TWO GRANULARITIES DIVERGED FOR THE SAME REASON and are now closed the same
                    // way. This one over-counted a whole-value pairing the operator skipped because the
                    // element diff was empty; the element loop above over-counted element pairings
                    // `is_one_of` short-circuited past. Both were the predicate re-deriving the
                    // operator's work and getting a different answer, and both are now questions asked
                    // of the operator's own functions.
                    //
                    // They are separable, and were separated, because each is sufficient on its own to
                    // set `refused`. With `ShortIso` of `[[[1]], [[7, 7], [8, 8]]]`,
                    // `some ShortIso[*] NOT IN [[1], [9]]` needs only the whole-value gate, while
                    // `some ShortIso[*] NOT IN [[1], ["a"]]` -- the SAME left operand -- needs both,
                    // because closing one leaves the other carrying the notice. The discriminator is
                    // whether the pairing the operator skipped would have compared incomparable kinds:
                    // for `[9]` the skipped pair is `compare_eq(1, 9)`, `Ok(false)`, refusing nothing;
                    // for `["a"]` it is `compare_eq(1, "a")`, `NotComparable`, a refusal. One fixture
                    // answering oppositely across two denylists is why the clause shape cannot be used
                    // to tell the two sources apart, and why a reader must not read one repair as
                    // covering the other.
                    //
                    // The element-loop half alone moves nothing observable: on every clause where it
                    // matters the whole-value residual fires too, and a residual left in place holds
                    // the notice up on its own.
                    // THE GATE WAS REPAIRED AND THE BODY WAS NOT, which is the fourth instance of this
                    // class and the last one in this arm. `whole_value_pairing_built` answers whether
                    // the operator's whole-list loop RUNS; it says nothing about how far that loop
                    // walks. The operator's loop `break`s on the first entry that matches -- by
                    // `PartialEq` or by `compare_eq` answering `Ok(true)` -- so a body that walks every
                    // entry regardless counts pairings the operator never compared, however correct its
                    // gate.
                    //
                    // Worth naming as its own mistake rather than as more of the same: replacing a
                    // re-derived CONDITION with an observed one reads as having brought the whole loop
                    // into line, and the body is a second place the same question has to be asked. The
                    // gate repair left this walk byte-identical to what it was before that commit.
                    //
                    // `membership_pairing_refused` over a one-element left side is the body, because
                    // the operator's whole-list walk IS `is_one_of` over the whole value -- that
                    // function now runs it, so there is one walk and the predicate reads it. The gate
                    // stays `whole_value_pairing_built`: two observations of the operator, one per
                    // question, neither re-derived.
                    //
                    // Its latency argument does NOT transfer from the `(left, List)` arm below, and
                    // assuming it did is what would have hidden this. That arm is suppressed because
                    // `compare_eq` has no edge between its numeric and textual comparability classes,
                    // so a sibling comparable to the offending entry refuses on its own account. The
                    // `(List, List)` arm bridges those classes: `compare_eq` on two lists compares
                    // LENGTH first and answers `Ok(false)` on a mismatch without examining element
                    // kinds. So a length-1 sibling is comparable to every length-2 entry, contributes
                    // no refusal of its own, and leaves the suspect's phantom refusal carrying the
                    // notice alone.
                    //
                    // Measured with `Whole` of `[[[1], [2]], [[9]]]`:
                    // `some Whole[*] NOT IN [[[1],[2]], ["a","b"]]` exits 0 and printed the notice. The
                    // suspect `[[1], [2]]` is `PartialEq`-equal to entry 0, so the operator breaks
                    // there and never reaches `["a","b"]`; this body did, and `compare_eq` zipped two
                    // length-2 lists into `compare_eq([1], "a")`, a refusal on kinds. The sibling
                    // `[[9]]` answers `Ok(false)` on length against both entries and refuses nothing,
                    // so the clause passes on a perfectly comparable value. Sibling alone is silent,
                    // suspect alone exits 19, and the unquantified spelling exits 19 -- the notice
                    // needed `some` and a sibling. The registry filter spelling fires too, so this one
                    // is user-visible rather than latent.
                    if rhsl.iter().any(|right| right.is_list())
                        && operators::whole_value_pairing_built(lhsl, rhsl)
                    {
                        refused |= operators::membership_pairing_refused(
                            std::slice::from_ref(&**value),
                            rhsl,
                        );
                    }
                }

                // A list against a value that is not one, which `contained_in` refuses on the SHAPES: it
                // dispatches on the left value first, so this pair reaches its `List` arm's catch-all and
                // answers `NotComparable` without asking `compare_eq` anything. There is no comparison
                // result to read, so the shape is what carries the refusal -- a predicate built from
                // `compare_eq` answers alone cannot see this class by construction, which is why it went
                // quiet on `Ports NOT IN D13[*]` and `Maps NOT IN Umap` when the operands were flattened
                // into pairs that are perfectly comparable.
                //
                // A shape test and NOT a `compare_eq` call standing in for one, which is the distinction
                // this arm exists to keep. Asking `compare_eq(whole_list, right)` here would produce a
                // refusal for most of these operands and would look like it worked, and it would be the
                // same defect the flatten was fixing: the predicate answering about a comparison the
                // operator never performed. `contained_in` compares nothing in this case, so what is
                // recorded is the fact that it declined, which is what the clause actually passed on.
                (PathAwareValue::List((_, lhsl)), right) => {
                    // The element question `contained_in` never asks, which the `(None, None)` arm asks
                    // for it with `is_one_of(element, [eachr])`.
                    //
                    // ONLY WHERE THE ARM ASKS IT, which was the missing condition rather than a missing
                    // stop. A DIFFERENT CLASS from every repair above it in this function, and saying so
                    // is the point rather than modesty about it: those were all a predicate walking
                    // FURTHER than the operator -- a loop counting pairings a `break` had already
                    // skipped -- and each was closed by asking the operator's own function how far its
                    // walk went. `pair_refused` is correctly aligned here and this loop stops where it
                    // should. What was absent is the question of whether any element-versus-right
                    // pairing exists at all to be refused in: `contained_in` dispatches
                    // on the left value, so a list against a non-list reaches its `List` arm's catch-all
                    // and answers `NotComparable` carrying the two WHOLE values, never decomposing. Each
                    // element then contributed a refusal for a comparison nobody made.
                    //
                    // Measured with `Mixed` of `[["a"], 7]`: `some Mixed[*] NOT IN 5` exits 0 and
                    // printed the notice, which is false about that clause. `["a"]` is the only value
                    // that could not be compared and it FAILED -- suspect alone exits 19 with
                    // `Can not compare type ... Value=["a"], Value=5`, the whole values -- while `7`
                    // passed on an ordinary `Ok(false)`. Nothing was read as "not a member", so there was
                    // nothing to warn about. Sibling alone is silent, which attributes it.
                    //
                    // `operators::element_pairings_built` is the condition, and it is asked of
                    // `operators::is_literal` for the reason the whole module gives: a condition written
                    // out here can drift from the one the arm branches on, and a call cannot. It is not
                    // `both_queried`. That flag names ONE of `InOperation::compare`'s four arms and
                    // collapses the other three, and two of the three collapsed arms do decompose --
                    // `(None, Some)` against a `String` expands the left-hand list into one `string_in`
                    // per element, and `(Some, None)` with no list among the right-hand values builds an
                    // element-wise `Vec::contains` diff. Both are refusals the operator really makes, so
                    // both are notices owed, and a gate keyed on `both_queried` alone silences them.
                    //
                    // The shape refusal below is keyed on `both_queried` and is RIGHT to be, which is
                    // why the two conditions differ rather than being shared. That one is about whether
                    // the refusal `contained_in` returns for the whole pair survives into the results,
                    // and only the `(None, None)` arm drops it. This one is about whether the arm builds
                    // element pairings in the first place. Same match arm, two different questions, and
                    // reading the lower one as settling the upper one is what left this ungated.
                    if operators::element_pairings_built(lhs, rhs, right) {
                        for left in lhsl {
                            refused |= pair_refused(left, right);
                        }
                    }

                    // The shape refusal itself, on the clauses that pass on it. Two conditions, and
                    // each excludes a shape that does not pass on it rather than one that is merely
                    // inconvenient.
                    //
                    // `both_queried`, because only the `(None, None)` arm drops the refusal. A literal
                    // right-hand side reaches `(None, Some)`, which pushes the `NotComparable` straight
                    // into the results, so `Ports NOT IN 5` is already exit 19 where the queried
                    // `Ports NOT IN Uint` is exit 0 on the same two values. A literal STRING does not
                    // reach `contained_in` at all -- that arm takes the `string_in` path per element --
                    // so `Empty NOT IN "abc"` has no refusal to pass on either, and counting it would be
                    // a false alarm rather than a suppressed one.
                    //
                    // An empty left-hand list, whatever the right operand is, because the operator never
                    // builds the pairing: `InOperation::compare` answers an empty left-hand collection
                    // as the empty collection it is, in every arm, before any containment or membership
                    // question is asked, so `contained_in` is never called for it and no right-hand kind
                    // is owed the shape refusal. This condition carries no right-hand kind test (no
                    // `&& !matches!(right, PathAwareValue::String(_))`): that no pairing of an empty
                    // left-hand list reaches the refusal is true by construction, for every right-hand
                    // kind, rather than by two exclusions that have to agree.
                    //
                    // What a stale half of this condition cost, which is why it is kept exact: `refused`
                    // ORs over the whole cross product, so a refusal credited to a pairing the operator
                    // never built rides out on a sibling that was compared and decided the clause. With
                    // `Mix` of `[[], "q"]` and `Ustr` of `"abc"`, `Mix[*] NOT IN Ustr` printed the
                    // membership notice whose subject was `"q"` against `"abc"` -- comparable, decided --
                    // while the `[]` that produced the refusal was compared with nothing.
                    // `a_skipped_pairing_does_not_earn_a_sibling_a_membership_notice` is that shape with
                    // the `NoEmpty` control beside it. `both_queried` is asked of `operators::is_literal`,
                    // the same function that selects the arm, so the predicate and the arm cannot drift
                    // into disagreeing about which pairs exist.
                    let empty_left = lhsl.is_empty();
                    if both_queried && !empty_left {
                        refused = true;
                    }
                }

                // `contained_in`'s `rest` arm against a list: the left value is the operand `compare_eq`
                // receives, so the value and the element it contributes are the same thing and nothing
                // is missing at a second granularity.
                //
                // THE THIRD SITE OF THE SHORT-CIRCUIT CLASS, closed the same way as the two above.
                // `contained_in`'s scalar arm `break`s on the first entry that matches, so the entries of
                // `rhsl` after a match are pairings the operator never built, and a loop over every entry
                // would count them. Three arms, one divergence each can fall into -- the predicate walking
                // further than the operator does -- and closing two while documenting the third would
                // leave the module with two rules instead of one.
                //
                // `operators::membership_pairing_refused` with a one-element left side, because the
                // operator's walk for a scalar IS `is_one_of` over the same slice. Same shared-walk shape
                // as the element-loop repair: it runs the operator's loop and reads what the pairings that
                // loop built said, rather than restating the stop condition here.
                //
                // IT WAS MEASURED LATENT AND REPAIRED ANYWAY, which is `membership_stops_after`'s own
                // rule and is followed here deliberately rather than re-decided. That note reads: "LATENT,
                // AND REPAIRED ANYWAY ... the suppression lives in a different function from the
                // divergence, though, so changing what either short-circuit fires on -- or adding a third
                // beside them -- makes it live with nothing in the tree to flag it." Verbatim true of this
                // arm: the verdict gate in `binary_operation` is what suppressed it, and the gate is not
                // in this function.
                //
                // The measurement, kept because it is what the repair rests on rather than a guess about
                // reach. Over a 23,496-clause grid, the shared walk moves 66 predicate answers and ZERO
                // notices against a loop over every entry -- 12,771 either way, 0 gained, 0 exit-code
                // movement, 0 stdout movement. The predicate figure came from an instrumented binary
                // computing the arm under both policies in one run, so a change the gate hides is still
                // counted, and every clause reached the predicate, so the denominator was complete.
                // `a_short_circuited_scalar_pairing_earns_no_refusal` is the cell that binds it; nothing
                // in the suite did before.
                //
                // THE ZERO IS A MEASUREMENT AND NOT A DEAD INSTRUMENT, which the probe's own positive
                // control is what establishes -- a run that answers "no movement" because it observed
                // nothing looks identical to one that observed everything and found no movement. Two
                // hand-checked clauses separate them. `Uint NOT IN [7, [9]]` over a `Uint` of 7 reported
                // the two policies DISAGREEING, so the probe could see this arm at all; and
                // `some Mixed[*] NOT IN [7, [9]]` over `[7, 99]` reported them AGREEING, because the
                // sibling `99` refuses against `[9]` on its own account and the over-count changes
                // nothing there. Without the first, 0 of 12,771 would prove only that the probe was
                // blind.
                //
                // Why the gate caught all 66. The over-count needs a denylist entry that MATCHES the left
                // value, or the walk does not stop early, and a later entry INCOMPARABLE to it, or the
                // skipped pairing refuses nothing. A matched value fails `NOT IN`, so only a sibling can
                // carry the clause -- but `compare_eq`'s comparability splits roughly into a numeric class
                // and a textual one, and mixing them is what makes the skipped pairing refuse, so a
                // sibling comparable to the offending entry sits in the other class from the matched entry
                // and refuses against that instead, earning the notice on its own account.
                //
                // THAT ARGUMENT EXPLAINS THE MEASUREMENT RATHER THAN STANDING IN FOR IT. It is the shape
                // of argument that reads a per-value gate as covering a whole-value residual, and the
                // `(List, right)` arm records the identical error about its own repair. Six hand-built attempts at a non-refusing sibling
                // all kept the notice, which is evidence and not proof. "Latent" was a property of the
                // measured population, and that is the reason this is repaired rather than left resting
                // on it.
                (left, PathAwareValue::List((_, rhsl))) => {
                    refused |=
                        operators::membership_pairing_refused(std::slice::from_ref(left), rhsl);
                }

                // Two values neither of which decomposes, which `contained_in` hands to `match_value`.
                (left, right) => refused |= pair_refused(left, right),
            }
        }
    }
    refused
}

/// The right-hand values `InOperation::compare`'s `(None, None)` arm pairs this left-hand value with.
///
/// A PREFIX of `rhs_values`, because that arm stops pairing a left-hand value at the first right-hand
/// value that matches it and [`incomparable_membership_in`] has to stop where the arm stops. Without
/// this the predicate counted refusals from pairings the arm never built --
/// [`operators::membership_stops_after`] carries the measurement and why a copy of the arm's rule
/// must not live here.
///
/// The stopping pairing is EXCLUDED along with the later ones, because a value that stops has either
/// MATCHED or was never paired at all. `found_in_string` answering `All` is a full string containment
/// and `contained_in` answering `Success` is a membership; a matched value FAILS `NOT IN`, so it cannot
/// be the value a passing `NOT IN` clause passed on, and counting its refusals credits a passing clause
/// with a refusal belonging to a value that failed. An empty left-hand list stops before its first
/// pairing, because the arm answers it as an empty collection above its loop and builds no pairing of
/// it, so no refusal of it exists to count; the `empty_left` exclusion in the `(List, right)` arm above
/// says the same thing from the other side.
///
/// Including the stopping pairing would rest on the arm "reaching `contained_in` for it and only skipping
/// the element loop", which is true of one stop and not of all of them: an `All` reaches only
/// `found_in_string`. Excluding the pairing is both simpler to state and correct for every stop, and it
/// settles the question -- a
/// list-against-list `Success` whose element pairs refuse while the subset holds, `["x", 1]` inside
/// `["x", 1]`, is precisely the accounting now dropped.
///
/// Exclusive is a strict reduction in what the predicate counts, so the direction of risk is silence
/// where a notice was owed, and the argument that it cannot happen is the one above rather than a sweep:
/// the stopping value matched, so its clause fails, and the gate in `binary_operation` emits nothing for
/// a clause that did not pass. What this drops was unreachable through the notice.
///
/// Whole slice when the call is not `(None, None)`, because the stop belongs to that arm alone. The
/// literal-right-hand arm walks every right-hand value with no short-circuit, so truncating there
/// would drop pairings it does build. `both_queried` is read from the same `operators::is_literal`
/// that selects the arm, so the two cannot disagree about which one runs.
fn rhs_values_paired_with<'v>(
    value: &Rc<PathAwareValue>,
    rhs_values: &'v [Rc<PathAwareValue>],
    both_queried: bool,
) -> &'v [Rc<PathAwareValue>] {
    if !both_queried {
        return rhs_values;
    }

    match rhs_values
        .iter()
        .position(|element| operators::membership_stops_after(value, element))
    {
        Some(at) => &rhs_values[..at],
        None => rhs_values,
    }
}

/// Whether one pair the membership comparison built refused for a reason that is an incomparability.
///
/// Not every `Err` is one. `fancy_regex` returns a `Result` from `is_match` because its backtracking
/// engine can run out of budget, so a `String` against a `Regex` -- a pair `compare_eq` has an arm for,
/// and builds the pattern for -- refuses with `RegexError` after comparing operands of perfectly
/// comparable kinds. Counted as incomparability, it produced a notice whose stated reason was wrong: the
/// engine quit, the values were fine, and rewriting the operands to "values of the same kind" would not
/// change anything.
///
/// Answered per pair rather than for the clause, which is the second half of the same point: the pair a
/// spent budget is right about is its own. `some Multi.*.V NOT IN [/re/]` over a thirty-character `a`
/// string and a list of ints: the string exhausts the budget, the ints refuse against the pattern --
/// `(Int, Regex)` is not an arm -- and the clause passes on the list. A `return false` for the whole cross
/// product on the evidence of the string's pair would let an unrelated sibling value's spent budget
/// destroy the warning the list is owed. Measured, the list alone earns the notice and the two together
/// earn it too. `a_spent_budget_on_one_value_does_not_silence_another_values_notice` pins all three.
///
/// Narrow on purpose: only the budget, never a kind mismatch. Passing over every `Err` would silence the
/// class this notice exists for, which is the tracked defect in `docs/KNOWN_ISSUES.md`.
///
/// Which pairs reach the budget arm follows from the caller comparing elements, not whole values against
/// elements. A FLAT denylist holding a regex hands it the left-hand list's ELEMENTS against that regex,
/// so `Cat NOT IN [/re/]` over a one-element `Cat` builds `(String, Regex)` and arrives with a spent
/// budget; the whole-value pair `(List, Regex)` is not an arm and would be counted as a kind refusal. A
/// denylist holding a NESTED list is the mirror: the element pair is `(String, List)`, a real
/// `NotComparable`, while the whole-value pair is `(List, List)` and zips into `(String, Regex)`. That
/// whole-value pair is built for the nested spelling too, by the second granularity in the caller, so
/// the nested clause reaches both.
///
/// Neither pairing is observable through the notice, because both clauses fail: `match_value` promotes
/// `RegexError` for the flat spelling and `contained_in` promotes it for the nested one, so the verdict
/// gate in `binary_operation` suppresses whatever this answered. Measured with the release binary on a
/// `Cat` of one thirty-character string of `a`s: `rule r { Cat NOT IN [/(?!x)((a+)+)b/] }` and
/// `rule r { Cat NOT IN [[/(?!x)((a+)+)b/]] }` each exit 19 with nothing on stderr, with the budget
/// exclusion in place and without it. `a_spent_backtracking_budget_is_not_an_incomparable_pair` and
/// `a_denylist_refuses_a_value_it_could_not_evaluate_in_either_spelling` hold both.
///
/// Nothing is lost by narrowing it. Where the budget is the only thing that refused the notice still
/// does not go out, which is the case this exclusion was added for; and such a clause is answered
/// elsewhere anyway, since `match_value` promotes `RegexError` and the clause fails saying the expression
/// could not be evaluated. That last part is true of an assertion and not of a gate -- a failing gate is
/// reported by nothing -- but the notice is not the thing to fix it with, because a clause that does not
/// pass is not one the coming fail-closed change moves.
fn pair_refused(lhs: &PathAwareValue, rhs: &PathAwareValue) -> bool {
    // The operator's own membership comparator, not `compare_eq`: a one-character string against a
    // char range is a pairing `contained_in` answers and `compare_eq` has no arm for, so asking
    // `compare_eq` here classed it refused and the notice fired on `Upper not in r[a,z]` over an `A`,
    // a clause that passed on a membership answer. Per that module's rule, this function observes the
    // operator rather than re-deriving it.
    match operators::compare_eq_for_membership(lhs, rhs) {
        Ok(_) | Err(Error::RegexError(_)) => false,
        Err(_) => true,
    }
}

/// The reason recorded against a left-hand value that is an empty collection, where the operator had
/// nothing to compare.
///
/// `docs/QUERY_AND_FILTERING.md` lists `Tags: []` alongside a missing key and an empty map as a
/// retrieval error, and says all retrieval errors are failures; the comparison answers as the
/// documentation says, and each sentence offers the `!empty` guard to the author who expects the
/// collection to be empty.
///
/// Names the side and the role, because the sentence a reader acts on differs. An assertion fails on
/// the value, filed against the empty collection's own path whichever side it was on. A `when` condition
/// is not satisfied by it, the way a condition over a property the document lacks is not satisfied, so
/// the rule is reported not applicable with this reason named. A filter predicate deselects the entry,
/// as it deselects an entry lacking the property.
///
/// The gate's text states what the comparison knows and names no outcome of its own, because the
/// outcome is not known where the text is recorded: a SKIP decided by a sibling conjunct and a rule
/// left not applicable by this condition share the record, and the sentence naming the outcome is added
/// where the outcome is known, by the skip-reason finder, which writes "did not apply because one of its
/// conditions was not met" ahead of it. Pinned by
/// `an_empty_collection_in_a_condition_leaves_the_rule_not_applicable` in `tests/validate.rs`.
fn empty_collection_message(side: operators::EmptySide, role: ClauseRole) -> String {
    let which = match side {
        operators::EmptySide::Lhs => "The value is an empty collection",
        operators::EmptySide::Rhs => "The right-hand side resolved to an empty collection",
    };
    match role {
        ClauseRole::Assertion => format!(
            "{which}, so there was nothing to compare, and an empty collection fails as a missing \
             key does. Guard the clause with `when <query> !empty {{ ... }}` if an empty collection \
             is expected."
        ),
        ClauseRole::Gate => format!(
            "{which}, so there was nothing to compare and the condition is not satisfied, as it is \
             not by a missing key. Guard the condition with `<query> !empty` if an empty collection \
             is expected."
        ),
        ClauseRole::Filter => format!(
            "{which}, so there was nothing to compare, and the entry is not selected. Add \
             `<query> !empty` to the filter if an empty collection is expected."
        ),
    }
}

/// The reason recorded against a clause whose two operands both resolved and yet produced no
/// comparison: every value on both sides was a collection with no element. Names the role for the
/// reason [`empty_collection_message`] gives.
fn nothing_to_compare_message(context: &str, role: ClauseRole) -> String {
    let what = format!(
        "{context} compared nothing: the operands produced no pair of values to compare (every \
         collection on both sides was empty, or a list with no element was written in the rule)"
    );
    match role {
        ClauseRole::Assertion => format!(
            "{what}, and the clause fails. Guard the clause with `when <query> !empty {{ ... }}` if \
             an empty collection is expected."
        ),
        ClauseRole::Gate => format!(
            "{what}, and the condition is not satisfied. Guard the condition with `<query> !empty` if \
             an empty collection is expected."
        ),
        ClauseRole::Filter => format!(
            "{what}, and the entry is not selected. Add `<query> !empty` to the filter if an empty \
             collection is expected."
        ),
    }
}

/// Notice for `NOT IN` against a list holding nothing the value can be compared with.
///
/// `docs/CLAUSES.md` says a comparison across kinds that are not both numeric "cannot be decided, and
/// the clause fails rather than guessing", and `docs/KNOWN_ISSUES.md` records the silent conversion to
/// `false` as a tracked defect. `!=` already fails closed on the same operands; `NOT IN` does not.
///
/// Not changed in this release, and the reason is specific rather than caution: five rules in
/// aws-guard-rules-registry rely on the current reading, and failing closed breaks them. They have to
/// change first.
///
/// Four of the five and the fifth break differently, and one sentence covering all five would describe
/// only the four. The four are filter predicates matching a `!Ref`-shaped
/// value against a regex denylist -- `some Properties.Users[*].Password not in [ /{{resolve\:...}}/, ... ]`
/// in `amazon_mq_broker_users_no_plaintext_password.guard:69` and its three siblings. Failing closed there
/// makes the filter select fewer resources, so a reported violation becomes a pass: the dangerous
/// direction, because nothing in the output changes.
///
/// The fifth is `secretsmanager_using_cmk.guard:41`,
/// `%aws_secretsmanager_secret_cmk.Properties.KmsKeyId not in ["alias/aws/secretsmanager"]`, and it is a
/// rule-body assertion rather than a filter, with a plain `String` element rather than a regex. Its pair is
/// `compare_eq(Map, String)` -- `KmsKeyId` is `{Ref: MyKMSKey}` in the fixture -- which has no arm and
/// reaches `compare_values`' catch-all. Failing closed there fails the clause, so the rule reports a
/// violation against a template that satisfies it by pointing at a customer-managed key. That is a false
/// alarm rather than a hidden one, and it is visible, so do not carry the filter argument over to it: the
/// harm is the opposite direction and the remedy for the rule is a different one.
///
/// Ends with the clause's source position, which is what makes the notice identify its own subject.
/// `context` is the clause's `Display` and carries no rule name, no file and no position, so two clauses
/// that differ only in something the rendering drops -- most easily a variable, since `%v NOT IN [1]`
/// renders alike however `v` is bound -- produced the same string, and `RootScope::deprecations` is a
/// `BTreeSet`. Two clauses then reported as one line, and an author who fixed the clause that line
/// appears to name was told nothing about the other.
///
/// A position rather than a counter or the offending value, because the set still has collapsing to do:
/// a rules file is evaluated once per test case, and `a_deprecation_notice_reaches_the_test_command`
/// requires two notices from three cases rather than six. A position is fixed at parse time, so it is
/// the same on every evaluation of one clause and different between two;  anything that varied per
/// emission would separate the duplicates as well as the distinct clauses.
fn incomparable_membership_notice(context: &str, location: &FileLocation<'_>) -> String {
    // The context is the clause as its `Display` writes it: query keys as written and a literal list
    // through the value renderer, so a tab or a bidi control inside `IN ['a<TAB>b']` would reach the
    // body raw. Text built from the rules file is escaped controls-only, as the gate notice escapes
    // its `when` text, so the line holds and the sink's assertion is met.
    format!(
        "{} passed because the value could not be compared with any element of the list, \
         which is currently read as \"not a member\". A future release fails closed here, as `!=` \
         already does. Compare against values of the same kind, or use `!=` if that is the intent. The \
         clause is at {}.",
        crate::utils::writer::escaped_controls_for_display(context),
        crate::utils::writer::location_for_notice(location)
    )
}

/// The statuses one comparison result contributes to a clause's verdict, with the value each one is
/// about, in the order the `Result` arm of `binary_operation` files them beside its records. The one
/// mapping from results to statuses.
///
/// A left-hand value that did not resolve, a right-hand reference that did not, and a refused pairing
/// are each one failure for their value. A successful `QueryIn` is one pass per left-hand value it
/// carries and a failed one is one failure per value in its diff, and nothing for the rest, which is
/// what makes `IN` against a multi-value query mean "any of these". Every other comparison is one status
/// for its one left-hand value.
fn value_statuses(
    result: &operators::ValueEvalResult,
    cmp: (CmpOperator, bool),
) -> Vec<(QueryResult, Status)> {
    // The one result that maps to no status: a refusal's marker paired with a left-hand value under a
    // positive `IN` (`marker_pair_under_in`); the same arm files no record for it, so the statuses and
    // the records stay one mapping.
    if marker_pair_under_in(cmp, result) {
        return vec![];
    }
    match result {
        operators::ValueEvalResult::LhsUnresolved(ur) => {
            vec![(QueryResult::UnResolved(ur.clone()), Status::FAIL)]
        }
        // An empty collection is one failure for the collection itself, whichever side it stood on,
        // which is how the `Result` arm files it. Both sides empty files nothing per value: that case is
        // explained at the block level, since a record with no other side is one the reporters drop.
        operators::ValueEvalResult::EmptyCollection {
            empty,
            other: Some(_),
            ..
        } => vec![(QueryResult::Resolved(Rc::clone(empty)), Status::FAIL)],
        operators::ValueEvalResult::EmptyCollection { other: None, .. } => vec![],
        operators::ValueEvalResult::ComparisonResult(comparison) => match comparison {
            operators::ComparisonResult::RhsUnresolved(_, lhs) => {
                vec![(QueryResult::Resolved(Rc::clone(lhs)), Status::FAIL)]
            }
            operators::ComparisonResult::NotComparable(nc) => {
                vec![(QueryResult::Resolved(Rc::clone(&nc.pair.lhs)), Status::FAIL)]
            }
            operators::ComparisonResult::Success(compare) => match compare {
                // The accepted values, not the whole left operand: a value the operator could not
                // answer is reported through its own refusal and never counts as accepted. For a
                // per-value record the two sets are the same one value.
                operators::Compare::QueryIn(qin) => qin
                    .accepted
                    .iter()
                    .map(|each| (QueryResult::Resolved(Rc::clone(each)), Status::PASS))
                    .collect(),
                operators::Compare::ListIn(lin) => {
                    vec![(QueryResult::Resolved(Rc::clone(&lin.lhs)), Status::PASS)]
                }
                operators::Compare::Value(pair) | operators::Compare::ValueIn(pair) => {
                    vec![(QueryResult::Resolved(Rc::clone(&pair.lhs)), Status::PASS)]
                }
            },
            operators::ComparisonResult::Fail(compare) => match compare {
                operators::Compare::QueryIn(qin) => qin
                    .diff
                    .iter()
                    .map(|each| (QueryResult::Resolved(Rc::clone(each)), Status::FAIL))
                    .collect(),
                operators::Compare::ListIn(lin) => {
                    vec![(QueryResult::Resolved(Rc::clone(&lin.lhs)), Status::FAIL)]
                }
                operators::Compare::Value(pair) | operators::Compare::ValueIn(pair) => {
                    vec![(QueryResult::Resolved(Rc::clone(&pair.lhs)), Status::FAIL)]
                }
            },
        },
    }
}

/// Notice for a `when` over a function's result whose answer moved because the result keeps entries the
/// function had no answer for.
///
/// Announced for one release, and only on measurement: `announce_a_moved_when` evaluates the `when`'s
/// conditions as written and again with those entries dropped, which is how every release before this
/// one read such a result, and calls this only when the gate's answer changed. `condition` is the first
/// condition whose own answer differs between the two readings, with `condition_now` and
/// `condition_then` its answers (`None` when a reading could not evaluate it). `dropped` is every
/// function result the conditions read whose entries the measurement dropped, each named with how many
/// entries it is read as now and was read as before. The move itself is the owner's call, and the
/// notice is how a rule author hears of it before a pipeline does. Carries the condition's position for
/// the reason [`incomparable_membership_notice`] gives, and each result's first unresolved entry with
/// its path and reason so the author sees which resource lacks the property. `resource` is the resource
/// the `when` was evaluated for when the answer moved (a type block's condition, or a `when` block in a
/// body evaluated per resource), named so the line is not read as a statement about every resource of
/// the block: the first unresolved entry is a resource that lacks the property, which is a different
/// one. The line then also says that a resource whose answer moved the other way gets a line of its
/// own, which is the one other line the `when` can print. A `when` evaluated at the document root has
/// none.
fn function_result_gate_notice(
    condition: &WhenGuardClause<'_>,
    condition_now: Option<Status>,
    condition_then: Option<Status>,
    now: Status,
    then: Status,
    dropped: &[DroppedEntries<'_>],
    resource: Option<&Path>,
) -> String {
    let location = crate::utils::writer::location_for_notice(when_clause_location(condition));
    // The condition is quoted from the rules file as the author wrote it, and a string literal in it may
    // hold a tab, an ESC or a bidi control that would break or reorder the line; escaped controls only,
    // as the path and the reason below are, so the one line spells every quoted text by one rule.
    let condition =
        crate::utils::writer::escaped_controls_for_display(&when_clause_text(condition));
    let direction = match then {
        Status::PASS => "its block ran before and is skipped now",
        _ => "its block was skipped before and runs now",
    };
    let answer = |status: Option<Status>| match status {
        Some(status) => status.to_string(),
        None => "no answer".to_string(),
    };
    let results = dropped
        .iter()
        .map(|entries| {
            let kept = match entries.kept {
                0 => String::new(),
                kept => format!(
                    " and {} entr{} its own query adds, kept in both readings",
                    kept,
                    if kept == 1 { "y" } else { "ies" }
                ),
            };
            // The resolved count is the function's own only for the name bound to the result itself;
            // a derived name's values are what its query produced from the result, so its count is
            // worded as the name's, not as what the function answered.
            let resolved_by = if entries.derived { "the name holds" } else { "it did answer" };
            format!(
                "%{}{} a function's result{} read as {} entr{} where it was read as {} before: {} entr{} \
                 the function had no answer for beside {} value{} {}{}, the first at {}{}.",
                entries.variable,
                if entries.derived { ", derived from" } else { " is" },
                if entries.derived { ", is" } else { "" },
                entries.resolved + entries.unresolved + entries.kept,
                if entries.resolved + entries.unresolved + entries.kept == 1 { "y" } else { "ies" },
                entries.resolved + entries.kept,
                entries.unresolved,
                if entries.unresolved == 1 { "y" } else { "ies" },
                entries.resolved,
                if entries.resolved == 1 { "" } else { "s" },
                resolved_by,
                kept,
                // The path and the reason beside it name the same entry, and the reason is text built
                // from several sources, a key quoted from the rules file beside the path from the
                // data, which the evaluator wrote as it stands and every other reader of a verdict
                // prints as written. So both are escaped the one way, controls only, and a resource
                // named `a\b` reads `a\b` in the path and in the reason; a path escaped as document
                // text here would spell the one name two ways on one line.
                crate::utils::writer::escaped_controls_for_display(
                    &entries.first.traversed_to.self_path().to_string()
                ),
                entries.first.reason.as_deref().map_or(String::new(), |reason| {
                    format!(
                        " ({})",
                        crate::utils::writer::escaped_controls_for_display(reason)
                    )
                }),
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    // The resource's path is escaped the one way the entry path and the reason above are, controls
    // only, so a resource named `a\b` is spelled `a\b` wherever this line names it; escaped as document
    // text it read `/Resources/a\\b` here beside `/Resources/a\b/...` in the entry's path.
    let for_resource = resource.map_or(String::new(), |path| {
        format!(
            ", for the resource at {} (the first resource of the block whose answer moved this way; a \
             resource whose answer moved the other way gets its own line, and no other resource is \
             listed),",
            crate::utils::writer::escaped_controls_for_display(&path.to_string())
        )
    });
    // What remained before this release: only values, unless a derived name kept entries of its own.
    let remained = match dropped.iter().any(|entries| entries.kept > 0) {
        true => "what remained, the entries the queries themselves added among them",
        false => "only the values that remained",
    };
    format!(
        "the `when` whose condition `{}` is at {}{} answers {} where before this release it \
         answered {}: {}. That condition answers {} now and answered {} before. {} Before this release \
         those entries were dropped and the conditions read {}; this release keeps them. The notice is \
         for this release only; the next release gives the new answer without it. To decide the block by \
         the resources that have the property, gate on the property itself (`when <query> !empty`) or \
         filter the resources before the function.",
        condition,
        location,
        for_resource,
        now,
        then,
        direction,
        answer(condition_now),
        answer(condition_then),
        results,
        remained,
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

/// Why a rule did not apply when its query selected nothing, for the two sites that know it.
///
/// `find_skip_reason` surfaces *refusals* -- a comparison that could not be decided -- and an empty
/// selection is not one. So this is a different sentence rather than a reuse of the refusal wording,
/// and it says what the two call sites actually branched on: the query ran, and it matched nothing.
///
/// [`empty_lhs_message`] is the neighbouring helper and is deliberately not reused. It is about the
/// left-hand *variable* of a comparison resolving to no values, so it tells the reader to look at
/// what binds the variable and says the clause fails. Neither half holds here: these are ordinary
/// queries with no variable to bind -- `Resources[ keys == /Z9/ ]` is the measured case -- and the
/// outcome is a SKIP, not a failure. Pointing a reader at a `let` they never wrote is the same class
/// of mistake as naming a condition a rule does not contain.
///
/// The query is named because it is the one thing that makes the line actionable, and no cause is
/// named at all -- which is a correction, not caution. The first draft said an empty selection is
/// what "a path the data does not have, an empty collection, and a filter that excluded every value
/// all produce alike", and two of those three are false here. Measured on this input:
///
/// ```text
/// Resources[ keys == /Z9/ ] { ... }      exit 0  SKIP   reaches here
/// Resources.*[ Type == "nope" ] { ... }  exit 0  SKIP   reaches here
/// Resources.Absent.Type == "x"           exit 19 FAIL   does not
/// Resources.One.Properties.Tags[*] { }   exit 19 FAIL   does not, over `Tags: []`
/// Resources.*.Type == "x"                exit 19 FAIL   does not, over `Resources: {}`
/// ```
///
/// A missing path and an empty collection are answered somewhere else rather than arriving as an
/// empty selection, so a filter that excluded every value is the only producer measured. That is
/// still not put in the sentence: one sampled producer is not proof of the only producer, and
/// telling an author to check filters on a query that has none would be the same mistake as naming
/// a condition the rule does not contain. The query is printed and the author reads their own query.
///
/// Rendered through [`SliceDisplay`], which is what every other query-naming message in this file
/// uses, so a filter prints as the parser's own name for it -- `Resources (map-key-filter-clauses)`
/// rather than `Resources[ keys == /Z9/ ]`. Ugly and not wrong; changing it would move every one of
/// those messages and belongs on its own.
///
/// # Every claim here is about this query and nothing wider
///
/// This sentence does not say "Nothing was refused -- the query ran and matched nothing": the first
/// half of that is a claim about the whole rule made from a fact local to one query. This function is
/// handed a query. It cannot see the rule's other clauses, so it cannot know whether one of them was
/// refused -- and when one is, that sentence is false:
///
/// ```text
/// rule r {
///     Resources[ keys == /Z9/ ] { Type == "AWS::S3::Bucket" }
///     or Resources.*[ Properties.KmsKeyId == "alias/aws/s3" ].Type == "nope"
/// }
/// ```
///
/// over `KmsKeyId: {Ref: MyKey}`, the second disjunct's filter compares a map against a string and is
/// refused. Exit 0 either way, and a report reading "Nothing was refused" would be wrong. Swapping the
/// two disjuncts makes the same rule on the same data report "a comparison in one of its query filters
/// reported: PathAwareValues are not comparable map, String" instead, so the false half would also
/// suppress the one actionable fact in the report, and which of the two a reader saw would depend on
/// the order they happened to write their disjuncts in.
///
/// Narrowing the claim to this query rather than dropping it does not work either, and that is worth
/// recording because it is the tempting repair. A refused comparison inside *this* query's own filter
/// also arrives here with an empty selection -- `Resources.*[ Properties.Size > 10 ]` over
/// `Size: "50"` sets this message on its `BlockGuardCheck` and is merely shadowed by the deeper
/// refusal that `find_skip_reason` finds first. So "nothing about this query was undecidable" is
/// unsupportable at this site too.
///
/// What is left is what the branch condition gives: the query ran, and it selected nothing. "Ran" is
/// worth keeping and is local -- the `Err` arm above returns before this point, so reaching here means
/// the query resolved rather than failed.
///
/// Not fixed here, and not this defect: which of two sibling reasons surfaces still depends on clause
/// order, because the walk takes the first child carrying a message. That is a ranking question in
/// `find_skip_reason` rather than a false claim in a sentence, and the two want separate changes.
fn empty_selection_message(query: &[QueryPart<'_>]) -> String {
    format!(
        "the rule did not apply because the query {} ran and selected no values from this input.",
        SliceDisplay(query)
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
/// easy to omit: a boolean threading that leaves
/// `WhenGuardClause::ParameterizedNamedRule` unthreaded evaluates a parameterized rule
/// invoked from a `when` condition with assertion strictness and produces exactly the
/// wrong-PASS described above. With an explicit parameter type
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
    /// The clause is a filter predicate selecting entries, `Resources.*[ ... ]`. It is a
    /// selection test, not an assertion and not a gate: an entry the predicate does not
    /// hold for is deselected, and the clause that uses the filter decides on what
    /// remains. Separate from `Gate` because the two speak about different things when
    /// a comparison decides against a value. A `when` condition that is not satisfied --
    /// by an empty collection as by a missing property -- leaves its whole rule not
    /// applicable; a filter predicate deselects the one entry, the way it deselects an
    /// entry lacking the property, because the comparison answer for one entry is not a
    /// fact about the others, and the clause decides on what remains. The recorded
    /// reason names the role's own consequence. An unevaluatable error leaves the filter
    /// as an error in this role too, with one exception: a selection nobody could decide.
    /// Inside a predicate the undecidable marker (`UnResolvedKind::Undecidable`) is built
    /// by a key filter whose right-hand side the document lacks or whose comparison the
    /// engine could not finish (the key-filter arm of the retrieval), by a capture the
    /// evaluator cannot bind (`eval_context::to_undecidable_result`), by a wildcard filter
    /// refused over a one-object or mixed map (`eval_context::to_refusal_result`, `refused` set)
    /// (`eval_context::refuse_a_filter_over_a_one_object_shaped_map`), and by the filter
    /// loops for an entry whose own predicate raised. The predicate's clause raises on it
    /// (`undecidable_selection`, `binary_operation`'s unresolved arms) rather than
    /// deselecting or selecting the entry, since the marker says the entry's own selection
    /// could not be decided and nothing about the other entries; the loop that tested the
    /// entry answers it with the same marker in the enclosing selection and goes on to the
    /// siblings, which are tested and reported; and the clause that uses the filter fails
    /// closed on the marker in either polarity unless a sibling settles the clause: under
    /// `some` a sibling entry that passes decides it, and in a `when` gate a sibling that is a
    /// decided failure settles it as not applicable (`undecided_gate`), the marker saying
    /// nothing about those entries. A block clause met in this role reads an undecided body
    /// the same way as in a gate (its `UndecidableComparison` arm is for every role but the
    /// assertion): the value is counted as not passed, not as decided, and the block's own
    /// table decides. A scalar met under a key inside a predicate keeps the deselect reading.
    Filter,
}

/// An error meaning the clause could not be evaluated at all, as opposed to the evaluation
/// machinery having gone wrong.
///
/// Two dedicated variants produce it, and they differ only in what they say. `Error::Unevaluatable` is
/// classified where it is raised: `EMPTY` against a type that cannot be empty, a converter asked to
/// read a value it cannot convert, a function argument the input could not supply, a `%var` used as a
/// key whose values are not strings, a filter after a key that holds a scalar, a capture declared after
/// `this`, an index, an earlier filter or a map-key filter over a value that is not a list, each for a
/// value the template supplied. Those are facts about the
/// data a clause met, not about the rules file, so every site answers them the same way: fail closed as
/// an assertion, carry the error as a gate, and in an `or` let a sibling that can decide do so. The
/// same operation on a value written in the rules file is the author's mistake and is classified
/// `IncompatibleError` at the raise site (`Error::unanswerable`). `UndecidableComparison` covers a
/// comparison that ran and was abandoned, today a spent `fancy_regex` backtracking budget, which the
/// value being compared decides; see [`Error::UndecidableComparison`].
///
/// Nothing else is admitted. A recorder fault, a parameterized rule called with the wrong number of
/// arguments and a binary clause that reached evaluation with no right-hand side (two invariants the
/// parser keeps, reachable only from a `RulesFile` assembled without it) are `InternalError`; a query
/// shape interpolation does not support and the rules-file literals above are `IncompatibleError`;
/// a filter after a key that holds a non-null scalar, and a `this[ ... ]` over a member map that kept
/// no entry while its predicate names a key of the member, are `Unevaluatable`, the evaluator's "no
/// answer either way" channel, and fail closed in both polarities (a filter after an indexed value
/// tests that one member and raises nothing); a pattern that does not compile is refused
/// by the parser, and `RegexError` names the rules file in its text; `NotComparable` is raised by the
/// comparators for a pair they cannot compare and classified into a comparison result by
/// `unanswerable_reason` before any hold sees it, so the evaluator itself raises it nowhere; an
/// undeclared name is `MissingValue`; a malformed rules file is `ParseError`. Each is a failure of
/// the machinery or a mistake in the rules file, and each stops the run: the disjunction hold in
/// `eval_conjunction_clauses` admits exactly what this predicate accepts. `the_or_hold_is_an_allow_list`
/// pins the two held variants, each beside a passing and a failing sibling, and a return-at-once row
/// for each error the evaluator raises into a disjunction (`IncompatibleError`, `ParseError`,
/// `MissingValue`, a recorder fault) or the hold once admitted (`NotComparable`, `RegexError`, which
/// reach the arm from no rules file today). The variants of `Error` with no row there are raised by no
/// evaluation site: `MissingProperty` is constructed nowhere, and `Errors` nowhere but by `?` on the
/// `Errors` type, which no evaluator source builds; `MissingVariable` by the older evaluator in
/// `evaluate.rs` alone; `RetrievalError` and `IncompatibleRetrievalError` by `PathAwareValue::select` and
/// `accumulate`, which that older evaluator and a command call, never this one, and by the reporters'
/// traversal; `MultipleValues` by `PathAwareValue::merge`, a command's; `IllegalArguments` by the
/// commands' argument checks; and the file, format and conversion errors (`JsonError`, `YamlError`,
/// `FormatError`, `IoError`, `FileNotFoundError`, `MissingDocument`, `UnsupportedDocument`, `XMLError`,
/// `ConversionError`) by the loaders, the readers and the commands.
/// `the_variants_the_hold_has_no_row_for_are_raised_by_no_evaluation_site` pins that against the
/// evaluator's own sources (`eval.rs`, `eval/`, `eval_context.rs`, `exprs.rs`, `functions.rs`,
/// `functions/`): no source spells a tuple variant's constructor or the unit variant's path, none calls
/// `select`, `accumulate` or `merge`, and none names a route that builds a `#[from]` variant's inner
/// error, except one YAML read in `strings.rs`, which maps its error to `unanswerable` on the same
/// expression (the test spells the route; this doc does not, since the test scans this file too).
/// `FormatError` alone is pinned by nothing: a `write!(..)?` in a function
/// returning this crate's `Result` would build it, and no text scan tells that call from a `Display`
/// impl's; it falls, like every variant without a row, to the return-at-once arm. A raise site added to
/// one of those sources reddens the test and this list with it. Matching
/// dedicated variants, rather than the general-purpose ones, is what let the raise sites decide the
/// class once: when this matched `IncompatibleError`, the recorder's own faults were held in an `or`
/// and turned into a fail-closed verdict in an assertion, because the recorder raised that variant
/// too. The decision is by variant alone; `a_record_tracker_imbalance_is_not_an_unevaluatable_clause`
/// pins that an `IncompatibleError` is a rules-file mistake that stops the run whatever its text says,
/// and that an `Unevaluatable` is a verdict whatever its text says.
///
/// The one classifier for "the data could not answer": the disjunction hold in `eval_conjunction_clauses`,
/// the block-body sites and the one-object probe of the pass-over refusal
/// (`eval_context::probe_predicate_carrying_errors`) all sort an error with this predicate and its
/// complement `Error::is_rules_file_mistake` plus the internal faults (returned at once), so a variant
/// admitted here is held or folded everywhere and never stops one site while another holds it.
pub(in crate::rules) fn is_unevaluatable(e: &Error) -> bool {
    matches!(e, Error::Unevaluatable(_) | Error::UndecidableComparison(_))
}

impl ClauseRole {
    /// True when an unevaluatable clause in this role should FAIL rather than SKIP.
    fn is_strict(self) -> bool {
        matches!(self, ClauseRole::Assertion)
    }
}

/// `access` is the clause's whole left-hand query. Its parts are what is evaluated; the query is
/// also what the empty-selection record below names, `some` included, so the modifier the author
/// wrote reaches the reporters instead of being dropped at this call.
#[allow(clippy::type_complexity)]
fn unary_operation<'r, 'l: 'r, 'loc: 'l>(
    access: &'l AccessQuery<'loc>,
    cmp: (CmpOperator, bool),
    inverse: bool,
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'l, 'loc>,
    role: ClauseRole,
) -> Result<EvaluationResult> {
    let lhs_query: &'l [QueryPart<'loc>] = &access.query;
    // The selection with the facts the retrieval recorded beside it. A pair-shaped filter straight after
    // `[*]` over a map of scalars is decided at the arm by the map's `{ Key, Value }` list twin and leaves
    // no note. A filter straight after `[*]` that read a map the twin does not read (a non-scalar entry,
    // a predicate outside the pair convention) as one object, compared against keys it holds none of and
    // kept nothing leaves the empty selection with a lacks-keys note (`eval_context::LacksKeysNote`) when
    // nothing follows it in its own query, and a bare unary over that selection (`Tags[*][ Key == 'Env' ] exists`, `!exists`,
    // `empty`, `!empty`, the same through a binding or a parameter, `when %env !empty { ... }`) is decided
    // by what the object holds: an object holding an entry the predicate compared a key against (`Env`
    // in `{ Env: dev }`, under any operator and in any clause) is not read as its list twin would be, so
    // "empty" is a guess at the twin's answer and the read is refused as a key's read is, delivered as
    // the deferred key reads are (`LacksKeysNote::refuse_bare_read`): inside a filter predicate the
    // undecidable marker for the object, on which the clause fails closed in both polarities while the
    // other entries are decided; outside one the held refusal, which an assertion fails closed on and a
    // gate carries to its condition site, so its rule fails closed rather than leaving the block
    // unopened. Under a selecting comparison an object holding no such entry (`{ Team: platform }`
    // under `[ Key == 'Env' ]`) keeps the empty selection, which is its list twin's answer; under a
    // NEGATED comparison (`[ Key != 'Env' ]`, `NOT IN`) the twin selects every pair the negation does not
    // exclude, so an object holding an entry no negated clause excludes (a clause on `Key` by the
    // entry's name, one on `Value` by its value: `Team: platform` under `Key != 'Env'`) is refused too,
    // while an entry a negated clause does exclude (`{ Team: platform }` under `[ Value != 'platform' ]`),
    // an object under a negated clause on a key the twin pair has not (`[ Action != '*' ]` over a
    // statement lacking `Action`) and an object a selecting conjunct names no entry of (`{ Team: platform
    // }` under `[ Key == 'Env'  Value != 'prod' ]`) keep the empty selection, the twin's answer; the
    // predicate is walked over each entry's pair with its `and`/`or` kept, so `[ Key != 'Env' or Value !=
    // 'prod' ]` and `[ Value == 'prod'  Key != 'Env' ]` over `{ Team: prod }` are refused, as the twin is
    // selected.
    let (mut lhs, _, passed_on) = eval_context.query_with_shape(lhs_query)?;
    // The reads the operator itself decides, and which of them are not the safe side: a bare `empty` (the
    // comparator's `!` and a leading `not` cancel, so `not X !empty` is bare too) over the empty selection
    // PASSES by that selection being empty. When a regex a selecting clause compares against matches
    // EVERY key of the one object (`Statement[*][ Sid == /^\w+$/ ] empty` over a one-object statement
    // without `Sid`, `when %s empty { ... }` over a binding to it) the compared-entry test names no entry,
    // so the read above keeps the selection, and the pass is vacuous: the regex matched every key, so the
    // author may have selected every entry, and the selection that reading keeps would fail; that read is
    // refused here instead, fail closed, by the note's second question
    // (`LacksKeysNote::refuse_every_key_regex_empty`), asked by the operator because the filter arm that
    // built the note did not know it (a PAIR-shaped predicate, `Tags[*][ Key == /^[A-Za-z]+[0-9]$/ ]` over
    // `{ Env1: dev }`, is decided by its `{ Key, Value }` list twin at that arm and builds no note, so the
    // predicates refused here name a field outside the pair convention). Which operators ask is a RULE
    // over every unary operator (`Asked::of`), computed from the operator's answer over the empty
    // selection against its answer over a kept pair: outside a filter predicate the bare `empty` alone,
    // the one read the empty selection passes where a kept pair fails (`!empty` failing is the safe side;
    // `exists`, `!exists` and the type checks are not applicable, the documented limit); inside a FILTER
    // PREDICATE a clause that does not hold DESELECTS the entry under test, so every operator whose answer
    // over nothing keeps or deselects the entry differently from a kept pair's: `!empty` failing, `exists`,
    // `is_struct`, `!is_string`, `!is_list` and the other checks a pair passes not applying, each dropping
    // the resource a kept pair keeps so that an outer `empty` passes over nothing (`Resources.*[
    // Properties.Tags[*][ Key == /^\w+$/ ] !empty ] empty` over `{ Env: dev }` passed at exit 0 where the
    // list form fails at exit 19, before the twin decided it), and the bare `empty` keeping the entry a
    // kept pair deselects; the marker the question returns fails the enclosing clause closed, so the outer
    // read is refused rather than deselected. `!exists`, `!is_struct`, `is_list`, `is_string` and the
    // other checks a pair fails are not asked in a predicate: the map's not applicable and a kept pair's
    // fail both deselect, the same answer.
    let in_predicate = eval_context.in_predicate();
    let asked = Asked::of(cmp.0, cmp.1 ^ inverse, in_predicate);
    for note in passed_on.lacks_keys() {
        if let Some(refused) = note.refuse_bare_read(in_predicate) {
            lhs.push(refused?);
        } else if let Some(asked) = asked {
            if let Some(refused) = note.refuse_every_key_regex_empty(asked, in_predicate) {
                lhs.push(refused?);
            }
        }
    }

    // The comparison a failure is recorded with. The parser keeps the two spellings of negation
    // apart -- `X not exists` sets `cmp.1`, and `not X exists` arrives here as `inverse` -- and the
    // verdict below honors both. A record carrying `cmp` alone would record `not X exists` failing
    // because `X` was present as `(Exists, false)`: the pair every reporter reads as
    // "did not exist", with `Operator = EXISTS` on the console and `["Exists", false]` in `-o json`,
    // telling the author to add the property the rule forbids. Folding the clause-level `not` in
    // here makes the record say what the clause as a whole asked, and lets every reporter stay as it
    // is. `cmp` itself is still what the operations below are built from.
    let recorded = (cmp.0, cmp.1 ^ inverse);

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
                    // `element_empty_operation`, which is the question the operator asks.
                    // `res.is_null()` is not that question: null is empty, but so are other things,
                    // and a null test consults nothing else.
                    //
                    // Under a null test a lone variable bound to an empty list or an empty string
                    // reports itself *not* empty, and `EMPTY` on it reports false -- both polarities
                    // wrong, on a value whose emptiness is the whole question -- and a variable bound
                    // to a number or a boolean cannot fail either clause for any input, the same
                    // silent always-pass that `element_empty_operation` rules out for the direct path.
                    //
                    // The shortcut itself has to stay. It is what makes the selection idiom work:
                    // for `%vols !empty` an empty selection resolves to zero values and is answered
                    // by the branch below, and dropping this arm would send that to the SKIP further
                    // down instead -- turning the most common gate in the registry from a failure
                    // into a silent skip.
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
                                    comparison: recorded,
                                    value: ValueCheck {
                                        status: Status::FAIL,
                                        message: Some(e.to_string()),
                                        custom_message: custom_message.clone(),
                                        from: each.clone(),
                                        refusal: is_refusal(&e),
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

                        // Every other error stops the run, but the record opened at the top of this
                        // loop still has to be closed, or `extract` reports the recorder's own
                        // imbalance ("context start and end does not match") in place of the error
                        // the user needs. This arm is reached now that `EMPTY` on a boolean written
                        // in the rules file (`let b = true` with `%b !EMPTY`) is an
                        // `IncompatibleError`; before the provenance split every error this match
                        // could see was unevaluatable and took the arm above. Recorded without an
                        // explanation, because the error leaves `eval_rules_file` before any
                        // reporter reads the tree; the comparison is still the clause's whole
                        // question, with the clause-level `not` folded in as every other record of
                        // this shortcut has it, because `validate` renders the record tree before
                        // it applies `?` to the error, and `-o json` printed `not %b EMPTY` as the
                        // pair for "asked to be empty".
                        Err(e) => {
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Unary(UnaryValueCheck {
                                    comparison: recorded,
                                    value: ValueCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        from: each.clone(),
                                        refusal: false,
                                    },
                                })),
                            )?;
                            return Err(e);
                        }
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
                                    comparison: recorded,
                                    value: ValueCheck {
                                        status: Status::FAIL,
                                        message: None,
                                        custom_message: custom_message.clone(),
                                        from: result.clone(),
                                        refusal: false,
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
                                        ClauseCheck::NoValueForEmptyCheck(EmptySelectionCheck {
                                            query: AccessQueryWithFilters(access).to_string(),
                                            custom_message,
                                        }),
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
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::Empty, not_empty) => box_create_func!(
            element_empty_operation,
            not_empty,
            inverse,
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsString, is_not_string) => box_create_func!(
            is_string_operation,
            is_not_string,
            inverse,
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsMap, is_not_map) => box_create_func!(
            is_struct_operation,
            is_not_map,
            inverse,
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsList, is_not_list) => box_create_func!(
            is_list_operation,
            is_not_list,
            inverse,
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsBool, is_not_bool) => box_create_func!(
            is_bool_operation,
            is_not_bool,
            inverse,
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsInt, is_not_int) => box_create_func!(
            is_int_operation,
            is_not_int,
            inverse,
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsNull, is_not_null) => box_create_func!(
            is_null_operation,
            is_not_null,
            inverse,
            recorded,
            eval_context,
            context,
            custom_message
        ),
        (CmpOperator::IsFloat, is_not_float) => box_create_func!(
            is_float_operation,
            is_not_float,
            inverse,
            recorded,
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

// `pub(crate)` on the types alone, because `key_filter::KeySelection` carries them in its interface;
// the fields stay private to this module and its children.
pub(crate) enum ComparisonResult {
    Comparable(ComparisonWithRhs),
    NotComparable(NotComparableWithRhs),
    UnResolvedRhs(UnResolvedRhs),
}

pub(crate) struct LhsRhsPair {
    lhs: Rc<PathAwareValue>,
    rhs: Rc<PathAwareValue>,
}

pub(crate) struct ComparisonWithRhs {
    outcome: bool,
    pair: LhsRhsPair,
}

#[allow(dead_code)]
pub(crate) struct NotComparableWithRhs {
    reason: String,
    /// Why there was no answer, for the same reason [`operators::NotComparable`] carries it: the map-key
    /// path has to tell a refusal to compare kinds from an evaluation the engine abandoned, and the
    /// reason string cannot be classified after the fact.
    cause: operators::Unanswerable,
    pair: LhsRhsPair,
}

/// A refusal to compare, built the same way at each of the three sites that raise one.
///
/// Shared so the classification happens once, in `operators::unanswerable_reason`, rather than three
/// times by hand. Before this, the map-key evidence pass matched `Error::NotComparable` and propagated
/// everything else, so a `RegexError` from a spent backtracking budget left the evaluator entirely: the
/// full report printed, then `main` reported "Error occurred Regex expression parse error for rules
/// file" and exited 255, which `guard/tests/utils.rs` names `INTERNAL_FAILURE`. Measured on
/// `Cfg[ keys == /(?!x)((a+)+)b/ ]`, the threshold was template-driven -- a seventeen-character key
/// exited 19 and an eighteen-character key exited 255 -- and all four comparators were affected.
fn map_key_refusal(
    err: Error,
    lhs: Rc<PathAwareValue>,
    rhs: Rc<PathAwareValue>,
) -> ComparisonResult {
    let unanswered = operators::unanswerable_reason(err);
    ComparisonResult::NotComparable(NotComparableWithRhs {
        reason: unanswered.reason,
        cause: unanswered.cause,
        pair: LhsRhsPair { lhs, rhs },
    })
}

pub(crate) struct UnResolvedRhs {
    rhs: QueryResult,
    lhs: Rc<PathAwareValue>,
}

impl UnResolvedRhs {
    /// Why the key's comparison against this right-hand value could not be finished: the retrieval
    /// stopped before reaching it, at a path with a query still to walk. One text for the fold, which
    /// fails the filter closed on it, and for the record the reporters print, so the summary says the
    /// right-hand side did not resolve rather than rendering a verdict about a comparison that never ran.
    /// `None` only for a resolved value held here, which `select_key` never builds.
    ///
    /// The retrieval's own explanation, when it left one, is part of the text: where the query stopped
    /// and what was left of it say that `Wanted[*].Name` got no further than `Wanted`, and only the
    /// retrieval's reason says why, that `Wanted` is an integer with no keys to read. Without it the
    /// author was told where and not why.
    fn did_not_resolve_reason(&self) -> Option<String> {
        match &self.rhs {
            // The marker a filter left for a value nobody could decide, reached as this right-hand
            // side (a capture read bare, `keys IN %b`, whose marker stands at the entry with nothing
            // left of the query; a key filter's right-hand query is rooted at the map it filters, so
            // the capture is the way such a marker arrives here): neither "did not resolve" nor "had
            // no value", since the walk arrived at a value the filter could not decide. Its own
            // reason says what could not be decided, and the keys compared against it cannot be
            // decided either. A refusal's marker (`refused` set) arrives the same way and reads the
            // same: the right-hand side could not be decided.
            QueryResult::UnResolved(UnResolved {
                traversed_to,
                reason,
                kind: UnResolvedKind::Undecidable { .. },
                ..
            }) => Some(format!(
                "the right-hand side of the key filter is a value nobody could decide at {}{}, so the \
                 keys it selects cannot be decided",
                traversed_to.self_path(),
                reason
                    .as_deref()
                    .map_or(String::new(), |why| format!(": {}", why.trim_end()))
            )),
            // A value a function had no answer for arrives with no remaining query and the function's
            // own reason (`no_answer_for`): "did not resolve at <path> (remaining query )" would say
            // the retrieval stopped where it had in fact arrived. The function's reason is the text.
            QueryResult::UnResolved(UnResolved {
                traversed_to,
                remaining_query,
                reason: Some(reason),
                ..
            }) if remaining_query.is_empty() => Some(format!(
                "the right-hand side of the key filter had no value at {}: {}, so the keys it selects \
                 cannot be decided",
                traversed_to.self_path(),
                reason
            )),
            QueryResult::UnResolved(unresolved) => {
                let explanation = match &unresolved.reason {
                    Some(reason) => format!(": {}", reason.trim_end()),
                    None => String::new(),
                };
                Some(format!(
                    "the right-hand side of the key filter did not resolve at {} (remaining query {}){}, \
                     so the keys it selects cannot be decided",
                    unresolved.traversed_to.self_path(),
                    unresolved.remaining_query,
                    explanation
                ))
            }
            QueryResult::Resolved(_) | QueryResult::Literal(_) => None,
        }
    }
}

/// Records one key-against-value comparison and answers its status.
///
/// `selected` is the verdict `key_filter::select_key` reached for the key, and it is what the record
/// and the status say. The comparison itself supplies only the two values and, when it had no answer,
/// the reason: a pair's own `outcome` is the comparator's answer before the key filter's polarity, so
/// reading the status off it would put the polarity rule in a second place.
fn report_value<'r, 'value: 'r, 'loc: 'value>(
    each_res: &ComparisonResult,
    selected: bool,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<(QueryResult, Status)> {
    let (lhs_value, rhs_value, reason) = match each_res {
        ComparisonResult::Comparable(ComparisonWithRhs {
            pair:
                LhsRhsPair {
                    lhs: lhs_value,
                    rhs: rhs_value,
                },
            ..
        }) => (
            QueryResult::Resolved(Rc::clone(lhs_value)),
            Some(QueryResult::Resolved(Rc::clone(rhs_value))),
            None,
        ),
        //},
        // The reason is carried rather than dropped. This arm bound the pair and discarded `reason`
        // through the `..`, so a key comparison that had no answer recorded a bare FAIL and the console
        // rendered it as "provided value [...] did not match expected value [...]" -- which asserts the
        // comparison was made and answered no. For a spent backtracking budget that is false, and it is
        // the sentence a rule author reads. Every other site that records a refusal already carries its
        // reason into the `Error Message` slot; this one is brought into line.
        ComparisonResult::NotComparable(NotComparableWithRhs {
            reason,
            pair:
                LhsRhsPair {
                    rhs: rhs_value,
                    lhs: lhs_value,
                },
            ..
        }) => (
            QueryResult::Resolved(Rc::clone(lhs_value)),
            Some(QueryResult::Resolved(Rc::clone(rhs_value))),
            Some(reason.clone()),
        ),
        //            },
        // The reason travels here too. With `None` the reporters rendered a key compared against a
        // value the retrieval never reached as "provided value [...] did not match expected value
        // [{}]", the map the retrieval stopped at standing in for a list the key was never compared
        // with; the record now says the right-hand side did not resolve, and where.
        ComparisonResult::UnResolvedRhs(unresolved) => (
            QueryResult::Resolved(Rc::clone(&unresolved.lhs)),
            Some(unresolved.rhs.clone()),
            unresolved.did_not_resolve_reason(),
        ),
    };

    Ok(if selected {
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

/// Records the `==` and `!=` evidence for one key against a right-hand side that is NOT a set: one
/// value, so one record. A set, of any length, goes to `report_by_lhs` as one record per key whatever
/// the operator written, so this never files one record per right-hand value.
///
/// One status per key, not one per record. The caller reads the statuses as the keys' verdicts and
/// selects a key's entry once per PASS it finds, so two records for one key would select its entry
/// twice; the records all carry the one verdict `selected`, and that verdict is returned once.
fn report_all_values<'r, 'value: 'r, 'loc: 'value>(
    comparisons: Vec<ComparisonResult>,
    selected: bool,
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &'r mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<(QueryResult, Status)>> {
    let mut status = None;
    for each_res in comparisons {
        let recorded = report_value(
            &each_res,
            selected,
            cmp,
            context.clone(),
            custom_message.clone(),
            eval_context,
        )?;
        status.get_or_insert(recorded);
    }
    Ok(status.into_iter().collect())
}

/// One record per left-hand value for the `IN` and `NOT IN` spellings, carrying the verdict `selected`
/// that `key_filter::select_key` reached. The fold -- one match for `IN`, every comparison for
/// `NOT IN` -- is `key_filter::key_selected_from`'s, not this function's, so that the two engines cannot
/// fold differently.
///
/// Groups by left-hand value in a `HashMap` and iterates it, so the order statuses come out in is
/// not defined. That is not observable today because `real_binary_operation` calls this once per key
/// and each call therefore yields one status. Do not widen a caller to hand it several left-hand
/// values at once without sorting the groups first, and without giving each its own verdict.
fn report_by_lhs<'r, 'value: 'r, 'loc: 'value>(
    rhs_comparisons: Vec<ComparisonResult>,
    selected: bool,
    undecided: Option<&str>,
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
            // The reason itself is read below, off `results`, rather than collected here. Grouping is
            // per left-hand value and the record is per left-hand value, so the reason has to be the
            // one belonging to THIS key -- collecting into a single variable while walking every
            // pairing would let one key's refusal be reported against another's failure.
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
        match selected {
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

                // The reason travels with the record, which is what `report_value` does for the `==`
                // and `!=` spellings of this same question. With `message` left `None` a key whose
                // comparison had no answer would be rendered by the reporters as one that was compared
                // and came out wrong: `NOT IN` printing "provided value [...] did match expected value
                // in [...]", asserting a success about a comparison fancy_regex abandoned, and `IN`
                // printing the mirror.
                //
                // The first refusal among this key's pairings, and only when the fold came out false
                // AND no pairing matched. A key that satisfied the clause has a verdict that did not
                // rest on the pairing that failed, so there is nothing to explain -- the same
                // precedence the `Comparable` arm of `satisfies` already applies. A key kept out of a
                // `NOT IN` because one pattern matched it is in the same position: the match decided
                // it, the pairing the engine abandoned did not, and a record saying the comparison
                // "could not be evaluated" would describe a verdict that was reached. The record then
                // reads as a plain match, which is what happened. First rather than all, because a
                // clause names one pattern in practice and the scalar arm reports one reason too.
                let settled_by_a_match = results.iter().any(|(r, _)| {
                    matches!(
                        r,
                        ComparisonResult::Comparable(ComparisonWithRhs { outcome: true, .. })
                    )
                });
                let refused = if settled_by_a_match {
                    None
                } else {
                    results.iter().find_map(|(r, _)| match r {
                        ComparisonResult::NotComparable(NotComparableWithRhs {
                            reason, ..
                        }) => Some(reason.clone()),
                        _ => None,
                    })
                };

                // The elements this key was equal to, so a written `!=` can be reported as the
                // equality it is: "a is equal to [a], one of [a, b]" names the element that excluded
                // the key and no other. One record per key carries the whole set in `to` and these in
                // `matched`; a record per element, each stamped with the key's one verdict, filed
                // "a is equal to b" for the element the key was NOT equal to.
                let matched = results
                    .iter()
                    .filter_map(|(r, rhs)| match r {
                        ComparisonResult::Comparable(ComparisonWithRhs {
                            outcome: true, ..
                        }) => Some(rhs.clone()),
                        _ => None,
                    })
                    .collect::<Vec<QueryResult>>();

                // A key kept out only by a right-hand value the query could not reach is a comparison
                // nobody finished, and the record says so, in the one text the fold fails the filter
                // on (`did_not_resolve_reason`): where the retrieval stopped, what was left of the
                // query, and the retrieval's own explanation when it left one, so the summary says the
                // right-hand side did not resolve instead of claiming a verdict about a comparison that
                // never ran. The record took its reason from refusals alone once: a `!=` against a set
                // with an unreachable entry recorded no reason and an empty `matched`, and the
                // renderers read that as an equality to an empty list, "is equal to [], one of [...]".
                // Only when nothing else explains the verdict: a key that was refused has its refusal,
                // and a key that equalled a resolved element has its equality, and the unreachable
                // entry unsettles neither.
                let unreachable = results.iter().find_map(|(r, _)| match r {
                    ComparisonResult::UnResolvedRhs(unresolved) => {
                        unresolved.did_not_resolve_reason()
                    }
                    _ => None,
                });
                // The reason the fold failed the filter on comes first, when it failed, so the record
                // and the error that decided the clause say the same thing. The fold fails on the first
                // comparison it could not finish, and that need not be the first refusal among the
                // key's pairings: a string key `IN [1, <unresolved>]` is refused by the integer first, a
                // kind mismatch the fold reads as "no answer" and goes past, and fails on the unresolved
                // value after it. Taking the first refusal here put the kind mismatch in the summary
                // while the exit code rested on the unresolved right-hand side. Only when the fold did
                // not fail does the record fall back to the refusal, the equality or the unreachable
                // entry, in that order, and only when the fold came out false.
                let reason = match undecided {
                    Some(reason) => Some(reason.to_string()),
                    None => match (refused, matched.is_empty()) {
                        (Some(refusal), _) => Some(refusal),
                        (None, true) => unreachable,
                        (None, false) => None,
                    },
                };

                eval_context.end_record(
                    &context,
                    RecordType::ClauseValueCheck(ClauseCheck::InComparison(InComparisonCheck {
                        from: QueryResult::Resolved(Rc::clone(lhs)),
                        to: to_collected,
                        matched: Some(matched),
                        message: reason,
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

/// `role` decides what a positive comparison against an empty reference reports: it
/// is unsatisfiable, so it fails as an [`ClauseRole::Assertion`] but must stay a SKIP
/// as a [`ClauseRole::Gate`]. See [`ClauseRole`] for why failing a gate is unsafe.
// Nine arguments, two over the lint's limit; the last two are `location` and `match_all`. `location` is
// there for the deprecation notice at the bottom and `match_all` for both that notice and
// `undecided_gate` beside it. Two ways to get back under it were considered and both cost more than the
// lint does.
//
// Folding either into `context` is the obvious one and it is not a refactor, it is a behaviour change:
// `context` is what every record in this function is filed under and what the reporters print, so widening
// it moves report text and the golden files with it. This change is diagnostics only.
//
// Taking `&AccessClause` in place of `lhs_query`, `custom_message`, `location` and `match_all` -- all four
// are its fields or its query's, and the one call site has it -- would reach five. That is a better
// signature and it rewrites the interior of a four-hundred-line function to reach a lint limit, with no
// behavioural gain and a real chance of a transcription error in the arms that clone `custom_message`.
// Worth doing on its own, next to nothing else.
#[allow(clippy::too_many_arguments)]
fn binary_operation<'value, 'loc: 'value>(
    lhs_query: &'value [QueryPart<'loc>],
    rhs: &[QueryResult],
    cmp: (CmpOperator, bool),
    context: String,
    custom_message: Option<String>,
    eval_context: &mut dyn EvalContext<'value, 'loc>,
    role: ClauseRole,
    // Where the clause is written, for the notice below and nothing else.
    location: &FileLocation<'loc>,
    // Whether the query needs every value or any one of them, which is what "did this clause pass" means
    // for it. Passed in rather than read off `lhs_query`, because that is the `query` field alone while the
    // flag lives on the `AccessQuery` around it; the single caller has both. Read by the notice at the
    // bottom and by `undecided_gate` beside it, which asks a different question of it -- see there.
    match_all: bool,
    // Where the right-hand query enumerated a collection, so the values in `rhs` are the entries of one
    // set rather than the one value the query names. Reported by the retrieval that produced `rhs` and
    // passed by the caller for `IN` only, because the resolved values cannot say: `Types[*]` over a
    // one-entry list and `Types[0]` deliver one identical `QueryResult`. `IN` reads it to compare
    // against the set as a whole, the way
    // it compares against a written-out list, and the membership notice reads it to walk the same
    // pairings. `Names` for every other operator and for a literal.
    rhs_enumerates: RhsEnumeration,
    // Whether the resolved `Rc`s in `rhs` are the same ones every evaluation of this clause reads: true
    // for a bare `%v`, whose values the scope memoizes, false for an inline query or a `%v` with parts
    // after it, which the walk re-materializes each time. `IN` caches its entry sets only for the former.
    rhs_shared: bool,
) -> Result<EvaluationResult> {
    let (mut lhs, _, passed_on) = eval_context.query_with_shape(lhs_query)?;
    // A left-hand side that is the empty selection a one-object filter left, handed on bare (`this ==
    // 'x'` in a block body running over it, `%v == 'x'` over `let v = this`): the clause read the
    // selection, so it is not judged as one that decided on nothing read from it
    // (`EmptySelection::clause_decided`); the comparison itself is decided below over no value, as the
    // arms below decide an empty left-hand side. The read is decided as the unary clause's bare read is
    // (`LacksKeysNote::refuse_bare_read`): refused over an object that holds an entry the predicate
    // compared against, or whose list twin could not be evaluated (`{ this == 'x' }` over `{ Env: { Ref:
    // P }, Team: platform }` under `[ Key == 'Env' ]` is refused as `{ this !empty }` is; the twin
    // compares the pair), kept over every other object. Outside a filter predicate the held refusal is
    // the clause's; inside one its marker joins the left-hand side and the `LhsUnresolved` arm below
    // reads it undecided, so the enclosing clause fails closed. The right-hand side gets the same reading
    // from the caller (`eval_guard_access_clause`), so `%allowed == this` is the read `this == %allowed`
    // is.
    let in_predicate = eval_context.in_predicate();
    passed_on.read_bare(in_predicate, &mut lhs)?;
    // A refused bare read on the RIGHT-hand side inside a filter predicate arrives as the refusal's
    // marker among the right-hand values (the caller pushes it; outside a predicate the refusal is the
    // clause's own error), and so does a refusal a CAPTURE holds: an enumeration whose walk was refused
    // cuts its captures back to the refusal's marker (`eval_context::enumerate_under_an_own_key_filter`,
    // `captures_after_a_refused_walk`), the clause's error is held by an `or`, and a sibling clause reads
    // `%x` as a plain assertion, the marker among its values beside whatever a same-name capture bound
    // before. The marker is not a value, so no pair against it is decided, and an absent left-hand value
    // beside it decides nothing either (the `LhsUnresolved` arm reads the marker's reason, not a decided
    // failure), so `Properties.Missing == %env` and `%env == Properties.Missing` are both unknown and fail
    // closed. Read here, before the comparison, and applied to the evidence
    // after it, by the comparator and the quantifier (the block above `undecided_gate` below). The
    // refusal's marker only (`refused_read_reason`, through `UnResolvedKind::is_refusal`) for `==`, `!=`
    // and the orderings: the marker a key filter nobody could decide leaves, or a capture refused inside
    // a predicate (`to_undecidable_result`, `refused` unset), is a value's own unresolved answer and is
    // read pair by pair by the `RhsUnresolved` arm, which records it undecided for that pair and leaves
    // every decided pair decided; read here as well it wiped the decided failures beside it, so `when Y
    // == Maps.*[ keys == /re/ ].*` with one key the regex could not be run over and one resolved `x`
    // beside it failed its rule closed where the control is not applicable. Membership and the
    // set-vs-set `==` read either kind (`rhs_marker` below): `Y IN {x, ?}` is a YES on `x` and unknown
    // otherwise whichever kind of unknown `?` is, and two sets whose only mismatch is on the left may be
    // equal through `?` whichever kind it is.
    let rhs_refused = rhs.iter().find_map(|value| match value {
        QueryResult::UnResolved(unresolved) => refused_read_reason(unresolved),
        QueryResult::Resolved(_) | QueryResult::Literal(_) => None,
    });
    let rhs_marker = rhs.iter().find_map(|value| match value {
        QueryResult::UnResolved(unresolved) => undecidable_reason(unresolved),
        QueryResult::Resolved(_) | QueryResult::Literal(_) => None,
    });
    // A marker of either kind among the LEFT-hand values (`%names != Properties.Missing`, the refused
    // selection compared against a document value; `%cfg == Properties.Missing` with a key filter's
    // marker in `%cfg`): an absent right-hand value then decides nothing, as an absent left-hand value
    // decides nothing beside a marker on the right, since the value the marker hides may be what the
    // absent one would have compared against. The `LhsUnresolved` arm reads the marker itself undecided;
    // this flag keeps the `RhsUnresolved` arm from calling the pairs beside it decided, so the clause is
    // unknown in both spellings, `%names != Properties.Missing` and `Properties.Missing != %names` alike.
    let lhs_marker = lhs.iter().any(|value| match value {
        QueryResult::UnResolved(unresolved) => undecidable_reason(unresolved).is_some(),
        QueryResult::Resolved(_) | QueryResult::Literal(_) => false,
    });
    // Computed here and emitted at the bottom, because neither end of the comparison has both halves
    // of the condition.
    //
    // It has to be computed before, because the incomparability is not recoverable from the result:
    // the not-flag has already turned "no element matched" into a success by then, and a success from
    // an incomparable operand looks exactly like a real one. Only `NOT IN` reaches this, so the extra
    // comparisons cost nothing on any other clause.
    //
    // It has to be emitted after, because the notice says the clause *passed* on the incomparability and
    // there is no verdict here to check that against. Gated on the incomparability alone it printed that
    // beside a FAIL, which is the opposite of what happened. Measured across 231 `NOT IN` shapes: 177
    // reach the notice, 146 pass and 31 fail, and every one of the 31 printed it.
    //
    // `IN` is built here with the shape of its right-hand side, which `CmpOperator`'s dispatch has no way
    // to carry; every other operator goes through that dispatch unchanged. Built once, with the entry
    // sets of an enumerating right-hand side inside it, and read by the notice predictor and the
    // comparison alike. Two cases: a bare `%v` right-hand side resolves to the same `Rc`s on every
    // evaluation, so its sets come from the evaluation's cache and a type block or a filter that reads
    // one `let`-bound allowlist once per resource builds them once; an inline right-hand side resolves
    // to fresh `Rc`s each time, so its sets are built here and dropped with the operator, and nothing is
    // retained per resource.
    let in_operation = InOperation::shaped_with(rhs_enumerates, rhs, |values, shape| {
        if rhs_shared {
            eval_context.entry_candidates(values, shape)
        } else {
            Rc::new(EntryCandidates::new(values, shape))
        }
    });
    let membership_is_incomparable =
        cmp.1 && cmp.0 == CmpOperator::In && incomparable_membership_in(&lhs, rhs, &in_operation);
    let results = match cmp.0 {
        CmpOperator::In => (in_operation, cmp.1).compare(&lhs, rhs)?,
        _ => cmp.compare(&lhs, rhs)?,
    };
    // The first comparison the operator could not answer, as opposed to one it answered no.
    //
    // Collected while the results are walked because it is not recoverable afterwards. Both outcomes
    // arrive at the `NotComparable` arm below as `Status::FAIL`, and `EvaluationResult` carries
    // statuses and values -- nothing that says whether a FAIL was a verdict or an absence of one. The
    // reason is kept so the failure the gate produces can name the pattern or the operand kinds rather
    // than announcing an undecidable condition and stopping there.
    //
    // First rather than all of them, matching `is_one_of` and `elements_not_matched`: a clause naming
    // one reason is what the console renders for a clause anyway.
    let mut evidence = ResultEvidence::default();
    // Annotated, and bound before it is unwrapped. Every arm below is an `Ok(..)`, and the match is
    // not the tail expression, so the function's return type does not pin their error type; `?`
    // erases the error type through `From`, so without the annotation the arms infer nothing.
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
        // the `EmptyRhsUnsatisfiable` arm below answers. Read as a SKIP, `%x == 'abc'`, `%x != 'abc'`
        // and `%x > 5` exit 0 when `%x` holds no values, so a rule whose only check is one of those
        // reports compliance having compared nothing -- the same bypass, on the other operand. It
        // fails closed as an assertion, and stays
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
                // Carries the reason for the same purpose the arm above carries one. This branch is
                // reached with the query in hand and `is_empty()` already decided, so the fact is
                // known here and was simply not written down: `find_skip_reason` reads this message
                // off the `GuardClauseBlockCheck` the caller builds from it, and a `None` made a
                // clause-form empty selection report a SKIP with no reason at all.
                false => EvaluationResult::EmptyQueryResult(
                    Status::SKIP,
                    Some(empty_selection_message(lhs_query)),
                ),
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
        // contains none of the denied values. That reading is what a SKIP would encode, and
        // the weaker status is not free in the standalone case. What it costs is the
        // enforcement of the clause: a rule whose only check is `Property != %empty_reference`
        // would exit 0 having compared nothing, which is a denylist bypass rather than a
        // compliant result.
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
                // The statuses come from the one mapping `folded_verdict` also reads; the arms below
                // write the records that go beside them, one record per status, and nothing else. One
                // exception: under a POSITIVE `IN` a pair against an undecidable marker among the
                // right-hand values (`marker_pair_under_in`) files neither a status nor a record.
                // Membership is a YES on any one listed value, so that pair decides nothing about a value
                // a listed entry matched, and a FAIL status for it read `Tags[*] IN %names` over a pair
                // `%names` holds as unmatched under `match_all`, where the caller's fold fails on any
                // FAIL. The marker still reaches the evidence (the `RhsUnresolved` arm), so a value no
                // listed entry matched stays unknown. Every other comparator keeps the status: `==` holds
                // only when every pair holds, and the marker's pair never does; under `NOT IN` the pair's
                // FAIL denies a pass.
                let statuses = value_statuses(&each, cmp);
                // Per left-hand value, for the pre-pass over a marker among the right-hand values
                // (`ResultEvidence::every_value_decided_no`): which values a comparison against a
                // RESOLVED value or a refusal of kinds decided no, which values were seen at all, and
                // whether some left-hand value was absent or an empty collection (decided nothing beside a
                // marker). Only with a marker present: the sets are read by nothing else, and a
                // comparison with no marker pays nothing for them. The left-hand values come from the
                // result's own left operand, never from a diff: a `QueryIn` built by `==` through
                // `QueryIn::from_rhs` carries RIGHT-hand values in its `diff`, and read as left-hand
                // values they made one left value against two right ones look like two left values.
                if rhs_marker.is_some() {
                    match &each {
                        operators::ValueEvalResult::LhsUnresolved(_) => evidence.absent_lhs = true,
                        operators::ValueEvalResult::EmptyCollection { side, other, .. } => {
                            match side {
                                operators::EmptySide::Lhs => evidence.absent_lhs = true,
                                operators::EmptySide::Rhs => {
                                    if let Some(other) = other {
                                        evidence.note_value(other, true);
                                    }
                                }
                            }
                        }
                        operators::ValueEvalResult::ComparisonResult(comparison) => {
                            let decided_no = match comparison {
                                operators::ComparisonResult::Fail(_) => true,
                                operators::ComparisonResult::NotComparable(nc) => {
                                    matches!(nc.cause, operators::Unanswerable::IncomparableKinds)
                                }
                                operators::ComparisonResult::Success(_)
                                | operators::ComparisonResult::RhsUnresolved(..) => false,
                            };
                            match comparison {
                                operators::ComparisonResult::Fail(operators::Compare::QueryIn(
                                    qin,
                                ))
                                | operators::ComparisonResult::Success(
                                    operators::Compare::QueryIn(qin),
                                ) => {
                                    // Every left-hand value was seen; the ones decided NO are the
                                    // left-hand values a `Fail` names, which is its `diff` only when
                                    // the diff was taken from the left (`DiffFrom::Lhs`); a diff taken
                                    // from the right names right-hand values and decides no left value.
                                    for value in &qin.lhs {
                                        evidence.note_value(value, false);
                                    }
                                    if decided_no && qin.diff_from == operators::DiffFrom::Lhs {
                                        for value in &qin.diff {
                                            evidence.note_value(value, true);
                                        }
                                    }
                                }
                                _ => {
                                    for (value, _) in &statuses {
                                        if let QueryResult::Resolved(value)
                                        | QueryResult::Literal(value) = value
                                        {
                                            evidence.note_value(value, decided_no);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                statues.extend(statuses);
                match each {
                    // A value the query could not produce. Decided rather than undecided when the
                    // property is absent, which is a fact about the document, and the comparison then
                    // fails on it definitively; recording it as decided is also what keeps a gate over an
                    // absent property reporting the rule as not applicable, which is where it already
                    // was. Undecided when the value is the undecidable marker a key filter leaves for a
                    // map it could not decide (`UnResolvedKind::Undecidable`): nobody knows what that
                    // selection holds, so it cannot settle a gate as "not applicable" or deselect an
                    // entry; read as decided, `rule r when Cfg[ keys == %missing ].Enabled == true { .. }`
                    // reported SKIP at exit 0 with its body unchecked. The marker's reason is what
                    // `undecided_gate` raises, as the unary operators raise it through
                    // `undecidable_selection`. (Inside a filter predicate the marker arrives here as
                    // well, whether the filter was evaluated there or bound outside, and is read
                    // undecided, so the enclosing clause fails closed; see `undecidable_selection`.)
                    // The kind is read by `undecidable_reason`, with no clone and no catch-all arm.
                    operators::ValueEvalResult::LhsUnresolved(ur) => {
                        match (undecidable_reason(&ur), rhs_marker.as_ref()) {
                            (Some(reason), _) => {
                                if evidence.undecided.is_none() {
                                    evidence.undecided = Some(reason);
                                }
                            }
                            // An absent left-hand value beside a marker of either kind among the
                            // right-hand values decides nothing: the value the marker hides may be what
                            // the absent one would have compared against, so `[ Properties.Missing ==
                            // %cfg ]` with a key filter's marker in `%cfg` is unknown as `[ %cfg ==
                            // Properties.Missing ]` is.
                            (None, Some(reason)) => {
                                evidence.undecided.get_or_insert_with(|| reason.clone());
                            }
                            (None, None) => evidence.decided_failure = true,
                        }
                        eval_context.start_record(&context)?;
                        eval_context.end_record(
                            &context,
                            RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                ComparisonClauseCheck {
                                    status: Status::FAIL,
                                    message: None,
                                    custom_message: custom_message.clone(),
                                    comparison: cmp,
                                    from: QueryResult::UnResolved(ur),
                                    to: None,
                                },
                            )),
                        )?;
                    }

                    // A collection with nothing in it on either side, where the operator would have
                    // compared its elements. The collection is empty, which is a fact about the
                    // document, and the comparison fails on it the way it fails on a missing key.
                    // Filed with the empty collection as the subject, whichever side it was on, so
                    // the report names the resource whose collection was empty; the other side's
                    // value is what it was compared with.
                    //
                    // Decided, in every role, the same way a property the document lacks is decided
                    // by the `LhsUnresolved` arm above: an empty collection is a retrieval error, and
                    // a retrieval error is a decided no, not a comparison with no answer. An assertion
                    // fails on the value. A filter predicate deselects the entry, as it deselects an
                    // entry lacking the property. A `when` condition is not satisfied, and the rule is
                    // reported not applicable with this reason named, exactly as `when Ports <= 100`
                    // over a document with no `Ports` is. One route for both, so that `Ports: []` and
                    // a missing `Ports` on the same gate read the same way, this message's own
                    // sentence ("fails as a missing key does") holds, and one empty list cannot fail
                    // a rule whose other resources comply. `undecided` is left to the comparisons the
                    // engine abandoned.
                    //
                    // The status is `value_statuses`'s, filed above with every other result's; this
                    // arm writes the record beside it and nothing else, so the clause's statuses
                    // carry the empty collection once.
                    operators::ValueEvalResult::EmptyCollection {
                        side,
                        empty,
                        other: Some(other),
                    } => {
                        let reason = empty_collection_message(side, role);
                        evidence.decided_failure = true;
                        // A comparison against a resolved value only when the EMPTY collection is the
                        // right-hand one: an empty left-hand collection against the right decided
                        // nothing about what its elements would have compared against, like an absent
                        // left-hand value, so beside a refusal's marker `Tags: []` reads as a missing
                        // `Tags` does, both unknown. Set once a result reads a decided no and never
                        // cleared, so an empty left-hand collection that follows a collision in the
                        // results (the right-hand unresolved pairs come first, the collections after)
                        // cannot undo it, in either document order.
                        if matches!(side, operators::EmptySide::Rhs) {
                            evidence.comparison_failed = true;
                        }
                        eval_context.start_record(&context)?;
                        eval_context.end_record(
                            &context,
                            RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                ComparisonClauseCheck {
                                    status: Status::FAIL,
                                    message: Some(reason),
                                    custom_message: custom_message.clone(),
                                    comparison: cmp,
                                    from: QueryResult::Resolved(empty),
                                    to: Some(QueryResult::Resolved(other)),
                                },
                            )),
                        )?;
                    }

                    // The same, with nothing on the other side to show beside it: every value there
                    // was an empty collection too. No per-value record: a resolved `from` with no
                    // `to` is a shape the structured reporter drops (it builds a resolved comparison
                    // only when both values are present) and the console renders as a comparison
                    // against `null` in the summary and as a bare `to=` in the verbose tree, so a run
                    // that filed one exited 19 with "Number of non-compliant resources 0" and
                    // `"checks": []` in `-o json`. `value_statuses` files nothing for it either, so the
                    // clause reaches the compared-nothing arm below and is explained at the block
                    // level, which every reporter renders.
                    operators::ValueEvalResult::EmptyCollection { other: None, .. } => {}

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::RhsUnresolved(urhs, lhs),
                    ) => {
                        // Decided, for the same reason as the arm above: the reference resolved to
                        // nothing, and there is nothing undecided about comparing against nothing.
                        // Unless the nothing is the undecidable marker, which is the arm above's
                        // exception mirrored on the right-hand side.
                        match undecidable_reason(&urhs) {
                            Some(reason) => {
                                if evidence.undecided.is_none() {
                                    evidence.undecided = Some(reason);
                                }
                            }
                            // Unless a marker stands among the LEFT-hand values (`lhs_marker`): the
                            // value this pair compares against the absent one is resolved, but the value
                            // the marker hides beside it may be the one the absent right-hand value would
                            // have compared against, so the pair decides nothing about the clause; the
                            // marker's own `LhsUnresolved` arm read it undecided, and the clause is
                            // unknown as its mirror image is.
                            None if lhs_marker => {}
                            None => {
                                evidence.decided_failure = true;
                                evidence.comparison_failed = true;
                            }
                        }
                        // A marker paired with a value under a positive `IN` files no record, as it
                        // files no status (`marker_pair_under_in`): a clause that passed on a listed
                        // value would otherwise carry a failing child the reporters render as a finding
                        // under a passing clause. The marker still reached the evidence above.
                        if cmp == (CmpOperator::In, false) && undecidable_reason(&urhs).is_some() {
                            continue;
                        }
                        eval_context.start_record(&context)?;
                        eval_context.end_record(
                            &context,
                            RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                ComparisonClauseCheck {
                                    status: Status::FAIL,
                                    message: None,
                                    custom_message: custom_message.clone(),
                                    comparison: cmp,
                                    from: QueryResult::Resolved(lhs),
                                    to: Some(QueryResult::UnResolved(urhs)),
                                },
                            )),
                        )?;
                    }

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::NotComparable(nc),
                    ) => {
                        // The one arm that can be either. An abandoned evaluation is undecided; a
                        // refusal to compare kinds is a decided no, because rule authors write a value
                        // against both spellings it might carry and rely on the pairing that does not
                        // apply answering "no" rather than "unknown". See `Unanswerable` for what
                        // reading that one the other way costs.
                        match nc.cause {
                            operators::Unanswerable::EngineGaveUp => {
                                if evidence.undecided.is_none() {
                                    evidence.undecided = Some(nc.reason.clone());
                                }
                            }
                            operators::Unanswerable::IncomparableKinds => {
                                evidence.decided_failure = true;
                                evidence.comparison_failed = true;
                            }
                        }
                        eval_context.start_record(&context)?;
                        eval_context.end_record(
                            &context,
                            RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                ComparisonClauseCheck {
                                    status: Status::FAIL,
                                    message: Some(nc.reason),
                                    custom_message: custom_message.clone(),
                                    comparison: cmp,
                                    from: QueryResult::Resolved(nc.pair.lhs),
                                    to: Some(QueryResult::Resolved(nc.pair.rhs)),
                                },
                            )),
                        )?;
                    }

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::Success(cmp),
                    ) => match cmp {
                        // One success record per left-hand value a `QueryIn` carries, as
                        // `value_statuses` files one status per value; one for every other shape.
                        operators::Compare::QueryIn(qin) => {
                            // The accepted values, not the whole left operand: a `Success` can carry
                            // a value the operator refused beside the ones it matched, and only the
                            // matched ones passed. For a per-value record the two sets are the same
                            // one value.
                            for _ in &qin.accepted {
                                eval_context.start_record(&context)?;
                                eval_context.end_record(
                                    &context,
                                    RecordType::ClauseValueCheck(ClauseCheck::Success),
                                )?;
                            }
                        }

                        operators::Compare::ListIn(_)
                        | operators::Compare::Value(_)
                        | operators::Compare::ValueIn(_) => {
                            eval_context.start_record(&context)?;
                            eval_context.end_record(
                                &context,
                                RecordType::ClauseValueCheck(ClauseCheck::Success),
                            )?;
                        }
                    },

                    operators::ValueEvalResult::ComparisonResult(
                        operators::ComparisonResult::Fail(cmpr),
                    ) => {
                        // Every shape under here is a comparison the operator performed and answered
                        // no. Recorded once for the whole arm rather than in each of its four branches:
                        // they differ in what they report, not in whether the answer exists. One
                        // exception: `==` between two value SETS (`QueryIn`, `X[*] == %ref`) beside an
                        // undecidable marker among the right-hand values is decided no only when a
                        // RESOLVED right-hand value has no equal on the left (`QueryIn::rhs_unmatched`),
                        // since the sets then differ whatever the marker hides; with every resolved
                        // right-hand value matched, the left-hand value with no resolved equal may be the
                        // one the marker hides, or the marker may be one more element on the right, so
                        // the comparison is not decided by its resolved values and the marker's reason
                        // stands as the clause's. Either marker kind: the question is whether an unknown
                        // value may make two sets equal, which its kind does not change. `!=` is not read
                        // here: its `Fail` is the left-hand values that collide with a RESOLVED right-hand
                        // value, a no the marker cannot undo. A `QueryIn` over NO left-hand value (every
                        // left-hand value was absent, and the operator still diffed the right-hand values
                        // against nothing) compared nothing and decides nothing here: each absent value
                        // carries its own verdict through the `LhsUnresolved` arm, decided or not as the
                        // marker beside it says, and a decided failure about a comparison that never ran
                        // read `[ Properties.Missing == %names ]` as decided beside the marker, where its
                        // `!=` twin is unknown.
                        let decided = match &cmpr {
                            operators::Compare::QueryIn(qin) => {
                                let set_undecided = cmp == (CmpOperator::Eq, false)
                                    && rhs_marker.is_some()
                                    && qin.rhs_unmatched.is_empty();
                                !(qin.lhs.is_empty() || set_undecided)
                            }
                            operators::Compare::Value(_)
                            | operators::Compare::ValueIn(_)
                            | operators::Compare::ListIn(_) => true,
                        };
                        if decided {
                            evidence.decided_failure = true;
                            evidence.comparison_failed = true;
                        } else if let Some(reason) = rhs_marker.as_ref() {
                            evidence.undecided.get_or_insert_with(|| reason.clone());
                        }
                        match cmpr {
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
                                            from: QueryResult::Resolved(pair.lhs),
                                            to: Some(QueryResult::Resolved(pair.rhs)),
                                        },
                                    )),
                                )?;
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
                                            from: QueryResult::Resolved(pair.lhs),
                                            to: vec![QueryResult::Resolved(pair.rhs)],
                                            matched: None,
                                        },
                                    )),
                                )?;
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
                                            from: QueryResult::Resolved(lin.lhs),
                                            to: vec![QueryResult::Resolved(lin.rhs)],
                                            matched: None,
                                        },
                                    )),
                                )?;
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

                                // The values the operator accepted get a PASS each, exactly as the
                                // `Success(QueryIn)` arm above records them. Without this the arm
                                // recorded the diff and nothing else, so a `some` clause -- which the
                                // fold passes on any one PASS -- had nothing to pass on, and
                                // `some X[*] IN Y[*]` answered as `X[*] IN Y[*]`: FAIL whenever any
                                // left-hand value was unmatched. The literal-right arms record one
                                // result per value and never had the gap. Under `all` this moves no
                                // verdict, since the FAILs below still decide it.
                                //
                                // Read off the result rather than by expanding the operator into
                                // per-element results, which the two-query `IN` arm's own comment
                                // records as the change that turns "any of these" into "all of these".
                                // The operator says which values it accepted; a value it could not
                                // answer is in no rejected set and must not read as accepted.
                                for matched in qin.accepted.iter().cloned() {
                                    eval_context.start_record(&context)?;
                                    eval_context.end_record(
                                        &context,
                                        RecordType::ClauseValueCheck(ClauseCheck::Success),
                                    )?;
                                    statues.push((QueryResult::Resolved(matched), Status::PASS));
                                }

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
                                                from: QueryResult::Resolved(lhs),
                                                to: rhs.clone(),
                                                matched: None,
                                            },
                                        )),
                                    )?;
                                }
                            }
                        }
                    }
                }
            }
            // Values on both sides and not one pair between them: every value on both sides was a
            // collection with no element, so no per-value record could be filed. A failure that
            // explains itself at the block level, in every role: an assertion fails, a filter
            // predicate deselects, and a `when` condition is not satisfied and leaves its rule not
            // applicable with this reason, as the per-value arm above decides for one empty
            // collection.
            //
            // `IN` included: an empty left-hand collection is answered per value on `IN` as on every
            // other operator, so a membership clause that compared nothing is explained the same way
            // rather than passing vacuously.
            if statues.is_empty() {
                // Every right-hand value an undecidable marker under a positive `IN` (a capture that
                // holds a refusal's marker alone, read as `%x`; a key filter that could decide none of
                // its maps): every pair filed no status, so there is nothing to fold and nothing to
                // compare, and the clause's answer is the marker's own reason, whatever the role: an
                // assertion fails on it, a gate or a predicate fails closed on it, where a "compared
                // nothing" reason named the wrong cause.
                match rhs_marker.as_ref() {
                    Some(reason) => Err(Error::UndecidableComparison(reason.clone())),
                    None => {
                        let reason = nothing_to_compare_message(&context, role);
                        Ok(EvaluationResult::EmptyQueryResult(
                            Status::FAIL,
                            Some(reason),
                        ))
                    }
                }
            } else {
                Ok(EvaluationResult::QueryValueResult(statues))
            }
        }
    };
    let outcome = outcome?;

    // A gate whose comparison had no answer keeps the error instead of answering FAIL.
    //
    // This is the same fail-open `ClauseRole::Gate` exists to prevent, reached through the one channel
    // that was not carrying it. `is_unevaluatable` recognises `IncompatibleError`, so `!EMPTY` against a
    // boolean already fails a gate closed. A comparison that could not be decided never becomes an
    // `Error` at all: `is_one_of` promotes a spent backtracking budget to `Membership::Unanswerable`,
    // which arrives at the arm above as a per-value `Status::FAIL`. One level out `eval_rule` and
    // `eval_when_condition_block` map every non-PASS condition to SKIP, so the body was dropped at exit
    // 0. Measured on a `Cat` of one thirty-character string of `a`s, every spelling leaking:
    //
    //     rule guarded when Cat NOT IN [[/(?!x)((a+)+)b/]] { MustBeTrue == true }   exit 0
    //     rule guarded when Cat NOT IN [/(?!x)((a+)+)b/]   { MustBeTrue == true }   exit 0
    //     rule guarded when Cat[*] NOT IN [/(?!x)((a+)+)b/] { MustBeTrue == true }  exit 0
    //     rule guarded when Enabled !EMPTY                 { MustBeTrue == true }   exit 19
    //     rule direct { MustBeTrue == true }                                        exit 19
    //
    // An error and not a status, which is the whole reason this works. `own_skip_reason` in
    // `eval_context.rs` reached the same diagnosis and concluded it could not be fixed, because "both
    // FAIL and SKIP on a condition drop the block it guards, so telling them apart needs a status that
    // means 'could not tell', which `Status` does not have". True of that site, which is a reporter. The
    // evaluator has such a channel: an `Err` is not folded by `eval_conjunction_clauses` into the FAIL
    // that outranks passing siblings -- it is held, discarded if a later disjunct decides the `or`, and
    // otherwise returned for the caller to split by role. That is exactly the shape the arms above want,
    // which is why `EmptyRhsUnsatisfiable` and its neighbours had to settle for SKIP-as-a-gate and this
    // does not.
    //
    // `UndecidableComparison`, and `is_unevaluatable` recognises it alongside `IncompatibleError`, so
    // every existing `(is_unevaluatable, is_strict)` site handles it with no new plumbing: a gate
    // propagates it and fails its own rule closed, and an outer assertion turns it into the FAIL that
    // keeps the rest of the file reporting.
    //
    // Its own variant rather than `IncompatibleError`, and the reason is the message.
    // `IncompatibleError` renders as "Types or variable assignments are incompatible `<reason>`", and
    // that claim is false here: the operands are of kinds the comparator has an arm for and the engine
    // quit part way. Both frames that print it would inherit the falsehood -- the rule frame would read
    // "not applicable: Types or variable assignments are incompatible `The regular expression could
    // not be evaluated ...`", and the filter frame would wrap the same sentence in "due to retrieval
    // error ... when handling clause, bailing". `UndecidableComparison` renders as its reason alone,
    // so each frame supplies its own framing and neither asserts a type mismatch.
    //
    // Gate only. An assertion already fails closed here and its report names the clause and the operand
    // values; converting would replace that with a rule-level failure and lose the comparison record.
    // `a_catastrophic_regex_asserted` and `the_whole_list_spelling_now_refuses` pin that half.
    //
    // An abandoned evaluation only, never a refusal to compare kinds, and that boundary is measured
    // rather than chosen for safety. Rule authors write a value against both spellings it might carry
    // and rely on the pairing that does not apply answering "no" rather than "unknown"; the registry's
    // `ScanOnPush == 'False' OR ScanOnPush == false` is the canonical shape. Reading a kind mismatch as
    // undecidable moves 143 rules of the pinned aws-guard-rules-registry corpus off their expectations,
    // most of them suppression tests expecting SKIP, where the comparator as written leaves 0 failed
    // rules. So the
    // kind-mismatch half of this defect stays open, tracked in `docs/KNOWN_ISSUES.md` behind the same
    // precondition `incomparable_membership_notice` already records -- those rules have to change first
    // -- and the notice is what covers it meanwhile. `Unanswerable` carries the split.
    //
    // That 143 is the cost of reading `IncomparableKinds` as an undecidable GATE, reached by `==` and
    // `!=` -- which is why the `ScanOnPush` idiom is its canonical shape. It is NOT the cost of
    // promoting the membership refusal, which is registry-free: measured by promoting
    // `is_one_of`'s `Err(_)` arm alone, the corpus stays byte-identical at 576794 bytes with all five
    // notices and 0 failed rules, and moves 19 clause verdicts instead. `Unanswerable`'s own doc in
    // `operators.rs` carries both figures and why neither route is open to a diagnostic fix.
    //
    // ALONE MEANS ALONE, and the 19 is not the price of the notice's destination. That arm is one of two
    // suppressions in series for any clause reaching `InOperation::compare`'s `(None, None)` arm:
    // promoting it turns `contained_in`'s answer from `Fail` into `NotComparable`, which that arm then
    // discards at the `_ => {}` of its `match contained_in(..)`. Measured with release
    // binaries, a build promoting that arm and `contained_in`'s scalar loop moves neither
    // `Ports NOT IN Uint` nor `some Iso[*] NOT IN Deny[*]`, while a build promoting the dropped result as
    // well takes both to FAIL. The first of that pair already sits in the tree at PASS beside its literal
    // `Ports NOT IN 5` at FAIL, so the understatement is visible without building anything. Price a
    // fail-closed release against the four-suppression oracle named above
    // `the_notice_asks_about_every_granularity_the_operator_decides_at`, not against this figure.
    //
    // The caller's fold is respected rather than preempted, which is the second thing `match_all` is read
    // for here, and both quantifiers have a value that decides the clause without the undecided ones.
    // `undecided_gate` holds the table and says which arm answers what.
    //
    // The marker read off the right-hand side above (`rhs_refused`, `rhs_marker`): no pair against it is
    // decided, and what the resolved pairs decided depends on the comparator and the quantifier. Under a
    // positive comparator a clause that passed is left alone (`IN` matched a listed value, a YES the marker
    // cannot undo, which is why the marker's pair files neither a status nor a record under a positive
    // `IN`, `marker_pair_under_in`: with a status, a matched value read as unmatched under `match_all`;
    // `==` holds only when every pair holds and the marker's pair never does, so it reaches no YES here),
    // and a clause that did not pass is
    // undecided unless a resolved pair decided it: a
    // comparison's no stays decided for every comparator but `IN`, where the marker may hold the match,
    // and a left-hand value that resolved to nothing (the `LhsUnresolved` arm) decided nothing, since the
    // refused value may be what it would have compared against. Under a negated comparator (`!=`, `NOT
    // IN`) a resolved match is a decided NO and stays one, a value that differs from every resolved
    // value is unknown, since it may equal the refused one (that PASS is not a pass, so it cannot settle
    // `some`, `passes_are_unknown`), and an absent left-hand value decided nothing, as under a positive
    // comparator; so under `match_all` the gate raises unless a resolved NO settles the clause, and under
    // `some` it raises unless EVERY left-hand value is a resolved NO (`settled_no`: no value can be the
    // one `some` passes on). Two value SETS compared under `==` (`QueryIn`, `X[*] == %ref`) are decided
    // no only when a RESOLVED right-hand value has no equal on the left (the `Fail` arm above reads
    // `QueryIn::rhs_unmatched`); a left-only mismatch, or two equal resolved sets, is unknown, since the
    // marker may hide the missing element or one more; under `!=` the sets are read value by value as
    // any other `!=` is (a resolved collision is a decided NO). A left-hand side that selected nothing
    // compared nothing, and its answer stands whatever the right-hand side holds. The first reason kept
    // is the comparison's own when it read one. For membership the marker of either kind drives this
    // block (`rhs_marker`), for every other comparator the refusal's alone (`rhs_refused`); the reads
    // above say why.
    let pre_pass = match cmp.0 {
        CmpOperator::In => rhs_marker,
        _ => rhs_refused,
    };
    if let (Some(reason), EvaluationResult::QueryValueResult(_)) = (pre_pass, &outcome) {
        if !cmp.1 {
            if !clause_passed(&outcome, match_all) {
                evidence.undecided.get_or_insert(reason);
                evidence.decided_failure = match cmp.0 {
                    CmpOperator::In => false,
                    _ => evidence.comparison_failed,
                };
            }
        } else {
            // Negated, in both quantifiers and whether or not any value passed: a resolved match is a
            // decided NO the marker cannot undo (`comparison_failed`), a pass may equal the refused
            // value (`passes_are_unknown`), and an absent left-hand value decided nothing (the
            // `LhsUnresolved` arm's failure is not a comparison, so `comparison_failed` is left as the
            // resolved pairs set it). Under `match_all` one decided NO settles the clause; under `some`
            // only every value decided NO does (`settled_no`), and any value without a resolved equal
            // leaves it unknown.
            evidence.undecided.get_or_insert(reason);
            evidence.passes_are_unknown = true;
            evidence.decided_failure = evidence.comparison_failed;
            evidence.settled_no = !match_all && evidence.every_value_decided_no();
        }
    }
    if let Some(reason) = undecided_gate(&outcome, evidence, match_all, role) {
        return Err(Error::UndecidableComparison(reason));
    }

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
    // with an empty report -- and, before this, an empty stderr with it -- while the same clause
    // asserted exits 19. So the one shape the notice exists for, a green file that quietly stopped
    // checking, was the shape it did not reach.
    //
    // The role is deliberately not consulted: `ClauseRole` does not carry whether the file reports the
    // clause, so asking it in place of the verdict would notice a failing `Gate` as an absorbed failure.
    // `ClauseRole`'s own documentation says what it answers --
    // whether an *unevaluatable* clause FAILs or SKIPs -- and reportedness is not it. Two `Assertion`
    // routes absorb a failure at exit 0, a disjunct beside a passing disjunct and `some`, so the role
    // does not even correlate with reportedness in one direction.
    //
    // Nor can reportedness be obtained here by asking something else, which is the more useful half. It
    // is a function of statuses this function returns before anything computes: an `or` is decided by a
    // sibling disjunct that may not have run -- `eval_conjunction_clauses` short-circuits on the first
    // PASS, so in `Other == 5 or Ports NOT IN [1, 3]` the second disjunct is never evaluated at all --
    // and a gate clause appears in the report exactly when some later clause in the same rule fails.
    // Measured: with the failing sibling inside the rule the report names the gate clause, and with it
    // moved to a second rule the report does not. Neither fact exists yet at this line.
    //
    // It is not needed. The notice says a future release fails closed where this one passes, so it
    // belongs on the clauses whose answer that change moves. A clause that does not pass today does not
    // move, and that is measured rather than argued: `!=` already fails closed, so the destination is
    // observable now, and a clause that already reaches `NotComparable` answers the same as one that
    // fails on a named element -- FAIL asserted, and the rule skipped at exit 0 as a gate.
    // `the_notice_fires_exactly_where_fail_closed_moves_the_answer` pins that against the fail-closed
    // spelling of each shape, so it goes red if the language stops agreeing.
    //
    // So the gate is the verdict, and the verdict alone -- which is what it was before the role joined it.
    // Read under the query's own `match_all`, because "did this clause pass" means one value for `some`
    // and every value otherwise; `clause_passed` says why that is not interchangeable with `all(PASS)`,
    // and what the difference costs.
    if membership_is_incomparable && clause_passed(&outcome, match_all) {
        eval_context.record_deprecation(incomparable_membership_notice(&context, location));
    }

    Ok(outcome)
}

/// What the per-value results carried, beyond the statuses [`EvaluationResult`] holds.
///
/// Both fields answer questions the status vector cannot. A value whose comparison had no answer and a
/// value whose comparison answered no both arrive as `Status::FAIL`, so "was anything undecided" and
/// "was anything decided against" are indistinguishable after the fact. Collected in the loop that
/// builds the statuses, where each arm knows which of the two it is.
///
/// Grouped rather than passed as two parameters because they are only ever read together, by
/// [`undecided_gate`], and because a bare `Option<String>` beside a bare `bool` at a call site says
/// nothing about which is which.
#[derive(Default)]
struct ResultEvidence {
    /// The first reason a comparison could not be answered, if one could not.
    undecided: Option<String>,
    /// Whether some value's comparison was performed and answered no. A refusal to compare kinds counts
    /// here, not in `undecided`; see [`operators::Unanswerable`].
    decided_failure: bool,
    /// Whether a comparison answered no against a value the operator read: every `decided_failure` but
    /// the `LhsUnresolved` arm's, whose failure is a left-hand value that resolved to nothing, and an
    /// empty LEFT-hand collection's (the `EmptyCollection` arm with the empty side on the left), which
    /// compared nothing either. Set for a pair against an ABSENT right-hand value too (the `RhsUnresolved`
    /// arm: the absence is a fact about the document the comparison fails on), unless a marker stands
    /// among the left-hand values, where that pair decides nothing (`lhs_marker`). Read where a
    /// refusal's marker sits among the right-hand values ([`binary_operation`]'s pre-pass), which keeps
    /// such a no decided and drops the absence, since the refused value may be what the absent one would
    /// have compared against.
    comparison_failed: bool,
    /// Whether the clause's PASS statuses are not passes: a negated comparator (`!=`, `NOT IN`) with a
    /// refusal's marker among the right-hand values answers yes to a value that differs from every
    /// resolved value, which may still equal the refused one, so [`undecided_gate`] must not settle
    /// `some` on such a pass.
    passes_are_unknown: bool,
    /// Whether the clause is decided NO under `some` with a negated comparator beside a refusal's marker:
    /// every left-hand value equals some RESOLVED right-hand value (a decided no the marker cannot undo),
    /// so no value can be the one `some` passes on ([`undecided_gate`] declines; the entry is deselected).
    settled_no: bool,
    /// Whether some left-hand value was absent (`LhsUnresolved`) or an empty collection: beside a
    /// refusal's marker such a value decided nothing, since the refused value may be what it would have
    /// compared against, so no clause with one is settled by its values alone.
    absent_lhs: bool,
    /// Every distinct left-hand value a comparison result named, resolved or literal, by its key
    /// ([`ResultEvidence::key_of`]). Filled only while a marker stands among the right-hand values, the
    /// one case that reads it.
    lhs_seen: std::collections::HashSet<String>,
    /// The left-hand values some result decided NO against a resolved right-hand value (`Fail`, a
    /// refusal of kinds, an empty right-hand collection), a subset of `lhs_seen`, by the same key.
    lhs_decided_no: std::collections::HashSet<String>,
}

impl ResultEvidence {
    /// The key a left-hand value is recorded under: its path, which names one document value; for a
    /// value the rules file wrote (a literal, whose path is empty) the value's own rendering, so two
    /// literals never share a key.
    fn key_of(value: &PathAwareValue) -> String {
        let path = value.self_path();
        if path.0.is_empty() {
            format!("{value:?}")
        } else {
            path.0.clone()
        }
    }

    /// Record a left-hand value a result named, and whether that result decided it NO.
    fn note_value(&mut self, value: &Rc<PathAwareValue>, decided_no: bool) {
        // The test that pins the bookkeeping to comparisons with a marker counts the entries recorded
        // (`the_marker_bookkeeping_runs_only_beside_a_marker`); the counter lives beside the other probe
        // counters in `eval_context`, see there for why.
        #[cfg(test)]
        super::eval_context::MARKER_BOOKKEEPING_VISITS.with(|visits| visits.set(visits.get() + 1));
        let key = Self::key_of(value);
        if decided_no {
            self.lhs_decided_no.insert(key.clone());
        }
        self.lhs_seen.insert(key);
    }

    /// Whether every left-hand value was decided NO against a resolved right-hand value: no value absent
    /// or empty, at least one seen, and each one in `lhs_decided_no`. Under `some` with a negated
    /// comparator beside a refusal's marker, that is the clause decided NO.
    fn every_value_decided_no(&self) -> bool {
        !self.absent_lhs
            && !self.lhs_seen.is_empty()
            && self.lhs_seen.is_subset(&self.lhs_decided_no)
    }
}

/// The reason a gate has no answer, when that is what happened.
///
/// `None` means the clause may answer with a status. `Some(reason)` means the gate has no answer and
/// [`binary_operation`] must keep the error rather than report the FAIL its values carry.
///
/// # The table
///
/// This is three-valued logic over a quantifier, and writing it out is the only way to see that the two
/// arms are mirror images rather than one rule with a special case:
///
/// ```text
/// match_all  ->  no      if ANY value decided no
///                unknown if none did and some value is unknown
///                yes     if every value decided yes
/// some       ->  yes     if ANY value decided yes
///                unknown if none did and some value is unknown
///                no      if every value decided no
/// ```
///
/// Only the middle row of each is this function's business; the outer two are the status the caller's
/// fold already produces. So each arm asks for the value that *decides* the clause without consulting
/// the unknown ones, and declines when it finds one.
///
/// The first version of this had the `some` arm and no `match_all` arm, returning unknown whenever
/// anything was undecided. That is `AND(no, unknown) = unknown`, and the right answer is `no`: a clause
/// needing every value is decided the moment one value definitively fails. Measured on
/// `Cat = [<thirty a characters>, "zzz"]` against `Cat[*] NOT IN [/(?!x)((a+)+)b/, "zzz"]`, a rule gated
/// on that clause went from not-applicable to a reported violation -- an undecided sibling manufacturing
/// a verdict out of an already-decided conjunction.
/// `a_clauses_answer_follows_three_valued_logic_over_every_value_combination` pins all seven value
/// subsets against both quantifiers, because the change that introduced the defect was checked against
/// three shapes and both wrong cells were outside them.
///
/// # Why the yes arm borrows and the no arm does not
///
/// The yes arm is [`clause_passed`]'s own under the clause's quantifier, called rather than
/// reimplemented: "did any value pass" for `some` and "did every value pass" for `match_all` are the same
/// predicates over the same vector for both of us, and two copies that agree are the setup for the next
/// divergence. Under `match_all` that arm is reached by one shape, `IN` against a right-hand side holding
/// a refusal's marker: the marker's pairs file no status there ([`marker_pair_under_in`]), so a value
/// every listed entry was compared with and one matched reads PASS alone, and the clause is decided by
/// its values (`AND(yes, yes) = yes`). Every other undecided pair is a FAIL status, which denies it.
///
/// The no arm cannot borrow from it, and that is a difference of question rather than of answer.
/// [`clause_passed`] asks "did this clause pass", which decides eligibility for a notice about a future
/// release. This asks "is this clause still undecided", whose `match_all` answer also turns on a decided
/// *failure* -- a question about the FAILs, not the PASSes, and one the status vector cannot answer at all
/// without [`ResultEvidence`], since a value whose comparison had no answer and a value whose comparison
/// answered no both arrive as FAIL.
///
/// # Disjoint from the notice
///
/// By construction, with one named exception. This fires only when `undecided` is `Some`, which two
/// things set: an arm of the comparison that pushes a `Status::FAIL` for the value it could not decide
/// (or, under a positive `IN`, no status at all for the pair against a marker), the `Fail` arm's reading
/// of `==` between two value sets beside a marker (a left-only mismatch, undecided), and the pre-pass
/// over a marker among the right-hand values ([`binary_operation`]), which sets it over a positive clause
/// that did not pass and over every negated clause beside a marker (`passes_are_unknown`). Under
/// `match_all` the notice needs every value PASS: a FAIL denies it, a positive clause that did not pass
/// denies it, and where every value did pass this declines outright, so the two agree the clause is
/// decided. Under `some` the notice needs one PASS: this declines outright when there is one and the
/// passes are passes. The exception: a `some` clause with a negated comparator beside a marker whose values passed is RAISED here although
/// the notice's own test (`clause_passed`) would call it passed; the two disagree by construction, and the
/// raise wins by ordering (this runs first, and the raise returns before the notice is considered).
/// `a_some_clause_beside_a_refused_value_is_never_eligible_for_the_notice` pins that such a clause reaches
/// no notice: the raise is the refusal's fail-closed answer, and a notice about a future fail-closed
/// release would describe a clause that already fails closed. So the early return never suppresses a
/// notice that would otherwise have gone out on a decided clause.
///
/// Takes the evidence by value: the caller has no use for it once this declines, and threading a
/// reference would make the `Err` construction clone a string on the path that is about to fail.
fn undecided_gate(
    result: &EvaluationResult,
    evidence: ResultEvidence,
    match_all: bool,
    role: ClauseRole,
) -> Option<String> {
    let reason = evidence.undecided?;

    // An assertion is decided by its statuses: every undecided pair but one is a FAIL status, which fails
    // the clause under `match_all` and denies that value under `some`. The one exception is `some` with a
    // negated comparator beside a marker among the right-hand values: a value that differs from every
    // resolved value reads PASS, and under `some` one PASS decides the clause, although that value may
    // equal the refused one (`passes_are_unknown`); so `some Cfg.Name NOT IN %x` with the marker in `%x`
    // passed on a name no resolved key equals. Raised here, as a filter predicate and a gate are, so the
    // assertion fails on the marker's reason; every other assertion keeps its fold.
    if role.is_strict() {
        if !match_all && evidence.passes_are_unknown && !evidence.settled_no {
            return Some(reason);
        }
        return None;
    }

    // `some` with a negated comparator beside a refusal's marker, every left-hand value a decided NO
    // against a resolved right-hand value: no value can be the one `some` passes on, whatever the marker
    // holds, so the clause is decided NO (the pre-pass's `settled_no`).
    if evidence.settled_no {
        return None;
    }

    // `some` is decided by any value that passed, and `match_all` by every value passing, so an
    // undecided sibling changes nothing; unless the passes are not passes (a negated comparator against
    // a refused right-hand value, where a value that differs from every resolved value may still equal
    // the refused one). Under `match_all` every value PASS beside an undecided reason is reached by `IN`
    // alone, whose pairs against a refusal's marker file no status (`marker_pair_under_in`); every other
    // undecided pair is a FAIL status, which denies it.
    if !evidence.passes_are_unknown && clause_passed(result, match_all) {
        return None;
    }

    // `match_all` is decided by any value that failed for a reason, which is the mirror of the line
    // above and the arm that was missing.
    if match_all && evidence.decided_failure {
        return None;
    }

    Some(reason)
}

/// True when the clause reached PASS, under the `match_all` its query was written with.
///
/// The clause and not any one value, because the notice this gates makes a claim about the clause --
/// "`<clause>` passed" -- and the clause is what the coming fail-closed change will or will not move. How
/// many values that takes is the query's own question: `match_all` needs every one, `some` needs one, and
/// this matches the fold the caller applies to these same statuses to get the status it reports.
///
/// Reading `all(PASS)` for both was tried, on the argument that the two agree wherever this notice can
/// fire: a value only collides with an element it can be compared with, so a genuine incomparability
/// should mean no collision and every value passing. **That argument is wrong, and the counterexample is a
/// spent regex budget.** `match_value` promotes `RegexError`, so a value can fail on a pair that is
/// neither a collision nor an incomparability -- comparable in kind, engine gave up.
/// `some Multi.*.V NOT IN [/re/]` over a thirty-character `a` string and the list `[1, 2]` is exactly
/// that: the string's pair exhausts the budget and fails, the list's ints refuse against the pattern, and
/// the clause reaches PASS on the list. An `all(PASS)` reading is silent there, and it is silent on a true
/// positive. `a_refusing_pair_beside_a_spent_budget` is that cell.
///
/// So the two readings are not interchangeable. This one carries no cost of its own: under a predicate
/// that compared whole values it would let `some` reach the whole-value false-alarm class, where a list is
/// incomparable entire while its elements are not, so `some Resources.*.Properties.Ports NOT IN [1, 3]`
/// over `[1, 2]` and `[7, 8]` would warn on a clause every pair of which is int against int. That noise
/// would come from the predicate's granularity rather than from this reading of the verdict, and the
/// element-wise predicate rules it out -- `a_some_clause_one_value_of_which_fails` is that clause,
/// expecting silence, and `a_some_clause_that_passes_on_a_refusal` beside it is the shape this reading
/// exists for.
///
/// An empty result is not a pass under either reading. Nothing decided means nothing passed, and a notice
/// saying otherwise would be the same defect with a different cause. Unreachable from the notice as
/// things stand -- `incomparable_membership` answers false unless some left-hand value resolved, and a
/// resolved value produces a status -- so it is a guard against a future caller rather than a case in
/// play.
fn clause_passed(result: &EvaluationResult, match_all: bool) -> bool {
    match result {
        EvaluationResult::EmptyQueryResult(status, _) => *status == Status::PASS,
        EvaluationResult::QueryValueResult(values) => {
            !values.is_empty()
                && match match_all {
                    true => values.iter().all(|(_, status)| *status == Status::PASS),
                    false => values.iter().any(|(_, status)| *status == Status::PASS),
                }
        }
    }
}

/// Compares the keys of a map against a right-hand side, for `[ keys <op> ... ]` filters.
///
/// The narrowed `MapKeyComparator` rather than a `(CmpOperator, bool)` pair: this function's only
/// caller is `QueryPart::MapKeyFilter`, the parser admits four comparators there, and the wider
/// type left four arms here that nothing could reach. See the type's own comment for why that
/// mattered.
#[allow(clippy::too_many_arguments)]
pub(super) fn real_binary_operation<'value, 'loc: 'value>(
    lhs: &[QueryResult],
    rhs: &[QueryResult],
    // What the retrieval that produced `rhs` reported about its shape (`ShapeNotes`): whether it
    // enumerated or selected (`%r[*]`, `KeyList[*]`, a filter), and which maps the author's `[*]`
    // handed on unchanged as the last part, by path. The values cannot say: `%r[*]` over a one-element
    // binding delivers the one `RangeChar` a bare `r[a,f]` does, and `Names[*]` over a map and over a
    // one-element list of maps deliver one map each. `Names` and no map for a literal and for a
    // function call.
    rhs_shape: RhsEnumeration,
    rhs_passed_on: &PassedOn,
    cmp: MapKeyComparator,
    // The filter's `keys` keyword, the site a notice about this filter is recorded once for.
    site: &FileLocation<'_>,
    context: String,
    custom_message: Option<String>,
    eval_context: &mut dyn EvalContext<'value, 'loc>,
) -> Result<EvaluationResult> {
    let mut statues: Vec<(QueryResult, Status)> = Vec::with_capacity(lhs.len());
    // The first key comparison that had no answer, if any had none. See the return below.
    let mut undecided: Option<String> = None;
    // The right-hand side as written, before the normalization and the expansion below: the earlier
    // engine counted these values to decide whether a written `==` was membership, and
    // `containment_move` reads that count. Nothing else reads this name; the comparator below reads
    // `rhs_normalized`, and the comparisons read the expanded `rhs`.
    let rhs_raw = rhs;

    // A right-hand entry the retrieval left as the marker of an enumeration over an EMPTY collection is
    // not a value the filter could not read; it is a collection with nothing in it. `Names[*]` over
    // `Names: []` has no entry to hand on, so the retrieval leaves the empty list itself as the value the
    // query stopped at, typed `EmptyEnumeration`, and read as an unresolved right-hand side that marker
    // was a comparison nobody decided: no key was selected under any comparator, and the rule did not
    // apply. A null is the same nothing. Both are dropped by `key_filter::normalize_rhs`, the one place
    // that reads them, which the legacy resolver's key-filter arm asks as well, so the two engines read
    // an empty right-hand side alike. An entry that stopped at a value with something in it, or at an
    // empty collection with a key still to find (an absent parameter, a member without the field, an
    // index past the end), is an unresolved right-hand side, and `select_key` below fails the filter
    // closed on it, naming the path. A map the query named is read there as its key set, and a map the
    // query enumerated to as a member; `rhs_shape` tells the two apart per value: the maps the last
    // part's `[*]` passed on unchanged are named, every other map under a last-part enumeration is a
    // member, and a map under no enumeration or under an earlier part's is named.
    let normalized = key_filter::normalize_rhs(rhs_raw, rhs_shape, rhs_passed_on);
    let rhs_normalized = &normalized.values;
    let rhs_enumerated = rhs_shape.is_entry_set();

    // The widening is `key_filter::key_comparator`'s, the same call the legacy resolver's arm makes,
    // so the comparator the verdict is folded under is one comparator for the evaluator and the legacy
    // resolver alike. It reads the
    // NORMALIZED right-hand side, `rhs_normalized`: the entries that stand for no value are dropped,
    // and a map the right-hand query NAMED arrives as its key set (`key_filter::normalize_rhs`; a
    // map the query ENUMERATED to stays whole), so `let exempt = Mappings.Exempt.Buckets` over
    // `{ A: true, B: true }` is one value as written and two here, and the comparator reads
    // `named_a_map` beside the count so that a one-key map is membership as a two-key map is. Apart
    // from that key-set reading the shape it sees (a list among the values, more than one value) is
    // the shape the author wrote, BEFORE the expansion below, together with the retrieval's report of
    // whether the right-hand query enumerated: a list on the right, of any length, is a set, and so is
    // an enumerating query at any length, and `==` against a set is membership. Read after the
    // expansion, a one-element list literal counted as one value and stayed `==`, so
    // `[ keys == [r[a,f]] ]` and `[ keys == [r[a,f], r[x,z]] ]` compared their first element
    // differently; read without the enumeration, `%r[*]` over a one-element binding did the same.
    // Needed here, before any key is compared, because the unresolved-key arm below records it too.
    //
    // The records NAME the operator the author wrote. The widening is how a `==` against a set is
    // decided; it is not what the rule says, and every reporter renders the record's operator back
    // to the author: the verbose tree as `Comparison= IN`, the JSON and structured reports as
    // `"comparison": ["In", ..]`, the summary as "did not match expected value in". A `keys == [...]`
    // recorded as the widened operator would come back in all of those as `in`, which no line of the
    // rule contains.
    //
    // The records take their SHAPE from the widened comparator, below: ONE record per key, against
    // the whole set, whenever the right-hand side is a set, and the one `Comparison` a `==` always
    // recorded against a single value otherwise. A version of this took the shape from the written
    // operator too and filed one `Comparison` per right-hand value for a written `==`/`!=`, each
    // stamped with the key's one verdict: `keys != ['a', 'b']` over `{ a: 1 }` then reported "a is
    // equal to b", which is false, and `keys == %allowed[*]` over a long allowlist reported one line
    // per entry for every failing key. The set record carries the elements the key was equal to, so
    // the reporters' equality arms can say what the `==` or `!=` found without stating a pair that
    // was never compared that way.
    let written_cmp = cmp;
    let cmp = key_filter::key_comparator(
        cmp,
        rhs_normalized,
        rhs_enumerated || normalized.named_a_map,
    );
    let recorded_cmp = written_cmp.as_cmp_operator();

    // One key per right-hand value, before anything compares against them.
    //
    // `resolve_variable` answers with the results a query produced, and one result can hold a list:
    // `let names = Cfg.KeyList` over `KeyList: [Name, Owner]` is a single `Resolved` naming two keys.
    // The widening once read `rhs.len()`, so that counted as one and `keys == %names` stayed strict
    // equality. `compare_eq` then refused every key-against-list pairing, the filter selected nothing,
    // and the clause SKIPped -- the run exited 0 with nothing in the report, while the same key names
    // spelled `%names[*]` widened to membership and failed at 19. Two spellings of one clause, and the
    // silent one was wrong.
    //
    // Flattened, so that `select_key` below compares each key against each element rather than against
    // the list. `interpolated_keys` is the same one-level expansion the variable-key path already does
    // for the same reason, reused rather than written twice, and the legacy resolver's arm asks it too.
    let rhs = &interpolated_keys(rhs_normalized);

    // A right-hand side with no entry left, whether the enumeration above yielded none or the author
    // wrote `[]`, is an empty set of names, and the filter decides it by polarity rather than by
    // comparing: no key is in the empty set, so `==` and `IN` select none and the clause reports that it
    // selected nothing; every key is outside it, so `!=` and `NOT IN` select every key, and the assertion
    // runs over all of them. The exemption direction is why this is not "select nothing under every
    // comparator": `Resources[ keys NOT IN %exempt ].Properties.Encrypted == true` over an exemption
    // list with nothing in it has to check every resource, where a filter that selected none reported
    // SKIP at exit 0 and checked nothing. Each key is recorded as the comparison arms record it, with
    // the empty set as the value it was compared with, so every reporter keeps the filter's trace. The
    // clause `Key <op> %names` over the same `[]` is untouched: it fails in both polarities, as a
    // comparison with an empty collection does.
    //
    // Decided AFTER the one-level expansion above, because a literal `[]` arrives as one value holding
    // an empty list and is empty only once expanded; decided here rather than in the comparison arms
    // below, because over no right-hand value there is no comparison to record and a key with no record
    // has no status, which reads as not applicable.
    //
    // The right-hand value of the record is the empty set as a RESOLVED empty list. With no right-hand
    // value the record was a shape the reporters render three ways: the verbose tree printed `to=`
    // with nothing after it, the console summary read "did not match expected value [null]", and the
    // structured reporter, which builds a resolved comparison only when both values are present,
    // dropped it. Resolved and not a literal, because both reporters treat a literal right-hand value
    // as unreachable. Its path is the root, the one place the set has no document position to claim.
    //
    // Only a resolved key reaches the records here: `lhs` is built from the map's keys, each a
    // `Resolved`, by the one caller, the `MapKeyFilter` arm of `query_retrieval_with_converter` in
    // `eval_context.rs`. The assertion states that invariant in place of a branch for an unresolved
    // entry, which would stand untested: a key with no value is not a shape a map can hold, so there
    // is nothing to record for one.
    if rhs.is_empty() {
        let selected = key_filter::empty_set_selects(cmp);
        let empty_set = Rc::new(PathAwareValue::List((Path::root(), vec![])));
        for each in lhs.iter() {
            debug_assert!(
                matches!(each, QueryResult::Resolved(_)),
                "a key filter's keys are built from the map's keys as resolved values, got {:?}",
                each
            );
            eval_context.start_record(&context)?;
            if !selected {
                eval_context.end_record(
                    &context,
                    RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
                        status: Status::FAIL,
                        message: None,
                        custom_message: custom_message.clone(),
                        comparison: recorded_cmp,
                        from: each.clone(),
                        to: Some(QueryResult::Resolved(Rc::clone(&empty_set))),
                    })),
                )?;
                statues.push((each.clone(), Status::FAIL));
            } else {
                eval_context
                    .end_record(&context, RecordType::ClauseValueCheck(ClauseCheck::Success))?;
                statues.push((each.clone(), Status::PASS));
            }
        }
        return Ok(EvaluationResult::QueryValueResult(statues));
    }

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
                // The verdict and the evidence, from `key_filter::select_key` -- the one entry point
                // the legacy resolver's `MapKeyFilter` arm asks as well, so the two engines cannot
                // answer one filter differently. Each right-hand value is compared once there, and the
                // same comparison is what the records below render. A right-hand value that did not
                // resolve comes back as evidence too, and the fold has read it as a comparison it could
                // not finish, which fails the whole filter closed below: a denylist with a hole in it
                // neither admits a key nor quietly keeps it out.
                //
                // A key whose comparison could not be finished is read before anything is recorded.
                // It becomes "not selected" like a key that plainly did not match, and one level up
                // the selection silently shrinks by a key nobody decided about, so an assertion over
                // the smaller selection can pass. The first such reason fails the whole filter closed
                // at the return below.
                let key_filter::KeySelection {
                    selected,
                    undecided: key_undecided,
                    evidence,
                } = key_filter::select_key(cmp, Rc::clone(l), rhs);

                // The deprecated reading of a string on the right is text the key could be contained
                // in. When that reading and `select_key`'s select the key differently, the move is
                // announced once per filter site, through the sink that writes the notice prefix. The
                // verdict is the one `select_key` reached; nothing here changes it.
                //
                // The site is asked first. The notice is kept once per site, and the move and its text
                // were computed for every key of every map the filter ran over, so
                // `Resources.*.Properties.Tags[ keys IN %allowed ]` over N resources built N texts and
                // kept one. A recorded site has nothing left to say, and neither the move nor the text
                // is computed for it (`a_containment_notice_is_built_once_per_site` counts).
                if !eval_context.has_deprecation_site(DeprecationKind::KeyFilterContainment, site) {
                    if let Some(moved) =
                        key_filter::containment_move(written_cmp, rhs_raw, l, selected)
                    {
                        eval_context.record_deprecation_once(
                            DeprecationKind::KeyFilterContainment,
                            site,
                            key_filter::containment_move_notice(written_cmp, l, &moved, site),
                        );
                    }
                }
                // The other move the previous release made and this one does not: a negated filter over
                // two or more values folded as ANY, so a key equal to one value was selected because
                // another differed. Containment's notice is silent on it by design (equality under the
                // earlier fold selects the key just the same), so it has a notice of its own, kept once
                // per site like the containment notice. Asked in cost order: whether the fold could have
                // moved a key under this filter at all (the comparator and the count of right-hand
                // values, `fold_can_move`, which the common `keys IN %allowed` and the one-value `!=`
                // fail, so they pay nothing here, not even the site lookup, which renders the position
                // and was paid once per key per map:
                // `the_fold_sites_lookup_is_skipped_for_a_filter_the_fold_cannot_move` counts), then the
                // site, then the move, then the text (`a_fold_notice_is_built_once_per_site` counts).
                // The two moves are disjoint, so a key draws at most one of the two lines.
                if key_filter::fold_can_move(written_cmp, rhs_raw) {
                    key_filter::count_fold_site_lookup();
                    if !eval_context.has_deprecation_site(DeprecationKind::KeyFilterFold, site) {
                        if let Some(moved) =
                            key_filter::fold_move(written_cmp, rhs_raw, l, selected)
                        {
                            eval_context.record_deprecation_once(
                                DeprecationKind::KeyFilterFold,
                                site,
                                key_filter::fold_move_notice(written_cmp, l, &moved, site),
                            );
                        }
                    }
                }

                match cmp {
                    MapKeyComparator::In | MapKeyComparator::NotIn => {
                        statues.extend(report_by_lhs(
                            evidence,
                            selected,
                            key_undecided.as_deref(),
                            recorded_cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context,
                        )?);
                    }

                    MapKeyComparator::Eq | MapKeyComparator::NotEq => {
                        let status = report_all_values(
                            evidence,
                            selected,
                            recorded_cmp,
                            context.clone(),
                            custom_message.clone(),
                            eval_context,
                        )?;
                        statues.extend(status);
                    }
                }
                // After the records, which read the key's own reason; the filter's is the first key's.
                if undecided.is_none() {
                    undecided = key_undecided;
                }
            }
        };
    }

    // A selection nobody could decide fails the clause closed rather than selecting a subset.
    //
    // `undecided_gate` is the sibling of this, and the differences are why this is written out rather
    // than calling it. There is no `role` to split on: `real_binary_operation`'s only caller is the
    // `[ keys <op> ... ]` filter in `eval_context.rs`, which passes no `ClauseRole` (the value filters
    // that reach `binary_operation` carry `ClauseRole::Filter` and deselect; a key nobody could decide
    // has no entry to deselect), so the fail-closed direction is the only one available here. And
    // there is no decided-failure mirror, because
    // a key that plainly does not match decides nothing about the selection -- it is simply not in it,
    // which is the ordinary case rather than an answer about the whole filter.
    //
    // Known cost, and it is a cost rather than an oversight: `Cfg[ keys == /re/ ] !empty` over a key the
    // pattern decidedly matches BESIDE an undecided key reports a failure, where three-valued logic
    // would answer yes on the strength of the matching key. Telling those apart needs the enclosing
    // operator, which this function is not given -- non-emptiness is decided there while membership is
    // not, and only the caller knows which of the two it asked about.
    //
    // The cost is the one MAP, not the whole query. `Err` here leaves `real_binary_operation` for the
    // map whose key could not be decided, and the key-filter arm that called it (the `MapKeyFilter`
    // arm of `query_retrieval_with_converter`) turns it into one unresolved result for that map, typed
    // `UnResolvedKind::Undecidable` and carrying this reason, and goes on to the next map. The clause
    // then fails closed on that map in either polarity (`undecidable_selection`) while its sibling maps
    // are decided and reported. A `?` at the call site would make it the whole query: the retrieval
    // would be left for every map, so `Resources.*.Cfg[ keys == Names[*].Name ] == 2` over a resource
    // whose `Names` has no `Name` beside one whose `x` is 3 would exit 19 naming the first alone, the
    // second's failure appearing nowhere in the run and which map is named depending on iteration order.
    // Inside a filter predicate the filter loops keep the same shape one level up: an entry whose
    // predicate raised this error is answered with the marker (`eval_context::to_undecidable_result`)
    // and its siblings are tested. The legacy resolver's key-filter arm still returns the error for the
    // whole selection; no command path reaches it.
    match undecided {
        Some(reason) => Err(Error::UndecidableComparison(reason)),
        None => Ok(EvaluationResult::QueryValueResult(statues)),
    }
}

/// What a query written with `some` hands back: the values it has, with the unresolved entries dropped.
/// Without the modifier the result is returned as it came.
///
/// One definition, called from every site that resolves a query carrying the modifier: the two `lookup`
/// implementations in `eval_context` for a `let` assignment, the right-hand side of a clause, and a
/// parameterized rule's argument. So the modifier cannot mean one thing in one position and nothing in
/// another, which is what it did while only the `let` sites read it. A clause's own left-hand query is
/// not resolved through this: its `match_all` is the quantifier the clause's fold applies, and the
/// unresolved entries it keeps are what the clause fails on.
///
/// A literal is kept. `%lit` for a `let lit = "foo"` arrives as `QueryResult::Literal`, and a literal is
/// never unresolved: keeping only `Resolved` dropped it, so `X == some %lit` compared against nothing
/// and failed with a message blaming a reference that resolved to no values. The `let` sites had that
/// filter before this helper existed, and `let y = some %lit` bound an empty `y` for the same reason.
///
/// The undecidable marker a key filter leaves for a map it could not decide (`UnResolvedKind::
/// Undecidable`) is kept too. `some` drops what the document lacks, because a value that is absent
/// cannot be one of the "some"; a selection nobody could decide is not absent, and dropping it read
/// `let kept = some Cfg[ keys NOT IN %missing ]` as an empty binding, so `%kept empty` passed and a
/// comparison over `%kept` reported nothing, where the operators downstream fail the marker closed
/// when they see it.
pub(in crate::rules) fn resolved_only_under_some(
    result: Vec<QueryResult>,
    match_all: bool,
) -> Vec<QueryResult> {
    if match_all {
        return result;
    }
    result
        .into_iter()
        .filter(|q| {
            !matches!(
                q,
                QueryResult::UnResolved(ur) if !ur.kind.is_undecidable()
            )
        })
        .collect()
}

/// Announce a `when` whose answer moved because a function's result keeps the entries the function had
/// no answer for.
///
/// Called once per evaluation of a `when` (per resource for a type block's condition), by
/// `eval_when_condition_block`, by the rule-conditions path of `eval_rule` and by the type-block-
/// conditions path of `eval_type_block_clause`, right after the conditions have been evaluated as
/// written and before the block they guard is decided. `now` is that answer, and `resource` is the
/// resource the `when` was evaluated for: a type block's condition passes the resource it is deciding, a
/// `when` block passes the resource its scope is rooted at (one inside a type block's or a block
/// clause's body runs once per resource), and a `when` evaluated at the document root passes `None`.
/// The type block's call comes through the per-resource scope its condition runs in. Nothing is
/// measured unless a condition reads, anywhere in either side, a name that carries a function's result
/// (`EvalContext::function_chain`) whose values hold an unresolved entry beside a resolved one: a
/// result with nothing resolved is empty under both readings, and a bare query carries its entries
/// under both.
///
/// The measurement is of the whole condition set, through the real scopes and the real query path, so
/// the conjunction logic that decides a `when` decides both readings: `A or B` where `B` passes either
/// way does not move, and `A B` where `A` went from set aside (SKIP) to failing does. Three readings
/// are taken, each writing nothing (see [`Measurement`]): first the whole set with the entries dropped
/// that each name carrying a function's result would have lost before this release (every unresolved
/// entry of a name bound to the result itself; of a derived name, only the entries that are the
/// result's by identity, so the ones its own query added stay), the one reading that decides whether
/// the gate moved; then, only once a notice is owed, each condition as written, for the per-condition
/// answers of this release, and each condition with the entries dropped, for the answers of the release
/// before, which together name the condition that moved. A notice
/// is owed only when the gate's answer changed, PASS to not-PASS or back, and it names the first
/// condition whose own answer differs between the two per-condition readings, with both of its answers. One per
/// `when` per direction ([`MoveDirection`]), however many resources a type block or a block over
/// resources evaluates it for, and once a direction's notice is recorded the `when` is settled that way
/// (`EvalContext::settle_when`) and every later evaluation of it that could only have moved that way
/// returns before measuring. The direction an evaluation could have moved in is known from `now` alone,
/// so the check costs nothing: a gate that fails now can only have passed before. A `when` is settled
/// by its notice and by nothing else: the conditions can read the resource beside the function's result
/// (`%p !empty Properties.X exists`), so one resource's gate can hold still while the next one's moves,
/// and a `when` settled by its first measurement whatever it found would hide the move a later
/// resource makes. So a resource, or a parameterized rule call,
/// whose gate reads the resource and did not move is measured and leaves the `when` open for the next;
/// a measurement that could not finish leaves it open too; once one has moved and its line is down, the
/// resources that could only have moved the same way are not measured, and a resource that could only
/// have moved the other way is, so the silent direction (checks that ran and are skipped now) is never
/// hidden behind the loud one. A `when` whose every name rests on document-level bindings
/// (`document_level_bindings`: a root `let`, a rule body's `let` outside any parameterized rule's call,
/// or a `let` computed from those and literals alone) answers the same for every resource and call that
/// reads the same bindings, so its first finished measurement settles it for those bindings whether or
/// not it moved: the usual gate, `%p !empty` over a rule-level `let`, is measured once per run and not
/// once per bucket. A called rule's `when` is one position shared by every caller, so the record carries
/// the bindings the names resolved to: the next call from the same caller block
/// (`AWS::S3::Bucket { check(this) }` over a caller's `let`) reads the same binding and returns before
/// measuring, while another caller's same-named `let` is another binding and is measured on its own, so
/// no caller's move is lost. A name bound inside the call from the call's arguments (a parameter, a
/// body `let` over one, the rule's own capture) can be a different value for the next call and keeps the
/// `when` open.
/// A line for a `when` evaluated per resource names the resource it was evaluated for when it moved, so
/// it is not read as a statement about every resource of the block, and says that a resource that moved
/// the other way gets its own line. Filter predicates and the bodies of referenced rules are gates too,
/// and are never measured on their own: a notice at a filter would name a `when` that is not there, and
/// a measurement per filtered element is a clone of the whole result per element.
///
/// Whether anything is owed is decided from the results the conditions read, which the scopes hold
/// (`EvalContext::variable_is_resolved`) and which cost nothing to read again. A result the conditions
/// never reached, because an `or` was decided by its other side, is not computed for that decision: it
/// is held nowhere, so reading it would run the function again, unmemoized, on every evaluation of the
/// `when` (read outside a measurement it would instead be memoized, its captures appended and its
/// notices recorded as though a condition had read it), and a disjunct the real run never read can only
/// have moved the gate if a condition it did read moved first. Once something is owed, every named
/// result is read, the unreached ones computed under the quiet reading, so the notice names the same
/// results in the same order whatever the run had read before; the two per-condition readings then
/// compute them again. All of that is paid at most once per direction for a `when` that settles: by
/// its line, or by a finished measurement of a `when` whose every name rests on document-level
/// bindings, which settles it for those bindings whether or not it found a move
/// (`EvalContext::when_is_settled`, set by `settle_when`). A settled `when` returns before any of it:
/// one settled by its line in one lookup, one settled by a measurement after the one walk of its
/// conditions' text that names the bindings its names rest on, which the binding stores answer before
/// anything is resolved, and that walk is paid only when a record for the `when` and direction exists
/// (`EvalContext::when_has_settled_measurements`). A `when` that reads the resource or a per-call
/// binding and never moves pays the pre-check and the one deciding reading on every evaluation. The pre-check
/// reads only names the scopes hold and runs outside any measurement, so a `when` with nothing to drop
/// never enters one (the one question that can read under a measurement from there, the entries of a
/// root nothing holds, is its own nested reading, `NestedMeasurement`, and leaves nothing behind); both
/// readings run through [`Measured`], which owns the reset.
///
/// A measurement already in progress (this `when` is inside a rule referenced, or a parameterized rule
/// called, from the conditions being measured) is left alone: its own answers are being read by the
/// outer one, and a second measurement would switch the outer one off from underneath.
fn announce_a_moved_when<'value, 'loc: 'value>(
    conditions: &'value WhenConditions<'loc>,
    now: Status,
    resource: Option<&Path>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
) {
    if resolver.measurement() != Measurement::Off {
        return;
    }
    // Settled means the line for this `when` moving the way this evaluation could have moved is
    // already down, and no reading taken for another resource or another call can add to it. The
    // direction is known from `now` alone: a gate that fails now can only have passed before. Checked
    // before anything is resolved, since this is the path every further resource of a type block takes
    // once the first move each way is announced; a resource that could only have moved the other way
    // is measured, so a line the release before this one printed is not dropped.
    let Some(first) = conditions.iter().flatten().next() else {
        return;
    };
    let when_site = when_clause_location(first);
    let direction = MoveDirection::of_now(now);
    if resolver.when_is_settled(when_site, direction, None) {
        return;
    }
    // Settled by a finished measurement, for the bindings this evaluation's names rest on: the path
    // the common gate (`AWS::S3::Bucket when %p !empty` over a rule-level `let`) takes on every
    // resource after the first settled it. The bindings are a walk of the conditions' text over the
    // binding stores, which are filled before anything is resolved, so they are known here and the
    // question costs one lookup plus that walk, asked before the pre-check below reads every name,
    // clones the memoized result, the chain and the entries and builds the set of dropped entries for
    // the resource. The walk is paid only when a record for this `when` and direction exists at all, so a
    // `when` nobody has measured yet allocates nothing here; its bindings are read once, after the
    // pre-check, and kept for the settling below.
    let mut settling_bindings = None;
    if resolver.when_has_settled_measurements(when_site, direction) {
        let bindings = document_level_bindings(conditions, &*resolver);
        if let Some(set) = &bindings {
            if resolver.when_is_settled(when_site, direction, Some(set)) {
                return;
            }
        }
        settling_bindings = Some(bindings);
    }
    #[cfg(test)]
    PRE_CHECKS.with(|count| count.set(count.get() + 1));

    // Every name carrying a function's result that any condition reads, wherever it reads it, whose
    // values hold an unresolved entry beside a resolved one. The first part of each side was the only
    // place looked at before, so a result used as an interpolated key (`Resources.%names exists`),
    // inside a filter's predicate (`Resources.*[ Name == %names ]`), as a map-key filter's right-hand
    // side or as a nested call's argument moved a `when` with no line, and a condition over two such
    // results was announced with one of them named.
    let mut names: Vec<&'value str> = Vec::new();
    for condition in conditions.iter().flatten() {
        if let WhenGuardClause::Clause(gac) = condition {
            function_results_read_by(gac, resolver, &mut names);
        }
    }
    // Decided outside any measurement: the names asked are the ones the scopes hold, whose
    // `resolve_variable` answers from the memo and writes nothing, so a `when` with nothing to drop is
    // never put into a measurement, and a count of the measurements taken tells it from a `when` that
    // was measured and did not move. The entries question a held derived name asks is answered from the
    // held root's memo, so it reads nothing afresh here either.
    // Each listed result keeps the position of the condition that names it, so the notice lists the
    // results in the order the conditions name them whichever pass found each.
    let mut kept_entries: Vec<(usize, DroppedEntries<'_>)> = Vec::new();
    for (position, name) in names.iter().copied().enumerate() {
        // Only a name the scopes already hold is read: for one, `resolve_variable` answers from the
        // memo and writes nothing, so a result the conditions never read is not computed, memoized or
        // announced by this question.
        if !resolver.variable_is_resolved(name) {
            continue;
        }
        let Some(chain) = resolver.function_chain(name) else {
            continue;
        };
        let Ok(values) = resolver.resolve_variable(name) else {
            continue;
        };
        // What the measurement drops from this name, listed as `dropped_entries` says; the same set
        // `measured_values` drops, so the pre-check and the measurement agree by construction.
        if let Some(entries) = dropped_entries(name, &values, &chain, resolver) {
            kept_entries.push((position, entries));
        }
    }
    if kept_entries.is_empty() {
        return;
    }

    // A `when` whose every name rests on document-level bindings answers the same for every resource
    // and every call that reads those same bindings, so one finished measurement decides it for them,
    // moved or not: a `when` reached again with the same bindings returned above, at the lookup before
    // the pre-check. One that reads the resource (a bare path, `this`, a per-resource `let`, a type
    // block's capture, a key a nested block handed up, a parameter) is left open by a measurement that
    // found no move, since the next resource or call can move; a rule body's own capture is a binding
    // at the body's capture generation and settles like a `let` (`BlockScope::document_level_site`).
    // Read here only when no record existed above: the first measurement of a `when` and direction that
    // can be settled, and every measurement of one whose names read the resource or a per-call binding
    // (`Properties.Versioning exists`), which no measurement settles and which therefore never has a
    // record. The settling below is this function's only writer, and nothing between the two reads
    // settles anything.
    let settling_bindings =
        settling_bindings.unwrap_or_else(|| document_level_bindings(conditions, &*resolver));
    #[cfg(test)]
    GATE_MEASUREMENTS.with(|count| count.set(count.get() + 1));

    // Whether the gate moved is settled first, by the one reading that decides it: the whole set with
    // the entries dropped, through the conjunction logic that decides a `when`. The reading writes
    // nothing; `Measured` is what puts the run back in `Off` whichever way it ends.
    let then = {
        let mut without = Measured::new(resolver, Measurement::WithoutUnresolved);
        eval_conjunction_clauses(conditions, &mut *without, eval_when_clause)
    };
    let Ok(then) = then else {
        return;
    };
    if (then == Status::PASS) == (now == Status::PASS) {
        // Nothing moved. A `when` that cannot answer differently for the next resource or call that
        // reads the same bindings is settled here for those bindings, so the measurement is taken once
        // per binding set and not once per resource; one that reads the resource stays open for the
        // next one. `now` is the same for every evaluation of the settled `when` over the same
        // bindings, so the one direction `of_now` names is the only key a later evaluation asks for.
        if settling_bindings.is_some() {
            resolver.settle_when(when_site, direction, settling_bindings);
        }
        return;
    }

    // Only once a notice is owed: the per-condition readings, as written and with the entries dropped,
    // which exist to name the condition that moved and its two answers. Taken earlier, they cost two
    // evaluations per condition on every measured gate, moved or not, and the common case is a gate
    // that did not move. Each reading writes nothing, and `Measured` resets the run whichever way it
    // ends.
    let as_written: Vec<Option<Status>> = {
        let mut quiet = Measured::new(resolver, Measurement::Quiet);
        // The results the conditions name that the scopes do not hold are read here, where nothing is
        // announced and what is memoized is this reading's alone, taken back at its end, so the notice
        // names one set whatever the run had read first: a name bound to the call itself, a derived
        // name whose root some condition read outside the measurement, and a derived name whose root
        // nothing held before this reading are each listed with what the measurement drops from them,
        // found as `dropped_entries` says.
        for (position, name) in names.iter().copied().enumerate() {
            if quiet.variable_is_resolved(name) {
                continue;
            }
            let Some(chain) = quiet.function_chain(name) else {
                continue;
            };
            let Ok(values) = quiet.resolve_variable(name) else {
                continue;
            };
            if let Some(entries) = dropped_entries(name, &values, &chain, &mut *quiet) {
                kept_entries.push((position, entries));
            }
        }
        conditions
            .iter()
            .flatten()
            .map(|condition| eval_when_clause(condition, &mut *quiet).ok())
            .collect()
    };
    kept_entries.sort_by_key(|(position, _)| *position);
    let kept_entries: Vec<DroppedEntries<'_>> = kept_entries
        .into_iter()
        .map(|(_, entries)| entries)
        .collect();
    #[cfg(test)]
    DROPPED_READINGS.with(|count| count.set(count.get() + 1));
    let dropped: Vec<Option<Status>> = {
        let mut without = Measured::new(resolver, Measurement::WithoutUnresolved);
        conditions
            .iter()
            .flatten()
            .map(|condition| eval_when_clause(condition, &mut *without).ok())
            .collect()
    };

    let moved = conditions
        .iter()
        .flatten()
        .zip(as_written.iter().zip(dropped.iter()))
        .find(|(_, (as_written, dropped))| as_written != dropped)
        .map(|(condition, (as_written, dropped))| (condition, *as_written, *dropped));
    let (condition, condition_now, condition_then) = match moved {
        Some(moved) => moved,
        // Every condition answered alike on its own and the set still moved: name the first one.
        None => match conditions.iter().flatten().next() {
            Some(condition) => (condition, Some(now), Some(then)),
            None => return,
        },
    };
    // Recorded under the `when` and the direction, so a `when` whose resources moved both ways gets a
    // line each way and no more; the text names the condition that moved, at its own position.
    let recorded = resolver.record_deprecation_once(
        DeprecationKind::FunctionResultGate(direction),
        when_site,
        function_result_gate_notice(
            condition,
            condition_now,
            condition_then,
            now,
            then,
            &kept_entries,
            resource,
        ),
    );
    // Settled for every evaluation by the line itself and by nothing else: a measurement that found no
    // move has returned above, settling the `when` for its bindings or leaving it open, and one that
    // could not finish has left it open for the next resource or call.
    if recorded {
        resolver.settle_when(when_site, direction, None);
    }
}

// The number of `when`s whose conditions a measurement was taken for on this thread, for the test that
// pins which gates are measured at all: one whose names hold none of a function's own entries is not.
// Counted once the pre-check has found something to drop, whatever readings follow. Per thread, since
// each test evaluates on its own. Absent from a release build.
#[cfg(test)]
thread_local! {
    pub(in crate::rules) static GATE_MEASUREMENTS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

// The number of times a `when` reached the pre-check on this thread (the names read, the memoized
// results and their dropped entries collected), for the test that pins that a `when` settled by a
// measurement returns before it on every later resource: one pre-check for N buckets, where N was
// paid. Counted after the settled lookups and before any name is read. Per thread, as above. Absent
// from a release build.
#[cfg(test)]
thread_local! {
    pub(in crate::rules) static PRE_CHECKS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

// The number of times the conditions were read one by one with the entries dropped on this thread, for
// the tests that pin one such reading per notice owed: the reading is taken only once the gate's own
// reading found a move, so a resource or call whose gate did not move costs none, and one settled by
// its line is not read again. Per thread, as above. Absent from a release build.
#[cfg(test)]
thread_local! {
    pub(in crate::rules) static DROPPED_READINGS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// A function result a `when` reads, or a `let` or parameter derived from one (`derived`), with the
/// entries the measurement drops from it (`unresolved`, the ones the function had no answer for) beside
/// the values the name holds (`resolved`: the function's own answers for the name bound to the result
/// itself, what its query produced from them for a derived name) and the unresolved entries both
/// readings keep (`kept`: a derived query's own, for a key a parsed value lacks): what the measurement
/// drops, and what the notice names.
struct DroppedEntries<'value> {
    variable: &'value str,
    derived: bool,
    resolved: usize,
    unresolved: usize,
    kept: usize,
    first: UnResolved,
}

/// What the measurement drops from `name`, whose reading as written is `values` and whose chain to a
/// function's result is `chain`, as the notice lists it; `None` when the name is not listed: a result
/// with nothing resolved is empty under both readings, one with nothing unresolved has nothing to drop,
/// and a derived name none of whose entries are the result's loses nothing.
///
/// The set is the one `measured_values` drops, so the notice and the measurement agree by construction,
/// and it is found the same way for a name the scopes hold and for one read under the quiet measurement:
///
/// - The name bound to the call itself loses every unresolved entry (`measured_values` reads a hops-0
///   name through `without_unresolved`). Listed wholesale rather than by identity, because a reading
///   taken under a measurement allocates objects no memo points at, and identity would match nothing.
/// - A name derived from the result through a query loses the entries that are the result's own, and
///   keeps the ones its query added. The result's own are told by `function_result_entries`: by address
///   against the root's memo in the scope that binds it, whose objects the clones point at, when a
///   reading holds the memo (the real run's, or this reading's own, since a derived name's quiet reading
///   memoizes the root it resolves), and by path, remaining query and reason against a fresh reading of
///   the root when nothing holds one; never from a same-named binding in this scope. One answer from
///   the one question, with no second reading of the name here, so a derived name whose entries are all
///   its query's own costs the pre-check one set lookup and nothing more.
fn dropped_entries<'value, 'loc: 'value>(
    name: &'value str,
    values: &[QueryResult],
    chain: &FunctionChain<'value>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
) -> Option<DroppedEntries<'value>> {
    // The two counts first, since they are free and decide most names.
    let resolved = values
        .iter()
        .filter(|value| !matches!(value, QueryResult::UnResolved(_)))
        .count();
    if resolved == 0 || resolved == values.len() {
        return None;
    }
    let dropped: Vec<UnResolved> = if chain.hops == 0 {
        unresolved_entries(values).cloned().collect()
    } else {
        match resolver.function_result_entries(name) {
            Some(Ok(entries)) => unresolved_entries(values)
                .filter(|entry| entries.contains(entry))
                .cloned()
                .collect(),
            Some(Err(_)) | None => return None,
        }
    };
    let first = dropped.first().cloned()?;
    Some(DroppedEntries {
        variable: name,
        derived: !chain.exact_alias,
        resolved,
        unresolved: dropped.len(),
        kept: values.len() - resolved - dropped.len(),
        first,
    })
}

/// The unresolved entries among `values`, in order.
fn unresolved_entries(values: &[QueryResult]) -> impl Iterator<Item = &UnResolved> {
    values.iter().filter_map(|value| match value {
        QueryResult::UnResolved(entry) => Some(entry),
        _ => None,
    })
}

/// A resolver put into a measurement for as long as this value lives, and back into
/// [`Measurement::Off`] when it is dropped, whichever way the reading ends.
///
/// The reset lives in `Drop` rather than at every exit of the caller so that no early return, `?` or
/// panic inside a reading can leave the run measuring. A run left in a measurement writes nothing for
/// the rest of the evaluation: it records nothing, memoizes nothing, and its filter captures become
/// no-ops, so a later `%capture` resolves empty and verdicts change, not only the notice list. The
/// reading reaches the resolver through `Deref` and `DerefMut`. A reading is entered only from `Off`,
/// which `announce_a_moved_when` checks before its first `Measured::new`, and its end is what takes
/// its writes back; a switch to another mode inside a reading is a nested reading, taken through
/// `eval_context::NestedMeasurement`, which restores the mode it found and leaves the outer reading's
/// writes in place until that reading ends.
struct Measured<'eval, 'value, 'loc: 'value> {
    resolver: &'eval mut (dyn EvalContext<'value, 'loc> + 'eval),
}

impl<'eval, 'value, 'loc: 'value> Measured<'eval, 'value, 'loc> {
    fn new(
        resolver: &'eval mut (dyn EvalContext<'value, 'loc> + 'eval),
        mode: Measurement,
    ) -> Self {
        resolver.set_measurement(mode);
        Measured { resolver }
    }
}

impl<'eval, 'value, 'loc: 'value> std::ops::Deref for Measured<'eval, 'value, 'loc> {
    type Target = dyn EvalContext<'value, 'loc> + 'eval;

    fn deref(&self) -> &Self::Target {
        self.resolver
    }
}

impl<'eval, 'value, 'loc: 'value> std::ops::DerefMut for Measured<'eval, 'value, 'loc> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.resolver
    }
}

impl Drop for Measured<'_, '_, '_> {
    fn drop(&mut self) {
        self.resolver.set_measurement(Measurement::Off);
    }
}

/// Collect, into `names`, every name carrying a function's result, or derived from one through a query
/// rooted at it (`EvalContext::function_chain` answers for a name on such a chain), that `gac` reads: at either
/// side's query root, as an interpolated key anywhere in a query (`Resources.%names`, a `Key` part
/// spelled `%name`), inside a filter's predicate (each access clause of its conjunctions, recursively),
/// as a map-key filter's right-hand side, and as an argument of a nested function call on the
/// right-hand side. Named-rule references and nested blocks inside a filter read no query of their own
/// here and are passed over.
fn function_results_read_by<'value, 'loc: 'value>(
    gac: &'value GuardAccessClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    names: &mut Vec<&'value str>,
) {
    function_results_in_query(&gac.access_clause.query.query, resolver, names);
    if let Some(value) = &gac.access_clause.compare_with {
        function_results_in_let_value(value, resolver, names);
    }
}

fn function_results_in_query<'value, 'loc: 'value>(
    parts: &'value [QueryPart<'loc>],
    resolver: &mut dyn EvalContext<'value, 'loc>,
    names: &mut Vec<&'value str>,
) {
    for part in parts {
        match part {
            // A `%name` root or key, in either spelling the parser keeps for it.
            QueryPart::Key(_) | QueryPart::Variable(_) => {
                if let Some(name) = part.variable() {
                    if !names.contains(&name) && resolver.function_chain(name).is_some() {
                        names.push(name);
                    }
                }
            }
            QueryPart::Filter(_, conjunctions) => {
                for clause in conjunctions.iter().flatten() {
                    if let GuardClause::Clause(inner) = clause {
                        function_results_read_by(inner, resolver, names);
                    }
                }
            }
            QueryPart::MapKeyFilter(_, clause) => {
                function_results_in_let_value(&clause.compare_with, resolver, names);
            }
            QueryPart::This
            | QueryPart::AllValues(_)
            | QueryPart::AllIndices(_)
            | QueryPart::AuthoredIndices
            | QueryPart::Index(_) => {}
        }
    }
}

fn function_results_in_let_value<'value, 'loc: 'value>(
    value: &'value LetValue<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    names: &mut Vec<&'value str>,
) {
    match value {
        LetValue::AccessClause(query) => function_results_in_query(&query.query, resolver, names),
        LetValue::FunctionCall(call) => {
            for argument in &call.parameters {
                function_results_in_let_value(argument, resolver, names);
            }
        }
        LetValue::Value(_) => {}
    }
}

/// The document-level bindings every condition of a `when` rests on, when the conditions read nothing
/// else, so that its answer is the same for every resource a type block visits and every call of a
/// parameterized rule that reads those same bindings; `None` when any condition reads the resource.
///
/// A condition qualifies when each query on either side is rooted at a `%name` the resolver answers
/// `binding_owners` for, and every other `%name` the query reaches (an interpolated key, a filter
/// predicate's sides, a map-key filter's right-hand side, a nested call's argument) is such a name too;
/// a literal on the right-hand side is fine and rests on nothing. The answer is the union of what every
/// name rests on. A query rooted at a key or at `this` reads the resource the scope is rooted at, a
/// `%name` bound per resource or per call reads it one step removed, and a named-rule or
/// parameterized-rule condition reads whatever that rule's body reads, so each of those keeps the `when`
/// open. Read before the pre-check on every evaluation of a `when` that has a record of settled
/// measurements, including the ones that then return at `kept_entries.is_empty()` without measuring,
/// and once more for a measurement of a `when` with no record; the binding stores answer it before any
/// name is resolved, so it costs a walk of the conditions' text and nothing else.
fn document_level_bindings<'value, 'loc: 'value>(
    conditions: &'value WhenConditions<'loc>,
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    let mut bindings = BTreeSet::new();
    for condition in conditions.iter().flatten() {
        match condition {
            WhenGuardClause::Clause(gac) => {
                bindings.append(&mut query_document_level_bindings(
                    &gac.access_clause.query.query,
                    resolver,
                )?);
                if let Some(value) = gac.access_clause.compare_with.as_ref() {
                    bindings.append(&mut let_value_document_level_bindings(value, resolver)?);
                }
            }
            WhenGuardClause::NamedRule(_) | WhenGuardClause::ParameterizedNamedRule(_) => {
                return None
            }
        }
    }
    Some(bindings)
}

/// The query half of [`document_level_bindings`]: rooted at a `%name`, with every `%name` it reaches
/// anywhere document-level too. The root is what makes a query read the document rather than the
/// resource; the walk over the parts, the root among them, is the inner one's. Also what a block scope
/// answers `binding_owners` from for a `let` of its own bound to a query, when the `let` is bound again
/// for every resource or call.
pub(in crate::rules) fn query_document_level_bindings<'value, 'loc: 'value>(
    parts: &'value [QueryPart<'loc>],
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    match parts.first() {
        Some(QueryPart::Variable(_)) => inner_query_document_level_bindings(parts, resolver),
        _ => None,
    }
}

/// What every `%name` reached anywhere in `parts` rests on, when each is document-level; the root may be
/// a key, since the query runs against a filtered element of a value already known to be
/// document-level. A predicate's sides are read against the filtered element, which is part of the
/// rooted value; only the names they reach can bring the resource in. Also what the root scope and a
/// block running once per evaluation answer `binding_owners` from for a `let` of their own bound to a
/// query: there a key-rooted query reads the document, so the root may be a key, and the names the query
/// reaches decide whether the `let` is one value for the evaluation (`let bs = %b.Properties.Name` over
/// a rule's capture `b` rests on the capture, so it is nobody's binding, where its own id alone read as a
/// constant and the quiet probes' memo kept the value a probe read before the filter had bound `b`).
pub(in crate::rules) fn inner_query_document_level_bindings<'value, 'loc: 'value>(
    parts: &'value [QueryPart<'loc>],
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    let mut bindings = BTreeSet::new();
    for part in parts {
        match part {
            QueryPart::Key(_) | QueryPart::Variable(_) => {
                if let Some(name) = part.variable() {
                    bindings.append(&mut resolver.binding_owners(name)?);
                }
            }
            QueryPart::Filter(_, conjunctions) => {
                bindings.append(&mut predicate_document_level_bindings(
                    conjunctions,
                    resolver,
                )?);
            }
            QueryPart::MapKeyFilter(_, clause) => {
                bindings.append(&mut predicate_value_document_level_bindings(
                    &clause.compare_with,
                    resolver,
                )?);
            }
            _ => {}
        }
    }
    Some(bindings)
}

/// What a filter's predicate rests on, for [`inner_query_document_level_bindings`]: both sides of every
/// clause are read against the filtered element, which is part of the rooted value, so a key root is
/// allowed on either side as it is on the query (`Properties.RoleName == Parameters.N.Default`, `Name ==
/// to_lower(Properties.N)`: only the `%name`s a side reaches can bring the resource in); a block clause
/// walks its query and its block's clauses the same way, a `when` block its conditions and its body; a
/// named rule or a parameterized call reaches a rule whose answer is the root's, `None`. One reading
/// answered `None` for any clause that was not a plain access clause and for a key-rooted right-hand
/// side, so a `let` holding such a filter was nobody's binding, and the `when` over it was measured on
/// every resource, the quiet probes kept nothing of it, and the member notice recorded no quiet verdict
/// for a filter that named it.
fn predicate_document_level_bindings<'value, 'loc: 'value>(
    conjunctions: &'value Conjunctions<GuardClause<'loc>>,
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    let mut bindings = BTreeSet::new();
    for clause in conjunctions.iter().flatten() {
        match clause {
            GuardClause::Clause(inner) => {
                bindings.append(&mut access_clause_document_level_bindings(inner, resolver)?);
            }
            GuardClause::BlockClause(block) => {
                bindings.append(&mut inner_query_document_level_bindings(
                    &block.query.query,
                    resolver,
                )?);
                bindings.append(&mut block_document_level_bindings(&block.block, resolver)?);
            }
            GuardClause::WhenBlock(conditions, body) => {
                for condition in conditions.iter().flatten() {
                    let WhenGuardClause::Clause(inner) = condition else {
                        return None;
                    };
                    bindings.append(&mut access_clause_document_level_bindings(inner, resolver)?);
                }
                bindings.append(&mut block_document_level_bindings(body, resolver)?);
            }
            GuardClause::NamedRule(_) | GuardClause::ParameterizedNamedRule(_) => return None,
        }
    }
    Some(bindings)
}

/// One access clause of a predicate, both sides read against the filtered element
/// (`predicate_document_level_bindings`).
fn access_clause_document_level_bindings<'value, 'loc: 'value>(
    clause: &'value GuardAccessClause<'loc>,
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    let mut bindings =
        inner_query_document_level_bindings(&clause.access_clause.query.query, resolver)?;
    if let Some(value) = clause.access_clause.compare_with.as_ref() {
        bindings.append(&mut predicate_value_document_level_bindings(
            value, resolver,
        )?);
    }
    Some(bindings)
}

/// A block inside a predicate (`predicate_document_level_bindings`): its clauses read against the
/// element the block is over, so they are walked as the predicate's are; a block that declares a `let`
/// of its own binds a name its clauses may read and this walk does not resolve, `None`.
fn block_document_level_bindings<'value, 'loc: 'value>(
    block: &'value crate::rules::exprs::Block<'loc, GuardClause<'loc>>,
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    if !block.assignments.is_empty() {
        return None;
    }
    predicate_document_level_bindings(&block.conjunctions, resolver)
}

/// The right-hand side of a clause inside a predicate, or a map-key filter's: a literal rests on
/// nothing, a query on the `%name`s it reaches with a key root allowed (it is read against the filtered
/// element), a call on what its arguments rest on, each read the same way.
fn predicate_value_document_level_bindings<'value, 'loc: 'value>(
    value: &'value LetValue<'loc>,
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    match value {
        LetValue::Value(_) => Some(BTreeSet::new()),
        LetValue::AccessClause(query) => {
            inner_query_document_level_bindings(&query.query, resolver)
        }
        LetValue::FunctionCall(call) => {
            let mut bindings = BTreeSet::new();
            for argument in &call.parameters {
                bindings.append(&mut predicate_value_document_level_bindings(
                    argument, resolver,
                )?);
            }
            Some(bindings)
        }
    }
}

/// The right-hand-side half of [`document_level_bindings`]: a literal rests on nothing, a query that
/// qualifies on its names, a call on what its every argument rests on.
fn let_value_document_level_bindings<'value, 'loc: 'value>(
    value: &'value LetValue<'loc>,
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    match value {
        LetValue::Value(_) => Some(BTreeSet::new()),
        LetValue::AccessClause(query) => query_document_level_bindings(&query.query, resolver),
        LetValue::FunctionCall(call) => function_call_document_level_bindings(call, resolver),
    }
}

/// What a function call's arguments rest on, when each of them qualifies: the call's value is a
/// function of its arguments and of nothing else. Also what a block scope answers `binding_owners` from
/// for a `let` of its own bound to a call, when the `let` is bound again for every resource or call.
pub(in crate::rules) fn function_call_document_level_bindings<'value, 'loc: 'value>(
    call: &'value FunctionExpr<'loc>,
    resolver: &dyn EvalContext<'value, 'loc>,
) -> Option<BTreeSet<BindingId<'value>>> {
    let mut bindings = BTreeSet::new();
    for argument in &call.parameters {
        bindings.append(&mut let_value_document_level_bindings(argument, resolver)?);
    }
    Some(bindings)
}

/// A `when` condition as the rules file spells it: an access clause through `clause_as_written`
/// (symbolic operators, a filter with its predicate; its `Display` is the record-tree rendering and
/// stood in for a filter with `(filter-clauses)`). Every part is joined with single spaces as it is
/// built and no whitespace is collapsed afterwards, so the inside of a string literal reaches the notice
/// as the author wrote it: a collapse over the finished text read the spaces inside `"a  b"` like the
/// padding around an operator and quoted the condition as `'a b'`. The fallback exists on this tree
/// because the as-written renderer answers `None` for one condition shape, a filter whose predicate
/// holds a named-rule reference or a nested block, which `predicate_as_written` cannot write out (every
/// comparator has a spelling); that condition is named through the record-tree rendering, and only that
/// text has its whitespace joined to one line, since the rendering pads its parts and no literal the
/// renderer declined is inside it. A literal cannot hold a raw line ending, so the notice stays on one
/// line.
fn when_clause_text(condition: &WhenGuardClause<'_>) -> String {
    match condition {
        WhenGuardClause::Clause(gac) => clause_as_written(gac).unwrap_or_else(|| {
            gac.to_string()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        }),
        WhenGuardClause::NamedRule(gnc) => format!(
            "{}{}",
            if gnc.negation { "not " } else { "" },
            gnc.dependent_rule
        ),
        // Each argument through the renderer the plain-condition arm uses for its right-hand side, so a
        // string argument is quoted as the grammar reads it and a query argument writes its filter out;
        // `LetValue`'s `Display` quoted `'a"  b'` as `"a"  b"` and printed a filter as `(filter-clauses)`.
        WhenGuardClause::ParameterizedNamedRule(prc) => format!(
            "{}{}({})",
            if prc.named_rule.negation { "not " } else { "" },
            prc.named_rule.dependent_rule,
            prc.parameters
                .iter()
                // As written, like the access-clause arm: `LetValue`'s `Display` is the record-tree
                // rendering, which named a filter argument `(filter-clauses)`.
                .map(|argument| {
                    let_value_as_written(argument).unwrap_or_else(|| argument.to_string())
                })
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn when_clause_location<'c, 'loc>(condition: &'c WhenGuardClause<'loc>) -> &'c FileLocation<'loc> {
    match condition {
        WhenGuardClause::Clause(gac) => &gac.access_clause.location,
        WhenGuardClause::NamedRule(gnc) => &gnc.location,
        WhenGuardClause::ParameterizedNamedRule(prc) => &prc.named_rule.location,
    }
}

/// `role` is [`ClauseRole::Gate`] when this clause is a `when` condition; see
/// [`binary_operation`].
#[allow(clippy::never_loop)]
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
            &gac.access_clause.query,
            gac.access_clause.comparator,
            gac.negation,
            format!("{}", gac),
            gac.access_clause.custom_message.clone(),
            resolver,
            role,
        )
    } else {
        // The right-hand side with the shape its retrieval reported: where the query enumerated, if
        // anywhere, which `IN` reads to compare against the values as one set or as the one value the
        // query names. Reported by the retrieval rather than read off the parse tree, so a reserved slot
        // the walk consumed (`%t[0]`), an interpolation that denoted one key, and a binding's own
        // enumeration are all what the walk did. A literal names its value.
        let (rhs, rhs_shape) = match &gac.access_clause.compare_with {
            Some(val) => match val {
                LetValue::Value(rhs_val) => (
                    vec![QueryResult::Literal(Rc::new(rhs_val.clone()))],
                    RhsEnumeration::Names,
                ),
                // The same treatment the clause's own query gets further down, for the same reason.
                //
                // Both arms recorded the clause as failing and then propagated the error regardless, so
                // an unevaluatable right-hand side aborted the run at 255 while the identical error on
                // the left exited 19. `%fine == %too_big` and `%too_big == %fine` disagreed about
                // whether a template that does not fit an i64 is a policy failure or a broken tool.
                //
                // Only for an assertion, and a gate still keeps the error, which is the split the
                // left-hand side and `eval_when_condition_block` already use.
                LetValue::AccessClause(acc_querty) => {
                    // Under `some`, only the values the query resolved, which is what the `let`
                    // binding of the same query keeps. The parser records the modifier on the
                    // right-hand query and this passed the bare parts to the resolver, so a `some`
                    // written here ran as `all`: the unresolved entry was compared, recorded as an
                    // unresolved right-hand side, and failed a clause whose `let` spelling passed.
                    // The shape the retrieval reported is kept beside the filtered values.
                    // A right-hand side that is the empty selection a one-object filter left, handed
                    // on bare (`%allowed == this` in a block body running over it): the clause read
                    // the selection as `this == %allowed` reads it on the left, so it is not judged as
                    // one that decided on nothing read (`EmptySelection::clause_decided`), and the
                    // read is decided as the left-hand side's and the unary clause's are
                    // (`LacksKeysNote::refuse_bare_read`: refused over an object holding an entry the
                    // predicate compared against or whose list twin could not be evaluated): the
                    // marker joins the values inside a filter predicate, for the comparison's
                    // `RhsUnresolved` arm to read undecided; the held refusal takes the
                    // refused-right-hand-side path below outside one.
                    let resolved = match resolver.query_with_shape(&acc_querty.query) {
                        Ok((result, shape, passed_on)) => {
                            let in_predicate = resolver.in_predicate();
                            let mut result = resolved_only_under_some(result, acc_querty.match_all);
                            passed_on
                                .read_bare(in_predicate, &mut result)
                                .map(|()| (result, shape))
                        }
                        Err(e) => Err(e),
                    };
                    match resolved {
                        Ok(resolved) => resolved,
                        Err(e) => {
                            resolver.end_record(
                                &blk_context,
                                RecordType::GuardClauseBlockCheck(BlockCheck {
                                    status: Status::FAIL,
                                    at_least_one_matches: !all,
                                    message: Some(format!(
                                        "Error {e} when handling clause, bailing"
                                    )),
                                    refusal: is_refusal(&e),
                                }),
                            )?;
                            return match (is_unevaluatable(&e), role.is_strict()) {
                                (true, true) => Ok(Status::FAIL),
                                _ => Err(e),
                            };
                        }
                    }
                }
                LetValue::FunctionCall(function) => {
                    // The call's own record is not read here: an argument that was an empty selection
                    // was counted, or refused, at the call's argument site.
                    match resolve_function_with_shape(function, resolver) {
                        Ok((result, shape, _)) => (result, shape),
                        Err(e) => {
                            resolver.end_record(
                                &blk_context,
                                RecordType::GuardClauseBlockCheck(BlockCheck {
                                    status: Status::FAIL,
                                    at_least_one_matches: !all,
                                    message: Some(format!(
                                        "Error {e} when handling clause, bailing"
                                    )),
                                    refusal: is_refusal(&e),
                                }),
                            )?;
                            return match (is_unevaluatable(&e), role.is_strict()) {
                                (true, true) => Ok(Status::FAIL),
                                _ => Err(e),
                            };
                        }
                    }
                }
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
                        refusal: false,
                    }),
                )?;
                // A binary clause with no right-hand side is a shape the parser does not produce, so
                // reaching here means a `RulesFile` assembled without the parser: a broken invariant of
                // cfn-guard's own, like the arity check in `eval_parameterized_rule_call`, raised as the
                // same `InternalError` variant. No disjunction hold admits it and the run stops as an
                // internal failure, not as the rules file's mistake, which the author could not repair.
                // `a_binary_clause_with_no_right_hand_side_is_an_internal_error` reaches this arm the
                // only way left, by stripping a parsed clause's right-hand side.
                return Err(Error::InternalError(
                    crate::rules::errors::InternalError::UncheckedParserInvariant(format!(
                        "GuardAccessClause {}, did not have a RHS for compare operation",
                        blk_context
                    )),
                ));
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
        // Only `IN` reads the shape. It cannot be read off the values in `rhs`: `Types[*]` over a
        // one-entry `Types` and `Types[0]` resolve to one identical `QueryResult`, and `IN` owes them
        // different answers -- the first names an entry set, the second a haystack -- which is why the
        // retrieval reports it.
        let rhs_enumerates = match comparator.0 {
            CmpOperator::In => rhs_shape,
            _ => RhsEnumeration::Names,
        };
        // A bare `%v` is the one right-hand spelling whose resolved `Rc`s the scope memoizes, so it is
        // the one whose entry sets `IN` may cache across evaluations.
        let rhs_shared = matches!(
            &gac.access_clause.compare_with,
            Some(LetValue::AccessClause(query)) if bare_variable_root(&query.query).is_some()
        );
        binary_operation(
            &gac.access_clause.query.query,
            &rhs,
            comparator,
            format!("{}", gac),
            gac.access_clause.custom_message.clone(),
            resolver,
            role,
            &gac.access_clause.location,
            all,
            rhs_enumerates,
            rhs_shared,
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
                        refusal: false,
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
                    // An empty vector does not reach the `all` branch as a PASS. A left-hand
                    // collection with no element is answered per value by `binary_operation`, on `IN`
                    // as on every other operator, and a right-hand one by its compared-nothing arm,
                    // each with a reason.
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
                        refusal: false,
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
                    refusal: is_refusal(&e),
                }),
            )?;

            // A clause whose own value could not be produced fails, and the rest of the file still
            // reports. Errors reach here from resolving the clause's query, which includes a `let`
            // whose function call could not convert its input: `let n = parse_int(Properties.Name)`
            // on a non-numeric name fails that clause rather than aborting the run at exit 255, which
            // would discard every other rule's verdict, including real violations an unrelated rule
            // had already found. The same split the incompatible-type arm makes, reached through a
            // function instead of an operator.
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
                // Gates only, not filters. `when not p(..)` guards a block, and a `p` that does not
                // apply has nothing to say about it, so its negation passes and the remaining
                // conditions decide. `Resources.*[ not p(Properties) ]` asks for the resources `p`
                // rejects, and one `p` has no opinion on is not among them: under `Filter` the SKIP
                // stands and the element is deselected, as for any predicate that cannot be
                // evaluated. Letting it pass selected every resource the rule did not apply to.
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
                            refusal: false,
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

/// The refusal a filter predicate's body met, folded as the block's own undecided reason and marked in
/// the record tree: one failed `GuardClauseBlockCheck` in the block's own `GuardBlockAccessClause#`
/// context (`guard_cxt`) with no children, the mark the per-value arm leaves for a value's body whose
/// read raised the marker. One function for the two arms that meet the refusal, the clause that read the
/// marker raising `UndecidableComparison` and a data-dependent error arriving at the block's `Err(e)` arm
/// after the selection refused a read, so the tree reads the same whichever clause of the body ran first:
/// `{ let n = parse_int(%kind)  %n == 1  Sid exists }` leaves the mark `{ Sid exists  let n =
/// parse_int(%kind)  %n == 1 }` leaves. The record carries no sentence of its own, as the
/// per-value arm's does not: every reporter stops at the filter's record (`find_failing_clauses`), so a
/// sentence here would be recorded and never rendered; the refusal's text reaches the reader through the
/// enclosing clause, which fails on the undecidable marker the selection delivered and prints its reason.
/// `fails` and `undecided` are the block's fold: one more failed body, and the FIRST reason kept. Both
/// arms hand it the FIRST refusal the selection delivered (`EmptySelection::refusal_text`), so the text
/// a refused body reports does not depend on which arm met it either.
fn fold_refused_body<'value, 'loc: 'value>(
    resolver: &mut dyn EvalContext<'value, 'loc>,
    guard_cxt: &str,
    match_all: bool,
    fails: &mut usize,
    undecided: &mut Option<Error>,
    reason: String,
) -> Result<()> {
    resolver.start_record(guard_cxt)?;
    resolver.end_record(
        guard_cxt,
        RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: !match_all,
            message: None,
            refusal: false,
        }),
    )?;
    *fails += 1;
    if undecided.is_none() {
        *undecided = Some(Error::UndecidableComparison(reason));
    }
    Ok(())
}

/// The error a block delivers for a body read refused over the empty selection a one-object filter left:
/// the refusal the selection delivered first (`kept`, the text `LacksKeysNote::deliver` keeps), re-minted
/// as a refusal (`refuse`), whatever error arrived: that refusal itself, a data-dependent error of another
/// clause, or a second refusal a gate-role body ran on to. With no kept refusal, the arriving error is the
/// read the body could not make, wrapped in a sentence that says so and raised as `Unevaluatable`, since
/// the error it carries may hold a value.
///
/// Re-minted rather than passed through, and decided by the kept text alone, never by comparing the two
/// errors' renderings: the kept text is the first refusal's, so an arriving refusal re-mints to an equal
/// value, and an error of another variant that happens to render the same text is not that refusal and
/// does not travel as one.
fn body_refusal_to_deliver(e: Error, kept: Option<String>) -> Error {
    match kept {
        Some(refusal) => refuse(refusal),
        None => Error::unanswerable_from(
            false,
            format!(
                "the body could not be read over the empty selection, so the read is refused: {e}"
            ),
        ),
    }
}

/// What failed in a block clause that fails closed through `fail_block_on_unevaluatable`: its query
/// could not be evaluated on this data; or its query evaluated to the empty selection a one-object
/// filter left and a clause of the body, run over that selection as a gate, read a key from it that
/// the inline arm's shape test refuses (`EmptySelection::read_from_the_empty_selection`), the held
/// refusal handed up, or met a data-dependent error over that selection (a value a clause could not
/// read as it asks), which is treated as the refused read and named inside the refusal's sentence. A
/// mistake in the rules file met by the body is not a failure of this kind: it is raised and stops the
/// run, as it does everywhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockFailure {
    QueryUnevaluatable,
    BodyReadRefused,
}

/// A block clause whose query, or whose body's read of the empty selection a one-object filter left,
/// could not be evaluated on this data: the same split the access clause makes for its own query, so
/// the block-clause spelling of a clause answers like the access-clause spelling: `Resources.%sizes {
/// Type exists }` and `Resources.%sizes exists` both fail closed as assertions when `%sizes` holds
/// non-strings, rather than the block clause alone returning the error and stopping the run. A
/// gate keeps the error so the enclosing condition site fails its rule closed, and every other error
/// stops the run. The record carries a message in both cases: when the data could not answer, as an
/// assertion this arm fails closed and the reporters read the record; as a gate the error travels to the
/// enclosing condition, which fails its own rule closed, and the tree is reported all the same. Every
/// other error stops the run, and on that branch `validate` reports the tree before it applies `?` to
/// the error, so the sentence is what names the cause beside the rule's FAIL on stdout. The record's
/// message names which of the two happened (`BlockFailure`): the query that could not be evaluated, or
/// the body's read of the one-object filter's empty selection that was refused after the query
/// evaluated.
fn fail_block_on_unevaluatable<'value, 'loc: 'value>(
    resolver: &mut dyn EvalContext<'value, 'loc>,
    context: &str,
    match_all: bool,
    role: ClauseRole,
    failure: BlockFailure,
    e: Error,
) -> Result<Status> {
    let unevaluatable = is_unevaluatable(&e);
    resolver.end_record(
        context,
        RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: !match_all,
            // The kind of the error embedded below, whichever sentence wraps it: a body read refused
            // with the refusal itself prints whole on the console; one refused with a text that wraps
            // another error, or a query that raised a converter's message with the value it could not
            // convert, is held to the cap like any message that may carry a value.
            refusal: is_refusal(&e),
            message: Some(match (failure, unevaluatable) {
                (BlockFailure::BodyReadRefused, _) => format!(
                    "The block's body read the empty selection a one-object filter left, and the \
                     read was refused: {}",
                    e
                ),
                (BlockFailure::QueryUnevaluatable, true) => format!(
                    "The block's query could not be evaluated on this data: {}",
                    e
                ),
                (BlockFailure::QueryUnevaluatable, false) => format!(
                    "The block's query raised an error that is not about the data, so the run \
                     stops: {}",
                    e
                ),
            }),
        }),
    )?;
    match (unevaluatable, role.is_strict()) {
        (true, true) => Ok(Status::FAIL),
        _ => Err(e),
    }
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
    let (mut block_values, passed_on) = match resolver.query_with_shape(&block_clause.query.query) {
        Ok((values, _, passed_on)) => (values, passed_on),
        // The same split the access clause makes for its own query, so the block-clause spelling
        // of a clause answers like the access-clause spelling: `Resources.%sizes { Type exists }`
        // and `Resources.%sizes exists` both fail closed as assertions when `%sizes` holds
        // non-strings, rather than the block clause alone returning the error and stopping the
        // run. A gate keeps the error so the enclosing condition site fails its rule closed, and
        // every other error stops the run.
        Err(e) => {
            return fail_block_on_unevaluatable(
                resolver,
                &context,
                match_all,
                role,
                BlockFailure::QueryUnevaluatable,
                e,
            )
        }
    };
    let mut fails = 0;
    let mut passes = 0;
    // The two readings of a failure the fold below cannot tell apart, kept beside the counts for the
    // same reason `ResultEvidence` keeps them for a clause: the first reason a value could not be
    // decided, and how many values were decided against. Read together after the loop, by the table
    // `undecided_gate` holds for the clause form.
    let mut undecided: Option<Error> = None;
    let mut decided_fails = 0;
    // The block form of the lacks-keys refusal. `Tags[*][ Key == 'Env' ] { Value == 'prod' }` over
    // map-shaped tags is the author's `Tags[*][ Key == 'Env' ].Value == 'prod'` with the key read in the
    // body, and the inline spelling is refused over `{ Env: dev }` because the filter read one object
    // holding none of the predicate's keys, kept nothing, and `Value` is read from it. The block's query
    // has nothing after the filter, so the retrieval hands the empty selection on with the fact beside
    // it (`eval_context::LacksKeysNote`, through the shape it reports), and the body RUNS over that empty
    // selection once, in a scope that holds the note (`ValueScope::empty_selection`): every `this`- or
    // key-rooted query a clause makes is answered from the note where it is made
    // (`EmptySelection::read_from_the_empty_selection`), judged by the shape test the inline arm judges
    // the part after its filter by. A clause reading the object as the shape the rule was written for (a
    // held key beside another key, no entry the predicate compared against) reads nothing and is not
    // applicable, as the inline spelling with such a key after the filter is; a clause reading any other
    // key is refused on the object as the inline spelling is; a `when` block in the body whose condition
    // does not hold reads nothing; a body that names no key reads nothing and is the empty selection.
    // Inside a filter predicate the refusal is the undecidable marker the inline spelling leaves there,
    // which the clause that read it raises as undecided, kept below as the block's own and raised after
    // the fold unless a sibling decided, so an assertion fails closed and a gate hands the reason to its
    // condition site; outside one it is the held refusal the inline arm raises, which the clause fails
    // closed on as an assertion, with the reason in its record, and hands up as a gate, so `some` cannot
    // decide past it with a sibling. The block form and the inline spelling answer the same way, so a
    // block over the one-object map fails closed exactly where its one-element-list twin fails. A body
    // whose every read is not applicable leaves the selection empty, decided below as the one-element
    // list decides it.
    // The selections the body runs over: one per note the block's own query handed on, whether or not
    // the query also selected values (a map-shaped `Tags` beside a list-shaped one under `Resources.*`
    // hands on the list's element and the map's note together, and the map is judged before the
    // element is folded, as the inline spelling holds its refusal before the list's value is read); or,
    // for a nested block written inside such a body over the enclosing selection itself, that selection
    // and not a copy: `{ this { Value == 'prod' } }` is the author's `{ Value == 'prod' }` with one more
    // brace, and `{ let v = this  %v { Value == 'prod' } }` and `rule check(p) { %p { Value == 'prod' } }`
    // called as `check(this)` read the same object through an alias of `this`. The bare `this` handed the
    // enclosing selection's own note on (`read_from_the_empty_selection`), with the flag the selection
    // reads, so a note the block's query passed on that shares that flag names the enclosing selection
    // (`EmptySelection::shares_the_flag_of`); the nested body runs over it, its reads are held there and
    // its refusal is the one refusal the enclosing block reads. A copy with a fresh flag would be refused
    // on its own and leave the enclosing body to refuse a second time, naming the whole body as the read.
    let enclosing = resolver.empty_selection();
    let mut selections: Vec<Rc<EmptySelection>> = Vec::new();
    for note in passed_on.lacks_keys() {
        let selection = match &enclosing {
            Some(shared) if shared.shares_the_flag_of(note) => Rc::clone(shared),
            _ => Rc::new(EmptySelection::of(note.clone())),
        };
        // Two aliases of `this` in one query name the enclosing selection once.
        if !selections.iter().any(|known| Rc::ptr_eq(known, &selection)) {
            selections.push(selection);
        }
    }
    for selection in selections {
        let in_predicate = resolver.in_predicate();
        // This run's judgement is its own: a nested block over the bare selection runs over the same
        // selection as the body that holds it, and the flag its clauses set is read by its own
        // `held_only_refusal` below, with the enclosing run's flag parked in the guard meanwhile
        // (`BodyRun::ends` hands this run's back; the guard puts the enclosing run's in place when it
        // goes, on an error path too).
        let body_run = selection.body_run();
        // The body runs over the empty selection as a DISCOVERY of the reads it refuses, never as an
        // evaluation of values: it runs under a quiet scope, which drops the records, captures and
        // notices the body's clauses would deposit, and under a quiet measurement, so a named rule the
        // body calls is not memoized and a binding it resolves is taken back when the run ends. The
        // list twin never runs this body (its filter kept nothing), so nothing the body did along the way
        // may show in the record or change a sibling's reading. What the discovery
        // finds is read from the selection afterwards (`refused`, `refusal_text`, `held_only_refusal`)
        // and recorded by this block, the one record a refused body leaves.
        let outcome = {
            // The reading in force stays in force: a discovery under a running measurement (a `when`
            // gate's dropped-entries reading) is read the way that reading reads a function result's
            // entries, as `QuietScope::read_clause_for_a_probe` keeps it; the quiet reading is entered
            // only from `Off`.
            let reading_mode = match resolver.measurement() {
                Measurement::Off => Measurement::Quiet,
                measuring => measuring,
            };
            let mut quiet = eval_context::QuietScope::over(selection.object(), resolver);
            let mut reading = eval_context::NestedMeasurement::enter(&mut quiet, reading_mode);
            let mut over_the_empty_selection = ValueScope {
                root: selection.object(),
                parent: &mut *reading,
                in_predicate,
                this_is_the_population: false,
                // The object the note keeps came from the block's own query, as the real values
                // beneath did: the same provenance the value scope below records.
                root_from: eval_context::RootProvenance::of(&block_clause.query.query),
                empty_selection: Some(Rc::clone(&selection)),
            };
            // Each clause of the body is marked before it runs and judged once it has decided, where it
            // is evaluated (`eval_guard_clause`): a top-level clause, a clause inside a `when` block of
            // the body, inside a nested block or inside a rule the body calls, each on its own reads.
            eval_general_block_clause(
                &block_clause.block,
                &mut over_the_empty_selection,
                |gc, r| eval_guard_clause(gc, r, role),
            )
        };
        let decided_on_nothing_read = body_run.ends();
        match outcome {
            // A read the selection refused outside a filter predicate is delivered to the clause that
            // made it as the held refusal, which the clause fails closed on: the body's FAIL is the
            // refusal's, and the block fails with it at once, as the inline spelling fails at its query
            // before the list's value is read. Held at the clause whatever the quantifier: counted into the
            // fold instead, a passing list-shaped sibling decided past it under `some`, and the two
            // functions the inline `some` spelling fails passed at exit 0 one spelling over. The
            // sentence is this record's: the discovery recorded nothing beneath it.
            // Outside a filter predicate only: inside one the refusal is the undecidable marker, which
            // the clause that read it raises as an error and the arms below count as undecided, so the
            // entry under test is never deselected by a decided FAIL (`Resources.*[ ... Tags[*][ Key ==
            // 'Env' ] { ... } ] empty` fails closed on the refusal). The flag is set by every refusal,
            // inside a predicate too, so the arm reads the role as well as the flag.
            Ok(Status::FAIL) if selection.refused() && !in_predicate => {
                // The discovery recorded nothing, so the refusal's sentence is this record's: the text
                // the clause that made the read delivered, kept on the selection's note.
                let refusal = selection.refusal_text().unwrap_or_else(|| {
                    "the read was refused by the one-object filter's note".to_string()
                });
                resolver.end_record(
                    &context,
                    RecordType::BlockGuardCheck(BlockCheck {
                        status: Status::FAIL,
                        at_least_one_matches: !match_all,
                        message: Some(format!(
                            "The block's body read the empty selection a one-object filter left, and \
                             the read was refused: {refusal}"
                        )),
                        // `refusal` is the text a refusal delivered, so the message is a refusal's.
                        refusal: true,
                    }),
                )?;
                return Ok(Status::FAIL);
            }
            // Otherwise the body ran over the empty selection to find the reads it refuses, not to decide
            // values. The keys it read are then judged together, as the inline chained filter judges its
            // predicate's keys (`EmptySelection::held_only_refusal`): a body that read every key the
            // object has is refused as that filter is, and so is a body that read no key and one of whose
            // clauses decided on nothing read from the selection (`%flag == true`, alone or beside a bare
            // `this exists`, at the top level or inside a `when` block, a nested block or a rule the body
            // calls), as the filter is over a predicate naming no key of the object; the refusal is
            // delivered through the arms the block's own query uses (the marker as a block value inside a
            // predicate, the held refusal outside). A body that read some keys beside others the object
            // holds (`{ Effect exists  %flag == true }` over a statement of `Effect`, `Action` and
            // `Resource`, judged on `Effect` as the chained filter `[ Effect exists  %flag == true ]` is),
            // or decided nothing (a
            // closed `when` gate), or decided only through its bare reads, leaves the selection empty,
            // decided as such below. The status is not read here: which clause decided, and what it read,
            // was judged clause by clause as the body ran (`clause_decided`), on this run's own flag.
            Ok(_) => match selection.held_only_refusal(
                in_predicate,
                decided_on_nothing_read,
                &block_clause.block,
            ) {
                None => {}
                Some(Ok(marker)) => block_values.push(marker),
                Some(Err(e)) => {
                    return fail_block_on_unevaluatable(
                        resolver,
                        &context,
                        match_all,
                        role,
                        BlockFailure::BodyReadRefused,
                        e,
                    )
                }
            },
            // The refusal met inside a filter predicate, raised by the clause that read the marker
            // as a gate: the block's own undecided reason, folded after the loop as a value's would be,
            // and marked beneath the block by `fold_refused_body`, the one function both arms that meet
            // the refusal fold through (the `Err(e)` arm below reaches it for the same refusal met after
            // another clause's error), so the record tree reads the same whichever clause ran first.
            Err(Error::UndecidableComparison(reason)) if !role.is_strict() => {
                // The text folded is the FIRST refusal the selection delivered (`refusal_text`, the one
                // `LacksKeysNote::deliver` keeps), as the `Err(e)` arm folds it, so a body refused twice
                // (`{ Sid == 'x' or %flag == true  Condition exists }` over a statement lacking both)
                // reports the same read inside a predicate as outside one; the marker's own reason is
                // the fallback for a marker no refusal of this selection stands behind.
                let first = selection.refusal_text().unwrap_or(reason);
                fold_refused_body(
                    resolver,
                    &format!("GuardBlockAccessClause#{}", block_clause.location),
                    match_all,
                    &mut fails,
                    &mut undecided,
                    first,
                )?;
            }
            // The held refusal handed up by a gate: the enclosing condition site fails its rule
            // closed, through the same arm the block's own query takes. A data-dependent error the body
            // met over the selection (a value a clause could not read as it asks: `is_unevaluatable`, the
            // class every other site decides as a verdict) is treated as the refused read too: the
            // discovery could not read the body over the selection, so the block fails closed on it, as
            // an assertion here and at the condition site as a gate, and the run goes on, the same
            // whichever shape the data has. When the selection has already refused a read of the body,
            // the refusal is what the block delivers, in the words of the FIRST read it refused
            // (`LacksKeysNote::deliver` keeps the first text), whichever error arrives here: the error
            // itself when it is that refusal (passed through unchanged), or the kept refusal when a
            // data-dependent error of another clause, or a second refusal a gate-role body ran on to,
            // arrived in its place. A mistake in the rules file (an unbound `%variable`, a call to
            // a rule the file does not declare) and an `InternalError` (a fault in the tool, which no
            // rules file can reach) are raised unchanged, as they are everywhere else, so the run stops
            // on them, refused selection or not.
            Err(e) => {
                if !is_unevaluatable(&e) {
                    // The block's record is closed so the tree stays balanced, as the fold after the
                    // loop closes it before raising: a record left open is a tracker with no final
                    // event. Every other path out of this function that returns an error closes the
                    // record first too: the query arm and the two body-refusal arms through
                    // `fail_block_on_unevaluatable`, a value's body error through its own `end_record`,
                    // and the undecided fold before its raise; the one propagation that cannot close
                    // it is the `?` on the tracker's own `start_record` and `end_record` calls, which
                    // every site in this file shares. No sentence of its own: the run stops on this
                    // error and the command prints it; nothing renders the record.
                    resolver.end_record(
                        &context,
                        RecordType::BlockGuardCheck(BlockCheck {
                            status: Status::FAIL,
                            at_least_one_matches: !match_all,
                            message: None,
                            refusal: false,
                        }),
                    )?;
                    return Err(e);
                }
                // Inside a filter predicate a refusal the selection delivered is folded as the clause
                // that read its marker folds it, through the same `fold_refused_body` as the arm above:
                // the block's own undecided reason, raised after the loop, and the mark beneath the
                // block, so the verdict and the record tree read the same whichever clause of the body
                // ran first.
                if in_predicate && !role.is_strict() && selection.refused() {
                    if let Some(refusal) = selection.refusal_text() {
                        fold_refused_body(
                            resolver,
                            &format!("GuardBlockAccessClause#{}", block_clause.location),
                            match_all,
                            &mut fails,
                            &mut undecided,
                            refusal,
                        )?;
                        continue;
                    }
                }
                let kept = match selection.refused() {
                    true => selection.refusal_text(),
                    false => None,
                };
                return fail_block_on_unevaluatable(
                    resolver,
                    &context,
                    match_all,
                    role,
                    BlockFailure::BodyReadRefused,
                    body_refusal_to_deliver(e, kept),
                );
            }
        }
    }
    if block_values.is_empty() && fails == 0 {
        let status = if block_clause.not_empty {
            Status::FAIL
        } else {
            Status::SKIP
        };
        // The reason is recorded here because here is where it is known: the branch condition *is*
        // the reason. `find_skip_reason` has an arm for this record shape already, so nothing was
        // missing but the message, and with `None` a block-form empty selection printed a bare
        // `Status = SKIP` with no reason line even under `--show-summary all`.
        //
        // Attached to the SKIP only, and not because the FAIL has no consumer. The sentence opens
        // "the rule did not apply", which is false of the `not_empty` FAIL -- there the rule did
        // apply and the clause failed for want of a value. A `not_empty` failure wants its own
        // wording, which is a separate change and not this one.
        let message = match status {
            Status::SKIP => Some(empty_selection_message(&block_clause.query.query)),
            _ => None,
        };
        resolver.end_record(
            &context,
            RecordType::BlockGuardCheck(BlockCheck {
                status,
                at_least_one_matches: !match_all,
                message,
                refusal: false,
            }),
        )?;
        return Ok(status);
    }
    // Whether the block's query names the document's population, so that a selection in the body over
    // `this` reads a null or empty value as the empty population: `Resources { this[ Type == 'X' ] ... }`
    // over a bare `Resources:` is the same check as `Resources[ Type == 'X' ] ...`, which selects
    // nothing, rather than a body run over the null that fails at exit 19. `names_the_population` is the
    // test the parameterized call uses for the same question. The scope built below carries the answer
    // as where its queries start (`QueryStart::Population`), so it travels with the block's own queries
    // and not into a filter predicate's, whose scope starts at its entry. Only a selection reads the
    // null that way: a body that reads the population's own keys runs over the null and fails as the
    // plain spelling does, and a block over an absent key fails in the unresolved arm below, since its
    // query comes back as the one unresolved result for the missing key and the block is the existence
    // check on it, as `Parameters exists` fails over a document with no `Parameters`. A bare `this` as
    // the block's query names the population exactly when this scope's own queries start there, so a
    // block nested in the population block keeps the reading.
    let this_is_the_population =
        names_the_population(&block_clause.query.query, resolver.query_start(), resolver);
    for each in block_values {
        match each {
            QueryResult::UnResolved(ur) => {
                fails += 1;
                // The marker a key filter leaves for a map it could not decide
                // (`UnResolvedKind::Undecidable`) is not a value the document lacks, and a gate cannot
                // read it as a decided no. As an assertion the block fails on it, which is the verdict
                // recorded below either way. As a gate (a parameterized rule whose body this block is,
                // called as a `when` condition) the marker's reason is kept rather than counted as a
                // failure like any other, which would report the rule not applicable with its body
                // unchecked at exit 0; it is raised after the loop unless the other values decide the
                // block, as the clause form raises it through `undecided_gate`, so the enclosing
                // condition site fails its rule closed. Inside a filter predicate the marker arrives
                // here too and is kept the same way, so the enclosing clause fails closed instead of
                // deselecting an entry nobody could decide. The record is written either way so the
                // tree names the reason. The kind is read by `undecidable_reason` on the borrowed
                // value, as the binary arms read it: no clone to ask, and no second kind test here.
                match (!role.is_strict())
                    .then(|| undecidable_reason(&ur).map(Error::UndecidableComparison))
                    .flatten()
                {
                    Some(error) => {
                        if undecided.is_none() {
                            undecided = Some(error);
                        }
                    }
                    None => decided_fails += 1,
                }
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
                        refusal: false,
                    })),
                )?;
            }

            QueryResult::Literal(rv) | QueryResult::Resolved(rv) => {
                // A block clause written inside a filter predicate is part of the predicate's test,
                // so the scope over the block's value carries the answer of the scope it opens from.
                let in_predicate = resolver.in_predicate();
                // A block over the document's own population, `Resources { ... }` or `%r { ... }` over
                // `let r = Resources`, opens a scope whose `this` IS the population, and the scope says
                // so, so a filter or a wildcard at the head of a query in the block reads a bare
                // `Resources:` and an empty `Resources` as the key spelling reads them: an empty
                // selection, not the absent key, and not an enumeration below a chosen subject. Decided
                // here, the one site that has the block's query, from the scope the block opens from,
                // which is what `Resources[ f ]` at the same spot is decided from.
                let mut val_resolver = ValueScope {
                    root: rv,
                    parent: resolver,
                    in_predicate,
                    this_is_the_population,
                    // `%m { ... }` rebases onto the binding's value, `Resources { ... }` onto a value
                    // of the enclosing root: the block's query head says which.
                    root_from: crate::rules::eval_context::RootProvenance::of(
                        &block_clause.query.query,
                    ),
                    empty_selection: None,
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
                            decided_fails += 1;
                        }
                        Status::SKIP => {}
                    },

                    // Same split for an error raised inside the block. An assertion fails closed for
                    // this value and the loop goes on; the value's own records say why, and the block
                    // clause's record is closed below with the fold's verdict. A gate keeps an
                    // UNDECIDED raise (the arm below) as the block's own `undecided` and goes on, so the
                    // table after the loop reads it beside the other values' verdicts; a gate hands any
                    // other unevaluatable error up so the enclosing condition site fails its rule
                    // closed, and every other error stops the run.
                    //
                    // The error is recorded against the value, so a reporter names it rather than
                    // falling back to its generic sentence for a block clause that has no failing
                    // children. A `GuardClauseBlockCheck` rather than the `MissingBlockValue` check
                    // the `UnResolved` arm above records: both reporters read that check's `from` as
                    // an unresolved path and `unreachable!()` on anything else, and this value did
                    // resolve.
                    //
                    // No rules file reaches the STRICT arm below today: `role` is passed down to every
                    // clause in the block, and each strict leaf (`eval_guard_access_clause`,
                    // `eval_when_condition_block`, `eval_rule`, `eval_parameterized_rule_call`, this
                    // function's own query arm) turns an unevaluatable error into FAIL before it can
                    // come back here, so as an assertion the only errors that arrive are the ones that
                    // stop the run. Until the parameterized call made its own split, an argument it
                    // could not convert arrived here and was counted without its text. The strict arm
                    // is here so the body answers like the query above if a leaf ever lets one through.
                    //
                    // As a GATE the leaves hand both unevaluatable kinds up, and the two are read
                    // differently here on purpose. A plain `Unevaluatable` from a value's body (a
                    // scalar a filter cannot walk, a value a converter cannot read) is not three-valued
                    // anywhere: the clause spelling of the same body hands it to the condition site,
                    // which fails the enclosing rule closed at once (`eval_rule`'s condition arm), with
                    // no sibling consulted. So the block spelling returns it too, through the last arm
                    // below, and the two spellings agree. Only `UndecidableComparison` is three-valued,
                    // through `undecided_gate` in the clause spelling, and only it is kept here.
                    //
                    // The undecided raise from a VALUE's body is the one a gate does meet here: a
                    // comparison or a unary operator inside the body over a key filter nobody can decide
                    // raises `UndecidableComparison` through `undecided_gate` when nothing in that body
                    // decided it. Returned from here it ended the loop at the first such value, so the
                    // block spelling failed its rule closed where the clause spelling of the same body
                    // read a decided sibling as settling `match_all` and reported not applicable, and
                    // the values after it were never evaluated. It is this value's answer: the value is
                    // marked failed (no sentence of its own: the clause inside the body that raised has
                    // recorded the reason, and a sentence here would be recorded and never rendered),
                    // the raise is kept as the block's first undecided reason, and the loop goes on; the
                    // table after the loop decides, as it does for the block's own query. The value
                    // counts as not passed, as an unresolved value does, and not as decided.
                    Err(Error::UndecidableComparison(reason)) if !role.is_strict() => {
                        // The same mark and fold as the empty-selection arms (`fold_refused_body`): a
                        // value's body that raised the marker is recorded as a refused body of this block.
                        fold_refused_body(
                            &mut val_resolver,
                            &format!("GuardBlockAccessClause#{}", block_clause.location),
                            match_all,
                            &mut fails,
                            &mut undecided,
                            reason,
                        )?;
                    }

                    Err(e) if is_unevaluatable(&e) && role.is_strict() => {
                        let guard_cxt = format!("GuardBlockAccessClause#{}", block_clause.location);
                        val_resolver.start_record(&guard_cxt)?;
                        val_resolver.end_record(
                            &guard_cxt,
                            RecordType::GuardClauseBlockCheck(BlockCheck {
                                status: Status::FAIL,
                                at_least_one_matches: !match_all,
                                message: Some(format!(
                                    "Error {} when evaluating the block clause for this value",
                                    e
                                )),
                                refusal: is_refusal(&e),
                            }),
                        )?;
                        fails += 1;
                        decided_fails += 1;
                    }

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
                                refusal: is_refusal(&e),
                            }),
                        )?;
                        return Err(e);
                    }
                }
            }
        }
    }

    // An undecided value raises only when no other value decided the block: the table `undecided_gate`
    // holds for the clause form, applied to the block form so the two spellings of one body agree as
    // gates. `some` is decided by any value that passed; `match_all` is decided by any value that failed
    // for a reason, an unresolved value the document lacks or a value whose block failed. Only the
    // middle row of each, nothing decided and something undecided, raises. Raising at the first
    // undecided value, as this did, let an undecided sibling manufacture a verdict out of a decided
    // conjunction (`a_block_clause_as_a_gate_finishes_the_loop_before_raising` pins both quantifiers
    // against the clause form), and left the values after it unevaluated, so the trace depended on the
    // order the maps were selected in. Every value is evaluated and recorded first, whatever the verdict,
    // the marker in the block's own query and the raise from a value's body alike
    // (`a_block_clause_as_a_gate_reads_an_undecided_body_beside_its_siblings`).
    if let Some(error) = undecided {
        let decided = match match_all {
            true => decided_fails > 0,
            false => passes > 0,
        };
        if !decided {
            // The block's own record is closed so the tree stays balanced, as the query arm closes it
            // before returning its error. No sentence of its own: the reporters render this record
            // through its children, and the `MissingBlockValue` check recorded in the loop carries the
            // marker's reason (measured in the verbose tree), while the enclosing condition site names
            // it again as the rule's reason in the console summary and in `-o json`. A sentence here
            // would be recorded and never shown.
            resolver.end_record(
                &context,
                RecordType::BlockGuardCheck(BlockCheck {
                    status: Status::FAIL,
                    at_least_one_matches: !match_all,
                    message: None,
                    refusal: false,
                }),
            )?;
            return Err(error);
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
            refusal: false,
        }),
    )?;
    Ok(status)
}

/// `role` is the role of the context this `when` block appears in, and it is inherited by the
/// guarded body.
///
/// Required rather than defaulted on purpose. A hardcoded [`ClauseRole::Assertion`] for the body,
/// on the reasoning that a guarded block holds the rule's own assertions however its conditions
/// were evaluated, is right for a rule evaluated as an assertion and wrong for one evaluated as a
/// gate: the body of a gate is part of deciding whether the gate applies, so an unevaluatable
/// clause in it has to SKIP rather than fail closed.
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
    // The condition is a gate over the block: while it runs, a clause of a body over the empty selection
    // is not judged (`EmptySelection::condition_begins`), so a parameterized condition (`when check(%flag)`
    // with `rule check(p) { %p == true }`, whose clauses pass through `eval_guard_clause`) reads as the
    // inline one (`when %flag == true`, which never does): a closed gate leaves the block not applicable
    // and refuses nothing. The block's own clauses are judged again once the condition has decided.
    let parked = resolver
        .empty_selection()
        .map(|selection| selection.condition_begins());
    let decided = eval_conjunction_clauses(conditions, resolver, eval_when_clause);
    if let Some(enclosing) = parked {
        if let Some(selection) = resolver.empty_selection() {
            selection.condition_ends(enclosing);
        }
    }
    let block = match decided {
        Ok(status) => {
            // A `when` block in a type block's or a block clause's body runs once per resource, in a
            // scope rooted at that resource, so its line names the resource the way a type block's
            // condition does; at the rule level the scope is rooted at the document and there is none.
            let root = resolver.root();
            let resource = (!root.self_path().0.is_empty()).then(|| root.self_path());
            announce_a_moved_when(conditions, status, resource, resolver);
            if status != Status::PASS {
                resolver.end_record(&when_context, RecordType::WhenCondition(status))?;
                resolver.end_record(
                    &context,
                    RecordType::WhenCheck(BlockCheck {
                        status: Status::SKIP,
                        at_least_one_matches: false,
                        message: None,
                        refusal: false,
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
                    refusal: is_refusal(&e),
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
            // exits 0 with the `Encrypted` violation unreported when the gate answers FAIL, where
            // keeping the error exits 19.
            // Converting the undecidable answer to a status here loses the information the outer
            // rule needs to fail closed. Keeping the error for a gate carries it to the enclosing
            // condition site, which fails its own rule closed instead of deciding the rule does not
            // apply.
            //
            // `an_undecidable_nested_gate_does_not_silence_the_outer_rule` is the regression test,
            // and it asserts the reported violation rather than only the exit code, because exit 19
            // alone does not tell a run that names the `Encrypted` violation from one that fails the
            // rule for another reason.
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
                        refusal: false,
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
                        refusal: is_refusal(&e),
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
    /// For each parameter the call site passed as a query, that query.
    ///
    /// A parameter is a binding like any other, and `%parameter` is spelled and evaluated as a query
    /// root, so the root-variable arm has the same question to ask about it: did resolving it already
    /// enumerate? Only `LetValue::AccessClause` arguments appear here -- a literal or a function call is
    /// one value, and `variable_binding_query` reports those as `None` by their absence.
    ///
    /// Recorded rather than recomputed, because the mapping from a parameter's *name* to the argument at
    /// its position lives in `param_rule.parameter_names`, which this scope does not hold.
    parameter_queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
    /// For every parameter, the argument the call site passed, as written: a query, a literal or a
    /// function call. Read by `variable_binding_source`, so a notice about a filter through `%p` can
    /// name the parameter with its argument whatever kind the argument was; `parameter_queries` holds
    /// the queries alone, for the questions only a query answers.
    parameter_arguments: HashMap<&'value str, &'value LetValue<'loc>>,
    /// The parameters whose argument named the document's population, `names(Resources)` or
    /// `names(%resources)` over `let resources = Resources`, recorded at the call site because the
    /// resolved values alone cannot say where they came from. See `names_the_population`.
    population_parameters: HashSet<&'value str>,
    /// For every parameter, where the argument's retrieval enumerated, as the CALLER's resolver reported
    /// it when the argument was resolved: `Names` for a literal, the query's shape for a query argument
    /// (a bare `%v` included, through the caller's `variable_shape`), and the call's shape for a call.
    /// Read by `variable_shape` for `%parameter` on the right of an `IN` inside the rule, so
    /// `check(to_lower(%allowed))` is membership exactly as the inline call is. Recorded at the call
    /// rather than re-derived from the argument's text in the callee, where `%allowed` would be read
    /// in the wrong scope.
    parameter_shapes: HashMap<&'value str, (RhsEnumeration, PassedOn)>,
    /// For every parameter whose argument was a bare `%v`, whether `v` lists a filter's captured keys in
    /// the caller's scope (`variable_lists_keys` there), so an interpolation over the parameter inside the
    /// rule enumerates as the caller's own interpolation over `%v` does. Recorded at the call for the
    /// reason `parameter_shapes` is. `false` for every other argument.
    parameter_lists_keys: HashMap<&'value str, bool>,
    /// The containers each projecting argument enumerated, keyed by the query's address and computed
    /// once per call; see `RootScope::projection_keys`.
    projection_keys: HashMap<usize, Rc<ProjectionKeys>>,
    /// Keys captured by a filter in the called rule's `when` condition, which `eval_rule` evaluates
    /// against this scope.
    ///
    /// Held here and dropped with the call rather than filed with the parent. Filing them with the
    /// parent put them in the calling rule's live map, so `rule p(x) when Resources[ b | Type ==
    /// 'AWS::S3::Bucket' ] !empty { ... }` called as `p("x")` from a rule whose own condition had
    /// captured `b` as `[MyRole]` made that rule's `%b` read `[MyRole, Bkt]`, failing a comparison on a
    /// key it never captured when the call preceded it and passing when the call followed it -- the
    /// same leak a named-rule reference had through `RootScope::rule_status`, which sets the caller's
    /// maps aside for the same reason. A capture belongs to the rule whose condition made it.
    captured: HashMap<&'value str, Vec<QueryResult>>,
    /// The open enumeration loops' per-entry scopes over `captured`; see `CaptureFrames`.
    capture_frames: CaptureFrames<'value>,
    /// Keys the called rule's body handed up when its block finished. The same lifetime as `captured`:
    /// they are the called rule's, and read by nothing once the call returns.
    merged: HashMap<&'value str, Vec<QueryResult>>,
    /// The parameters the call site computed with a function call, so that a `when` over one of them
    /// is read as a condition over a function's result: see `EvalContext::function_chain`.
    function_parameters: HashSet<&'value str>,
    /// Whether a measurement was already on when this scope was built, which is the case for a call
    /// made from inside the `when` being measured. Such a scope is built for that reading and dropped
    /// with it, so its captures are its only ones and the measurement skip does not apply to it: were
    /// it to capture nothing, the called rule's condition would read an unresolved name, the reading
    /// would end in an error, and the outer `when`'s notice would be lost. The block scope the called
    /// rule's body builds, and the root scope's maps set aside for a referenced rule, carry the same
    /// answer; `eval_context::writes_without_undo` is the one decision for all of them.
    built_under_measurement: bool,
    /// For each parameter in `function_parameters` a measurement has asked about, the set of its own
    /// unresolved entries, built once from its values for the life of the call; see
    /// `EvalContext::function_result_entries`.
    function_entries: HashMap<&'value str, Rc<FunctionEntries>>,
    parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

impl<'eval, 'value, 'loc: 'value> ResolvedParameterContext<'eval, 'value, 'loc> {
    /// A parameter's `values` as the call site computed them, or, under
    /// [`Measurement::WithoutUnresolved`], as every release before this one read them: for a parameter
    /// handed a function call, with every unresolved entry dropped (`without_unresolved`); for one
    /// handed a query rooted at a name that is or derives from a function's result (`guarded(%p)`,
    /// `guarded(%p.Mode)`, `guarded(%mode)` with `let mode = %p.Settings.Mode`), with the entries
    /// dropped that are, by identity, entries of that function's result (`function_result_entries`);
    /// the entries the argument's own query added, which sit on values allocated for the call, stay, as
    /// they did before this release. The one answer for both `resolve_variable` and
    /// `resolve_variable_from_nested_block`, which differ only in the deferral they make for a name that
    /// is not a parameter.
    fn measured_parameter(
        &mut self,
        variable_name: &'value str,
        values: Vec<QueryResult>,
    ) -> Result<Vec<QueryResult>> {
        if self.parent.measurement() != Measurement::WithoutUnresolved {
            return Ok(values);
        }
        if self.function_parameters.contains(variable_name) {
            return Ok(without_unresolved(values));
        }
        match self.function_result_entries(variable_name) {
            Some(Ok(entries)) => Ok(without_entries(values, &entries)),
            Some(Err(error)) => Err(error),
            None => Ok(values),
        }
    }

    /// This scope's step of the binding walk; see `BindingStep`. A parameter passed as a bare `%v` is
    /// the caller's `v`, judged in the caller's scope at the same reading; a parameter passed as any
    /// other query is bound here; a literal or function argument, or a capture the called rule made,
    /// is bound by no query; anything else is the caller's.
    fn binding_step<'n>(
        &self,
        variable_name: &'n str,
        merged: MergedKeys,
    ) -> BindingStep<'n, 'value, 'loc>
    where
        'value: 'n,
    {
        if let Some(query) = self.parameter_queries.get(variable_name).copied() {
            if let Some(root) = bare_variable_root(&query.query) {
                return BindingStep::Deferred(root, merged);
            }
            return BindingStep::Query(query);
        }
        if self.resolved_parameters.contains_key(variable_name)
            || self.holds_own_capture(variable_name, merged)
        {
            return BindingStep::Unqueried;
        }
        BindingStep::Deferred(variable_name, merged)
    }

    /// Whether this call's own stores bind `variable_name` as a capture: a key the called rule's `when`
    /// condition captured, or, under the `Visible` reading only, a key its body handed up when a block
    /// finished. The one place this scope consults the two stores for a binding question, so that every
    /// question about the called rule's captures -- the binding walk, whether a binding is a capture,
    /// its shape and whether it lists keys -- reads the same stores under the same reading; `RootScope`
    /// and `BlockScope` have the same helper over their own stores for the same reason. Two of those
    /// four questions once read the stores here and two did not, and that is the drift that made an
    /// interpolation over a condition capture enumerate in one question and name one value in another.
    fn holds_own_capture(&self, variable_name: &str, merged: MergedKeys) -> bool {
        self.captured.contains_key(variable_name)
            || (merged == MergedKeys::Visible && self.merged.contains_key(variable_name))
    }
}

impl<'eval, 'value, 'loc: 'value> EvalContext<'value, 'loc>
    for ResolvedParameterContext<'eval, 'value, 'loc>
{
    /// Forwarded: a notice raised while the called rule's body runs belongs to the run's collection as
    /// much as one raised in a plain rule. Left to the trait's no-op default, a key filter's "read from
    /// the document root" notice raised inside `rule check(x) { Mappings[ keys == to_upper(Wanted) ]
    /// ... }` was dropped here, while the same clause in a plain rule printed it;
    /// `vacuous_comparison_inside_a_parameterized_rule.guard` pins the line that reaches stderr now.
    fn record_deprecation(&mut self, notice: String) {
        self.parent.record_deprecation(notice)
    }

    /// Forwarded for the reason `record_deprecation` is: a warning raised inside a parameterized rule's
    /// body belongs to the run, not to this context.
    fn record_warning(
        &mut self,
        site: &FileLocation<'_>,
        argument: &str,
        map: &str,
        notice: String,
    ) {
        self.parent.record_warning(site, argument, map, notice)
    }

    /// Forwarded for the reason `record_warning` is.
    fn record_capture_warning(&mut self, site: &FileLocation<'_>, capture: &str, notice: String) {
        self.parent.record_capture_warning(site, capture, notice)
    }

    /// Forwarded with the two notice methods, whose notices are the one reader of the name.
    fn data_file_name(&self) -> Option<&'value str> {
        self.parent.data_file_name()
    }

    /// Forwarded for the reason `data_file_name` is.
    fn case_label(&self) -> Option<&str> {
        self.parent.case_label()
    }

    /// Forgets the called rule's own captures and merged keys, and deliberately not the caller's: the
    /// trait's reason, a referenced rule must not discard the captures of the rule that referenced it.
    /// Nothing calls this between a call's clauses today; it is answered so that the scope decides
    /// rather than inherits.
    fn reset_captures(&mut self) {
        self.captured.clear();
        self.merged.clear();
        self.capture_frames.clear();
    }

    /// Forwarded, as every capture write is: this scope holds no index captures of its own.
    fn add_variable_capture_index(&mut self, name: &str, index: Rc<PathAwareValue>) -> Result<()> {
        self.parent.add_variable_capture_index(name, index)
    }

    /// Forwarded, as `record_deprecation_once` is.
    fn has_deprecation_site(&mut self, kind: DeprecationKind, site: &FileLocation<'_>) -> bool {
        self.parent.has_deprecation_site(kind, site)
    }

    fn has_quiet_filter_site(
        &mut self,
        kind: DeprecationKind,
        site: &FileLocation<'_>,
        map_path: &str,
    ) -> bool {
        self.parent.has_quiet_filter_site(kind, site, map_path)
    }

    fn has_quiet_record_at(&mut self, kind: DeprecationKind, site: &FileLocation<'_>) -> bool {
        self.parent.has_quiet_record_at(kind, site)
    }

    fn record_quiet_filter_site(
        &mut self,
        kind: DeprecationKind,
        site: &FileLocation<'_>,
        map_path: &str,
    ) {
        self.parent.record_quiet_filter_site(kind, site, map_path)
    }

    /// A parameter is reported as the parameter it is, with the rule's name and the argument the call
    /// site passed -- a query, a literal or a function call -- so a notice about a filter through `%m`
    /// inside `rule r(m)` can say so instead of inventing a `let m = ...` the file does not have. The
    /// stores are read in `resolve_variable`'s order, the parameter before the called rule's captures,
    /// so the binding named is the one that produced the values. The parser refuses a filter capture in
    /// the rule's own `when` under a parameter's name, so a file it loaded never holds one name in both
    /// stores; the order is kept for a `RulesFile` built another way, where `%p[ ... ]` in the body
    /// walks the parameter's map and a capture-first answer left it unnamed and the filter unannounced.
    /// A name only a filter inside the rule captured is the capture's. Any other name is the caller's.
    fn variable_binding_source(
        &mut self,
        variable_name: &str,
    ) -> Option<BindingSource<'value, 'loc>> {
        if let Some(argument) = self.parameter_arguments.get(variable_name).copied() {
            return Some(BindingSource::Parameter {
                rule: self.call_rule.named_rule.dependent_rule.as_str(),
                argument,
            });
        }
        if self.captured.contains_key(variable_name) || self.merged.contains_key(variable_name) {
            return None;
        }
        self.parent.variable_binding_source(variable_name)
    }

    /// A parameter is answered from its argument read in the parent, the caller: the argument is
    /// written at the call site, and the `%name` at its head is read there. The walk goes on in the
    /// parent with the budget that is left, so a parameterized rule calling another with its own
    /// parameter (`rule outer(m) { inner(%m) }`) climbs one call per hop until it reaches the `let` or
    /// the document query the outermost caller wrote, where asking this scope again would have answered
    /// its own parameter for a shared name and looped to the bound. A name only a filter inside the
    /// rule captured is a chain that cannot be read, as `variable_binding_source` reads it; any other
    /// name is the caller's.
    fn quiet_record_key_step(
        &mut self,
        variable_name: &str,
        hops_left: usize,
    ) -> crate::rules::eval_context::QuietRecordKey {
        if let Some(argument) = self.parameter_arguments.get(variable_name).copied() {
            return crate::rules::eval_context::quiet_record_key_of_argument(
                &mut *self.parent,
                argument,
                hops_left,
            );
        }
        if self.captured.contains_key(variable_name) || self.merged.contains_key(variable_name) {
            return crate::rules::eval_context::QuietRecordKey::PathByFallback;
        }
        self.parent.quiet_record_key_step(variable_name, hops_left)
    }

    /// Forwarded: the called rule's root is the caller's, and a parameter's value is rebased onto by
    /// the scope a `%parameter` block or filter builds, which answers for itself.
    fn root_quiet_record_key(
        &mut self,
        hops_left: usize,
    ) -> crate::rules::eval_context::QuietRecordKey {
        self.parent.root_quiet_record_key(hops_left)
    }

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
        let start = self.query_start();
        let in_predicate = self.in_predicate();
        let results = query_retrieval(0, query, root, self, start, in_predicate)?;
        // Passed up as every wrapping scope passes it, so that a scope beneath a probe answers rather
        // than inherits; see `EvalContext::note_query_grounding`. No probe sits above this scope today:
        // both probes that re-run a filter predicate through a `QuietScope`, the bound-map notice's
        // (`announce_a_filter_that_lost_its_map`) and the own-key grounding probe
        // (`wildcard_entry_closure`), never evaluate a parameterized call: the bound-map probe is kept
        // off a predicate holding one by `predicate_reaches_outside`, and the grounding probe skips the
        // clause that holds one (`clause_reaches_outside`, `OutsideClauses::SkippedOnAKeptEntry`), so the call here
        // and in `note_query_grounding` below reach the root's no-op. The convention is kept so that a
        // probe admitted above a call later finds the path already there.
        self.parent.note_query_grounding(query, &results);
        Ok(results)
    }

    /// Passed up, as `query` passes its own result up; see there for why nothing receives it today.
    fn note_query_grounding(&mut self, query: &'value [QueryPart<'loc>], results: &[QueryResult]) {
        self.parent.note_query_grounding(query, results);
    }

    fn query_with_shape(
        &mut self,
        query: &'value [QueryPart<'loc>],
    ) -> Result<(Vec<QueryResult>, RhsEnumeration, PassedOn)> {
        let root = self.root();
        let start = self.query_start();
        let in_predicate = self.in_predicate();
        let (results, shape, passed_on) =
            query_retrieval_shaped(query, root, self, start, in_predicate)?;
        self.parent.note_query_grounding(query, &results);
        Ok((results, shape, passed_on))
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

    fn document_root(&mut self) -> Rc<PathAwareValue> {
        self.parent.document_root()
    }

    fn query_start(&self) -> QueryStart {
        self.parent.query_start()
    }

    /// Forwarded, as `root` is: a parameterized rule's own queries read the scope it was called from,
    /// so a rule called from a block body running over the empty selection reads that selection, and a
    /// key-rooted read in its body (`rule check(p) { Value == 'prod' }` called as `check(this)`) is
    /// judged from the filter's note where it is made, as the body's own `Value` is, never answered from
    /// the one object's real entries. What the caller handed it through its parameters is judged the
    /// same way at the variable arm (`check(this)` hands the empty selection on with its note, so
    /// `%p.Value` inside the rule is refused as `Value` in the body is; `check(Value)` hands the refused
    /// read on). A rule called from anywhere else forwards `None`, as its caller answers.
    fn empty_selection(&self) -> Option<Rc<eval_context::EmptySelection>> {
        self.parent.empty_selection()
    }

    /// Forwarded: a parameterized rule called from a filter predicate is part of that predicate's
    /// test, and one called from a rule body is not.
    fn in_predicate(&self) -> bool {
        self.parent.in_predicate()
    }

    /// Forwarded: a key filter inside the called rule's body reads beside its map as the caller does,
    /// and not at all under the caller's grounding probe.
    fn reads_beside_the_map(&self) -> bool {
        self.parent.reads_beside_the_map()
    }

    /// This scope's root: a key filter inside the called rule's body is handed this scope as its
    /// resolver, so the scope beside its map is this one.
    fn fallback_root(&mut self) -> Rc<PathAwareValue> {
        self.root()
    }

    fn is_top_level_alias(&self, variable_name: &str, merged: MergedKeys) -> bool {
        // A parameter answers from what the call site recorded about its argument; a name the called
        // rule's own condition captured, or its body handed up, is a capture and not an alias of the
        // population, whatever the caller bound under the name (the same order `resolve_variable`
        // reads the stores in, so the answer is about the binding that produced the values); any
        // other name is bound outside this call and is asked of the caller under the reading this
        // clause has, as `variable_binding_query` forwards it.
        if self.resolved_parameters.contains_key(variable_name) {
            self.population_parameters.contains(variable_name)
        } else if self.holds_own_capture(variable_name, merged) {
            false
        } else {
            self.parent.is_top_level_alias(variable_name, merged)
        }
    }

    fn rule_status(&mut self, rule_name: &'value str, role: ClauseRole) -> Result<Status> {
        self.parent.rule_status(rule_name, role)
    }

    /// A parameter's values as the call site computed them, or, under
    /// [`Measurement::WithoutUnresolved`], those values as every release before this one read them
    /// (`measured_parameter`): for a parameter handed a function call, with every unresolved entry
    /// dropped (`without_unresolved`); for one handed a query rooted at a name that is or derives from
    /// a function's result (`guarded(%p)`, `guarded(%p.Mode)`, `guarded(%mode)` with
    /// `let mode = %p.Settings.Mode`), with the entries dropped that are, by identity, entries of that
    /// function's result (`function_result_entries`, `without_entries`); the entries the argument's own
    /// query added, which sit on values allocated for the call, stay, as they did before this release.
    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        if let Some(values) = self.resolved_parameters.get(variable_name).cloned() {
            return self.measured_parameter(variable_name, values);
        }
        // The called rule's own captures, before anything the caller holds: a clause in the called
        // rule reading a name its condition captured reads that capture, as a top-level rule's would.
        if let Some(keys) = self.captured.get(variable_name) {
            return Ok(keys.clone());
        }
        if let Some(keys) = self.merged.get(variable_name) {
            return Ok(keys.clone());
        }
        self.parent.resolve_variable(variable_name)
    }

    /// A parameter handed a function call is the call's result itself: its own root, no hop. One handed
    /// a query rooted at a name (`guarded(%p)`, `guarded(%p.Mode)`, `guarded(%mode)` over a derived
    /// `let`) is one hop past the parent's chain for that name, exact only if the argument was `%p` or
    /// `%p[*]` and the parent's chain was exact; the parent answers for the root name rather than a set
    /// filled at the call, so the answer follows the binding the parent holds the way `resolve_variable`
    /// of that name does. A literal is on no chain; any other name is the parent's to answer for.
    fn function_chain(&mut self, variable_name: &str) -> Option<FunctionChain<'value>> {
        if !self.resolved_parameters.contains_key(variable_name) {
            return self.parent.function_chain(variable_name);
        }
        if let Some(own) = self.function_parameters.get(variable_name).copied() {
            return Some(FunctionChain {
                root: own,
                exact_alias: true,
                hops: 0,
            });
        }
        let query = self.parameter_queries.get(variable_name).copied()?;
        let root = query.query.first().and_then(QueryPart::variable)?;
        let parent = self.parent.function_chain(root)?;
        Some(FunctionChain {
            root: parent.root,
            exact_alias: parent.exact_alias && function_result_alias_root(&query.query).is_some(),
            hops: parent.hops + 1,
        })
    }

    /// A parameter handed a function call answers from the values fixed at the call, once per call; one
    /// handed a query rooted at a name is the parent's to answer for that name, so a parameter named like
    /// the caller's root (`rule guarded(cfg)` over `let cfg = json_parse(...)`, called as
    /// `guarded(%cfg.Mode)`) never has its own values read in the root's place; any other name is the
    /// parent's.
    fn function_result_entries(
        &mut self,
        variable_name: &str,
    ) -> Option<Result<Rc<FunctionEntries>>> {
        if !self.resolved_parameters.contains_key(variable_name) {
            return self.parent.function_result_entries(variable_name);
        }
        if let Some(own) = self.function_parameters.get(variable_name).copied() {
            if let Some(entries) = self.function_entries.get(own) {
                return Some(Ok(Rc::clone(entries)));
            }
            let entries = Rc::new(FunctionEntries::of(self.resolved_parameters.get(own)?));
            self.function_entries.insert(own, Rc::clone(&entries));
            return Some(Ok(entries));
        }
        let query = self.parameter_queries.get(variable_name).copied()?;
        let root = query.query.first().and_then(QueryPart::variable)?;
        self.parent.function_result_entries(root)
    }

    /// A parameter's values were computed at the call site, so a parameter is resolved; any other name
    /// is the parent's to answer for.
    fn variable_is_resolved(&self, variable_name: &str) -> bool {
        self.resolved_parameters.contains_key(variable_name)
            || self.parent.variable_is_resolved(variable_name)
    }

    /// A parameter holds what its ARGUMENT holds without evaluation, read as the trait says: a literal
    /// argument (`chk('Env')`) is that literal; a bare `%name` argument (`chk(%wanted)`) is whatever the
    /// caller's scope holds for that name, asked of the parent, so a literal `let` passes through and a
    /// query-bound one does not; an argument that is a query (`chk(Parameters.Wanted.Default)`) or a
    /// function call is `None`, the same answer the `let` spelling of that binding gives, whatever
    /// `resolved_parameters` holds for it. A non-parameter name the called rule captured itself (`captured`) or that
    /// one of its blocks merged up (`merged`) holds nothing here, as the root's and the block's readings
    /// say of theirs: a capture is the query-bound name it is declared by, and the merged keys depend on
    /// the order the iterations ran in, so `rule chk(p) when Mappings.Wanted[ w | this == true ] !empty {
    /// %p.Tags[*][ Key == %w ] empty }` over `Tags: { Env: dev }` names nothing in its refusal's advice, as
    /// the plain spelling of the same rule does (the refusal itself is the twin's, which cannot read a
    /// `%name`, in both). Any other name is the caller's to answer for.
    fn literal_binding(&self, variable_name: &str) -> Option<Vec<Rc<PathAwareValue>>> {
        if let Some(argument) = self.parameter_arguments.get(variable_name).copied() {
            return match argument {
                LetValue::Value(literal) => Some(vec![Rc::new(literal.clone())]),
                LetValue::AccessClause(query) => match query.query.as_slice() {
                    [part] => part
                        .variable()
                        .and_then(|name| self.parent.literal_binding(name)),
                    _ => None,
                },
                LetValue::FunctionCall(_) => None,
            };
        }
        if self.resolved_parameters.contains_key(variable_name)
            || self.captured.contains_key(variable_name)
            || self.merged.contains_key(variable_name)
        {
            return None;
        }
        self.parent.literal_binding(variable_name)
    }

    fn record_deprecation_once(
        &mut self,
        kind: DeprecationKind,
        site: &FileLocation<'_>,
        notice: String,
    ) -> bool {
        self.parent.record_deprecation_once(kind, site, notice)
    }

    fn predicate_regexes(
        &self,
        site: &FileLocation<'_>,
    ) -> Rc<crate::rules::eval_context::CompiledRegexes> {
        self.parent.predicate_regexes(site)
    }

    fn set_measurement(&mut self, mode: Measurement) {
        self.parent.set_measurement(mode)
    }

    fn measurement(&self) -> Measurement {
        self.parent.measurement()
    }

    fn when_is_settled(
        &self,
        site: &FileLocation<'loc>,
        direction: MoveDirection,
        bindings: Option<&BTreeSet<BindingId<'value>>>,
    ) -> bool {
        self.parent.when_is_settled(site, direction, bindings)
    }

    fn when_has_settled_measurements(
        &self,
        site: &FileLocation<'loc>,
        direction: MoveDirection,
    ) -> bool {
        self.parent.when_has_settled_measurements(site, direction)
    }

    fn settle_when(
        &mut self,
        site: &FileLocation<'loc>,
        direction: MoveDirection,
        bindings: Option<BTreeSet<BindingId<'value>>>,
    ) {
        self.parent.settle_when(site, direction, bindings)
    }

    fn binding_owners(&self, variable_name: &str) -> Option<BTreeSet<BindingId<'value>>> {
        // A parameter is bound once per call, with that call's argument, and shadows a root `let` of
        // the same name for the rules called from inside this one (the parser accepts the spelling):
        // without this arm a nested call's question would reach the root and settle on the wrong
        // binding. A name the rule's own conditions captured is this call's too; a root `let` beside a
        // filter capture of the same name is refused by the parser, so this arm decides nothing for a
        // file the parser accepts and is kept so the two stores answer alike (see `holds_own_capture`).
        // Any other name is the caller's: the caller's scopes name the binding it reaches, so a `let`
        // in one caller's body is one binding and the same-named `let` in another caller's body is
        // another, and the called rule's `when`, one position shared by every caller, is settled for
        // each caller's binding on its own.
        if self.resolved_parameters.contains_key(variable_name)
            || self.holds_own_capture(variable_name, MergedKeys::Visible)
        {
            None
        } else {
            self.parent.binding_owners(variable_name)
        }
    }

    /// Forwarded to the caller: the table is the root's.
    fn value_before_the_wildcard_clones(
        &self,
    ) -> Option<std::rc::Rc<std::cell::RefCell<super::eval_context::ValueBeforeClones>>> {
        self.parent.value_before_the_wildcard_clones()
    }

    /// Forwarded to the caller: the memo is the root's, and a parameter, bound per call, is never kept in
    /// it (`binding_owners` answers `None` for one).
    fn document_binding_memo(
        &self,
    ) -> Option<std::rc::Rc<std::cell::RefCell<super::eval_context::DocumentBindingMemo<'value>>>>
    {
        self.parent.document_binding_memo()
    }

    fn binding_owners_memo(
        &self,
    ) -> Option<std::rc::Rc<std::cell::RefCell<super::eval_context::BindingOwnersMemo<'value>>>>
    {
        self.parent.binding_owners_memo()
    }

    fn note_binding_walk_limit(&self, text: String) {
        self.parent.note_binding_walk_limit(text)
    }

    fn resolving_a_binding(&self) -> bool {
        self.parent.resolving_a_binding()
    }

    fn within_parameterized_call(&self) -> bool {
        // This is the call: a block built beneath it is the called rule's body, bound again for every
        // call from this call's arguments.
        true
    }

    /// The call site's arguments first and then the parent's bindings, which is the order
    /// `resolve_variable` reaches them in.
    ///
    /// The deferral is on whether the name is a parameter at all, not on whether it is one of the
    /// parameters that came from a query. A parameter passed as a literal or a function call is a
    /// binding this call owns that no query produced, so the answer for it is `None` here; falling
    /// through to the parent instead would answer about an outer `let` of the same name that this call
    /// has shadowed, and report a projection for values the projection never produced.
    ///
    /// A bare `%v` argument is answered from the caller's scope instead of being handed back as it
    /// stands. The query recorded for a parameter is the argument's *text*, and that text was written at
    /// the call site, so its names mean what they mean there. `query_projects` reads this answer by
    /// recursing with the resolver it was given, which is this scope, so a returned `%v` gets resolved
    /// against the callee's own parameters rather than against the `v` the author was naming. Forwarding
    /// to the parent asks the one scope where the name means what it says, and it is what the trait
    /// already asks for: the binding that produced these values.
    ///
    /// Only a bare `%v` needs it, and `query_projects` bounds that itself. Its `1 =>` arm is the only
    /// one that recurses, and `access_query` reserves slot 1 only when there is a remainder to reserve
    /// in front of, so a one-part variable-rooted query is exactly `%v` with nothing after it. An
    /// argument like `%a.Meta` is three parts, takes `_ =>`, never re-resolves the name, and has to keep
    /// the answer it already has: that answer agrees with the one `let m = %a.Meta` gets, and widening
    /// this to every argument would move the parameter path off the `let` path for a shape neither the
    /// caller's scope nor this one disagrees about.
    ///
    /// Each hop goes strictly outward through a scope chain that is a stack, so forwarding terminates
    /// without any cycle bookkeeping of its own; the name may repeat across hops, but the depth cannot.
    ///
    /// It defers one level, and one level is enough because the parent follows a bare `%v` binding of
    /// its own before answering. An argument passed through an intermediate binding -- `let b = %a`
    /// invoked as `inner(%b)` against a parameter named `a` -- would otherwise get the parent's answer
    /// for `b` as the raw AST `%a`, which `query_projects` would then resolve with *this* resolver while
    /// `rooted_through` already held the parameter's name; its cycle check would refuse and the rule
    /// would report SKIP at exit 0. With the parent following the chain, what comes back for `b` is the
    /// query at the end of it, resolved at each step in the scope that wrote the step. This forward
    /// stays one level because that is all it is
    /// responsible for: the argument's text was written one scope out, and each scope owns the names in
    /// the text it holds.
    ///
    /// Reaching this mattered more than the shape suggests, because the wrong answer was silent.
    /// `rooted_through` refuses a name already on the chain, so a parameter that resolved to itself came
    /// back as `false` -- right as cycle termination, wrong as a projection answer -- and a filter handed
    /// the whole collection rather than each member selects nothing. An assertion over an empty selection
    /// is not applicable, so the rule reported SKIP at exit 0 with nothing on either channel, which reads
    /// exactly like a rule whose `when` legitimately excluded the input.
    ///
    /// `merged` is passed on unchanged, as `resolve_variable_from_nested_block` passes `unbound` on: an
    /// argument the call site passed is the same binding whichever depth of block reads it, and this
    /// scope holds no keys a finished block handed up, so crossing it changes neither reading. The
    /// forward below passes it for the same reason, and doing so is what lets a caller's binding that
    /// lives in the merged store be found at all.
    fn variable_binding_query(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> Option<&'value AccessQuery<'loc>> {
        match self.binding_step(variable_name, merged) {
            BindingStep::Query(query) => Some(query),
            BindingStep::Unqueried => None,
            BindingStep::Deferred(name, onward) => self.parent.variable_binding_query(name, onward),
        }
    }

    /// The same walk, run to the containers; a parameter's own projecting query runs here, at the
    /// caller's root, which is where the argument was written.
    fn projection_member_keys(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> Result<Option<Rc<ProjectionKeys>>> {
        match self.binding_step(variable_name, merged) {
            BindingStep::Query(query) => {
                let key = query as *const AccessQuery<'loc> as usize;
                if let Some(found) = self.projection_keys.get(&key) {
                    return Ok(Some(found.clone()));
                }
                let found = keys_of_projection(query, self)?;
                if let Some(found) = &found {
                    self.projection_keys.insert(key, found.clone());
                }
                Ok(found)
            }
            BindingStep::Unqueried => Ok(None),
            BindingStep::Deferred(name, onward) => self.parent.projection_member_keys(name, onward),
        }
    }

    /// The same walk as `variable_binding_query`, so the two questions agree about a parameter: one
    /// passed as a bare `%v` is the caller's `v`, and whether that is a capture is the caller's answer;
    /// one passed as any other query is not a capture; one passed as a literal or a function result is
    /// not either, while the called rule's own captures are; anything else is the parent's question.
    ///
    /// Answering `false` for every parameter here while the binding question deferred a bare `%v`
    /// walked the reserved slot into a captured value: `rule check(x) { %x[ Key == 'Name' ] !empty }`
    /// called as `check(%t)` over a captured tag met the tag's own `Key` string under the filter, where
    /// the caller's `%t[ Key == 'Name' ]` tests the tag whole.
    ///
    /// A parameter is not a capture even when the rule's own `when` captured a filter's keys under its
    /// name. The parser refuses that file, so the `resolved_parameters` check below is defense in depth
    /// for a `RulesFile` built another way: `resolve_variable` reads the parameter first and hands the
    /// body the argument's values, so the shape question has to answer for that binding too. Read as a
    /// capture, `%p[ Statement exists ]` over a parameter bound to a parsed map walks the capture's
    /// arm, selects the map whole under that arm's one-object reading, passes where the same filter
    /// without the collision fails, and raises no notice.
    fn binding_is_a_capture(&mut self, variable_name: &str, merged: MergedKeys) -> bool {
        match self.binding_step(variable_name, merged) {
            BindingStep::Query(_) => false,
            BindingStep::Unqueried => {
                !self.resolved_parameters.contains_key(variable_name)
                    && self.holds_own_capture(variable_name, merged)
            }
            BindingStep::Deferred(name, onward) => self.parent.binding_is_a_capture(name, onward),
        }
    }

    /// The shape the caller's resolver reported for the argument at the call site, recorded in
    /// `eval_parameterized_rule_call` -- a query's, a call's, or `Names` for a literal -- so
    /// `check(to_lower(%allowed))` answers inside the rule as the inline call does and no argument is
    /// re-read in the callee's scope, where its names mean something else.
    ///
    /// Then the called rule's own captures, in the order `resolve_variable` reads the stores: a key its
    /// `when` condition captured, or (when `Visible`) one its body handed up, names its value, as a
    /// capture does in every other scope. Handing these names to the parent paired the capture's keys
    /// with whatever the caller had bound under the name -- a `let`'s recorded shape, or nothing -- so
    /// the values came from one binding and the shape from another. Any other name is the parent's to
    /// answer.
    ///
    /// The record beside a parameter's shape travels with it: the maps the argument's last-part `[*]`
    /// passed on unchanged, as the caller's resolver reported when the call was made
    /// (`check(Mappings.Exempt.Names[*])` reads `%ex` inside the rule as the caller reads `%exempt`). A
    /// capture passed nothing on.
    fn variable_shape(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> (RhsEnumeration, PassedOn) {
        if let Some(shape) = self.parameter_shapes.get(variable_name) {
            return shape.clone();
        }
        if self.holds_own_capture(variable_name, merged) {
            return (RhsEnumeration::Names, PassedOn::default());
        }
        self.parent.variable_shape(variable_name, merged)
    }

    /// Whether the argument the call site passed under this name was itself a capture (`r(%buckets)`),
    /// as the caller's resolver said when the call was made and recorded in `parameter_lists_keys`, so
    /// `Resources.%names.Properties.BucketName` inside the rule enumerates as the caller's
    /// `Resources.%buckets.Properties.BucketName` does.
    ///
    /// Then the called rule's own captures, under the same reading `variable_shape` applies: a key the
    /// rule's `when` condition captured lists a filter's keys, so `Resources.%b.Properties.BucketName`
    /// in the body after `when Resources[ b | Type == 'AWS::S3::Bucket' ] !empty` enumerates as the
    /// inline `Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName` does. Asked of the parent
    /// instead, the answer was whatever the caller held under `b`: `false` for no binding or a `let`,
    /// so the interpolation named one value and `IN` read it as a haystack, passing a substring the
    /// inline spelling refuses. Any other name is the parent's to answer.
    fn variable_lists_keys(&self, variable_name: &str, merged: MergedKeys) -> bool {
        if let Some(lists_keys) = self.parameter_lists_keys.get(variable_name) {
            return *lists_keys;
        }
        if self.holds_own_capture(variable_name, merged) {
            return true;
        }
        self.parent.variable_lists_keys(variable_name, merged)
    }

    fn entry_candidates(
        &mut self,
        values: Vec<Rc<PathAwareValue>>,
        shape: RhsEnumeration,
    ) -> Rc<EntryCandidates> {
        self.parent.entry_candidates(values, shape)
    }

    /// An argument the call site passed is the same binding whichever depth of block reads it, so this
    /// answers as `resolve_variable` does, measured under [`Measurement::WithoutUnresolved`] by the same
    /// `measured_parameter`, and only the onward deferral differs: the entries the measurement drops for
    /// a parameter handed a function call, or one handed a query rooted at a function's result, are
    /// dropped on both paths. Answered from the map directly, the body's `when %n == "a"` over
    /// `inner(to_lower(...))` read under the measurement what the real run read, so a call that moved
    /// was measured and never announced.
    ///
    /// Answering here is what keeps a parameter readable under shadowing: a block inside the rule
    /// declaring a capture of the parameter's name must not end the lookup before it reaches this
    /// scope, or the argument the call site passed is unreadable for that whole block.
    fn resolve_variable_from_nested_block(
        &mut self,
        variable_name: &'value str,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        // Measured as `resolve_variable` measures it, through the one helper, because this is the path
        // a `when` block inside the called rule's body reads the parameter by: every block scope defers
        // a name it does not bind through the nested-block lookup, and a block measures only its own
        // names on the strength of the parent having measured the deferred ones. With the parameter
        // handed back raw here, the gate's measured reading saw every unresolved entry, read "did not
        // move", and lost its notice while the rule's own `when` kept its own.
        if let Some(values) = self.resolved_parameters.get(variable_name).cloned() {
            return self.measured_parameter(variable_name, values);
        }
        // A condition capture is in reach of the called rule's body, as a rule-level `when` capture is
        // in reach of a top-level rule's body; `merged` is not, for the reason every scope withholds it
        // from a nested lookup.
        if let Some(keys) = self.captured.get(variable_name) {
            return Ok(keys.clone());
        }
        self.parent
            .resolve_variable_from_nested_block(variable_name, unbound)
    }

    fn add_variable_capture(
        &mut self,
        variable_name: &'value str,
        result: QueryResult,
    ) -> Result<()> {
        // A measurement captures nothing, unless this scope was built for it; see
        // `eval_context::writes_without_undo`. The called rule's `when` is evaluated against this
        // scope, and a measurement of it re-evaluates its filter against this scope too, so without the
        // skip the body read every captured key once per reading.
        if !super::eval_context::writes_without_undo(
            self.parent.measurement(),
            self.built_under_measurement,
        ) {
            return Ok(());
        }
        self.captured.entry(variable_name).or_default().push(result);
        Ok(())
    }

    /// The live length plus the slices the open frames hold parked: the scale the marks are taken on
    /// (`RootScope::variable_capture_len`).
    fn variable_capture_len(&self, variable_name: &str) -> usize {
        self.captured.get(variable_name).map_or(0, Vec::len)
            + self
                .capture_frames
                .parked_len(CaptureHome::Captured, variable_name)
    }

    fn truncate_variable_capture(&mut self, variable_name: &'value str, len: usize) -> Result<()> {
        // As `add_variable_capture`: nothing is written under a measurement this scope was not built
        // for, so there is nothing to cut either. `len` is on the absolute scale; the frames cut the
        // parked slices first (`CaptureFrames::cut`, as `RootScope::truncate_variable_capture`).
        if !super::eval_context::writes_without_undo(
            self.parent.measurement(),
            self.built_under_measurement,
        ) {
            return Ok(());
        }
        self.capture_frames.cut(
            CaptureHome::Captured,
            &mut self.captured,
            variable_name,
            len,
        );
        Ok(())
    }

    /// This scope keeps the called rule's condition captures itself, so the frames are its own and
    /// nothing is forwarded, as `BlockScope` answers for a body. No `let` of its own is ever resolved
    /// here (the depth is 0); `merged` goes with every call.
    fn open_capture_frame(&mut self) {
        // Whether `add_variable_capture` writes here right now, the same test it makes.
        let writes_captures = super::eval_context::writes_without_undo(
            self.parent.measurement(),
            self.built_under_measurement,
        );
        self.capture_frames.open(
            CaptureHome::Captured,
            0,
            &self.captured,
            &self.merged,
            writes_captures,
        );
    }

    fn begin_capture_entry(&mut self) {
        self.capture_frames
            .begin_segment(&self.captured, &self.merged);
    }

    fn end_capture_entry(&mut self) {
        self.capture_frames
            .end_segment(&mut self.captured, &mut self.merged);
    }

    fn end_capture_entry_detached(&mut self) -> EntryCaptures<'value> {
        self.capture_frames
            .end_segment_detaching(&mut self.captured, &mut self.merged)
            .1
    }

    fn refile_captures(&mut self, captures: EntryCaptures<'value>) {
        CaptureFrames::refile(&mut self.captured, &mut self.merged, captures);
    }

    fn close_capture_frame(&mut self) {
        self.capture_frames
            .close(&mut self.captured, &mut self.merged);
    }

    fn add_variable_capture_key_below_the_entry(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        if !super::eval_context::writes_without_undo(
            self.parent.measurement(),
            self.built_under_measurement,
        ) {
            return Ok(());
        }
        let result = QueryResult::Resolved(key);
        if !self.capture_frames.insert_below_segment(
            &mut self.captured,
            variable_name,
            result.clone(),
        ) {
            self.captured.entry(variable_name).or_default().push(result);
        }
        Ok(())
    }

    fn add_merged_capture(
        &mut self,
        variable_name: &'value str,
        result: QueryResult,
    ) -> Result<()> {
        if !super::eval_context::writes_without_undo(
            self.parent.measurement(),
            self.built_under_measurement,
        ) {
            return Ok(());
        }
        self.merged.entry(variable_name).or_default().push(result);
        Ok(())
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
                        // The author's `<< >>` body replaces the rule's own message, so no refusal.
                        refusal: false,
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

/// The arguments a parameterized call passes in, by parameter name: the values (a literal as written,
/// a query's result, or a function's result), the query each query-valued argument was, the
/// parameters whose argument named the document's population, where each argument's retrieval
/// enumerated, whether each argument was a bare `%v` whose `v` lists captured keys, the parameters
/// whose argument was a function call, and every argument as the call site wrote it.
type CallArguments<'value, 'loc> = (
    HashMap<&'value str, Vec<QueryResult>>,
    HashMap<&'value str, &'value AccessQuery<'loc>>,
    HashSet<&'value str>,
    HashMap<&'value str, (RhsEnumeration, PassedOn)>,
    HashMap<&'value str, bool>,
    HashSet<&'value str>,
    HashMap<&'value str, &'value LetValue<'loc>>,
);

/// The values a parameterized call passes in, by parameter name: a literal as written, a query's
/// result, or a function's result. Split out of `eval_parameterized_rule_call` so that its caller can
/// classify an error from any of the three the same way.
fn resolve_call_arguments<'value, 'loc: 'value>(
    call_rule: &'value ParameterizedNamedRuleClause<'loc>,
    param_rule: &'value ParameterizedRule<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
) -> Result<CallArguments<'value, 'loc>> {
    let mut resolved_parameters = HashMap::with_capacity(call_rule.parameters.len());
    let mut parameter_queries = HashMap::new();
    let mut population_parameters = HashSet::new();
    let mut parameter_shapes = HashMap::with_capacity(call_rule.parameters.len());
    let mut parameter_lists_keys = HashMap::with_capacity(call_rule.parameters.len());
    let mut function_parameters = HashSet::new();
    let mut parameter_arguments = HashMap::with_capacity(call_rule.parameters.len());
    for (idx, each) in call_rule.parameters.iter().enumerate() {
        let parameter_name = (param_rule.parameter_names[idx]).as_str();
        parameter_arguments.insert(parameter_name, each);
        match each {
            // `Literal`, the variant `let x = <literal>` binds, an inline right-hand literal is
            // wrapped in, and a function of literals (`p(parse_int("5"))`) answers. This was
            // `Resolved`, the variant a document value arrives in, and `is_literal` dispatches the
            // comparator arms on the variant: `%x IN "aws:arn:s3"` for an `x` of `["s3", "arn"]`
            // expanded the list into substring checks and passed where the `let` spelling compared
            // the list whole and refused, and `%x IN Names[*]` compared the list whole against each
            // name and failed where the `let` spelling read it as a subset and passed. One constant,
            // two verdicts, decided by which keyword bound it. The variant also carries the
            // argument's provenance inside the called rule: `p(true)` with `%n !EMPTY` in the body
            // is the author's mistake, not a fact about the data, and `Error::unanswerable` has to
            // see a `Literal` to say so; wrapped as `Resolved`, the same clause was held in an `or`
            // and failed closed alone.
            LetValue::Value(val) => {
                resolved_parameters.insert(
                    parameter_name,
                    vec![QueryResult::Literal(Rc::new(val.clone()))],
                );
                parameter_shapes
                    .insert(parameter_name, (RhsEnumeration::Names, PassedOn::default()));
                parameter_lists_keys.insert(parameter_name, false);
            }
            LetValue::AccessClause(query) => {
                // Recorded before the argument is resolved, so the parameter can be read inside the
                // rule the way its argument would be read here: `%res.*[ ... ]` over a parameter
                // bound by `names(Resources)` gets the same empty-population answer as
                // `Resources.*[ ... ]` written out, and a parameter bound by anything else does not.
                if names_the_population(&query.query, resolver.query_start(), resolver) {
                    population_parameters.insert(parameter_name);
                }
                // Resolved with its shape here, with the caller's resolver, which is the one scope
                // where the argument's names mean what the author meant. See `parameter_shapes`.
                let (values, shape, passed_on) = resolver.query_with_shape(&query.query)?;
                // The same filter the right-hand side of a clause applies, for the same reason: the
                // argument's `some` was parsed and then never read.
                resolved_parameters.insert(
                    parameter_name,
                    resolved_only_under_some(values, query.match_all),
                );
                parameter_shapes.insert(parameter_name, (shape, passed_on));
                // A bare `%v` argument carries whether `v` lists captured keys, asked of the caller's
                // scope as the shape is. See `parameter_lists_keys`.
                let lists_keys = match bare_variable_root(&query.query) {
                    Some(root) => resolver.variable_lists_keys(root, MergedKeys::Visible),
                    None => false,
                };
                parameter_lists_keys.insert(parameter_name, lists_keys);
                // Kept alongside the values, so that `%parameter` used as a query root can be judged
                // against the query that produced them. See `parameter_queries`.
                parameter_queries.insert(parameter_name, query);
                // An argument rooted at a name carrying a function's result hands the function's
                // unresolved entries on, whatever follows the root (`guarded(%p)`, `guarded(%p[*])`,
                // `guarded(%p.Mode)` with `let p = to_lower(...)`), since the variable-root arm passes
                // each one through. The scope's `function_chain` reads the shape off
                // `parameter_queries` and asks the parent for the root name, so nothing is recorded for
                // it here.
            }
            LetValue::FunctionCall(function) => {
                // The call's record (`PassedOn::read_from`) is kept with the parameter, so a read of `%n`
                // in the called rule counts as a read of the selections the call read: `check(count(this))`
                // with `rule check(n) { %n == 0  %n < 10 }` reads the selection in both clauses.
                let (result, shape, computed_from) =
                    resolve_function_with_shape(function, resolver)?;
                resolved_parameters.insert(parameter_name, result);
                parameter_shapes.insert(parameter_name, (shape, computed_from));
                parameter_lists_keys.insert(parameter_name, false);
                function_parameters.insert(parameter_name);
            }
        }
    }
    Ok((
        resolved_parameters,
        parameter_queries,
        population_parameters,
        parameter_shapes,
        parameter_lists_keys,
        function_parameters,
        parameter_arguments,
    ))
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
    // site against the definition it names and rejects the file at exit 5 -- at the rule level, inside
    // a `when`, inside a filter, through a parameter alias, with a function argument -- so a parsed file
    // cannot reach here with the counts unequal; the check stays because the indexing below would
    // otherwise panic, and because a `RulesFile` assembled some other way has no parser to have checked
    // it.
    //
    // Reaching this therefore means cfn-guard let through a file it said it had validated, and the
    // error says so by its variant as well as its message. Raised as `IncompatibleError` it would be
    // classified by `Error::is_rules_file_mistake` and exit 5, the code that tells the author their
    // rules file needs fixing, for a fault in the tool. As an `InternalError` no command classifies it:
    // `Err` propagates to `main`, which exits -1, and -1 -- `INTERNAL_FAILURE` in
    // `guard/tests/utils.rs` -- is the right code for a broken invariant.
    // `an_unchecked_call_site_arity_mismatch_is_an_internal_error` reaches this arm the only way left,
    // by widening a parsed call after the fact.
    if param_rule.parameter_names.len() != call_rule.parameters.len() {
        return Err(Error::InternalError(
            crate::rules::errors::InternalError::UncheckedParserInvariant(format!(
                "Arity mismatch for called parameter rule {}, expected {}, got {}. The rules file was \
                 accepted with a call this malformed, which is a defect in cfn-guard rather than in \
                 the file.",
                call_rule.named_rule.dependent_rule,
                param_rule.parameter_names.len(),
                call_rule.parameters.len()
            )),
        ));
    }

    // The arguments are resolved before the rule is entered, and an argument the data cannot
    // answer -- `p(parse_int(Properties.Name))` on a name that is not a number -- is split by role
    // like the access clause's own query: an assertion records the error against the call and fails
    // it closed, a gate keeps the error so the enclosing condition fails its rule closed, and every
    // other error stops the run. Resolving with a bare `?` made the four bodies that can hold a call
    // disagree: a rule body, a type block and a `when` block stopped the run, while a block clause
    // caught the error one level up and failed closed without its text.
    let arguments = match resolve_call_arguments(call_rule, param_rule, resolver) {
        Ok(resolved) => resolved,
        Err(e) if is_unevaluatable(&e) && role.is_strict() => {
            // A `GuardClauseBlockCheck`, the record the access clause closes with its own "bailing"
            // message, because that is the record the console reporter prints under "Could not be
            // evaluated" when it has no children. A `DependentRule` value check carrying the same
            // sentence reached the summary as a bare FAIL with no reason (measured).
            let context = format!("{}", call_rule.named_rule);
            resolver.start_record(&context)?;
            resolver.end_record(
                &context,
                RecordType::GuardClauseBlockCheck(BlockCheck {
                    status: Status::FAIL,
                    at_least_one_matches: false,
                    message: Some(format!(
                        "{} failed because an argument could not be evaluated on this data: {}",
                        context, e
                    )),
                    refusal: is_refusal(&e),
                }),
            )?;
            return Ok(Status::FAIL);
        }
        Err(e) => return Err(e),
    };
    let (
        resolved_parameters,
        parameter_queries,
        population_parameters,
        parameter_shapes,
        parameter_lists_keys,
        function_parameters,
        parameter_arguments,
    ) = arguments;
    let built_under_measurement = resolver.measurement() != Measurement::Off;
    let mut eval = ResolvedParameterContext {
        parent: resolver,
        resolved_parameters,
        parameter_queries,
        parameter_arguments,
        population_parameters,
        parameter_shapes,
        parameter_lists_keys,
        projection_keys: HashMap::new(),
        captured: HashMap::new(),
        capture_frames: CaptureFrames::default(),
        merged: HashMap::new(),
        function_parameters,
        built_under_measurement,
        function_entries: HashMap::new(),
        call_rule,
    };
    // Propagate the call site's role: a parameterized rule used as a `when` gate
    // must evaluate its body with gate semantics, or an unevaluatable clause inside
    // it fails the gate and silently disarms the block it guards.
    let status = eval_rule(&param_rule.rule, &mut eval, role)?;

    // Apply the clause-level negation of the *call*. The parser accepts and stores a
    // leading `not` on a parameterized invocation (`not is_relevant("x")`) exactly as
    // it does for a plain named-rule reference; returning the invoked rule's status
    // unchanged here would silently discard the `not`, and `not r(...)` would behave
    // identically to `r(...)`.
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
        // Gates only, not filters, for the reason given at the same arm in
        // `eval_guard_named_clause`: a negated reference that does not apply guards a block by passing,
        // but inside a filter it deselects the element rather than selecting everything the rule had no
        // opinion on.
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
    // A clause of a block body running over the empty selection a one-object filter left
    // (`EvalContext::empty_selection`: `Some` under such a body and nowhere else) is marked before it
    // runs and judged once it has decided (`EmptySelection::clause_begins`, `clause_decided`): a clause
    // that decided while reading nothing from the selection, bare or by key, is what the body's
    // `held_only_refusal` refuses when the body read no key. Judged here, at the one place every clause
    // of such a body passes, so a clause inside a `when` block of the body, inside a nested block or
    // inside a rule the body calls is judged on its own reads as a top-level clause is, and a bare read
    // beside it excuses nothing but itself; the `when` block, the nested block or the call is judged as
    // a clause as well, on the reads its clauses made, which never sets the flag a clause of its own
    // has not.
    let judged = resolver.empty_selection().map(|selection| {
        let reads = selection.clause_begins();
        (selection, reads)
    });
    let status = match gc {
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
    };
    if let (Some((selection, reads)), Ok(decided)) = (judged, &status) {
        selection.clause_decided(reads, *decided);
    }
    status
}

// The number of `when` conditions evaluated on this thread, for the test that pins what measuring a
// gate costs: one evaluation per condition for the real reading and one per condition for the gate's
// measured reading on a gate that did not move, the two per-condition readings only on one that did.
// Per thread, since each test evaluates on its own. Absent from a release build.
#[cfg(test)]
thread_local! {
    pub(in crate::rules) static WHEN_CLAUSE_EVALUATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

pub(in crate::rules) fn eval_when_clause<'value, 'loc: 'value>(
    when_clause: &'value WhenGuardClause<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
) -> Result<Status> {
    #[cfg(test)]
    WHEN_CLAUSE_EVALUATIONS.with(|evaluations| evaluations.set(evaluations.get() + 1));
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
        // The same split as the block clause's query and the access clause's. The parser builds
        // this query from the type name alone (`Resources.*[ Type == "<name>" ]`), and a comparison
        // the filter cannot make is answered inside the filter rather than raised, so no rules file
        // reaches the fail-closed arm today; it is here so that every query site answers an
        // unevaluatable query the same way, and so that a future query shape does not reopen the
        // abort by accident.
        Err(e) => {
            let unevaluatable = is_unevaluatable(&e);
            resolver.end_record(
                &context,
                RecordType::TypeCheck(TypeBlockCheck {
                    type_name: &type_block.type_name,
                    block: BlockCheck {
                        status: Status::FAIL,
                        at_least_one_matches: false,
                        refusal: false,
                        // No message, unlike the block clause's query arm, which records a sentence
                        // in both roles because the tree is reported before the error stops the
                        // run. This arm is not reachable from rules text (the parser
                        // builds the selection from the type name, and the filter answers an
                        // impossible comparison inside itself), so a sentence here could never be
                        // checked to render, and `every_recorded_explanation_has_a_rendering_path`
                        // refuses to count one it cannot check. If a query shape ever reaches this
                        // arm, give it a message then and confirm the output.
                        message: None,
                    },
                }),
            )?;
            return match (unevaluatable, role.is_strict()) {
                (true, true) => Ok(Status::FAIL),
                _ => Err(e),
            };
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
                    refusal: false,
                },
            }),
        )?;
        return Ok(Status::SKIP);
    }

    let mut fails = 0;
    let mut passes = 0;
    // Tracked only so the SKIP below can name the right cause. Three different things reach SKIP
    // here and they call for three different sentences; telling a reader the wrong one of them is
    // worse than telling them nothing. `selected` counts the slots that resolved to a resource,
    // `exempted` the ones the block's own `when` condition declined, and `unresolved_reason` keeps
    // the first retrieval failure so the "selected nothing" sentence can name it.
    let mut selected = 0;
    let mut exempted = 0;
    let mut unresolved_reason: Option<String> = None;
    for (idx, each) in values.iter().enumerate() {
        match each {
            QueryResult::Literal(rv) | QueryResult::Resolved(rv) => {
                selected += 1;
                let block_context = format!("{}/{}", context, idx);
                resolver.start_record(&block_context)?;

                let in_predicate = resolver.in_predicate();
                let mut val_resolver = ValueScope {
                    root: Rc::clone(rv),
                    parent: resolver,
                    in_predicate,
                    this_is_the_population: false,
                    // A type block's resources are the document's population, the enclosing root's.
                    root_from: crate::rules::eval_context::RootProvenance::Enclosing,
                    empty_selection: None,
                };

                // Conditions are evaluated per resource, against the same scope as the clauses
                // they guard.
                //
                // Evaluating them one time, before this loop, against the enclosing resolver
                // would resolve a condition from the file root while the block's clauses resolve
                // from each resource. That split makes the natural spelling a trap:
                // `AWS::EC2::Volume when Properties.Size > 10 { ... }` reads as "every volume
                // over 10 GiB must ..." and would instead look for `Properties` at the file
                // root, find nothing, and skip every template it is run against -- reporting
                // `not_applicable` at exit 0, including for the templates it was written to
                // catch.
                //
                // The cost is the mirror image, and it is real: a condition written as a literal
                // root-anchored path (`when Resources.A.Properties.Size > 10`) does not resolve,
                // because `ValueScope::query` starts at the resource. Accepted
                // for two reasons. A condition over one named resource does not belong on a
                // block that iterates all of them, and the variable idiom that real rulesets use
                // is unaffected -- `ValueScope::resolve_variable` delegates to the parent, so
                // `let vols = ...` followed by `when %vols !empty` still resolves at the root.
                // `a_type_block_condition_is_evaluated_against_each_resource` asserts all three
                // spellings so the trade is visible rather than inferred.
                //
                // The condition's captures need the resource's lifetime, and the `ValueScope` cannot
                // give it: it rebases the root and binds nothing, filing a filter capture with its
                // parent, which here is the rule's scope. So `AWS::S3::Bucket when
                // Properties.Config[ cfg | Enabled == true ] !empty { some %cfg == "alpha" }` kept
                // the first bucket's `alpha` in the rule scope's `captured` map, the second bucket's
                // body read `[alpha, beta]` and passed on a key from another resource, and the same
                // two buckets in the other order failed. The block-clause spelling had been given a
                // per-iteration scope for exactly this.
                //
                // The condition gets a scope of its own per resource, holding its captures and
                // nothing else, and the body's scope is built beneath it as before. Not the body's
                // scope: running the condition there made it read a body-level `let` that shadows a
                // rule-level one (PASS to SKIP at exit 0 both ways), and resolve a name only the body
                // binds, where the `when` block-clause spelling of the same text is an unresolved
                // name at exit 5. `declare_captures` gives the scope the condition's names, so a body
                // clause reading a name the condition declared but this resource did not capture
                // gets the empty selection a declared name gets, one deferral up, rather than a
                // deferral past the type block. Every other name the condition reads is asked of the
                // type block's resolver at that resolver's own level -- the condition is written at
                // the rule's level and is one of its readers, so a capture an earlier block clause
                // handed up is in its reach, as it was through the `ValueScope` -- while the body's
                // scope beneath it still asks as a nested block. Both scopes' captures are handed up
                // to the rule's scope as merged keys on every exit from the resource (body done,
                // exempted, undecidable), so a clause after the type block reads the union over every
                // resource.
                let mut condition_scope = capture_scope(Rc::clone(rv), &mut val_resolver);
                if let Some(conditions) = &type_block.conditions {
                    condition_scope.declare_captures(conditions);
                    let when_context = format!("{}/When", block_context);
                    condition_scope.start_record(&when_context)?;
                    match eval_conjunction_clauses(
                        conditions,
                        &mut condition_scope,
                        eval_when_clause,
                    ) {
                        Ok(status) => {
                            // The third place a `when` is decided, measured like the other two.
                            // Through the condition's own scope, which writes nothing while a
                            // measurement is on and forwards the notice. The line names this
                            // resource, and once it is recorded the `when` is settled and the
                            // resources after this one skip the measurement.
                            announce_a_moved_when(
                                conditions,
                                status,
                                Some(rv.self_path()),
                                &mut condition_scope,
                            );
                            condition_scope
                                .end_record(&when_context, RecordType::TypeCondition(status))?;
                            if status != Status::PASS {
                                // Not applicable to this resource, so it contributes to neither
                                // count. If that holds for every resource the fold below answers
                                // SKIP, which is the honest answer: the block applied to nothing.
                                exempted += 1;
                                condition_scope.end_record(
                                    &block_context,
                                    RecordType::TypeBlock(Status::SKIP),
                                )?;
                                // Handed up whatever the condition decided, as a block's are
                                // whatever its verdict: a clause after the type block reads the
                                // union over every resource, exempted ones included, which is what
                                // it read when these keys went straight to the rule scope.
                                condition_scope.merge_captures_into_parent()?;
                                continue;
                            }
                        }

                        // A condition this resource cannot answer fails closed for that resource,
                        // rather than aborting the file or exempting the resource. Exempting it is the
                        // dangerous direction: the block's clauses would never run and the rule could
                        // report compliance for a resource nothing checked.
                        Err(e) if is_unevaluatable(&e) => {
                            condition_scope.end_record(
                                &when_context,
                                RecordType::TypeCondition(Status::FAIL),
                            )?;
                            condition_scope
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
                                condition_scope.end_record(
                                    &context,
                                    RecordType::TypeCheck(TypeBlockCheck {
                                        type_name: &type_block.type_name,
                                        block: BlockCheck {
                                            status: Status::FAIL,
                                            refusal: false,
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
                            // Handed up on this exit too. The condition's first clause may have
                            // captured before a later one could not be decided, and a clause after
                            // the type block reads that key the same whether the resource then
                            // failed closed or ran its body; leaving without the merge made
                            // `%cfg !empty` after the block read an empty selection here only.
                            condition_scope.merge_captures_into_parent()?;
                            continue;
                        }

                        Err(e) => {
                            condition_scope.end_record(
                                &when_context,
                                RecordType::TypeCondition(Status::FAIL),
                            )?;
                            condition_scope
                                .end_record(&block_context, RecordType::TypeBlock(Status::FAIL))?;
                            condition_scope.end_record(
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
                                        refusal: is_refusal(&e),
                                    },
                                }),
                            )?;
                            return Err(e);
                        }
                    }
                }

                // The body's own scope, beneath the condition's. Its captures merge into the
                // condition scope's `merged` map, and the merge below carries both up.
                let status = eval_general_block_clause(block, &mut condition_scope, |gc, r| {
                    eval_guard_clause(gc, r, role)
                });
                condition_scope.merge_captures_into_parent()?;
                match status {
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
                                    refusal: is_refusal(&e),
                                },
                            }),
                        )?;
                        return Err(e);
                    }
                }
            }
            // A slot the type block's query could not resolve is not applicable, not an error.
            //
            // Returning `Err` here would abort the whole rules file: a document with no
            // `Resources` at its root would take every other rule in the file down with it, so a
            // violation an unrelated rule had already found would stop being reported, the exit
            // code going from 19 to 255 as the finding vanished.
            //
            // The situation is the one the `values.is_empty()` branch above already answers with
            // SKIP -- the document does not contain the type being checked -- so it gets the same
            // answer here, and `ur.reason` is kept for the block's own message rather than turned
            // into an error. Counting it as neither a pass nor a fail leaves the fold below to
            // decide: if no slot resolved, the block applied to nothing and reports SKIP.
            //
            // Both forms reach this slot: the plain form aborts without this arm, and so does the
            // `when` form once the type block's conditions are evaluated per resource rather than
            // behind an early return that masks the slot. Pinned by
            // `an_unresolved_type_block_query_skips_without_aborting_the_file`.
            //
            // Recorded as `TypeBlock`, matching what every resolved slot in this loop emits. A
            // second `TypeCheck` recorded here breaks the record shape display.rs documents and
            // relies on -- "has one TypeBlock for the block associated" -- so a `-v` run renders one
            // type block as two nested identical `Type(...)` nodes with the slot's own node
            // missing. The reason travels in `unresolved_reason` instead, which
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
                refusal: false,
                // Only the SKIP needs explaining, and it has three causes that call for three
                // different sentences. A rule that never fires looks exactly like a rule that
                // passes, so the reader needs to know which one happened -- and naming the wrong
                // cause sends them to the wrong place.
                //
                // The `when` sentence is guarded on `exempted == selected` rather than being the
                // default: as the default, a block with no `when` condition at all would report
                // that its `when` condition had exempted every resource -- reachable
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
                announce_a_moved_when(conditions, status, None, resolver);
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
                        refusal: is_refusal(&e),
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

/// The notice for a body capture that shadows an enclosing `let`; see `shadowing_body_captures`.
///
/// Named and located, because the move is otherwise invisible in the clause text: `%allowed` after
/// `Properties.Ports[ allowed ] > 0` reads the ports now, where a list wildcard bound nothing and the
/// name fell through to the enclosing `let allowed`. Carrying the position keeps one notice per site in
/// the set the root scope collects, so a block run over many resources prints it once.
fn shadowed_assignment_notice(shadowed: &ShadowedAssignment<'_, '_>) -> String {
    let site = match shadowed.site {
        // The position's file name is the path given on the command line, escaped as every other
        // notice escapes it, so a path holding an ESC or a line feed does not reach the body raw.
        Some(location) => format!(
            "the clause at {}",
            crate::utils::writer::location_for_notice(location)
        ),
        None => "an assignment's right-hand side or a rule argument".to_string(),
    };
    format!(
        "the filter capture `{name}` in rule `{rule}` ({site}) shadows a `let {name}` \
         of an enclosing scope: every clause of its block reads the captured values under `%{name}`, \
         where this shape read the assignment before captures bound on it. Rename one of them to make \
         the reading explicit.",
        name = shadowed.name,
        rule = shadowed.rule_name,
        site = site,
    )
}

pub(crate) fn eval_rules_file<'value, 'loc: 'value>(
    rule: &'value RulesFile<'loc>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    data_file_name: Option<&'value str>,
) -> Result<Status> {
    let context = format!("{}", rule);
    resolver.start_record(&context)?;
    // A body capture that shadows an enclosing `let` is read from the text, so it is announced once
    // per capture site before any rule runs, whatever the data holds; the collection is a set, so a
    // site prints once however many data files one run reads.
    for shadowed in shadowing_body_captures(rule) {
        resolver.record_deprecation(shadowed_assignment_notice(&shadowed));
    }
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
        // A conjunct with no answer, held across the conjunction rather than returned at once.
        // `AND(no, unknown)` is `no`: a conjunct that FAILed decides the conjunction whatever a
        // later or earlier conjunct could not decide, so the error is raised below only when no
        // conjunct decided. Returning it at the conjunct that raised it made `when L !empty
        // L == 'x'` over an `L` of `[]` fail its rule closed, at a time when an empty collection
        // was read as undecided -- the first conjunct had already answered no, and the guard the
        // message recommends did not work as a sibling condition. An empty collection is a decided
        // no, so that example does not reach here; a comparison the engine abandoned does, and the
        // hold is what keeps `when Size > 10 Name == /re/` decided by its first conjunct when the
        // regex runs out of budget on the second.
        let mut held: Option<Error> = None;
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
                                        refusal: false,
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
                    //
                    // Only an error that `is_unevaluatable` names is held: a clause the data could
                    // not answer, which is the case the hold above was written for. That is an
                    // allow-list, and it has to be one. The parent commit held every error, and a
                    // sibling that happened to pass then dropped it: `%nosuch == 1 or Resources
                    // exists` passed at exit 0 on every template with a `Resources` key and stopped
                    // the run only on one without, so the same typo was reported or silent depending
                    // on the data. A deny-list of name-lookup errors was tried next and had the same
                    // shape for a different error: `substring` with a bad bound raises `ParseError`
                    // during evaluation, and held, `%p == "vol" or Resources exists` went quiet
                    // whenever `Resources` existed. The list is the two dedicated variants
                    // `is_unevaluatable` names, each classified where the error is raised, because
                    // keying it on a general-purpose variant had the same shape once more: the
                    // recorder raised `IncompatibleError` for its own faults, so a recorder fault was
                    // held here too. Every error outside the allow-list -- an undeclared variable,
                    // rule or parameterized rule, a function argument the rules file got wrong, a
                    // parser invariant reached unchecked, a recorder fault -- returns at once. Upstream
                    // stopped on all of those but the `IncompatibleError` ones, which its hold
                    // admitted and failed closed.
                    //
                    // `NotComparable` and `RegexError` are not admitted either: neither reaches this arm
                    // from any rules file (the parser refuses a regex literal that does not compile, and
                    // a refusal the comparators produce is classified by `unanswerable_reason` into a
                    // comparison result before any hold sees it), and a refusal the data produced is
                    // already raised as `Unevaluatable` or `UndecidableComparison` where it arises. The
                    // scripted cells of `the_or_hold_is_an_allow_list` and
                    // `a_recorder_fault_in_a_disjunction_stops_the_run` inject each variant through
                    // `eval_fn` and pin what this arm holds and what it returns.
                    Err(e) if is_unevaluatable(&e) => {
                        if undecided.is_none() {
                            undecided = Some(e);
                        }
                    }

                    // The record carries no message. `validate` reports the record tree before it
                    // applies `?` to the error, so the rule is printed as FAIL on stdout, but the
                    // cause is already named there by the disjunct's own record (the
                    // access clause's "bailing" sentence), which every reporter renders in place of a
                    // disjunction's message when the disjunction has children; measured in the
                    // console, json, yaml and structured outputs, a sentence recorded here reaches
                    // none of them. The error text itself also reaches stderr.
                    //
                    // This is still decided by evaluation order: a sibling that passes first
                    // short-circuits the `or` before the error is ever raised, so `Resources exists
                    // or %nosuch == 1` still passes. Catching that needs a name check at load time,
                    // which is a different change.
                    Err(e) => {
                        if multiple_ors_present {
                            resolver.end_record(
                                &context,
                                RecordType::Disjunction(BlockCheck {
                                    message: None,
                                    status: Status::FAIL,
                                    at_least_one_matches: true,
                                    refusal: false,
                                }),
                            )?;
                        }
                        return Err(e);
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
                            refusal: is_refusal(&e),
                        }),
                    )?;
                }
                if held.is_none() {
                    held = Some(e);
                }
                continue;
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
                            refusal: false,
                        }),
                    )?;
                } else {
                    resolver.end_record(
                        &context,
                        RecordType::Disjunction(BlockCheck {
                            message: None,
                            status: Status::SKIP,
                            at_least_one_matches: true,
                            refusal: false,
                        }),
                    )?;
                }
            }
        }
        if num_fails > 0 {
            break Status::FAIL;
        }
        // Nothing decided no, and some conjunct had no answer: the conjunction has none either.
        // The caller decides what that means -- an assertion fails closed, a gate keeps the error
        // and fails its own rule closed.
        if let Some(e) = held {
            return Err(e);
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
