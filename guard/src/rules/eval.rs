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
/// # It used to ask two different questions, and both answers were wrong
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
/// fail-closed release will refuse. The note that used to sit at the top of this comment defended it --
/// "a mixed list that contains anything of the right kind is left alone" -- and that is a statement about
/// which pair is convenient to stop at, not about what the clause's answer rested on.
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
/// polarities over one document:
///
/// ```text
///                              true positives   false alarms   beside a non-PASS   false negatives   agreeing
/// before the alignment                    289             16                   0                81        694
/// the alignment                           355              0                   0                15        710
/// both granularities and the shape        370              0                   0                 0        710
/// ```
///
/// Measured at `c67f8774` against a `b8d3901e`-based oracle; four `[]`-against-a-string cells no longer owe
/// a notice at this commit. That is the whole caveat on the third row, and it is bounded rather than vague:
/// `69628df7` is the only change in `b8d3901e..HEAD` that removes a path into the four promoted sites, its
/// skip is gated on the left-hand VALUE being a zero-element `List` and the right-hand RESULT being a
/// `String`, so the affected set is exactly {left resolving to `[]`} x {right resolving to a String} x {both
/// polarities}. Of those, only the `NOT IN` half was ever owed: the `IN` half FAILed at `abbf73a7`, so
/// `clause_passed` suppressed the notice and nothing was owed there.
///
/// `EmptyOuter`, spelled `[[]]`, is NOT in that set and its two rows stand. It is a ONE-element list, so
/// `elements.is_empty()` is false and the skip never fires; the `f54089b4` sweep names `[]` and `[[]]` as two
/// left-hand shapes and only the first is affected. Do not read the caveat as covering both.
///
/// **Like the 132-shape grid above, this one is not reproducible from the tree.** Its clause list -- the
/// eighteen left-hand values and thirty right-hand spellings -- was never committed, so the other rows cannot
/// be re-derived or falsified from a checkout, and no figure in them should be restated as a property of
/// this tree. The 94-clause sweep in `eval_tests.rs` and the 140-clause grid in `operators.rs` both carry
/// this admission; this table did not, which is how the third row's zeros came to read as current. If the
/// question comes up again, commit the clause list.
///
/// One further reason a row here may have moved, recorded rather than resolved: `07774380` took the
/// `[ keys <op> ... ]` path from 255 to 19. Any such clause in the uncommitted list moved for that reason and
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
/// `EmptyList NOT IN Str` WAS one of the 13, and this paragraph used to say it "is a shape refusal,
/// `([], "abc")`, which is there whether or not anything flattens". That was true at `c67f8774` and is false
/// now. `69628df7` gave the `(None, None)` arm its own skip for a string right operand paired with an empty
/// left-hand list -- the `uncompared_pairings` skip under `elements.is_empty()` in `contained_in`, above the
/// only `contained_in` call that arm makes -- so the
/// pair is never built and there is no refusal for the clause to pass on. The half of the old paragraph that
/// still holds is the diagnosis of the error it was correcting: reaching "not repairable" from the element
/// pairs, of which there are indeed none, and stating it of the clause.
///
/// The VERDICT question that cell also sits in is a different one and is untouched: `Empty NOT IN Str`
/// against `Empty NOT IN Strs[*]` owe opposite answers from operands no predicate can tell apart, which
/// `27383c98` proves and which nothing here moves. A notice is not a verdict, and the impossibility is
/// about the verdict.
///
/// And the empty-left-hand family OWED two notices here rather than one, which was the same paragraph's
/// other error. This paragraph said "owes", present tense, and at `69628df7` the family owes neither.
/// `Empty NOT IN Ustr` was the documented one; `Empty NOT IN Strs[*]` was the second, easy to read past
/// because it looks like a different shape -- the right operand is a query that EXPANDS to strings rather
/// than a string, so it reached the same `(None, None)` arm with the same `([], "a")` shape pair, and it is
/// not a `Str`. Both emitted at `e8a03dda` and both went silent at `b8d3901e`, which is unchanged history.
/// The 120-cell sweep behind "the pair is the whole family" -- 30 right-operand kinds in both polarities for
/// a `[]` and a `[[]]` -- established the family, and the family is what the skip above took out in one go.
///
/// What they get instead, measured with the release binary at `69628df7` over
/// `{Empty: [], Str: "abc", Ustr: "abc", Strs: ["abc"]}`: `Empty NOT IN Ustr`, `Empty NOT IN Str`,
/// `Empty NOT IN Strs[*]` and `Empty IN Ustr` each exit 0 printing `vacuous_comparison_notice` -- "passed
/// without comparing anything" -- and none of the four prints "could not be compared with any element of the
/// list". The literal `Empty NOT IN "abc"` prints that same notice and always has, so the query spellings
/// joined their literal rather than losing a diagnostic.
///
/// This predicate had not been told, and the shape arm below has been told now: its `vacuous_match` is
/// `lhsl.is_empty()` alone, because the operator skips an empty left-hand list against every right-hand
/// kind and the condition named only the string.
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
/// The wider grid a repair has to survive is not this one, because a before-and-after only covers the
/// shapes it enumerates. 928 further shapes -- the `[0]`/`[*]` spellings the impossibility proofs turn on, a
/// two-value left query and `some`, an empty string, an empty map and a null on the left -- carry 25 more
/// owed notices at the alignment and none after. Then 402 more with a LITERAL on the left, which is the one
/// arm reached by reading rather than by measurement: `InOperation::compare`'s `(Some, None)` arm decides a
/// list-valued literal with `Vec::contains`, which is `PartialEq` and cannot refuse, so it should own no
/// owed notice. It does not. A list written out on the left of a clause does not parse at all, so that arm
/// is reachable only through a `let`, and 306 `let`-bound cells reach 61 true positives with nothing owed
/// and nothing spurious.
///
/// Across all 2410 cells: no false alarm, no owed notice missed, and status, exit code and stdout byte
/// count identical to the merge-base. This is diagnostics.
///
/// # The branch this predicate cannot model, and why that is not a gap yet
///
/// `InOperation::compare`'s `(Some, None)` arm decides a list-valued LITERAL against a right-hand side
/// holding no list with `!rhs.contains(elem)` -- `Vec::contains`, so `PartialEq` and no `compare_eq`
/// anywhere. Nothing in that branch can refuse, so nothing this predicate reads is produced there, and no
/// shape test helps either: the shape arm above is about a refusal `contained_in` returns, and this branch
/// never calls `contained_in`.
///
/// Measured rather than left open. 160 cells satisfy the branch's own condition -- eight list literals bound
/// with `let`, against ten queries resolving only to non-list values, both polarities -- and the fail-closed
/// build moves NONE of them, so nothing is owed there. No notice is emitted either.
///
/// But the silence is OVER-DETERMINED, and saying so is the point of this section. All 80 `NOT IN` cells of
/// that shape FAIL, at the merge-base and here alike, so `clause_passed` in `binary_operation` gates the
/// notice off whatever this predicate answered. So the measurement does not show the shape arm staying
/// quiet on the branch, and an earlier draft of this paragraph claimed it did -- reading absence of a notice
/// as evidence about a predicate whose answer nothing consulted. What it does show is narrower and still
/// worth having: no clause of that shape reaches the state this notice describes, so there is no notice to
/// owe and none to get wrong. `a_membership_decided_by_partial_eq_owes_no_notice` carries three of the
/// cells, and its own comment says which half of it can fail.
///
/// The oracle's reach is the second limit and it is independent of the first. The fail-closed build promotes
/// four `compare_eq` suppressions and this branch calls none of them, so "the change moves this clause"
/// cannot be true of any cell decided there whatever its verdict. If a later release fails that branch
/// closed, or gives it a comparison that can refuse, both limits lift at once and this predicate is not
/// where the answer would come from -- there is nothing for it to read.
///
/// # The `[*]` bypass this fix waited on, and why the wait is over
///
/// Alignment was blocked, deliberately, while the `[*]` membership bypass was open. Measured on a tree with
/// the granularity change and nothing else: the suite stayed green, all five aws-guard-rules-registry
/// notices survived, the false alarms went -- and `Pair NOT IN Deny13[*]`, with `{"Pair":[1,2],"Deny13":[1,3]}`,
/// went from exit 0 *with* the notice to exit 0 **silent**. That clause admitted a value its denylist names,
/// and no test in the suite failed when it did. So the noise was accepted for one true positive on a live
/// bypass at exit 0, and only until the bypass closed.
///
/// `e331c6b` closed the right-expanded denylist arm and the re-measurement was run rather than assumed:
/// `Pair NOT IN Deny13[*]` over the same document is exit 0 with the notice at `b05f922` and **exit 19 and
/// silent** at `8ed1b54`, across six spellings. Re-verified again here, after `f6639d5`, `6aeb59b` and
/// `20c72f0` had each touched the neighbourhood.
///
/// Why it is silent depends on the spelling, and an earlier revision of this paragraph gave one reason for
/// both. Asserted -- the spelling `8ed1b54` measured -- the verdict gate suppresses it and the report does
/// name the clause: exit 19, `provided value [[1,2]] did match expected value in [[1,3]]`. As a `when`
/// condition the verdict gate still suppresses it and the report names nothing at all: exit 0, empty
/// stdout. Both are silent and only the first is silent for the reason given, so the sentence was true of
/// what it measured and false as a general claim. Every spelling of that clause is now silent, in either
/// role.
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
/// bodies before their `Location[...]` tails are byte-identical to the ones the merge-base prints.
/// `a_left_hand_value_that_is_not_a_list_is_not_flattened` pins that shape as a unit cell and the registry
/// corpus pins the five themselves.
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
    let rhs_values = values(rhs);
    // Nothing on one side is nothing compared, and nothing compared is nothing to warn about. About the
    // VALUES and not their elements: an empty list is a value `contained_in` receives and answers for,
    // and the arms below say what it answers.
    if lhs_values.is_empty() || rhs_values.is_empty() {
        return false;
    }

    // Whether `InOperation::compare` will take its `(None, None)` arm, which is the one thing here that
    // is about the call rather than about the values. That arm drops the refusal the shape arm below is
    // about; every other arm reports it and the clause fails closed on it already. Asked of
    // `operators::is_literal` rather than re-derived, so the two cannot drift.
    let both_queried = operators::is_literal(lhs).is_none() && operators::is_literal(rhs).is_none();

    // Some pair refused for a reason that is an incomparability. Tracked rather than returned, because
    // the answer is a property of every pair the clause was decided on: one refusal is enough, and no
    // refusal at all means there is nothing here to warn about.
    //
    // An answered pair cancels nothing. It used to `return false`, on the reading that a clause with
    // anything comparable in it decided on the comparable pair. That is false of `NOT IN`: a value
    // passes it by matching NOTHING, so every pair was built and an answered one says only that this
    // element was not the collision.
    //
    // ONE answered pair anywhere silenced the whole predicate, and position had nothing to do with it.
    // That `return false` returned from the FUNCTION rather than from the element loop, so the first pair
    // `compare_eq` could answer ended the walk wherever it sat. An earlier revision of this note said the
    // silence was a matter of walking order -- `Str NOT IN Haystack` over `["zzz", 7, false]` "silent
    // because `\"zzz\"` is written first, and noticed if it is written last" -- and that is wrong, in a way
    // that reads as an explanation. Measured on 2026-09-03 with release binaries: `["zzz", 7, false]`,
    // `[false, 7, "zzz"]` and `[7, false, "zzz"]` are ALL silent at `e8a03dda` and all noticed at
    // `b8d3901e`, so rewriting the denylist so the answerable element comes last changes nothing. The
    // substance stands -- an answered pair discarded a refusal that had already been seen -- and only the
    // order framing was false. Worth spelling out because "reorder the denylist" is a plausible thing for a
    // reader to try, and it would tell them the predicate was fixed when it was not.
    let mut refused = false;
    for value in &lhs_values {
        for element in rhs_values_paired_with(value, &rhs_values, both_queried) {
            match (&**value, &**element) {
                // `contained_in`'s list-against-list arm, which decides at TWO granularities and used to
                // be read as deciding at one.
                //
                // The element pairs are always built, by `elements_not_matched` asking `is_one_of` per
                // left-hand element. Not recursively -- for a `Deep` of `[["a"]]` the element is
                // `["a"]`, and that is the operand `is_one_of` is handed, so a second level would
                // compare something no clause compares.
                (PathAwareValue::List((_, lhsl)), PathAwareValue::List((_, rhsl))) => {
                    for left in lhsl {
                        for right in rhsl {
                            refused |= pair_refused(left, right);
                        }
                    }

                    // And the WHOLE left-hand list against each entry, which that arm walks when no
                    // element matched and the denylist holds a list. Keyed on the same condition the
                    // operator branches on, because that is what decides whether the loop exists to
                    // refuse in: a flat denylist never reaches it, and reinstating the whole-value pair
                    // there is exactly the false-alarm class the alignment removed --
                    // `Strs NOT IN ["x", "y"]` is `(List, String)`, which has no arm, on a clause every
                    // pair of which is string against string.
                    //
                    // Not gated on the elements having failed to match, though the operator's loop is.
                    // Where they all match `contained_in` returns Success, and the walk stops at that
                    // pairing rather than carrying the value on to later right-hand values --
                    // `rhs_values_paired_with` is what stops it, and before it did the verdict gate in
                    // `binary_operation` was the only thing between this loop and a false notice.
                    // The operator gates this loop TWICE and the predicate mirrored only the first.
                    // `operators.rs:1031` is `rhsl.iter().any(|elem| elem.is_list())`, which is the
                    // condition below. `operators.rs:1054` is `if !flat_subset`, where `flat_subset` is
                    // `elements_not_matched(lhsl, rhsl)`'s diff being empty. An empty `lhsl` has nothing
                    // to leave unmatched, so its diff is empty, `flat_subset` holds, and the operator
                    // skips its whole-list loop -- it builds no whole-value pairing for such a value at
                    // all. `operators.rs:1029-1030` says so outright, and it is measurable from outside:
                    // `Empty IN [[9], 5]` exits 0, which is `contained_in` answering `Success`.
                    //
                    // So `lhsl.is_empty()` restores the missing half of a two-part gate rather than
                    // carving out a special case, and that is a claim about the operator's structure a
                    // reader can check. Without it the element loops above iterate zero times for such a
                    // value, leaving `compare_eq([], entry)` as the arm's entire contribution --
                    // `NotComparable` against an int entry -- so `refused` went true on a pairing nothing
                    // built.
                    //
                    // UNGATED, and an earlier revision of this fix wrote `both_queried && lhsl.is_empty()`,
                    // which is the inverse of the coverage needed. The QUERIED path needs no guard here:
                    // `membership_stops_after(empty, X)` is true for every non-String X, so any list
                    // element is a stop and the exclusive prefix drops it, leaving only Strings inside
                    // `[0..at)` -- and a String is not a list, so this arm is unreachable. The LITERAL
                    // path is the one that reaches it, because `rhs_values_paired_with` returns at
                    // `eval.rs:732-734` before the endpoint is consulted, so the prefix cannot help there.
                    // Gating on `both_queried` skipped the loop exactly where the prefix already covers it
                    // and left it running on the only path that needed it.
                    //
                    // A RESIDUAL of the same class is left open on purpose. `flat_subset` is also true
                    // when `lhsl` is non-empty and every element matched; the operator skips the loop
                    // there too, and this still walks it. `lhsl.is_empty()` does not cover that, and
                    // closing it needs the operator's `diff` at the predicate, which
                    // `Comparator::compare` does not carry out -- the same shape as the `own_skip_reason`
                    // gap. It is latent by the argument this arm rests on: every element matching means
                    // `contained_in` returns `Success`, which is a match, which fails `NOT IN`, so the
                    // verdict gate shuts. Re-deriving `elements_not_matched` here is NOT the fix.
                    // Re-deriving what the operator already computed is the defect class this round has
                    // been retiring, and it is how the divergence being repaired arose.
                    if !lhsl.is_empty() && rhsl.iter().any(|right| right.is_list()) {
                        for right in rhsl {
                            refused |= pair_refused(value, right);
                        }
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
                    for left in lhsl {
                        refused |= pair_refused(left, right);
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
                    // The vacuous match, because it happens first. The `(None, None)` arm reads an empty
                    // left-hand list as vacuously present in anything that denotes a set and continues
                    // the outer loop, so `contained_in` is never called and `Empty NOT IN D13[*]` fails
                    // on the match rather than passing on a refusal.
                    //
                    // An empty left-hand list, whatever the right operand is, because the operator skips
                    // the pairing for every right-hand kind and this condition used to name only one of
                    // them.
                    //
                    // It carried `&& !matches!(right, PathAwareValue::String(_))`, which read "a string is
                    // the exclusion in the operator, so it is the exclusion here". That stopped being true
                    // at `69628df7`, which gave the string pairing a skip of its own: an empty left-hand
                    // list against a string increments `uncompared_pairings` and `continue`s, and against
                    // anything else takes `continue 'each_lhs`. Both leave before `contained_in` is called,
                    // so no right-hand kind reaches the refusal and the whole `lhsl.is_empty()` case is a
                    // pairing the operator never builds.
                    //
                    // What the stale half cost, which is a live false notice rather than dead code. The
                    // earlier note here said no notice goes out because the gate in `binary_operation` also
                    // requires `clause_passed`, and a clause whose only pairing was skipped compared
                    // nothing. That is true of a left operand whose ONLY value is the empty list, which is
                    // the population it was checked against, and false as soon as the empty list has a
                    // sibling: `refused` ORs over the whole cross product, so a skipped pairing's refusal
                    // rides out on a sibling that was compared and decided the clause. With `Mix` of
                    // `[[], "q"]` and `Ustr` of `"abc"`, `Mix[*] NOT IN Ustr` exits 0 and printed the
                    // membership notice, whose subject is `"q"` against `"abc"` -- String against String,
                    // comparable, decided false -- while the `[]` that produced the refusal was compared
                    // with nothing. Dropping `[]` from the left operand drops the notice, which is what
                    // attributes it to the skip.
                    //
                    // `a_skipped_pairing_does_not_earn_a_sibling_a_membership_notice` is that shape with the
                    // `NoEmpty` control beside it, and
                    // `every_string_spelling_warns_through_the_channel_that_is_true_of_it` is the
                    // sole-value population this condition was right about.
                    //
                    // The widened condition holds, and the argument is structural rather than a sweep --
                    // worth recording because a soundness claim is cheap to assert and rarely grounded.
                    // Inside `InOperation::compare`'s `(None, None)` arm an empty left-hand list never
                    // reaches `contained_in` for ANY right-hand kind: against a `String` the arm
                    // increments `uncompared_pairings` and `continue`s, and against every other kind it
                    // takes `continue 'each_lhs`, both above the `found_in_string` call. So no right-hand
                    // kind is owed the shape refusal and `lhsl.is_empty()` cannot be too wide. The other
                    // half is that `both_queried` is asked of `operators::is_literal`, the same function
                    // that selects that arm, so the predicate and the arm cannot drift into disagreeing
                    // about which pairs exist. Neither half depends on a clause list, so both survive a
                    // rebase; prefer them to a re-run of the grid.
                    let vacuous_match = lhsl.is_empty();
                    if both_queried && !vacuous_match {
                        refused = true;
                    }
                }

                // `contained_in`'s `rest` arm against a list: the left value is the operand `compare_eq`
                // receives, so the value and the element it contributes are the same thing and nothing
                // is missing at a second granularity.
                (left, PathAwareValue::List((_, rhsl))) => {
                    for right in rhsl {
                        refused |= pair_refused(left, right);
                    }
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
/// value that matches it and [`incomparable_membership`] has to stop where the arm stops. Without
/// this the predicate counted refusals from pairings the arm never built --
/// [`operators::membership_stops_after`] carries the measurement and why a copy of the arm's rule
/// must not live here.
///
/// The stopping pairing is EXCLUDED along with the later ones, because a value that stops has MATCHED.
/// All three stops are matches: the empty-left skip reads an empty list as vacuously present, which is
/// the convention `InOperation::compare` states where it takes that skip; `found_in_string` answering
/// `All` is a full string containment; `contained_in` answering `Success` is a membership. A matched
/// value FAILS `NOT IN`, so it cannot be the value a passing `NOT IN` clause passed on, and counting its
/// refusals credits a passing clause with a refusal belonging to a value that failed.
///
/// An earlier revision included it, reasoning that the arm "reaches `contained_in` for it and only skips
/// the element loop". That is true of one stop of the three and was being used to justify all three: the
/// empty-left skip reaches NEITHER `found_in_string` nor `contained_in`, and an `All` reaches only
/// `found_in_string`. Excluding the pairing is both simpler to state and correct for all three, and it
/// settles rather than defers the question that revision left open -- a list-against-list `Success`
/// whose element pairs refuse while the subset holds, `["x", 1]` inside `["x", 1]`, is precisely the
/// accounting now dropped.
///
/// Exclusive is a strict reduction in what the predicate counts, so the direction of risk is silence
/// where a notice was owed, and the argument that it cannot happen is the one above rather than a sweep:
/// the stopping value matched, so its clause fails, and the gate in `binary_operation` emits nothing for
/// a clause that did not pass. What this drops was unreachable through the notice.
///
/// NOT the empty-left skip against a STRING, which is not a stop at all.
/// [`operators::membership_stops_after`] answers false there, because the arm skips that one pairing
/// with a plain `continue` and KEEPS the value. So an empty left-hand list still reaches the
/// `(List, right)` arm above, and the `vacuous_match` exclusion there is still the only thing keeping
/// its shape refusal out. This change does not subsume it.
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
/// Answered per pair rather than for the clause, and that is the second half of the same correction. It
/// used to `return false` for the whole cross product on the evidence of one pair, and the pair it is
/// right about is its own. `some Multi.*.V NOT IN [/re/]` over a thirty-character `a` string and a list of
/// ints: the string exhausts the budget, the ints refuse against the pattern -- `(Int, Regex)` is not an
/// arm -- and the clause passes on the list. Measured, the list alone earned the notice and the two
/// together earned nothing, so an unrelated sibling value's spent budget destroyed a warning that was
/// owed. `a_spent_budget_on_one_value_does_not_silence_another_values_notice` pins all three.
///
/// Narrow on purpose: only the budget, never a kind mismatch. Passing over every `Err` would silence the
/// class this notice exists for, which is the tracked defect in `docs/KNOWN_ISSUES.md`.
///
/// Which pairs reach the budget arm moved when the caller stopped comparing whole values against
/// elements, and the two spellings this arm was written around swapped places. A FLAT denylist holding a
/// regex now hands it the left-hand list's ELEMENTS against that regex, so `Cat NOT IN [/re/]` over a
/// one-element `Cat` builds `(String, Regex)` and arrives with a spent budget -- where it used to build
/// `(List, Regex)`, which is not an arm, and be counted as a kind refusal. A denylist holding a NESTED
/// list is the mirror: the element pair is `(String, List)`, a real `NotComparable`, where the
/// whole-value pair was `(List, List)` and zipped into `(String, Regex)`. That whole-value pair is built
/// again for the nested spelling, by the second granularity in the caller, so the nested clause now
/// reaches both.
///
/// Neither swap is observable through the notice, because both clauses fail: `match_value` promotes
/// `RegexError` for the flat spelling and `contained_in` promotes it for the nested one, so the verdict
/// gate in `binary_operation` suppresses whatever this answered. Measured with the release binary on a
/// `Cat` of one thirty-character string of `a`s: `rule r { Cat NOT IN [/(?!x)((a+)+)b/] }` and
/// `rule r { Cat NOT IN [[/(?!x)((a+)+)b/]] }` each exit 19 with nothing on stderr, before this change
/// and after it. `a_spent_backtracking_budget_is_not_an_incomparable_pair` and
/// `a_denylist_refuses_a_value_it_could_not_evaluate_in_either_spelling` hold both.
///
/// Nothing is lost by narrowing it. Where the budget is the only thing that refused the notice still
/// does not go out, which is the case this exclusion was added for; and such a clause is answered
/// elsewhere anyway, since `match_value` promotes `RegexError` and the clause fails saying the expression
/// could not be evaluated. That last part is true of an assertion and not of a gate -- a failing gate is
/// reported by nothing -- but the notice is not the thing to fix it with, because a clause that does not
/// pass is not one the coming fail-closed change moves.
fn pair_refused(lhs: &PathAwareValue, rhs: &PathAwareValue) -> bool {
    match compare_eq(lhs, rhs) {
        Ok(_) | Err(Error::RegexError(_)) => false,
        Err(_) => true,
    }
}

/// Notice for a comparison that passed without comparing anything, because the value it selected was
/// an empty collection.
///
/// `docs/QUERY_AND_FILTERING.md` lists `Tags: []` alongside a missing key and an empty map as a
/// retrieval error, and says all retrieval errors are failures. The other two do fail; this one passes,
/// which makes it the odd one out rather than a design choice. It is not changed in this release
/// because the change turns a passing run into a failing one, and a rule author deserves to hear about
/// that before a pipeline does.
///
/// Carries the clause's source position for the reason given on [`incomparable_membership_notice`]: the
/// context is a `Display` that names no rule and no file, so two clauses rendering alike collapse in the
/// set these are collected in.
fn vacuous_comparison_notice(context: &str, location: &FileLocation<'_>) -> String {
    format!(
        "DEPRECATION: {} passed without comparing anything, because the query selected an empty \
         collection. From the next release this reports a failure, matching a missing key and an empty \
         map. Guard the clause with `when <query> !empty {{ ... }}` if an empty collection is expected. \
         The clause is at {}.",
        context, location
    )
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
/// Four of the five and the fifth break differently, which is worth stating because one sentence used to
/// cover all five and described only the four. The four are filter predicates matching a `!Ref`-shaped
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
    format!(
        "DEPRECATION: {} passed because the value could not be compared with any element of the list, \
         which is currently read as \"not a member\". A future release fails closed here, as `!=` \
         already does. Compare against values of the same kind, or use `!=` if that is the intent. The \
         clause is at {}.",
        context, location
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
/// A missing path and an empty collection fail closed somewhere else rather than arriving as an
/// empty selection, so a filter that excluded every value is the only producer measured. That is
/// still not put in the sentence: one sampled producer is not proof of the only producer, and
/// telling an author to check filters on a query that has none would be the same mistake as naming
/// a condition the rule does not contain. The query is printed and the author reads their own query.
///
/// Rendered through [`SliceDisplay`], which is what every other query-naming message in this file
/// uses, so a filter prints as the parser's own name for it -- `Resources. (map-key-filter-clauses)`
/// rather than `Resources[ keys == /Z9/ ]`. Ugly and not wrong; changing it would move every one of
/// those messages and belongs on its own.
///
/// # Every claim here is about this query and nothing wider
///
/// This sentence used to end "Nothing was refused -- the query ran and matched nothing", and the
/// first half of that was a claim about the whole rule made from a fact local to one query. This
/// function is handed a query. It cannot see the rule's other clauses, so it cannot know whether one
/// of them was refused -- and when one was, the sentence said otherwise:
///
/// ```text
/// rule r {
///     Resources[ keys == /Z9/ ] { Type == "AWS::S3::Bucket" }
///     or Resources.*[ Properties.KmsKeyId == "alias/aws/s3" ].Type == "nope"
/// }
/// ```
///
/// over `KmsKeyId: {Ref: MyKey}`, the second disjunct's filter compares a map against a string and is
/// refused. Exit 0 either way, and the report said "Nothing was refused". Swapping the two disjuncts
/// makes the same rule on the same data report "a comparison in one of its query filters reported:
/// PathAwareValues are not comparable map, String" instead, so the false half was also suppressing the
/// one actionable fact in the report, and which of the two a reader saw depended on the order they
/// happened to write their disjuncts in.
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
/// Two kinds produce it, and they differ only in what they say. `IncompatibleError` covers operands the
/// comparator has no arm for -- `EMPTY` against a type that cannot be empty, a function argument the
/// input cannot supply -- and `UndecidableComparison` covers a comparison that ran and was abandoned,
/// today a spent `fancy_regex` backtracking budget. Both are verdicts about the clause and both are
/// classified together here, because every caller asks the same question of them: does this clause fail
/// closed as an assertion and keep its error as a gate. The two exist separately so the message can be
/// true; see [`Error::UndecidableComparison`].
///
/// It is matched rather than propagated because an unevaluatable clause is a verdict about that clause,
/// while a genuine failure of the machinery should still stop the run.
fn is_unevaluatable(e: &Error) -> bool {
    matches!(
        e,
        Error::IncompatibleError(_) | Error::UndecidableComparison(_)
    )
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
    /// Why there was no answer, for the same reason [`operators::NotComparable`] carries it: the map-key
    /// path has to tell a refusal to compare kinds from an evaluation the engine abandoned, and the
    /// reason string cannot be classified after the fact.
    cause: operators::Unanswerable,
    pair: LhsRhsPair,
}

/// A refusal to compare, built the same way at each of the three sites that raise one.
///
/// Shared so the classification happens once, in `operators::unanswerable_reason`, rather than three
/// times by hand. Before this, `each_lhs_compare` matched `Error::NotComparable` and propagated
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

                    // Any refusal, not only `NotComparable`. This arm used to name that one variant and
                    // leave a sibling `Err(e) => return Err(e)`, so a spent backtracking budget left the
                    // evaluator unclassified; see `map_key_refusal`. Both kinds are now offered the
                    // element-wise retries below, which is a second chance at a decidable answer rather
                    // than a change of meaning: a shorter element may finish inside the budget where the
                    // whole value did not.
                    Err(e) => {
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

                                        Err(e) => statues.push(map_key_refusal(
                                            e,
                                            Rc::new(each.clone()),
                                            Rc::clone(each_rhs_resolved),
                                        )),
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

                                            Err(e) => statues.push(map_key_refusal(
                                                e,
                                                Rc::clone(&lhs),
                                                Rc::new(rhs_inner_single_element.clone()),
                                            )),
                                        }
                                        continue;
                                    }
                                }
                            }
                        }

                        statues.push(map_key_refusal(
                            e,
                            Rc::clone(&lhs),
                            Rc::clone(each_rhs_resolved),
                        ));
                    }
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
            false,
            Some(reason.clone()),
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

                // The reason travels with the record, which is what `report_value` does for the `==`
                // and `!=` spellings of this same question. `message` was `None` unconditionally, so a
                // key whose comparison had no answer was rendered by the reporters as one that was
                // compared and came out wrong: `NOT IN` printed "provided value [...] did match
                // expected value in [...]", asserting a success about a comparison fancy_regex
                // abandoned, and `IN` printed the mirror. 07774380 fixed the sibling and its scoping
                // sentence named this function without changing it.
                //
                // The first refusal among this key's pairings, and only when the fold came out false.
                // A key that satisfied the clause has a verdict that did not rest on the pairing that
                // failed, so there is nothing to explain -- the same precedence the `Comparable` arm of
                // `satisfies` already applies. First rather than all, because a clause names one
                // pattern in practice and the scalar arm reports one reason too.
                let reason = results.iter().find_map(|(r, _)| match r {
                    ComparisonResult::NotComparable(NotComparableWithRhs { reason, .. }) => {
                        Some(reason.clone())
                    }
                    _ => None,
                });

                eval_context.end_record(
                    &context,
                    RecordType::ClauseValueCheck(ClauseCheck::InComparison(InComparisonCheck {
                        from: QueryResult::Resolved(Rc::clone(lhs)),
                        to: to_collected,
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
    // It has to be emitted after, because the notice says the clause *passed* on the incomparability and
    // there is no verdict here to check that against. Gated on the incomparability alone it printed that
    // beside a FAIL, which is the opposite of what happened. Measured across 231 `NOT IN` shapes: 177
    // reach the notice, 146 pass and 31 fail, and every one of the 31 printed it.
    //
    // Two things `e26817a6`'s message says about this predicate need correcting here, because a message
    // cannot be amended.
    //
    // It cites the predicate as `eval.rs:1567`. That was right at `e26817a6` and is not right now: the
    // line has moved. Cite the symbol instead -- the `membership_is_incomparable` binding in
    // `binary_operation`. The quoted source text in that message is exact, which is what keeps it
    // findable, so search for the text and not for the number. This is the same rot `a1e552fe` wrote the
    // prefer-the-symbol rule against, and it happened inside the twelve commits that wrote the rule.
    //
    // And it attributes `"8 over-denials and creates 0"` to `69628df7` as a quotation. That string does
    // not appear in `69628df7`'s message. The nearest real text there is "trading eight over-denials for
    // four", which prices the REJECTED `unanswerable` repair rather than what `69628df7` fixed. The
    // companion quotation in the same sentence, "no `NOT IN` cell moves", IS verbatim, and it is the one
    // the conclusion rests on: that `69628df7` created 25 silent `NOT IN` over-denials while claiming
    // none moved. The finding stands on the quotation that is real; the other one is not a paraphrase to
    // be tracked down, it is a sentence to stop looking for.
    //
    // Two further claims in that message are about the residual query-versus-literal set rather than the
    // verdict, and both need correcting.
    //
    // "all 12 are over-admissions, the safer direction" holds over that commit's own 432-clause sweep and
    // does not generalize, which is how it reads. Over-denials survive in that set. With `NoEmptyPartial`
    // of `["ab"]` and `Strs2` of `["abc", "zzz"]`, `NoEmptyPartial NOT IN Strs2[*]` exits 19 while
    // `NoEmptyPartial NOT IN ["abc", "zzz"]` exits 0 -- the query denying a value its literal admits,
    // because `found_in_string` reads substring containment where the literal reads membership. Identical
    // at `abbf73a7`, `69628df7`, `e26817a6` and here, so it is pre-existing and this branch created none
    // of it. Two of four enumerated query/literal pairs are over-denials; that population is those four
    // pairs and no claim is made about a wider one.
    //
    // And the two cells that message calls "the two new ones" are misattributed and mislabeled. They are
    // `Empty IN Strs[0]` and `Empty IN Strs[*]`, and both moved FAIL to PASS at `69628df7`, not here:
    // exit 19 at `abbf73a7`, exit 0 at `69628df7` and after. At `e26817a6` they are not disagreements at
    // all, query and literal both exiting 0. The label is wrong as well: `Strs[0]` and `Strs[*]` never
    // diverge FROM EACH OTHER. Over 56 enumerated cells -- seven left operands, both polarities, four
    // right-hand spellings -- they return identical verdicts at `abbf73a7`, `69628df7`, `e26817a6` and
    // here. What diverges is the queried string against the written-out list, and the surviving instance
    // is `Empty NOT IN Strs[*]` at 0 against its literal's 19, in the `NOT IN` polarity, at every commit
    // measured. Prefer this correction to the number: a wrong count invites recomputation, while a wrong
    // mechanism name gets believed.
    //
    // None of that touches the impossibility argument carried above `found_in_string` and in
    // `eval_tests.rs`. That one is about the verdicts an oracle OWES two spellings which resolve to the
    // same value -- a statement about the specification, not about observed divergence, and it stands.
    // What is corrected here is only a message reusing its name for a pair of cells it does not describe.
    let membership_is_incomparable =
        cmp.1 && cmp.0 == CmpOperator::In && incomparable_membership(&lhs, rhs);
    let results = cmp.compare(&lhs, rhs)?;
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
                    // A value the query could not produce. Decided rather than undecided: the property
                    // is absent, which is a fact about the document, and the comparison then fails on
                    // it definitively. Recording it as decided is also what keeps a gate over an absent
                    // property reporting the rule as not applicable, which is where it already was.
                    operators::ValueEvalResult::LhsUnresolved(ur) => {
                        evidence.decided_failure = true;
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
                        // Decided, for the same reason as the arm above: the reference resolved to
                        // nothing, and there is nothing undecided about comparing against nothing.
                        evidence.decided_failure = true;
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
                                evidence.decided_failure = true
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
                    ) => {
                        // Every shape under here is a comparison the operator performed and answered
                        // no. Recorded once for the whole arm rather than in each of its four branches:
                        // they differ in what they report, not in whether the answer exists.
                        evidence.decided_failure = true;
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
                                            from: QueryResult::Resolved(Rc::clone(&pair.lhs)),
                                            to: Some(QueryResult::Resolved(pair.rhs)),
                                        },
                                    )),
                                )?;
                                statues.push((
                                    QueryResult::Resolved(Rc::clone(&pair.lhs)),
                                    Status::FAIL,
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
                                    Status::FAIL,
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
                                    Status::FAIL,
                                ));
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
                                    statues.push((
                                        QueryResult::Resolved(Rc::clone(&lhs)),
                                        Status::FAIL,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            Ok(EvaluationResult::QueryValueResult(statues))
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
    // Its own variant rather than `IncompatibleError`, which is what this used to raise, and the reason
    // is the message. `IncompatibleError` renders as "Types or variable assignments are incompatible
    // `<reason>`", and that claim is false here: the operands were of kinds the comparator has an arm
    // for and the engine quit part way. Both frames that print it inherited the falsehood -- the rule
    // frame read "not applicable: Types or variable assignments are incompatible `The regular
    // expression could not be evaluated ...`", and the filter frame wrapped the same sentence in "due
    // to retrieval error ... when handling clause, bailing". The new variant renders as its reason
    // alone, so each frame supplies its own framing and neither asserts a type mismatch.
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
    // most of them suppression tests expecting SKIP, where the merge-base has 0 failed rules. So the
    // kind-mismatch half of this defect stays open, tracked in `docs/KNOWN_ISSUES.md` behind the same
    // precondition `incomparable_membership_notice` already records -- those rules have to change first
    // -- and the notice is what covers it meanwhile. `Unanswerable` carries the split.
    //
    // That 143 is the cost of reading `IncomparableKinds` as an undecidable GATE, reached by `==` and
    // `!=` -- which is why the `ScanOnPush` idiom is its canonical shape. It is NOT the cost of
    // promoting the membership refusal, which is registry-free: measured at `1ba4648d`, promoting
    // `is_one_of`'s `Err(_)` arm alone leaves the corpus byte-identical at 576794 bytes with all five
    // notices and 0 failed rules, and moves 19 clause verdicts instead. `Unanswerable`'s own doc in
    // `operators.rs` carries both figures and why neither route is open to a diagnostic fix.
    //
    // The caller's fold is respected rather than preempted, which is the second thing `match_all` is read
    // for here, and both quantifiers have a value that decides the clause without the undecided ones.
    // `undecided_gate` holds the table and says which arm answers what.
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
    // The role is deliberately not consulted. A previous revision asked it instead of the verdict, on
    // the reading that `ClauseRole` carries whether the file reports the clause, so a failing `Gate`
    // could be noticed as an absorbed failure. `ClauseRole`'s own documentation says what it answers --
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
/// # Why the `some` arm borrows and the `match_all` arm does not
///
/// The `some` arm is [`clause_passed`]'s own, called rather than reimplemented: "did any value pass" is
/// the same predicate over the same vector for both of us, and two copies that agree are the setup for
/// the next divergence.
///
/// The `match_all` arm cannot borrow from it, and that is a difference of question rather than of
/// answer. [`clause_passed`] asks "did this clause pass", which decides eligibility for a notice about a
/// future release; under `match_all` that is every-value-passed. This asks "is this clause still
/// undecided", whose `match_all` answer turns on a decided *failure* -- a question about the FAILs, not
/// the PASSes, and one the status vector cannot answer at all without [`ResultEvidence`]. Unifying them
/// would have to pick one meaning for `match_all` and would hand the other caller the wrong one.
///
/// # Disjoint from the notice
///
/// By construction rather than by ordering, under both readings. This fires only when `undecided` is
/// `Some`, and the arm that sets it pushes a `Status::FAIL` for that value. Under `match_all` the notice
/// needs every value PASS, which that FAIL denies. Under `some` the notice needs one PASS, and this
/// declines outright when there is one. So no result satisfies both, and the early return can never
/// suppress a notice that would otherwise have gone out.
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

    if role.is_strict() {
        return None;
    }

    // `some` is decided by any value that passed, so an undecided sibling changes nothing.
    if !match_all && clause_passed(result, false) {
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
/// "<clause> passed" -- and the clause is what the coming fail-closed change will or will not move. How
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
/// So the two readings are not interchangeable. This one used to carry a cost as well, and it does not any
/// more: it let `some` reach the whole-value false-alarm class the predicate then had, where a list is
/// incomparable entire while its elements are not, so `some Resources.*.Properties.Ports NOT IN [1, 3]`
/// over `[1, 2]` and `[7, 8]` warned on a clause every pair of which was int against int. That noise came
/// from the predicate's granularity rather than from this reading of the verdict, and it went with the
/// alignment fix -- `a_some_clause_one_value_of_which_fails` is that clause, now expecting silence, and
/// `a_some_clause_that_passes_on_a_refusal` beside it is the shape this reading exists for.
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
pub(super) fn real_binary_operation<'value, 'loc: 'value>(
    lhs: &[QueryResult],
    rhs: &[QueryResult],
    cmp: MapKeyComparator,
    context: String,
    custom_message: Option<String>,
    eval_context: &mut dyn EvalContext<'value, 'loc>,
) -> Result<EvaluationResult> {
    let mut statues: Vec<(QueryResult, Status)> = Vec::with_capacity(lhs.len());
    // The first key comparison that had no answer, if any had none. See the return below.
    let mut undecided: Option<String> = None;

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

                // Read before the fold consumes `r`. A key whose comparison had no answer becomes a
                // `Status::FAIL` like a key that plainly did not match, and one level up that means
                // "not selected" -- so the selection silently shrinks by a key nobody decided about,
                // and an assertion over the smaller selection can pass.
                if undecided.is_none() {
                    undecided = r.iter().find_map(|each| match each {
                        ComparisonResult::NotComparable(nc)
                            if nc.cause == operators::Unanswerable::EngineGaveUp =>
                        {
                            Some(nc.reason.clone())
                        }
                        _ => None,
                    });
                }

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

    // A selection nobody could decide fails the clause closed rather than selecting a subset.
    //
    // `undecided_gate` is the sibling of this, and the differences are why this is written out rather
    // than calling it. There is no `role` to split on: `real_binary_operation`'s only caller is the
    // `[ keys <op> ... ]` filter in `eval_context.rs`, and a filter predicate is always a gate, so the
    // fail-closed direction is the only one available. And there is no decided-failure mirror, because
    // a key that plainly does not match decides nothing about the selection -- it is simply not in it,
    // which is the ordinary case rather than an answer about the whole filter.
    //
    // Known cost, and it is a cost rather than an oversight: `Cfg[ keys == /re/ ] !empty` over a key the
    // pattern decidedly matches BESIDE an undecided key reports a failure, where three-valued logic
    // would answer yes on the strength of the matching key. Telling those apart needs the enclosing
    // operator, which this function is not given -- non-emptiness is decided there while membership is
    // not, and only the caller knows which of the two it asked about.
    //
    // The cost is the whole QUERY and not the one map, which is wider than this paragraph used to say.
    // `Err` here leaves `real_binary_operation` for every value the query selected, so a sibling map with
    // no undecided key in it is lost too. Measured with the release binary at `69628df7` on
    // `rule d { Resources.*.Cfg[ keys == /(?!x)((a+)+)b/ ] !empty }`, where `R1.Cfg` is `{<18 a's>: 1}` and
    // `R2.Cfg` is `{aaab: 2}`: exit 19 naming only `/Resources/R1/Cfg`, with `R2` absent from the report
    // entirely -- and `R2` alone over the same rule exits 0. So a PASS that the document contains does not
    // appear anywhere in the run. Same result with 30 a's, so it is not a threshold artifact.
    //
    // Nothing regresses even so, and that is measured rather than assumed for the wider shape as well:
    // at `b8d3901e` the two-resource document exited 255 with "Error executing regex: Max limit for
    // backtracking count exceeded" and named neither map, so `R2`'s PASS was not available there either.
    // 255 to 19 with one map named is strictly more than that run gave.
    match undecided {
        Some(reason) => Err(Error::UndecidableComparison(reason)),
        None => Ok(EvaluationResult::QueryValueResult(statues)),
    }
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
            &gac.access_clause.location,
            all,
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
                        resolver.record_deprecation(vacuous_comparison_notice(
                            &blk_context,
                            &gac.access_clause.location,
                        ));
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
