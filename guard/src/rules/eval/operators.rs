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
    /// The left-hand values that collide with nothing on the right.
    ///
    /// A separate field because `diff` answers "what should the report name" and this answers "which
    /// left-hand values found nothing", and the two part company for two unrelated reasons: under
    /// [`DiffFrom::Rhs`] the diff holds right-hand values instead, and under
    /// [`QueryIn::partly_matched`] a left-hand list is in the diff because `IN` rejected it and out of
    /// this set because the right-hand side names one of its elements. Equal to `diff` everywhere else,
    /// which is [`QueryIn::new`] and so every remaining `IN` spelling and most of `==`. The negation
    /// wrapper needs the second question and only ever had the first.
    ///
    /// "Collide" rather than "found no equal", which is what this said while `partly_matched` did not
    /// exist: a list-valued left-hand side with one element named on the right has no equal there and
    /// collides with it anyway, and `NOT IN` has to deny it.
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

    /// `IN` between two queries, where the values the report should name and the values that collide
    /// with the right-hand side are not the same set.
    ///
    /// A list-valued left-hand side only *partly* present in a right-hand one is in both: it is outside
    /// `IN`, so the report names it, and it is outside `NOT IN` as well, because the right-hand side
    /// names one of its elements. `collides` is the left-hand values in that position, and it is removed
    /// from `lhs_unmatched` rather than from `diff`, which is what keeps the two answers apart --
    /// `Pair NOT IN Deny` must deny a `Pair` of `[1, 2]` against a `Deny` of `[1, 3]`, and
    /// `Pair IN Deny` must still fail and still name `/Pair` when it does.
    ///
    /// `diff_from` stays [`DiffFrom::Lhs`]: the diff is left-hand values either way, so the reporter
    /// prints the right-hand operand as what they were compared with, exactly as for [`QueryIn::new`].
    /// Only the negation wrapper reads `lhs_unmatched`, so nothing else can see the difference.
    fn partly_matched(
        diff: Vec<Rc<PathAwareValue>>,
        collides: Vec<Rc<PathAwareValue>>,
        lhs: Vec<Rc<PathAwareValue>>,
        rhs: Vec<Rc<PathAwareValue>>,
    ) -> QueryIn {
        QueryIn {
            lhs,
            rhs,
            lhs_unmatched: reverse_diff(collides, &diff),
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

/// The elements of a [`ListIn`]'s left-hand list that the right-hand side did match.
///
/// `ListIn::diff` holds the elements that found nothing, so this is its complement, and it is the set
/// `NOT IN` reports: those are the values that collide with the denylist. Empty exactly when nothing
/// collided, which is both the verdict the negation wrapper needs and the question
/// `InOperation`'s two-query arm asks about a partly-present left-hand list. One function rather than
/// two loops, so the two spellings of `NOT IN` cannot disagree about what counts as a collision --
/// disagreeing about that is what let `Pair NOT IN Deny` admit a `Pair` the written-out denylist denied.
///
/// An empty result means nothing collided, and for every left-hand list that reaches here that is now the
/// opposite of an empty `diff` rather than the same thing. The one input where both were empty was a
/// left-hand list with no elements, and it no longer arrives: `contained_in` answers Success for an empty
/// left-hand list in both of its branches, because the element-wise diff comes out empty and the subset
/// reading holds vacuously, and the two call sites below match on `Fail` only. `Empty NOT IN [[9]]` used
/// to be answered here, which is why it passed; it is decided before the negation wrapper now, and fails.
fn matched_elements(lin: &ListIn) -> Vec<Rc<PathAwareValue>> {
    let elements = match &*lin.lhs {
        PathAwareValue::List((_, elements)) => elements,
        // `ListIn` is constructed only by `contained_in`'s list-valued left-hand arm.
        _ => unreachable!(),
    };

    elements
        .iter()
        .map(|each| Rc::new(each.clone()))
        .filter(|each| !lin.diff.contains(each))
        .collect()
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
    /// Why there was no answer, which is not recoverable from `reason`.
    pub(crate) cause: Unanswerable,
    pub(crate) pair: LhsRhsPair,
}

/// Why a comparison had no answer.
///
/// Both kinds record `NotComparable` and both fail a clause closed, so for a long time nothing needed
/// to tell them apart. `binary_operation` does: it turns an undecidable *gate* into an error so the
/// rule fails closed instead of being skipped, and only one of these two may be treated that way.
///
/// [`Unanswerable::IncomparableKinds`] must not be, and the reason is a load-bearing idiom rather than
/// caution. Rule authors write a value against both spellings it might carry -- the registry's
/// `ScanOnPush == 'False' OR ScanOnPush == false` is the canonical shape -- and rely on the pairing
/// that does not apply answering "no" rather than "unknown". Reading it as unknown makes
/// `ECR_REPO_SCAN_ON_PUSH` fail on a compliant template; measured, 143 rules across the pinned
/// aws-guard-rules-registry corpus move that way, most of them suppression tests expecting SKIP.
/// `docs/KNOWN_ISSUES.md` already tracks that suppression as a defect whose repair needs those rules
/// changed first, and this keeps that boundary exactly where it was.
///
/// WHICH PATH THAT FIGURE COVERS, because three comments cite it beside a decision about a different
/// one. The 143 is the cost of reading `IncomparableKinds` as an undecidable GATE, which is why
/// `ScanOnPush == 'False' OR ScanOnPush == false` is its canonical shape: an `==` clause, answered by
/// `EqOperation`. It is not the cost of promoting the membership refusal, and `EqOperation` reaches none
/// of the membership machinery: its impl references neither `is_one_of`, `contained_in`,
/// `elements_not_matched` nor `substring_or_contained_in`.
///
/// THE DISCARD IS THREE ARMS, NOT ONE. An earlier revision of this paragraph called `is_one_of` "the
/// only place a kind mismatch is discarded on the `IN` path", which is false, and it reached for a
/// stronger premise than its conclusion needed: reachability is what makes `EqOperation` irrelevant, and
/// uniqueness got assumed on the way there. Three code-level `Err(_) => {}` arms sit on this path, each
/// directly below an `Err(err @ Error::RegexError(_))` arm and therefore receiving `NotComparable` and
/// nothing else -- `is_one_of`'s at `:810`, `contained_in`'s whole-list loop at `:1071`, and
/// `contained_in`'s scalar arm at `:1182`. Counting the `(None, None)` arm's dropped result, which is not
/// an `Err(_) => {}`, there are four suppressions, which is what `eval.rs:327-329` and
/// `eval_tests.rs:12199-12200` have said all along. The sibling comment at `:761-765` in this file says
/// "Two sites, one reading" about two of them, so this file already contradicted itself one screen down.
///
/// Measured at `1ba4648d` by promoting `is_one_of`'s arm and nothing else: the pinned
/// aws-guard-rules-registry corpus comes back byte-identical, 576794 bytes of stdout, all five
/// DEPRECATION lines present and 0 failed rules. Re-confirmed at `1b81431c` with that arm promoted and
/// the release binary rebuilt -- stdout byte-identical at 576794, stderr byte-identical at 4597, five
/// DEPRECATION lines, corpus rc=0 -- so the result transfers, nothing between the two commits touching
/// the comparison path. Said explicitly because the two figures were measured at different commits and a
/// reader would otherwise assume one run. The membership promotion is registry-free, and a reader who
/// takes the 143 as covering it will believe the opposite.
///
/// THAT BYTE COUNT IS INVOCATION-SENSITIVE, so it is a fingerprint only beside the invocation that
/// produced it: `cfn-guard test -d rules --output-format json` from the corpus root, which is
/// `check-registry-corpus.sh`'s own shape. `test -d .` from inside `rules` gives 576030, the CI path
/// shape `test -d aws-guard-rules-registry/rules` gives 581569, and plain text instead of json gives
/// 291528. A byte-exact figure with no invocation attached is the same trap as a suite total with no
/// baseline SHA.
///
/// The five DEPRECATION lines are five sites carrying the SAME incomparable-membership message, on
/// stderr, at `secretsmanager_using_cmk.guard:41`,
/// `iam_user_login_profile_no_plaintext_password.guard:68`,
/// `kinesis_firehose_redshift_destination_configuration_no_plaintext_password.guard:68`,
/// `kinesis_firehose_splunk_destination_configuration_no_plaintext_password.guard:68` and
/// `amazon_mq_broker_users_no_plaintext_password.guard:69`. The count alone reads as five distinct
/// deprecations, which is a different fact.
///
/// WHAT EACH SITE COSTS, SEPARATELY, because a sequencing plan needs per-site prices and nothing in the
/// tree carried them. Distinct lib-target tests whose verdict or message moves when each site is
/// promoted -- the three `Err(_) => {}` arms to the form `:768-769` documents, the fourth through the
/// channel named below, baseline 1414 passed:
///
/// ```text
/// promoted                              tests moved
/// is_one_of (:810)                               27
/// whole-list loop (:1071)                         8
/// scalar loop (:1182)                             3
/// (None, None) dropped result (:1691)            18
/// ```
///
/// THESE PRICES MAY NOT BE SUMMED. That sentence is the one that matters here, because summing them is
/// the mistake this paragraph was written to correct. Measured combinations against what the individual
/// sets predict:
///
/// ```text
/// combination                    predicted   actual   interaction
/// the three Err(_) sites                33       33             0
/// dropped result + whole-list            26       29            +3
/// dropped result + is_one_of             43       59           +16
/// dropped result + scalar                21       67           +46
/// all four                               49      111   +65, less 3 masked
/// ```
///
/// The union of the four single-site sets is 49; the all-four run is 111, and `49 + 65 - 3 = 111` closes
/// exactly. The three `Err(_) => {}` sites ARE additive among themselves at 33, with empty symmetric
/// difference against the union and inclusion-exclusion closing at 27 + 8 + 3 - 5 = 33 on pairwise
/// overlaps of 5, 0 and 0. That part is reproducible: a second promotion harness produced a byte-identical
/// three-site failing set.
///
/// WHY IT BREAKS, which is `:1182` and `:1691` being in SERIES rather than parallel. `contained_in`'s
/// scalar arm ends at `:1186-1203` with `match (found, unanswerable)`: `(true, _)` gives
/// `Success(ValueIn)`, `(false, Some(reason))` gives `not_comparable_because(..)`, and `(false, None)`
/// gives `Fail(Compare::ValueIn)`. Promoting `:1182` sets `unanswerable`, which flips `(false, None)` into
/// `(false, Some(reason))` -- a pairing that returned `Fail(ValueIn)` now returns a `NotComparable`. In the
/// `(None, None)` arm's `match contained_in(..)`, `Fail(ValueIn)` and `NotComparable` both fell into
/// `_ => {}`; with `:1691` promoted the second is recorded. So `:1182` MANUFACTURES the inputs `:1691` acts
/// on, and that is the whole of the +46.
///
/// THE RULE, stated because a bare "these are additive" invites extension to a site where it fails, which
/// is exactly how the wrong figure got here: disjoint individual effects do not imply independence.
/// `dropped result` and `scalar` have an empty intersection as single-site sets and their combination
/// still moves 46 more tests than the sum. Additivity held across the three `Err(_)` sites because all
/// three feed the SAME consumer; it broke the moment a site was added that consumes what another produces.
///
/// The fourth site is `_ => {}` and not an `Err(_) => {}`, so it is not reachable by the promotion form
/// the other three take. It was promoted through the channel the arm already uses for `is_one_of`'s
/// `Membership::Unanswerable` at `:1861-1866`, carrying the refusal's own `reason` and `cause` rather than
/// re-deriving either.
///
/// Three tests move under a single promotion and are GREEN under all four, which is the signature of a
/// verdict moved one way by one promotion and back by another:
/// `a_denylist_named_by_a_variable_denies_what_the_same_list_written_out_denies::case_05_query_bound_nested_element_collision`,
/// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names::case_68_denied_by_a_nested_element_collision_via_query`
/// and `which_spelling_of_a_queried_denylist_reaches_which_arm::case_17_nested_entry_denied_unexpanded`.
/// All three are element-collision cells.
///
/// FOR SEQUENCING, the consequence is that a plan needs the combination measured at each step it actually
/// intends to take, not a per-site price picked off the first table. `dropped result` then `scalar` and
/// `scalar` then `dropped result` are the two worth pricing, because the series direction is what decides
/// which order is cheap. The six the whole-list and scalar arms reach and
/// `is_one_of` does not are `the_notice_asks_about_every_granularity_the_operator_decides_at`'s
/// `case_01_a_whole_value_pair_only_a_nested_denylist_builds`,
/// `case_02_the_same_whole_value_pair_at_length_two` and
/// `case_03_a_whole_value_pair_that_zips_onto_a_regex`, plus
/// `the_notice_fires_exactly_where_fail_closed_moves_the_answer::case_1_a_clause_that_passes_on_the_incomparability`,
/// `every_operator_and_operand_shape_agrees_with_a_stated_oracle` and
/// `generated_rule_shapes_hold_the_evaluator_invariants`.
///
/// Three limits on those figures, stated rather than left to be discovered. The denominator is distinct
/// lib-target tests and NOT clauses of the 676-clause sweep, so 27 does not convert to 19 and no
/// converted figure appears here -- the ratio would suggest something near 23 of 676, which is
/// extrapolation across populations. `cargo test` stops after the first failing target, so each run
/// reported one target rather than sixteen. And 33 is the three `Err(_)` sites only: the fourth
/// suppression is measured above at 18 alone and 111 in combination, and it is the site that makes the
/// three-site additivity non-extensible.
///
/// WHAT `is_one_of` ALONE COSTS AT CLI LEVEL. 19 clauses of a 676-clause sweep of the membership
/// shapes move from exit 0 to exit 19: `Pair NOT IN Ubool`, `Ports NOT IN Umap`, `Nest NOT IN D13[*]`,
/// `AbList[*] NOT IN Uint`, `Deep NOT IN Umap`, `some AbList[*] NOT IN D13[*]` and thirteen more. Each
/// is a clause that passed on a refusal and now fails closed, which is the answer `docs/CLAUSES.md`
/// gives for a comparison across kinds that are not both numeric, so the 19 move toward correctness
/// rather than away. They are verdict changes even so, and they are what promoting THAT ONE ARM has to
/// be argued against -- not the registry, which does not move, and not the other two arms, whose price
/// is the table above. This prose used to read as though 19 priced the whole membership fail-closed
/// change. It prices one arm of it, and a lower bound presented as a total misprices the deferral that
/// this paragraph is the basis for.
///
/// Neither that sweep's clause list nor the 54 cited below is committed, so treat both numbers as notes
/// on what was run; the reproducible half of each claim is the argument beside it. That is the convention
/// `:1987-1989` already applies to the 140-clause grid, and it holds here for the same reason.
///
/// AND WHY NEITHER ROUTE IS AVAILABLE TO A DIAGNOSTIC FIX, which is a stronger statement than
/// "deferred" and is measured rather than argued. `incomparable_membership` exists because the notice
/// has to know that a pairing refused while the clause still passed, and the result the operator
/// returns cannot say that, for 287 of the 291 notice-emitting clause evaluations in the suite.
/// Instrumented immediately after `cmp.compare`: 287 carry zero `NotComparable` results and FOUR carry
/// one or more. An earlier revision of this line claimed all of them did, "literal-right-hand shapes
/// included", and that universal is false -- both exceptions are literal-right-hand shapes, which is the
/// case it singled out as covered.
///
/// The four are two distinct clauses appearing once per build target, both `some`-quantified:
/// `some Multi.*.V NOT IN [/(?!x)((a+)+)b/]` at `eval_tests.rs:12831` and
/// `some WithNonString[*] NOT IN "abc"` at `eval_tests.rs:11463`. The second is the sharpest instance of
/// the tree refuting its own comment: that case is spelled
/// `#[case::a_refusing_element_under_a_literal_operand(.., true)]`, and the trailing `true` is the
/// notice-expectation flag, so a committed test asserts the notice fires for a shape this paragraph said
/// could not happen.
///
/// `some` is the whole mechanism, which is why it is exactly these. `eval.rs` reads the gate under the
/// query's own `match_all` -- `clause_passed(&outcome, match_all)` -- because "did this clause pass" means
/// one value for `some` and every value otherwise. Under `some`, one passing value carries the clause
/// while a sibling value's comparison sits in `NotComparable`, so the predicate fires, the clause passes,
/// the notice goes out, and the operator's result set still holds the refusal. Under `all` the refusing
/// value sinks the clause, `clause_passed` is false, and nothing is emitted. That is the 287.
///
/// THE CONCLUSION GETS STRONGER, not weaker, which is why this is a repair rather than a deletion. A
/// result-reading implementation would work for precisely the two `some` shapes and be blind for the
/// other 287 -- a partial-coverage trap rather than a clean impossibility, and worse to ship, because it
/// appears to work on whichever shapes someone happens to test. The `NOT THE BUILT PAIR SET ITSELF` note
/// on `membership_stops_after` below depends on this, and 287 of 291 supports it better than a universal
/// that does not hold. Cited by name rather than by line, because a line number in a comment is a
/// citation that the next insertion silently invalidates.
///
/// The registry half stands as written: the pinned corpus is clean, 25 notice-emitting evaluations across
/// its 5 clause sites, every one with zero `NotComparable`. It is the generalization beyond the registry
/// that was wrong.
///
/// Provenance, because these figures are a corrected recount and the first pass was believable. It
/// reported 58 notice-emitting evaluations and 2 candidates with `NotComparable` > 0, both undercounts:
/// libtest writes `test <name> ... ` to stdout with no trailing newline, so under `2>&1` the first
/// `eprintln!` of each test is glued onto that partial line and a `^INSTR_` line anchor misses it. The
/// tell was arithmetic rather than semantic -- two probe sites with an identical guard on the identical
/// `usize` reported 0 and 52, which cannot both be right. Unanchored, both read 52. The figures here are
/// the unanchored recount.
///
/// The positive control is what makes "287 carry zero" a measurement rather than a dead counter: a variant
/// printing for every clause found 712 of 11084 evaluations carrying `NotComparable` > 0, firing on the
/// expected kind mismatches. That 712 came from the ANCHORED run, so it is a floor rather than an exact
/// count and nothing should rest on its value; recording it without that caveat would reintroduce the
/// class of error this paragraph is fixing.
///
/// Carrying it needs one of two things. Promoting the refusal is the route above:
/// 19 verdicts, and it is the `docs/KNOWN_ISSUES.md` change gated on those registry rules. Carrying it
/// WITHOUT changing a verdict needs a state meaning "no match, something refused, and do not fail
/// closed" -- a fourth `Membership` variant threaded through `Compare`, `ComparisonResult`,
/// `ValueEvalResult` and `QueryIn`/`ListIn`, 167 non-test sites at this commit -- and that state is
/// exactly the "refused but passing" distinction this enum was split to keep out of the result type. So
/// the separate predicate is not an accident a tidier design removes. It is the mechanism by which the
/// result type stays free of that distinction, the drift risk it carries is a cost of that choice, and
/// `membership_stops_after` calling the arm's own functions is the mitigation for the risk rather than
/// a workaround for a missing refactor.
///
/// [`Unanswerable::EngineGaveUp`] has no such constituency. The operands were of kinds the comparator
/// has an arm for and the engine quit part way, so no rule can be relying on the answer -- there is no
/// answer to rely on, and the same clause decides differently as the subject gets longer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unanswerable {
    /// The operands are of kinds the comparator has no arm for, so it refused before comparing.
    IncomparableKinds,
    /// The operands were comparable and the evaluation was abandoned -- today, `fancy_regex`
    /// exhausting its backtracking budget.
    EngineGaveUp,
}

/// A reason with the cause that produced it, so the two cannot drift apart.
///
/// Paired rather than passed separately because the reason travels a long way from where the error was
/// seen: through `is_one_of`, `elements_not_matched`, and two membership loops before anything builds a
/// [`NotComparable`]. Every one of those hops used to carry a bare `String`, so a site that wanted the
/// cause would have had to re-derive it from the wording -- which is a classifier that goes silently
/// wrong the first time a message is reworded.
#[derive(Clone, Debug)]
pub(crate) struct Unanswered {
    pub(crate) reason: String,
    pub(crate) cause: Unanswerable,
}

impl Unanswered {
    /// A refusal to compare two kinds, for the sites that build the wording themselves rather than
    /// receiving an `Error`.
    fn kinds(reason: String) -> Self {
        Unanswered {
            reason,
            cause: Unanswerable::IncomparableKinds,
        }
    }
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
/// Returns the cause beside the reason. Only this function sees the `Error`, so it is the one place
/// that can classify without guessing, and every reason reaching a [`NotComparable`] from an error
/// comes through here.
/// `pub(super)` so `each_lhs_compare` on the map-key path can classify with this one rather than
/// growing a second copy. That path used to propagate anything that was not `NotComparable`, which is
/// how a spent backtracking budget in `[ keys <op> ... ]` reached `main` and exited 255.
pub(super) fn unanswerable_reason(err: Error) -> Unanswered {
    match err {
        Error::NotComparable(reason) => Unanswered::kinds(reason),

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
        Error::RegexError(err) => Unanswered {
            reason: format!(
                "The regular expression could not be evaluated against the value: {err}"
            ),
            cause: Unanswerable::EngineGaveUp,
        },

        // Classified with the kind mismatches rather than given a third variant. Nothing reaches this
        // arm today -- the doc comment above enumerates the two that do -- and the conservative
        // reading is the one that leaves a gate's verdict where it already was.
        rest => Unanswered::kinds(format!("The comparison could not be performed: {rest}")),
    }
}

fn not_comparable_because(
    lhs: Rc<PathAwareValue>,
    rhs: Rc<PathAwareValue>,
    unanswered: Unanswered,
) -> ValueEvalResult {
    ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(NotComparable {
        reason: unanswered.reason,
        cause: unanswered.cause,
        pair: LhsRhsPair { lhs, rhs },
    }))
}

/// Which arm of a `compare` implementation a pair of operands reaches, as the operators ask it.
///
/// `pub(super)` for `incomparable_membership` in `eval.rs`, which has to know whether the `(None, None)`
/// arm of `InOperation::compare` is the one that will run: that arm drops a shape refusal where every
/// other arm reports it, and the difference decides whether a clause passes on the refusal or fails
/// closed on it. Shared rather than re-derived there, so the predicate and the dispatch cannot drift
/// apart -- the `len() == 1` half is easy to omit and would answer for a two-value query.
pub(super) fn is_literal(query_results: &[QueryResult]) -> Option<Rc<PathAwareValue>> {
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
/// Symmetric because the arm that first called it is. That arm reads `==` as equality of two operand
/// sets and folds in both directions so an extra value on either side is seen, so a one-sided unwrap
/// would leave the reverse pass unmatched and the clause still failing.
///
/// Every arm of `EqOperation::compare` asks this now, and originally two of them did not. A rule
/// literal that is a one-element list reaches `(Some, None)` or `(Some, Some)`, both of which compared
/// the list against the scalar whole and refused the pair: `%lit_other != Val` for a `Val` of `Name` and
/// a `lit_other` of `["Other"]` exited 19 reading "PathAwareValues are not comparable array, String",
/// two values that visibly differ, while `Val != %otherkey` -- the same question with the list arriving
/// from a query -- passed. Being asked from every arm is the point: this relates one pair of shapes, and
/// an arm that does not ask disagrees with the ones that do.
///
/// Two arms reach the same verdict without it, and asking anyway is harmless there. A literal scalar
/// against a query list, and a query list against a literal scalar, walk the list and compare element by
/// element, so a one-element list already answers as its element does. By the time this is called on
/// those paths both operands are scalars and it falls straight through.
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

/// How much of this left-hand value `IN` finds inside a string on the right.
///
/// Three answers, not two, and `Partial` is the one that has to exist. The `(None, Some)` arm applies
/// `string_in` once per left-hand element, expanding a list-valued one, so a list is really N separate
/// comparisons folded by ALL: `["s3","arn"] in "aws:arn:s3::${s3}"` holds, `["zz","qq"]` does not, and
/// `["s3","zzz"]` -- one element found, one not -- cannot satisfy ALL in *either* polarity and so fails
/// both. `(None, None)` compares a left-hand result whole and has one boolean per result, which can say
/// "in" or "not in" and had no way to say the third thing. So it answered the partial case as a plain
/// miss, and negating a miss passes: `["s3","zzz"] NOT IN Haystack` reported compliance while the
/// haystack verbatim contained `s3`, and its typed-out spelling failed.
///
/// Only a list can be partly found, so `Partial` and `HoldsANonString` both name a list. `NotAString`
/// is the sibling for everything this function does not decompose, and exists for the same reason as
/// `HoldsANonString`, which is recorded below.
///
/// `HoldsANonString` is separate from `Partial`, and the reason is a defect this function shipped with.
/// Containment cannot be asked of an element that is not a string, and the literal arm says so: it hands
/// each element to `string_in`, which answers "not comparable" for a non-string, and one such result
/// makes the ALL-fold fail in both polarities. The first version of this function had `found` return
/// `false` for a non-string, conflating "is a string and is not contained" with "cannot be asked", so a
/// list of nothing but non-strings counted zero hits and came out `NoneFound` -- a plain miss, which
/// negates to a pass. `[5, 6] NOT IN Haystack` reported compliance where its typed-out spelling failed.
///
/// `["s3", 5]` masked it. That list has a contained string, so it reached `Partial` and failed closed for
/// the right verdict by the wrong route, and the cell passed. A cell that passes for the wrong reason is
/// worse than one that fails, because it reads as coverage: it is why the grid now carries `[5, 6]` as
/// well, and why the non-string test comes *before* the hit count rather than after it.
///
/// Measured at three points before the fix, all FAIL under the literal spelling and PASS under the query
/// spelling, so this was never a regression from any of them: `258772a` (before substring `IN` reached a
/// query at all), `aae25d0` (which made it reach one), and `fe4ac73` (which added `Partial`).
///
/// The empty-list guard is `contained_in`'s, for the reason recorded there: an empty collection passing
/// a comparison is what `vacuous_comparison_notice` in `eval.rs` is deprecating, so this does not add
/// another one. Empty is `NoneFound` rather than unanswerable because it keeps its existing answer --
/// `NOT IN` over nothing passes -- and folding it in would change a cell this is not about.
///
/// A non-string, non-list left-hand value used to be left out, and the reason given for leaving it out
/// was checked against the wrong spelling. It read: `contained_in` already asks `compare_eq` for such a
/// value and gets "not comparable", so `%int in Haystack` and `%int not in Haystack` both fail already.
/// That is true, and it is true of the `(Some, None)` arm, which is where a literal needle goes:
/// `substring_or_contained_in` there falls through to `contained_in` per result and the incomparable
/// answer is the clause's answer. The `(None, None)` arm keeps one verdict for the whole left-hand
/// operand set and only treats `contained_in`'s *Success* as a match, so an incomparable pairing was
/// indistinguishable from a miss, joined the unmatched diff, and negated to a pass. With
/// `Haystack: "aws:arn:s3::${s3}"`, none of these denied anything, and the fourth is why the row above
/// no longer calls them scalars:
///
/// ```text
/// Int    5        not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Float  5.5      not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Bool   true     not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Map    {a: 1}   not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// Null   null     not in Haystack   PASS      not in "aws:arn:..."   FAIL
/// ```
///
/// Reporting that incomparable answer from the loop instead was tried and rejected. `contained_in`
/// answers "not comparable" for a *list* against a string too -- lists and strings are not comparable
/// types -- and containment has already decided that pairing, correctly, as a genuine miss. So the
/// blanket reading turns `NoneList not in Haystack`, every element a string and none present, from PASS
/// into FAIL. That is `undenied_wholly_absent_list_query_haystack`, kept as a control by the commit
/// that added `HoldsANonString`, and it fails under the blanket fix and passes under this one.
#[derive(Copy, Clone, PartialEq)]
enum StringContainment {
    /// Every element, or the scalar itself, is contained.
    All,
    /// Every element is a string; some are contained and some are not, so no single answer is right in
    /// either polarity.
    Partial,
    /// At least one element is not a string, so containment cannot be asked of it.
    HoldsANonString,
    /// The left-hand value is neither a string nor a list, so containment cannot be asked of it as a
    /// whole. Separate from `HoldsANonString` because the two complaints are about different things:
    /// that one is about elements this function tested one at a time, and this one is about a value it
    /// never decomposed, so a message naming elements would describe contents nothing looked at.
    ///
    /// The reason used to read "a scalar holds nothing", and a `Map` refutes it. Only `List` is
    /// decomposed here, so `Map` arrives at the same arm as `Null`, `Bool`, `Int`, `Float`, `Char`,
    /// `Regex` and the three range kinds, and `{"a": 1}` plainly holds something.
    /// `denied_map_query_needle_query_haystack` in
    /// `substring_in_answers_the_same_against_a_query_as_against_a_literal` is that cell. The message it
    /// produces was accurate all along -- `Value={"a":1} is not a string, so it cannot be tested for
    /// containment in ...`, at exit 19 -- and only the justification for it was wrong.
    NotAString,
    /// Every element is a string and none is contained, or the right-hand side is not a string at all.
    NoneFound,
}

fn found_in_string(lhs: &PathAwareValue, rhs: &PathAwareValue) -> StringContainment {
    let haystack = match rhs {
        PathAwareValue::String((_, haystack)) => haystack,
        _ => return StringContainment::NoneFound,
    };

    let contained = |value: &PathAwareValue| match value {
        PathAwareValue::String((_, needle)) => Some(haystack.contains(needle)),
        _ => None,
    };

    match lhs {
        PathAwareValue::List((_, elements)) => {
            if elements.is_empty() {
                return StringContainment::NoneFound;
            }

            // Before the hit count, not after it: a non-string element decides the answer however many
            // of its neighbours are contained.
            if elements.iter().any(|element| contained(element).is_none()) {
                return StringContainment::HoldsANonString;
            }

            match elements
                .iter()
                .filter(|element| contained(element).unwrap_or(false))
                .count()
            {
                0 => StringContainment::NoneFound,
                hits if hits == elements.len() => StringContainment::All,
                _ => StringContainment::Partial,
            }
        }

        // Bound as `not_a_list`, and it used to be bound as `scalar`: a `Map` arrives here, so the old
        // name described a subset of what the arm receives.
        not_a_list => match contained(not_a_list) {
            Some(true) => StringContainment::All,
            Some(false) => StringContainment::NoneFound,
            None => StringContainment::NotAString,
        },
    }
}

fn not_comparable(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> ValueEvalResult {
    ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(NotComparable {
        pair: LhsRhsPair {
            lhs: Rc::clone(&lhs),
            rhs: Rc::clone(&rhs),
        },
        reason: format!("Type not comparable, {}, {}", lhs, rhs),
        cause: Unanswerable::IncomparableKinds,
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

/// Whether one left-hand element is one of a right-hand list's elements.
///
/// `PartialEq` and then `compare_eq`, which is the idiom `d7f01ec` put in the scalar-left-hand arm of
/// `contained_in` and is here for the reason it gives there. `Vec::contains` decides membership with
/// `PartialEq` alone, `PartialEq` is asked `element == value`, and the range table is written the other
/// way round -- scalar on the left, range on the right -- and lives in `compare_eq`. So a list-valued
/// left-hand side could not have an element matched by a range written beside it: for `Ports` of `[85]`,
/// `Ports IN [r[80,90]]` failed and `Ports NOT IN [r[80,90]]` passed, a denylist of forbidden port
/// ranges admitting every port. The scalar spelling of the same question was right, because it reaches
/// `compare_eq`.
///
/// Asking both is not belt and braces, and it is not redundant either way round. `compare_eq` answers
/// everything `PartialEq` answers here -- two equal ranges, a string against a regex it matches, a
/// number across `Int` and `Float`, a `Char` against the one-character string that spells it, and two
/// collections structurally -- and adds exactly `compare_eq`'s five range-membership arms. So this can
/// only add a match, never remove one, and `PartialEq` stays first because it short circuits on the
/// common case and costs one comparison on a path that runs one anyway.
///
/// `NotComparable` is swallowed and `RegexError` is promoted, which is the split the scalar arm of
/// `contained_in` already makes at its own membership loop. `Err` here is `NotComparable` in every
/// reachable case but one, it arrives constantly, and swallowing it is the point: a pair that cannot be
/// compared is not a match, so the element belongs in the diff below rather than aborting the clause.
/// `compare_eq`'s `(_, _)` fall-through asks `compare_values`, whose own `(_, _)` refuses any pairing of
/// kinds it has no arm for, and a denylist written beside values of another kind is ordinary rather than
/// exotic.
///
/// Measured at 9bcf2053 on rustc 1.77.2, by replacing the `Err(_) => {}` arm below with
/// `Err(e) => panic!("{:?}", e)` and running `cargo test --lib`: 85 of the 1220 lib tests redden, one
/// recorded error each, and all 85 are `NotComparable` from that fall-through. So this is not an
/// unreachable arm kept for safety.
///
/// Read that figure as a census of the test corpus on a dated commit, because that is what it is. It read
/// 58 when it was written, and 40 of today's 85 are cells of
/// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names` with 15 more from
/// `which_spelling_of_a_queried_denylist_reaches_which_arm` -- both grown by later commits on the same
/// branch that wrote the 58. A five-way breakdown by type pair used to sit here and is not reproduced,
/// because nothing acts on it and every figure in it moved. What does not drift is the KIND: this arm
/// receives `NotComparable` and nothing else, since the `RegexError` arm above it takes the only other
/// error that can arrive. Re-run the probe rather than trusting the number. Over the whole suite it
/// reports 170, the lib and bin targets each compiling this module and every reaching cell existing in
/// both.
///
/// The sibling scalar arm below swallows the same error through its own
/// `Err(_) => {}`, for the reason written out there: `NOT IN` against an operand of a kind it cannot be
/// compared with currently passes, `docs/KNOWN_ISSUES.md` records that suppression as a tracked defect,
/// and `incomparable_membership` in `eval.rs` warns rule authors before it changes. Two sites, one
/// reading.
///
/// Two probes, two questions, and the 85 above answers only the first: a panic reddens every test that
/// *reaches* the line. Replacing the same arm with
/// `Err(e) => { if unanswerable.is_none() { unanswerable = Some(unanswerable_reason(e)); } }` instead
/// reddens only the tests whose *verdict or message moves*, which at 9bcf2053 is 16 under
/// `cargo test --lib` and 32 over the whole suite. So 85 execute this arm, 16 depend on what it returns,
/// and the 69 in between run the line without caring: they find a match on another element, or their
/// verdict is already decided. A reader who reaches for the promotion probe and gets the smaller figure
/// has measured the second question, not contradicted the first.
///
/// Both are censuses on a dated commit and both drift upward together -- they read 58 and 11 when this
/// paragraph was written -- so the durable claim is the gap between them and not either figure. Restate
/// them only from a fresh run of the two probes named above.
///
/// The other two errors `compare_eq` can raise are not alike. A NaN against a numeric range cannot
/// arrive, for the reason `compare_eq`'s own note gives -- it enumerates the four `Float` construction
/// sites that gate a non-finite one. `RegexError` splits in two. A pattern that will not compile cannot
/// arrive, because `parse_regex_inner` answers `nom::Err::Failure` unless `Regex::try_from` accepted the
/// pattern first, and no data format has a regex spelling. A pattern that compiled and then exhausted
/// `fancy_regex`'s backtracking budget does arrive here, raised by `reg.is_match(s)` at the foot of
/// `compare_eq`: the same panic probe fires with `Vals IN [/(?!x)((a+)+)b/]` against a `Vals` holding one
/// thirty-character string of `a`s.
///
/// That one is promoted, and the direction is the codebase's own requirement rather than a preference for
/// two spellings agreeing. The scalar arm below states the requirement: a regex `compare_eq` could not
/// evaluate "is read rather than discarded, which is what makes `Port in [/re/]` answer the same way as
/// `Port == /re/`". This arm never honored it. For a `Size` of thirty `a` characters,
/// `Size NOT IN [/(?!x)((a+)+)b/]` exited 19 as a scalar and 0 as a list, so what the promotion changes
/// is the verdict -- and the claim it replaces, that promoting would change "the shape of the `ListIn`
/// diff for no input that exists", was wrong about the input and about what moves.
fn is_one_of(each: &PathAwareValue, rhsl: &[PathAwareValue]) -> Membership {
    let mut unanswerable: Option<Unanswered> = None;
    for elem in rhsl {
        if elem == each {
            return Membership::Matched;
        }
        match compare_eq(each, elem) {
            Ok(true) => return Membership::Matched,
            Ok(false) => {}
            Err(err @ Error::RegexError(_)) => {
                if unanswerable.is_none() {
                    unanswerable = Some(unanswerable_reason(err));
                }
            }
            Err(_) => {}
        }
    }

    match unanswerable {
        Some(unanswered) => Membership::Unanswerable(unanswered),
        None => Membership::NoMatch,
    }
}

/// What a right-hand list says about one left-hand element.
///
/// Three answers because `compare_eq` has three outcomes, and folding the middle one into
/// [`Membership::NoMatch`] is what let a denylist admit a value. `Matched` outranks
/// `Unanswerable` inside [`is_one_of`] rather than at its callers: once an element matches, the
/// answer did not depend on the comparison that failed, so there is nothing left to report.
enum Membership {
    /// Some right-hand element matched.
    Matched,
    /// No right-hand element matched, and every comparison had an answer.
    NoMatch,
    /// No right-hand element matched, and at least one comparison had no answer.
    ///
    /// Carries the first reason rather than all of them, which is what the scalar arm reports and
    /// what a clause naming one pattern needs.
    ///
    /// Always [`Unanswerable::EngineGaveUp`] as things stand: [`is_one_of`] promotes only
    /// `RegexError` and discards a kind mismatch. The cause is carried rather than assumed at the
    /// consuming sites so that widening what gets promoted cannot silently reclassify a gate.
    Unanswerable(Unanswered),
}

/// The left-hand elements that no right-hand element matched, and the first reason one of them could
/// not be decided.
///
/// Both branches below need this pair, and both used to build the diff with the same four lines. The
/// reason travels with the diff because it is only about elements that landed in it: an element that
/// matched is decided, so a pattern that failed against it changes no verdict.
fn elements_not_matched(
    lhsl: &[PathAwareValue],
    rhsl: &[PathAwareValue],
) -> (Vec<Rc<PathAwareValue>>, Option<Unanswered>) {
    let mut diff = Vec::new();
    let mut unanswerable: Option<Unanswered> = None;

    for each in lhsl {
        match is_one_of(each, rhsl) {
            Membership::Matched => {}
            Membership::NoMatch => diff.push(Rc::new(each.clone())),
            Membership::Unanswerable(unanswered) => {
                if unanswerable.is_none() {
                    unanswerable = Some(unanswered);
                }
                diff.push(Rc::new(each.clone()));
            }
        }
    }

    (diff, unanswerable)
}

fn contained_in(lhs_value: Rc<PathAwareValue>, rhs_value: Rc<PathAwareValue>) -> ValueEvalResult {
    match &*lhs_value {
        PathAwareValue::List((_, lhsl)) => match &*rhs_value {
            PathAwareValue::List((_, rhsl)) => {
                // A list-valued left-hand side is IN a right-hand list if the whole list is one of
                // its elements, or if the left-hand side is non-empty and every left-hand element is
                // one of its elements.
                //
                // Two readings, and each right-hand element decides for itself which one it can
                // answer. Membership -- "the whole left-hand list is one of these elements" -- is what
                // `Resources IN [["a","b"], ["c","d"]]` means, and only a nested list can satisfy it.
                // Subset -- "every left-hand element is one of these" -- is what
                // `Actions IN ["s3:Get", "s3:Put"]` means. Nothing about one element changes what
                // another element answers.
                //
                // The subset test asks nothing about the depth of the element that matches, and it
                // used to require a non-list one. That requirement made two spellings of the same
                // question disagree with each other: for a `Nest` of `[1, [9]]`, `Nest IN [1, [9]]`
                // failed because `[9]` could not match the `[9]` written beside it, and
                // `Nest NOT IN [1, [9]]` failed as well -- neither polarity would admit a pair of
                // operands where every element of the left is spelled out on the right. It also let
                // this branch report a failure with an empty diff, since the diff below is computed
                // with `Vec::contains`, which has no such requirement. Dropping it makes "every
                // element matched" and "the element-wise diff is empty" the same statement, which is
                // why `flat_subset` is now written in terms of `diff` rather than beside it.
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
                // in a list literal, by asking each element in turn. Same idiom here, in both readings:
                // `is_one_of` asks `compare_eq` as well as `PartialEq`, so a right-hand list holding a
                // range or a regex reaches the function that knows about them, and the whole-list
                // membership test asks `compare_eq` on the list itself for the same reason.
                //
                // The two swallow different populations, and the count from one says nothing about the
                // other. Measured at 9bcf2053 on rustc 1.77.2 by replacing both `Err` arms below with
                // `Err(e) => panic!("{:?}", e)`, leaving the `flat_subset` short circuit in place, and
                // running `cargo test --lib`: 19 tests reach it, 17 carrying `NotComparable` and 2
                // carrying `RegexError`. The sibling inside `is_one_of` reaches 85, all `NotComparable`,
                // so a reader carrying that figure across to this line would be describing a different
                // set.
                //
                // Both are censuses of the test corpus at a commit, and this one is the shorter-lived of
                // the pair: it read 18 when it was written at 158932b6 and measured 19 two commits later.
                // The arrival counts are what drift; the split by error kind is what the paragraphs below
                // actually use, and the 2 are named there so they can be checked without a probe.
                //
                // This corrects the measurement 2631880 recorded here, which read "fires for none,
                // anywhere in the lib suite". That was taken without distinguishing the two error
                // kinds and is wrong about `NotComparable`: the cells counted above drove one through this
                // line before this branch was touched, which is why promoting `RegexError` alone moves no
                // cell of theirs. Whether that population is 16 or 17 changes nothing in the argument, so
                // no figure is repeated here. What was true, and is the half worth keeping, is that the
                // `RegexError` path here had no coverage. The 2 cells above are the first, and naming them
                // is what makes that figure checkable without re-running a probe:
                // `a_denylist_refuses_a_value_it_could_not_evaluate_in_either_spelling`'s
                // `case_5_list_in_a_nested_list` and `case_6_list_not_in_a_nested_list`. Before them
                // nothing in the suite had ever driven a regex failure through this comparison.
                //
                // The subset test used to stay on `PartialEq`, to match the all-flat branch below. That
                // matched the branch and left the same hole in it: a range beside a list-valued
                // left-hand side matched no element, so `Ports NOT IN [r[80,90]]` admitted a `Ports` of
                // `[85]` while `Port NOT IN [r[80,90]]` denied an 85. Both readings ask `is_one_of` now,
                // so the two agree at the level the scalar arm already worked at rather than at the one
                // neither of them did.
                //
                // Gating subset on the RIGHT-hand side holding no list was tried and rejected. It is
                // order-independent, so it closes the defect, but it keeps the shape of what caused
                // it: one nested element would suppress the subset reading for every flat element
                // beside it, so adding `[9]` to `IN [1, 2]` stopped `1` and `2` matching, with no
                // diagnostic and nothing wrong with the clause.
                //
                // The diff on failure is the unmatched ELEMENTS, which is what the flat branch below
                // reports and what the negation wrapper reads. That wrapper takes the elements of
                // `lin.lhs` and keeps the ones absent from `lin.diff`, calling those the values that
                // collide with the denylist. Reporting the whole left-hand list as a single diff
                // element -- which is what this branch did -- matches no element of itself, so every
                // element read as colliding and `NOT IN` failed for every left-hand value whenever
                // the denylist held any nested list: `Pair NOT IN [[99,98]]`, two disjoint pairs,
                // exited 19. Populating it element-wise is the whole fix, and it must land with the
                // paragraph above: a failure whose diff is empty would report every element as
                // colliding again, for the same reason and by the same route.
                //
                // Negating the verdict was tried and rejected before this commit, and the measurement
                // is a reviewer's rather than this one's. A marker field mirroring `QueryIn::diff_from`
                // would let the wrapper flip a failed membership to Success without recomputing
                // anything, and it is smaller. It admits four values the denylist names, because "the
                // whole list is not a member" says nothing about the elements: for a `Nest` of
                // `[1, [9]]`, `Nest NOT IN [[9]]` reaches exit 0 under it, and so does
                // `Deep NOT IN [["a"]]` for a `Deep` of `[["a"]]`. Both are cells of
                // `a_list_denylist_holding_a_nested_list_denies_only_what_it_names`, which is where to
                // look before trying it again.
                //
                // An empty left-hand list reaches the subset reading here, the same as it does in the
                // branch below. It has no elements, so `diff` comes out empty and the subset reading
                // holds vacuously. An `is_empty` guard used to keep it out of that reading, on purpose,
                // to avoid adding a second vacuous pass. The guard is gone because what it bought was
                // not worth what it cost.
                //
                // What it cost was monotonicity, which is the property a denylist cannot trade away:
                // adding an entry must never turn a failing `NOT IN` into a passing one. The guard
                // applied in this branch only, and which branch a clause takes turns on whether the
                // denylist holds a list at all, so the empty case answered one way for a flat denylist
                // and the other way for the same denylist with one nested element added. On a document
                // where `Empty` is `[]`, `Empty NOT IN [1,2,3]` exited 19 and `Empty NOT IN [1,2,3,[9]]`
                // exited 0 -- one entry added, and a denylist that had denied the value admitted it. The
                // flip was position-independent, so `[[9],1,2,3]` and `[1,[9],3]` did it too.
                //
                // `05232a2`'s message says "`NOT IN` therefore only ever goes from Success to Fail,
                // never the other way." That is true of the mechanism that commit added and false of
                // this function as it stands, and it is corrected here rather than left to be read as a
                // guarantee about the branch: a reader who takes it that way concludes no lax flip can
                // exist and stops looking, which is how the empty-left-hand flip above survived review.
                // `contained_in` decides the `IN` verdict and the wrapper negates it, so a change that
                // moves a Fail to a Success turns a `NOT IN` failure into a pass, and a change in the
                // other direction does the opposite. Both are reachable from a one-token edit to the
                // condition below.
                //
                // The cost of removing the guard is that `[] IN <a denylist holding a list>` now passes,
                // which is a second vacuous pass rather than one fewer. Two alternatives were weighed.
                // Failing the empty case in both branches leaves no vacuous pass at all and is also
                // monotone, but it moves `[] IN [1,2,3]` from pass to fail -- behavior that predates the
                // nested-list work, and what an allowlist written as `x IN <list>` rests on. Keeping the
                // guard and special-casing the negation wrapper was rejected because the wrapper reads
                // this diff to decide which values collide, so a Fail carrying an empty diff has to keep
                // meaning no collision; the `_via_query` cells of
                // `a_list_denylist_holding_a_nested_list_denies_only_what_it_names` pin that.
                //
                // `vacuous_comparison_notice` in `eval.rs` covers neither pass, which is why this change
                // is silent before and after. That notice fires on `compared_nothing`, an operand query
                // that expanded to no values at all, and an empty list is one value that does get
                // compared. Measured rather than reasoned: `Empty NOT IN [1,2,3]` and
                // `Empty NOT IN [1,2,3,[9]]` each print nothing on stderr. So the guard was not holding
                // a line that notice was about to move.
                // The membership reading beside the subset one raises on its own, and it used to
                // swallow that too. `compare_eq` recurses through a pair of lists element by
                // element, so for a `Size` of `["aaa..."]` the pair `(Size, [/re/])` reaches
                // `compare_eq(String, Regex)` and raises from there. The element-wise pass above
                // never sees that pattern -- `compare_eq` has no `(String, List)` arm and falls
                // through to `compare_values`, whose catch-all refuses on the shapes before any regex
                // runs -- so this call site is the only one that can report it, and
                // `Size NOT IN [[/(?!x)((a+)+)b/]]` exited 0 while the unnested spelling exited 19.
                //
                // `if !flat_subset` is the short circuit the `flat_subset ||` expression this replaced
                // had for free, and it is kept deliberately rather than by habit. Without it the
                // membership comparison runs on every input that reaches this branch instead of only
                // the ones that need it: with the same panic probe named above, replacing this condition
                // with `if true` takes arrivals from 19 to 46 at 9bcf2053 under `cargo test --lib` (they
                // read 18 and 39 when this paragraph was written, and both endpoints drift with the
                // corpus). No verdict moves either way, because a true `flat_subset` decides the
                // clause before `unanswerable` is read, so the difference is work done and the
                // population any future probe here measures. It also keeps the vacuous case cheap:
                // with the `is_empty` guard gone, an empty left-hand list makes `flat_subset` true, so
                // it now skips the membership loop rather than walking a denylist it cannot match.
                if rhsl.iter().any(|elem| elem.is_list()) {
                    let (diff, mut unanswerable) = elements_not_matched(lhsl, rhsl);
                    // An open question is deliberately NOT answered here. `IN` for a list has two
                    // readings, and which one an empty left-hand side should get is unresolved
                    // upstream: under the subset reading every element of `[]` is in the denylist
                    // vacuously, so `NOT IN` fails, and under the membership reading `[]` is not one
                    // of the denylist's elements, so `NOT IN` passes. This tree has answered FAIL
                    // since before the nested-list work, and that answer is untouched by this line.
                    //
                    // What this line changed is only that the answer no longer depends on the shape
                    // of the denylist. Deciding the convention itself is a user-visible change to
                    // long-standing evaluation semantics in a policy tool, so it belongs to the
                    // maintainers and to its own change, not bundled into a regression fix.
                    //
                    // A change that does decide it PASSes has two cells to move, both in
                    // `a_list_denylist_holding_a_nested_list_denies_only_what_it_names`:
                    // `denied_empty_over_a_flat_list` from FAIL, and `in_empty_over_a_flat_list`
                    // from PASS, each with its `_via_query` twin. Those four are the convention and
                    // the rest of the empty-left-hand cells follow from it. An allowlist spelled
                    // `x IN <list>` is what the second one protects.
                    let flat_subset = diff.is_empty();

                    let mut whole_list_member = false;
                    if !flat_subset {
                        for elem in rhsl {
                            if elem == &*lhs_value {
                                whole_list_member = true;
                                break;
                            }
                            match compare_eq(&lhs_value, elem) {
                                Ok(true) => {
                                    whole_list_member = true;
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
                    }

                    // Either reading matching outranks a reason, for `Membership::Matched`'s reason:
                    // the verdict did not rest on the comparison that failed.
                    match (flat_subset || whole_list_member, unanswerable) {
                        (true, _) => ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                            Compare::ListIn(ListIn::new(vec![], lhs_value, rhs_value)),
                        )),

                        (false, Some(reason)) => {
                            not_comparable_because(lhs_value, rhs_value, reason)
                        }

                        (false, None) => ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                            Compare::ListIn(ListIn::new(diff, lhs_value, rhs_value)),
                        )),
                    }
                } else {
                    let (diff, unanswerable) = elements_not_matched(lhsl, rhsl);

                    // An empty diff cannot carry a reason: an element with no answer is put in the
                    // diff beside the ones that plainly did not match, so `(true, _)` is `(true,
                    // None)` and the wildcard states that rather than admitting a fourth case.
                    match (diff.is_empty(), unanswerable) {
                        (true, _) => ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                            Compare::ListIn(ListIn::new(diff, lhs_value, rhs_value)),
                        )),

                        (false, Some(reason)) => {
                            not_comparable_because(lhs_value, rhs_value, reason)
                        }

                        (false, None) => ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                            Compare::ListIn(ListIn::new(diff, lhs_value, rhs_value)),
                        )),
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
                    // A list against a value that is not one. `compare_eq` has no arm for the pair, so
                    // this is a refusal to compare kinds and not an abandoned evaluation -- which is
                    // what keeps `Cat NOT IN [/^a+$/]` on the side of the boundary it was already on.
                    cause: Unanswerable::IncomparableKinds,
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
                let mut unanswerable: Option<Unanswered> = None;
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

/// Whether `InOperation::compare`'s `(None, None)` arm stops pairing this left-hand value once it has
/// seen this right-hand one.
///
/// [`super::incomparable_membership`] walks the same cross product that arm walks, to count the
/// refusals a passing `NOT IN` clause passed on. The arm stops pairing a left-hand value the moment
/// one matches -- `continue 'each_lhs` at the string-containment and membership arms below, and at
/// the empty-left skip above them -- and the predicate had no such stop, so it kept pairing the value
/// against every LATER right-hand value and counted refusals from pairings the arm never built.
///
/// Measured at `d4286e68` over a 676-clause sweep of the mixed-left shapes: 54 clauses where the
/// predicate refuses on a pairing the arm short-circuited past. `MatchStr[*] NOT IN HayInt[*]` over
/// `{"MatchStr": ["ab"], "HayInt": ["xxabxx", 5]}` is the smallest -- `"ab"` is contained in
/// `"xxabxx"`, so the arm stops, and `("ab", 5)` is the predicate's pairing alone.
///
/// LATENT, AND REPAIRED ANYWAY. All 54 are suppressed by the verdict gate in `binary_operation`,
/// because a short-circuit IS a match and a matched value cannot be the value a passing `NOT IN`
/// clause passed on; every multi-value shape that could pass also builds its own refusal on the
/// sibling that reaches the refusing right-hand value. So no input reaches a false notice today. The
/// suppression lives in a different function from the divergence, though, so changing what either
/// short-circuit fires on -- or adding a third beside them -- makes it live with nothing in the tree
/// to flag it. `ee60bc5f` is the same shape one level up, and its own soundness argument was sound
/// about the population it had examined and silent about the one it had not.
///
/// BY CALLING THE ARM'S OWN FUNCTIONS rather than restating their conditions. `found_in_string` and
/// `contained_in` are the calls the arm makes; reading `All` and `Success` off them is reading their
/// answers, not re-deriving them, which is how the divergence this repairs arose in the first place.
/// A copy of the rule is what must not exist here.
///
/// NOT THE BUILT PAIR SET ITSELF, and the reason is the call order rather than the size of the
/// change. `binary_operation` calls the predicate BEFORE `cmp.compare`, deliberately: the note there
/// records that the incomparability is not recoverable from the result, because the not-flag has
/// already turned "no element matched" into a success by then. Reading the set the arm built
/// therefore needs either the comparison to run first -- the order the notice cannot use -- or
/// `Comparator::compare` to carry the set out for every operator, which reaches 99 non-test
/// `QueryResult::Resolved` sites. This is the same rule read from one place instead, and
/// `the_membership_notice_stops_pairing_where_the_operator_stops` pins the prefix it yields.
pub(super) fn membership_stops_after(lhs: &Rc<PathAwareValue>, rhs: &Rc<PathAwareValue>) -> bool {
    // The empty-left skip, which sits above both short-circuits in the arm and answers differently for
    // the two right-hand kinds: against a string the arm skips the pairing and KEEPS the value
    // (`continue`), and against every other kind it drops the value (`continue 'each_lhs`). So a
    // string does not stop the walk and anything else does.
    if let PathAwareValue::List((_, elements)) = &**lhs {
        if elements.is_empty() {
            return !matches!(&**rhs, PathAwareValue::String(_));
        }
    }

    if matches!(found_in_string(lhs, rhs), StringContainment::All) {
        return true;
    }

    matches!(
        contained_in(Rc::clone(lhs), Rc::clone(rhs)),
        ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))
    )
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

                // One `QueryIn` result holding the values that matched nothing, which is what makes `IN`
                // against a multi-value query mean "any of these". That shape is load-bearing and must
                // not change: expanding a left-hand value into one result per element here -- which is
                // what the literal-right-hand arm does, and the obvious way to make the two spellings
                // structurally identical -- turns "any" into "all". Measured, with `Type: gp3` and
                // `Names: ["gp2","gp3","io1"]`: `Type in Names[*]` is PASS today and FAIL under that
                // change, so every allowlist in every rules file would start rejecting the values it
                // allows. `a_long_in_comparison_is_truncated_with_a_total` and
                // `a_failing_in_comparison_against_a_plan_is_rendered_not_a_panic` are what caught it;
                // the first also pins the "and N more" summary this single result carries. Do not
                // expand here.
                let mut diff = Vec::with_capacity(lhs_selected.len());
                let mut collides = Vec::new();
                let mut unanswerable: Vec<ValueEvalResult> = Vec::new();
                // A fourth outcome for a left-hand value, beside matched, unmatched and unanswerable: no
                // comparison was made of it at all. The written-out string arm has always had this one --
                // `(None, Some)` decomposes a list left-hand side into one `string_in` per element, so an
                // EMPTY list produces no results and the clause passes in both polarities -- and this arm
                // had no way to say it.
                //
                // THE VALUES AND NOT A COUNT, and a count is what shipped first. `QueryIn` carries `lhs`
                // beside `lhs_unmatched`, and the negation wrapper derives the collided set as
                // `lhs \ lhs_unmatched` -- so a value withheld from `diff` and left in `lhs` reads as
                // MATCHED, which is the opposite of what withholding it meant. Dropping it from `diff`
                // alone made `NOT IN` deny it: with a `Mismatch` of `[[], ["zzz"]]` against a `Str` of
                // `"abc"`, `Mismatch[*] NOT IN Str` exited 19 reporting `provided value [[]] did match
                // expected value in [["abc"]]` -- the empty list named as having matched a haystack nothing
                // compared it against -- while `Mismatch[*] NOT IN "abc"` exits 0. Seventeen cells, every
                // one an over-denial and every one silent, because the notice gate fires only on a PASS.
                // So the set has to leave `lhs` as well, and these are the values that leave it.
                let mut uncompared: Vec<Rc<PathAwareValue>> = Vec::new();
                'each_lhs: for eachl in &lhs_selected {
                    let mut unanswerable_against: Option<(Rc<PathAwareValue>, StringContainment)> =
                        None;
                    let mut unanswerable_membership: Option<(Rc<PathAwareValue>, Unanswered)> =
                        None;
                    let mut element_collision = false;
                    let mut uncompared_pairings = 0_usize;
                    for eachr in &rhs_selected {
                        // The vacuous match, for a right operand that denotes a SET of candidate values.
                        // A string does not, which is the one exclusion below.
                        //
                        // THREE OUTCOMES, and the third one is what the exclusion routes to: a string
                        // right operand paired with an empty left-hand list is not a match and not a miss
                        // either, it is a pairing no comparison was made of. Excluding it from the match
                        // was right and recording it as unmatched was not, and that second half is what
                        // made `Empty IN Str` exit 19 where `Empty IN "abc"` exits 0.
                        //
                        // An empty left-hand list is vacuously a subset of a set, so it passes `IN` and
                        // fails `NOT IN`. `contained_in` supplies that from its list-against-list arm,
                        // where an empty left-hand list yields an empty diff and so a Success, and
                        // `4609b60e` made it survive a denylist holding a nested list. It cannot arrive
                        // when the right operand resolves to scalars, which is what `[*]` and `[0]` do to
                        // a denylist of scalars: a list against a scalar is `contained_in`'s incomparable
                        // catch-all, no Success is returned, and the empty list joined the unmatched set.
                        // So `Empty NOT IN [1, 3]` and `Empty NOT IN D13` exited 19 while
                        // `Empty NOT IN D13[*]` exited 0 -- the same two values, and the `[*]` deciding
                        // whether the denial happened.
                        //
                        // NOT A STRING, and the first version of this check had no test on the right
                        // operand at all, licensed by "there is no reading of the right operand for this
                        // case to get wrong". That was argued from a list-valued right operand, which is
                        // the only shape the argument examines, and stated universally. It is false of a
                        // string: `IN` against a string is substring containment -- the relation
                        // `found_in_string` and the `(None, Some)` string arm exist for -- and a haystack
                        // is not a set for anything to be a subset of. `found_in_string` declines the
                        // vacuous reading deliberately, returning `NoneFound` for an empty left-hand list
                        // so that `NOT IN` over nothing keeps passing rather than adding a second vacuous
                        // pass to the one `vacuous_comparison_notice` is deprecating. This check ran
                        // first and overrode it, so one question answered two ways: `Empty NOT IN Str`
                        // exited 19 while `Empty NOT IN "abc"`, the same string written out, exited 0,
                        // and the report claimed a match against a string nothing compared.
                        //
                        // The string kind and not "not a list", because the boundary is where the
                        // written-out spelling already is. Measured, against an `Empty` of `[]`:
                        //
                        //     [1, 3]      IN  0   NOT IN 19   vacuous subset match
                        //     "abc"       IN  0   NOT IN  0   no comparison is made at all
                        //     5           IN 19   NOT IN 19   NotComparable, fails closed both ways
                        //     true        IN 19   NOT IN 19   NotComparable, fails closed both ways
                        //     {"k": 1}    IN 19   NOT IN 19   NotComparable, fails closed both ways
                        //
                        // `NOT IN` against a map or a non-string scalar is 19 written out, so this check
                        // makes those query spellings AGREE with their literal. Excluding them as well
                        // would open a divergence rather than close one, and `Empty NOT IN Map` at 19 is
                        // therefore correct rather than the regression it looks like beside the string
                        // cell.
                        //
                        // AND NO REPAIR HERE CAN SERVE BOTH STRING SPELLINGS, by the construction
                        // `27383c98` established for the arm further down. `Strs` of `["abc"]` has one
                        // entry, so `Strs[0]` and `Strs[*]` both resolve to `String("abc")` at the same
                        // path `/Strs/0` and this loop receives one identical `QueryResult` either way,
                        // while the oracle owes them opposite verdicts: `Strs[0]` IS an operand whose
                        // value is the haystack and answers as `"abc"` does, PASS; `Strs[*]` names the
                        // entry set and answers as `["abc"]` does, FAIL. So at most one can be right, and
                        // the haystack reading is served rather than the entry set for two reasons
                        // pointing the same way.
                        //
                        // The `[0]`/`[*]` pair and NOT `Strs[*]` against `Str`, which is how this used to
                        // be written. `Strs[*]` resolves at `/Strs/0` and `Str` at `/Str`, so a path
                        // predicate separates those two and they are not forced to move together --
                        // measured, and asserted by
                        // `the_string_pair_that_cannot_be_separated_is_the_index_and_wildcard_spellings`.
                        // `Str` at 19 is an
                        // over-denial, which the arm below already records as the worse direction for a
                        // policy tool, and `Str` at 0 is the answer `found_in_string` documents and the
                        // parent shipped. `Empty NOT IN Strs[*]` at PASS is the residual that leaves, and
                        // it sits in the table beside `Empty NOT IN Strs` at FAIL so the disagreement is
                        // visible without reading this.
                        //
                        // That impossibility is confined to `NOT IN`, and reading it as covering the pair
                        // is what left the `IN` polarity over-denied for a release. The two candidate
                        // oracles disagree only in that polarity -- `"abc"` is 0 and `["abc"]` is 19 -- and
                        // on `IN` they AGREE at 0, so serving the string there costs the entry set nothing
                        // and `Empty IN Strs[*]` owes PASS on either reading. It was 19, along with
                        // `Empty IN Str`, `Strs[0]`, `Strs2[*]`, both `Resources.*.Properties.Name`
                        // spellings and the mixed `Lists[*]`, because a skipped pairing still pushed the
                        // value into `diff`. The skip below is what closes them, and THE CLAIM TO CARRY IS
                        // THE PREDICATE: it moves no `NOT IN` cell at all, so the residual above is exactly
                        // as it was.
                        //
                        // This said "eight cells over-denied" and the figure is retired rather than
                        // corrected. It counted a hand-authored population that was never named, so a
                        // reader cannot tell which set it counts: the enumeration in the sentence above
                        // lists SEVEN spellings, and ten clauses were measured moving 19 to 0 across the
                        // three relevant fixtures. Reaching eight needs `ListsRev[*]` or `Ustr`, and
                        // neither appears. The predicate cannot drift that way -- enlarging the population
                        // cannot falsify "no `NOT IN` cell moves" -- and it is the claim the skip is
                        // defended by. If a figure is wanted here, count over a CLOSED population computed
                        // inside the test, the way `3fe2c62d` counts two of seven subsets times two
                        // quantifiers times two roles.
                        //
                        // Rejected: also gating on `rhs_selected.len() > 1`, which fixes a two-entry
                        // string denylist while leaving the one-entry spelling above. It buys one cell by
                        // making the verdict depend on how many entries the denylist happens to hold, so
                        // a rule would pass against `["abc"]` and fail against `["abc", "zzz"]` with
                        // nothing in the clause to explain it.
                        //
                        // That rejection is now measured rather than argued, because the argument it
                        // rests on is answerable: two or more results prove the operand did not come
                        // from a `[0]` index, which yields exactly one, so the count looks like the
                        // provenance signal the `[0]`-versus-`[*]` collapse destroys. What refutes it is
                        // a query that resolves to several strings without a list anywhere in it.
                        // `Resources.*.Properties.Name` over two resources delivers two haystacks, and
                        // under that gate `Empty NOT IN Resources.*.Properties.Name` exits 19 -- the
                        // empty list denied against two strings nothing compared, which is the false
                        // report the string exclusion above exists to remove, recovered by adding a
                        // second resource. The one-resource spelling stays 0, so the boundary it draws
                        // falls between one resource and two. `a_multi_candidate_string_query_is_not_an_entry_set`
                        // is that cell, and `Empty NOT IN Strs2[*]` sits in the table above at PASS with
                        // its literal at FAIL beside it as the residual this leaves.
                        //
                        // AND THE `IN` POLARITY OF A NON-LIST RIGHT OPERAND HAS NO REPAIR HERE EITHER,
                        // which is this check's own defect rather than an inherited one and is a proof
                        // rather than a preference. `Empty IN Map` exits 0 where the written-out
                        // `Empty IN {"k": 1}` exits 19, and `N`, `B`, `Flt` and `Nullv` do the same. Take
                        // a `D1` of `[5]`, one entry, so cardinality cannot discriminate: `D1[0]` and
                        // `D1[*]` deliver one identical `Int(5)` at one identical path `/D1/0`, so no
                        // predicate over the value, the kind or the path can separate them, while the
                        // oracle owes them opposite verdicts -- `D1[0]` IS the operand and answers as `5`
                        // does, 19, and `D1[*]` names the entry set and answers as `[5]` does, 0.
                        //
                        // The asymmetry with `NOT IN` is why the non-string kinds were repairable in that
                        // polarity: `Empty NOT IN 5` and `Empty NOT IN [5]` are BOTH 19, one by
                        // `NotComparable` failing closed and one by this match negated, so one answer
                        // serves both spellings. On `IN` they are 19 and 0, so no answer does.
                        //
                        // A CELL, NOT A POLARITY, and this comment used to say "the whole reason that
                        // polarity was repairable" -- which the string kind inverts, eighty lines above
                        // where it is already recorded. `Empty NOT IN "abc"` is 0 and
                        // `Empty NOT IN ["abc"]` is 19, so the two oracles DISAGREE on `NOT IN` there,
                        // while `Empty IN "abc"` and `Empty IN ["abc"]` are both 0 and AGREE. Measured
                        // across all six literal kinds: every non-string kind gives IN 19 / NOT IN 19 bare
                        // and IN 0 / NOT IN 19 wrapped, so the agreement is in `NOT IN`; the string gives
                        // 0/0 bare and 0/19 wrapped, so it is in `IN`. What is fixable is the
                        // (non-string, `NOT IN`) cell and the (string, `IN`) cell -- one per kind family,
                        // in opposite polarities. Reading either as a whole polarity is what left the other
                        // family's fixable cell sitting there.
                        //
                        // The pair above is also not enough for the residual it is cited for, because both
                        // `D1[0]` and `D1[*]` resolve at `/D1/0` and so both paths end in an index. A
                        // predicate keyed on that -- last path segment is a digit -- treats them alike and
                        // escapes the pair, while moving `Empty IN Map`, `N`, `B`, `Flt` and `Nullv` (at
                        // `/Map`, `/N`, `/B`, `/Flt`, `/Nullv`) to the 19 their literals owe and leaving
                        // `D1[*]`, `D13[*]`, `Maps[*]` and `Strs` alone -- which is exactly the price this
                        // comment quotes to reject the `unanswerable` repair. `OneKeyMap` of
                        // `{"Inner": 5}` is what forecloses it: `OneKeyMap.Inner` and `OneKeyMap.*` resolve
                        // to one identical `Int(5)` at one identical `/OneKeyMap/Inner`, `Location`
                        // included and no digit in either, and owe opposite verdicts by the same
                        // construction -- 19 as `5` and 0 as `[5]`. So a path-shaped repair for `Map`
                        // breaks `OneKeyMap.*`.
                        // `a_digit_free_query_pair_resolves_identically_and_forecloses_a_path_shaped_repair`
                        // asserts the identity where it lives, on the `QueryResult`.
                        //
                        // Two repairs serving the other side were built and measured. Firing only for a
                        // list-valued result reddens 27 rstest cells at `b8d3901e` and is a revert: `[*]`
                        // over a scalar denylist resolves to scalars, so the check becomes a no-op for the
                        // shape it exists for and `Empty NOT IN D13[*]` returns to 0. Recording the
                        // pairing as unanswerable is surgical -- every cell it moves is an `IN` cell, no
                        // `NOT IN` cell moves -- and brings seven to the 19 their literals owe while
                        // taking THIRTEEN the other way, among them `Empty IN Strs`, `D13[*]`, `D1[*]`,
                        // `Maps[*]` and `Mixed[*]` from 0 to 19. `Strs` is in that list because this check
                        // fires for any non-string result, a list included, so an unexpanded list denylist
                        // is answered here and never reaches `contained_in`'s list arm -- instrumented at
                        // that call site, `Empty IN Strs` and `Empty NOT IN Strs` make zero calls to it
                        // while `D13 NOT IN Strs` and `Strs2 NOT IN Strs` make one each. That is
                        // over-denial, which the collision arm below records as the
                        // worse direction for a policy tool, and `SomeList IN Allowed[*]` is the ordinary
                        // allowlist spelling, so it would start reporting a violation whenever the list
                        // it checks is empty. It is also the answer the `Denies[0]` proof below already
                        // rules out for this arm, by the same test: the information is missing from the
                        // call rather than from the question, and one member of the pair has a definite
                        // PASS.
                        // `the_in_polarity_of_a_queried_scalar_right_operand_has_no_repair_in_this_arm`
                        // carries the pair and both measured prices.
                        //
                        // Seven for THIRTEEN, and this comment said seven for five. The five were the
                        // losses visible in the two tables the author had open; seven more are `Empty IN`
                        // cells pinned at PASS in
                        // `an_empty_left_hand_list_is_vacuously_in_every_spelling_of_a_denylist` and
                        // `a_list_denylist_holding_a_nested_list_denies_only_what_it_names`, and the
                        // thirteenth had no cell anywhere -- `Empty IN MixedRev[*]` goes 0 to 19 while its
                        // literal `[5, "abc"]` stays 0, and at `b8d3901e` its only occurrence as a CELL was
                        // a `NOT IN` cell. So the repair loses on count AND on direction rather than winning
                        // narrowly on one. The conclusion is unchanged and now stronger -- adding that cell
                        // is what took the candidate repair's red count from 19 to 22.
                        //
                        // This said "every one of `MixedRev`'s four occurrences was a `NOT IN` cell", which
                        // counted grep hits as cells. Four hits is right; one is a cell, and the other three
                        // are a table row, a prose sentence and the data-document field. Fixed here as well
                        // as at the three sites in `eval_tests.rs`, since a wrong count inside the paragraph
                        // warning against wrong counts is the one place it cannot be left standing.
                        //
                        // WHICH SHAPE OF FIGURE IS SAFE, because the wrong number came from the method
                        // this comment recommends. A count over a hand-authored population of cells is not
                        // a property of the code: it changes when someone writes another cell, and it is
                        // silently short by however many nobody wrote. The predicate beside it -- every
                        // moved cell is an `IN` cell -- survives, because enlarging the population cannot
                        // falsify "all of them are". At this commit the same repair reddens 22 cells rather
                        // than 19, eight gains and fourteen losses, because the `OneKeyMap` pair added one
                        // of each and the `MixedRev[*]` cell made the thirteenth loss observable. The code
                        // did not move between those figures; the population did.
                        // Prefer a predicate over the moved set; failing that, a count
                        // over a CLOSED population computed inside the test, the way `3fe2c62d` counts two
                        // of 28 subset-times-quantifier-times-role combinations; failing that, a clause
                        // sweep, which at least cannot miss a cell nobody authored.
                        //
                        // A match, not a collision. The collision arm below asks whether the denylist
                        // names one of the left-hand elements, and an empty list has none to name, so no
                        // loop over `elements` can ever record one. What the convention says is that the
                        // empty list matched, so a match is what this reports, and `NOT IN` derives the
                        // denial by negation exactly as it does for the unexpanded spelling.
                        //
                        // Inside the loop rather than above it, so a left-hand value with no right-hand
                        // results to compare against is untouched, which is how the list-against-list
                        // path already behaves.
                        //
                        // An empty list, not a value that looks empty: an empty string and an empty map
                        // are not lists, no subset reading applies to either, and both already pass
                        // `NOT IN` correctly.
                        // `an_empty_left_hand_list_is_vacuously_in_every_spelling_of_a_denylist` pins
                        // those as the mirror, with a non-empty list that must keep answering by what the
                        // denylist names, and
                        // `the_vacuous_subset_reading_belongs_to_a_right_operand_that_denotes_a_set` pins
                        // the right-operand kinds with each kind's literal spelling beside it.
                        //
                        // `continue` and not `continue 'each_lhs` for the string: the pairing is skipped,
                        // the value is not. A later right-hand result that is not a string still reaches
                        // the vacuous match below, which is the "any right-hand value will do" reading this
                        // loop applies everywhere else, and it is why `Empty NOT IN Mixed[*]` over
                        // `["abc", 5]` still denies in either element order.
                        if let PathAwareValue::List((_, elements)) = &**eachl {
                            if elements.is_empty() {
                                if matches!(&**eachr, PathAwareValue::String(_)) {
                                    uncompared_pairings += 1;
                                    continue;
                                }

                                continue 'each_lhs;
                            }
                        }

                        // Containment first, membership second, which is the order the two arms above
                        // apply when the right-hand side is written out. This arm asked `contained_in`
                        // alone, and two scalars there fall through to `compare_eq`, so
                        // `Needle in Haystack` was equality while `Needle in "aws:arn:s3::${s3}"` was
                        // containment -- and `Needle not in Haystack` therefore PASSED on a needle the
                        // haystack verbatim contains, a denylist admitting the value it names at exit 0.
                        match found_in_string(eachl, eachr) {
                            StringContainment::All => continue 'each_lhs,

                            // Recorded, not answered. A full match against a later right-hand result
                            // still wins, which is this loop's existing "any right-hand value will do"
                            // reading, so an undecidable pairing only decides if nothing else does.
                            undecidable @ (StringContainment::Partial
                            | StringContainment::HoldsANonString
                            | StringContainment::NotAString) => {
                                if unanswerable_against.is_none() {
                                    unanswerable_against = Some((Rc::clone(eachr), undecidable));
                                }
                            }

                            StringContainment::NoneFound => {}
                        }

                        match contained_in(Rc::clone(eachl), Rc::clone(eachr)) {
                            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) => {
                                continue 'each_lhs
                            }

                            // A failed membership is not the same statement as a total miss, and this
                            // arm used to treat it as one. `contained_in` fails a list-valued left-hand
                            // side that is only *partly* present -- neither the whole list nor every
                            // element found an equal -- and reports the elements that found nothing as
                            // the `ListIn` diff. The elements missing from that diff DID find one, and
                            // those are the values a denylist names. Counting only Success as a match
                            // made a `Fail` carrying a real element collision indistinguishable from a
                            // pairing where nothing matched at all, so it joined the unmatched set and
                            // negated to a pass: with `Pair` of `[1, 2]` and `Deny` of `[1, 3]`,
                            // `Pair NOT IN Deny` exited 0 while `Pair NOT IN [1, 3]` exited 19.
                            //
                            // Recorded rather than answered, for the reason the string case above gives:
                            // a full match against a later right-hand result still wins, so a partial
                            // collision only decides when nothing else does.
                            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                                Compare::ListIn(lin),
                            )) => element_collision |= !matched_elements(&lin).is_empty(),

                            _ => {}
                        }

                        // The arm that was never written, for the pairing that produces no `ListIn` to
                        // read a collision out of.
                        //
                        // `contained_in` dispatches on the LEFT value first, so a list-valued left-hand
                        // side enters its `List` arm and a right-hand value that is not a list reaches
                        // that arm's catch-all, which answers `NotComparable`. Only two lists build a
                        // `ListIn`. So the arm above cannot see a collision when the right operand
                        // resolves to scalars, which is what `[*]` on the right does: with `Pair` of
                        // `[1, 2]` and `Deny13` of `[1, 3]`, `Pair NOT IN Deny13[*]` paired a list with
                        // `1` and then with `3`, recorded nothing either time, and exited 0 while
                        // `Pair NOT IN Deny13` exited 19. One denylist, one value, and whether the
                        // right-hand query was spelled with `[*]` decided whether the value it names was
                        // admitted.
                        //
                        // `NotComparable` is the right answer for what that arm is asked -- a list and a
                        // scalar are not comparable -- so this is an addition rather than a correction to
                        // it. The reading "a pair that cannot be compared is not a match" is stated
                        // explicitly for a scalar left-hand side, by the `Err(_) => {}` in `contained_in`'s
                        // `rest` arm and by `is_one_of`'s `unwrap_or(false)`. For a list left-hand side it
                        // was implemented by the ABSENCE of an arm here, which is the same reading applied
                        // to the whole list when the question is about its elements. What was missing is
                        // the element question, and that is what this asks.
                        //
                        // Which is also why no experiment at that `Err(_) => {}` could ever have moved
                        // this bypass, and why the unwrapped spelling was always right: both sit in the
                        // `rest` arm, guarded by the left value NOT being a list, and `Pair` is a list.
                        // The two sites are separable for the same reason -- different arms for different
                        // operand shapes -- so a change to either cannot regress the other.
                        //
                        // Keyed on the operand shapes rather than on the verdict the pairing produced,
                        // because the verdict is what was unreadable: reading `NotComparable` here would
                        // stop firing the moment that catch-all reports something else, and silently.
                        // `eachr.is_list()` is exactly the case the arm above already answers, so the two
                        // cannot both count one collision.
                        //
                        // `is_one_of`, not a fresh loop, and that is the whole point of the function --
                        // it is what `contained_in` asks for the written-out spelling, so the two
                        // spellings cannot disagree about what counts as an element collision again.
                        // Asking `PartialEq` alone here would leave a range or a regex on the right
                        // matching no element, which is the hole `d7f01ec` closed one arm at a time.
                        //
                        // Whole-list membership needs nothing added here: `compare_eq` of a list
                        // against a scalar is an error, so no scalar right-hand value can be the
                        // left-hand list itself.
                        //
                        // A right-hand result that IS a list goes to the arm above and is NOT fully
                        // answered there, which this comment used to claim it was. `contained_in` reads
                        // such a result as a set of candidate entries rather than as one entry, so
                        // `Deny[*]` over a `Deny` of `[[9]]` compares against `{9}` where the written-out
                        // and unexpanded spellings compare against `{[9]}`. For a `Nest` of `[1, [9]]`
                        // that is exit 0 against three spellings at exit 19, and it is the same class of
                        // bypass as the one repaired here, one operand shape further in.
                        // `right_expanded_nested_entry_undenied_no_local_fix` in `eval_tests.rs` pins it
                        // with its three disagreeing siblings beside it, and
                        // `right_expanded_nested_string_entry_undenied_no_local_fix` pins the same bypass
                        // in strings.
                        //
                        // Deleting the `!eachr.is_list()` guard is the obvious repair for it and is
                        // WRONG, which is measured rather than argued. It closes both of those cells and
                        // moves no `IN` cell, and it also denies a value no denylist names: for a
                        // `Wrap13` of `[[1, 3]]` and a `Deny13` of `[1, 3]`,
                        // `Wrap13 NOT IN Deny13` goes to exit 19 while `Wrap13 NOT IN [1, 3]` stays at 0
                        // -- one denylist, one value, and the query spelling deciding to deny what the
                        // literal spelling admits. That is this arm's own defect class mirrored into
                        // over-denial, which is the worse direction for a policy tool. The three
                        // `an_lhs_element_equal_to_the_whole_..._denylist_is_undenied` cells are the
                        // guard, and they exist because the suite did not catch this: with them absent, a
                        // build carrying that deletion reported 2553 passed and 0 unexpected failures.
                        //
                        // The reason it cannot be keyed on shape is that the two cases ARE one shape. A
                        // list-valued `eachr` is either the whole denylist, which an unexpanded `Deny13`
                        // resolves to, or one entry, which `Deny13[*]` resolves to; the first has to be
                        // decomposed and the second taken whole. "An element of `eachl` equals `eachr`"
                        // holds for `Nest` against `[9]` and for `Wrap13` against `[1, 3]` alike, and the
                        // first owes FAIL and the second PASS, so no predicate over these two values can
                        // separate them.
                        //
                        // And no repair confined to this arm can be right, which is stronger than the
                        // deletion above being wrong, and is a proof rather than a preference. Take a
                        // `Denies` of `[[1, 3]]`, one entry. `Denies[0]` and `Denies[*]` resolve to the
                        // same single value, the inner list `[1, 3]`, at the same path, so `compare`
                        // receives one identical `QueryResult` either way. The oracle owes them opposite
                        // verdicts: `Denies[0]` is a single right-hand operand whose value IS the
                        // right-hand list, members `1` and `3`, and a `Pair` of `[1, 2]` holds `1`, so
                        // FAIL; `Denies[*]` names the entry set, whose one member is `[1, 3]`, which
                        // `Pair` neither is nor holds, so PASS. The nested shape is the same pair with the
                        // polarity reversed -- `Nest NOT IN DenyNestedNine[0]` owes PASS and
                        // `Nest NOT IN DenyNestedNine[*]` owes FAIL. Each pair holds one cell that is
                        // right today and one that is wrong, and anything written here moves both
                        // together, so at most one member of each pair can be correct. Measured: the
                        // deletion above closes `right_expanded_nested_entry_undenied_no_local_fix` and
                        // reddens `a_single_indexed_nested_entry_denies_by_its_members` in the same run.
                        //
                        // THE SAME PAIR SETTLES THE OVER-DENIAL, which is the `element_collision` read of
                        // `contained_in`'s `ListIn` diff further up rather than this guard, and which was
                        // taken to need the query-layer redesign before anyone had run this test on it.
                        // `Denies[*]` in the pair just given IS an over-denial -- `Pair` is `[1, 2]`, the
                        // entry `[1, 3]` names neither it nor an element of it read as an entry, and the
                        // clause denies anyway -- so the `[*]` half that is wrong today is the defect
                        // itself, and the conclusion for it was already recorded and unread. In the
                        // defect's own entry shape, a `DenyWrapOne` of `[[1]]`, the two spellings deliver
                        // the same inner list `[1]` at the same path AND the same `rhs_selected` count of
                        // one, so not even the number of right-hand results tells them apart, while
                        // `DenyWrapOne[0]` owes FAIL by its members and `DenyWrapOne[*]` owes PASS by its
                        // entry. Measured, taking the entry reading at both sites together, which is the
                        // only way to take it since they answer for the same operand shapes: five open
                        // cells reach their owed verdict and twelve correct ones leave theirs in the same
                        // run, among them `Pair NOT IN Deny13` returning to the exit 0 `e331c6b` closed,
                        // `Nest NOT IN DenyNestedNine` unexpanded losing its denial, and
                        // `Wrap13 NOT IN Deny13` starting to over-deny. So this is one impossibility with
                        // two faces rather than two defects, and the over-denial needs the same change to
                        // how a queried right-hand operand reaches the comparators. The
                        // `DenyWrapOne` and `DenyWrappedOneTwo[0]` cells in
                        // `which_spelling_of_a_queried_denylist_reaches_which_arm` carry it.
                        //
                        // Which also rules out answering "undecidable" and joining `unanswerable`, the
                        // third answer this arm already has for a pairing with no right verdict in either
                        // polarity. These pairings do have right verdicts, fixed by the operand values
                        // and the spelling, and one member of each pair is a PASS; failing closed there
                        // would deny a value no denylist names and would assert that a decided question
                        // is undecided. The information is missing from the call, not from the question,
                        // and that is the test for whether `unanswerable` is the honest answer to a new
                        // ambiguity or a dodge -- when the question itself has no answer, as for a
                        // genuinely incomparable pairing, `NotComparable` is right.
                        //
                        // `QueryResult` is `Literal | Resolved | UnResolved` and keeps no record of the
                        // traversal that produced a value; `binary_operation` receives the right-hand
                        // side already resolved and consumes the access expression that separates the two
                        // spellings. Carrying the provenance means changing `Comparator::compare` for
                        // every operator, and even then it does not reach `NOT IN %deny`, since a
                        // variable's binding is resolved before any comparator sees it and
                        // `a_denylist_named_by_a_variable_denies_what_the_same_list_written_out_denies`
                        // covers that spelling. Closing this is a change to how a queried right-hand
                        // operand reaches the comparators, not a repair to this arm.
                        //
                        // `is_one_of` answers three ways now, and the third one belongs to the
                        // `unanswerable` list below rather than to `element_collision`. A collision is a
                        // claim: the report says this value collides with the denylist, and `NOT IN`
                        // denies it on that basis. An element whose comparison could not be evaluated
                        // supports no such claim, so folding it into the boolean either way states
                        // something false -- `true` asserts a collision nothing established, `false`
                        // asserts absence from a denylist that was never read. This arm already has a
                        // third answer for exactly that, three paragraphs down, and it fails closed in
                        // both polarities while naming the reason. `Matched` still wins, because a
                        // matched element decides the value without reference to the one that failed.
                        //
                        // No input reaches that third answer today, and it is written out rather than
                        // met with an `unreachable!()` for a reason that is about where the values come
                        // from. `is_one_of` promotes `RegexError` only, so reaching it needs a
                        // `PathAwareValue::Regex` on the right, and `eachr` here is a query result. Data
                        // cannot carry one: `Value::Regex` is built in exactly one place,
                        // `parse_regex_inner` in the rules parser, and `MarkedValue::Regex` -- the
                        // variant the data path would have to produce -- is never constructed anywhere
                        // in the crate. A rules literal can be a regex, and four spellings of one
                        // bound to a `let` and expanded with `[*]` were measured: none reaches this arm
                        // at all. The arm itself is live, so this is not dead code guarded by a dead
                        // check -- the reproducer in e331c6b's own message drives it twice with
                        // `rhs_kind=int`. So the shape is defensive: it costs one match arm, and it is
                        // what stops a future spelling that does put a literal regex here from silently
                        // reading "could not evaluate" as "does not collide", which is the defect this
                        // commit exists to close one arm over.
                        if let PathAwareValue::List((_, elements)) = &**eachl {
                            if !eachr.is_list() {
                                for each in elements {
                                    match is_one_of(each, std::slice::from_ref(&**eachr)) {
                                        Membership::Matched => element_collision = true,
                                        Membership::NoMatch => {}
                                        Membership::Unanswerable(unanswered) => {
                                            if unanswerable_membership.is_none() {
                                                unanswerable_membership =
                                                    Some((Rc::clone(eachr), unanswered));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Nothing matched, and something could not be decided: the clause was posed at the
                    // wrong granularity and has no right answer in either polarity. `NotComparable` is
                    // how this arm already says that -- `%int in Haystack` and `%int not in Haystack`
                    // both fail, because an incomparable type fails closed both ways -- so these join
                    // an existing rule rather than introducing one. Failing closed is also the safe
                    // direction for a policy engine: a denylist that cannot decide must not report
                    // compliance.
                    //
                    // BOTH third answers under one `!element_collision`, and they used to be two blocks
                    // with opposite precedence: the membership one was gated and the containment one was
                    // checked unconditionally, one screen above it. So a clause that established a
                    // collision AND could not decide a containment reported the containment complaint
                    // and dropped the collision. With `Vals` of `["abc", "zzz"]` and `Deny` of
                    // `["abcdef", "zzz"]`, `Vals NOT IN Deny[*]` recorded `Some but not all of
                    // Value=["abc","zzz"] is contained in Value="abcdef"` -- the claim that the question
                    // has no answer -- while `"zzz"` is verbatim a denylist entry. Two right-hand
                    // results produce the two records, which is why neither one alone looks wrong:
                    // `"abcdef"` holds `"abc"` and not `"zzz"`, so `found_in_string` reaches `Partial`,
                    // and `"zzz"` is matched exactly by one element, so `is_one_of` reaches `Matched`.
                    //
                    // The collision wins, and that is the rule the other two sites already follow. A
                    // collision is a claim this arm can support -- the denylist holds this element, so
                    // `NOT IN` denies it on that basis and the report can name it -- and an undecidable
                    // containment supports no claim about the value at all. Reporting the second while
                    // holding the first states the weaker of two findings and discards the one a rule
                    // author can act on. `found_in_string`'s `All` already continues the outer loop
                    // immediately, and `is_one_of` applies the same precedence internally by letting
                    // `Matched` outrank `Unanswerable`, so this is one site joining a rule rather than a
                    // new rule. One `if` for both, because two guards that have to agree are what came
                    // apart.
                    //
                    // The verdict does not move and the report does. `NotComparable` fails closed in
                    // both polarities and a non-empty `diff` carrying a collision also fails both, so
                    // the clause above is exit 19 before and after; measured, `Vals IN Deny[*]` is 19
                    // too. What changes is that the undecidable reason disappears and an `InComparison`
                    // naming the collision takes its place, which is why
                    // `a_decided_element_collision_outranks_an_undecidable_containment` asserts on the
                    // recorded messages and `a_reported_collision_is_recorded_as_a_membership_check`
                    // asserts on the variant -- the first alone is satisfied by dropping both answers.
                    //
                    // Why nothing caught it. `found_in_string` outranks the collision arm for
                    // essentially every string pairing, so that arm has observable effect only when no
                    // right-hand value is a string -- which is what `e331c6b`'s own reproducer used, at
                    // `rhs_kind=int`. Traced: against a string right operand, a contained element gives
                    // `Partial` or `All` and a non-string element gives `HoldsANonString`, so both record
                    // or continue before the collision can decide; and the one remaining case, every
                    // element a string and none contained, cannot produce a collision either, because an
                    // element EQUAL to the string would also be contained in it. The clause above is the
                    // gap, where the two answers come from different right-hand results and neither
                    // trace covers both at once.
                    //
                    // Three reasons, because they are three different complaints and a reader acts on
                    // them differently: a list whose elements are all strings but only some of them
                    // present, a list holding something containment cannot be asked of at all, and a
                    // value that is not a string and not a list either. The third says "is not a string"
                    // rather than "holds", because `found_in_string` decomposes only a list, so nothing
                    // examined the value's contents and a message about them would name what was never
                    // tested. A `Map` reaches this reason and does hold something, which is why the
                    // wording is about what was asked rather than about what the value contains.
                    if !element_collision {
                        if let Some((other, undecidable)) = unanswerable_against {
                            let reason = match undecidable {
                                StringContainment::HoldsANonString => format!(
                                    "{} holds a value that is not a string, so it cannot be tested \
                                     for containment in {}",
                                    eachl, other
                                ),

                                StringContainment::NotAString => format!(
                                    "{} is not a string, so it cannot be tested for containment in {}",
                                    eachl, other
                                ),

                                _ => {
                                    format!("Some but not all of {} is contained in {}", eachl, other)
                                }
                            };

                            // Kinds, not an abandoned evaluation: every wording above is about what the
                            // operands are, and `found_in_string` refuses on the shape of the value
                            // rather than starting a match it cannot finish.
                            unanswerable.push(not_comparable_because(
                                Rc::clone(eachl),
                                other,
                                Unanswered::kinds(reason),
                            ));
                            continue;
                        }

                        // The membership question's own third answer, joining the containment one above
                        // rather than getting a rule of its own. Same shape: nothing matched, one
                        // comparison had no answer, so there is no verdict to record in either polarity
                        // and the reason is what a rule author can act on.
                        if let Some((other, unanswered)) = unanswerable_membership {
                            unanswerable.push(not_comparable_because(
                                Rc::clone(eachl),
                                other,
                                unanswered,
                            ));
                            continue;
                        }
                    }

                    // Every pairing was skipped, so nothing was asked about this value and it is neither
                    // matched nor unmatched. Recording it in `diff` is what made the query spelling of a
                    // string right operand disagree with the written-out one in the `IN` polarity:
                    // `Empty IN Str` exited 19 where `Empty IN "abc"` exits 0, and the same for
                    // `Strs[0]`, `Strs[*]`, `Strs2[*]` and `Resources.*.Properties.Name`.
                    //
                    // A count rather than "is this an empty list", and the two are equivalent today: the
                    // only skip above is the string pairing, and ANY non-string right-hand result takes an
                    // empty list out through `continue 'each_lhs`, so reaching this line with one at all
                    // means every pairing was skipped. Measured -- rewriting this as `uncompared_pairings
                    // > 0` moves nothing across a 140-clause CLI grid of the string-and-vacuous shapes, in
                    // both element orders. That grid's clause list is not committed either, so treat the
                    // number as a note on what was run; the reproducible half of this claim is the argument
                    // above it, which holds by inspection of the two `continue`s.
                    // So this is defensive in the same way the `Unanswerable` arm below is:
                    // it costs a counter, and it is what stops a second skip added here later from reading
                    // "one pairing was not compared" as "none of them were", which is the whole defect this
                    // repairs one polarity of.
                    //
                    // The `!is_empty` guard keeps a left-hand value with no right-hand results to compare
                    // against on its existing path, which is the same reason the skip above sits inside
                    // the loop rather than over it.
                    if !rhs_selected.is_empty() && uncompared_pairings == rhs_selected.len() {
                        uncompared.push(Rc::clone(eachl));
                        continue;
                    }

                    if element_collision {
                        collides.push(Rc::clone(eachl));
                    }

                    diff.push(Rc::clone(eachl));
                }

                // One verdict per value, not two that disagree about the same one.
                //
                // With something unanswerable and nothing left unmatched there is no unmatched value for
                // this record to be about, and recording it anyway files a second verdict against a
                // value the loop has already reported it cannot decide. On `NOT IN` that second verdict
                // is the one a report shows: for an `Int` of `5` against a string haystack,
                // `Int not in Haystack` records the reason -- `/Int` is not a string, so containment
                // cannot be tested -- and then, without this, an `InComparison` FAIL filing `/Int` as a
                // value that WAS present in the haystack, contradicting the record beside it. On `IN` the
                // extra record is a bare `Success` carrying no message and no operands.
                //
                // Not a verdict change, and the comment here used to say it was: it claimed an empty
                // `diff` would otherwise report Success. Measured both ways, the clause exits 19 either
                // way, because a `NotComparable` result fails closed on its own and decides the verdict
                // whatever is recorded beside it. What this decides is what the report says, which is
                // why `an_unanswerable_containment_records_one_verdict_not_two` asserts on the recorded
                // clause checks rather than on the status. Nothing asserted on it before that test:
                // removing this line left 976 passed and 0 failed.
                //
                // Renamed from `every_value_was_unanswerable`, which described a narrower case than the
                // condition. Both halves hold whenever anything was unanswerable and nothing was left
                // unmatched, including when other left-hand values matched in full: with
                // `Values: ["s3", 5]`, `"s3"` is contained and so never reaches `diff`, `5` cannot be
                // asked, and the flag is true with one of the two values perfectly answerable.
                let unanswerable_and_nothing_unmatched =
                    !unanswerable.is_empty() && diff.is_empty();

                // Nothing was compared, so there is nothing to report -- which is a verdict of PASS in both
                // polarities, and the reason this arm CAN reach PASS/PASS after all. The comment on
                // `an_empty_list_is_in_a_string` said it could not, on the grounds that skipping the
                // value gives PASS/FAIL and recording it gives FAIL/PASS. Both are true of those two moves;
                // the third move is to emit no result at all, which is exactly what the `(None, Some)`
                // string arm does with an empty list and what the sibling comment identified as the fix
                // while placing it in another arm. `EvalResult::Result(vec![])` is already the shape that
                // carries it -- `Empty IN "abc"` and `Empty NOT IN "abc"` are both exit 0 today and that arm
                // pushes nothing.
                //
                // THE UNCOMPARED VALUES LEAVE `lhs`, not only `diff`, and this is the whole repair for the
                // over-denials the first version of this fix created. `QueryIn` carries both sets, and the
                // negation wrapper reads the collided set as `lhs \ lhs_unmatched` -- so any value present
                // in `lhs` and absent from `lhs_unmatched` is, to that wrapper, a value that MATCHED. A
                // value withheld from `diff` was therefore reported as a match against the very operand no
                // comparison examined, and `NOT IN` denied it. `Mismatch[*] NOT IN Str` over
                // `[[], ["zzz"]]` and `"abc"` was exit 19 against its literal's 0.
                //
                // `reverse_diff` compares by value, and that is sound here rather than merely convenient:
                // whether a left-hand value is uncompared depends only on the value and on `rhs_selected`,
                // so two equal left-hand values are always classified alike and removing one can never
                // remove a compared sibling. A `Lists` of `[[], []]` is the case -- both empty lists are
                // uncompared, and both leave.
                //
                // Every value, not any: with one left-hand value uncompared and another matched, the ones
                // that WERE compared all matched and `Success` is the honest aggregate. That is the literal
                // spelling's behavior too, since it unions per-value results and an empty list contributes
                // none. Suppressing on `uncompared` being non-empty instead would take
                // `Lists[*] NOT IN Str` over `[[], ["abc"]]` from 19 to 0 while
                // `Lists[*] NOT IN "abc"` stays at 19 -- a denylist admitting a value one of its haystacks
                // contains verbatim. `an_uncompared_empty_list_does_not_silence_its_siblings` carries that
                // cell, a compared-and-FAILING sibling for the over-denial above, and both element orders.
                //
                // Derived from `lhs_compared` rather than from a count, so the two facts the aggregate needs
                // -- which values to name, and whether any were compared at all -- cannot disagree. The
                // `!lhs_selected.is_empty()` guard keeps a left-hand query that resolved to nothing on its
                // existing path.
                //
                // WHY THE AGGREGATE NEEDS SUPPRESSING AT ALL, stated as the shape rather than as this
                // instance, because the shape is worth recognising elsewhere -- and this fix got caught by
                // it twice. The `Success` above is decided by `diff.is_empty()`, and an empty `diff` has two
                // causes that mean opposite things: everything that was asked matched, or nothing was asked.
                // A predicate over the ABSENCE of recorded failures cannot separate those, so it reads "no
                // comparison happened" as "every comparison succeeded". `lhs \ lhs_unmatched` in the
                // negation wrapper is the SAME predicate one consumer along, and tracking the third state
                // for the verdict while leaving the wrapper to infer it from two empty sets is what produced
                // the over-denials. Any absence-derived set has this hole, and a fix has to reach every
                // consumer of it, not just the one that motivated the fix.
                let lhs_compared = reverse_diff(uncompared, &lhs_selected);
                let nothing_was_compared = !lhs_selected.is_empty() && lhs_compared.is_empty();

                results.extend(unanswerable);
                if !unanswerable_and_nothing_unmatched && !nothing_was_compared {
                    results.push(if diff.is_empty() {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                            Compare::QueryIn(QueryIn::new(diff, lhs_compared, rhs_selected)),
                        ))
                    } else {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(
                            QueryIn::partly_matched(diff, collides, lhs_compared, rhs_selected),
                        )))
                    });
                }
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
        // `compare_eq_unwrapping_a_one_element_list` throughout, not `compare_eq`. `compare_eq`'s five
        // range arms are written scalar-on-the-left because every other caller has a subject and a
        // pattern, and `==` does not -- so with a range on the left of `==` the pair reached the
        // incomparable catch-all and `%l == Port` refused where `Port == r[80,90]` passed.
        // `compare_eq_symmetric`, which that wrapper is, puts the scalar on the left for this operator
        // only, which is why `IN` and the map key filters, for which one-directional is correct, keep
        // asking `compare_eq` directly.
        //
        // Throughout means every arm, and it did not. The unwrap that relates a scalar to a
        // one-element list was reached by the `(None, None)` arm, which asks the comparator per pair,
        // and by the `(None, Some)` list arm, which unwraps inline at `rhsl[0]`. Two arms asked
        // `compare_eq_symmetric` for a pair one of them would have unwrapped, and refused it: with
        // `Val: "Name"` and `let lit_other = ["Other"]`, `%lit_other != Val` exited 19 reading
        // "PathAwareValues are not comparable array, String" -- two values that visibly differ,
        // rejected rather than answered, where `Val != %otherkey` passed. `(Some, Some)` did the same
        // in both orientations.
        //
        // The two arms that expand rather than unwrap need no change and get none: with a literal
        // scalar against a query list, or a query list against a literal scalar, the list is walked
        // element by element and each element compared, which reaches the same verdict for a
        // one-element list by a different route. Asking the unwrapping comparator there costs nothing,
        // since by then both operands are scalars, and it means no arm of this operator can disagree
        // about the unwrap again -- which is the property that was missing, not any one arm.
        match (is_literal(lhs), is_literal(rhs)) {
            (Some(ref l), Some(ref r)) => {
                results.push(match_value(
                    Rc::clone(l),
                    Rc::clone(r),
                    compare_eq_unwrapping_a_one_element_list,
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
                            results.push(match_value(
                                Rc::clone(&l),
                                each,
                                compare_eq_unwrapping_a_one_element_list,
                            ));
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
                                            compare_eq_unwrapping_a_one_element_list,
                                        ));
                                    }
                                }

                                rest_rhs => {
                                    results.push(match_value(
                                        Rc::new(single_value.clone()),
                                        Rc::new(rest_rhs.clone()),
                                        compare_eq_unwrapping_a_one_element_list,
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
                                    compare_eq_unwrapping_a_one_element_list,
                                ))
                            } else {
                                results.push(match_value(
                                    each,
                                    Rc::clone(&r),
                                    compare_eq_unwrapping_a_one_element_list,
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
                                        compare_eq_unwrapping_a_one_element_list,
                                    ));
                                }
                            } else {
                                results.push(match_value(
                                    each.clone(),
                                    Rc::clone(&r.clone()),
                                    compare_eq_unwrapping_a_one_element_list,
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
                let mut unanswerable: Option<(Rc<PathAwareValue>, Rc<PathAwareValue>, Unanswered)> =
                    None;
                let mut without_a_match =
                    |from: &[Rc<PathAwareValue>], against: &[Rc<PathAwareValue>]| {
                        let mut unmatched = Vec::with_capacity(from.len());
                        'each: for each in from {
                            let mut refused: Option<(Rc<PathAwareValue>, Unanswered)> = None;
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
                                if let Some((other, unanswered)) = refused {
                                    unanswerable = Some((Rc::clone(each), other, unanswered));
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
                                            let reverse_diff = matched_elements(&lin);
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
                                            // ALL elements, and `matched_elements` is deliberately
                                            // not used here. A Success means the whole left-hand
                                            // list was contained, so every element is a value
                                            // `NOT IN` has to name; the helper answers the narrower
                                            // question "which elements did the right-hand side
                                            // match", which is what the Fail arm above wants.
                                            //
                                            // The two coincide only while every `ListIn` Success
                                            // path carries an empty diff, because with an empty diff
                                            // "absent from the diff" is "all of them".
                                            // `a_successful_list_containment_carries_an_empty_diff`
                                            // pins that, and its message names the two construction
                                            // sites: `contained_in`'s nested-right-hand Success arm
                                            // passes `vec![]`, and its all-flat Success arm passes a
                                            // `diff` it has just tested `is_empty()`.
                                            //
                                            // Substituting the helper was measured byte-identical
                                            // and rejected anyway: it would turn a visible
                                            // difference between two loops into a silent dependency
                                            // on that invariant, so a third Success path carrying a
                                            // non-empty diff would make this arm under-report which
                                            // values collide instead of failing a test.
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
