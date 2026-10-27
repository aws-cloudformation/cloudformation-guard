use std::cell::OnceCell;
use std::collections::HashSet;
use std::rc::Rc;

use crate::rules::errors::Error;
use crate::rules::eval_context::RhsEnumeration;
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
/// and the finding read "property B was not present in \[B\]" -- a claim refuted by the set it names.
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
    /// The left-hand values the operator accepted: compared, answered, and found to hold.
    ///
    /// Explicit rather than derived, because the three other sets cannot say it. A value the operator
    /// could not answer is in none of `diff`, `lhs_unmatched` or the empty collections -- it is reported
    /// through its own `NotComparable` result -- so "`lhs` minus the rejected" read it as accepted, and
    /// `some Values[*] IN <queried string>` over `[5, "other"]` passed on the `5` nothing could test.
    /// The `some` fold records a PASS for exactly these values, and nothing else may read as one.
    pub(crate) accepted: Vec<Rc<PathAwareValue>>,
    pub(crate) lhs: Vec<Rc<PathAwareValue>>,
    pub(crate) rhs: Vec<Rc<PathAwareValue>>,
    pub(crate) diff_from: DiffFrom,
    /// The resolved right-hand values no left-hand value equals, when the arm that built this result
    /// computed them: `Some` from the equality operator's two-query arm (the one arm that compares both
    /// ways; carried through the negation wrapper), `Some(empty)` meaning every resolved right-hand value
    /// found an equal; `None` from every other constructor, meaning NEVER COMPUTED, because right-hand
    /// extras are not a question those shapes ask.
    ///
    /// Read beside an undecidable marker among the right-hand values, where the two mismatches are not
    /// alike: a right-hand value with no equal on the left makes the sets unequal whatever the marker
    /// hides, so `==` is decided no; a left-hand value with no RESOLVED equal may be the value the marker
    /// hides, so with this set computed and empty the comparison is not decided by its resolved values.
    /// The two `Option` answers are different answers to `eval.rs`'s question beside such a marker under
    /// `==` ("may the resolved values still leave the two sets equal?"): a computed empty set says yes and
    /// leaves the clause to the marker, an uncomputed one says nothing and leaves the decided `Fail` as it
    /// stands; one collection for both would read "never computed" as "every value matched", and any
    /// further `==` path building a `QueryIn` would turn a decided no into a fail-closed gate.
    pub(crate) rhs_unmatched: Option<Vec<Rc<PathAwareValue>>>,
}

impl QueryIn {
    /// The same result with `rhs_unmatched` as given: `Some` for the arm that computed it, or the value
    /// another result carried, which the negation wrapper passes through unchanged.
    fn with_rhs_unmatched(mut self, rhs_unmatched: Option<Vec<Rc<PathAwareValue>>>) -> QueryIn {
        self.rhs_unmatched = rhs_unmatched;
        self
    }

    /// The ordinary case: the diff holds left-hand values that found nothing to match on the right.
    /// Every `IN` spelling produces this, and so does `==` whenever the reporter can place a left-hand
    /// value. Every value outside the diff is accepted, so an arm that refused some of its values
    /// leaves them out of `lhs` before building this, as the two-query `IN` arm does.
    fn new(
        diff: Vec<Rc<PathAwareValue>>,
        lhs: Vec<Rc<PathAwareValue>>,
        rhs: Vec<Rc<PathAwareValue>>,
    ) -> QueryIn {
        QueryIn {
            accepted: reverse_diff(diff.clone(), &lhs),
            lhs,
            rhs,
            lhs_unmatched: diff.clone(),
            diff,
            diff_from: DiffFrom::Lhs,
            rhs_unmatched: None,
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
            accepted: reverse_diff(diff.clone(), &lhs),
            lhs,
            rhs,
            lhs_unmatched: reverse_diff(collides, &diff),
            diff,
            diff_from: DiffFrom::Lhs,
            rhs_unmatched: None,
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
            // The diff holds right-hand values here, so `lhs_unmatched` is the record of which
            // left-hand values found no equal.
            accepted: reverse_diff(lhs_unmatched.clone(), &lhs),
            lhs,
            rhs,
            rhs_unmatched: Some(diff.clone()),
            diff,
            lhs_unmatched,
            diff_from: DiffFrom::Rhs,
        }
    }

    /// A literal list on the left of `IN`, decided element-wise against right-hand scalars, reported at
    /// whole-list granularity: the list is the verdict's one left-hand value, and `diff` names the
    /// elements with no equal on the right.
    ///
    /// One value, not the elements, so that `some` over the literal spelling answers as it does over a
    /// list-valued document value: a list that is not a subset gives `some` nothing to pass on, whichever
    /// of its elements happen to be present.
    ///
    /// `lhs_unmatched` is the list itself when none of its elements collides with the right-hand side,
    /// and empty when one does. The negation wrapper denies `lhs \ lhs_unmatched`, so `NOT IN` passes in
    /// the first case and fails in the second, naming the list. `QueryIn::new`'s `lhs_unmatched = diff`
    /// cannot say that for this shape: `diff` holds elements and `lhs` holds the list, a list is never
    /// equal to one of its elements, and the subtraction removed nothing, so `NOT IN` failed whatever
    /// the right-hand side held. An empty list has no element to collide, so it passes `IN` and fails
    /// `NOT IN` by the same construction.
    ///
    /// The list is accepted exactly when every element was found, which is when the diff is empty; a
    /// list with an element missing is not accepted, however many of its elements are present, so
    /// `some` over the literal spelling has nothing to pass on there.
    fn whole_list(
        diff: Vec<Rc<PathAwareValue>>,
        collides: bool,
        list: Rc<PathAwareValue>,
        rhs: Vec<Rc<PathAwareValue>>,
    ) -> QueryIn {
        let lhs_unmatched = if collides {
            Vec::new()
        } else {
            vec![Rc::clone(&list)]
        };
        let accepted = if diff.is_empty() {
            vec![Rc::clone(&list)]
        } else {
            Vec::new()
        };
        QueryIn {
            accepted,
            lhs: vec![list],
            rhs,
            diff,
            lhs_unmatched,
            diff_from: DiffFrom::Lhs,
            rhs_unmatched: None,
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
/// opposite of an empty `diff` rather than the same thing. The one input where both would be empty is a
/// left-hand list with no elements, and it does not arrive: `contained_in` answers Success for an empty
/// left-hand list in both of its branches, because the element-wise diff comes out empty and the subset
/// reading holds vacuously, and the two call sites below match on `Fail` only. `Empty NOT IN [[9]]` is
/// decided before the negation wrapper, and fails.
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

/// One pair's answer. IDENTITY CONTRACT, which `eval::accepted_left_values` and `eval::marker_pair_under_in`
/// rely on: a `Success` and a `RhsUnresolved` name the LEFT-hand value by the comparison's own `Rc` (a
/// `Rc::clone` of the value in the left operand, as `membership_in_entries` and the `QueryIn` constructors
/// pass it), never a fresh box holding the same value. Those readers key the values a resolved entry
/// accepted under a positive `IN` by `Rc::as_ptr`, and the marker's pair for such a value is dropped by
/// that key alone; a `Success` that reboxed its left value would read as a value no entry accepted, so the
/// marker's pair for it would keep a FAIL status beside the pass and the clause would fail closed on a
/// value a listed entry matched. An arm that expands a list into its elements carries each element's own
/// `Rc`, and an arm that answers for the whole left value carries the operand's.
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
    /// A value that is an empty collection, on either side, where the operator would have compared the
    /// collection's elements and so had nothing to compare.
    ///
    /// Emitted instead of nothing. The ordering operators flatten a list-valued value into its
    /// elements, and `==` against a scalar written in the rule walks them, so an empty list on its own
    /// would contribute no result at all and the clause would pass on a comparison that never ran:
    /// `Ports: []` would satisfy `Ports <= 100` and `Ports > 100` alike, and `%max >= Sizes` would hold
    /// over a `Sizes` of `[]`. Between two queries `==` and `!=` ask the comparator for each pair whole,
    /// so an empty document list against a scalar is a refusal of kinds there, in both polarities, and
    /// never this result; `IN` and `NOT IN` answer it once per resolved right-hand value
    /// (`empty_left_collection`) and the orderings once per empty collection.
    /// `docs/QUERY_AND_FILTERING.md` lists an empty collection beside a missing key and an empty map as
    /// a retrieval error, and the other two fail; this result is what makes the third fail too, per
    /// value and with the empty collection's own path, so the report names the resource whose
    /// collection was empty rather than a clause that compared nothing.
    ///
    /// Produced by `IN` and `NOT IN` too, for an empty left-hand collection against any right operand:
    /// there is no vacuous subset reading that would pass `[] IN <set>`, since an empty collection has
    /// nothing to be a member of anything with. Not produced where two lists are compared whole under
    /// `==`, so `Ports == []` still holds -- that is a comparison that happens, and this is only for the
    /// ones that did not.
    ///
    /// `empty` is the collection; `other` is one value from the other side it would have been compared
    /// with, for the report, and `None` when that side held no value to show, which with the
    /// unresolved values reported on their own leaves exactly the case where both sides were empty.
    EmptyCollection {
        side: EmptySide,
        empty: Rc<PathAwareValue>,
        other: Option<Rc<PathAwareValue>>,
    },
    ComparisonResult(ComparisonResult),
}

/// Which operand an [`ValueEvalResult::EmptyCollection`] was found on. The report wording differs,
/// and nothing else does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmptySide {
    Lhs,
    Rhs,
}

/// The empty collection in a pair of a DOCUMENT value that is an empty list and a value that is not a
/// list, as [`ValueEvalResult::EmptyCollection`] names it, with the other value beside it; `None` when
/// the pair is not that shape.
///
/// For the two arms of `==` that compare a literal against document values themselves rather than
/// through [`CommonOperator`], asked about the document side only. An empty collection is a fact about
/// the document -- `Ports: []` is a retrieval error like a missing `Ports` -- and a `[]` written in the
/// rule, inline or bound through `let`, is a value the author wrote and compares as one: against a scalar
/// the comparator refuses the kinds, as it does for `[1]`, and `[] == []` holds. Asked about both sides,
/// `when Properties.Mode == []` over a `Mode` of `"x"` and `let e = []` with `%e == "x"` are explained
/// as empty collections the document never held. Two lists are left to the
/// comparator either way: `Ports == []` is a comparison that happens, and it holds.
fn empty_document_list_against_a_scalar(
    document: &Rc<PathAwareValue>,
    other: &Rc<PathAwareValue>,
    side: EmptySide,
) -> Option<ValueEvalResult> {
    let is_empty_list =
        |value: &PathAwareValue| matches!(value, PathAwareValue::List((_, l)) if l.is_empty());
    let is_list = |value: &PathAwareValue| matches!(value, PathAwareValue::List(_));
    if is_empty_list(document) && !is_list(other) {
        return Some(ValueEvalResult::EmptyCollection {
            side,
            empty: Rc::clone(document),
            other: Some(Rc::clone(other)),
        });
    }
    None
}

/// `IN` for a `[]` written in the rule, inline or bound through `let`.
///
/// The list is a value the author wrote, not an empty collection the document resolved to, and a list
/// literal on the left of `IN` reads element-wise whatever the right-hand kind: a non-empty one holds
/// when some element is a member of a right-hand list, or equals a right-hand scalar, and the empty one
/// has no element, so it is a member of a right-hand list only when one of that list's elements is itself
/// an empty list, and a member of a scalar never. So `[] IN [80]` is false and `[] NOT IN [80]` true, as
/// `5 IN [80]` and `5 NOT IN [80]` are; `[] IN [[], 80]` holds; and `[] IN 80` is false with `[] NOT IN 80`
/// true, the same answers as for the list. Neither a vacuous subset reading over every empty left-hand
/// list, which would pass `[] IN [80]` over nothing, nor the empty-collection answer the document's
/// `Ports: []` gets, nor a refusal of kinds for a scalar right-hand value: the refusal stays with the
/// equality family, where a list against a scalar has no element-wise reading.
fn empty_list_literal_in(lhs: Rc<PathAwareValue>, rhs: Rc<PathAwareValue>) -> ValueEvalResult {
    let member = match &*rhs {
        PathAwareValue::List((_, elements)) => elements
            .iter()
            .any(|element| matches!(element, PathAwareValue::List((_, inner)) if inner.is_empty())),
        _ => false,
    };
    let pair = LhsRhsPair::new(lhs, rhs);
    ValueEvalResult::ComparisonResult(if member {
        ComparisonResult::Success(Compare::ValueIn(pair))
    } else {
        ComparisonResult::Fail(Compare::ValueIn(pair))
    })
}

/// The empty collection on the left of a membership test, as [`ValueEvalResult::EmptyCollection`]
/// names it, with the right-hand value it would have been tested against; `None` when the left value
/// is not an empty list.
///
/// For the two arms of `IN` whose left operand the DOCUMENT resolved, before any membership or
/// containment question is asked. An empty list is not read as vacuously a subset of whatever the right
/// operand denotes, which would pass `Ports IN [80]` over nothing and let `NOT IN` deny the nothing by
/// negation, and against a string haystack would skip the pairing and pass both polarities. The empty
/// collection is the same retrieval error on `IN` as on `==` and the ordering operators: the assertion
/// fails naming it, a `when` condition is not satisfied and its rule is not applicable, a filter
/// predicate deselects the entry. Whatever the right-hand value is, because the left has nothing to be
/// a member of anything with. A `[]` written in the rule is not a retrieval error and does not come
/// here; [`empty_list_literal_in`] compares it as the value it is.
fn empty_left_collection(
    lhs: &Rc<PathAwareValue>,
    rhs: &Rc<PathAwareValue>,
) -> Option<ValueEvalResult> {
    match &**lhs {
        PathAwareValue::List((_, list)) if list.is_empty() => {
            Some(ValueEvalResult::EmptyCollection {
                side: EmptySide::Lhs,
                empty: Rc::clone(lhs),
                other: Some(Rc::clone(rhs)),
            })
        }
        _ => None,
    }
}

/// The values on one side that are collections with no element and that the DOCUMENT resolved to.
///
/// A literal does not count: `let e = []` followed by `%e <= 100` arrives as `QueryResult::Literal`, and
/// a `[]` the author wrote is a value, not a retrieval error. The ordering operators flatten it into its
/// elements, of which it has none, so such a clause compares nothing and is explained at the block
/// level, where a document's `Ports: []` is named as the empty collection it is.
fn empty_collections(query_results: &[QueryResult]) -> Vec<Rc<PathAwareValue>> {
    query_results
        .iter()
        .filter_map(|each| match each {
            QueryResult::Resolved(value) => match &**value {
                PathAwareValue::List((_, list)) if list.is_empty() => Some(Rc::clone(value)),
                _ => None,
            },
            QueryResult::Literal(_) | QueryResult::UnResolved(_) => None,
        })
        .collect()
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
/// Both kinds record `NotComparable` and both fail an assertion closed. `binary_operation` tells them
/// apart for a *gate*: an undecidable gate becomes an error so the rule fails closed instead of being
/// skipped, and only [`Unanswerable::EngineGaveUp`] may be treated that way.
///
/// [`Unanswerable::IncomparableKinds`] must not be, because rule authors rely on a kind mismatch
/// answering "no". The registry idiom `ScanOnPush == 'False' OR ScanOnPush == false` writes a value
/// against both spellings it might carry, and reading the inapplicable pairing as unknown fails
/// compliant templates across the pinned aws-guard-rules-registry corpus. `docs/KNOWN_ISSUES.md`
/// tracks that suppression as a defect whose repair needs those rules changed first; this keeps the
/// boundary where it is. That cost belongs to the `==` path: `EqOperation` reaches none of the
/// membership machinery.
///
/// On the `IN` path a kind refusal is still discarded at three sites, each directly below an
/// `Err(err @ Error::RegexError(_))` arm, so each receives `NotComparable` and nothing else:
/// `is_one_of_observed`'s `Err(_)` arm (the list-against-list walk, in both of its readings),
/// `contained_in`'s scalar-against-list loop, and the `(None, None)` arm of `InOperation::compare`,
/// which drops `contained_in`'s result through a `_ => {}`. The three are in series: the scalar loop
/// manufactures the `NotComparable` the `(None, None)` arm records. So the verdicts a fail-closed build
/// moves cannot be priced per site and then summed or unioned; a plan prices the combination it intends
/// to take, measured at its own tip. `incomparable_membership` in `eval.rs` is the one-release warning
/// for the clauses that pass on such a refusal.
///
/// That predicate is a separate function on purpose. Carrying "no match, something refused, do not fail
/// closed" through the result types would be the very "refused but passing" state this enum was split to
/// keep out of them, and under `some` one passing value carries a clause while a sibling's refusal sits
/// in the results, so the result set alone cannot say whether a passing clause refused anything. The
/// predicate observes the operator's own functions (`membership_stops_after`,
/// `membership_pairing_refused`, `compare_eq_for_membership`) rather than re-deriving the walk, which
/// is what keeps the two from drifting.
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
/// [`NotComparable`]. Were those hops to carry a bare `String`, a site that wanted the cause would have
/// to re-derive it from the wording -- which is a classifier that goes silently wrong the first time a
/// message is reworded.
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

/// `IN`, carrying the one fact about the right-hand side that its resolved values cannot: whether the
/// query that produced them enumerated a collection.
///
/// `pub(super)` because `binary_operation` in `eval.rs` builds it directly for `IN` with the shape the
/// retrieval reported, where every other operator goes through `CmpOperator`. `CmpOperator::In.compare`
/// builds it with the flag off, which is the reading every caller carrying no shape keeps.
pub(super) struct InOperation {
    /// Where the right-hand query enumerates a collection it passes through -- `[*]`, `.*`, a filter --
    /// if anywhere. When it does, the resolved right-hand values are the entries of ONE set and the
    /// comparison is the one the written-out list gets: `contained_in` against `entry_set(..)`,
    /// membership for a scalar and subset for a list; when the enumeration is not the query's last part,
    /// a list-valued result is a list of candidates and its members join the set. When it does not
    /// enumerate, each resolved string is a haystack and containment is asked first. `Names` for a
    /// right-hand side that is a literal or whose shape the caller does not know.
    pub(super) rhs_enumerates: RhsEnumeration,
    /// The entry sets of an enumerating right-hand side, built once by [`InOperation::shaped_with`] from the
    /// same resolved values `compare` receives, so the comparison and the notice predictor in `eval.rs`
    /// read one build rather than each making their own. `None` when the right-hand side names its
    /// value, or when the operator was built without its values.
    candidates: Option<Rc<EntryCandidates>>,
}

impl InOperation {
    /// `IN` with no shape: every resolved right-hand string is a haystack, as `CmpOperator::In` reads it.
    pub(super) fn named() -> InOperation {
        InOperation {
            rhs_enumerates: RhsEnumeration::Names,
            candidates: None,
        }
    }

    /// `IN` with the shape the retrieval of `rhs` reported, its entry sets built here, once, from the
    /// resolved values of `rhs`; `compare` must then be handed the same `rhs`. The tests' constructor;
    /// `binary_operation` goes through [`InOperation::shaped_with`] and the evaluation's cache.
    #[cfg(test)]
    pub(super) fn shaped(rhs_enumerates: RhsEnumeration, rhs: &[QueryResult]) -> InOperation {
        Self::shaped_with(rhs_enumerates, rhs, |values, shape| {
            Rc::new(EntryCandidates::new(values, shape))
        })
    }

    /// `InOperation::shaped` with the entry sets supplied by `build`, which `binary_operation` points
    /// at the evaluation's cache (`EvalContext::entry_candidates`): a type block or a filter evaluates
    /// one clause once per resource against the same resolved right-hand side, and the sets are built
    /// once per distinct right-hand side rather than once per resource.
    pub(super) fn shaped_with(
        rhs_enumerates: RhsEnumeration,
        rhs: &[QueryResult],
        build: impl FnOnce(Vec<Rc<PathAwareValue>>, RhsEnumeration) -> Rc<EntryCandidates>,
    ) -> InOperation {
        let candidates = rhs_enumerates
            .is_entry_set()
            .then(|| build(selected(rhs, |_| {}, Vec::push), rhs_enumerates));
        InOperation {
            rhs_enumerates,
            candidates,
        }
    }

    /// The entry sets this operator compares against, for the notice predictor: `Some` exactly when the
    /// right-hand side enumerates and the operator was built with its values.
    pub(super) fn candidates(&self) -> Option<&EntryCandidates> {
        self.candidates.as_deref()
    }

    /// The sets `compare` reads: the ones built at construction, or, for an operator built without its
    /// values, built now from the values it was handed.
    fn candidates_for(&self, rhs_values: &[Rc<PathAwareValue>]) -> Rc<EntryCandidates> {
        match &self.candidates {
            Some(candidates) => Rc::clone(candidates),
            None => Rc::new(EntryCandidates::new(
                rhs_values.to_vec(),
                self.rhs_enumerates,
            )),
        }
    }
}

/// The one set an enumerating right-hand query denotes: its resolved values as the elements of a list.
///
/// `Allowed.Types[*]` over `[gp2, gp3]` resolves to two strings, and the question `IN` asks of them is
/// the question `IN ["gp2", "gp3"]` asks of the written-out list, so the values are put back into a list
/// and handed to the same `contained_in`.
///
/// `members_of_lists` flattens a list-valued result one level: a list of candidates rather than one
/// candidate. For a scalar on the left that is the reading whichever part enumerated, because a scalar is
/// never a member of a list: `Resources.*[ Type == 'Custom::Policy' ].Properties.AllowedTypes` resolves
/// to the one list each policy holds, and taking that list as one entry made `VolumeType IN %allowed`
/// refuse `gp2` on kinds (a string against a list) where the named spelling `Resources.Policy.Properties
/// .AllowedTypes` admitted it; with the members joined, the two agree, and so do `Mappings.X.*.List`,
/// `Parameters.*.AllowedValues` and `Mappings.TypesByRegion.*`. For a list on the left it is the reading
/// of an earlier-part enumeration only ([`RhsEnumeration::flattens_lists`]), where a list-valued result
/// is what one enumerated member holds at the key that followed; under a last-part enumeration
/// (`Denies[*]` over `[[1, 3]]`, `Mappings.DenyGroups.*`) each list result is one entry as it is, as it
/// is in the written-out list of lists, and a list on the left is compared against those whole entries.
///
/// Called by [`EntryCandidates`] on first use of each set it holds and never again for that set, and
/// each call is a deep copy of the entries into a new list, because `contained_in` takes one
/// `PathAwareValue::List` and the resolved results arrive as separate `Rc`s. A scalar on the left never
/// calls it: its membership is read off the results in place (`EntryCandidates::member_refs`). Nothing
/// else in the membership path copies an entry, and `take_entry_copies` counts the copies under test.
fn entry_set<'a>(
    values: impl Iterator<Item = &'a Rc<PathAwareValue>>,
    members_of_lists: bool,
) -> Rc<PathAwareValue> {
    let mut entries = Vec::new();
    for value in values {
        match &**value {
            PathAwareValue::List((_, members)) if members_of_lists => {
                entries.extend(members.iter().cloned())
            }
            entry => entries.push(entry.clone()),
        }
    }
    #[cfg(test)]
    ENTRY_COPIES.with(|copies| copies.set(copies.get() + entries.len()));
    Rc::new(PathAwareValue::List((Path::root(), entries)))
}

#[cfg(test)]
thread_local! {
    /// Entries deep-copied into entry sets by [`entry_set`] on this thread, for the test that pins the
    /// copies at one per distinct right-hand side per evaluation rather than one per resource.
    static ENTRY_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The number of entries [`entry_set`] has copied on this thread since the last call, which resets it.
#[cfg(test)]
pub(crate) fn take_entry_copies() -> usize {
    ENTRY_COPIES.with(|copies| copies.replace(0))
}

/// The sets an enumerating right-hand query denotes, built ONCE per distinct resolved right-hand side in
/// an evaluation (`EvalContext::entry_candidates` keeps them by the identity of the resolved `Rc`s, so a
/// type block or a filter evaluating one clause once per resource against one `let`-bound allowlist
/// shares one of these) and read for every left-hand value. Each set is built on its first use and then
/// kept, so a clause with a scalar on the left, the common allowlist, copies no entry at all: the
/// members are read off the results in place. Everything else is an `Rc` clone.
///
/// A scalar on the left is a member of the flattened members, whatever the shape: a scalar is never a
/// member of a list, so the lists an enumeration hands back can only be lists of candidates for it.
/// A list on the left is a SUBSET question. Under an earlier-part enumeration it is asked of one
/// list-valued result at a time, as it was in the pairing loop, because pooling tuples admits what no
/// tuple allows -- with `Combos: {a: {Pair: [s1, g1]}, b: {Pair: [s2, g2]}}`, `Pair IN
/// Mappings.Combos.*.Pair` must refuse `[s1, g2]`, a subset of the pool and of neither pair -- and of
/// the SCALAR results pooled into one set, because a projection of scalars IS the written-out list of
/// them: `VolumeTypes IN Mappings.Allowed.Entries[*].Name` with `[gp2, gp3]` against names `gp2`, `gp3`
/// holds as `IN ["gp2", "gp3"]` holds, and so does `IN Resources.*[ Type == 'Custom::Policy' ]
/// .Properties.AllowedTypes` over two policies whose `AllowedTypes` are the scalars `gp2` and `gp3`,
/// where two policies holding `[gp2]` and `[gp3]` refuse it (a subset of neither list). The whole-entry
/// reading guards the nested-denylist bypass, and that bypass lives in list entries. Under a last-part
/// enumeration the question is asked of the whole entries, exactly as the written-out list of lists is
/// compared, so `Pair IN Mappings.Pairs.List[*]` holds for `[s1, g1]` and not for the permuted `[g1, s1]`
/// or the partial `[s1]`, `Nest: [1, [9]] NOT IN DenyNestedNine[*]` over `[[9]]` is denied for the entry
/// `[9]` it holds, as `NOT IN [[9]]` denies it, and `Ports: [22, 80] NOT IN Mappings.DenyGroups.*` over
/// `{ssh: [22], rdp: [3389]}` passes as `NOT IN [[22], [3389]]` does. The headline rule -- an enumerating
/// query is compared exactly as the list literal its results would spell out -- is the oracle.
///
/// The two polarities are deliberately asymmetric for that list on the left. `IN` admits only a subset
/// of some single set, so an allowlist of pairs is not widened to their pool. `NOT IN` denies when any
/// left-hand element is a member of the union of all results' members, which is what the pairing loop
/// and the named spelling do: `Protocols: [ssh, tcp] NOT IN Resources.*[ Type == 'Custom::Policy' ]
/// .Properties.DeniedTypes` over `DeniedTypes: [ssh]` is denied for the `ssh` it holds, exactly as
/// `NOT IN Resources.Policy.Properties.DeniedTypes` denies it. Reading the collision per result instead
/// opened that denylist (`[ssh, tcp]` is a subset of no result, and shares one element with one), which is
/// the unsafe direction for a denylist, so both polarities are the fail-closed reading: a list is in only
/// when some set holds all of it, and out only when no result holds any of it. Under a last-part
/// enumeration the collision set is the whole entries, as it is for the written-out list of pairs:
/// `[1, 2] NOT IN Denies[*]` over `[[1, 3]]` collides with nothing, as `NOT IN [[1, 3]]` does.
pub(crate) struct EntryCandidates {
    /// The resolved right-hand values as they came, `Rc` clones and nothing copied: what every set below
    /// is built from, and the identity `same_values` keys the per-evaluation cache on.
    values: Vec<Rc<PathAwareValue>>,
    /// Where the right-hand query enumerated, which decides how a list on the left reads the results.
    shape: RhsEnumeration,
    /// Every entry with list-valued results flattened one level, as one list, built on first use: the
    /// collision set for a list on the left under an earlier-part enumeration, and the set the notice
    /// predictor replays a scalar's walk against. A scalar on the left itself reads the members in place
    /// (`member_refs`) and never builds this. `Port NOT IN Mappings.DenyGroups.*` over `{ssh: [22], rdp:
    /// [3389]}` denies `22`, and `VolumeType IN Mappings.TypesByRegion.*` over `{useast1: [gp2]}` admits
    /// `gp2`, because a scalar is never a member of a list and the lists the enumeration handed back are
    /// the lists of candidates.
    members: OnceCell<Rc<PathAwareValue>>,
    /// Every result as it came, as one list, built on first use: the set a list on the left is a
    /// whole-entry member or a subset of under a last-part enumeration (`Pairs.List[*]` matches whole
    /// pairs, as the written-out list of pairs does), and its collision set there. The same `Rc` as
    /// `members` when no result is a list.
    entries: OnceCell<Rc<PathAwareValue>>,
    /// Under an earlier-part enumeration only, the scalar results pooled into one set, built on first
    /// use by a list on the left: the written-out list a projection of scalars spells out. The
    /// list-valued results stand beside it as sets of their own, uncopied.
    scalars: OnceCell<Rc<PathAwareValue>>,
}

impl EntryCandidates {
    /// Keeps the resolved values (`Rc` clones) and the shape; every set is built on its first use.
    pub(crate) fn new(values: Vec<Rc<PathAwareValue>>, shape: RhsEnumeration) -> EntryCandidates {
        EntryCandidates {
            values,
            shape,
            members: OnceCell::new(),
            entries: OnceCell::new(),
            scalars: OnceCell::new(),
        }
    }

    /// Whether these are the sets of exactly these resolved values under this shape: the same `Rc`s in
    /// the same order. Identity and not equality, so two allowlists that happen to hold the same strings
    /// at different paths are two entries in the cache, and the `Rc`s held here keep the addresses from
    /// being reused for as long as the cache lives.
    pub(crate) fn same_values(&self, values: &[Rc<PathAwareValue>], shape: RhsEnumeration) -> bool {
        self.shape == shape
            && self.values.len() == values.len()
            && self
                .values
                .iter()
                .zip(values)
                .all(|(mine, theirs)| Rc::ptr_eq(mine, theirs))
    }

    /// The members a scalar on the left is asked to be one of, read off the results in place: every
    /// scalar result, and every element of a list-valued result.
    fn member_refs(&self) -> Vec<&PathAwareValue> {
        let mut members = Vec::with_capacity(self.values.len());
        for value in &self.values {
            match &**value {
                PathAwareValue::List((_, elements)) => members.extend(elements.iter()),
                scalar => members.push(scalar),
            }
        }
        members
    }

    /// The flattened members as one list, copied on first use.
    fn members_list(&self) -> &Rc<PathAwareValue> {
        self.members
            .get_or_init(|| entry_set(self.values.iter(), true))
    }

    /// The whole entries as one list, copied on first use; the members list itself when no result is a
    /// list, because the two are then the same list.
    fn entries_list(&self) -> &Rc<PathAwareValue> {
        self.entries.get_or_init(|| {
            if self.values.iter().any(|value| value.is_list()) {
                entry_set(self.values.iter(), false)
            } else {
                Rc::clone(self.members_list())
            }
        })
    }

    /// The scalar results pooled into one list, copied on first use; `None` when every result is a list.
    fn scalar_pool(&self) -> Option<&Rc<PathAwareValue>> {
        if self.values.iter().all(|value| value.is_list()) {
            return None;
        }
        Some(
            self.scalars.get_or_init(|| {
                entry_set(self.values.iter().filter(|value| !value.is_list()), false)
            }),
        )
    }

    /// The sets `lhs` has to be in -- a member of, for a scalar; a subset of, for a list -- for `IN` to
    /// hold: the flattened members for a scalar (as one list, for the predictor's replay; the operator
    /// itself reads `member_refs`), the pooled scalars and then each list-valued result for a list under
    /// an earlier-part enumeration, the whole entries for a list under a last-part one.
    pub(super) fn membership_sets(&self, lhs: &PathAwareValue) -> Vec<Rc<PathAwareValue>> {
        if !lhs.is_list() {
            vec![Rc::clone(self.members_list())]
        } else if self.shape.flattens_lists() {
            let mut sets = Vec::with_capacity(self.values.len() + 1);
            if let Some(pool) = self.scalar_pool() {
                sets.push(Rc::clone(pool));
            }
            sets.extend(self.values.iter().filter(|value| value.is_list()).cloned());
            sets
        } else {
            vec![Rc::clone(self.entries_list())]
        }
    }

    /// The set whose members a list on the left collides with for `NOT IN`: every element of every result
    /// under an earlier-part enumeration, every whole entry under a last-part one.
    pub(super) fn collision_set(&self) -> &Rc<PathAwareValue> {
        if self.shape.flattens_lists() {
            self.members_list()
        } else {
            self.entries_list()
        }
    }

    /// The sets the operator DECIDED `lhs` on, in the order it compared them, for the notice predictor in
    /// `eval.rs`: the walk [`membership_in_entries`] makes, replayed by the same function. A set the
    /// operator never reached -- one after a match -- is not here, so a refusal it would have raised is
    /// not counted; and a value some set held was decided by that match, so nothing is here for it at
    /// all, a refusal an earlier set raised being a refusal seen before a match, which earns no notice
    /// on the pairing path either (`is_one_of_observed`).
    pub(super) fn sets_compared(&self, lhs: &Rc<PathAwareValue>) -> Vec<Rc<PathAwareValue>> {
        let walk = walk_entries(lhs, self, true);
        match walk.outcome {
            WalkOutcome::Matched => Vec::new(),
            WalkOutcome::Refused(_) | WalkOutcome::Missed { .. } => walk.compared,
        }
    }
}

/// What one walk of [`membership_in_entries`] decided and which sets it compared on the way.
struct Walk {
    outcome: WalkOutcome,
    compared: Vec<Rc<PathAwareValue>>,
}

enum WalkOutcome {
    /// Some membership set held the value, and the walk stopped there.
    Matched,
    /// No set held it and some set refused to say; the refusal is the one to report.
    Refused(ValueEvalResult),
    /// No set held it and none refused; `collides` says whether a list on the left shares an element
    /// with the collision set, which is what `NOT IN` denies on.
    Missed { collides: bool },
}

/// How a scalar on the left stands to the members of the entry set.
enum ScalarMembership {
    /// Some member equals it.
    Member,
    /// No member equals it, and at least one member was comparable with it and answered no.
    NotAMember,
    /// No member equals it and the question had no answer: a regex whose budget ran out (reported
    /// first, as `contained_in` reports it), or no member comparable with it at all. Carries the member
    /// the refusal is about, so the report names an entry at its own path.
    Refused(Rc<PathAwareValue>, Unanswered),
}

/// Whether a scalar on the left is one of the members, asking the pairs `contained_in`'s scalar arm asks
/// in the order it asks them, and refusing where that arm answers no.
///
/// That arm turns a pair of kinds `compare_eq` has no arm for into a plain miss (`Err(_) => {}`), which is
/// right for the written-out list it was built for -- a denylist written beside values of another kind
/// is ordinary -- and wrong for the enumerating query, where it opened the unsafe direction: an
/// `InstanceType` of `!Ref TypeParam` (a map) or a `FromPort` of `22` (an int) against enumerated
/// strings compared with nothing, was read as not a member, and `NOT IN` passed it, where the pairing
/// loop it replaced raised a refusal (`found_in_string` answered `NotAString`) and failed closed in both
/// polarities. So a value no STRING member could be compared with is refused here, as it was there; a
/// value some member could be compared with and none equals is not a member, as `80` is not a member of
/// `[22, "ssh"]`; and a value against members of another non-string kind is a miss, as it was there and
/// is for the written-out list (`"" NOT IN D13[*]` over `[1, 3]` passes).
fn scalar_membership<'a>(
    value: &PathAwareValue,
    members: impl Iterator<Item = &'a PathAwareValue>,
) -> ScalarMembership {
    // The first refusal of each kind, with the member it was raised against; `unanswerable_reason`
    // classifies the error as every other refusing site does. The member is copied only into a refusal.
    let mut budget_spent: Option<(&'a PathAwareValue, Error)> = None;
    let mut kinds_refused: Option<(&'a PathAwareValue, Error)> = None;
    let mut answered = false;
    for member in members {
        if member == value {
            return ScalarMembership::Member;
        }
        match compare_eq(value, member) {
            Ok(true) => return ScalarMembership::Member,
            Ok(false) => answered = true,
            Err(err @ Error::RegexError(_)) => {
                if budget_spent.is_none() {
                    budget_spent = Some((member, err));
                }
            }
            // A refusal only against a STRING member, which is the pairing the loop this replaces
            // refused (`found_in_string` answering `NotAString` for a non-string left against a string
            // haystack). A string or a map against an int entry was a plain miss there, as it is for the
            // written-out list, so `"" NOT IN D13[*]` over `[1, 3]` keeps passing beside `"" NOT IN
            // [1, 3]`.
            Err(err) if matches!(member, PathAwareValue::String(_)) => {
                if kinds_refused.is_none() {
                    kinds_refused = Some((member, err));
                }
            }
            Err(_) => {}
        }
    }
    if let Some((member, err)) = budget_spent {
        return ScalarMembership::Refused(Rc::new(member.clone()), unanswerable_reason(err));
    }
    match (answered, kinds_refused) {
        (false, Some((member, err))) => {
            ScalarMembership::Refused(Rc::new(member.clone()), unanswerable_reason(err))
        }
        _ => ScalarMembership::NotAMember,
    }
}

/// The one walk both the operator and the notice predictor make: for a scalar on the left, the members
/// once, read in place; for a list on the left, each membership set in order, stopping at the first that
/// holds the value, then, when no set held it and no set refused, the collision set, unless it was the
/// one set already walked. `record_sets` is the predictor's: it wants the sets walked, as lists, and
/// for a scalar that list is a copy the operator itself never needs, so the operator passes `false`.
fn walk_entries(
    value: &Rc<PathAwareValue>,
    candidates: &EntryCandidates,
    record_sets: bool,
) -> Walk {
    if !value.is_list() {
        let compared = if record_sets {
            vec![Rc::clone(candidates.members_list())]
        } else {
            Vec::new()
        };
        let outcome = match scalar_membership(value, candidates.member_refs().into_iter()) {
            ScalarMembership::Member => WalkOutcome::Matched,
            ScalarMembership::NotAMember => WalkOutcome::Missed { collides: false },
            ScalarMembership::Refused(member, unanswered) => {
                WalkOutcome::Refused(not_comparable_because(Rc::clone(value), member, unanswered))
            }
        };
        return Walk { outcome, compared };
    }
    let sets = candidates.membership_sets(value);
    let mut compared = Vec::with_capacity(sets.len() + 1);
    let mut matched_some_element = false;
    let mut refused: Option<ValueEvalResult> = None;
    for set in sets {
        compared.push(Rc::clone(&set));
        match contained_in(Rc::clone(value), Rc::clone(&set)) {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) => {
                return Walk {
                    outcome: WalkOutcome::Matched,
                    compared,
                };
            }
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ListIn(lin))) => {
                matched_some_element |= !matched_elements(&lin).is_empty();
            }
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_)) => {}
            refusal => {
                refused.get_or_insert(refusal_names_an_entry(refusal, &set));
            }
        }
    }
    if let Some(refusal) = refused {
        return Walk {
            outcome: WalkOutcome::Refused(refusal),
            compared,
        };
    }
    let collision = candidates.collision_set();
    let collision_walked = compared.len() == 1 && Rc::ptr_eq(&compared[0], collision);
    let collides = value.is_list()
        && if collision_walked {
            matched_some_element
        } else {
            compared.push(Rc::clone(collision));
            match contained_in(Rc::clone(value), Rc::clone(collision)) {
                ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) => true,
                ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ListIn(lin))) => {
                    !matched_elements(&lin).is_empty()
                }
                _ => false,
            }
        };
    Walk {
        outcome: WalkOutcome::Missed { collides },
        compared,
    }
}

/// A refusal `contained_in` reports against a membership set names the set it was handed, a list built
/// here at the root path and holding every entry, which the report would then print whole at
/// `[L:0,C:0]`. Re-pointed at the entry that refused -- the first member a left-hand element met with a
/// regex whose backtracking budget ran out, found by asking `compare_eq` the pairs the list walk asked --
/// which carries its own path, so the refusal names something the author can find; the reason and the
/// cause are the refusal's own. When no such member is found the set is left as it was: naming no entry
/// rather than a wrong one.
fn refusal_names_an_entry(refusal: ValueEvalResult, set: &Rc<PathAwareValue>) -> ValueEvalResult {
    match refusal {
        ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(mut refused))
            if Rc::ptr_eq(&refused.pair.rhs, set) =>
        {
            if let PathAwareValue::List((_, entries)) = &**set {
                if let Some(index) = refusing_entry_index(&refused.pair.lhs, entries) {
                    refused.pair.rhs = Rc::new(entries[index].clone());
                }
            }
            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(refused))
        }
        other => other,
    }
}

/// The index of the first entry a left-hand value (or, for a list, one of its elements) meets with a regex
/// the engine cannot evaluate, in the order `contained_in` pairs them; `None` when every pairing has an
/// answer, which is when the refusal did not come from these pairings.
fn refusing_entry_index(lhs: &PathAwareValue, entries: &[PathAwareValue]) -> Option<usize> {
    let elements: Vec<&PathAwareValue> = match lhs {
        PathAwareValue::List((_, elements)) => elements.iter().collect(),
        scalar => vec![scalar],
    };
    for element in elements {
        for (index, entry) in entries.iter().enumerate() {
            if let Err(Error::RegexError(_)) = compare_eq(element, entry) {
                return Some(index);
            }
        }
    }
    None
}

/// One left-hand value against the entries an enumerating right-hand query denotes, reported as the
/// `QueryIn` the pairing loop reports, so a failure names the entries with their paths, and the
/// resource-grouped report truncates a long allowlist with a total
/// (`a_long_in_comparison_is_truncated_with_a_total` pins that rendering). Both `InOperation` arms that
/// see an enumerating query call this: the query-vs-query arm once per left-hand value, and the
/// literal-left arm for its one value, so `%needle IN Types[*]` names each entry at its own path too.
///
/// The answer is `contained_in` against each membership set of [`EntryCandidates`]: a match in any set
/// is a match; no match is a failure, which collides for `NOT IN` when the value is a list and some
/// element of it is a member of the collision set (`[gp2, io1]` against the names `gp2`, `gp3`;
/// `[ssh, tcp]` against a policy's `[ssh]`); and a refusal `contained_in` itself reports -- a regex it
/// could not evaluate -- is passed through as the `NotComparable` it is when no set matched, so it
/// fails closed in both polarities, as for the written-out list.
pub(super) fn membership_in_entries(
    value: &Rc<PathAwareValue>,
    rhs_selected: &[Rc<PathAwareValue>],
    candidates: &EntryCandidates,
) -> ValueEvalResult {
    let lhs = vec![Rc::clone(value)];
    match walk_entries(value, candidates, false).outcome {
        WalkOutcome::Matched => ValueEvalResult::ComparisonResult(ComparisonResult::Success(
            Compare::QueryIn(QueryIn::new(vec![], lhs, rhs_selected.to_vec())),
        )),
        WalkOutcome::Refused(refusal) => refusal,
        WalkOutcome::Missed { collides } => {
            let query_in = if collides {
                QueryIn::partly_matched(lhs.clone(), lhs.clone(), lhs, rhs_selected.to_vec())
            } else {
                QueryIn::new(lhs.clone(), lhs, rhs_selected.to_vec())
            };
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(query_in)))
        }
    }
}

/// The two answers a comparison has before it looks at any value, shared by `CmpOperator::compare` and
/// `InOperation::compare` so that `IN` built directly answers them the same way the dispatch does.
///
/// An empty left-hand side means the query selected nothing, so the clause has nothing to say about
/// this input. That is genuinely inapplicable -- it is what lets one ruleset run against templates that
/// do not all contain the resource type being checked (`docs/QUERY_AND_FILTERING.md` describes this for
/// filters) -- and it stays a SKIP, checked first so it keeps precedence when both sides are empty. An
/// empty right-hand side is a different situation and does not share that outcome: there ARE values on
/// the left to check, but the reference they would be compared against resolved to nothing. Whether that
/// is a pass or a failure depends on the polarity of the comparison, so it is reported as `EmptyRhs` and
/// the `(C, bool)` wrapper decides.
fn nothing_to_compare(lhs: &[QueryResult], rhs: &[QueryResult]) -> Option<EvalResult> {
    if lhs.is_empty() {
        return Some(EvalResult::Skip);
    }

    if rhs.is_empty() {
        return Some(EvalResult::EmptyRhs);
    }

    None
}

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
    // A list is expanded into its elements, each boxed ONCE here so every result filed for the element,
    // the marker's pair included, carries that element's own `Rc`; every other value is carried as the
    // operand's own `Rc`: the identity contract `ComparisonResult` states. Re-boxed per value, no left
    // value the orderings answered was the operand's by address, so the readers of a result's left value
    // by address (`eval::compared_left_values`, `eval::accepted_left_values`, the marker's pair for an
    // empty list) never found it.
    selected(query_results, c, |into, p| {
        if let PathAwareValue::List((_, list)) = &*p {
            into.extend(list.iter().cloned().map(Rc::new));
        } else {
            into.push(p);
        }
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
        // Flattening an empty list leaves nothing in the flattened sets for it, so the empty
        // collections on both sides are answered separately below. See
        // `ValueEvalResult::EmptyCollection`.
        let lhs_empty = empty_collections(lhs);
        let rhs_empty = empty_collections(rhs);
        let mut rhs_unresolved = false;
        let rhs_flattened = flattened(rhs, |ur| {
            rhs_unresolved = true;
            // Every left-hand value, the empty collections included: an unresolved right-hand side
            // is reported against each of them, and that record is the whole verdict for an empty
            // left-hand collection -- the empty-collection result below is withheld when the
            // right-hand side resolved to nothing but unresolved entries, so one finding is filed
            // rather than two about the same value.
            results.extend(lhs_flattened.iter().chain(&lhs_empty).map(|lhs| {
                ValueEvalResult::ComparisonResult(ComparisonResult::RhsUnresolved(
                    ur.clone(),
                    lhs.clone(),
                ))
            }))
        });
        let rhs = &rhs_flattened;
        if !(rhs_unresolved && rhs.is_empty() && rhs_empty.is_empty()) {
            for empty in lhs_empty {
                results.push(ValueEvalResult::EmptyCollection {
                    side: EmptySide::Lhs,
                    empty,
                    other: rhs.first().cloned(),
                });
            }
        }
        // An empty collection on the right fails each left-hand value it would have been compared
        // with, the mirror of the above; the empty collection is the subject either way.
        for empty in &rhs_empty {
            for each_lhs in &lhs_flattened {
                results.push(ValueEvalResult::EmptyCollection {
                    side: EmptySide::Rhs,
                    empty: Rc::clone(empty),
                    other: Some(Rc::clone(each_lhs)),
                });
            }
        }
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
/// answer. None of them is a reason to stop the run, so none of them may reach a panic: with
/// `RegexError` unhandled and an `unreachable!()` catch-all, a rules file with one unevaluatable
/// regex would abort the process at exit 101 and take every other rule's verdict with it.
///
/// The two reachable variants today are `NotComparable`, from `compare_values` under all five
/// comparators, and `RegexError`, from `compare_eq` alone. Anything else still reports rather than
/// aborts, because a wrong-looking message beats no verdict at all.
/// Returns the cause beside the reason. Only this function sees the `Error`, so it is the one place
/// that can classify without guessing, and every reason reaching a [`NotComparable`] from an error
/// comes through here.
/// `pub(crate)` so the map-key path -- `map_key_refusal` in `eval.rs`, and through it
/// `key_filter::select_key`, which the evaluator and the legacy resolver both ask -- can classify with
/// this one rather than growing a
/// second copy. A path that propagates anything that is not `NotComparable` lets a spent backtracking
/// budget in `[ keys <op> ... ]` reach `main` and exit 255.
pub(crate) fn unanswerable_reason(err: Error) -> Unanswered {
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
/// Two arms do NOT ask it, on purpose. A literal scalar against a query list, and a query list against
/// a literal scalar, walk the list and compare element by element with `compare_eq_symmetric`, so a
/// one-element list already answers as its element does -- the expansion is their unwrap. Asking this
/// as well unwrapped a nested one-element element a second time, and `LL == "a"` held for an `LL` of
/// `[["a"]]` where the literal spelling `%ll == "a"` was refused.
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
/// An empty left-hand list never reaches this: every arm of `IN` answers an empty left-hand collection as
/// the retrieval error it is before asking containment, as `==` and the ordering operators do. Empty is
/// still `NoneFound` rather than unanswerable here, so that an empty list nested as an ELEMENT of a
/// non-empty left-hand list, which does reach this, keeps its existing answer and no cell this is not
/// about moves.
///
/// A non-string, non-list left-hand value is answered here too, as `NotAString`, and the argument for
/// leaving it out checks against the wrong spelling. That argument runs: `contained_in` already asks
/// `compare_eq` for such a value and gets "not comparable", so `%int in Haystack` and
/// `%int not in Haystack` both fail already. That is true of the `(Some, None)` arm, which is where a
/// literal needle goes: `substring_or_contained_in` there falls through to `contained_in` per result and
/// the incomparable answer is the clause's answer. The `(None, None)` arm keeps one verdict for the
/// whole left-hand operand set and only treats `contained_in`'s *Success* as a match, so an incomparable
/// pairing left to it is indistinguishable from a miss, joins the unmatched diff, and negates to a pass.
/// With `Haystack: "aws:arn:s3::${s3}"`, none of these would be denied, and the fourth is why the row
/// above does not call them scalars:
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
    /// The reason is not "a scalar holds nothing", which a `Map` refutes. Only `List` is
    /// decomposed here, so `Map` arrives at the same arm as `Null`, `Bool`, `Int`, `Float`, `Char`,
    /// `Regex` and the three range kinds, and `{"a": 1}` plainly holds something.
    /// `denied_map_query_needle_query_haystack` in
    /// `substring_in_answers_the_same_against_a_query_as_against_a_literal` is that cell. The message it
    /// produces is accurate -- `Value={"a":1} is not a string, so it cannot be tested for
    /// containment in ...`, at exit 19 -- for this reason and not the scalar one.
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

        // Bound as `not_a_list` rather than `scalar`: a `Map` arrives here, so a name claiming a scalar
        // would describe a subset of what the arm receives.
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
/// `PartialEq` and then `compare_eq`, the idiom the scalar-left-hand arm of `contained_in` uses, and
/// here for the reason it gives there. `Vec::contains` decides membership with
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
/// Measured on rustc 1.77.2, by replacing the `Err(_) => {}` arm below with
/// `Err(e) => panic!("{:?}", e)` and running `cargo test --lib`: 85 of the 1220 lib tests redden, one
/// recorded error each, and all 85 are `NotComparable` from that fall-through. So this is not an
/// unreachable arm kept for safety.
///
/// Read that figure as a census of the test corpus on a dated commit, because that is what it is. It read
/// 58 when it was written, and 40 of today's 85 are cells of
/// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names` with 15 more from
/// `which_spelling_of_a_queried_denylist_reaches_which_arm` -- both grown by later commits on the same
/// branch that wrote the 58. What does not drift is the KIND: this arm receives `NotComparable` and
/// nothing else, since the `RegexError` arm above it takes the only other error that can arrive. Re-run
/// the probe rather than trusting the number. Over the whole suite it reports 170, the lib and bin
/// targets each compiling this module and every reaching cell existing in both.
///
/// The 85 also counts a population it did not when it was taken: `contained_in`'s whole-list loop is
/// a call to `is_one_of`, so this arm receives that loop's arrivals as well -- a census taken here
/// before that change and one taken after are over different call sets, and the difference is not
/// visible in the number.
///
/// The sibling scalar arm below swallows the same error through its own
/// `Err(_) => {}`, for the reason written out there: `NOT IN` against an operand of a kind it cannot be
/// compared with currently passes, `docs/KNOWN_ISSUES.md` records that suppression as a tracked defect,
/// and `incomparable_membership` in `eval.rs` warns rule authors before it changes. Two sites, one
/// reading -- and those two are ALL of them on this path, where the block above
/// `InOperation` counted three.
///
/// Two probes, two questions, and the 85 above answers only the first: a panic reddens every test that
/// *reaches* the line. Replacing the same arm with
/// `Err(e) => { if unanswerable.is_none() { unanswerable = Some(unanswerable_reason(e)); } }` instead
/// reddens only the tests whose *verdict or message moves*, which is 16 under
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
    is_one_of_observed(each, rhsl, &mut false)
}

/// [`is_one_of`], with the kind refusals it discards reported to the caller.
///
/// ONE loop, not two. [`super::incomparable_membership_in`] needs to know whether any pairing this walk
/// BUILT refused for an incomparability, and the walk short-circuits: `Matched` returns on the first
/// right-hand element that matches, so later pairings for that element are never built. A predicate
/// that walks the full cross product counts refusals from comparisons the operator never made. The
/// only honest way to answer is to be inside this loop rather than beside it, which is why this is
/// the body and [`is_one_of`] is a wrapper over it.
///
/// `refused_incomparably` is set on the same arm the returned `Membership` drops -- the `Err(_)`
/// below, which receives `NotComparable` and nothing else, the `RegexError` arm above it having
/// taken the budget case. That is exactly the classification `super::pair_refused` makes, so the
/// predicate's notion of a refusal and this one cannot drift apart.
///
/// The returned `Membership` is untouched, and that is what makes reading this verdict-neutral. A
/// kind mismatch still does not become `Unanswerable`; promoting it is the fail-closed change
/// `docs/KNOWN_ISSUES.md` gates on the registry rules, priced at 19 verdicts above, and it is not
/// what this does. The flag is written and the existing callers pass a throwaway.
///
/// WITHHELD ON THE `Matched` EXITS, which is the rule [`super::rhs_values_paired_with`] already
/// applies one granularity up and this function did not. That one drops a right-hand VALUE the arm
/// stopped at, on the ground that "a value that stops has MATCHED ... counting its refusals credits a
/// passing clause with a refusal belonging to a value that failed". Identically true of an operand
/// here: a walk that refuses against entry `i` and then matches entry `j` has had its refusal
/// DISCARDED by the operator, and nothing was read as "not a member".
///
/// Stopping where the operator stops is not the same property, and having it is what made this look
/// closed. Three call sites were repaired to walk this loop rather than imitate it, and all three then
/// reported a refusal seen on the way to a match -- so the walk was right about which pairings exist
/// and wrong about which of them decided anything.
///
/// The discarded refusal cannot be owed, and the argument is the fail-closed destination rather than a
/// sweep. Promoting the `Err(_)` arm sets `unanswerable` and the walk CONTINUES, so a later `Ok(true)`
/// still returns `Matched` -- [`Membership`]'s own note states that precedence. Every consumer then
/// reads the matched branch: [`elements_not_matched`] keeps the element out of the diff,
/// [`contained_in`]'s whole-list match yields `Success`, and its scalar arm yields
/// `Success(ValueIn)`. No verdict moves, so the notice would fire where fail-closed changes nothing,
/// which is exactly what it must not do.
///
/// Live rather than latent, in the spelling the registry rules use. Measured with release binaries:
/// `some Iso[*] NOT IN [["a"], [1]]` over an `Iso` of `[[[1]], [[9,9],[8,8]]]` exited 0 and printed
/// the notice, whose subject is `[[9,9],[8,8]]` -- every pairing it builds answers `Ok(false)` on
/// `compare_eq`'s length check. The suspect `[[1]]` matched and so FAILED; dropping it drops the
/// notice and keeping only it exits 19, which is what attributes the notice to the matched walk. The
/// filter spelling `Resources.*[ some Properties.V[*] NOT IN [["a"], [1]] ]` does it too.
///
/// THE DENYLIST SPELLING AND NOT THE SHAPE is the reading to guard against here: a withholding
/// justified by that fixture reads as a statement about `Iso` against `[["a"], [1]]`, and querying the
/// same denylist must not invert the answer. `Deny[*]` enumerates, `Deny` being that list in the data
/// document, so `InOperation::compare` puts its entries back into one set and asks this same walk of
/// `[[1]]` against `[["a"], [1]]`, exactly as the written-out spelling does, and the queried cells agree
/// with their literal twins -- a refusal seen on the way to a match earns nothing in either. Were each
/// `Deny[*]` entry delivered as its own right-hand value instead, `contained_in`'s subset reading would
/// take the entry's ELEMENTS as the candidates -- the `Int` `1` rather than the list `[1]`, no
/// `PartialEq` match anywhere, both values refusing on kinds -- and `some Iso[*] NOT IN Deny[*]` would
/// PASS and OWE its notice. `the_element_pairing_through_a_queried_denylist` and its two
/// attribution cells carry that agreement, with `a_queried_nested_denylist_that_refuses_on_kinds` beside
/// its written-out twin as the cell where a refusal IS owed in both spellings.
///
/// Classifying that clause needs the arm's dropped result promoted as well, and the reason belongs here
/// because this is the arm a reader reaches for. Promoting this `Err(_)` turns `contained_in`'s answer
/// from `Fail(ListIn)` into `NotComparable`, and `InOperation::compare`'s `(None, None)` arm discards
/// that at the `_ => {}` of its `match contained_in(..)`. The two suppressions are in SERIES, so a
/// fail-closed build made from this arm alone reports no movement for every clause routing through that
/// arm, whatever is owed there. `Ports NOT IN Uint` at PASS beside `Ports NOT IN 5` at FAIL is that fact
/// with nothing built, and both are cells of
/// `the_notice_asks_about_every_granularity_the_operator_decides_at`, whose note names the
/// four-suppression oracle these classifications are taken against.
///
/// WHY THE SHORT ORACLE IS THE ONE A READER BUILDS, which is what made the first reading of this clause
/// wrong rather than merely coarse. The third suppression is a `_ => {}` and not an `Err(_) => {}`, so the
/// promotion form the other two take does not apply to it -- `Unanswerable`'s doc records the
/// `unanswerable_membership` channel it has to be promoted through instead -- and a fail-closed build
/// shaped like the other two sites' therefore never applies any oracle to this route at all. Its silence
/// about a queried denylist is blindness rather than a verdict, and that is the trap, because silence
/// reads as coverage.
///
/// Nor can the in-language oracle stand in.
/// `the_notice_fires_exactly_where_fail_closed_moves_the_answer` decides owed-ness by evaluating
/// `X NOT IN [v]` beside `X != v`, and its own comment requires a scalar left-hand side against a
/// one-element denylist for those two to be the same question; this is a list against two entries. With
/// the cheap oracle unavailable and the natural build blind, the route stayed unclassified until the
/// four-site build named above was run.
///
/// One token of denylist ordering is why nothing caught it. The gate repair's own table,
/// `a_matched_subset_earns_no_whole_value_refusal_the_operator_never_built`, builds this exact
/// population and writes its denylist as `[[1], [9]]`, matching entry FIRST -- so its matched walk
/// records nothing before it stops. `a_refusal_seen_before_a_match_earns_no_notice` is the same table
/// with the incomparable entry moved ahead of the matching one, at all three granularities. Withholding
/// the flag moves no other test: the whole suite reads 3195 passed either way.
///
/// That 3195 is a census of the corpus on the commit that took it and has since moved with the corpus, so
/// read the predicate beside it rather than the number. The durable form of the same claim is the SET of
/// cells the reversion reddens, which `a_refusal_seen_before_a_match_earns_no_notice` now records for its
/// own table: cases 1, 9 and 12 and nothing else, including nothing among the queried-denylist cells,
/// which is a structural fact about that route rather than a gap in them.
fn is_one_of_observed(
    each: &PathAwareValue,
    rhsl: &[PathAwareValue],
    refused_incomparably: &mut bool,
) -> Membership {
    let mut unanswerable: Option<Unanswered> = None;
    let mut refused_here = false;
    for elem in rhsl {
        if elem == each {
            return Membership::Matched;
        }
        // The membership comparator, not `compare_eq` directly: a one-character element against a
        // char range in the denylist is answered as the character, as every other membership site
        // answers it, and a refusal on that pair would be one `contained_in` never made.
        match compare_eq_for_membership(each, elem) {
            Ok(true) => return Membership::Matched,
            Ok(false) => {}
            Err(err @ Error::RegexError(_)) => {
                if unanswerable.is_none() {
                    unanswerable = Some(unanswerable_reason(err));
                }
            }
            Err(_) => refused_here = true,
        }
    }
    *refused_incomparably |= refused_here;

    match unanswerable {
        Some(unanswered) => Membership::Unanswerable(unanswered),
        None => Membership::NoMatch,
    }
}

/// Whether any element pairing `contained_in`'s list-against-list arm actually BUILT refused for an
/// incomparability.
///
/// The element-granularity counterpart of [`whole_value_pairing_built`]. That one answers whether a
/// pairing exists; this one answers what the pairings that exist said. Both exist because
/// [`super::incomparable_membership_in`] cannot see the operator's work and had been re-deriving it.
///
/// It walks `elements_not_matched`'s walk -- `is_one_of` per left-hand element, short-circuiting on a
/// match -- so a left-hand element that matched contributes only the pairings up to its match, which
/// is what the operator compared. The predicate previously walked `lhsl` x `rhsl` entire, and counted
/// the rest.
///
/// Return value discarded from `is_one_of_observed` deliberately: the membership answer is
/// `elements_not_matched`'s to compute and act on, and duplicating that decision here would be the
/// re-derivation both helpers exist to avoid. Only the refusal flag is read.
pub(super) fn membership_pairing_refused(lhsl: &[PathAwareValue], rhsl: &[PathAwareValue]) -> bool {
    let mut refused = false;
    for each in lhsl {
        is_one_of_observed(each, rhsl, &mut refused);
    }
    refused
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
/// Both branches below need this pair, and one function keeps them from building the diff twice. The
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

/// The membership comparator: `compare_eq`, with a one-character string against a char range first
/// read as the character.
///
/// No loader produces a `Char`: a YAML `b`, a quoted `"b"` and a rules-side `'b'` all arrive as
/// `String`, and `compare_eq`'s only membership arm for a `RangeChar` is `(Char, RangeChar)`. So
/// `Grade in r[a,f]` fell to the incomparable catch-all on every document and exited 19 reading "not
/// comparable String, range(char, char)", and `Grade not in r[a,f]` did the same -- a clause neither
/// polarity could satisfy, which only `parse_char(Grade)` could reach. The range literal parses, so a
/// rule author can write it, and the value it is meant for is one character of text; reading that
/// character out of the string is what lets the clause answer.
///
/// Exactly one character, counted in characters and not bytes, so a two-byte `é` is one. A longer
/// string is not a character and goes to `compare_eq` as it always did, which refuses it: guessing
/// its first character would make `"bc" in r[a,f]` answer for `b` alone and admit a value the range
/// does not describe. Every other pair is `compare_eq`'s, unchanged.
///
/// ONE comparator, asked at every site that pairs a scalar with a range for membership, and not a
/// predicate the sites consult before asking `compare_eq` themselves: `contained_in`'s scalar arm for
/// the bare `in r[a,f]`; its scalar-against-list loop and `is_one_of_observed` for the bracketed
/// `in [r[a,f]]`; the membership arm of `key_filter::key_pair_compare`, the comparator the evaluator's
/// and the legacy resolver's key filters use, so `[ keys IN r[a,f] ]` answers as `Key IN r[a,f]` does;
/// and `pair_refused` there,
/// so the incomparable-membership notice
/// cannot call refused a pairing the operator answered. Each of those was reached in turn by a
/// version that covered fewer of them: the first lived inline in the scalar arm alone, and
/// `Upper not in r[a,z]` over an `A` passed correctly while printing the notice that said it had
/// passed on a refusal; the second was an `Option` the sites matched on before their own `compare_eq`,
/// and the key filters still asked `compare_eq` directly. A site that asks `compare_eq` for
/// membership without going through here is the bug to look for next time two spellings disagree.
///
/// Here rather than in `compare_eq`, because `compare_eq` is also `==`, and `"b" == r[a,f]` has no
/// reading this would be deciding for it; membership is the one question a range answers.
pub(super) fn compare_eq_for_membership(
    lhs: &PathAwareValue,
    rhs: &PathAwareValue,
) -> crate::rules::Result<bool> {
    if let (PathAwareValue::String((_, s)), PathAwareValue::RangeChar((_, range))) = (lhs, rhs) {
        let mut chars = s.chars();
        if let (Some(c), None) = (chars.next(), chars.next()) {
            return Ok(crate::rules::values::WithinRange::is_within(&c, range));
        }
    }
    compare_eq(lhs, rhs)
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
                // The subset test asks nothing about the depth of the element that matches. Requiring a
                // non-list one would make two spellings of the same question disagree with each other:
                // for a `Nest` of `[1, [9]]`, `Nest IN [1, [9]]` would fail because `[9]` could not
                // match the `[9]` written beside it, and `Nest NOT IN [1, [9]]` would fail as well --
                // neither polarity would admit a pair of operands where every element of the left is
                // spelled out on the right. It would also let this arm report a failure with an empty
                // diff, since the diff below is computed with `Vec::contains`, which has no such
                // requirement. Without it, "every element matched" and "the element-wise diff is empty"
                // are the same statement, which is why `flat_subset` is written in terms of `diff`
                // rather than beside it.
                //
                // That independence is the whole fix. A reading of `rhsl[0]` alone would let element
                // zero answer for elements 1..n: for a `Pair` of `[1, 2]`, `Pair NOT IN ["zzz", [1,2]]`
                // would exit 0 and `Pair NOT IN [[1,2], "zzz"]` exit 19 -- one denylist, one value, and
                // the order it was typed in deciding whether it admitted a value it verbatim contains.
                // `IN` would invert the same way and print `was not present in [["zzz",[1,2]]]`, refuted
                // by the set beside it.
                //
                // This is the failure shape the scalar-left-hand arm below closes by asking each
                // element in turn, where `rhsl.contains(rest)` cannot see a range nested in a list
                // literal. Same idiom here, in both readings:
                // `is_one_of` asks `compare_eq` as well as `PartialEq`, so a right-hand list holding a
                // range or a regex reaches the function that knows about them, and the whole-list
                // membership test asks `compare_eq` on the list itself for the same reason.
                //
                // There are no `Err` arms here: the whole-list loop is a call to `is_one_of`, so this
                // arm's arrivals are a subset of `is_one_of`'s, and the only probe of them is to
                // promote `is_one_of_observed`, which also promotes every other caller of it. An
                // arrival count for this line alone is not separately measurable and none is kept;
                // the split by error kind is what the paragraphs below use, and the `RegexError` cells
                // are named so they can be checked without a probe.
                //
                // Kind mismatches reach this line and are discarded (`is_one_of` folds a
                // `NotComparable` into a miss), so promoting `RegexError` alone moves no cell of
                // theirs, and their exact count changes nothing in the argument. The `RegexError`
                // path through this comparison is covered by two cells, and naming them is what makes
                // that checkable without a probe:
                // `a_denylist_refuses_a_value_it_could_not_evaluate_in_either_spelling`'s
                // `case_5_list_in_a_nested_list` and `case_6_list_not_in_a_nested_list`.
                //
                // The subset test asks `is_one_of` rather than staying on `PartialEq` to match the
                // all-flat branch below. Matching the branch that way would leave the same hole in both:
                // a range beside a list-valued left-hand side matches no element under `PartialEq`, so
                // `Ports NOT IN [r[80,90]]` would admit a `Ports` of `[85]` while
                // `Port NOT IN [r[80,90]]` denies an 85. Both readings ask `is_one_of`, so the two agree
                // at the level the scalar arm works at rather than at one neither of them does.
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
                // element would match no element of itself, so every element would read as colliding
                // and `NOT IN` would fail for every left-hand value whenever the denylist held any
                // nested list: `Pair NOT IN [[99,98]]`, two disjoint pairs, at exit 19. The element-wise
                // diff and the depth-free subset match above hold together: a failure whose diff is
                // empty would report every element as colliding again, for the same reason and by the
                // same route.
                //
                // Negating the verdict instead was measured and rejected. A marker field mirroring
                // `QueryIn::diff_from` would let the wrapper flip a failed membership to Success
                // without recomputing anything, and it is smaller. It admits four values the denylist
                // names, because "the whole list is not a member" says nothing about the elements:
                // for a `Nest` of `[1, [9]]`, `Nest NOT IN [[9]]` reaches exit 0 under it, and so
                // does `Deep NOT IN [["a"]]` for a `Deep` of `[["a"]]`. Both are cells of
                // `a_list_denylist_holding_a_nested_list_denies_only_what_it_names`, which is where to
                // look before trying it again.
                //
                // An empty left-hand list reaches the subset reading here, the same as it does in the
                // branch below. It has no elements, so `diff` comes out empty and the subset reading
                // holds vacuously. There is no `is_empty` guard keeping it out of that reading to avoid
                // a second vacuous pass, because what such a guard buys is not worth what it costs.
                //
                // What it costs is monotonicity, which is the property a denylist cannot trade away:
                // adding an entry must never turn a failing `NOT IN` into a passing one. Such a guard
                // applies in this branch only, and which branch a clause takes turns on whether the
                // denylist holds a list at all, so the empty case answers one way for a flat denylist
                // and the other way for the same denylist with one nested element added. On a document
                // where `Empty` is `[]`, `Empty NOT IN [1,2,3]` exited 19 and `Empty NOT IN [1,2,3,[9]]`
                // exited 0 -- one entry added, and a denylist that had denied the value admitted it. The
                // flip was position-independent, so `[[9],1,2,3]` and `[1,[9],3]` did it too.
                //
                // The nested-entry guard's own description was that `NOT IN` therefore only ever goes
                // from Success to Fail, never the other way. That is true of the guard's mechanism and
                // false of this function as it stands, and it is corrected here rather than left to be
                // read as a guarantee about the branch: a reader who takes it that way concludes no lax
                // flip can exist and stops looking, and the empty-left-hand flip above is the flip such
                // a reading misses.
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
                // Neither pass is the compared-nothing case that `==` and the ordering operators fail in
                // `eval.rs`, which is why the compared-nothing notice is silent with and without the
                // `is_empty` guard. That case is an operand that expanded to no values at all, and an
                // empty list under `IN` is one value that does get compared. Measured rather than
                // reasoned: `Empty NOT IN [1,2,3]` and `Empty NOT IN [1,2,3,[9]]` each print nothing on
                // stderr. So the guard was not holding a line that notice was about to move.
                // The membership reading beside the subset one raises on its own, and it does not
                // swallow that either. `compare_eq` recurses through a pair of lists element by
                // element, so for a `Size` of `["aaa..."]` the pair `(Size, [/re/])` reaches
                // `compare_eq(String, Regex)` and raises from there. The element-wise pass above
                // never sees that pattern -- `compare_eq` has no `(String, List)` arm and falls
                // through to `compare_values`, whose catch-all refuses on the shapes before any regex
                // runs -- so this call site is the only one that can report it; swallowed here,
                // `Size NOT IN [[/(?!x)((a+)+)b/]]` exits 0 while the unnested spelling exits 19.
                //
                // `if !flat_subset` is the short circuit the `flat_subset ||` expression this replaced
                // had for free, and it is kept deliberately rather than by habit. Without it the
                // membership comparison runs on every input that reaches this branch instead of only
                // the ones that need it: with the same panic probe named above, replacing this condition
                // with `if true` takes arrivals from 19 to 46 under `cargo test --lib` (they
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
                    // What this line decides is only that the answer does not depend on the shape
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

                    // THIS WALK WAS A THIRD COPY OF `is_one_of` and is now that function. Written out,
                    // it was the same five arms in the same order over the same slice: `PartialEq`
                    // first, then `compare_eq`, `Ok(true)` matching and breaking, `RegexError`
                    // recorded once, every other `Err` discarded. `is_one_of` over the whole
                    // left-hand value answers all of it, and `Membership`'s three variants are
                    // exactly the three outcomes this needed -- `Matched` is `whole_list_member`,
                    // `Unanswerable` carries the reason, `NoMatch` is neither.
                    //
                    // Collapsed rather than left agreeing, because the copy is what let the two drift.
                    // `super::incomparable_membership` mirrors this walk to decide whether a refusal
                    // belongs to a pairing the operator built, and it had already diverged here twice:
                    // once on the GATE, repaired by reading `whole_value_pairing_built`, and once on
                    // the BODY, which walked past the break this loop takes. A predicate reading one
                    // walk cannot diverge from it.
                    //
                    // `Matched` DISCARDING a `RegexError` seen earlier in the same walk is not a
                    // behavior change, though it is the one difference worth checking. The original
                    // recorded the reason and then broke on a later match, keeping it in
                    // `unanswerable`; `is_one_of` returns `Matched` and drops it. The match below
                    // reads `(flat_subset || whole_list_member, unanswerable)` and its `(true, _)` arm
                    // ignores the reason whenever the membership held, so both spellings answer
                    // `Success` on that input.
                    //
                    // The element walk's reason still outranks this one, which `is_none()` preserves:
                    // `unanswerable` arrives already populated from `elements_not_matched` above when
                    // an ELEMENT could not be decided, and that is the reason a reader of the failure
                    // wants first.
                    let mut whole_list_member = false;
                    if !flat_subset {
                        match is_one_of(&lhs_value, rhsl) {
                            Membership::Matched => whole_list_member = true,
                            Membership::NoMatch => {}
                            Membership::Unanswerable(unanswered) => {
                                if unanswerable.is_none() {
                                    unanswerable = Some(unanswered);
                                }
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
                // `eq` is consulted first. `compare_eq` carries the three range-against-range arms
                // itself, so asking it alone would not lose `%range_literal in [r[80,90]]`, which
                // makes this call belt and braces: there is no pair `eq` answers true and
                // `compare_eq` answers false, so it could be dropped. Kept because it costs one
                // comparison on a path that already runs one, and because `eq` answering true short
                // circuits while `eq` answering false changes nothing -- `compare_eq` is asked next
                // either way. `compare_eq` can only add a match, never remove one.
                //
                // A regex `compare_eq` could not evaluate is read rather than discarded, which is
                // what makes `Port in [/re/]` answer the same way as `Port == /re/`. Both spellings
                // reach a regex that cannot be evaluated; the unwrapped one goes through
                // `match_value` and reports it, and this one reads it out of `compare_eq` rather than
                // panicking inside `eq`. An element that matches still wins over an element
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
                    // The membership comparator: a range written inside the list literal is the
                    // same range as one written bare, so a one-character string meets it the same way.
                    match compare_eq_for_membership(rest, elem) {
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

                // The pair's left value is the operand's own `Rc` (`rest` is the whole left value, not an
                // element), the identity contract `ComparisonResult` states; re-boxed, the value a listed
                // entry accepted was never found among the accepted by address (`marker_pair_under_in`).
                match (found, unanswerable) {
                    (true, _) => ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                        Compare::ValueIn(LhsRhsPair::new(
                            Rc::clone(&lhs_value),
                            Rc::clone(&rhs_value),
                        )),
                    )),

                    (false, Some(reason)) => {
                        not_comparable_because(Rc::clone(&lhs_value), Rc::clone(&rhs_value), reason)
                    }

                    (false, None) => {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ValueIn(
                            LhsRhsPair::new(Rc::clone(&lhs_value), Rc::clone(&rhs_value)),
                        )))
                    }
                }
            }

            rhs_rest => match_value(
                Rc::clone(&lhs_value),
                Rc::new(rhs_rest.clone()),
                compare_eq_for_membership,
            ),
        },
    }
}

/// Whether `InOperation::compare`'s `(None, None)` arm stops pairing this left-hand value once it has
/// seen this right-hand one.
///
/// [`super::incomparable_membership_in`] walks the same cross product that arm walks, to count the
/// refusals a passing `NOT IN` clause passed on. The arm stops pairing a left-hand value the moment
/// one matches -- `continue 'each_lhs` at the string-containment and membership arms below, and at
/// the empty-left skip above them -- and the predicate had no such stop, so it kept pairing the value
/// against every LATER right-hand value and counted refusals from pairings the arm never built.
///
/// Measured over a 676-clause sweep of the mixed-left shapes: 54 clauses where the
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
/// to flag it. The short-circuit one level up is the same shape, and its own soundness argument was
/// sound about the population it had examined and silent about the one it had not.
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
    // An empty left-hand list is answered as an empty collection above the arm's loop, before any
    // pairing is built, whatever the right-hand kind. So the walk stops at once: no pairing of it is
    // the arm's, and none can carry a refusal.
    if let PathAwareValue::List((_, elements)) = &**lhs {
        if elements.is_empty() {
            return true;
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

/// Whether [`contained_in`]'s list-against-list arm builds the whole-left-hand-list pairing for these
/// two lists.
///
/// The second half of a two-part gate. That arm reaches its whole-list loop only when the denylist
/// holds a list AND the element-wise diff is non-empty, and the diff is what this answers;
/// [`super::incomparable_membership_in`] asks the first part for itself, because `is_list` is cheap and
/// this is not.
///
/// BY CALLING `elements_not_matched` rather than restating what an empty diff means, which is the same
/// rule [`membership_stops_after`] follows one function up. The distinction matters here because the
/// arm's own note forbids re-deriving the diff at the predicate, and this does not: it asks the
/// function the arm asks and reads the answer. A copy of "every element matched" written out in the
/// predicate is what must not exist -- that is how the divergence both helpers repair arose.
///
/// The cost is that `elements_not_matched` runs twice per pairing, once here and once in the arm, and
/// it allocates the diff both times. Accepted for the same reason [`is_literal`] is asked twice: the
/// alternative is a cheaper condition that can drift from the one the arm branches on. Nothing reads
/// the diff's contents here, only whether it is empty, so the second call is discarded work rather
/// than a second answer that could disagree.
pub(super) fn whole_value_pairing_built(lhsl: &[PathAwareValue], rhsl: &[PathAwareValue]) -> bool {
    !elements_not_matched(lhsl, rhsl).0.is_empty()
}

/// Whether the arm of [`InOperation::compare`] that will run pairs the ELEMENTS of a list-valued
/// left-hand value against `rhs_value`, as opposed to comparing that value whole.
///
/// A different question from the two helpers above, and the difference is the point. Those answer how
/// far a walk goes; this answers whether the walk exists. [`super::incomparable_membership_in`]'s
/// `(List, right)` arm records a refusal per left-hand ELEMENT, and for most right-hand kinds
/// [`contained_in`] never decomposes the left-hand list at all: it dispatches on the left value, so a
/// list against a non-list reaches its `List` arm's catch-all and answers `NotComparable` carrying the
/// two WHOLE values. There is no element-versus-right pairing there to refuse, so a per-element
/// refusal counted against such a pair belongs to a comparison nobody performed.
///
/// # PRECONDITION: `rhs_value` is not a list
///
/// Asserted with a `debug_assert!` rather than left to the reader, because the rows below are stated
/// per arm and for a LIST `rhs_value` the arm stops mattering. `contained_in`'s `(List, List)` arm
/// reaches [`elements_not_matched`], which asks [`is_one_of`] per left-hand element, and every arm of
/// [`InOperation::compare`] can land there -- so for a list right-hand value the honest answer is
/// "always yes" and three of the four rows below would be wrong.
///
/// Measured with counters at the only two sites that pair a list's elements against a
/// right-hand value, one right-hand value per case so the count is attributable. For a list
/// `rhs_value`: `(Some, Some)`, `(None, Some)` and `(Some, None)` each predict `false` and each builds
/// 2 element pairings through `elements_not_matched` -- three disagreements. `(None, None)` predicts
/// `true` and observes 2, so it agrees, but NOT for the reason the row gives: its own element loop is
/// skipped by the `if !eachr.is_list()` guard, and `contained_in` builds the pairings instead. A
/// reading that credits the row's own loop is wrong even where the answer is right.
///
/// The caller satisfies this today by match-arm ordering alone: the sole caller is
/// [`super::incomparable_membership_in`]'s `(List, right)` arm, and a `(List, List)` pair is consumed by
/// the arm above it, so `right` is never a list there. That is a real guarantee and an invisible one --
/// nothing at either end says so, in a helper whose entire reason for existing is that a condition
/// restated away from the dispatch can drift from it. One reordering turns three latent wrong answers
/// live, which is why the assertion is executable rather than narrative.
///
/// Asked of [`is_literal`] rather than of a flag, because the answer is a property of the ARM and the
/// four arms differ. `both_queried` names ONE of the four and collapses the other three, and two of the
/// three it collapses do decompose, so a gate spelled that way is wrong for both of them.
///
/// Every row below holds under the precondition above and NOT in general.
///
/// * `(None, None)` decomposes. The arm asks `is_one_of(element, [eachr])` once per left-hand element,
///   under a `!eachr.is_list()` guard which the precondition makes vacuous. The shape refusal further
///   down that same match arm already sets `refused` whenever the left-hand list is non-empty, and the
///   loop body never runs when it is empty, so this arm of the answer is never what carries a notice --
///   it is here because it is true of the operator, not because the predicate needs it.
/// * `(None, Some)` decomposes for a `String` right operand ONLY. That arm expands a list-valued
///   left-hand value into one [`string_in`] per element, which is a per-element pairing, and that fact
///   alone is what this function reports. Every other right-hand kind reaches `contained_in` with the
///   value whole.
///
///   NOT because `string_in`'s refusal matches [`super::pair_refused`]'s: the two do not make the same
///   partition, since `string_in` answers `not_comparable` for
///   `(Regex, String)`, `(String, Regex)` and `(Regex, Regex)` while `compare_eq` answers `Ok(true)` for
///   all three, so `pair_refused` would refuse none of them -- measured, three disagreements out of four
///   probed pairs, with only `(Int, String)` agreeing. That match is also unnecessary: what the gate needs
///   is that element pairings EXIST here, not that the two functions classify them alike. It is
///   unreachable rather than merely wrong -- a `PathAwareValue::Regex` is built only by the rules parser,
///   and a rule literal on the left makes `is_literal(lhs)` `Some`, which is a different arm -- but an
///   unreachable justification is still the wrong justification to leave standing.
/// * `(Some, None)` decomposes unless some right-hand value is a list. With none, that arm builds an
///   element-wise diff with `Vec::contains`, so an element incomparable to a right-hand value really
///   is read as "not a member" -- which is exactly what the notice announces, so it is owed. With one,
///   the arm calls [`substring_or_contained_in`] on the whole value instead and no element pairing
///   exists for the non-list values it then walks.
/// * `(Some, Some)` never decomposes -- for a non-list `rhs_value`. One [`substring_or_contained_in`]
///   on the whole pair, which reaches `contained_in`'s catch-all. Note this differs from `(None, Some)`
///   for the same two operand kinds: a `String` right operand gets the left-hand list expanded in one
///   arm and not in the other.
///
///   For a LIST `rhs_value` this row is false, and the route is worth naming because a reader tracing
///   it will otherwise find the doc contradicting the code: `substring_or_contained_in` falls through
///   to `contained_in`, into its `(List, List)` arm, into `elements_not_matched`, which asks `is_one_of`
///   per element. Measured, 2 pairings where this row predicts none. The precondition is what keeps the
///   row true, not the arm.
///
/// `!any(is_list)` over [`selected`] rather than over a slice the caller assembled, so the predicate
/// and the arm cannot disagree about which right-hand values exist. `selected` is the function the arm
/// itself calls and it drops `UnResolved` the same way, which a hand-written filter at the call site
/// would have to restate.
///
/// Asked once per PAIR, and the arm selection it repeats is per clause. Hoisting that half above the
/// loop would be cheaper and is not done, for [`whole_value_pairing_built`]'s reason: the condition
/// would then live in two places, one of which can be edited without the other. The cost is one
/// discarded `Vec` per pair on the `(Some, None)` path only -- `is_literal` is two comparisons, and the
/// other three arms allocate nothing.
///
/// A gate spelled `both_queried || matches!(right, String(_))` was measured and rejected. It is wrong
/// in both directions at once, and only one of them is findable by reading a diff: it drops the
/// `(Some, None)` element-wise diff above, which is silence where a notice is owed and leaves no
/// artifact, and it keeps `(Some, Some)` against a `String`, which is a false alarm a reader can
/// still trip over. Measured over a 30,132-clause grid by a probe computing both spellings and this one
/// in a single run, so a difference the verdict gate hides is still counted: 6,750 clauses reach the
/// arm, and against this condition that spelling drops 222 predicate answers it should keep and keeps
/// 84 it should drop. The asymmetry between the two directions is the reason for the wording above. All
/// 84 are false alarms and SIX of them are live notices -- `%lit NOT IN NestedThenStr[*]` and its
/// siblings, exit 0 with the notice printed, where `contained_in` refused on `[1,2]` against `"abc"`
/// whole. None of the 222 was observable in that grid, because the `(Some, None)` list-valued path then
/// failed closed on `QueryIn`'s collided-set derivation and the verdict gate suppressed every one; the
/// repair was made anyway, on [`membership_stops_after`]'s rule that a suppression living in
/// `binary_operation` is not one this file can see lifting. It has lifted: that path's verdict is now
/// [`QueryIn::whole_list`]'s, the list as the one recorded value with `lhs_unmatched` set from whether
/// any element collides, and `%lit NOT IN X[*]` passes when no element is on the right, so the 222 are
/// LIVE. A same-kind pass (`[85]` against ints) owes nothing and a mixed-kind one
/// (`["x"]` against ints) owes the notice, which `a_membership_decided_by_partial_eq_owes_no_notice`
/// and `a_membership_decided_by_partial_eq_over_mixed_kinds_owes_the_notice` in `eval_tests.rs` pin.
///
/// `element_pairings_are_built_only_by_the_arms_that_decompose` below is the table over all four arms,
/// and `an_element_pairing_the_arm_does_not_build_earns_no_refusal` in `eval_tests.rs` asserts the same
/// partition through the predicate; each row of either fails under a different wrong spelling of this
/// condition. Prefer them to a re-run of the grid.
pub(super) fn element_pairings_built(
    lhs: &[QueryResult],
    rhs: &[QueryResult],
    rhs_value: &PathAwareValue,
) -> bool {
    // The rows in this function's doc are stated per ARM, and for a list `rhs_value` the arm stops
    // deciding: `contained_in`'s `(List, List)` walk pairs elements no matter which arm reached it, so
    // three of the four rows would be wrong. Enforced by match-arm ordering at the sole caller and by
    // nothing else, hence executable here.
    debug_assert!(
        !rhs_value.is_list(),
        "element_pairings_built is answered per arm and is only valid for a non-list rhs_value; \
         `contained_in`'s (List, List) arm pairs elements regardless of arm"
    );
    match (is_literal(lhs), is_literal(rhs)) {
        (None, None) => true,
        (None, Some(_)) => matches!(rhs_value, PathAwareValue::String(_)),
        (Some(_), None) => !selected(rhs, |_| {}, Vec::push)
            .iter()
            .any(|value| value.is_list()),
        (Some(_), Some(_)) => false,
    }
}

impl Comparator for InOperation {
    fn compare<'value>(
        &self,
        lhs: &[QueryResult],
        rhs: &[QueryResult],
    ) -> crate::rules::Result<EvalResult> {
        // The same two early answers `CmpOperator::compare` gives, because `binary_operation` builds
        // this operator directly for `IN` and does not pass through that dispatch.
        if let Some(early) = nothing_to_compare(lhs, rhs) {
            return Ok(early);
        }

        let mut results = Vec::with_capacity(lhs.len());
        match (is_literal(lhs), is_literal(rhs)) {
            // A `[]` written in the rule is a value, and a member of nothing but a list that holds an
            // empty list; see `empty_list_literal_in`. Only a document value can be the empty
            // collection, which the two document-left arms below answer first.
            (Some(ref l), Some(ref r)) => {
                if matches!(&**l, PathAwareValue::List((_, list)) if list.is_empty()) {
                    results.push(empty_list_literal_in(Rc::clone(l), Rc::clone(r)));
                } else {
                    results.push(substring_or_contained_in(Rc::clone(l), Rc::clone(r)));
                }
            }

            // A scalar literal against a right-hand query that NAMES several values without enumerating a
            // collection (a filter capture holding the keys it bound, `let lit = 'A'  %lit IN %x`): the
            // values are one set the literal is a member of or not, one verdict (`membership_in_entries`,
            // the question the written-out list is asked), as the document-left twin `Key IN %x` over
            // `Key: A` is a member of the keys. That set is read off the right-hand side's SHAPE, which a
            // capture reports as an entry set (`variable_shape`: the keys a filter bound are the members
            // it kept, as `query_projects` reads a bare capture), so the entry-set branch below takes it
            // for one key as for two. Decided by the count of values instead, one key was read as a
            // haystack (`'a' NOT IN %x` over the one key `Fallback` failed on the `a` inside it) and two
            // keys as a set, so adding an entry to a deny set turned a FAIL into a PASS. A right-hand side
            // that names ONE value from a plain `let` or a key path is a haystack, as the type doc says,
            // and the branches below read it per value.
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

                // A `[]` written in the rule is a value, not an empty collection the document resolved
                // to, and it is answered first, per right-hand value and whatever the right operand's
                // kind or shape; see `empty_list_literal_in`. Only a document value can be the empty
                // collection, which the document-left arms answer with `empty_left_collection`.
                //
                // Otherwise an enumerating right-hand query is one entry set, and a literal on its left
                // is asked the question the `(Some, Some)` arm asks of a written-out list:
                // `contained_in`, membership for a scalar and subset for a list, through the same
                // `membership_in_entries` the query-vs-query arm uses, so the failure is the same
                // `QueryIn` naming the entries. The two branches below read each resolved value on its
                // own -- `substring_or_contained_in` per value, so `%needle IN Types[*]` admitted a
                // `needle` of `gp` (and of `""`) by containment in `gp2` while
                // `%needle IN ["gp2","gp3"]` refused it -- and the per-value `Vec::contains` diff, which
                // is already membership and is kept for the non-enumerating list literal.
                if matches!(&**l, PathAwareValue::List((_, list)) if list.is_empty()) {
                    // The empty list literal as a value: a member of a right-hand list that holds an
                    // empty list, and of nothing else. Before the element diff below, which for a list
                    // with no element is empty and would read as a vacuous subset.
                    for r in &rhs {
                        results.push(empty_list_literal_in(Rc::clone(l), Rc::clone(r)));
                    }
                } else if self.rhs_enumerates.is_entry_set() {
                    let candidates = self.candidates_for(&rhs);
                    results.push(membership_in_entries(l, &rhs, &candidates));
                } else if rhs.iter().any(|elem| elem.is_list()) {
                    rhs.into_iter()
                        .for_each(|r| results.push(substring_or_contained_in(Rc::clone(l), r)));
                } else if let PathAwareValue::List((_, list)) = &**l {
                    // Subset reading, element by element, reported for the list as a whole; the
                    // `NOT IN` answer is `QueryIn::whole_list`'s. `collides` is whether any element
                    // is on the right, which is what `NOT IN` denies.
                    let diff = list
                        .iter()
                        .filter(|elem| !rhs.iter().any(|r| **r == **elem))
                        .cloned()
                        .map(Rc::new)
                        .collect::<Vec<_>>();
                    let collides = diff.len() < list.len();

                    let query_in = QueryIn::whole_list(diff, collides, Rc::clone(l), rhs);
                    results.push(ValueEvalResult::ComparisonResult(
                        if query_in.diff.is_empty() {
                            ComparisonResult::Success(Compare::QueryIn(query_in))
                        } else {
                            ComparisonResult::Fail(Compare::QueryIn(query_in))
                        },
                    ));
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
                .for_each(|l| {
                    if let Some(empty) = empty_left_collection(&l, &r) {
                        results.push(empty);
                        return;
                    }
                    match &*r {
                        PathAwareValue::String(_) => match &*l {
                            PathAwareValue::List((_, lhsl)) => {
                                for eachl in lhsl {
                                    results.push(string_in(Rc::new(eachl.clone()), Rc::clone(&r)));
                                }
                            }

                            // The whole left value, carried as the operand's own `Rc` (the identity
                            // contract `ComparisonResult` states); the elements above are fresh boxes.
                            _ => results.push(string_in(Rc::clone(&l), Rc::clone(&r))),
                        },

                        rest => results.push(contained_in(l, Rc::new(rest.clone()))),
                    }
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

                // One `QueryIn` result PER LEFT-HAND VALUE, built after the loop from the four sets the
                // loop sorts the values into (matched, unmatched in `diff`, undecided, uncompared): a
                // left-hand value is in or out of the right-hand query as a whole, so a value is never
                // expanded into one result per element here -- that is the literal-right-hand arm's
                // shape and it would turn "any of these" into "all of these". A reporter names each
                // unmatched value with the entries it was compared against, and
                // `a_long_in_comparison_is_truncated_with_a_total` pins the "and N more" summary of
                // those entries.
                // The four sets are keyed on the address of the left-hand value's `Rc` (`Rc::as_ptr`),
                // so classifying a value and asking after it are both one hash lookup, and two equal
                // left-hand values are classified each on its own, exactly as the loop classifies them.
                // The `Rc`s live in `lhs_selected` for the whole arm, so no address is reused meanwhile.
                let mut diff: HashSet<*const PathAwareValue> =
                    HashSet::with_capacity(lhs_selected.len());
                let mut collides: HashSet<*const PathAwareValue> = HashSet::new();
                let mut unanswerable: Vec<ValueEvalResult> = Vec::new();
                // The values the `unanswerable` results are about, so the per-value results built after
                // the loop file nothing else for them: a refused value's only verdict is its refusal,
                // and it is never accepted.
                let mut undecided: HashSet<*const PathAwareValue> = HashSet::new();
                // A fourth outcome for a left-hand value, beside matched, unmatched and unanswerable: it
                // is an empty collection, and no membership question is asked of it at all. Its verdict is
                // the `EmptyCollection` pushed per right-hand value, so the per-value results built after
                // the loop file nothing else for it either: a value with no record is neither matched nor
                // unmatched, and the negation wrapper, which reads a value present in `lhs` and absent from
                // `lhs_unmatched` as MATCHED, never sees it.
                let mut empties: HashSet<*const PathAwareValue> = HashSet::new();

                // An enumerating right-hand query is one entry set, asked the question the written-out
                // list is asked: membership for a scalar on the left, subset for a list, once per
                // left-hand value (`membership_in_entries`, shared with the literal-left arm). The
                // resolved values cannot say whether the query enumerated (`Types[*]` over a one-entry
                // list and `Types[0]` deliver one identical result), so the caller reads it off the query
                // and `rhs_enumerates` carries it. One `QueryIn` per left-hand value, carrying the
                // resolved entries as its right operand: the reporter names the entries with their paths
                // and truncates a long allowlist with a total (`a_long_in_comparison_is_truncated_with_a_
                // total`), and one status per value is what `some` folds. A list that is no subset but
                // shares an element with the set is filed through `partly_matched`, so `NOT IN` denies
                // it; a refusal `contained_in` reports (a regex it could not evaluate) fails closed in
                // both polarities. An empty left-hand list is not a vacuous subset: it is answered as the
                // empty collection it is, before any subset question, as in every other arm.
                // Every right-hand entry unresolved (an empty `rhs` never reaches this arm;
                // `nothing_to_compare` answers it first): each left-hand value already carries one
                // `RhsUnresolved` per entry, pushed above, and that is its whole verdict, decided for a
                // value the document lacks and undecided for a key filter's marker. Asking membership of
                // no entries filed a `Fail` beside it for every left-hand value, a decided failure about a
                // question nobody could put, and a `when` gate read the decided failure first; see the
                // same guard in `EqOperation`.
                if !rhs.is_empty() && rhs_selected.is_empty() {
                    return Ok(EvalResult::Result(results));
                }

                if self.rhs_enumerates.is_entry_set() {
                    let candidates = self.candidates_for(&rhs_selected);
                    for eachl in &lhs_selected {
                        if matches!(&**eachl, PathAwareValue::List((_, list)) if list.is_empty()) {
                            for eachr in &rhs_selected {
                                results.extend(empty_left_collection(eachl, eachr));
                            }
                            continue;
                        }
                        results.push(membership_in_entries(eachl, &rhs_selected, &candidates));
                    }
                    return Ok(EvalResult::Result(results));
                }

                'each_lhs: for eachl in &lhs_selected {
                    if matches!(&**eachl, PathAwareValue::List((_, list)) if list.is_empty()) {
                        for eachr in &rhs_selected {
                            results.extend(empty_left_collection(eachl, eachr));
                        }
                        empties.insert(Rc::as_ptr(eachl));
                        continue 'each_lhs;
                    }
                    let mut unanswerable_against: Option<(Rc<PathAwareValue>, StringContainment)> =
                        None;
                    let mut unanswerable_membership: Option<(Rc<PathAwareValue>, Unanswered)> =
                        None;
                    let mut element_collision = false;
                    for eachr in &rhs_selected {
                        // No vacuous match here. An empty left-hand collection is answered above this
                        // loop, as the empty collection it is, before any pairing is built, so no
                        // `eachl` reaching this point is an empty list: nothing here reads one as a
                        // subset of a right operand that denotes a set or skips its pairing with a
                        // string haystack, which would pass `Empty IN D13[*]` and pass `Empty IN Str` in
                        // both polarities.

                        // Containment first, membership second, which is the order the two arms above
                        // apply when the right-hand side is written out. This arm asked `contained_in`
                        // alone, and two scalars there fall through to `compare_eq`, so
                        // `Needle in Haystack` was equality while `Needle in "aws:arn:s3::${s3}"` was
                        // containment -- and `Needle not in Haystack` therefore PASSED on a needle the
                        // haystack verbatim contains, a denylist admitting the value it names at exit 0.
                        //
                        // ONLY FOR A RIGHT-HAND QUERY THAT NAMES ITS VALUE. A query that enumerates a
                        // collection never reaches this pairing loop: it is one entry set, answered at
                        // the top of the outer loop, and reading each of its entries as a haystack here
                        // is the defect recorded there. `Haystack`, `Names[0]` and `Parameters.X.Default`
                        // are the right-hand shapes this loop is for.
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
                            // arm does not treat it as one. `contained_in` fails a list-valued left-hand
                            // side that is only *partly* present -- neither the whole list nor every
                            // element found an equal -- and reports the elements that found nothing as
                            // the `ListIn` diff. The elements missing from that diff DID find one, and
                            // those are the values a denylist names. Counting only Success as a match
                            // would make a `Fail` carrying a real element collision indistinguishable
                            // from a pairing where nothing matched at all, so it would join the
                            // unmatched set and negate to a pass: with `Pair` of `[1, 2]` and `Deny` of
                            // `[1, 3]`, `Pair NOT IN Deny` would exit 0 while `Pair NOT IN [1, 3]`
                            // exits 19.
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
                        // matching no element, the hole `is_one_of` exists to close.
                        //
                        // Whole-list membership needs nothing added here: `compare_eq` of a list
                        // against a scalar is an error, so no scalar right-hand value can be the
                        // left-hand list itself.
                        //
                        // A right-hand result that IS a list goes to the arm above and is NOT fully
                        // answered there. `contained_in` reads such a result as a set of candidate
                        // entries rather than as one entry, so `Deny[*]` over a `Deny` of `[[9]]`
                        // compares against `{9}` where the written-out and unexpanded spellings compare
                        // against `{[9]}`. For a `Nest` of `[1, [9]]` that is exit 0 against three
                        // spellings at exit 19, and it is the same class of bypass as the one repaired
                        // here, one operand shape further in.
                        // `right_expanded_nested_entry_denied` in `eval_tests.rs` pins it with its three
                        // siblings beside it, and `right_expanded_nested_string_entry_denied` pins the
                        // same shape in strings; both are closed by the entry-set path above and the
                        // argument below is about the pairing loop a NAMED right-hand value still takes.
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
                        // deletion above closed `right_expanded_nested_entry_denied` (then pinned at the
                        // bypass) and reddened `a_single_indexed_nested_entry_denies_by_its_members` in
                        // the same run.
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
                        // run, among them `Pair NOT IN Deny13` returning to the exit 0 the collision fix closed,
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
                        // traversal that produced a value, so this arm cannot separate the two spellings
                        // from the values. THE PROVENANCE IS NOW CARRIED, the part of it that matters
                        // here: `rhs_enumerates` is reported by the retrieval of the right-hand
                        // `AccessClause` itself (`query_retrieval_shaped` in `eval_context.rs`), whose
                        // root-variable arm folds in the binding's own shape, so `NOT IN %deny` over
                        // `let deny = Denies[*]` is reached too --
                        // and handed to `InOperation` by `binary_operation` directly, without widening
                        // `Comparator::compare` for every operator. An enumerating spelling therefore
                        // takes the entry-set path at the top of the outer loop and never reaches this
                        // guard: `Denies[*]` answers as `[[1, 3]]` does, and `Nest NOT IN Deny[*]` over a
                        // `Deny` of `[[9]]` denies. What this guard and the paragraphs above still
                        // describe is the pairing loop for a right-hand query that NAMES its value --
                        // `Denies[0]`, `Deny13`, `Str` -- where the two readings of a list-valued `eachr`
                        // (the whole denylist, or one entry) are both still possible and the values
                        // still cannot tell them apart.
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
                        // check -- the collision reproducer drives it twice with
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
                    // BOTH third answers under one `!element_collision`, with one precedence. Two blocks
                    // with opposite precedence -- the membership one gated and the containment one
                    // checked unconditionally, one screen above it -- would let a clause that
                    // established a collision AND could not decide a containment report the containment
                    // complaint and drop the collision. With `Vals` of `["abc", "zzz"]` and `Deny` of
                    // `["abcdef", "zzz"]`, `Vals NOT IN Deny[*]` would record `Some but not all of
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
                    // the clause above is exit 19 whichever of the two answers is recorded; measured,
                    // `Vals IN Deny[*]` is 19 too. What changes is that the undecidable reason
                    // disappears and an `InComparison` naming the collision takes its place, which is why
                    // `a_decided_element_collision_outranks_an_undecidable_containment` asserts on the
                    // recorded messages and `a_reported_collision_is_recorded_as_a_membership_check`
                    // asserts on the variant -- the first alone is satisfied by dropping both answers.
                    //
                    // Why nothing caught it. `found_in_string` outranks the collision arm for
                    // essentially every string pairing, so that arm has observable effect only when no
                    // right-hand value is a string -- which is what the collision fix's reproducer used, at
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
                            undecided.insert(Rc::as_ptr(eachl));
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
                            undecided.insert(Rc::as_ptr(eachl));
                            continue;
                        }
                    }

                    if element_collision {
                        collides.insert(Rc::as_ptr(eachl));
                    }

                    diff.insert(Rc::as_ptr(eachl));
                }

                // One result per left-hand value, and exactly one verdict for each, so `some` folds one
                // status per value (as the enumerating spelling files them) and `some X IN Y` over ports
                // `22` and `8080` against `[22, 443]` passes on the `22`. A value that matched is a
                // `Success` naming it; a value left unmatched is a `Fail` naming it, with itself as the
                // collision when an element of it was a member of some entry, which `NOT IN` denies on. A
                // value the loop could not decide is the `NotComparable` already pushed for it and nothing
                // else: a second verdict beside a refusal is what a `NOT IN` report would show
                // (`an_unanswerable_containment_records_one_verdict_not_two`). A value nothing was
                // compared with (an empty list against string haystacks only, the one pairing
                // `found_in_string` declines) has no result at all, a PASS in both polarities as the
                // `(None, Some)` string arm answers it, and its compared siblings keep their own verdicts
                // (`an_uncompared_empty_list_does_not_silence_its_siblings`).
                //
                // Membership of the four sets is by identity (the address of the value's `Rc`, the key
                // the loop above inserted), so two equal left-hand values are classified each on its
                // own, exactly as the loop above classified them, and each question is one hash lookup.
                // An empty collection and a refused value have their records already (the
                // `EmptyCollection` per right-hand value, the refusal), so neither gets a second one.
                results.extend(unanswerable);
                for eachl in &lhs_selected {
                    let key = Rc::as_ptr(eachl);
                    if empties.contains(&key) || undecided.contains(&key) {
                        continue;
                    }
                    let lhs = vec![Rc::clone(eachl)];
                    results.push(if diff.contains(&key) {
                        let collides = if collides.contains(&key) {
                            lhs.clone()
                        } else {
                            vec![]
                        };
                        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(
                            QueryIn::partly_matched(
                                lhs.clone(),
                                collides,
                                lhs,
                                rhs_selected.clone(),
                            ),
                        )))
                    } else {
                        ValueEvalResult::ComparisonResult(ComparisonResult::Success(
                            Compare::QueryIn(QueryIn::new(vec![], lhs, rhs_selected.clone())),
                        ))
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
        // The two arms that expand rather than unwrap -- a literal scalar against a query list, and a
        // query list against a literal scalar -- walk the list element by element and compare each
        // element with plain `compare_eq_symmetric`. The expansion IS the one unwrap for them, and
        // asking the unwrapping comparator on top of it, which they did, took a second level off a
        // nested element: `LL == "a"` held for an `LL` of `[["a"]]` because the element `["a"]` was
        // unwrapped again to `"a"`, while `%ll == "a"` with the same list as a rule literal reached
        // the `(Some, Some)` arm, unwrapped once to `["a"]`, and was refused. A one-element list
        // inside the list is an element like any other; for a flat list both operands are scalars by
        // the time they are compared and nothing changes.
        match (is_literal(lhs), is_literal(rhs)) {
            // Two values the author wrote, compared as the values they are, an empty list included:
            // `[] == "x"` is a refusal of the kinds, as `[1] == "x"` is, and `[] == []` holds. Only a
            // document value can be the empty collection; see `empty_document_list_against_a_scalar`.
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

                // The document value is the pair's subject and the literal is what it was compared
                // with, in each call below, although the literal is the clause's left operand. `==`
                // is symmetric, so the verdict is the same either way; what differs is the finding.
                // A rule literal is built with `Path::root()`, so filed as the subject it has no
                // resource to group under and no line to quote, and the report printed
                // `PropertyPath = [L:0,C:0]` beside the first lines of the document. The two-query arm
                // below already prefers the document value for the same reason, and a parameterized
                // rule's literal argument reaches this arm rather than that one, so this arm has to
                // make the same choice or `%expected == %replaced` loses the path that arm would name.
                match &*l {
                    PathAwareValue::List(_) => {
                        for each in rhs {
                            // A document value that is an empty list, against a scalar literal, before
                            // the comparator refuses the pair. The literal list on the left, empty or
                            // not, is a value and goes to the comparator.
                            if let Some(result) =
                                empty_document_list_against_a_scalar(&each, &l, EmptySide::Rhs)
                            {
                                results.push(result);
                                continue;
                            }
                            results.push(match_value(
                                each,
                                Rc::clone(&l),
                                compare_eq_unwrapping_a_one_element_list,
                            ));
                        }
                    }

                    single_value => {
                        for eachr in rhs {
                            match &*eachr {
                                PathAwareValue::List((_, rhsl)) => {
                                    // Walking the elements of an empty list pushes nothing, so
                                    // `%expected == Resources.*.Properties.L` held over an `L` of
                                    // `[]`. See `ValueEvalResult::EmptyCollection`.
                                    if rhsl.is_empty() {
                                        results.push(ValueEvalResult::EmptyCollection {
                                            side: EmptySide::Rhs,
                                            empty: Rc::clone(&eachr),
                                            other: Some(Rc::clone(&l)),
                                        });
                                    }
                                    // Plain `compare_eq_symmetric` on the elements: the expansion
                                    // is the one unwrap, so asking the unwrapping comparator as
                                    // well took a second level off a nested element (see the note
                                    // at the head of this `match`).
                                    for each_rhs in rhsl {
                                        results.push(match_value(
                                            Rc::new(each_rhs.clone()),
                                            Rc::new(single_value.clone()),
                                            compare_eq_symmetric,
                                        ));
                                    }
                                }

                                rest_rhs => {
                                    results.push(match_value(
                                        Rc::new(rest_rhs.clone()),
                                        Rc::new(single_value.clone()),
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
                    PathAwareValue::List(_) => {
                        // The list goes to the comparator whole, with no inline unwrap of a
                        // one-element list as `rhsl[0]` for a scalar left-hand value: the comparator
                        // performs that unwrap itself, so an inline one would take two levels off, and
                        // `Val == [["a"]]` would pass for a `Val` of `a` while the same pair spelled
                        // `%x == [["a"]]` reaches `(Some, Some)`, unwraps once, and refuses `"a"`
                        // against `["a"]`. One unwrap is the documented reading
                        // (see `compare_eq_unwrapping_a_one_element_list`), the comparator is where
                        // it lives, and every arm asking the comparator is what keeps the arms from
                        // disagreeing. The reported right-hand operand is the list the rule wrote, not
                        // its element, which is also what `(Some, Some)` reports.
                        for each in lhs_flattened {
                            // A document value that is an empty list, against a scalar literal, before
                            // the comparator refuses the pair. The literal list on the right, empty or
                            // not, is a value: `Mode == []` over a `Mode` of `"x"` is the refusal the
                            // comparator gives any list against a string, not an empty collection.
                            if let Some(result) =
                                empty_document_list_against_a_scalar(&each, &r, EmptySide::Lhs)
                            {
                                results.push(result);
                                continue;
                            }
                            results.push(match_value(
                                each,
                                Rc::clone(&r),
                                compare_eq_unwrapping_a_one_element_list,
                            ));
                        }
                    }

                    single_value => {
                        for each in lhs_flattened {
                            if let PathAwareValue::List((_, lhs_list)) = &*each {
                                // Walking the elements of an empty list pushes nothing, which must
                                // not pass the clause. See `ValueEvalResult::EmptyCollection`.
                                if lhs_list.is_empty() {
                                    results.push(ValueEvalResult::EmptyCollection {
                                        side: EmptySide::Lhs,
                                        empty: Rc::clone(&each),
                                        other: Some(Rc::clone(&r)),
                                    });
                                }
                                // Plain `compare_eq_symmetric` on the elements, for the reason
                                // given at the head of this `match`: the expansion is the unwrap.
                                for each_lhs in lhs_list {
                                    results.push(match_value(
                                        Rc::new(each_lhs.clone()),
                                        Rc::new(single_value.clone()),
                                        compare_eq_symmetric,
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
                // records. Deciding with `contains` makes `==` and `!=` between two queries the only
                // spellings that never report it: with `Num: 1` and `Str: "x"`, `Num == "x"` refuses
                // and names `not comparable int, String`, while `Num == Str` fails with no reason at
                // all and `Num != Str` **passes, exit 0, nothing in the report**. `<` behaved the same
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
                //
                // Per value, and apart from the unmatched, the way the two-query `IN` arm keeps its
                // `refused`. A value that matched nothing and could not be compared with something is
                // refused, not unmatched: its verdict is the refusal, and it is in neither the diff nor
                // the left operand the record is built from. Kept in the diff, it read as "unequal" the
                // moment the polarity flipped -- the negation wrapper accepts whatever is in `lhs` and
                // outside the matched set, so `some Vals[*] != One` over `["x", "y"]` against `1` PASSED
                // on two strings nothing could compare with an integer, where `some Vals[*] != 1` fails.
                // Each refused value also carries its own refusal, rather than one refusal standing for
                // every value the operator could not answer with the rest filed as plain inequality.
                let without_a_match =
                    |from: &[Rc<PathAwareValue>], against: &[Rc<PathAwareValue>]| {
                        let mut unmatched = Vec::with_capacity(from.len());
                        let mut refusals: Vec<(
                            Rc<PathAwareValue>,
                            Rc<PathAwareValue>,
                            Unanswered,
                        )> = Vec::new();
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
                            // `each` has no equal anywhere in `against`. A pairing it could not answer
                            // is its verdict; otherwise it is one of the values that fails the clause.
                            match refused {
                                Some((other, unanswered)) => {
                                    refusals.push((Rc::clone(each), other, unanswered))
                                }
                                None => unmatched.push(Rc::clone(each)),
                            }
                        }
                        (unmatched, refusals)
                    };

                // Both directions, because `==` between two queries asks whether the operand sets
                // denote the same values, and one direction alone cannot see an extra value on the
                // other side. Picking the direction by operand-set size -- which is what stood here --
                // reads as set equality and is not: `A` selecting `[1, 2]` against `B` selecting
                // `[1, 1]` are the same length, so only `B \ A` was checked, it was empty, and the
                // clause passed on two operands that plainly differ.
                let (lhs_unmatched, lhs_refusals) = without_a_match(&lhs_selected, &rhs_selected);
                let (rhs_unmatched, rhs_refusals) = without_a_match(&rhs_selected, &lhs_selected);

                // The left operand the record is built from, without the values whose verdict is a
                // refusal, for the reason above. The right-hand refusals are reported only when the left
                // has none: a left-hand refusal already names the pairing that had no answer, so `[1]`
                // against `["x"]` refuses once, as the pair it is, while `["a"]` against `["a", 5]`
                // still reports the `5` nothing on the left could be compared with, which is what keeps
                // that clause from passing as equal on the one value that matched.
                let lhs_compared = reverse_diff(
                    lhs_refusals
                        .iter()
                        .map(|(each, _, _)| Rc::clone(each))
                        .collect(),
                    &lhs_selected,
                );
                let rhs_refusals = if lhs_refusals.is_empty() {
                    rhs_refusals
                } else {
                    Vec::new()
                };

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

                // Read before `rhs_selected` moves into the record below; see `nothing_was_compared`.
                let every_rhs_entry_unresolved = !rhs.is_empty() && rhs_selected.is_empty();

                // `lhs_unmatched` travels with the diff either way, because it is what `!=` negates
                // against and the two are the same set only when the diff was taken from the left.
                // Both mismatch sets travel with the result, whichever side the diff was taken from:
                // beside an undecidable marker on the right `eval.rs` decides by the right-hand
                // mismatches alone (`QueryIn::rhs_unmatched`).
                let query_in = if take_rhs {
                    QueryIn::from_rhs(rhs_unmatched, lhs_unmatched, lhs_compared, rhs_selected)
                } else {
                    QueryIn::new(lhs_unmatched, lhs_compared, rhs_selected)
                        .with_rhs_unmatched(Some(rhs_unmatched))
                };

                // The refusals first, one per value the operator could not answer, and then the diff
                // over the values it could. Both are reported, because each is about different values:
                // a refused value is outside the diff and the diff holds only the values that were
                // compared and found unequal.
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
                // from `--output-format json --structured`, which undoes the point of carrying it at all.
                // Making it render means changing that mapping, which also currently discards
                // `custom_message` for this variant -- a separate defect and a wider change than this one.
                //
                // A refusal must stay a `NotComparable`: the negation wrapper passes that through
                // untouched and inverts `Fail`, so this is what keeps `%q != %r` failing on a pair it
                // cannot compare instead of passing at exit 0. With the refused values out of `lhs`, the
                // inverted record cannot accept them either.
                for (each, other, reason) in lhs_refusals.into_iter().chain(rhs_refusals) {
                    results.push(not_comparable_because(each, other, reason));
                }

                // With the diff empty the record is a `Success` whose accepted set is every compared
                // value: `some Vals[*] == One` over `[1, "x"]` has one value matched and one refused,
                // and passes as `some Vals[*] == 1` does, with the refusal as the `"x"`'s verdict. When
                // every left-hand value was refused there is no record at all, as in the `IN` arm: the
                // refusals are the whole report, and a record over no values would say nothing about
                // the right-hand extras either, since those are compared with nothing.
                //
                // Nothing was compared either when every right-hand entry is unresolved: `rhs_selected`
                // is empty while `rhs` is not (an empty `rhs` never reaches this arm; `nothing_to_compare`
                // answers it first). Each left-hand value already carries one `RhsUnresolved` per such
                // entry, pushed above, and that is its whole verdict: decided for a value the document
                // lacks, undecided for the marker a key filter leaves for a map it could not decide. The
                // diff over no right-hand values filed a `Fail` beside it for every left-hand value, a
                // DECIDED failure about a comparison that never ran, and a `when` gate read that decided
                // failure first: `when Cfg.Enabled == Cfg[ keys == %missing ].Enabled { .. }` reported
                // its rule not applicable at exit 0 with the body unchecked, while the same clause asserted
                // failed, and the same gate with the undecidable selection on the LEFT failed its rule.
                let nothing_was_compared = (!lhs_selected.is_empty() && query_in.lhs.is_empty())
                    || every_rhs_entry_unresolved;
                if !nothing_was_compared {
                    results.push(ValueEvalResult::ComparisonResult(
                        if query_in.diff.is_empty() {
                            ComparisonResult::Success(Compare::QueryIn(query_in))
                        } else {
                            ComparisonResult::Fail(Compare::QueryIn(query_in))
                        },
                    ));
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
        // SKIP for nothing on the left, `EmptyRhs` for nothing on the right; `nothing_to_compare` says
        // why each, and the `(C, bool)` wrapper below turns the second into a verdict by polarity.
        if let Some(early) = nothing_to_compare(lhs, rhs) {
            return Ok(early);
        }

        match self {
            CmpOperator::Eq => EqOperation {}.compare(lhs, rhs),
            // With no shape, because this entry has none to give: `IN` built here reads every resolved
            // right-hand string as a haystack. `binary_operation` does not come through here for `IN`;
            // it builds `InOperation` itself with the shape the retrieval reported.
            CmpOperator::In => InOperation::named().compare(lhs, rhs),
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

/// The polarity wrapper: `(operator, true)` is the negated operator (`!=`, `NOT IN`), and `(operator,
/// false)` is the operator itself. Over any `Comparator` rather than over `CmpOperator` alone, so that
/// `(InOperation { .. }, not_in)` -- the way `binary_operation` reaches `IN` with the shape of its
/// right-hand side -- negates by the same rules as `(CmpOperator::In, not_in)`.
impl<C: Comparator> Comparator for (C, bool) {
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
                                            // `diff` is not that set whenever `diff_from` is `Rhs`, so
                                            // the filter reads `lhs_unmatched`, not `diff`. Reading
                                            // `reverse_diff(qin.diff, &qin.lhs)` rests on the premise
                                            // that a right-hand diff means "the left had no unmatched
                                            // ones", so every left value would survive the filter.
                                            // `EqOperation` also takes the right-hand diff when the
                                            // left operand's unmatched values are all rule literals and
                                            // so unreportable -- which is exactly what a parameterized
                                            // rule's `%expected != %query` is -- and then the premise
                                            // is false. `lhs \ rhs_unmatched` for two disjoint operand
                                            // sets is all of `lhs`, so `!=` would report Fail for two
                                            // values that are comparable and unequal:
                                            // `parse_int("7") != 1` at exit 19, with a reason reading
                                            // that `[[L:0,C:0]]` "was not present in" the document
                                            // value.
                                            //
                                            // The same where the premise does hold. With every left
                                            // value matched, `lhs_unmatched` is empty and the filter
                                            // keeps all of `lhs` -- the answer `diff` gives there too,
                                            // because a right-hand value with no equal on the left
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
                                                        )
                                                        .with_rhs_unmatched(qin.rhs_unmatched),
                                                    )),
                                                )
                                            } else {
                                                ValueEvalResult::ComparisonResult(
                                                    ComparisonResult::Fail(Compare::QueryIn(
                                                        QueryIn::new(
                                                            reverse_diff,
                                                            qin.lhs,
                                                            qin.rhs,
                                                        )
                                                        .with_rhs_unmatched(qin.rhs_unmatched),
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
                                                    QueryIn::new(reverse_diff, qin.lhs, qin.rhs)
                                                        .with_rhs_unmatched(qin.rhs_unmatched),
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
