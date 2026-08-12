// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The outcome of evaluating a clause, block, or rule, and the algebra for combining
//! outcomes.
//!
//! # Why this exists alongside [`Status`]
//!
//! [`Status`] is the reported vocabulary: `PASS`, `FAIL`, `SKIP`. It is what appears
//! in JSON, SARIF and JUnit output and what the exit code is derived from, so it is
//! part of the tool's contract and is not changing.
//!
//! It is a poor *internal* representation, because `SKIP` conflates outcomes that the
//! folds have to treat differently:
//!
//! - a rule that does not apply to this input (the query selected nothing)
//! - a clause that could not be evaluated (its reference resolved to nothing)
//! - a clause that is vacuously satisfied (a negated comparison against an empty
//!   reference)
//!
//! Those three collapse to `SKIP`, and the fourteen evaluation folds then treat that
//! single value inconsistently. Concretely, `eval_conjunction_clauses` short-circuits
//! on `PASS` but absorbs `SKIP`, so returning `PASS` for a vacuously-satisfied clause
//! silently satisfies an entire `or` block and abandons its sibling disjuncts:
//!
//! ```text
//! X != %empty_denylist  or  X == true
//! ```
//!
//! The first disjunct is vacuously true, so the real check never runs and a violating
//! input passes. That defect was introduced and then caught during the work that
//! preceded this module, which is why the distinction is now carried in the type
//! rather than in a comment.
//!
//! # The algebra
//!
//! [`Outcome::and`] and [`Outcome::or`] are each commutative, associative and
//! idempotent, and share [`Outcome::NotApplicable`] as their identity:
//!
//! - `and` — identity [`Outcome::NotApplicable`], absorbing [`Outcome::Violated`]
//! - `or`  — identity [`Outcome::NotApplicable`], absorbing [`Outcome::Satisfied`]
//!
//! This is **not** a bounded lattice, and the distinction matters. Absorption
//! (`a.and(a.or(b)) == a`) fails at exactly `a == NotApplicable`, because the shared
//! identity is not a bound of either operation. Restricted to the three
//! evidence-bearing variants it *is* a lattice: `Violated < Unevaluatable < Satisfied`
//! is a chain with `and` as min and `or` as max. `NotApplicable` sits outside that
//! chain as the identity of both.
//!
//! Distributivity also fails, and must. `Satisfied.and(Violated.or(NotApplicable))` is
//! `Violated`, while the distributed form is `Satisfied` — so a test asserting
//! distributivity would assert a violation being laundered into a pass. The property to
//! rely on instead is monotonicity in the evidence order, which does hold: no
//! combination reports more evidence than its strongest operand.
//!
//! `outcome_tests` asserts all of this exhaustively over every pair and triple rather
//! than by sampling, and pins the exact set of absorption failures so that nobody
//! "fixes" it by making the identity absorbing — that would let an inapplicable rule
//! satisfy a disjunction, which is the defect this module exists to prevent.
//!
//! The rule that closes the empty-input defects: **a fold over zero elements returns
//! the identity, never `Satisfied`.** A property whose value is `[]` previously
//! satisfied a `match_all` block clause, because the fold counted zero failures and
//! concluded success.

use crate::rules::Status;

use super::ClauseRole;

/// Why an evaluation reached the answer it did.
///
/// Prefer this over [`Status`] inside the evaluator; convert with
/// [`Outcome::to_status`] at the reporting boundary.
///
/// Wired into the per-value fold in `eval_guard_access_clause`, which folds with
/// [`Outcome::all`]/[`Outcome::any`] and converts back with [`Outcome::to_status`].
///
/// That conversion was blocked for a long time on deciding what a `when` condition means
/// when its comparison has nothing to compare: the vacuous PASS that a naive conversion
/// removes is load-bearing for gates, and removing it makes `eval_rule` treat the rule as
/// inapplicable and drop every check in the guarded body. Three attempts turned a blocked
/// violating template into a passing one and were reverted.
///
/// What unblocked it was splitting the empty-collection arm by [`super::ClauseRole`]: an
/// assertion contributes SKIP so it cannot absorb a disjunction, a gate still contributes
/// PASS so it stays open. That split is only sound once the role survives the named-rule
/// boundary, which is why keying the rule-status cache on `(rule, role)` had to land first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The check ran and the input satisfied it.
    ///
    /// This is the only variant that constitutes affirmative evidence, and therefore
    /// the only one that may satisfy a disjunction.
    Satisfied,

    /// The check ran and the input violated it.
    Violated,

    /// The check does not apply to this input: the query selected nothing, or a
    /// gating condition excluded it.
    ///
    /// Not evidence in either direction, so it is the identity element of both folds.
    /// It must never satisfy a disjunction — a rule that did not apply cannot stand
    /// in for one that passed.
    NotApplicable,

    /// The check could not be evaluated: a reference resolved to no values, or a type
    /// did not support the operation.
    ///
    /// Distinct from [`Outcome::NotApplicable`] because the correct reported status
    /// depends on the role the clause played. An assertion that cannot be evaluated
    /// is a failure — the rule claimed something it could not establish. A *gate*
    /// that cannot be evaluated is merely inapplicable, because failing a gate makes
    /// its rule inapplicable and silently drops every check inside it.
    Unevaluatable,
}

impl Outcome {
    /// Conjunction: every element must be satisfied.
    ///
    /// Identity [`Outcome::NotApplicable`], absorbing [`Outcome::Violated`]. An
    /// unevaluatable element propagates unless something already failed, so the
    /// stronger reason survives.
    pub(crate) fn and(self, other: Outcome) -> Outcome {
        use Outcome::*;
        match (self, other) {
            // A violation anywhere fails the conjunction, whatever else is present.
            (Violated, _) | (_, Violated) => Violated,

            // Inapplicable is the identity: it defers to the other side entirely.
            (NotApplicable, keep) | (keep, NotApplicable) => keep,

            // Neither side failed and neither is inapplicable. An unevaluatable
            // element dominates a satisfied one: the conjunction as a whole was not
            // fully established.
            (Unevaluatable, _) | (_, Unevaluatable) => Unevaluatable,

            (Satisfied, Satisfied) => Satisfied,
        }
    }

    /// Disjunction: at least one element must be satisfied.
    ///
    /// Identity [`Outcome::NotApplicable`], absorbing [`Outcome::Satisfied`].
    ///
    /// The load-bearing property is that only [`Outcome::Satisfied`] absorbs.
    /// `NotApplicable` and `Unevaluatable` must not, or a branch that never ran would
    /// satisfy the whole disjunction and its siblings would go unevaluated.
    pub(crate) fn or(self, other: Outcome) -> Outcome {
        use Outcome::*;
        match (self, other) {
            // One satisfied branch is enough.
            (Satisfied, _) | (_, Satisfied) => Satisfied,

            // Identity.
            (NotApplicable, keep) | (keep, NotApplicable) => keep,

            // Nothing was satisfied. An unevaluatable branch means the disjunction
            // could not be decided, which is weaker than a clean violation, so it
            // dominates: reporting Violated here would blame the input for a
            // reference that failed to resolve.
            (Unevaluatable, _) | (_, Unevaluatable) => Unevaluatable,

            (Violated, Violated) => Violated,
        }
    }

    /// The identity element of both [`Outcome::and`] and [`Outcome::or`].
    ///
    /// A fold over zero elements returns this. Returning [`Outcome::Satisfied`]
    /// instead is the empty-input defect class: a property whose value is `[]` would
    /// satisfy a `match_all` block clause because the fold saw no failures.
    pub(crate) const fn identity() -> Outcome {
        Outcome::NotApplicable
    }

    /// Fold a sequence under [`Outcome::and`], returning [`Outcome::identity`] when
    /// empty.
    pub(crate) fn all<I: IntoIterator<Item = Outcome>>(iter: I) -> Outcome {
        iter.into_iter().fold(Outcome::identity(), Outcome::and)
    }

    /// Fold a sequence under [`Outcome::or`], returning [`Outcome::identity`] when
    /// empty.
    pub(crate) fn any<I: IntoIterator<Item = Outcome>>(iter: I) -> Outcome {
        iter.into_iter().fold(Outcome::identity(), Outcome::or)
    }

    /// True when this outcome produces a `FAIL` verdict, and so blocks a deployment.
    ///
    /// Only [`Outcome::Violated`] does unconditionally; [`Outcome::Unevaluatable`]
    /// does so only as an assertion.
    ///
    /// This is **not** the question to ask about a gate. A gate that does not fail can
    /// still close, silently dropping every check it guards — see
    /// [`Outcome::closes_gate`]. Conflating the two is what makes a "the gate never
    /// failed" test look like a safety property when it is a tautology.
    pub(crate) fn blocks(self, role: ClauseRole) -> bool {
        matches!(self.to_status(role), Status::FAIL)
    }

    /// True when this outcome, used as a `when` condition, stops the guarded block from
    /// being evaluated.
    ///
    /// `eval_rule` returns `SKIP` for the whole rule when its condition is anything
    /// other than `PASS`, so a condition that merely *did not apply* drops the body
    /// exactly as thoroughly as one that failed. Only [`Outcome::Satisfied`] opens a
    /// gate.
    ///
    /// Deliberately takes no [`ClauseRole`]: the gate *is* the role, and closure does
    /// not depend on how the condition would have been reported. It is also why
    /// [`Outcome::blocks`] is the wrong predicate for gate safety —
    /// [`Outcome::NotApplicable`] and [`Outcome::Unevaluatable`] both close a gate
    /// while blocking nothing, and that gap is the silent-drop hazard.
    pub(crate) fn closes_gate(self) -> bool {
        !matches!(self, Outcome::Satisfied)
    }

    /// Collapse to the reported [`Status`].
    ///
    /// `role` matters for exactly one variant, [`Outcome::Unevaluatable`]: it is a
    /// failure as an assertion and inapplicable as a gate. Every other variant maps
    /// the same way regardless of role, which is what makes the role parameter safe
    /// to thread mechanically.
    pub(crate) fn to_status(self, role: ClauseRole) -> Status {
        match self {
            Outcome::Satisfied => Status::PASS,
            Outcome::Violated => Status::FAIL,
            Outcome::NotApplicable => Status::SKIP,
            Outcome::Unevaluatable => {
                if role.is_strict() {
                    Status::FAIL
                } else {
                    Status::SKIP
                }
            }
        }
    }

    /// Lift a reported [`Status`] back into an outcome.
    ///
    /// Lossy in one direction by construction: `SKIP` becomes
    /// [`Outcome::NotApplicable`], because the reason it was skipped is exactly the
    /// information `Status` discards. Use only at boundaries where a `Status` is all
    /// that is available, such as a rule status resolved from the recorder.
    pub(crate) fn from_status(status: Status) -> Outcome {
        match status {
            Status::PASS => Outcome::Satisfied,
            Status::FAIL => Outcome::Violated,
            Status::SKIP => Outcome::NotApplicable,
        }
    }

    /// Invert a satisfied/violated outcome, leaving the two non-evidence variants
    /// unchanged.
    ///
    /// Negating "did not apply" or "could not be evaluated" must not manufacture
    /// affirmative evidence — that is the defect where `not <skipped rule>` reported
    /// compliance for a check that never ran.
    ///
    /// Not called by the evaluator, and not for want of finishing the migration: this
    /// evaluator has no verdict-negation site. Negation is applied to *flags* before a
    /// comparison happens (`comparator.1 ^ gac.negation` in `eval_guard_access_clause`), and
    /// to *evidence payloads* afterwards (the `(CmpOperator, bool)` wrapper in `operators.rs`
    /// rebuilds `Compare` values with reversed diffs so the report names the right values).
    /// Neither is an `Outcome` being inverted. The two places that do invert a verdict —
    /// `eval_guard_named_clause` and `eval_parameterized_rule_call` — deliberately fail closed
    /// on SKIP rather than leaving it unchanged, which is the opposite of what this does, so
    /// routing them through it would be wrong rather than merely verbose.
    ///
    /// Retained rather than deleted because `de_morgan_holds_over_the_whole_domain` is stated
    /// in terms of it, and that law is part of the algebra's specification: it is verified over
    /// all sixteen pairs, and its comment records an earlier version that restricted itself to
    /// the evidence-bearing variants on reasoning that turned out to be wrong. Deleting the
    /// function would delete the law.
    #[allow(dead_code)]
    pub(crate) fn negate(self) -> Outcome {
        match self {
            Outcome::Satisfied => Outcome::Violated,
            Outcome::Violated => Outcome::Satisfied,
            unchanged @ (Outcome::NotApplicable | Outcome::Unevaluatable) => unchanged,
        }
    }
}
