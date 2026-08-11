// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exhaustive tests for the [`Outcome`] algebra.
//!
//! Every test here enumerates the whole domain rather than sampling it. The domain is
//! small enough that there is no reason not to: 4 variants gives 16 pairs, 64 triples,
//! and 8 variant/role combinations. Sampling is how the defects this module exists to
//! prevent survived review in the first place.

use super::outcome::Outcome;
use super::ClauseRole;
use crate::rules::Status;

/// The complete domain. Any new variant must be added here, and the exhaustiveness
/// test below fails if it is not.
const ALL: [Outcome; 4] = [
    Outcome::Satisfied,
    Outcome::Violated,
    Outcome::NotApplicable,
    Outcome::Unevaluatable,
];

const ROLES: [ClauseRole; 2] = [ClauseRole::Assertion, ClauseRole::Gate];

/// Asserts that the evaluator does not yet use [`Outcome`], and fails when that changes.
///
/// `outcome.rs` carries `#[allow(dead_code)]` because CI runs `cargo clippy -- -D
/// warnings` (`.github/workflows/pr.yml:94`), so an unwired module cannot simply be left
/// to warn — the build would fail. That suppression costs the one signal that would
/// otherwise say "this algebra is not connected to anything", and a partial rewiring that
/// left half the operations orphaned would then be invisible.
///
/// This test restores the signal in a form that cannot be suppressed by a lint attribute:
/// it greps the evaluator for constructor uses of the type. While the module is dormant
/// there are none, and that is asserted rather than assumed. The first real rewiring makes
/// this test fail, which is the intended prompt to delete it along with the `allow`.
///
/// Deliberately a string search and not a type-level check: the property is about whether
/// *other* modules reference this one, which the type system cannot express from inside.
#[test]
fn the_evaluator_does_not_yet_use_this_algebra() {
    let eval_rs = include_str!("../eval.rs");

    let uses: Vec<&str> = eval_rs
        .lines()
        .filter(|line| {
            let code = line.split("//").next().unwrap_or("");
            code.contains("Outcome::") || code.contains("Outcome>") || code.contains("-> Outcome")
        })
        .collect();

    assert!(
        uses.is_empty(),
        "eval.rs now references Outcome, so the algebra is being wired in. Remove the \
         `#[allow(dead_code)]` from outcome.rs, delete this test, and make sure the \
         gating-semantics question in that module's docs is settled first. Found:\n{}",
        uses.join("\n")
    );
}

/// Guards the `ALL` array against a variant being added to `Outcome` without being
/// added here, which would silently reduce every other test's coverage.
///
/// Uses an exhaustive match so adding a variant is a compile error, not a silent gap.
#[test]
fn all_covers_every_variant() {
    for o in ALL {
        // Exhaustive: a new variant makes this fail to compile.
        match o {
            Outcome::Satisfied
            | Outcome::Violated
            | Outcome::NotApplicable
            | Outcome::Unevaluatable => {}
        }
    }
    assert_eq!(ALL.len(), 4, "ALL must list every Outcome variant exactly once");

    // No duplicates, so the count above is a real coverage guarantee.
    for (i, a) in ALL.iter().enumerate() {
        for (j, b) in ALL.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "ALL contains a duplicate variant");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// `and` — conjunction. Identity NotApplicable, absorbing Violated.
// ---------------------------------------------------------------------------

/// All 16 pairs, written out as an explicit truth table rather than derived from the
/// implementation, so the test disagrees with the code if either changes.
#[test]
fn and_truth_table_is_exhaustive() {
    use Outcome::*;
    let cases = [
        (Satisfied, Satisfied, Satisfied),
        (Satisfied, Violated, Violated),
        (Satisfied, NotApplicable, Satisfied),
        (Satisfied, Unevaluatable, Unevaluatable),
        (Violated, Satisfied, Violated),
        (Violated, Violated, Violated),
        (Violated, NotApplicable, Violated),
        (Violated, Unevaluatable, Violated),
        (NotApplicable, Satisfied, Satisfied),
        (NotApplicable, Violated, Violated),
        (NotApplicable, NotApplicable, NotApplicable),
        (NotApplicable, Unevaluatable, Unevaluatable),
        (Unevaluatable, Satisfied, Unevaluatable),
        (Unevaluatable, Violated, Violated),
        (Unevaluatable, NotApplicable, Unevaluatable),
        (Unevaluatable, Unevaluatable, Unevaluatable),
    ];
    assert_eq!(cases.len(), ALL.len() * ALL.len(), "table must cover all pairs");

    for (a, b, want) in cases {
        assert_eq!(a.and(b), want, "and({a:?}, {b:?})");
    }
}

#[test]
fn and_identity_is_not_applicable() {
    for o in ALL {
        assert_eq!(Outcome::NotApplicable.and(o), o, "left identity for {o:?}");
        assert_eq!(o.and(Outcome::NotApplicable), o, "right identity for {o:?}");
    }
}

#[test]
fn and_absorbs_violated() {
    for o in ALL {
        assert_eq!(Outcome::Violated.and(o), Outcome::Violated);
        assert_eq!(o.and(Outcome::Violated), Outcome::Violated);
    }
}

#[test]
fn and_is_commutative() {
    for a in ALL {
        for b in ALL {
            assert_eq!(a.and(b), b.and(a), "and not commutative for ({a:?}, {b:?})");
        }
    }
}

/// All 64 triples.
#[test]
fn and_is_associative() {
    for a in ALL {
        for b in ALL {
            for c in ALL {
                assert_eq!(
                    a.and(b).and(c),
                    a.and(b.and(c)),
                    "and not associative for ({a:?}, {b:?}, {c:?})"
                );
            }
        }
    }
}

#[test]
fn and_is_idempotent() {
    for o in ALL {
        assert_eq!(o.and(o), o, "and not idempotent for {o:?}");
    }
}

// ---------------------------------------------------------------------------
// `or` — disjunction. Identity NotApplicable, absorbing Satisfied.
// ---------------------------------------------------------------------------

#[test]
fn or_truth_table_is_exhaustive() {
    use Outcome::*;
    let cases = [
        (Satisfied, Satisfied, Satisfied),
        (Satisfied, Violated, Satisfied),
        (Satisfied, NotApplicable, Satisfied),
        (Satisfied, Unevaluatable, Satisfied),
        (Violated, Satisfied, Satisfied),
        (Violated, Violated, Violated),
        (Violated, NotApplicable, Violated),
        (Violated, Unevaluatable, Unevaluatable),
        (NotApplicable, Satisfied, Satisfied),
        (NotApplicable, Violated, Violated),
        (NotApplicable, NotApplicable, NotApplicable),
        (NotApplicable, Unevaluatable, Unevaluatable),
        (Unevaluatable, Satisfied, Satisfied),
        (Unevaluatable, Violated, Unevaluatable),
        (Unevaluatable, NotApplicable, Unevaluatable),
        (Unevaluatable, Unevaluatable, Unevaluatable),
    ];
    assert_eq!(cases.len(), ALL.len() * ALL.len(), "table must cover all pairs");

    for (a, b, want) in cases {
        assert_eq!(a.or(b), want, "or({a:?}, {b:?})");
    }
}

#[test]
fn or_identity_is_not_applicable() {
    for o in ALL {
        assert_eq!(Outcome::NotApplicable.or(o), o, "left identity for {o:?}");
        assert_eq!(o.or(Outcome::NotApplicable), o, "right identity for {o:?}");
    }
}

#[test]
fn or_absorbs_satisfied() {
    for o in ALL {
        assert_eq!(Outcome::Satisfied.or(o), Outcome::Satisfied);
        assert_eq!(o.or(Outcome::Satisfied), Outcome::Satisfied);
    }
}

/// The property whose absence caused a wrong PASS: a branch that did not run, or
/// could not be evaluated, must never satisfy a disjunction on its own.
#[test]
fn or_is_only_satisfied_by_satisfied() {
    for a in ALL {
        for b in ALL {
            let satisfied = a.or(b) == Outcome::Satisfied;
            let either_satisfied = a == Outcome::Satisfied || b == Outcome::Satisfied;
            assert_eq!(
                satisfied, either_satisfied,
                "or({a:?}, {b:?}) claimed satisfied without a satisfied operand"
            );
        }
    }
}

#[test]
fn or_is_commutative() {
    for a in ALL {
        for b in ALL {
            assert_eq!(a.or(b), b.or(a), "or not commutative for ({a:?}, {b:?})");
        }
    }
}

#[test]
fn or_is_associative() {
    for a in ALL {
        for b in ALL {
            for c in ALL {
                assert_eq!(
                    a.or(b).or(c),
                    a.or(b.or(c)),
                    "or not associative for ({a:?}, {b:?}, {c:?})"
                );
            }
        }
    }
}

#[test]
fn or_is_idempotent() {
    for o in ALL {
        assert_eq!(o.or(o), o, "or not idempotent for {o:?}");
    }
}

// ---------------------------------------------------------------------------
// Empty folds. This is the WP-1 defect class.
// ---------------------------------------------------------------------------

/// A property whose value is `[]` used to satisfy a `match_all` block clause, because
/// the fold counted zero failures and concluded PASS. An empty fold must return the
/// identity, which is never affirmative evidence.
#[test]
fn empty_folds_return_identity_not_satisfied() {
    let empty: [Outcome; 0] = [];

    assert_eq!(Outcome::all(empty), Outcome::identity());
    assert_eq!(Outcome::any(empty), Outcome::identity());

    assert_ne!(
        Outcome::all(empty),
        Outcome::Satisfied,
        "an empty conjunction must not be affirmative evidence"
    );
    assert_ne!(
        Outcome::any(empty),
        Outcome::Satisfied,
        "an empty disjunction must not be affirmative evidence"
    );
}

#[test]
fn identity_is_shared_by_both_folds() {
    for o in ALL {
        assert_eq!(Outcome::identity().and(o), o);
        assert_eq!(Outcome::identity().or(o), o);
    }
}

#[test]
fn single_element_folds_are_the_element() {
    for o in ALL {
        assert_eq!(Outcome::all([o]), o, "all([{o:?}])");
        assert_eq!(Outcome::any([o]), o, "any([{o:?}])");
    }
}

/// `all`/`any` must agree with repeated application of the binary operators, over
/// every triple.
#[test]
fn folds_agree_with_binary_operators() {
    for a in ALL {
        for b in ALL {
            for c in ALL {
                assert_eq!(Outcome::all([a, b, c]), a.and(b).and(c));
                assert_eq!(Outcome::any([a, b, c]), a.or(b).or(c));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// `to_status` — the reporting boundary.
// ---------------------------------------------------------------------------

/// All 8 variant/role combinations.
#[test]
fn to_status_is_exhaustive_over_variants_and_roles() {
    use Outcome::*;
    let cases = [
        (Satisfied, ClauseRole::Assertion, Status::PASS),
        (Satisfied, ClauseRole::Gate, Status::PASS),
        (Violated, ClauseRole::Assertion, Status::FAIL),
        (Violated, ClauseRole::Gate, Status::FAIL),
        (NotApplicable, ClauseRole::Assertion, Status::SKIP),
        (NotApplicable, ClauseRole::Gate, Status::SKIP),
        // The only role-dependent variant.
        (Unevaluatable, ClauseRole::Assertion, Status::FAIL),
        (Unevaluatable, ClauseRole::Gate, Status::SKIP),
    ];
    assert_eq!(cases.len(), ALL.len() * ROLES.len());

    for (o, role, want) in cases {
        assert_eq!(o.to_status(role), want, "to_status({o:?}, {role:?})");
    }
}

/// Role must affect exactly one variant. If it starts affecting others, the role
/// threading stops being safe to do mechanically.
#[test]
fn only_unevaluatable_depends_on_role() {
    for o in ALL {
        let as_assertion = o.to_status(ClauseRole::Assertion);
        let as_gate = o.to_status(ClauseRole::Gate);
        if o == Outcome::Unevaluatable {
            assert_ne!(as_assertion, as_gate, "Unevaluatable must be role-dependent");
        } else {
            assert_eq!(as_assertion, as_gate, "{o:?} must not depend on role");
        }
    }
}

/// A gate must never report FAIL for a non-evidence outcome: a failing gate makes its
/// rule inapplicable and drops every check inside the guarded block.
#[test]
fn a_gate_only_fails_on_an_actual_violation() {
    for o in ALL {
        if o.to_status(ClauseRole::Gate) == Status::FAIL {
            assert_eq!(
                o,
                Outcome::Violated,
                "{o:?} failed as a gate, which would disarm the guarded block"
            );
        }
    }
}

#[test]
fn blocks_agrees_with_to_status() {
    for o in ALL {
        for role in ROLES {
            assert_eq!(o.blocks(role), o.to_status(role) == Status::FAIL);
        }
    }
}

// ---------------------------------------------------------------------------
// Round-tripping with `Status`.
// ---------------------------------------------------------------------------

#[test]
fn from_status_round_trips_for_every_status() {
    for (status, want) in [
        (Status::PASS, Outcome::Satisfied),
        (Status::FAIL, Outcome::Violated),
        (Status::SKIP, Outcome::NotApplicable),
    ] {
        assert_eq!(Outcome::from_status(status), want);
        // And back again, under either role, since none of these three is
        // role-dependent.
        for role in ROLES {
            assert_eq!(want.to_status(role), status, "round trip for {status:?}");
        }
    }
}

/// `from_status` cannot recover `Unevaluatable` — that is the information `Status`
/// discards, and the reason the evaluator should not round-trip through it.
#[test]
fn from_status_never_produces_unevaluatable() {
    for status in [Status::PASS, Status::FAIL, Status::SKIP] {
        assert_ne!(Outcome::from_status(status), Outcome::Unevaluatable);
    }
}

// ---------------------------------------------------------------------------
// `negate`.
// ---------------------------------------------------------------------------

#[test]
fn negate_is_exhaustive() {
    use Outcome::*;
    for (o, want) in [
        (Satisfied, Violated),
        (Violated, Satisfied),
        (NotApplicable, NotApplicable),
        (Unevaluatable, Unevaluatable),
    ] {
        assert_eq!(o.negate(), want, "negate({o:?})");
    }
}

/// Negating a non-evidence outcome must not manufacture evidence. This is the defect
/// where `not <skipped rule>` reported compliance for a check that never ran.
#[test]
fn negate_never_manufactures_evidence() {
    for o in ALL {
        let is_evidence = matches!(o, Outcome::Satisfied | Outcome::Violated);
        let negated_is_evidence = matches!(o.negate(), Outcome::Satisfied | Outcome::Violated);
        assert_eq!(
            is_evidence, negated_is_evidence,
            "negate({o:?}) changed whether the outcome is evidence"
        );
    }
}

#[test]
fn negate_is_an_involution() {
    for o in ALL {
        assert_eq!(o.negate().negate(), o, "negate not an involution for {o:?}");
    }
}

/// De Morgan, over the whole domain — all 16 pairs, both directions.
///
/// An earlier version of this test restricted itself to the evidence-bearing variants,
/// on the stated grounds that negation is not an inversion for `NotApplicable` and
/// `Unevaluatable` so the law could not apply to them. That reasoning was wrong: the law
/// holds for all 16 pairs, verified by enumeration. Restricting it left twelve pairs
/// unasserted, so an edit to `negate` could have broken the law on the non-evidence
/// variants without any test noticing.
#[test]
fn de_morgan_holds_over_the_whole_domain() {
    for a in ALL {
        for b in ALL {
            assert_eq!(
                a.and(b).negate(),
                a.negate().or(b.negate()),
                "de morgan failed: negate({a:?} and {b:?}) != negate({a:?}) or negate({b:?})"
            );
            assert_eq!(
                a.or(b).negate(),
                a.negate().and(b.negate()),
                "de morgan failed: negate({a:?} or {b:?}) != negate({a:?}) and negate({b:?})"
            );
        }
    }
}

/// The partial order under which both operations are monotone.
///
/// `Violated` is the bottom and `Satisfied` the top; the two non-evidence variants sit
/// incomparably between them. This is the coarsest order on the four variants making
/// both `and` and `or` monotone, so it is the order the evaluator may reason with.
fn at_most_as_much_evidence_as(a: Outcome, b: Outcome) -> bool {
    use Outcome::*;
    matches!(
        (a, b),
        (Violated, _)
            | (_, Satisfied)
            | (NotApplicable, NotApplicable)
            | (Unevaluatable, Unevaluatable)
    )
}

/// Monotonicity in the evidence order: strengthening an operand can never weaken the
/// result.
///
/// This is the property to rely on in place of distributivity, which genuinely fails.
/// `Satisfied.and(Violated.or(NotApplicable))` is `Violated` while the distributed form
/// is `Satisfied`, so asserting distributivity would assert a violation being laundered
/// into a pass. Monotonicity is the guarantee that actually protects against that: no
/// combination may report more evidence than its strongest operand.
#[test]
fn both_operations_are_monotone_in_the_evidence_order() {
    for a in ALL {
        for b in ALL {
            if !at_most_as_much_evidence_as(a, b) {
                continue;
            }
            for c in ALL {
                assert!(
                    at_most_as_much_evidence_as(a.and(c), b.and(c)),
                    "and not monotone: {a:?} <= {b:?} but {:?} is not <= {:?} (with {c:?})",
                    a.and(c),
                    b.and(c)
                );
                assert!(
                    at_most_as_much_evidence_as(a.or(c), b.or(c)),
                    "or not monotone: {a:?} <= {b:?} but {:?} is not <= {:?} (with {c:?})",
                    a.or(c),
                    b.or(c)
                );
            }
        }
    }
}

/// Absorption fails, and it must. Pinning the exact failure set stops anyone "fixing" it
/// by making the shared identity absorbing, which would let an inapplicable rule satisfy
/// a disjunction — the defect this module exists to prevent.
///
/// The law holds except when `a` is `NotApplicable` and `b` is anything else, because
/// `NotApplicable` is the identity of both operations rather than a bound of either.
/// That is also why the module is not a bounded lattice.
#[test]
fn absorption_fails_exactly_at_the_shared_identity() {
    for a in ALL {
        for b in ALL {
            let absorbs = a.and(a.or(b)) == a && a.or(a.and(b)) == a;
            let expected = a != Outcome::NotApplicable || b == Outcome::NotApplicable;
            assert_eq!(
                absorbs, expected,
                "absorption for a={a:?} b={b:?} did not match what the shared identity implies"
            );
        }
    }
}

/// The three evidence-bearing variants form a chain, with `and` as min and `or` as max.
/// This is the structure the module doc describes, pinned so the doc cannot drift from
/// the code.
#[test]
fn the_evidence_variants_form_a_chain_under_both_operations() {
    const CHAIN: [Outcome; 3] = [
        Outcome::Violated,
        Outcome::Unevaluatable,
        Outcome::Satisfied,
    ];
    for (i, a) in CHAIN.iter().copied().enumerate() {
        for (j, b) in CHAIN.iter().copied().enumerate() {
            assert_eq!(
                a.and(b),
                CHAIN[i.min(j)],
                "{a:?} and {b:?} was not the weaker of the two"
            );
            assert_eq!(
                a.or(b),
                CHAIN[i.max(j)],
                "{a:?} or {b:?} was not the stronger of the two"
            );
        }
    }
}

/// `negate` distributes over both folds, for every triple. This is what a `not` wrapped
/// around a block relies on.
#[test]
fn negate_distributes_over_both_folds() {
    for a in ALL {
        for b in ALL {
            for c in ALL {
                let seq = [a, b, c];
                let negated = seq.map(Outcome::negate);
                assert_eq!(
                    Outcome::all(seq).negate(),
                    Outcome::any(negated),
                    "negate(all({a:?}, {b:?}, {c:?})) disagreed with any of the negations"
                );
                assert_eq!(
                    Outcome::any(seq).negate(),
                    Outcome::all(negated),
                    "negate(any({a:?}, {b:?}, {c:?})) disagreed with all of the negations"
                );
            }
        }
    }
}

/// `blocks(Gate)` is the WRONG predicate for gate safety, and this pins why.
///
/// An earlier version of this file asserted `!blocks(Gate)` over every non-violating
/// sequence and called that "gate safety at the fold level". That assertion cannot fail:
/// for `Gate`, `to_status` maps both non-evidence variants to `SKIP`, so nothing except
/// `Violated` can ever make `blocks` true — and `Violated` was excluded from the input
/// set by construction. The test passed for a reason unrelated to its name.
///
/// The real hazard is that a gate does not need to FAIL to be unsafe. `eval_rule` returns
/// `SKIP` for the entire rule when its condition is anything other than `PASS`
/// (`eval.rs:2082`), so a condition that merely did not apply drops every check in the
/// guarded body just as thoroughly as one that failed — while reporting nothing. That is
/// the wrong-PASS shape: exit 0 with the check silently unenforced.
///
/// So the honest statement is that these two predicates disagree, and the disagreement is
/// exactly the silent-drop set.
#[test]
fn blocking_a_deployment_and_closing_a_gate_are_different_questions() {
    // The tautology, kept as a pin: for a gate, only a violation ever reports FAIL.
    for o in ALL {
        assert_eq!(
            o.blocks(ClauseRole::Gate),
            o == Outcome::Violated,
            "{o:?} as a gate reported FAIL when only Violated should"
        );
    }

    // The property that actually matters, and which `blocks` does not express.
    assert!(!Outcome::Satisfied.closes_gate(), "a satisfied gate must open");
    for o in [
        Outcome::Violated,
        Outcome::NotApplicable,
        Outcome::Unevaluatable,
    ] {
        assert!(o.closes_gate(), "{o:?} must close a gate");
    }

    // The silent-drop set: closes the gate, reports nothing. Non-empty, which is the
    // whole finding — if this were ever empty, `blocks` would be a sufficient check.
    let silent: Vec<Outcome> = ALL
        .iter()
        .copied()
        .filter(|o| o.closes_gate() && !o.blocks(ClauseRole::Gate))
        .collect();
    assert_eq!(
        silent,
        vec![Outcome::NotApplicable, Outcome::Unevaluatable],
        "the set of outcomes that drop a guarded body without reporting a failure changed"
    );
}

/// Gate closure at the FOLD level.
///
/// This is the assertion the deleted test was reaching for. A rewired gate condition is a
/// fold over clause outcomes, and the question is whether the fold can close the gate,
/// not whether it can fail.
///
/// The load-bearing case is the empty fold: `identity()` is `NotApplicable`, which closes
/// the gate. A gate with nothing to evaluate therefore drops its body — which is precisely
/// the mechanism behind the reverted empty-collection fix. Asserting it here means the
/// behaviour is documented as a known consequence rather than rediscovered by a
/// differential test.
///
/// What this still does not catch: the reverted fix acted in a *clause*, upstream of any
/// fold, so no fold-level test would have caught it. Gate correctness needs `eval_rule`
/// itself to distinguish "condition false" from "condition unevaluatable".
#[test]
fn a_gate_opens_only_when_the_fold_is_actually_satisfied() {
    assert!(
        Outcome::all([]).closes_gate(),
        "an empty and-fold must close a gate: nothing was established"
    );
    assert!(
        Outcome::any([]).closes_gate(),
        "an empty or-fold must close a gate: nothing was satisfied"
    );

    for a in ALL {
        for b in ALL {
            for c in ALL {
                for seq in [vec![a], vec![a, b], vec![a, b, c]] {
                    let and_opens = !Outcome::all(seq.iter().copied()).closes_gate();
                    // An and-fold opens the gate only if every element is satisfied, or
                    // if the satisfied elements are padded solely by the identity.
                    let and_expected = seq.iter().any(|o| *o == Outcome::Satisfied)
                        && seq
                            .iter()
                            .all(|o| matches!(o, Outcome::Satisfied | Outcome::NotApplicable));
                    assert_eq!(
                        and_opens, and_expected,
                        "an and-fold of {seq:?} opened a gate it should not have"
                    );

                    let or_opens = !Outcome::any(seq.iter().copied()).closes_gate();
                    // An or-fold opens the gate exactly when something is satisfied.
                    // Nothing else may stand in — that is the absorption property.
                    assert_eq!(
                        or_opens,
                        seq.iter().any(|o| *o == Outcome::Satisfied),
                        "an or-fold of {seq:?} disagreed with its satisfied elements"
                    );
                }
            }
        }
    }
}

/// The one wholly uncovered interaction dimension: folding and then converting to a
/// status, over every sequence up to length three and both roles.
#[test]
fn folding_then_converting_is_covered_for_every_sequence_and_role() {
    for role in ROLES {
        // Length 0.
        assert_eq!(Outcome::all([]).to_status(role), Status::SKIP);
        assert_eq!(Outcome::any([]).to_status(role), Status::SKIP);

        for a in ALL {
            for b in ALL {
                for c in ALL {
                    for seq in [vec![a], vec![a, b], vec![a, b, c]] {
                        // The composed result must equal converting the folded outcome,
                        // and must never claim PASS unless something was satisfied.
                        let folded_all = Outcome::all(seq.iter().copied());
                        let folded_any = Outcome::any(seq.iter().copied());

                        // A PASS from either fold requires at least one genuinely
                        // satisfied element, and no element that is not either
                        // satisfied or the identity. `NotApplicable` is the identity of
                        // both operations, so `[Satisfied, NotApplicable]` folding to
                        // Satisfied is correct -- "every element satisfied" would be
                        // too strong an assertion.
                        if folded_all.to_status(role) == Status::PASS {
                            assert!(
                                seq.contains(&Outcome::Satisfied)
                                    && seq.iter().all(|o| matches!(
                                        o,
                                        Outcome::Satisfied | Outcome::NotApplicable
                                    )),
                                "and-fold of {seq:?} reported PASS as {role:?} with an element that was neither satisfied nor inapplicable"
                            );
                        }
                        if folded_any.to_status(role) == Status::PASS {
                            assert!(
                                seq.contains(&Outcome::Satisfied),
                                "or-fold of {seq:?} reported PASS as {role:?} with nothing satisfied"
                            );
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The gate-safety invariant, stated over the whole domain.
// ---------------------------------------------------------------------------

/// The property that ties the algebra back to the tool's purpose: no combination of
/// outcomes may turn a violation into a non-blocking result under conjunction.
///
/// Enumerated over all 16 pairs and both roles.
#[test]
fn conjunction_never_launders_a_violation() {
    for a in ALL {
        for b in ALL {
            for role in ROLES {
                if a == Outcome::Violated || b == Outcome::Violated {
                    assert!(
                        a.and(b).blocks(role),
                        "and({a:?}, {b:?}) stopped blocking as {role:?}"
                    );
                }
            }
        }
    }
}

/// Under disjunction a violation *may* be excused, but only by an actually-satisfied
/// branch — never by one that did not run.
#[test]
fn disjunction_only_excuses_a_violation_with_real_evidence() {
    for a in ALL {
        for b in ALL {
            if (a == Outcome::Violated || b == Outcome::Violated)
                && a.or(b) == Outcome::Satisfied
            {
                assert!(
                    a == Outcome::Satisfied || b == Outcome::Satisfied,
                    "or({a:?}, {b:?}) excused a violation without a satisfied branch"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Equivalence with the imperative folds that were deliberately NOT converted.
//
// `eval_conjunction_clauses` is a hand-rolled counter whose PASS arm does
// `continue 'conjunction`. That short-circuit is load-bearing for the *recorded event
// tree*, not just the verdict: it suppresses records for the remaining disjuncts, and
// the golden-file integration tests assert on that tree. Expressing it as
// `Outcome::any` would evaluate every disjunct and change the recorded output.
//
// So it stays imperative, and these tests pin the equivalence instead. If someone
// later changes either the fold or the lattice so they disagree, this fails rather
// than silently drifting.
// ---------------------------------------------------------------------------

/// Reimplements the disjunction level of `eval_conjunction_clauses` exactly as written
/// (eval.rs: PASS short-circuits, SKIP ignored, FAIL counted) and asserts it agrees
/// with `Outcome::any` for every sequence of up to three statuses.
#[test]
fn imperative_disjunction_agrees_with_or_fold() {
    /// Faithful transcription of the inner loop's accounting.
    fn imperative(disjuncts: &[Status]) -> Status {
        let mut num_of_disjunction_fails = 0;
        for status in disjuncts {
            match status {
                // `continue 'conjunction` -- the whole conjunct is satisfied.
                Status::PASS => return Status::PASS,
                Status::SKIP => {}
                Status::FAIL => num_of_disjunction_fails += 1,
            }
        }
        if num_of_disjunction_fails > 0 {
            Status::FAIL
        } else {
            Status::SKIP
        }
    }

    const STATUSES: [Status; 3] = [Status::PASS, Status::FAIL, Status::SKIP];

    // Length 0.
    assert_eq!(imperative(&[]), Status::SKIP);
    assert_eq!(
        Outcome::any([]).to_status(ClauseRole::Assertion),
        Status::SKIP
    );

    // Lengths 1 through 3, exhaustively: 3 + 9 + 27 = 39 sequences.
    for a in STATUSES {
        let seq = [a];
        assert_eq!(
            imperative(&seq),
            Outcome::any(seq.iter().copied().map(Outcome::from_status))
                .to_status(ClauseRole::Assertion),
            "disagreement on {seq:?}"
        );

        for b in STATUSES {
            let seq = [a, b];
            assert_eq!(
                imperative(&seq),
                Outcome::any(seq.iter().copied().map(Outcome::from_status))
                    .to_status(ClauseRole::Assertion),
                "disagreement on {seq:?}"
            );

            for c in STATUSES {
                let seq = [a, b, c];
                assert_eq!(
                    imperative(&seq),
                    Outcome::any(seq.iter().copied().map(Outcome::from_status))
                        .to_status(ClauseRole::Assertion),
                    "disagreement on {seq:?}"
                );
            }
        }
    }
}

/// Same for the conjunction level: FAIL wins, else PASS if anything passed, else SKIP.
#[test]
fn imperative_conjunction_agrees_with_and_fold() {
    fn imperative(conjuncts: &[Status]) -> Status {
        let mut num_passes = 0;
        let mut num_fails = 0;
        for status in conjuncts {
            match status {
                Status::PASS => num_passes += 1,
                Status::FAIL => num_fails += 1,
                Status::SKIP => {}
            }
        }
        if num_fails > 0 {
            Status::FAIL
        } else if num_passes > 0 {
            Status::PASS
        } else {
            Status::SKIP
        }
    }

    const STATUSES: [Status; 3] = [Status::PASS, Status::FAIL, Status::SKIP];

    assert_eq!(imperative(&[]), Status::SKIP);
    assert_eq!(
        Outcome::all([]).to_status(ClauseRole::Assertion),
        Status::SKIP
    );

    // Lengths 1 through 3, for symmetry with the disjunction test above. An earlier
    // version enumerated only lengths 0 and 3, leaving twelve sequences unchecked with
    // no stated reason.
    for a in STATUSES {
        let seq = [a];
        assert_eq!(
            imperative(&seq),
            Outcome::all(seq.iter().copied().map(Outcome::from_status))
                .to_status(ClauseRole::Assertion),
            "disagreement on {seq:?}"
        );

        for b in STATUSES {
            let seq = [a, b];
            assert_eq!(
                imperative(&seq),
                Outcome::all(seq.iter().copied().map(Outcome::from_status))
                    .to_status(ClauseRole::Assertion),
                "disagreement on {seq:?}"
            );

            for c in STATUSES {
                let seq = [a, b, c];
                assert_eq!(
                    imperative(&seq),
                    Outcome::all(seq.iter().copied().map(Outcome::from_status))
                        .to_status(ClauseRole::Assertion),
                    "disagreement on {seq:?}"
                );
            }
        }
    }
}

/// The `match_all` per-value fold, which WAS converted. Its old form concluded PASS for
/// an empty result set; the lattice concludes NotApplicable. This test pins the
/// divergence deliberately, so the fix cannot be silently reverted.
#[test]
fn converted_match_all_fold_differs_from_the_old_one_only_when_empty() {
    /// The pre-conversion implementation, transcribed.
    fn old(results: &[Status], all: bool) -> Status {
        let mut fails = 0;
        let mut pass = 0;
        for status in results {
            match status {
                Status::PASS => pass += 1,
                Status::FAIL => fails += 1,
                Status::SKIP => {}
            }
        }
        if all {
            if fails > 0 {
                Status::FAIL
            } else {
                Status::PASS
            }
        } else if pass > 0 {
            Status::PASS
        } else {
            Status::FAIL
        }
    }

    const STATUSES: [Status; 3] = [Status::PASS, Status::FAIL, Status::SKIP];

    // Empty: this is the whole point. Old said PASS under `all`; the lattice says SKIP.
    assert_eq!(old(&[], true), Status::PASS);
    assert_eq!(
        Outcome::all([]).to_status(ClauseRole::Assertion),
        Status::SKIP,
        "an empty match_all must not be affirmative evidence"
    );

    // Non-empty and SKIP-free, the shapes actually produced on this path: the two agree,
    // so the conversion did not disturb ordinary evaluation.
    for a in [Status::PASS, Status::FAIL] {
        for b in [Status::PASS, Status::FAIL] {
            let seq = [a, b];
            let lifted = seq.iter().copied().map(Outcome::from_status);
            assert_eq!(
                old(&seq, true),
                Outcome::all(lifted).to_status(ClauseRole::Assertion),
                "match_all disagreement on {seq:?}"
            );
        }
    }

    // With SKIP present the two can differ, because `old` ignored SKIP while the lattice
    // treats it as the identity. Assert the direction of the difference is always
    // safe -- never old=FAIL becoming lattice=PASS.
    for a in STATUSES {
        for b in STATUSES {
            let seq = [a, b];
            let lifted = seq.iter().copied().map(Outcome::from_status);
            let new = Outcome::all(lifted).to_status(ClauseRole::Assertion);
            if old(&seq, true) == Status::FAIL {
                assert_ne!(
                    new,
                    Status::PASS,
                    "conversion turned a failure into a pass on {seq:?}"
                );
            }
        }
    }
}
