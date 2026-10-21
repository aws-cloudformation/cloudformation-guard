//! Reproducers for parser defects found by a line-by-line read of the parser, and the pins for the ones fixed.
//!
//! Why this file exists: a lot of parser work landed after the last pass over `parser.rs`, and these
//! are what a fresh pass over it and the walks in
//! `exprs.rs` that it feeds turned up. Each entry asserts the *correct* behavior, so an entry whose
//! defect is still open carries `#[ignore]` and an entry whose defect is fixed does not.
//!
//! Every row is FIXED, so nothing here carries `#[ignore]` and
//!
//! ```text
//! cargo test --lib parser_regression_repros -- --ignored --test-threads=1
//! ```
//!
//! selects nothing. An open row's test is red rather than merely skipped, and running that command
//! prints the measured wrong answer -- an `#[ignore]` nobody runs is invisible, which is why the command
//! is written down rather than left implicit. The command is kept because it is what the next open row
//! will need: assert the correct behavior, add `#[ignore]`, and drop the attribute when the defect
//! closes so the test becomes the regression guard.
//!
//! Which finding owns which test, so that neither an `#[ignore]` nor its absence has to be guessed at.
//! "main" in the origin column means the upstream parser has the defect as well, "branch" that it does
//! not, and "both" that it has a narrower form of it. Rows are in file order.
//!
//! | test                                                            | finding                                  | origin | state   |
//! |-----------------------------------------------------------------|------------------------------------------|--------|---------|
//! | `a_named_index_on_a_variable_rooted_query_resolves`             | 1, variable-rooted named index           | both   | FIXED   |
//! | `a_parameterized_call_inside_a_filter_is_checked_at_parse_time` | 2, no walk descends into a filter        | branch | FIXED   |
//! | `a_plain_reference_to_a_parameterized_rule_is_rejected`         | 3, `RuleReference::Plain` unchecked      | branch | FIXED   |
//! | `a_file_level_let_filter_is_checked_at_parse_time`              | 2, its file-level position               | branch | FIXED   |
//! | `a_cycle_closing_through_a_filter_is_refused`                   | 2, its cycle half                        | branch | FIXED   |
//! | `a_function_call_error_reaches_the_author`                      | 5, function diagnostics discarded        | main   | FIXED   |
//! | `a_dangling_or_is_a_syntax_error`                               | 6, trailing `or` reads as a rule name    | main   | FIXED   |
//! | `rendering_a_block_clause_does_not_panic`                       | 7, `Display for BlockGuardClause` panics | main   | FIXED   |
//! | `rendering_every_clause_variant_does_not_panic`                 | 8, `Display for GuardClause` unimplemented | main   | FIXED   |
//! | `no_query_spelling_produces_a_named_all_values`                 | 4, the dead `map_key_lookup` branch      | branch | FIXED   |
//!
//! Finding 8 sits on the path finding 7 opens: rendering a block of plain clauses reaches
//! `Display for GuardClause` for every clause in the body, so a body holding a `when` block or a
//! parameterized call takes the same arm as the bare forms of those two variants. Every variant of
//! `GuardClause` renders; an `_ => unimplemented!()` arm there would panic on either shape,
//! which is what `rendering_every_clause_variant_does_not_panic` pins.
//!
//! Finding 4 is last because it is the one entry that pins a dead branch rather than a wrong answer.
//! Finding 1 is "both" because the upstream parser mishandles `%r[name]` too, and only the spaced
//! spelling `%r[ name ]` is particular to this tree; its doc comment has the measurement.
//!
//! Two changes closed the first six FIXED rows, and each was measured on its own before they were
//! brought together. Findings 1 and 4 are two faces of one shadowing in `predicate_or_index` -- the
//! branch that made 4 dead is the branch whose part shape broke 1 -- so one change closes both.
//! Findings 2 and 3 are two halves of one omission in the rule-reference walks, and the fourth and fifth
//! rows are positions that same change reached which the original pass had not written down: a
//! file-level `let`, and the cycle half, whose consequence turned out to be a stack overflow at exit 134
//! rather than the exit 0 that pass recorded.
//!
//! Findings 7, 5 and 6 closed the last three rows, in that order and one commit each, and each
//! commit's separability was shown rather than asserted: the reproducers of the findings not yet
//! addressed were re-run at every intermediate commit and were still red. They are separable because
//! they share no code. Finding 7 is arithmetic in `exprs.rs` with no parser production in it. Finding 5
//! changes two error constructors in `function_expr`. Finding 6 adds a refusal to `rule_clause`. No two
//! of the three touch the same function.
//!
//! Findings 5 and 6 are one class seen twice -- a parser diagnostic that never reaches the author -- and
//! the class is wider than these two rows. Three further sites in `parser.rs` build a message and return
//! it as `nom::Err::Error`, and all three were left because backtracking past them is load-bearing:
//! `reject_trailing_identifier`, without which no property whose name begins with a keyword parses
//! (`whenCreated EXISTS`, `Name == falseFlag`); `parse_float`'s float-shape test, without which no bare
//! integer parses; and `value_cmp`'s "Custom message tag detected" sentinel, without which a custom
//! message on a rule reference stops parsing. Each is a message that cannot reach an author, which is a
//! dead diagnostic rather than a lost one, and converting any of them would trade a bad message for a
//! refused file.

use super::*;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::root_scope;
use crate::rules::path_value::PathAwareValue;
use std::rc::Rc;

fn parse_file(text: &str) -> Result<Option<RulesFile>, Error> {
    rules_file(from_str2(text))
}

/// A rules file evaluated against a template, reduced to the one word a caller acts on.
fn verdict(rules_text: &str, template: &str) -> String {
    let rules = match RulesFile::try_from(rules_text) {
        Ok(rules) => rules,
        Err(e) => return format!("PARSE-ERR: {}", e),
    };
    let yaml: serde_yaml::Value = serde_yaml::from_str(template).expect("template parses");
    let value = PathAwareValue::try_from(yaml).expect("template converts");
    let mut root = root_scope(&rules, Rc::new(value));
    match eval_rules_file(&rules, &mut root, None) {
        Ok(status) => format!("{:?}", status),
        Err(e) => format!("EVAL-ERR: {}", e),
    }
}

const TWO_RESOURCES: &str = r#"
Resources:
  bucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: ok
  queueB:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: q
"#;

const ONE_BUCKET: &str = r#"
Resources:
  bucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: ok
"#;

/// A named index on a query rooted at a variable has to keep resolving.
///
/// `all_indices`' named branch carries a `preceded(zero_or_more_ws_or_comment, ..)` so that `[x]` and
/// `[ x ]` agree, which is what makes the interpolated-key position -- `Tags.%k[ x ]` -- work and what
/// exposes the position-0 position: `[ x ]` comes back `AllIndices(Some(_))`, as `[x]` does, rather
/// than reaching `map_key_lookup` and coming back `AllValues(Some(_))`, and an `access_query` that
/// suppresses the `AllIndices(None)` a variable-rooted query needs whenever `parts.get(1)` matches
/// `AllIndices(_)` therefore inserts nothing. The variable arm in
/// `eval_context::query_retrieval_with_converter` then *skips* the part after the variable, so the
/// capture never happens and the rest of the query is applied to the variable's own value instead of
/// to its members.
///
/// Measured with one line differing and nothing else -- the same tree, the same fixture, the
/// `preceded` added or removed:
///
/// ```text
/// %r[ name ].Type in ["AWS::S3::Bucket", "AWS::SQS::Queue"]
///     without the whitespace tolerance   exit 0   PASS
///     with it                            exit 19  "retrieval error ... Could not find key Type
///                                                  inside struct at path /Resources"
/// ```
///
/// and in a `when` gate the direction reverses into silence, which is the reason this is first:
///
/// ```text
/// rule gate when %r[ name ].Type == "AWS::S3::Bucket" { ...BucketName == "required" }
///     without the preceded   exit 19, the violation reported with a full ComparisonError
///     with it                exit 0, no output on any channel
/// ```
///
/// `Resources[ name ].Type` -- the same syntax with no variable at the root -- still works, so the
/// break is specific to a variable-rooted query. No `.guard` file in this repository writes
/// `%var[ name ]`, which is why the suite stayed green:
/// `whitespace_inside_a_named_index_does_not_change_the_query_part` asserts only that the five
/// spellings agree with each other, not which query part they agree on and not that any of them
/// evaluates.
///
/// FIXED, and this is now the regression guard. Two corrections to the account above:
///
/// The break is not confined to the spaced spelling. `%r[name].Type` -- no spaces, which takes
/// `all_indices`' named branch with or without the whitespace tolerance -- is exit 19 either way. So
/// the tolerance widens the hole from one spelling to both rather than opening it, and the
/// with-and-without table above is a true statement about `[ name ]` and not about the position. Both
/// spellings are asserted here.
///
/// The guard sits in `access_query`, not in `all_indices`. The named index lands in slot 1 of the
/// query, the slot the root-variable arm of `query_retrieval_with_converter` consumes, whenever the
/// insert that reserves that slot is suppressed for any `AllIndices(_)` rather than for the bare `[*]`
/// that is the only harmless occupant. See the comment there for why keeping the parser tolerant and
/// narrowing the suppression beats making the two parser branches distinguishable again.
#[test]
fn a_named_index_on_a_variable_rooted_query_resolves() {
    // All four spellings, because agreement between them is what the parser test asserts and it is
    // satisfied by all four being equally unevaluatable.
    for index in ["[name]", "[ name]", "[name ]", "[ name ]"] {
        let query = format!(
            "let r = Resources\nrule main {{\n    %r{}.Type in [\"AWS::S3::Bucket\", \"AWS::SQS::Queue\"]\n}}\n",
            index
        );
        assert_eq!(
            verdict(&query, TWO_RESOURCES),
            "PASS",
            "every resource's Type is in the list, so %r{}.Type must pass",
            index
        );

        // The silent direction: a gate whose query cannot resolve never fires.
        let gate = format!(
            "let r = Resources\nrule gate when %r{}.Type == \"AWS::S3::Bucket\" {{\n    Resources.bucketA.Properties.BucketName == \"required\"\n}}\n",
            index
        );
        assert_eq!(
            verdict(&gate, ONE_BUCKET),
            "FAIL",
            "the gate matches the one bucket, so the body must run and report the violation: %r{}",
            index
        );
    }

    // Control: the same syntax without a variable at the root is unaffected and must stay so.
    let no_variable = "rule main {\n    Resources[ name ].Type in [\"AWS::S3::Bucket\", \"AWS::SQS::Queue\"]\n}\n";
    assert_eq!(verdict(no_variable, TWO_RESOURCES), "PASS");

    // Control the other way: the interpolated-key position, which is what the whitespace tolerance in
    // `all_indices` was added for. Both spellings must resolve, or the fix bought the root position back
    // by giving this one up.
    const TAGS: &str = "\nCfg:\n  KeyList:\n    - Env\n  Tags:\n    Env: prod\n";
    for index in ["[x]", "[ x ]"] {
        let interpolated = format!(
            "let k = Cfg.KeyList[*]\nrule main {{\n    Cfg.Tags.%k{} == \"prod\"\n}}\n",
            index
        );
        assert_eq!(
            verdict(&interpolated, TAGS),
            "PASS",
            "an interpolated key indexed as %k{} must resolve",
            index
        );
    }
}

/// A parameterized rule call inside a query filter is a call site like any other.
///
/// FIXED. `RuleRefs for GuardClause` answered `Clause(_) => {}` and walked only a `BlockClause`'s
/// *body*, and `WhenGuardClause::Clause(_) => {}` did the same, so no walk descended into a
/// `QueryPart::Filter`'s conjunctions -- where `predicate_filter_clauses` parses a full `clause`, and
/// `clause` includes `parameterized_rule_call_clause`. `rule_refs_in` also never walked
/// `rule.block.assignments`, so a call in a `let` right-hand side's filter was missed twice over.
///
/// The tell that this was an omission rather than a decision is that the two sibling walks over the
/// same tree both do descend into a filter: `collect_query_capture_names` and
/// `collect_query_variable_refs` each have a `QueryPart::Filter` arm. This walk has one too, and reads
/// a block's assignments beside its conjunctions, so all three agree on the tree.
///
/// Without the `Filter` arm, the same arity mistake, outside a filter and in each of the four places a
/// filter can sit, against a one-bucket template:
///
/// ```text
/// rule main { check(1) }                              exit 5, "Rule check is declared with 2
///                                                             parameters, and a call passes it 1"
/// rule main { Resources.*[ check(1) ] exists }        exit 19
/// rule main { Resources.*[ check(1) ] { .. } }        exit 255   <- INTERNAL_FAILURE
/// rule main when Resources.*[ check(1) ] exists { }   exit 19
/// rule main { let s = Resources.*[ check(1) ] .. }    exit 19
/// ```
///
/// All four of the reachable ones reported through `Error::IncompatibleError`, whose own text reads
/// "The rules file was accepted with a call this malformed, which is a defect in cfn-guard rather
/// than in the file" -- the code already declared this state impossible, and 255 is the exit code
/// `first_call_site_mismatch`'s doc comment says it was written to eliminate. All five are exit 5 with
/// the arity message now, which is the point: the diagnostic must not depend on where the mistake sits.
///
/// One filter level was not the worst of it. Nesting the same call deeper, one level added at a time and
/// nothing else changed -- `Resources[ <inner> ] exists` wrapped around `check(1)`:
///
/// ```text
/// filter levels    before            after
/// 0                exit 5, arity     exit 5, arity
/// 1                exit 19           exit 5, arity
/// 2                exit 0, SILENT    exit 5, arity
/// 3                exit 0, SILENT    exit 5, arity
/// ```
///
/// At two levels the file exited 0 with nothing on either channel, because the outer filter's clause is
/// the one that errors, an erroring predicate selects nothing, and `exists` over an empty selection is a
/// pass. So the same authoring mistake was loud, then confusing, then invisible, decided by how deeply it
/// happened to be nested. The two-level spelling is asserted below for that reason.
///
/// A fifth position, not in that table and not in the assertions below because it belongs to no rule: a
/// *file-level* `let sel = Resources.*[ check(1) ]` was missed as well, since `first_call_site_mismatch`
/// iterated the two rule lists only. It measured exit 19 through the same `IncompatibleError` and is
/// exit 5 now; `a_file_level_let_filter_is_checked_at_parse_time` covers it.
///
/// The cycle half of the same gap has a worse consequence than the round-21 pass recorded, and
/// `a_cycle_closing_through_a_filter_is_refused` carries it. That pass tried three parameterized
/// spellings, found all three terminating at exit 0 -- a filter predicate is evaluated in the Gate role,
/// and a clause that errors there selects nothing -- and wrote the exposure up as real in the check and
/// unproven in its consequence. It did not try the *plain* reference, which a filter reaches through a
/// nested `when`'s conditions rather than through `clause` directly:
///
/// ```text
/// rule a { Resources.*[ when a { Type exists } ] exists }   exit 134, stack overflow
/// ```
///
/// with nothing on stdout and "thread 'main' has overflowed its stack" on stderr -- the exact abort
/// `first_rule_reference_cycle` exists to prevent, still reachable because no walk entered the filter.
/// Both checks read `rule_refs_in`, so one fix closes both halves.
///
/// The assertions read the message, not merely the rejection. An `is_err()` is satisfied by any refusal
/// at all: with the arity branch of `rules_file` returning `ParseError("unexpected token")`, such a test
/// passes while the sibling for the file-level `let` fails, and the regression the paragraph above
/// calls "the point" goes through unnoticed. Each position has to carry the text
/// `call_site_mismatch_message` produces for two parameters and one argument, and anything else -- `Ok`,
/// another error kind, another message -- panics with the source so the failure names the position.
#[test]
fn a_parameterized_call_inside_a_filter_is_checked_at_parse_time() {
    let definition = "rule check(a, b) {\n    Resources exists\n}\n";
    let expected = "Rule check is declared with 2 parameters, and a call passes it 1 argument";

    let arity_message_of = |src: &str, label: &str| -> String {
        match parse_file(src) {
            Err(Error::ParseError(message)) => message,
            Err(other) => panic!(
                "{}: expected a ParseError, got {:?} for\n{}",
                label, other, src
            ),
            Ok(_) => panic!(
                "{}: expected a rejection, but the file parsed:\n{}",
                label, src
            ),
        }
    };

    // Control: outside a filter this is already rejected with the arity message, and must stay so.
    let control = format!("{definition}rule main {{\n    check(1)\n}}\n");
    let message = arity_message_of(&control, "the control outside a filter");
    assert!(
        message.contains(expected),
        "the control must keep its arity message, or this test proves nothing; got {:?}",
        message
    );

    for (label, body) in [
        ("clause query", "    Resources.*[ check(1) ] exists\n"),
        (
            "block clause query",
            "    Resources.*[ check(1) ] {\n        Type exists\n    }\n",
        ),
        (
            "let right-hand side",
            "    let sel = Resources.*[ check(1) ]\n    %sel exists\n",
        ),
        // Two filter levels, the spelling that exited 0 with no output at all. A one-level assertion
        // alone would not have covered it: the mechanism that silences it is the *outer* filter treating
        // the inner error as an empty selection, so it only appears once there is an outer filter.
        (
            "two nested clause queries",
            "    Resources[ Resources[ check(1) ] exists ] exists\n",
        ),
    ] {
        let src = format!("{definition}rule main {{\n{body}}}\n");
        let message = arity_message_of(&src, label);
        assert!(
            message.contains(expected),
            "arity mismatch in a {} must be reported with the arity message, got {:?}",
            label,
            message
        );
    }

    let when_condition = format!(
        "{definition}rule main when Resources.*[ check(1) ] exists {{\n    Resources exists\n}}\n"
    );
    let message = arity_message_of(&when_condition, "when condition");
    assert!(
        message.contains(expected),
        "arity mismatch in a when condition's filter must be reported with the arity message, got {:?}",
        message
    );
}

/// A rule declared with a parameter list cannot be referenced without one.
///
/// FIXED. `first_call_site_mismatch` reads every call site against its definition, and
/// `RuleReference::Plain(_) => continue` skipped exactly this direction. The mirror --
/// `check()` against `rule check { ... }` -- is what its `NotParameterized` arm was written for, and
/// that arm's doc comment gives the reason: the runtime message "contradicted itself".
///
/// This direction produced the same contradiction. Measured, on `rule check(t) { Resources exists }`
/// plus `rule main { check }`:
///
/// ```text
/// exit 5
///   stdout: Status = FAIL / FAILED rules / main FAIL
///           "Check was not compliant as dependent rule [check] did not PASS"
///   then:   "Rule check by that name does not exist, Rule Names = [\"main\"]"
/// ```
///
/// So one report said `check` ran and did not pass, and said `check` does not exist, about a rule
/// declared two lines above -- and the rule-name list it printed omitted it, because the lookup consults
/// `guard_rules` only. Every fact needed to say "write `check(...)`" is in the parse tree.
///
/// The exit code does not move: 5 before, 5 after. What moves is the report, from those two statements
/// to one that names the edit -- "Rule check is declared with 1 parameter, so it cannot be referenced as
/// a bare check. Write check(...) passing 1 argument." A `CallSiteMismatch` variant of its own rather
/// than a reuse of `NotParameterized`, because that arm's advice is "write check on its own", which is
/// the input.
#[test]
fn a_plain_reference_to_a_parameterized_rule_is_rejected() {
    let plain_to_parameterized =
        "rule check(t) {\n    Resources exists\n}\nrule main {\n    check\n}\n";
    let message = parse_file(plain_to_parameterized)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        message.contains("cannot be referenced as a bare check")
            && message.contains("Write check(...)"),
        "the refusal has to name the edit rather than merely refuse, got: {}",
        message
    );

    // Control: the mirror is already rejected, and the message names the *opposite* fix. Asserted here
    // because a single `CallSiteMismatch` variant serving both directions would satisfy the assertion
    // above while telling the author of one of them to write back what they already wrote.
    let parameterized_to_plain =
        "rule check {\n    Resources exists\n}\nrule main {\n    check()\n}\n";
    let mirror = parse_file(parameterized_to_plain)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        mirror.contains("cannot be called as check(...)"),
        "the mirror control must keep its message, got: {}",
        mirror
    );

    // Control: a plain reference to a rule that really is plain still parses, so the new arm keys on the
    // definition's parameter list rather than on the reference being plain.
    let plain_to_plain = "rule check {\n    Resources exists\n}\nrule main {\n    check\n}\n";
    assert!(
        parse_file(plain_to_plain).is_ok(),
        "an ordinary plain reference must keep parsing: {:?}",
        parse_file(plain_to_plain).err()
    );
}

/// A file-level `let` whose filter holds a call is a call site too.
///
/// The position that belongs to no rule, and so the one a `first_call_site_mismatch` that iterated only
/// `guard_rules` and `parameterized_rules` would miss even with `rule_refs_in` walking a rule's own
/// assignments: a file-level assignment is in neither list.
///
/// Not in the four-position table on `a_parameterized_call_inside_a_filter_is_checked_at_parse_time`
/// because that table enumerates the places a *filter* can sit inside a rule. Left unchecked, this
/// position is exit 19 through the same `Error::IncompatibleError`, reported under "Could not be
/// evaluated" against whichever clause reads `%sel`; checked, it is exit 5 with the arity message.
#[test]
fn a_file_level_let_filter_is_checked_at_parse_time() {
    let src = "let sel = Resources.*[ check(1) ]\nrule check(a, b) {\n    Resources exists\n}\n\
               rule main {\n    %sel exists\n}\n";
    let message = parse_file(src)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        message.contains("check")
            && message.contains("2 parameters")
            && message.contains("1 argument"),
        "a file-level let's filter must be read against the definition it names, got: {}",
        message
    );

    // Control: the same file with the count corrected has to keep parsing. Without it the assertion
    // above would also hold for a fix that rejected every filter containing a call.
    let correct =
        "let sel = Resources.*[ check(1, 2) ]\nrule check(a, b) {\n    Resources exists\n}\n\
                   rule main {\n    %sel exists\n}\n";
    assert!(
        parse_file(correct).is_ok(),
        "the corrected file must still parse: {:?}",
        parse_file(correct).err()
    );
}

/// A cycle that closes through a query filter is refused.
///
/// The other half of the walk gap, and the half whose consequence the round-21 pass under-measured. It
/// tried three parameterized spellings, saw all three terminate at exit 0, and recorded the exposure as
/// unproven. The plain reference is the one that bites, because a filter reaches it through a nested
/// `when`'s conditions rather than through `clause` directly:
///
/// ```text
/// rule a { Resources.*[ when a { Type exists } ] exists }   exit 134, stack overflow, stdout empty
/// ```
///
/// 134 is outside the documented exit codes -- 0, 5, 19 -- so a caller checking for them got neither a
/// pass nor a failure it could act on, and the abort happened before any finding was written.
///
/// All four spellings are refused. Two of them would otherwise exit 0: a self-reference behind a filter
/// can run vacuously, because a filter predicate is evaluated in the Gate role and a clause that errors
/// there selects nothing. Rejected anyway, on the
/// ground `first_rule_reference_cycle`'s own doc comment gives for the `when`-guarded case it already
/// refuses -- nothing in a rules file can make a recursion terminate, so whether one does is decided by
/// the document rather than by the file.
#[test]
fn a_cycle_closing_through_a_filter_is_refused() {
    for (label, src) in [
        (
            "a self-reference through a filter",
            "rule a(n) {\n    Resources.*[ a(%n) ] exists\n}\nrule main {\n    a(1)\n}\n",
        ),
        (
            "a ring through two filters",
            "rule a(n) {\n    Resources.*[ b(%n) ] exists\n}\nrule b(n) {\n    \
             Resources.*[ a(%n) ] exists\n}\nrule main {\n    a(1)\n}\n",
        ),
        (
            "a plain reference through a filter's nested when",
            "rule a {\n    Resources.*[ when a { Type exists } ] exists\n}\n",
        ),
        (
            "a self-reference through a let's filter",
            "rule a(n) {\n    let sel = Resources.*[ a(%n) ]\n    %sel exists\n}\n\
             rule main {\n    a(1)\n}\n",
        ),
    ] {
        let message = parse_file(src)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            message.contains("references itself") || message.contains("reference each other"),
            "{} should be refused as a cycle, got: {:?}",
            label,
            message
        );
    }

    // Control: a reference through a filter that closes no ring must keep parsing, or the four
    // assertions above would hold for a fix that called every filter reference a cycle.
    let acyclic = "rule a(n) {\n    Resources.*[ b(%n) ] exists\n}\nrule b(n) {\n    \
                   Resources exists\n}\nrule main {\n    a(1)\n}\n";
    assert!(
        parse_file(acyclic).is_ok(),
        "an acyclic reference through a filter must still parse: {:?}",
        parse_file(acyclic).err()
    );
}

/// A wrong function name or argument count has to reach the author.
///
/// A diagnostic that `function_expr` builds and returns as `nom::Err::Error` is indistinguishable from
/// "this is not a function call". Both `assignment` and `clause_tail_with_map` then read the same text
/// as a bare property access, leave the argument list unconsumed, and the only thing that eventually
/// complains is `all_consuming`, pointing at the parenthesis:
///
/// ```text
/// let x = json_parse(a, b)         exit 5, "at line 1 at column 19 ... fragment (a, b)"
/// let x = unknown_function(a)      exit 5, "at line 1 at column 25 ... fragment (a)"
/// X == json_parse(a, b)            exit 5, "at line 2 at column 58 ... fragment (a, b)"
/// ```
///
/// with "function: json_parse requires: 1 parameters to be passed, but received: 2" and "No function
/// with the name 'unknown_function' exists." formatted and discarded in all three.
///
/// Neither case is ambiguous. `name(` is a function call or nothing: no query production reads a `(`,
/// and a parameterized rule call is parsed by `parameterized_rule_call_clause` through `call_expr`
/// rather than through `function_expr`. So the precedent this file already set applies --
/// `parse_float`, `parse_regex_inner` and `parse_range` were each changed from `Error` to `Failure`
/// for exactly this reason, each with a comment saying the message never reached the author.
///
/// FIXED, and this is now the regression guard. Two additions to the account above, both measured
/// while making the change.
///
/// The precedent is a fourth site as well as those three, and its argument is the one that applies
/// here verbatim: `parameter_names` is `Failure` "because `(` and a name list have already been
/// consumed here". Both refusals in `function_expr` sit after `call_expr` has consumed the name, the
/// `(`, the arguments and the `)`, so the same sentence covers them.
///
/// The claim that no query production reads a `(` is now measured rather than asserted: the whole of
/// `parser.rs` contains exactly two readers of that character, `call_expr` and `parameter_names`, and
/// the second one reads a rule definition's parameter list. So the `access` fallback these errors were
/// reaching could never have been the right reading of `name(...)`.
///
/// What did *not* change is `call_expr`'s own failure on a missing `(`. That one stays recoverable,
/// because it is the signal that says "this is an ordinary property access, try `access`", and every
/// `alt` over `function_expr` depends on it. `parse_float` splits the same way, which is why its
/// float-shape test is still an `Error` while its out-of-range checks are not.
#[test]
fn a_function_call_error_reaches_the_author() {
    let arity = parse_file("let x = json_parse(a, b)\n")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        arity.contains("json_parse") && arity.contains("parameters"),
        "the arity error should name the function and the counts, got: {}",
        arity
    );

    // The position names the call, not the text after it. Column 9 is where `json_parse` starts;
    // spanning the input left over by `call_expr` reported column 25, the end of the line, which is
    // where this pointed when the message first became visible.
    assert!(
        arity.contains("at column 9"),
        "the arity error should point at the function name, got: {}",
        arity
    );

    let unknown = parse_file("let x = unknown_function(a)\n")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        unknown.contains("unknown_function"),
        "the unknown-function error should name the function, got: {}",
        unknown
    );

    // And it says "Parser Error when parsing" once. `FunctionName::try_from` hands back an
    // `Error::ParseError`, whose `Display` already adds that prefix, so carrying `e.to_string()` into a
    // context that is wrapped the same way again said it twice around one sentence. Nobody could see
    // that while the error was being thrown away.
    assert_eq!(
        unknown.matches("Parser Error when parsing").count(),
        1,
        "the diagnostic should carry its own wrapper once, got: {}",
        unknown
    );

    // `LetExpr::try_from` should not hand back a wrong tree either: today it returns
    // `Ok(AccessClause([Key("json_parse")]))` with the arguments dropped on the floor.
    assert!(
        LetExpr::try_from("let x = json_parse(a, b)").is_err(),
        "a malformed call must not produce an Ok LetExpr: {:?}",
        LetExpr::try_from("let x = json_parse(a, b)")
    );
}

/// A dangling `or` is a syntax error, not a reference to a rule called `or`.
///
/// `separated_list1` backtracks the separator when the element after it fails, which leaves the literal
/// `or` in front of `rule_clause`; `or` is a valid `var_name` and is followed by a newline, so without
/// the refusal in `rule_clause` the peek there accepts it as a bare rule name.
///
/// Measured on `rule r { Resources exists or }` over three lines: the file parses into two
/// conjunctions, the second a `NamedRule("or")`, and evaluation ends at exit 5 with the same
/// self-contradicting pair as the plain-reference case above -- "dependent rule [or] did not PASS"
/// and then "Rule or by that name does not exist" -- about a name the author never wrote.
///
/// FIXED, and this is now the regression guard. Three things the original pass had not written down,
/// each measured while making the change.
///
/// A `when` list has the same hole, through the same production. `rule main when a or { .. }` reported
/// the identical pair, `Rule or by that name does not exist, Rule Names = ["main", "a"]`, because
/// `single_clauses` alternates onto `rule_clause` exactly as a rule body does. Asserted below, since a
/// fix placed in the body's path alone would leave it.
///
/// The refusal is `rule_clause`'s own, not `CallSiteMismatch`'s. That check reads a call site against
/// the definition it names, and this input has neither half: no argument list to disagree about and no
/// definition of `or` to disagree with. Reusing `MissingArguments` would also mean building the wrong
/// tree and diagnosing it afterwards, where the parser holds the operator's span; and that variant's
/// own doc comment argues against a reuse whose message misdescribes the input.
///
/// What is deliberately left: `rule or { .. }` still parses. A file declaring `rule or` *and* referencing
/// it as a bare `or` is refused all the same, where a parser that let a matching definition rescue the
/// reference would accept it at exit 0; that capability is narrowed on purpose -- inside a disjunction the
/// name cannot be told apart from the operator. Refusing the definition too is a second behavior change
/// with no defect behind it, so both halves are pinned below and a later widening has to be chosen rather
/// than drifted into.
#[test]
fn a_dangling_or_is_a_syntax_error() {
    for src in [
        "rule r {\n    Resources exists or\n}\n",
        "rule r {\n    a or\n}\n",
        // Inline, where the `}` rather than a newline is what the peek accepts.
        "rule r {\n    Resources exists or }\n",
        // The `when` position, which reaches `rule_clause` through `single_clauses`.
        "rule a {\n    Resources exists\n}\nrule main when a or {\n    Resources exists\n}\n",
        // The uppercase spelling `or_term` also accepts.
        "rule r {\n    Resources exists OR\n}\n",
        // A definition of `or` does not rescue the reference, which is the capability being narrowed.
        "rule or {\n    Resources exists\n}\nrule r {\n    or\n}\n",
    ] {
        // The message is asserted for every spelling, not for the first alone. With `is_err()` for
        // the rest, a parser that refused the uppercase `OR` with the old `Rule OR by that name does
        // not exist` kept this test green while giving that author exactly the misdescription the
        // doc above says was removed; the same held for the `when` position and the inline `}`.
        // The message names the edit rather than only refusing, and it has to do so in each position.
        let message = parse_file(src)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            !message.is_empty(),
            "a dangling `or` should be a syntax error, but this parsed: {:?}",
            src
        );
        assert!(
            message.contains("disjunction operator") && message.contains("not a rule name"),
            "the refusal has to say what `or` is instead of naming a missing rule, for {:?} got: {}",
            src,
            message
        );
    }

    // Control: a well-formed disjunction is untouched, in a body and in a `when` list. Without these the
    // assertions above would hold for a fix that refused every `or`.
    for src in [
        "rule r {\n    Resources exists or Resources empty\n}\n",
        "rule a {\n    Resources exists\n}\nrule b {\n    Resources exists\n}\n\
         rule main when a or b {\n    Resources exists\n}\n",
    ] {
        assert!(
            parse_file(src).is_ok(),
            "a well-formed disjunction must keep parsing: {:?} gave {:?}",
            src,
            parse_file(src).err()
        );
    }

    // Control: a name that merely resembles the operator is a name. Neither spelling is one `or_term`
    // accepts, so no separator would ever have consumed them, and refusing them would take a rule name
    // away over a resemblance.
    for name in ["Or", "oR", "orange"] {
        let src = format!("rule {name} {{\n    Resources exists\n}}\nrule r {{\n    {name}\n}}\n");
        assert!(
            parse_file(&src).is_ok(),
            "`{}` is an ordinary rule name and must keep parsing: {:?}",
            name,
            parse_file(&src).err()
        );
    }

    // Control: the declaration side is deliberately untouched, and this is what says so.
    assert!(
        parse_file("rule or {\n    Resources exists\n}\n").is_ok(),
        "refusing the reference must not refuse the definition: {:?}",
        parse_file("rule or {\n    Resources exists\n}\n").err()
    );

    // Control: `or` as a *property* name is read by `clause`, which is tried before `rule_clause`, so
    // this path never reaches the refusal above.
    assert!(
        parse_file("rule r {\n    or exists\n}\n").is_ok(),
        "a property named `or` is a clause, not a rule reference: {:?}",
        parse_file("rule r {\n    or exists\n}\n").err()
    );
}

/// Rendering a block clause must not panic.
///
/// LATENT: nothing in the library or the binary renders a `GuardClause`. The panic was unconditional
/// rather than edge-case, which is what makes a tripwire worth having: `for idx in 0..len - 2`
/// underflows for the one-clause block that every ordinary `q { .. }` produces, and `each[len]` is one
/// past the end for *every* length, so no input rendered. With that arithmetic, `Properties { X == 1 }`
/// panics with "attempt to subtract with overflow" at the `0..len - 2` and
/// `Properties { X == 1 or Y == 2 }` panics on the index. `eval.rs` already
/// does `format!("{}", gac)` on the sibling `GuardAccessClause`, so the next reader who reaches for the
/// same thing one enum level up was getting a panic out of code that read as working.
///
/// FIXED, and this is now the regression guard. One correction to the account above, because a reader
/// would be right to re-run its measurement. The claim that deleting `Display for GuardClause` and
/// `Display for BlockGuardClause` and running `cargo check --workspace --all-targets` reports no error
/// at all does not hold for a tree that holds this test, because *this test* is a call site. Deleting
/// both impls makes `cargo check --workspace --all-targets` fail with exactly two `E0277`s, at the two
/// `format!` call sites inside `rendering_a_block_clause_does_not_panic` and nowhere else, reported
/// once for the `lib test` target and once for the `bin "cfn-guard" test` target. So the conclusion the
/// claim was making -- zero call sites outside the tests -- is intact and re-derivable, and the
/// deletion check is still the right instrument rather than grepping for `format!`, because it also
/// covers a generic instantiation such as `SliceDisplay<T: Display>`.
///
/// That measurement is also why the arithmetic was repaired instead of the impls being deleted.
/// Deleting them would have meant deleting this test as well, which is the only evidence the defect
/// existed, and `eval.rs`'s use of the sibling makes a future call site plausible rather than
/// hypothetical.
///
/// The assertions pin the disjunction separator, not merely the absence of a panic. Both plausible
/// off-by-one repairs survive a "does it panic" test: `0..len` with `each[len - 1]` renders the last
/// clause twice, which the one-clause case catches by requiring no ` or `, and `0..len - 1` with
/// `each[len - 2]` loses the last clause, which the two-clause case catches by requiring `Y`.
#[test]
fn rendering_a_block_clause_does_not_panic() {
    let one_clause = GuardClause::try_from("Properties { X == 1 }").expect("parses");
    let rendered = format!("{}", one_clause);
    assert!(
        rendered.contains("Properties") && rendered.contains('X'),
        "a one-clause block must render its query and its clause, got: {}",
        rendered
    );
    assert!(
        !rendered.contains(" or "),
        "a one-clause block has nothing to disjoin, so a repair that re-renders the last term shows \
         up here, got: {}",
        rendered
    );

    let two_clauses = GuardClause::try_from("Properties { X == 1 or Y == 2 }").expect("parses");
    let rendered = format!("{}", two_clauses);
    assert!(
        rendered.contains("Properties")
            && rendered.contains('X')
            && rendered.contains('Y')
            && rendered.contains(" or "),
        "a two-clause block must render both terms joined by `or`, got: {}",
        rendered
    );
}

/// `Display for GuardClause` panicked with "not implemented" for a `when` block and for a parameterized
/// rule call, bare or as the body of a `Properties { .. }` block.
///
/// The impl matched `Clause` and `BlockClause` and left `_ => unimplemented!()` for the other three
/// variants. Two of them are what the `clause` production builds for `when .. { .. }` and `name(..)`,
/// and a block body is parsed with `clause`, so `Display for BlockGuardClause` forwarded a body holding
/// either straight into the arm. The repair above made a block of plain clauses render, which is what
/// opened that route; the bare forms panicked at the same arm before it.
///
/// Every case renders under `catch_unwind` so that one panicking variant does not hide another, and
/// each is pinned to its exact rendering, so an arm that writes a placeholder, drops a term, or changes
/// a separator shows up here. The spellings are the report's, not the file's -- the comparator prints
/// as `EQUALS` and an access clause leads with the space its `not` would occupy -- because that is
/// what the `Display` impls for `GuardAccessClause` and `BlockGuardClause` produce, and the `when` and
/// parameterized-call arms are built from them. The two plain cases are the control: they are pinned
/// to what those two impls render on their own.
///
/// `when` conditions are joined, not terminated: ` or ` inside a disjunction, a space between
/// conjunctions, nothing before the `{`. A block body, including a `when` block's, keeps the `; ` after
/// every clause and every `let` that `Display for BlockGuardClause` has always written.
#[test]
fn rendering_every_clause_variant_does_not_panic() {
    let cases = [
        (
            "bare when block",
            "when X == 1 { Y == 2 }",
            "when  X EQUALS  1 {  Y EQUALS  2;  }",
        ),
        (
            "block body holding a when block",
            "Properties { when X == 1 { Y == 2 } }",
            "Properties { when  X EQUALS  1 {  Y EQUALS  2;  };  }",
        ),
        (
            "bare parameterized call",
            "check(%x, \"lit\")",
            "check(%x, \"lit\")",
        ),
        (
            "negated parameterized call",
            "not check(%x)",
            "not check(%x)",
        ),
        (
            "block body holding a parameterized call",
            "Properties { check(%x) }",
            "Properties { check(%x);  }",
        ),
        (
            "when block whose conditions name a rule and disjoin",
            "when other_rule or X == 1 { Y == 2 }",
            "when other_rule or  X EQUALS  1 {  Y EQUALS  2;  }",
        ),
        (
            "when block with two conjoined conditions",
            "when X == 1\n Z == 3 { Y == 2 }",
            "when  X EQUALS  1  Z EQUALS  3 {  Y EQUALS  2;  }",
        ),
        (
            "block body holding a let",
            "Properties { let v = 1\n X == %v }",
            "Properties { let v = 1;  X EQUALS  %v;  }",
        ),
        (
            "control: plain block",
            "Properties { X == 1 }",
            "Properties {  X EQUALS  1;  }",
        ),
        ("control: plain clause", "X == 1", " X EQUALS  1"),
    ];
    let mut failures = Vec::new();
    for (label, text, expected) in cases {
        let clause = GuardClause::try_from(text)
            .unwrap_or_else(|e| panic!("{} ({:?}) should parse: {}", label, text, e));
        match std::panic::catch_unwind(|| format!("{}", clause)) {
            Ok(rendered) => {
                if rendered != expected {
                    failures.push(format!(
                        "{}: rendering of {:?}\n  expected {:?}\n  got      {:?}",
                        label, text, expected, rendered
                    ));
                }
            }
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                failures.push(format!(
                    "{}: rendering of {:?} panicked: {}",
                    label, text, msg
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "Display for GuardClause failed for:\n{}",
        failures.join("\n")
    );
}

/// Nothing the parser can read produces `QueryPart::AllValues(Some(_))`.
///
/// NOT IGNORED, and it passes: this pinned a dead branch rather than a wrong answer, and it is why
/// removing the branch was a safe change rather than a guess.
///
/// `all_indices`' named branch is whitespace-tolerant, and it is tried first in `predicate_or_index`.
/// Its language is exactly what a named branch of `map_key_lookup` would accept --
/// `[ ws* var_name ws* ]`, since `close_array` skips the trailing whitespace in both -- so such a
/// branch is unreachable for every input, and `parser.rs` is the only place in the tree that
/// constructs `AllValues(Some(_))`.
///
/// FIXED, by deletion. `map_key_lookup`'s named branch is gone, along with the two consumers that read
/// its output: the `Some(n)` capture in the `QueryPart::AllValues` arm of
/// `eval_context::query_retrieval_with_converter`, and `AllValues`' half of
/// `collect_query_capture_names`' `AllValues(name) | AllIndices(name)` arm. All three had to go
/// together -- the shape `MapKeyComparator`'s own doc comment argues against is a value nothing can
/// build being handled by code that reads as live -- and restoring any one of them alone would put it
/// back.
///
/// The payload stays on the variant. `AllValues(Option<String>)` is serialized into the `parse-tree`
/// command's output as `AllValues: null`, which the goldens in `guard/tests/parse_tree.rs` and the
/// checked-in trees under `guard/resources/parse-tree/` both spell that way, so narrowing the variant to
/// carry nothing would change a user-visible format to tidy an internal one. This test is what keeps the
/// `None`-only invariant honest instead.
#[test]
fn no_query_spelling_produces_a_named_all_values() {
    let spellings = [
        "Resources[x]",
        "Resources[ x]",
        "Resources[x ]",
        "Resources[ x ]",
        "Resources[\tx\t]",
        "Resources[\n  x\n]",
        "Resources[ # comment\n x ]",
        "Resources[ x # comment\n ]",
        "Resources[\"x\"]",
        "Resources[ \"x\" ]",
        "Resources[*]",
        "Resources[ * ]",
        "Resources[0]",
        "Resources[ 0 ]",
        "Resources[ x | Type == 'a' ]",
        "Resources[ keys == /^a/ ]",
    ];
    for spelling in spellings {
        let query = AccessQuery::try_from(spelling)
            .unwrap_or_else(|e| panic!("{:?} should parse: {}", spelling, e))
            .query;
        assert!(
            !query
                .iter()
                .any(|part| matches!(part, QueryPart::AllValues(Some(_)))),
            "{:?} produced AllValues(Some(_)), so map_key_lookup's named branch is live after all \
             and this pin is stale: {:?}",
            spelling,
            query
        );
    }

    // And the named index is the part they all land on, which is what makes the other branch dead
    // rather than merely rare.
    assert_eq!(
        AccessQuery::try_from("Resources[ x ]").unwrap().query[1],
        QueryPart::AllIndices(Some(String::from("x")))
    );
}
