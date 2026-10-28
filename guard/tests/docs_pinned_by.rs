// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! The clause tables in `docs/*.md` (the tables under the header `| the clause | the map's shape |
//! operator | verdict | notice | pinned by |`, in `docs/CLAUSES.md` and in `docs/KNOWN_ISSUES.md`) cite,
//! in their "pinned by" column, the test that asserts each row. This test reads every such table and the
//! cited test sources and checks every citation, so a renamed test or a reworded case label fails here,
//! naming the row, instead of leaving the table pointing at nothing.
//!
//! A cell is `none` (a row no test asserts) or one or more citations separated by `; `, each
//! `<file>:<fn>`, `<file>:<fn> (case "<label>")` or `<file>:<fn> (cases "<label>", "<label>", ...)`,
//! each optionally followed by `, fixture `<file>`` naming a fixture file under `guard/resources/`; a
//! last part reading `unpinned` or `unpinned: <what>` marks a spelling of the row that no test asserts,
//! and nothing follows it (a bare `unpinned` or an `unpinned: <what>` anywhere but last is malformed, and
//! so is the singular `(case ...)` holding several labels). A citation by fn alone pins the row to the
//! test and to no case of it, so it still fails on a renamed test. What is checked: the file is one of
//! the five test sources (`CITED_TEST_SOURCES`), `fn <fn>(` is defined in it, the fixture file exists by
//! name under `resources/` (not that the fn reads it), and every label is a string the fn CARRIES, one
//! of: a named rstest case `#[case::<label>(` on that fn; the string arguments of one unnamed
//! `#[case(...)]` on it, joined by `, `; a string literal anywhere in the fn's body (an assertion message
//! or a rule fragment counts as much as a case, so a resolved label proves the fn writes the string, not
//! that the fn asserts a run by that name); a string literal of a `const` or `static` row table the body
//! names (one declared in the fn's own body first, else one of the fn's module or an enclosing module); a
//! format template that is the format argument of a `format!`, `panic!`, `assert!`, `assert_eq!` or
//! `assert_ne!` call in the body, with each `{}` or `{name}` placeholder standing for any non-empty
//! string the fn carries in any slot (not the argument passed there), so a placeholder text the fn never
//! carries, or a label that drops a placeholder, is refused (a brace that is not a placeholder, as in a
//! Guard rule written into a plain string, makes the
//! literal a plain one, matched whole); or, for a fn whose body names the wildcard-filter fixtures
//! directory, a `<rules file> over <document>` row of that README's `## Cells` table (its other tables
//! are not rows a test runs). The PROSE of `docs/CLAUSES.md`, `docs/KNOWN_ISSUES.md` and the README is
//! read too (`PROSE_CITATIONS_READ_IN`, `prose_citations`): inside a "pinned by" span, up to its closing
//! `)` outside a backtick, every backticked name before the first `;` outside a backtick is a test fn
//! name (lower-case words joined by `_`, defined in the source named just before it or as
//! `<source>:<fn>`, else in any cited source), a cited source name, `<source>:<fn>`, or a whole table-cell
//! citation `<source>:<fn> (case ...)`, read as a cell is, cases and all, and anything else fails; past
//! that `;` the span is prose, so a name bound to a source and a fn-shaped name that is not one of
//! Guard's own (`GUARD_FUNCTION_NAMES`: its built-in functions and `match_all`) are checked there and
//! other words are left alone; a second "pinned by" written inside a span opens a span of its own; a
//! line whose code span or "pinned by" span is still open at its end continues on the next line, so a
//! wrapped citation is read, and a backtick a span never closes is a failure; and every backticked file
//! name ending in `.yaml` or `.guard` that `ILLUSTRATIVE_FILE_NAMES` does not name is a file under
//! `resources/`.
//!
//! A label is spelled as a non-raw Rust string literal would spell it: a quote inside it as `\"`, a
//! backslash as `\\`, a line break as `\n` (a `\r\n` in the source reads as `\n`), a tab as `\t`. A
//! literal the source writes raw (`r#"..."#`), or a plain literal written across source lines, is read in
//! that spelling too, so `r#"rule r { Name == "b" }"#` is cited as `rule r { Name == \"b\" }` and a plain
//! literal's real line break as `\n`; a plain literal continued with a `\` at the end of a source line
//! drops the break and the next line's leading blanks, as the compiler does. A `|` inside a label is
//! written `\|`, as a Markdown table cell writes a pipe, and a `|` inside a code span of any table row of
//! the three documents is written `\|` too, since GitHub splits the cell there (a clause-table row holding
//! a bare one is refused whatever its cell count comes to; a row of any other table is named by line).
//!
//! Labels are resolved against the sources in every document. The three tables of `docs/KNOWN_ISSUES.md`
//! were written with prose labels before this check existed, and the labels that name no case, body
//! string or row of their test are listed by document, the row's clause cell (the text of the row's first
//! column, as written), the cited `<source>:<fn>` and the label in `KNOWN_UNRESOLVED_LABELS`: the row
//! that carries a listed label is still parsed (its shape, the test it names and the fixture files it
//! names are checked, so a renamed test or a malformed cell fails here), every other label of it must
//! resolve, and the listed label must stay unresolved, so a label that is re-pinned comes off the list
//! in the same change and a listed label no row of its clause carries under its test is reported by
//! name; a row whose labels are all unlisted fails here as a `docs/CLAUSES.md` row does. A row that moves
//! leaves the list as it is; a row whose clause cell is reworded, or whose citation moves to another
//! test, is re-listed with the new text; two rows of one document that write the same clause, cite the
//! same test and carry the same label share one entry, whose row count `SHARED_UNRESOLVED_ENTRIES`
//! states, and an entry met on another number of rows is reported, so a row copied with a listed clause
//! cell, citation and label is not exempt until it is counted. The list's length is the count of
//! distinct such entries.
//!
//! The sources are parsed once with `syn` and read at run time from the crate directory, and the
//! documents from the repository beside it; a crate packaged without `docs/` fails this test unless
//! `GUARD_DOCS_ABSENT=1` is set, which is what a packaging run sets.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Lit, Meta};

const CLAUSE_TABLE_HEADER: &str =
    "| the clause | the map's shape | operator | verdict | notice | pinned by |";

/// The test sources a clause table or a prose citation may cite, by the name the documents use and the
/// path under the crate.
const CITED_TEST_SOURCES: [(&str, &str); 5] = [
    ("eval_tests.rs", "src/rules/eval_tests.rs"),
    ("eval_context_tests.rs", "src/rules/eval_context_tests.rs"),
    ("loader_tests.rs", "src/rules/libyaml/loader_tests.rs"),
    ("tests/validate.rs", "tests/validate.rs"),
    ("tests/test_command.rs", "tests/test_command.rs"),
];

/// The fixture directories whose README tables a cited test reads row by row.
const CITED_FIXTURE_DIRS: [&str; 1] = ["wildcard-filter-release-verdicts"];

/// The labels known not to resolve, by document, the row's clause cell (its first column, as written),
/// the cited `<source>:<fn>` and the label as the cell writes it: the prose labels of the
/// `docs/KNOWN_ISSUES.md` tables, written before this check existed (the module doc). A row that carries
/// a listed label is still parsed and its test and fixture names checked, every OTHER label of it must
/// resolve, and the listed label must FAIL to resolve, so a label that is re-pinned comes off the list
/// in the same change; a listed label no row carries (its clause cell reworded, the citation moved to
/// another test, or the label dropped) is reported by name, with the rows to add, each named with its
/// clause cell. The key does not move when rows are inserted above a listed one, and it confines the
/// exemption to the test the label was written against. Two rows of one document that write the same
/// clause, cite the same test and carry the same label share one entry, listed with its row count in
/// `SHARED_UNRESOLVED_ENTRIES` (two pairs do today: a row repeated, in a later table or the same one,
/// with another verdict or notice); an entry met on another number of rows than its count is reported,
/// so no copied row inherits an exemption unlisted. Regenerate it from the test's own report, or from a
/// reading of every row's labels against the sources.
const KNOWN_UNRESOLVED_LABELS: [(&str, &str, &str, &str); 132] = [
    (
        "KNOWN_ISSUES.md",
        r#"`%s[ securityContext !exists ] !empty`"#,
        "eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling",
        r#"alias gate over a spec lacking securityContext"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%s[ securityContext !exists ] !empty`"#,
        "eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling",
        r#"alias gate over a spec with securityContext"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`spec[ securityContext !exists ] !empty`"#,
        "eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling",
        r#"literal gate over the same spec: refused, fail closed"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`spec[ securityContext !exists ]`"#,
        "eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling",
        r#"literal gate over the same spec: refused, fail closed"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[ Owner !exists ]`"#,
        "eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence",
        r#"the compliant mixed map, one member carrying the key"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`spec[*][ securityContext !exists ]`"#,
        "eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling",
        r#"the author's [*] over the spec lacking securityContext"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%r[ Properties !exists ]`"#,
        "eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape",
        r#"the population alias over a section written as a lone transform, under an absence check"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`labels[ this !empty ] empty`"#,
        "eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause",
        r#"control: `this !empty` alone"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`labels.*[ env exists ] empty`"#,
        "eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause",
        r#"control: `labels.*[ env exists ] empty` over the all-scalar map"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`labels.*[ this !empty ] empty`"#,
        "eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause",
        r#"control: `labels.*[ this !empty ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Properties[ Foo !exists ] !empty`"#,
        "eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause",
        r#"the literal spelling over all-scalar Properties under a key the map lacks"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%p[ TagSpecifications !exists ]`"#,
        "eval_tests.rs:a_sub_map_carrying_the_checked_key_under_a_named_binding_is_announced",
        r#"the example"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%r[ DeletionPolicy !exists ]`"#,
        "eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape",
        r#"the common absence check over a nested collection one resource of which carries the key"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%d[ MetadataOptions !exists ]`"#,
        "eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape",
        r#"a named map whose sub-maps share no key name is an object"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%s[ securityContext !exists ]`"#,
        "eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape",
        r#"a Deployment `spec` of `selector` and `template`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%s[ securityContext !exists ]`"#,
        "eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape",
        r#"the same `spec` as a `when` gate"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%md[ labels !exists ]`"#,
        "eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape",
        r#"a map of scalars: the predicate resolved no key on any entry"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ Type == 'AWS::S3::Bucket' or BucketA exists ]`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"bracket wildcard, a member key beside the map's own key"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Rules[*][ R1 !exists or Action == 'deny' ]`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"a disjunct that never holds beside the negated own key"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`some Cfg[*][ Mode exists or M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty or Ref !exists ].Kind == 'k'`"#,
        "eval_tests.rs:an_entry_held_without_grounding_does_not_decide_past_an_undecided_one",
        r#"some after [*]: the undecided entry's marker alone answers"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*[ Properties.Cfg[*][ x \| R1 !exists ] !empty ]`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"inside a predicate: the refused enumeration's capture holds the refusal's marker alone"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`let sel = Cfg[ y ][ Kind == 'k' ]` and `let sel = Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`, read by `%sel !empty`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"`Cfg[ y ][ Kind == 'k' ]`, no own key named"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`let sel = Cfg[ y ][ Kind == 'k' ]` and `let sel = Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`, read by `%sel !empty`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"`Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`.M[ keys == to_upper(Env) ]`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"a later part of the same query reads the scope's root"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"the own-key spelling: `%x` is bound to each held key just before that entry is walked"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[ y ][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %y ]`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"the own-key spelling, the wildcard's own capture read mid-query"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`let sel = Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]` and `let sel = Cfg[*][ x \| Kind == 'k' ].Peers[ this IN %x ]`, read by `%sel !empty`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"the own-key spelling over the entries in the other order"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`let sel = Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]` and `let sel = Cfg[*][ x \| Kind == 'k' ].Peers[ this IN %x ]`, read by `%sel !empty`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"the regular spelling over the entries in the other order"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`.Sub[*][ s \| R1 !exists ]`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"an enumeration the continuation refuses"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[*][ x \| Kind == 'k' ].Sub[*][ s \| R1 !exists ]`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"the regular spelling (`Cfg[*][ x \| Kind == 'k' ]`, no own key named)"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[ x \| Kind == 'k' ] !empty`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"a same-name capture another clause of the block filed before the refused walk"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`.M[ keys == Names[*].Name ]`"#,
        "eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one",
        r#"an undecidable the walk meets for another reason"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ BucketA exists ] empty`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"a member named like the key alone under empty"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%r[ Properties.Tags empty ] !empty`"#,
        "eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling",
        r#"tagging idiom over a transform beside two tagged buckets"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key !exists ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"tags written as a loop under `Tags[*][ Key !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`States[*][ Type !exists ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"states written as a loop under the [*] spelling of `[ Type !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*.Metadata[ Comment !exists ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"a resource's `Metadata` attribute holding only a transform"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Parameters[ Value !exists ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"a `Parameters` holding only a transform under `Parameters[ Value !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Parameters[ Type !exists ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"a `Parameters` holding only a loop under `Parameters[ Type !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Tags !exists ] empty`"#,
        "eval_tests.rs:a_directive_is_read_the_same_at_a_nested_map_and_beside_any_sibling",
        r#"the include alone as `Properties` under `Properties.*[ Tags !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`SecurityGroupIngress[*][ Description !exists ] empty`"#,
        "eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance",
        r#"a lone directive under `[*]`: the directive sentence"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Value !exists ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"tags written as a transform under the [*] spelling of `[ Value !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*[ this IS_LIST ] empty`"#,
        "eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling",
        r#"a ForEach list beside two members, .*: `[ this IS_LIST ] empty` selects the list"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags.*[ Key !exists ] empty`"#,
        "eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling",
        r#"a one-key `Fn::If` tag list, .*: `Tags.*[ Key !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Target[*][ Name !exists ] empty`"#,
        "eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling",
        r#"a one-key `Fn::FindInMap` scalar list, [*]: `Target[*][ Name !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Mappings.RegionMap.*[ AMI !exists ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"a transform beside the region entries of `Mappings.RegionMap`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Parameters.*[ Default !exists ] !empty`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"a parameter named like the key, `Default !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Parameters.*[ Default exists ] empty`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"a parameter named like the key, `Default exists ] empty`: no parameter declares one"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ BucketA !exists ] !empty`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"bracket wildcard, a member named like the key negated: every resource is kept"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%r[*]`"#,
        "eval_tests.rs:the_member_notice_decides_on_what_the_predicate_kept_and_probes_each_site_once",
        r#"control: a site whose probe read a hold (`%r[*]`: the bound map itself)"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ AWSTemplateFormatVersion exists ] !empty`"#,
        "eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance",
        r#"a key the document holds and no member holds (`AWSTemplateFormatVersion exists`)"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ BucketA exists Type == 'AWS::S3::Bucket' ] empty`"#,
        "eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard",
        r#"a member key conjoined with a key the map lacks under `empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ Tags !exists ]`"#,
        "eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance",
        r#"the same hold under `!empty`: the verdict agrees"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ Tags !exists ].Type == 'AWS::S3::Bucket'`"#,
        "eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance",
        r#"a hold by the absence of a key the document lacks (`Tags !exists`)"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ BucketA !exists M[ keys == Tags[ Key == 'Env' ].Value ] !empty ] empty`"#,
        "eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance",
        r#"an undecidable member under `empty`: fails closed"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*.Metadata[*][ "AWS::CloudFormation::Init" exists ] empty`"#,
        "eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard",
        r#"the Init shape under `exists ] empty`: nothing selected"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`resources[*][ limits exists ] empty`"#,
        "eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard",
        r#"a container's resources of limits beside requests under `exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*.Metadata.*[ "AWS::CloudFormation::Init" exists ] empty`"#,
        "eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard",
        r#"the Init shape under `.*` and `exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*.Metadata[*][ Type exists ] !empty`"#,
        "eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard",
        r#"the resource's own key `Type` asked of its Metadata members under `[*]` and `!empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%p[*][ BucketEncryption exists ] !empty`"#,
        "eval_tests.rs:a_wildcard_filter_over_a_mixed_or_dot_enumerated_one_object_map_is_refused_by_name",
        r#"the projecting binding over all-structure Properties, gate polarity"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ BucketA exists ]`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"`BucketA exists`, !empty: the selection keeps nothing"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources[*][ BucketA exists ]`"#,
        "eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused",
        r#"a member named like the key alone under empty"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Templates[*].Resources`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"a `Resources` holding only a loop, in a `Templates` list"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*.Properties.*[ Name == 'AWS::Include' ] empty`"#,
        "eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only",
        r#"an include beside `BucketName` under `Properties.*[ Name == 'AWS::Include' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[ Owner !exists this[ keys == to_upper(Env) ] !empty ] empty`"#,
        "eval_tests.rs:the_one_object_probe_reads_the_fallback_and_carries_its_errors_as_the_bracket_reading_would",
        r#"must-flag: over `Env: prod` the fallback read holds the key filter on `PROD`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[ Owner !exists this[ Owner !exists ] !empty ] empty`"#,
        "eval_tests.rs:the_one_object_probe_reads_the_fallback_and_carries_its_errors_as_the_bracket_reading_would",
        r#"must-flag: a refusal raised inside the predicate is carried out of the probe"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`spec.*[ securityContext !exists ] !empty`"#,
        "eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling",
        r#"dot wildcard over the spec with replicas beside the sub-maps"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Properties.Tags[*][ Key == 'Env' ].Value == 'prod'`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under `== 'prod'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Principal == '*' ].Effect == 'Deny'`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"the same identity-policy statement with a part after the filter that reads `Effect`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Action == '*' ].Condition exists`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a `NotAction` statement under `[ Action == '*' ].Condition exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Principal == '*' ][ Effect == 'Allow' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a chained filter whose predicate names `Effect`, a key the object holds"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Principal == '*' ][ Sid == 'x' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a chained filter whose predicate names `Sid`, a key the object also lacks"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*[ Properties.PolicyDocument.Statement[*][ Principal.AWS == '*' ].Effect == 'Allow' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"inside a predicate, `[ Principal.AWS == '*' ].Effect == 'Allow'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Principal.AWS == '*' ][ Effect == 'Allow' ] !empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"inside a predicate, a chained filter `[ Principal.AWS == '*' ][ Effect == 'Allow' ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key IN ['Env', 'Environment'] ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under a binding to `[ Key IN ['Env', 'Environment'] ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key != 'Env' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"two tags under `[ Key != 'Env' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == 'Env' Value == 'prod' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"list tags `dev` under `[ Key == 'Env' Value == 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == 'Env' ] exists`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under a bare `[ Key == 'Env' ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == 'Env' Value == 'prod' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"list tags `dev` under `[ Key == 'Env' Value == 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == 'Owner' Value == 'Team' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags with no compared entry under `[ Key == 'Owner'  Value == 'Team' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key NOT IN ['Env', 'Environment'] ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags with no compared entry under `[ Key NOT IN ['Env', 'Environment'] ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key != 'Env' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags with no compared entry under a NEGATED bare `[ Key != 'Env' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key != 'Env' or Value != 'prod' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `prod` under `[ Key != 'Env' or Value != 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Value == 'prod' Key != 'Env' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `prod` under `[ Value == 'prod'  Key != 'Env' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key != 'Env' or Action != '*' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags with no compared entry under `[ Key != 'Env' or Action != '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Env[*][ Name != 'x' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"an env-var map keyed by name under `Env[*][ Name != 'x' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Values != 'x' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"an env-var map keyed by name under `Env[*][ Values != 'x' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Action != '*' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object `NotAction` statement under `[ Action != '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Value != 'platform' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags with no compared entry under a negation on the value"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Value != 'platform' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under `[ Value != 'platform' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Action != '*' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object `NotAction` statement under `[ Action != '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == 'Env' Value != 'prod' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags with no compared entry under `[ Key == 'Env'  Value != 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Principal == '*' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"an identity-policy statement under `[ Principal == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Action == '*' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a `NotAction` statement under `[ Action == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Resource == '*' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a trust-policy statement under `[ Resource == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Principal.AWS == '*' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"the same statement under `[ Principal.AWS == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*[ Properties.Tags[*][ Key == 'Env' ].Value != 'prod' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"select the violators, assert none"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key exists ] !empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"`[ Key exists ] !empty` over map tags"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == 'Env' ].Value == 'prod'`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under `== 'prod'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == %w ] !empty` where `%w` is the capture of an earlier clause"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under `[ Key == %w ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`let env = Resources.*.Properties.Tags[*][ t \| Key == 'Env' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under a filter capture read later"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ t \| Key == 'Env' ] exists` (the first clause of a rule whose second clause is `%t.Value == 'prod'`)"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under a filter capture and a bare `exists` in the filter's own clause"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == 'Env' ] { check(this) }`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under the block form `{ check(this) }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Principal == '*' ] { Effect == 'Allow' Condition exists }`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement under `[ Principal == '*' ] { Effect == 'Allow'  Condition exists }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Sid == 'x' or %flag == true ]`"#,
        "eval_tests.rs:a_clause_nested_in_the_body_is_judged_on_its_own_reads",
        r#"the inline chained `[ Sid == 'x' or %flag == true ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`some Resources.*.Properties.Tags[*][ Key == 'Env' ] { Value == 'prod' }`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"two functions, one map-shaped and one list-shaped, both `prod`, under `some` and the block form"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Principal == '*' ].Condition exists`"#,
        "eval_tests.rs:a_deferred_lacks_keys_refusal_is_recorded_as_the_inline_spellings_is",
        r#"the control"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == /^(?!aws:)/ ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under a binding to `[ Key == /^(?!aws:)/ ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == /^[A-Za-z]+[0-9]$/ ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `{ Env1: dev }` under a bare `[ Key == /^[A-Za-z]+[0-9]$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Principal == '*' or Sid == /^\w+$/ ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement under `[ Principal == '*' or Sid == /^\w+$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Sid == /^\w+$/ ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement under a bare `[ Sid == /^\w+$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Sid == /^\w+$/ ] !exists`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement under a bare `[ Sid == /^\w+$/ ] !exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Resources.*[ Properties.PolicyDocument.Statement[*][ Sid == /^\w+$/ ] is_struct ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement without `Sid`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Sid == /.+/ ].Effect == 'Deny'`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement under `[ Sid == /.+/ ].Effect == 'Deny'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Sid == /^[A-Za-z0-9]+$/ ].Effect == 'Deny'`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement under `[ Sid == /^[A-Za-z0-9]+$/ ].Effect == 'Deny'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Sid == /^[A-Za-z]+$/ ] exists`"#,
        "eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure",
        r#"statement `{ Effect: Allow }` under a bare `[ Sid == /^[A-Za-z]+$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == /^[A-Za-z]+$/ ] exists`"#,
        "eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure",
        r#"mixed map under a bare `[ Key == /^[A-Za-z]+$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Sid == /^\w+$/ ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement under a bare `[ Sid == /^\w+$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == /^[A-Za-z]+$/ ] empty`"#,
        "eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure",
        r#"mixed map under a bare `[ Key == /^[A-Za-z]+$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == /^[Ee][Nn][Vv]$/ ] exists`"#,
        "eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure",
        r#"mixed map `{ Env: { Ref }, Team: platform }` under a bare `[ Key == /^[Ee][Nn][Vv]$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == /^[[:alpha:]]+$/ ] exists`"#,
        "eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure",
        r#"mixed map `{ Env: dev, ENV: { Ref } }` under a bare `[ Key == /^[[:alpha:]]+$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*][ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists`"#,
        "eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure",
        r#"statement `{ Effect: Allow }` under a bare `[ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Sid == /^\w+s?$/ ] exists`"#,
        "eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure",
        r#"statement `{ Effect: Allow }` under a bare `[ Sid == /^\w+s?$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Sid == /^E/ ].Effect == 'Deny'`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a one-object statement holding `Effect`, `Env` and `Action` under `[ Sid == /^E/ ].Effect == 'Deny'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Tags[*][ Key == 'Env' ] { Value == 'prod' }`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under the block form `[ Key == 'Env' ] { Value == 'prod' }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`%env[ Value == 'x' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `Team` and `Value` under `%env[ Value == 'x' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`some Resources.*.Properties.Tags[*][ Key == 'Env' ].Value == 'prod'`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"two functions, one map-shaped and one list-shaped, both `prod`, under `some` and the inline spelling"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Statement[*] { when Principal exists { Principal.AWS != '*' } }`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"the presence-guarded spelling is not applicable over the statement with no principal"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key == 'Env' ] exists`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under a bare `[ Key == 'Env' ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key != 'Env' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under `[ Key != 'Env' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Value == 'prod' ] empty`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `{ Team: prod }` under `[ Value == 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ t \| Key == 'Env' ]`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"map tags `dev` under a filter capture read later"#,
    ),
];

/// The entries of `KNOWN_UNRESOLVED_LABELS` that more than one row writes, with the number of rows: a
/// row repeated, in a later table or the same one, with another verdict or notice, citing the same test.
/// Every other entry is met on exactly one row. The test counts the rows each entry is met on and
/// reports a count that differs, so a row copied with a listed clause cell, citation and label does not
/// inherit the exemption in silence (it is listed here by its count) and a twin row that is gone brings
/// the count down.
const SHARED_UNRESOLVED_ENTRIES: [(&str, &str, &str, &str, usize); 2] = [
    (
        "KNOWN_ISSUES.md",
        r#"`spec[ securityContext !exists ]`"#,
        "eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling",
        r#"literal gate over the same spec: refused, fail closed"#,
        2,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Action == '*' ].Condition exists`"#,
        "eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused",
        r#"a `NotAction` statement under `[ Action == '*' ].Condition exists`"#,
        2,
    ),
];

/// A shared entry as `SHARED_UNRESOLVED_ENTRIES` writes it: a listed key and the number of rows.
type SharedKey<'a> = (&'a str, &'a str, &'a str, &'a str, usize);

/// The number of rows a listed entry is met on under `shared`: its count there, else one.
fn rows_listed_in(shared: &[SharedKey], entry: &ListedKey) -> usize {
    shared
        .iter()
        .find(|(doc, clause, cited, label, _)| {
            (doc, clause, cited, label) == (&entry.0, &entry.1, &entry.2, &entry.3)
        })
        .map_or(1, |(_, _, _, _, rows)| *rows)
}

/// The number of rows a listed entry is met on: its `SHARED_UNRESOLVED_ENTRIES` count, else one.
fn rows_listed_for(entry: &ListedKey) -> usize {
    rows_listed_in(&SHARED_UNRESOLVED_ENTRIES, entry)
}

/// The documents whose PROSE citations are read too (`prose_citations`): a backticked fn name after
/// "pinned by" is defined in a cited test source, and a backticked file name ending in `.yaml` or
/// `.guard` is a file under `resources/` unless `ILLUSTRATIVE_FILE_NAMES` exempts it. The README sits
/// beside the repository root, not under `docs/`, so it is read from there.
const PROSE_CITATIONS_READ_IN: [&str; 3] = ["CLAUSES.md", "KNOWN_ISSUES.md", "README.md"];

/// File names the documents write as examples, not as fixtures: a backticked `.yaml` or `.guard` name
/// in this list is prose, every other one must exist under `resources/`. Every entry is a README example
/// (a rules file and a template a reader writes, a hook's configuration) at this writing.
const ILLUSTRATIVE_FILE_NAMES: [&str; 7] = [
    ".pre-commit-config.yaml",
    "api_gateway_private_access.guard",
    "api_gateway_private_access_tests.yaml",
    "k8s-pod-containers-limits.guard",
    "network.yaml",
    "security_groups.guard",
    "security_groups_fail.yaml",
];

/// The fewest clause-table rows, and the fewest of them pinned, each document is read to hold: the
/// document's counts when the floors were set (`CLAUSES.md` 131 rows, 117 pinned; `KNOWN_ISSUES.md` 253
/// rows, 235 pinned) less about a tenth. A document whose tables were deleted or whose cells were all
/// made `none` fails here by name, where one floor over the documents together was met by the larger
/// document alone. A change that shrinks a table below its floor on purpose lowers the floor with it.
const TABLE_FLOORS: [(&str, usize, usize); 2] =
    [("CLAUSES.md", 120, 105), ("KNOWN_ISSUES.md", 240, 215)];

/// Guard's own names the prose may write in backticks past the `;` of a "pinned by" span without citing
/// a test: the built-in functions `eval_context.rs` resolves by name whose names hold an underscore (a
/// name without one, `count`, `join`, `now`, `substring`, is never fn-shaped and needs no entry), the
/// `is_<kind>` type checks, and the `match_all` spelling of the quantifier. A fn-shaped name there that
/// is not one of these is a citation and is checked.
const GUARD_FUNCTION_NAMES: [&str; 18] = [
    "is_bool",
    "is_float",
    "is_int",
    "is_list",
    "is_string",
    "is_struct",
    "json_parse",
    "match_all",
    "parse_boolean",
    "parse_char",
    "parse_epoch",
    "parse_float",
    "parse_int",
    "parse_string",
    "regex_replace",
    "to_lower",
    "to_upper",
    "url_decode",
];

/// One path per document, as every report line writes it: the README at the repository root, the
/// others under `docs/`.
fn shown_path(name: &str) -> String {
    if name == "README.md" {
        name.to_string()
    } else {
        format!("docs/{}", name)
    }
}

/// What a cited fn carries: the module path it is declared in, its rstest cases, the string literals of
/// its body in the spelling a plain literal writes, the format templates of its formatting macros, every
/// identifier its body mentions, and the `const` / `static` items declared inside its body.
#[derive(Default)]
struct FnFacts {
    module: Vec<String>,
    named_cases: Vec<String>,
    unnamed_cases: Vec<String>,
    literals: Vec<String>,
    templates: Vec<String>,
    idents: HashSet<String>,
    local_consts: HashMap<String, Vec<String>>,
}

/// A module-level `const` or `static`: the module path it is declared in and its string literals.
struct ModuleItem {
    module: Vec<String>,
    literals: Vec<String>,
}

/// One parsed source: every fn by name (a name declared in several modules has several entries) and
/// every module-level `const` / `static` by name, each with the module path it is declared in.
#[derive(Default)]
struct SourceIndex {
    fns: HashMap<String, Vec<FnFacts>>,
    consts: HashMap<String, Vec<ModuleItem>>,
}

/// The text of a string literal in the spelling a plain (not raw) literal writes it: a plain literal's
/// text as written between its quotes, escapes kept as the source spells them; a raw literal's contents
/// with a quote written `\"`, a backslash `\\` and a line break `\n`, so the two spellings of one text
/// read alike and a table cites either the same way.
fn literal_as_written(lit: &syn::LitStr) -> String {
    let raw = lit.token().to_string();
    if let Some(rest) = raw.strip_prefix('r') {
        let hashes = rest.bytes().take_while(|b| *b == b'#').count();
        let inner = &rest[hashes + 1..rest.len() - 1 - hashes];
        // a checkout that rewrote the source's line breaks as `\r\n` reads as the `\n` the compiler
        // reads, so a citation written on one platform resolves on the other
        return inner
            .replace("\r\n", "\n")
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
    }
    // a plain literal written across source lines carries its line breaks (and any raw tab or carriage
    // return) as bytes; they read as the escapes a one-line table cell can write, as a raw literal's do,
    // while an escape the source spells (`\n` as two characters) is kept as spelled; a `\` at the end of
    // a source line continues the literal, and the compiler drops that line break and the next line's
    // leading blanks, so the spelling drops them too
    let inner = &raw[1..raw.len() - 1];
    let mut joined = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            joined.push(ch);
            continue;
        }
        match chars.peek() {
            Some('\n') | Some('\r') => {
                while matches!(
                    chars.peek(),
                    Some('\r') | Some('\n') | Some(' ') | Some('\t')
                ) {
                    chars.next();
                }
            }
            Some(next) => {
                // an escape the source spells, `\\` and `\"` included, is kept as spelled
                joined.push('\\');
                joined.push(*next);
                chars.next();
            }
            None => joined.push('\\'),
        }
    }
    joined
        .replace("\r\n", "\n")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// The index of the format argument of a formatting macro, by the macro's name.
fn template_argument(macro_name: &str) -> Option<usize> {
    match macro_name {
        "format" | "format_args" | "panic" | "print" | "println" | "eprint" | "eprintln"
        | "unreachable" | "todo" => Some(0),
        "assert" | "write" | "writeln" => Some(1),
        "assert_eq" | "assert_ne" => Some(2),
        _ => None,
    }
}

/// The top-level comma-separated arguments of a macro's tokens.
fn macro_arguments(tokens: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut args = vec![Vec::new()];
    for tree in tokens {
        match &tree {
            TokenTree::Punct(p) if p.as_char() == ',' => args.push(Vec::new()),
            _ => args.last_mut().unwrap().push(tree),
        }
    }
    args
}

/// Walks a macro's tokens: the format argument of a formatting macro is a template, every other string
/// literal is a plain literal, every identifier is a mention, and a nested `name!(...)` is walked as
/// its own macro.
fn walk_macro_tokens(name: &str, tokens: TokenStream, facts: &mut FnFacts) {
    let template_at = template_argument(name);
    for (index, argument) in macro_arguments(tokens).into_iter().enumerate() {
        if template_at == Some(index) && argument.len() == 1 {
            if let TokenTree::Literal(literal) = &argument[0] {
                if let Lit::Str(s) = Lit::new(literal.clone()) {
                    facts.templates.push(literal_as_written(&s));
                    continue;
                }
            }
        }
        walk_token_trees(&argument, facts);
    }
}

fn walk_token_trees(trees: &[TokenTree], facts: &mut FnFacts) {
    let mut i = 0;
    while i < trees.len() {
        match &trees[i] {
            TokenTree::Ident(ident) => {
                facts.idents.insert(ident.to_string());
                // a nested macro call: `name ! ( ... )`
                if let (Some(TokenTree::Punct(bang)), Some(TokenTree::Group(group))) =
                    (trees.get(i + 1), trees.get(i + 2))
                {
                    if bang.as_char() == '!' && group.delimiter() != Delimiter::None {
                        walk_macro_tokens(&ident.to_string(), group.stream(), facts);
                        i += 3;
                        continue;
                    }
                }
            }
            TokenTree::Literal(literal) => {
                if let Lit::Str(s) = Lit::new(literal.clone()) {
                    facts.literals.push(literal_as_written(&s));
                }
            }
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                walk_token_trees(&inner, facts);
            }
            TokenTree::Punct(_) => {}
        }
        i += 1;
    }
}

/// Collects a fn body's (or a const's) literals, templates and identifiers, and the `const` / `static`
/// items declared inside a fn body, by name.
#[derive(Default)]
struct BodyCollector {
    facts: FnFacts,
}

/// The string literals and templates of a `const` or `static` item's expression.
fn item_literals(expr: &syn::Expr) -> Vec<String> {
    let mut body = BodyCollector::default();
    body.visit_expr(expr);
    let mut literals = body.facts.literals;
    literals.extend(body.facts.templates);
    literals
}

impl<'ast> Visit<'ast> for BodyCollector {
    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        self.facts.literals.push(literal_as_written(node));
    }

    fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
        self.facts.idents.insert(node.to_string());
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        walk_macro_tokens(&name, node.tokens.clone(), &mut self.facts);
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        self.facts
            .local_consts
            .insert(node.ident.to_string(), item_literals(&node.expr));
        visit::visit_item_const(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        self.facts
            .local_consts
            .insert(node.ident.to_string(), item_literals(&node.expr));
        visit::visit_item_static(self, node);
    }
}

/// Collects every fn, `const` and `static` of a source, nested modules included, each with the module
/// path it is declared in. A `const` or `static` declared inside a fn body is that fn's own
/// (`FnFacts::local_consts`), never a module item.
#[derive(Default)]
struct SourceCollector {
    index: SourceIndex,
    module: Vec<String>,
}

impl<'ast> Visit<'ast> for SourceCollector {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.module.push(node.ident.to_string());
        visit::visit_item_mod(self, node);
        self.module.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let mut body = BodyCollector::default();
        body.visit_block(&node.block);
        let mut facts = body.facts;
        facts.module = self.module.clone();
        for attr in &node.attrs {
            let path = attr.path();
            if path.segments.first().map(|s| s.ident.to_string()) != Some("case".to_string()) {
                continue;
            }
            if path.segments.len() == 2 {
                facts.named_cases.push(path.segments[1].ident.to_string());
            } else if let Meta::List(list) = &attr.meta {
                let labels: Vec<String> = list
                    .tokens
                    .clone()
                    .into_iter()
                    .filter_map(|tree| match tree {
                        TokenTree::Literal(literal) => match Lit::new(literal) {
                            Lit::Str(s) => Some(literal_as_written(&s)),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect();
                facts.unnamed_cases.push(labels.join(", "));
            }
        }
        self.index
            .fns
            .entry(node.sig.ident.to_string())
            .or_default()
            .push(facts);
        // The body was read by the BodyCollector above; a `const` inside it is the fn's own, so the
        // module walk does not descend into the fn.
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        self.index
            .consts
            .entry(node.ident.to_string())
            .or_default()
            .push(ModuleItem {
                module: self.module.clone(),
                literals: item_literals(&node.expr),
            });
        visit::visit_item_const(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        self.index
            .consts
            .entry(node.ident.to_string())
            .or_default()
            .push(ModuleItem {
                module: self.module.clone(),
                literals: item_literals(&node.expr),
            });
        visit::visit_item_static(self, node);
    }
}

fn index_source_text(text: &str, what: &str) -> SourceIndex {
    let file = syn::parse_file(text)
        .unwrap_or_else(|e| panic!("the cited test source {} parses as Rust: {}", what, e));
    let mut collector = SourceCollector::default();
    collector.visit_file(&file);
    collector.index
}

fn parse_source(path: &Path) -> SourceIndex {
    let text = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "the cited test source {} is readable: {}",
            path.display(),
            e
        )
    });
    index_source_text(&text, &path.display().to_string())
}

/// The fixed pieces of a format template around its placeholders (`{}`, `{name}`, `{name:spec}`, with
/// `{{` and `}}` as braces), or `None` when the literal is not a format template: no placeholder, a
/// stray brace (a Guard rule written into a plain string), or under twelve characters of its own text,
/// which would match every label.
fn template_pieces(template: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = template.chars().collect();
    let mut pieces = vec![String::new()];
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '{' if chars.get(i + 1) == Some(&'{') => {
                pieces.last_mut().unwrap().push('{');
                i += 2;
            }
            '{' => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if chars.get(j) == Some(&':') {
                    j += 1;
                    while j < chars.len() && chars[j] != '{' && chars[j] != '}' {
                        j += 1;
                    }
                }
                if chars.get(j) != Some(&'}') {
                    return None;
                }
                pieces.push(String::new());
                i = j + 1;
            }
            '}' if chars.get(i + 1) == Some(&'}') => {
                pieces.last_mut().unwrap().push('}');
                i += 2;
            }
            '}' => return None,
            c => {
                pieces.last_mut().unwrap().push(c);
                i += 1;
            }
        }
    }
    if pieces.len() < 2 || pieces.iter().map(String::len).sum::<usize>() < 12 {
        return None;
    }
    Some(pieces)
}

/// Whether a label is one rendering of a format template the fn can write: its fixed pieces in order,
/// the first a prefix and the last a suffix, and the text each placeholder stands for a string the fn
/// carries (`carried`: its cases, its body literals and the literals of the row tables it names). A
/// label whose pieces fit but whose placeholder text the fn never writes is no rendering of its run.
fn label_matches_template(template: &str, label: &str, carried: &HashSet<&str>) -> bool {
    let Some(pieces) = template_pieces(template) else {
        return false;
    };
    let (first, last) = (&pieces[0], &pieces[pieces.len() - 1]);
    if label.len() < first.len() + last.len()
        || !label.starts_with(first.as_str())
        || !label.ends_with(last.as_str())
    {
        return false;
    }
    let inner = &label[first.len()..label.len() - last.len()];
    fills_are_carried(inner, &pieces[1..pieces.len() - 1], carried)
}

/// Whether `text` reads `<fill> piece <fill> piece ... <fill>` over `pieces`, every fill a carried
/// string that is not empty (a label that drops a placeholder is no rendering of the template, even
/// when the fn carries `""`). Every position of each piece is tried, so a piece that also occurs inside
/// a fill cannot hide the split that works.
fn fills_are_carried(text: &str, pieces: &[String], carried: &HashSet<&str>) -> bool {
    let Some((piece, rest)) = pieces.split_first() else {
        return !text.is_empty() && carried.contains(text);
    };
    let mut from = 0;
    while let Some(found) = text[from..].find(piece.as_str()) {
        let at = from + found;
        if at > 0
            && carried.contains(&text[..at])
            && fills_are_carried(&text[at + piece.len()..], rest, carried)
        {
            return true;
        }
        from = at + text[at..].chars().next().map_or(1, char::len_utf8);
        if from > text.len() {
            break;
        }
    }
    false
}

/// The cells of one clause-table row, split as GitHub Flavored Markdown splits them: at every `|` that
/// is not written `\|`, inside a code span too (a `|` inside backticks is a cell boundary to GitHub, so
/// the documents write it `\|`); each cell trimmed; `None` for a line that is not a row. A leading `> `
/// (the tables sit inside block quotes) is dropped first.
fn clause_table_cells(line: &str) -> Option<Vec<&str>> {
    let body = line.trim_start().trim_start_matches('>').trim();
    let body = body.strip_prefix('|')?;
    let mut cells = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (i, ch) in body.char_indices() {
        match ch {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '|' => {
                cells.push(body[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        cells.push(tail);
    }
    Some(cells)
}

/// Every file name under a directory, at any depth.
fn file_names_under(dir: &Path, into: &mut HashSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            file_names_under(&path, into);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            into.insert(name.to_string());
        }
    }
}

/// Everything the check reads: the parsed sources by the name the tables use, the fixture READMEs'
/// `<rules file> over <document>` rows by directory name, and the names of every file under
/// `resources/`, which a `, fixture `...`` part names.
struct Index {
    sources: HashMap<&'static str, SourceIndex>,
    fixture_rows: HashMap<&'static str, HashSet<String>>,
    fixture_files: HashSet<String>,
}

impl Index {
    fn build(crate_dir: &Path) -> Index {
        let sources = CITED_TEST_SOURCES
            .iter()
            .map(|(name, path)| (*name, parse_source(&crate_dir.join(path))))
            .collect();
        let fixture_rows = CITED_FIXTURE_DIRS
            .iter()
            .map(|dir| {
                let readme = crate_dir
                    .join("resources/validate")
                    .join(dir)
                    .join("README.md");
                let text = fs::read_to_string(&readme).unwrap_or_else(|e| {
                    panic!(
                        "the fixtures README {} is readable: {}",
                        readme.display(),
                        e
                    )
                });
                // the rows of the `## Cells` section alone: the README's other tables (its Notices
                // table among them) are not rows a test runs by `<rules file> over <document>`
                let mut in_cells = false;
                let rows = text
                    .lines()
                    .filter(|line| {
                        if line.starts_with("## ") {
                            in_cells = line.trim_end() == "## Cells";
                            return false;
                        }
                        in_cells
                    })
                    .filter_map(clause_table_cells)
                    .filter(|cells| {
                        cells.len() >= 2
                            && cells[0].ends_with(".guard")
                            && cells[1].ends_with(".yaml")
                    })
                    .map(|cells| format!("{} over {}", cells[0], cells[1]))
                    .collect();
                (*dir, rows)
            })
            .collect();
        let mut fixture_files = HashSet::new();
        file_names_under(&crate_dir.join("resources"), &mut fixture_files);
        Index {
            sources,
            fixture_rows,
            fixture_files,
        }
    }

    /// Why a label is not one the fn carries, or `None` when it is. A fn declared in several modules
    /// of the file resolves the label when any of its declarations carries it.
    fn unresolved_label(&self, file: &str, fn_name: &str, label: &str) -> Option<String> {
        let Some(source) = self.sources.get(file) else {
            return Some(format!(
                "`{}` is not a test source the tables may cite",
                file
            ));
        };
        let Some(declarations) = source.fns.get(fn_name) else {
            return Some(format!("no `fn {}(` in {}", fn_name, file));
        };
        // a pipe inside a label is written `\|`, as a Markdown table cell writes it
        let label = label.replace("\\|", "|");
        let label = label.as_str();
        for facts in declarations {
            // every string the fn carries: its cases, its body literals, and the literals of a row
            // table the body names (one declared in the fn's own body first, since it shadows a module
            // item of the same name, else one of the fn's module or an enclosing module)
            let mut carried: HashSet<&str> = HashSet::new();
            carried.extend(facts.named_cases.iter().map(String::as_str));
            carried.extend(facts.unnamed_cases.iter().map(String::as_str));
            carried.extend(facts.literals.iter().map(String::as_str));
            let mentioned = facts.idents.iter().filter(|name| {
                facts.local_consts.contains_key(*name) || source.consts.contains_key(*name)
            });
            for name in mentioned {
                if let Some(literals) = facts.local_consts.get(name) {
                    carried.extend(literals.iter().map(String::as_str));
                    continue;
                }
                if let Some(items) = source.consts.get(name) {
                    for item in items
                        .iter()
                        .filter(|item| facts.module.starts_with(&item.module))
                    {
                        carried.extend(item.literals.iter().map(String::as_str));
                    }
                }
            }
            if carried.contains(label) {
                return None;
            }
            // a rendering of a format template, each placeholder standing for a carried string
            if facts
                .templates
                .iter()
                .any(|t| t == label || label_matches_template(t, label, &carried))
            {
                return None;
            }
            if self
                .fixture_rows
                .iter()
                .filter(|(dir, _)| facts.literals.iter().any(|l| l == *dir))
                .any(|(_, rows)| rows.contains(label))
            {
                return None;
            }
        }
        let where_declared = if declarations.len() > 1 {
            format!(
                " (declared {} times, in modules {})",
                declarations.len(),
                declarations
                    .iter()
                    .map(|f| {
                        if f.module.is_empty() {
                            "the file root".to_string()
                        } else {
                            f.module.join("::")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            String::new()
        };
        Some(format!(
            "`{}` in {}{} has no case, case label, body string or row reading `{}`",
            fn_name, file, where_declared, label
        ))
    }

    /// Why `<file>:<fn>` names no fn of a cited source, or `None` when the source is one the documents may
    /// cite and defines the fn; the one lookup every citation shape runs.
    fn undefined_fn(&self, file: &str, fn_name: &str) -> Option<String> {
        let Some(source) = self.sources.get(file) else {
            return Some(format!(
                "`{}` is not a test source the documents may cite",
                file
            ));
        };
        if !source.fns.contains_key(fn_name) {
            return Some(format!("no `fn {}(` in {}", fn_name, file));
        }
        None
    }

    /// Why a `pinned by` cell does not name tests and cases they have, or `None` when every citation of
    /// it does.
    fn unresolved_cell(&self, cell: &str) -> Option<String> {
        self.unresolved_cell_in(cell, true)
    }

    /// `unresolved_cell`, with the labels read and resolved (`resolve_labels`) or read alone: a cell
    /// whose labels are read alone still has its shape, its tests and its fixture files checked.
    fn unresolved_cell_in(&self, cell: &str, resolve_labels: bool) -> Option<String> {
        self.unresolved_cell_with(cell, resolve_labels, &|_, _, _| false, &mut Vec::new())
    }

    /// `unresolved_cell_in` with the known-unresolved labels of the row (`exempt`, asked with the cited
    /// source, the fn and the label): a label the closure admits is not a failure when it does not
    /// resolve, and every such label is pushed onto `exempt_hits` as `(<source>:<fn>, label, still
    /// fails)`, so the caller can see a listed label that resolves after all (and comes off the list) and
    /// a listed label the row no longer carries (absent from the hits).
    fn unresolved_cell_with(
        &self,
        cell: &str,
        resolve_labels: bool,
        exempt: &dyn Fn(&str, &str, &str) -> bool,
        exempt_hits: &mut Vec<(String, String, bool)>,
    ) -> Option<String> {
        if cell == "none" {
            return None;
        }
        let malformed = |what: &str| {
            Some(format!(
                "not `<file>:<fn>[ (case \"...\")][, fixture `...`]` citations separated by `; `, with `unpinned[: ...]` last ({}): {}",
                what, cell
            ))
        };
        let mut rest = cell;
        let mut citations = 0usize;
        // the cell's first unlisted failing label, returned once every citation's labels are read, so
        // a listed label of a LATER citation is still recorded as met
        let mut cell_failure: Option<String> = None;
        loop {
            if rest == "unpinned" {
                break;
            }
            if let Some(what) = rest.strip_prefix("unpinned: ") {
                if what.contains("; ") {
                    return malformed("`unpinned: ...` is not the last part");
                }
                break;
            }
            // `unpinned; <more>`: the marker is the last part or the cell is malformed, so the
            // citation after it is never read in silence
            if rest.starts_with("unpinned; ") {
                return malformed("`unpinned` is not the last part");
            }
            let Some(colon) = rest.find(':') else {
                return malformed("no `<file>:`");
            };
            let file = &rest[..colon];
            let fn_end = rest[colon + 1..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(|at| colon + 1 + at)
                .unwrap_or(rest.len());
            let fn_name = &rest[colon + 1..fn_end];
            if fn_name.is_empty() {
                return malformed("not a test fn name");
            }
            let mut after_fn = &rest[fn_end..];
            // the fn is defined in the named source, whatever follows the citation
            if let Some(why) = self.undefined_fn(file, fn_name) {
                return Some(why);
            }
            if let Some(mut labels_text) = after_fn.strip_prefix(" (") {
                let plural = labels_text.starts_with("cases \"");
                labels_text = match labels_text.strip_prefix("cases \"") {
                    Some(t) => t,
                    None => match labels_text.strip_prefix("case \"") {
                        Some(t) => t,
                        None => return malformed("neither `(case \"` nor `(cases \"`"),
                    },
                };
                let mut labels = Vec::new();
                loop {
                    let Some(close) = label_end(labels_text) else {
                        return malformed("an unclosed label");
                    };
                    labels.push(&labels_text[..close]);
                    labels_text = &labels_text[close + 1..];
                    if let Some(more) = labels_text.strip_prefix(", \"") {
                        labels_text = more;
                        continue;
                    }
                    let Some(after) = labels_text.strip_prefix(')') else {
                        return malformed("a label list not closed by `)`");
                    };
                    labels_text = after;
                    break;
                }
                if !plural && labels.len() > 1 {
                    return malformed(
                        "`(case \"...\")` with several labels; the plural is `(cases ...)`",
                    );
                }
                if resolve_labels {
                    // every label of every citation is read, so a listed one is recorded as met
                    // whether or not an unlisted one failed before it, in this citation or an earlier
                    // one; the first failure is the cell's
                    let mut first_failure = None;
                    for label in labels {
                        // a label listed as known-unresolved must still fail, and is recorded as met;
                        // one that resolves after all is recorded so it comes off the list
                        let listed = exempt(file, fn_name, label);
                        let cited = || format!("{}:{}", file, fn_name);
                        match (listed, self.unresolved_label(file, fn_name, label)) {
                            (false, Some(why)) => {
                                if first_failure.is_none() {
                                    first_failure = Some(why);
                                }
                            }
                            (true, Some(_)) => exempt_hits.push((cited(), label.to_string(), true)),
                            (true, None) => exempt_hits.push((cited(), label.to_string(), false)),
                            (false, None) => {}
                        }
                    }
                    if cell_failure.is_none() {
                        cell_failure = first_failure;
                    }
                }
                after_fn = labels_text;
            }
            citations += 1;
            // `, fixture `<file>`` parts, each naming a file under resources/
            while let Some(fixture_text) = after_fn.strip_prefix(", fixture `") {
                let Some(close) = fixture_text.find('`') else {
                    return malformed("an unclosed fixture name");
                };
                let fixture = &fixture_text[..close];
                if !self.fixture_files.contains(fixture) {
                    return Some(format!(
                        "no file named `{}` under guard/resources/ for the fixture part of: {}",
                        fixture, cell
                    ));
                }
                after_fn = &fixture_text[close + 1..];
            }
            if after_fn.is_empty() {
                break;
            }
            let Some(next) = after_fn.strip_prefix("; ") else {
                return malformed("text after a citation that is not `; `");
            };
            rest = next;
        }
        if citations == 0 {
            return malformed("no citation beside the unpinned marker");
        }
        cell_failure
    }
}

/// The offset of the `"` that closes a label, skipping a quote written as `\"` (a label is written as the
/// source literal is, so a quote inside it carries its backslash), or `None` when no quote closes it.
fn label_end(text: &str) -> Option<usize> {
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match (escaped, c) {
            (true, _) => escaped = false,
            (false, '\\') => escaped = true,
            (false, '"') => return Some(at),
            (false, _) => {}
        }
    }
    None
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A clause-table row as read: its line number and, for a six-cell row, `(the clause cell, the
/// pinned-by cell)`, else why the line under a header is not such a row. The clause cell is the row's
/// first column as written, the text that keys the row in `KNOWN_UNRESOLVED_LABELS`.
type ClauseRow = (usize, Result<(String, String), String>);

/// A listed entry as a row names it: `(document, clause cell, <source>:<fn> as cited, label)`.
type ListedEntry = (String, String, String, String);

/// A listed entry as the list writes it: `(document, clause cell, <source>:<fn>, label)`.
type ListedKey<'a> = (&'a str, &'a str, &'a str, &'a str);

/// Whether a cited `<source>:<fn>` is the one a listed entry names, without building the joined text.
fn cites(listed: &str, file: &str, fn_name: &str) -> bool {
    listed
        .strip_prefix(file)
        .and_then(|rest| rest.strip_prefix(':'))
        .is_some_and(|rest| rest == fn_name)
}

/// What reading one document's clause tables yields: the rows that fail (a line whose labels were read
/// names the row's clause cell, the key an entry for it is written with), the listed entries met on a
/// row with the label still failing and the entries whose label resolved on a row, each with the row's
/// line, and the row counts.
#[derive(Default)]
struct RowsReading {
    unresolved: Vec<String>,
    met: Vec<(ListedEntry, usize)>,
    resolved: Vec<(ListedEntry, usize)>,
    /// The listed entries whose cited test and label a row carries that failed the shape check (its fn,
    /// fixture or citation grammar), by line: the row is reported in `unresolved` with its own fault and
    /// its labels were never read, so the entry is neither met nor missing (`classify`). Counted as
    /// missing, the report told the reader to drop an exemption the row still needs once its shape is
    /// fixed.
    shape_failed: Vec<(ListedEntry, usize)>,
    rows: usize,
    pinned: usize,
}

/// Reads one document's clause tables against the index and the known-unresolved labels (`list`, keyed
/// by document, the row's clause cell, the cited `<source>:<fn>` and the label): every row's shape, test
/// and fixture names first, its labels second, with a listed label admitted when it fails, recorded when
/// it resolves, and every other label required to resolve. Written as a fn of its inputs so a doctored
/// document and list are read the same way as the real ones.
fn read_rows(
    index: &Index,
    name: &str,
    shown: &str,
    text: &str,
    list: &[ListedKey],
) -> RowsReading {
    let mut reading = RowsReading::default();
    for (number, row) in clause_table_rows(text) {
        reading.rows += 1;
        match row {
            Err(why) => reading
                .unresolved
                .push(format!("{}:{}: {}", shown, number, why)),
            Ok((clause, cell)) => {
                if cell != "none" {
                    reading.pinned += 1;
                }
                // the shape, the fn and the fixture names first, for every row alike; the line names the
                // clause cell too, since a renamed test is re-cited and its entries re-keyed, not dropped
                if let Some(why) = index.unresolved_cell_in(&cell, false) {
                    reading.unresolved.push(format!(
                        "{}:{}: {} (the row's clause cell is {})",
                        shown, number, why, clause
                    ));
                    // the row's listed labels were not read: recorded as carried by a shape-failed row,
                    // so the report neither counts them met nor tells the reader to drop them (the cited
                    // test and the label are looked for as the cell writes them, the label as the quoted
                    // literal)
                    for (doc, c, cited, label) in list {
                        if *doc == name
                            && *c == clause
                            && cell.contains(cited)
                            && cell.contains(&format!("\"{}\"", label))
                        {
                            reading.shape_failed.push((
                                (
                                    name.to_string(),
                                    clause.clone(),
                                    cited.to_string(),
                                    label.to_string(),
                                ),
                                number,
                            ));
                        }
                    }
                    continue;
                }
                // then the labels: a listed one (by document, the row's clause cell, the cited test and
                // the label) must still fail, every other one must resolve
                let listed_here = |file: &str, fn_name: &str, label: &str| {
                    list.iter().any(|(doc, c, f, l)| {
                        *doc == name && *c == clause && cites(f, file, fn_name) && *l == label
                    })
                };
                let mut hits = Vec::new();
                if let Some(why) = index.unresolved_cell_with(&cell, true, &listed_here, &mut hits)
                {
                    // the line names the clause cell, so the entry to add can be copied from it
                    reading.unresolved.push(format!(
                        "{}:{}: {} (the row's clause cell is {})",
                        shown, number, why, clause
                    ));
                }
                // a listed label the cell cites twice for one test is one citation written twice: the
                // row counts once for the entry, so the repeat is named here rather than passed over
                for (i, (cited, label, _)) in hits.iter().enumerate() {
                    if hits[..i].iter().any(|(c, l, _)| c == cited && l == label) {
                        reading.unresolved.push(format!(
                            "{}:{}: the cell cites {} with the label {:?} twice (the row's clause cell is {})",
                            shown, number, cited, label, clause
                        ));
                    }
                }
                for (cited, label, still_fails) in hits {
                    let entry = (name.to_string(), clause.clone(), cited, label);
                    if still_fails {
                        reading.met.push((entry, number));
                    } else {
                        reading.resolved.push((entry, number));
                    }
                }
            }
        }
    }
    reading
}

/// What the listed entries read as once every document's rows are read: the entries met nowhere (they
/// come off the list), the entries met on another number of rows than they are listed for, the entries
/// whose label resolves (they come off the list too), the entries the list writes twice, and the shared
/// entries that name one row or are not in the list. Each line names the entry by document, label,
/// clause cell and cited test.
#[derive(Default)]
struct Classified {
    missing: Vec<String>,
    miscounted: Vec<String>,
    resolving: Vec<String>,
    duplicated: Vec<String>,
    shared_faults: Vec<String>,
}

/// Line numbers as a report writes them.
fn lines(numbers: &[usize]) -> String {
    numbers
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Classifies the listed entries (`list`, with the shared ones and their row counts in `shared`) against
/// the rows they were met on with the label still failing (`met`), the rows their label resolved on
/// (`resolved`), and the rows that carried them while failing the shape check (`shape_failed`), each as
/// `(entry, line)`; a row counts once however many times its cell writes the label. An entry carried
/// only by shape-failed rows is reported through those rows' own lines, never as missing. Written as a
/// fn of its inputs so a doctored reading is classified as the real one is.
fn classify(
    met: &[(ListedEntry, usize)],
    resolved: &[(ListedEntry, usize)],
    shape_failed: &[(ListedEntry, usize)],
    list: &[ListedKey],
    shared: &[SharedKey],
) -> Classified {
    let mut out = Classified::default();
    let named = |(doc, clause, cited, label): &ListedKey| {
        format!(
            "{}: {:?} on the row whose clause is {}, citing {}",
            shown_path(doc),
            label,
            clause,
            cited
        )
    };
    let mut distinct: HashSet<ListedKey> = HashSet::new();
    for entry in list {
        if !distinct.insert(*entry) {
            out.duplicated.push(named(entry));
        }
    }
    for (doc, clause, cited, label, rows) in shared {
        let key = (*doc, *clause, *cited, *label);
        if *rows < 2 {
            out.shared_faults.push(format!(
                "{}: listed as shared for {} row(s); a shared entry names at least two",
                named(&key),
                rows
            ));
        } else if !distinct.contains(&key) {
            out.shared_faults.push(format!(
                "{}: listed as shared but not in KNOWN_UNRESOLVED_LABELS",
                named(&key)
            ));
        }
    }
    // rows, not hits: a label a cell writes twice is one row
    let by_row = |hits: &[(ListedEntry, usize)]| {
        let mut on: HashMap<ListedEntry, Vec<usize>> = HashMap::new();
        for (entry, line) in hits {
            let rows = on.entry(entry.clone()).or_default();
            if rows.last() != Some(line) {
                rows.push(*line);
            }
        }
        on
    };
    let met_on = by_row(met);
    let resolved_on = by_row(resolved);
    let shape_failed_on: HashSet<&ListedEntry> =
        shape_failed.iter().map(|(entry, _)| entry).collect();
    for entry in list {
        let (doc, clause, cited, label) = entry;
        let key = (
            doc.to_string(),
            clause.to_string(),
            cited.to_string(),
            label.to_string(),
        );
        let met_lines = met_on.get(&key).map_or(&[][..], Vec::as_slice);
        let resolved_lines = resolved_on.get(&key).map_or(&[][..], Vec::as_slice);
        let expected = rows_listed_in(shared, entry);
        let count_note = if met_lines.is_empty() || met_lines.len() == expected {
            String::new()
        } else {
            format!(
                "; met on {} row(s) (line(s) {}) where the list allows {}",
                met_lines.len(),
                lines(met_lines),
                expected
            )
        };
        match (met_lines.is_empty(), resolved_lines.is_empty()) {
            // carried by a row that failed the shape check: that row's own line says what to fix, and
            // the entry stays until the row's labels can be read
            (true, true) if shape_failed_on.contains(&key) => {}
            (true, true) => out.missing.push(named(entry)),
            (false, true) if !count_note.is_empty() => {
                out.miscounted
                    .push(format!("{}{}", named(entry), count_note))
            }
            (false, true) => {}
            // a label resolves or fails the same way on every row of its entry, since the key names the
            // cited test and resolution is a question of that test's source alone; so an entry never
            // both resolves and still fails, and a resolving one comes off the list
            (_, false) => out.resolving.push(format!(
                "{}: resolves on line(s) {} and comes off the list",
                named(entry),
                lines(resolved_lines)
            )),
        }
    }
    out
}

/// The code span of a table row that holds a `|` not written `\|`, as written up to that pipe, or
/// `None`: GitHub Flavored Markdown splits the cell there, so the row renders with one cell more than
/// it was written with.
fn bare_pipe_in_code_span(row: &str) -> Option<String> {
    // code spans as CommonMark reads them: a run of backticks opens a span only when a run of the same
    // length closes it later in the row (an unmatched run is literal text), a double-backtick span
    // holding a single backtick stays one span, and a backslash escapes the `|` it precedes (inside a
    // span too, as GitHub reads a table cell) and, outside a span, any ASCII punctuation after it (so
    // `\\` is an escaped backslash and a backtick after it opens a span; inside a span a backslash
    // escapes nothing else)
    let chars: Vec<char> = row.chars().collect();
    let run_at = |at: usize| chars[at..].iter().take_while(|c| **c == '`').count();
    // (the run's length, where the span's text starts)
    let mut open: Option<(usize, usize)> = None;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' if chars.get(i + 1) == Some(&'|') => i += 2,
            '\\' if open.is_none()
                && chars.get(i + 1).is_some_and(|c| c.is_ascii_punctuation()) =>
            {
                i += 2
            }
            '`' => {
                let run = run_at(i);
                match open {
                    Some((n, _)) if n == run => open = None,
                    Some(_) => {}
                    None => {
                        let mut j = i + run;
                        let closes_later = loop {
                            if j >= chars.len() {
                                break false;
                            }
                            if chars[j] == '`' {
                                let later = run_at(j);
                                if later == run {
                                    break true;
                                }
                                j += later;
                            } else {
                                j += 1;
                            }
                        };
                        if closes_later {
                            open = Some((run, i));
                        }
                    }
                }
                i += run;
            }
            '|' => {
                if let Some((_, from)) = open {
                    return Some(chars[from..=i].iter().collect());
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// The lines of every table of a document OTHER than its clause tables that hold a `|` inside a code
/// span not written `\|`: GitHub renders each as a cell boundary, so the row shows one cell more than it
/// was written with. Each is a failure line naming the document (as `shown`) and the line. A clause
/// table's rows are read by `clause_table_rows`, which refuses such a row itself.
fn bare_pipe_rows(shown: &str, text: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let mut in_clause_table = false;
    for (i, line) in text.lines().enumerate() {
        let stripped = line.trim_start().trim_start_matches('>').trim();
        if stripped == CLAUSE_TABLE_HEADER {
            in_clause_table = true;
            continue;
        }
        if !stripped.starts_with('|') {
            in_clause_table = false;
            continue;
        }
        if !in_clause_table && bare_pipe_in_code_span(stripped).is_some() {
            failures.push(format!(
                "{}:{}: a table row holds a `|` inside a code span, which GitHub renders as a cell boundary; write it `\\|`",
                shown,
                i + 1
            ));
        }
    }
    failures
}

/// The clause-table rows of one document, every line under a clause-table header read as a `ClauseRow`.
fn clause_table_rows(text: &str) -> Vec<ClauseRow> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        let stripped = line.trim_start().trim_start_matches('>').trim();
        if stripped == CLAUSE_TABLE_HEADER {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if stripped.starts_with("|---") {
            continue;
        }
        if !stripped.starts_with('|') {
            in_table = false;
            continue;
        }
        let Some(cells) = clause_table_cells(line) else {
            rows.push((number, Err("not a table row".to_string())));
            continue;
        };
        // a `|` inside a code span is a cell boundary to GitHub, whatever the count comes to: a row
        // written with five cells and one such pipe renders as six of the wrong content
        if let Some(span) = bare_pipe_in_code_span(stripped) {
            rows.push((
                number,
                Err(format!(
                    "the `|` inside the code span written {} splits the cell as GitHub renders it, so it is written `\\|`",
                    span
                )),
            ));
            continue;
        }
        if cells.len() != 6 {
            rows.push((
                number,
                Err(format!("{} cells where the header has 6", cells.len())),
            ));
            continue;
        }
        rows.push((number, Ok((cells[0].to_string(), cells[5].to_string()))));
    }
    rows
}

/// A name a document's prose cites, with the line it sits on.
type ProseCitation = (usize, String);

/// A test fn a document's prose cites: its line, the source the prose bound it to (`<source>:<fn>`, or a
/// backticked source name just before it; empty when the prose named none, so any cited source may
/// define it) and the fn name.
type ProseFn = (usize, String, String);

/// What a document's PROSE cites, outside the clause tables, each with its line number: the test fns
/// named inside a `pinned by` span (from "pinned by `" to the next `)` outside a backtick or to the next
/// "pinned by `", which opens a span of its own; before the first `;` outside a backtick every backticked
/// name is a fn name (lower-case words joined by `_`), a cited source name, `<source>:<fn>` or a
/// table-cell citation `<source>:<fn> (case ...)`, and anything else is odd, which the caller reports;
/// after that `;` the span is prose, so a name bound to a source and a fn-shaped name that is not one of
/// `GUARD_FUNCTION_NAMES` are read and other words are left alone; a wrapped line is read with the line
/// it starts on and a backtick a span never closes is odd);
/// the table-cell citations among them, read as a cell is, cases and all; and every backticked file
/// name ending in `.yaml` or `.guard` that `ILLUSTRATIVE_FILE_NAMES` does not exempt. The prose of
/// `docs/CLAUSES.md`, `docs/KNOWN_ISSUES.md` and the README names tests and fixtures the same way the
/// tables do, so a renamed test, a renamed case or a renamed fixture fails here as a table cell does.
struct ProseCitations {
    fns: Vec<ProseFn>,
    cells: Vec<ProseCitation>,
    fixtures: Vec<ProseCitation>,
    odd: Vec<ProseCitation>,
}

fn prose_citations(text: &str) -> ProseCitations {
    // a test fn name as this crate writes them: lower-case words joined by `_`
    let is_fn_name = |s: &str| {
        s.contains('_')
            && !s.starts_with('_')
            && !s.ends_with('_')
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    let is_source_name = |s: &str| CITED_TEST_SOURCES.iter().any(|(name, _)| *name == s);
    let is_file_name = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    };
    let mut cited = ProseCitations {
        fns: Vec::new(),
        cells: Vec::new(),
        fixtures: Vec::new(),
        odd: Vec::new(),
    };
    // a physical line whose code span, or whose last "pinned by" span, is still open at its end continues
    // on the next line (the documents wrap long prose; a code span and a span may cross the break), so a
    // citation wrapped onto the next line is read with the line it starts on. The spans are read as
    // CommonMark pairs backtick runs: a run opens a span when a run of the same length closes it, in the
    // line or on the very next line; a run nothing closes is literal text and joins nothing. A line
    // continues only onto prose of the same blockquote depth: a blank line, a table row, a fence, a
    // heading or a list item ends the join, a fence line and a table row never join, and a line that
    // ends a sentence closes its "pinned by" span.
    fn blockquote_depth(raw: &str) -> (usize, &str) {
        let mut rest = raw.trim_start();
        let mut depth = 0;
        while let Some(after) = rest.strip_prefix('>') {
            depth += 1;
            rest = after.trim_start();
        }
        (depth, rest)
    }
    fn is_fence_or_row(s: &str) -> bool {
        s.starts_with('|') || s.starts_with("```") || s.starts_with("~~~")
    }
    // the next line as a paragraph continuation: prose at the same blockquote depth that is not a
    // blank line, a table row, a fence, a heading or a list item
    fn plain_continuation(raw: &str, depth: usize) -> Option<&str> {
        let (d, s) = blockquote_depth(raw);
        if d != depth || s.is_empty() || is_fence_or_row(s) || s.starts_with('#') {
            return None;
        }
        if s.starts_with("- ") || s.starts_with("* ") || s.starts_with("+ ") {
            return None;
        }
        let digits = s.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && (s[digits..].starts_with(". ") || s[digits..].starts_with(") ")) {
            return None;
        }
        Some(s)
    }
    // whether each char of a line sits inside a code span closed on the line, and the length of the
    // first run no later run on the line closes (the span a wrapped line would leave open), if any
    let span_state = |chars: &[char]| -> (Vec<bool>, Option<usize>) {
        let run_at = |at: usize| chars[at..].iter().take_while(|c| **c == '`').count();
        let mut inside = vec![false; chars.len()];
        let mut i = 0;
        while i < chars.len() {
            if chars[i] != '`' {
                i += 1;
                continue;
            }
            let run = run_at(i);
            let mut j = i + run;
            let mut close = None;
            while j < chars.len() {
                if chars[j] == '`' {
                    let later = run_at(j);
                    if later == run {
                        close = Some(j);
                        break;
                    }
                    j += later;
                } else {
                    j += 1;
                }
            }
            match close {
                Some(at) => {
                    inside[i..at + run].iter_mut().for_each(|c| *c = true);
                    i = at + run;
                }
                None => {
                    inside[i..].iter_mut().for_each(|c| *c = true);
                    return (inside, Some(run));
                }
            }
        }
        (inside, None)
    };
    let has_run_of = |s: &str, run: usize| -> bool {
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '`' {
                let r = chars[i..].iter().take_while(|c| **c == '`').count();
                if r == run {
                    return true;
                }
                i += r;
            } else {
                i += 1;
            }
        }
        false
    };
    let pinned_by: Vec<char> = "pinned by `".chars().collect();
    let continues_on = |line: &str, next: &str| -> bool {
        let chars: Vec<char> = line.chars().collect();
        let (inside, open_run) = span_state(&chars);
        if let Some(run) = open_run {
            // the span closes on the next line, or the run was literal text
            return has_run_of(next, run);
        }
        let Some(at) = (0..chars.len())
            .rev()
            .find(|&k| chars[k..].starts_with(&pinned_by))
        else {
            return false;
        };
        let closed = (at + pinned_by.len()..chars.len()).any(|k| chars[k] == ')' && !inside[k]);
        !closed && !line.trim_end().ends_with(['.', ':'])
    };
    let physical: Vec<&str> = text.lines().collect();
    let mut logical: Vec<(usize, String)> = Vec::new();
    let mut i = 0;
    while i < physical.len() {
        let number = i + 1;
        let (depth, first) = blockquote_depth(physical[i]);
        let joinable = !is_fence_or_row(first);
        let mut line = physical[i].to_string();
        i += 1;
        while joinable && i < physical.len() {
            let Some(next) = plain_continuation(physical[i], depth) else {
                break;
            };
            if !continues_on(&line, next) {
                break;
            }
            line.push(' ');
            line.push_str(next);
            i += 1;
        }
        logical.push((number, line));
    }
    for (number, line) in &logical {
        let (number, line) = (*number, line.as_str());
        let stripped = line.trim_start().trim_start_matches('>').trim_start();
        if stripped.starts_with('|') {
            continue;
        }
        // every backticked file name of the line: a fixture unless the documents write it as an example
        let mut at = 0;
        while let Some(found) = line[at..].find('`') {
            let open = at + found;
            let after = &line[open + 1..];
            let Some(close) = after.find('`') else {
                break;
            };
            let name = &after[..close];
            if is_file_name(name)
                && (name.ends_with(".yaml") || name.ends_with(".guard"))
                && !ILLUSTRATIVE_FILE_NAMES.contains(&name)
            {
                cited.fixtures.push((number, name.to_string()));
            }
            at = open + 1 + close + 1;
        }
        // every `pinned by` span, to the next `)` outside a backtick or to the next "pinned by `",
        // whichever comes first: before the first `;` outside a backtick every name is a fn, a source,
        // `<source>:<fn>` or a backticked table-cell citation (anything else is odd); after it the span
        // is prose that may name a Guard function or a word (`pinned by `a`; the `match_all` spelling
        // keeps `b``), so a name bound to a source (`<source>:<fn>`, a source then its fn, a cell
        // citation) and a fn-shaped name that is not one of `GUARD_FUNCTION_NAMES` are read and the rest
        // is left alone. A second "pinned by `" written inside that
        // prose, before the `)` (`pinned by `a`; the pass carries no record, pinned by `b``), opens a
        // span of its own, strict again, so `b` is read as `a` is; the first span ends where it opens.
        let mut from = 0;
        while let Some(found) = line[from..].find("pinned by `") {
            let start = from + found + "pinned by ".len();
            let span_end = {
                let mut in_code = false;
                line[start..]
                    .char_indices()
                    .find(|(_, c)| {
                        if *c == '`' {
                            in_code = !in_code;
                        }
                        *c == ')' && !in_code
                    })
                    .map_or(line.len(), |(at, _)| start + at)
            };
            let span_end = line[start..span_end]
                .find("pinned by `")
                .map_or(span_end, |nested| start + nested);
            let span = &line[start..span_end];
            let mut strict = true;
            let mut pending_source: Option<String> = None;
            let mut span_at = 0;
            while span_at < span.len() {
                let rest = &span[span_at..];
                let next_tick = rest.find('`');
                let next_semicolon = rest.find(';');
                match (next_tick, next_semicolon) {
                    (None, _) => break,
                    (Some(tick), Some(semicolon)) if semicolon < tick => {
                        // a `;` outside any backtick ends the strict part of the span
                        strict = false;
                        pending_source = None;
                        span_at += semicolon + 1;
                        continue;
                    }
                    (Some(tick), _) => {
                        let after = &rest[tick + 1..];
                        let Some(close) = after.find('`') else {
                            // a backtick the span never closes (a code span broken across a blank line
                            // or into a table row) is reported, never passed over
                            cited.odd.push((number, format!("`{}", after)));
                            break;
                        };
                        let name = &after[..close];
                        let cell_form = name.contains(" (")
                            && name
                                .split_once(':')
                                .is_some_and(|(source, _)| is_source_name(source));
                        if cell_form {
                            // a table-cell citation in prose, cases and all, read as a cell is
                            pending_source = None;
                            cited.cells.push((number, name.to_string()));
                        } else if is_fn_name(name) {
                            match pending_source.take() {
                                Some(source) => cited.fns.push((number, source, name.to_string())),
                                // past the `;` a fn-shaped name is still a citation unless it is one
                                // of Guard's own names the prose may write there (`match_all`)
                                None if strict || !GUARD_FUNCTION_NAMES.contains(&name) => {
                                    cited.fns.push((number, String::new(), name.to_string()))
                                }
                                None => {}
                            }
                        } else if is_source_name(name) {
                            // the source named just before its fn (`tests/validate.rs`'s `fn`)
                            pending_source = Some(name.to_string());
                        } else if let Some((source, fn_name)) = name.split_once(':') {
                            pending_source = None;
                            if is_source_name(source) && is_fn_name(fn_name) {
                                cited
                                    .fns
                                    .push((number, source.to_string(), fn_name.to_string()));
                            } else if strict {
                                cited.odd.push((number, name.to_string()));
                            }
                        } else {
                            pending_source = None;
                            if strict {
                                cited.odd.push((number, name.to_string()));
                            }
                        }
                        span_at += tick + 1 + close + 1;
                    }
                }
            }
            from = span_end.max(start);
        }
    }
    cited
}

/// The failures of one document's PROSE citations, when the document is one of
/// `PROSE_CITATIONS_READ_IN` (else none): a fn named after "pinned by" that its bound source, or no cited
/// source, defines; a table-cell citation in prose that a cell would be refused for; a file name that is
/// no fixture and no listed example; an odd name in a span's strict part. Each line names the document
/// (as `shown`) and the line.
fn prose_failures(index: &Index, name: &str, shown: &str, text: &str) -> Vec<String> {
    let mut failures = Vec::new();
    if PROSE_CITATIONS_READ_IN.contains(&name) {
        let prose = prose_citations(text);
        for (number, cell) in prose.cells {
            if let Some(why) = index.unresolved_cell(&cell) {
                failures.push(format!(
                    "{}:{}: the prose cites `{}` after \"pinned by\" and {}",
                    shown, number, cell, why
                ));
            }
        }
        for (number, source, fn_name) in prose.fns {
            let defined = if source.is_empty() {
                index.sources.values().any(|s| s.fns.contains_key(&fn_name))
            } else {
                index
                    .sources
                    .get(source.as_str())
                    .is_some_and(|s| s.fns.contains_key(&fn_name))
            };
            if !defined {
                failures.push(format!(
                    "{}:{}: the prose names `{}` after \"pinned by\" and {}",
                    shown,
                    number,
                    fn_name,
                    if source.is_empty() {
                        format!("no cited test source defines `fn {}(`", fn_name)
                    } else {
                        format!("{} defines no `fn {}(`", source, fn_name)
                    }
                ));
            }
        }
        for (number, fixture) in prose.fixtures {
            if !index.fixture_files.contains(&fixture) {
                failures.push(format!(
                    "{}:{}: the prose names the file `{}` and no file of that name is under guard/resources/ (an example file is named in ILLUSTRATIVE_FILE_NAMES)",
                    shown, number, fixture
                ));
            }
        }
        for (number, odd) in prose.odd {
            failures.push(format!(
                "{}:{}: the prose names `{}` after \"pinned by\", which is no test fn name (lower-case words joined by `_`), no cited test source and no `<source>:<fn>`",
                shown, number, odd
            ));
        }
    }
    failures
}

/// Every `pinned by` cell of the clause tables in `docs/*.md` names tests that exist and cases they have
/// (the module doc states the rule). Doctored cells are refused and accepted first, so the resolver is
/// seen to refuse and to accept in the same run; then every row of every document is read, and a failure
/// names the document and the row.
#[test]
fn every_pinned_by_cell_of_the_clause_tables_names_a_test_and_a_case_it_has() {
    let crate_dir = crate_dir();
    let docs_dir = crate_dir.join("../docs");
    let documents = match fs::read_dir(&docs_dir) {
        Ok(entries) => {
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("md"))
                .collect();
            paths.sort();
            paths
        }
        Err(e) if std::env::var("GUARD_DOCS_ABSENT").as_deref() == Ok("1") => {
            eprintln!(
                "GUARD_DOCS_ABSENT=1: {} is not readable ({}); the clause tables are not checked here",
                docs_dir.display(),
                e
            );
            return;
        }
        Err(e) => panic!(
            "{} is readable (set GUARD_DOCS_ABSENT=1 for a crate packaged without docs/): {}",
            docs_dir.display(),
            e
        ),
    };
    assert!(
        documents
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("CLAUSES.md")),
        "docs/CLAUSES.md is among the documents read: {:?}",
        documents
    );
    let index = Index::build(&crate_dir);

    const REMEDY_TEST: &str = "a_bracket_wildcard_still_accepts_an_array_or_a_single_value";
    const MOVED_KEY_TEST: &str =
        "a_moved_key_filter_reading_is_a_warning_and_a_kept_one_a_deprecation";
    // Doctored cells and whether each is refused with its labels read alone too (a shape, fn or fixture
    // fault) or only once the labels are resolved (a label fault).
    let refused: Vec<(String, bool)> = vec![
        // a fn no file defines
        (
            "eval_tests.rs:a_test_fn_no_file_defines (case \"statement_is_a_single_map\")".to_string(),
            true,
        ),
        // a fn no file defines, cited by fn alone
        ("eval_tests.rs:a_test_fn_no_file_defines".to_string(), true),
        // a label no case carries
        (
            format!("eval_tests.rs:{} (case \"a label no case carries\")", REMEDY_TEST),
            false,
        ),
        // the old plural form with `and`
        (
            format!(
                "eval_tests.rs:{} (cases \"statement_is_a_list\" and \"statement_is_a_single_map\")",
                REMEDY_TEST
            ),
            true,
        ),
        // two citations, the second naming a case the fn lacks
        (
            format!(
                "eval_tests.rs:{} (case \"statement_is_a_list\"); eval_tests.rs:{} (case \"statement_is_a_tuple\")",
                REMEDY_TEST, REMEDY_TEST
            ),
            false,
        ),
        // a reworded rule body carrying braces: a plain string, matched whole, never as a template
        (
            "eval_tests.rs:a_bound_map_filter_that_left_only_undecidable_entries_says_so (case \"let m = Resources.Only\\nrule r { anything at all }\")".to_string(),
            false,
        ),
        // an unpinned marker with no citation beside it
        ("unpinned: the whole row".to_string(), true),
        // an unpinned marker that is not the last part: the citation after it would go unread
        (
            format!(
                "eval_tests.rs:{} (case \"statement_is_a_list\"); unpinned: another spelling; eval_tests.rs:a_test_fn_no_file_defines (case \"x\")",
                REMEDY_TEST
            ),
            true,
        ),
        // a raw-string document cited with one value misquoted (the source writes "beta")
        (
            format!(
                r#"eval_tests.rs:{} (case "{{\"Wanted\":\"gamma\",\"Resources\":{{\"Cfg\":{{\"Map\":{{\"Wanted\":\"alpha\",\"alpha\":1,\"beta\":2}}}}}}}}")"#,
                MOVED_KEY_TEST
            ),
            false,
        ),
        // a fixture part naming a file resources/ does not hold
        (
            "tests/validate.rs:the_wildcard_filter_fixtures_draw_the_pinned_current_verdicts (case \"type_after_star_without_a_filter.guard over two_buckets.yaml\"), fixture `no_such_fixture.guard`".to_string(),
            true,
        ),
        // a rendering of a format template whose placeholders hold text the fn never writes (the fixed
        // pieces fit; `Foo == 1` and `banana` are no case, literal or row of it)
        (
            "eval_tests.rs:a_filter_after_a_key_over_null_reads_as_absent_and_over_a_scalar_is_refused (case \"plain spelling, predicate `Foo == 1` over an entry that is `banana`\")".to_string(),
            false,
        ),
        // a bare unpinned marker that is not the last part: the citation after it would go unread
        (
            format!(
                "eval_tests.rs:{} (case \"statement_is_a_list\"); unpinned; eval_tests.rs:{}",
                REMEDY_TEST, REMEDY_TEST
            ),
            true,
        ),
        // the singular `(case ...)` with several labels: the plural form says what it holds
        (
            format!(
                "eval_tests.rs:{} (case \"statement_is_a_list\", \"statement_is_a_single_map\")",
                REMEDY_TEST
            ),
            true,
        ),
    ];
    for (cell, refused_with_labels_unread) in &refused {
        assert!(
            index.unresolved_cell(cell).is_some(),
            "the doctored cell is refused: {}",
            cell
        );
        // the labels-read-alone path (a listed row's shape check): the shape, the fn and the fixture
        // file are still checked, so a cell whose fault is one of those is refused there too, and a
        // cell whose only fault is a label passes it
        assert_eq!(
            *refused_with_labels_unread,
            index.unresolved_cell_in(cell, false).is_some(),
            "the doctored cell read with its labels unread (refused: {}): {}",
            refused_with_labels_unread,
            cell
        );
    }
    let accepted = [
        format!("eval_tests.rs:{} (case \"statement_is_a_single_map\")", REMEDY_TEST),
        format!(
            "eval_tests.rs:{} (cases \"statement_is_a_list\", \"statement_is_a_single_map\")",
            REMEDY_TEST
        ),
        format!(
            "eval_tests.rs:{} (case \"statement_is_a_list\"); tests/validate.rs:a_key_filter_over_a_member_is_refused (case \"key_over_a_member\"); unpinned: a spelling no test asserts",
            REMEDY_TEST
        ),
        // a citation by fn alone
        format!("eval_tests.rs:{}", REMEDY_TEST),
        // the rule body as written, whole
        "eval_tests.rs:a_bound_map_filter_that_left_only_undecidable_entries_says_so (case \"let m = Resources.Only\\nrule r { %m[ Tags !exists or M[ keys == Tags[ Key == 'Env' ].Value ] !empty ] empty }\")".to_string(),
        // a rendering of a format template
        "eval_tests.rs:a_filter_after_a_key_over_null_reads_as_absent_and_over_a_scalar_is_refused (case \"plain spelling, predicate `this[ Type == 'X' ]` over an entry that is `null`\")".to_string(),
        // a label holding a quote, written `\"` as a plain literal writes it
        "eval_tests.rs:an_unanswerable_clause_never_silences_the_rule_it_guards (case \"rule inner(u) { GUARD }\\nrule guarded when inner(\\\"x\\\") { BODY }\")".to_string(),
        // a raw-string document holding quotes, cited in the spelling a plain literal writes
        format!(
            r#"eval_tests.rs:{} (cases "rule r {{ Resources.Cfg.Map[ keys == to_lower(Wanted) ] == 1 }}", "{{\"Wanted\":\"beta\",\"Resources\":{{\"Cfg\":{{\"Map\":{{\"Wanted\":\"alpha\",\"alpha\":1,\"beta\":2}}}}}}}}")"#,
            MOVED_KEY_TEST
        ),
        // a fixture part naming a file under resources/
        "tests/validate.rs:the_wildcard_filter_fixtures_draw_the_pinned_current_verdicts (case \"type_after_star_without_a_filter.guard over two_buckets.yaml\"), fixture `type_after_star_without_a_filter.guard`".to_string(),
    ];
    for cell in &accepted {
        assert_eq!(
            None,
            index.unresolved_cell(cell),
            "the well-formed cell resolves: {}",
            cell
        );
    }

    // A known-unresolved label (the exemption a listed row carries) is admitted when it fails and
    // reported when it resolves after all; a label the row carries that is not listed must resolve.
    let remedy_cited = format!("eval_tests.rs:{}", REMEDY_TEST);
    let listed_fault = format!(
        "{} (cases \"statement_is_a_list\", \"a label no case carries\")",
        remedy_cited
    );
    let mut hits = Vec::new();
    assert_eq!(
        None,
        index.unresolved_cell_with(
            &listed_fault,
            true,
            &|_, _, label| label == "a label no case carries",
            &mut hits
        ),
        "a cell whose failing label is listed passes: {}",
        listed_fault
    );
    assert_eq!(
        vec![(
            remedy_cited.clone(),
            "a label no case carries".to_string(),
            true
        )],
        hits,
        "the listed label is recorded as met and still failing, with the test it is cited under"
    );
    let mut hits = Vec::new();
    assert_eq!(
        None,
        index.unresolved_cell_with(
            &listed_fault,
            true,
            &|_, _, label| label == "a label no case carries" || label == "statement_is_a_list",
            &mut hits
        ),
        "a listed label that resolves is no failure of the cell: {}",
        listed_fault
    );
    assert!(
        hits.contains(&(
            remedy_cited.clone(),
            "statement_is_a_list".to_string(),
            false
        )),
        "the listed label that resolves is recorded as resolving (it comes off the list): {:?}",
        hits
    );
    assert!(
        index
            .unresolved_cell_with(
                &listed_fault,
                true,
                &|_, _, label| label == "statement_is_a_list",
                &mut Vec::new()
            )
            .is_some(),
        "an unlisted failing label still fails the cell: {}",
        listed_fault
    );
    // the exemption names the cited test: the same label under another fn is unlisted
    assert!(
        index
            .unresolved_cell_with(
                &listed_fault,
                true,
                &|file, fn_name, label| file == "eval_tests.rs"
                    && fn_name == "another_fn"
                    && label == "a label no case carries",
                &mut Vec::new()
            )
            .is_some(),
        "a label listed under another test is unlisted for this citation: {}",
        listed_fault
    );
    // every label of the cell is read: a listed label after an unlisted failing one is still recorded
    // as met, so the report never says to drop an exemption the row still needs
    let listed_after_a_failure = format!(
        "{} (cases \"an unlisted label no case carries\", \"a label no case carries\")",
        remedy_cited
    );
    let mut hits = Vec::new();
    assert!(
        index
            .unresolved_cell_with(
                &listed_after_a_failure,
                true,
                &|_, _, label| label == "a label no case carries",
                &mut hits
            )
            .is_some_and(|why| why.contains("an unlisted label no case carries")),
        "the cell fails on its first unlisted failing label: {}",
        listed_after_a_failure
    );
    assert_eq!(
        vec![(
            remedy_cited.clone(),
            "a label no case carries".to_string(),
            true
        )],
        hits,
        "the listed label after the failure is still recorded as met"
    );
    // and so is a listed label of a LATER citation of the cell, after an earlier citation's failure
    let listed_in_a_later_citation = format!(
        "{} (case \"an unlisted label no case carries\"); {} (case \"a label no case carries\")",
        remedy_cited, remedy_cited
    );
    let mut hits = Vec::new();
    assert!(
        index
            .unresolved_cell_with(
                &listed_in_a_later_citation,
                true,
                &|_, _, label| label == "a label no case carries",
                &mut hits
            )
            .is_some_and(|why| why.contains("an unlisted label no case carries")),
        "the cell fails on the first citation's unlisted label: {}",
        listed_in_a_later_citation
    );
    assert_eq!(
        vec![(
            remedy_cited.clone(),
            "a label no case carries".to_string(),
            true
        )],
        hits,
        "the listed label of the later citation is still recorded as met"
    );

    // The row reader against a doctored table and list: an entry is met once per row that writes its
    // clause cell and carries its label still failing, so a copied row shows as a second met line; a
    // listed label the rows do not carry is met nowhere; an unlisted failing label fails its row with a
    // line that names the row's clause cell.
    let doctored_rows = format!(
        "> {}\n> |---|---|---|---|---|---|\n> | `x` | one-object | == | PASS | none | eval_tests.rs:{} (case \"a label no case carries\") |\n> | `x` | one-object | == | FAIL | none | eval_tests.rs:{} (case \"a label no case carries\") |\n> | `y` | one-object | == | PASS | none | eval_tests.rs:{} (case \"a label no case carries\") |\n",
        CLAUSE_TABLE_HEADER, REMEDY_TEST, REMEDY_TEST, REMEDY_TEST
    );
    let listed_x = (
        "KNOWN_ISSUES.md",
        "`x`",
        remedy_cited.as_str(),
        "a label no case carries",
    );
    let listed_elsewhere = (
        "KNOWN_ISSUES.md",
        "`z`",
        remedy_cited.as_str(),
        "a label no case carries",
    );
    const SHOWN_KI: &str = "docs/KNOWN_ISSUES.md";
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &doctored_rows,
        &[listed_x, listed_elsewhere],
    );
    assert_eq!(
        (3, 3),
        (reading.rows, reading.pinned),
        "three pinned rows were read"
    );
    let key_x = (
        listed_x.0.to_string(),
        listed_x.1.to_string(),
        listed_x.2.to_string(),
        listed_x.3.to_string(),
    );
    assert_eq!(
        vec![(key_x.clone(), 3), (key_x, 4)],
        reading.met,
        "the entry for clause `x` is met on both rows that write it, by line"
    );
    assert!(
        reading.resolved.is_empty(),
        "no listed label resolved: {:?}",
        reading.resolved
    );
    assert_eq!(
        1,
        reading.unresolved.len(),
        "the row whose clause cell is listed nowhere fails on its label: {:?}",
        reading.unresolved
    );
    assert!(
        reading.unresolved[0].starts_with("docs/KNOWN_ISSUES.md:5: ")
            && reading.unresolved[0].ends_with("(the row's clause cell is `y`)"),
        "the failing row's line names its line number and its clause cell: {:?}",
        reading.unresolved
    );
    let (shared_doc, shared_clause, shared_cited, shared_label, shared_rows) =
        SHARED_UNRESOLVED_ENTRIES[0];
    assert_eq!(
        (1, shared_rows),
        (
            rows_listed_for(&listed_x),
            rows_listed_for(&(shared_doc, shared_clause, shared_cited, shared_label))
        ),
        "an entry is listed for one row unless SHARED_UNRESOLVED_ENTRIES counts it"
    );
    // a shared count binds on all four fields: a twin that differs in exactly one of them is listed
    // for one row, so a lookup matching on fewer fields than the key would read 2 for one of these
    let twins = [
        ("CLAUSES.md", shared_clause, shared_cited, shared_label),
        (shared_doc, "`another clause`", shared_cited, shared_label),
        (
            shared_doc,
            shared_clause,
            "eval_tests.rs:another_fn",
            shared_label,
        ),
        (shared_doc, shared_clause, shared_cited, "another label"),
    ];
    for twin in &twins {
        assert_eq!(
            1,
            rows_listed_for(twin),
            "a twin of a shared entry that differs in one key field is listed for one row: {:?}",
            twin
        );
    }
    // a row that fails the shape check (a fn no source defines) carrying a listed cited test and label:
    // the row is reported for its shape, its entry is recorded as carried by a shape-failed row, neither
    // met nor missing, and the classifier does not say to drop the exemption
    let shape_failed_row = format!(
        "> {}\n> |---|---|---|---|---|---|\n> | `w` | one-object | == | PASS | none | eval_tests.rs:no_such_test_fn_anywhere (case \"a label no case carries\") |\n",
        CLAUSE_TABLE_HEADER
    );
    let listed_w = (
        "KNOWN_ISSUES.md",
        "`w`",
        "eval_tests.rs:no_such_test_fn_anywhere",
        "a label no case carries",
    );
    let shape_reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &shape_failed_row,
        &[listed_w],
    );
    let key_w = (
        listed_w.0.to_string(),
        listed_w.1.to_string(),
        listed_w.2.to_string(),
        listed_w.3.to_string(),
    );
    assert_eq!(
        (1, vec![(key_w, 3)], 0),
        (
            shape_reading.unresolved.len(),
            shape_reading.shape_failed.clone(),
            shape_reading.met.len()
        ),
        "the shape-failed row is reported once, its entry recorded as carried by it and not met: {:?}",
        shape_reading.unresolved
    );
    let classified = classify(
        &shape_reading.met,
        &shape_reading.resolved,
        &shape_reading.shape_failed,
        &[listed_w],
        &[],
    );
    assert!(
        classified.missing.is_empty(),
        "an entry carried only by a shape-failed row is not reported as missing: {:?}",
        classified.missing
    );

    // The classifier on the doctored reading: the entry met on two rows where the list allows one is
    // miscounted (a copied row inherits no exemption), the entry no row writes is missing; with the
    // entry listed as shared for two rows nothing is miscounted; a list that repeats an entry, and a
    // shared entry that is not listed or counts one row, are reported, not met.
    let classified = classify(
        &reading.met,
        &reading.resolved,
        &reading.shape_failed,
        &[listed_x, listed_elsewhere],
        &[],
    );
    assert_eq!(
        (1, 1, 0, 0, 0),
        (
            classified.miscounted.len(),
            classified.missing.len(),
            classified.resolving.len(),
            classified.duplicated.len(),
            classified.shared_faults.len()
        ),
        "one miscounted and one missing entry: {:?} {:?}",
        classified.miscounted,
        classified.missing
    );
    assert!(
        classified.miscounted[0].contains("met on 2 row(s) (line(s) 3, 4) where the list allows 1")
            && classified.miscounted[0].contains("citing eval_tests.rs:"),
        "the miscount names the rows, the allowance and the cited test: {:?}",
        classified.miscounted
    );
    assert!(
        classified.missing[0].contains("`z`"),
        "the missing entry is the one no row writes: {:?}",
        classified.missing
    );
    let shared_x = (listed_x.0, listed_x.1, listed_x.2, listed_x.3, 2usize);
    let classified = classify(
        &reading.met,
        &reading.resolved,
        &reading.shape_failed,
        &[listed_x],
        &[shared_x],
    );
    assert!(
        classified.miscounted.is_empty() && classified.missing.is_empty(),
        "the entry listed as shared for two rows is met as listed: {:?} {:?}",
        classified.miscounted,
        classified.missing
    );
    let classified = classify(
        &reading.met,
        &reading.resolved,
        &reading.shape_failed,
        &[listed_x, listed_x],
        &[
            (
                listed_elsewhere.0,
                listed_elsewhere.1,
                listed_elsewhere.2,
                listed_elsewhere.3,
                2,
            ),
            (listed_x.0, listed_x.1, listed_x.2, listed_x.3, 1),
        ],
    );
    assert_eq!(
        (1, 2),
        (classified.duplicated.len(), classified.shared_faults.len()),
        "a repeated entry and two faulty shared entries are reported: {:?} {:?}",
        classified.duplicated,
        classified.shared_faults
    );

    // The prose reader: a fn name after "pinned by" (bound to the source named just before it, or in
    // `<source>:<fn>`, or to none), a table-cell citation, every file-shaped `.yaml`/`.guard` name that is
    // not an allowlisted example, and the odd names of a span's strict part; past a `;` outside a backtick
    // a source-bound name and a fn-shaped name are still read (`a_fourth_fn`) while one of Guard's own
    // names (`match_all`) and a plain word are prose; a `)` inside a backtick does not end the span; a
    // sentence that ends in `.yaml` and a table row are not read.
    let prose = prose_citations(
        &format!(
            "An example `security_groups.guard` sits in a line (pinned by `no_such_test_fn` and `tests/validate.rs`'s `another_missing_fn`; the `NOT IN` gate keeps its wording under `match_all`, `a_fourth_fn` and `eval_tests.rs:a_bound_tail_fn`) that names `no_such.yaml`, the illustrative `rules.guard` and the trailer example (`and 195 more, not t60.yaml`) (pinned by `IN`, `eval_tests.rs:{} (cases \"statement_is_a_list\", \"a label no case carries\")` and `eval_tests.rs:a_third_fn`).\n| a | table | row | is | not | read (pinned by `skipped_fn`) |\n",
            REMEDY_TEST
        ),
    );
    assert_eq!(
        vec![
            (1, String::new(), "no_such_test_fn".to_string()),
            (
                1,
                "tests/validate.rs".to_string(),
                "another_missing_fn".to_string()
            ),
            (1, String::new(), "a_fourth_fn".to_string()),
            (1, "eval_tests.rs".to_string(), "a_bound_tail_fn".to_string()),
            (1, "eval_tests.rs".to_string(), "a_third_fn".to_string()),
        ],
        prose.fns,
        "the fn names of the prose spans with the sources bound to them; past the `;` the source-bound one and the fn-shaped word, not Guard's `match_all`; the table row skipped"
    );
    assert_eq!(
        vec![(
            1,
            format!(
                "eval_tests.rs:{} (cases \"statement_is_a_list\", \"a label no case carries\")",
                REMEDY_TEST
            )
        )],
        prose.cells,
        "a table-cell citation in prose is read whole, the `)` inside its backticks ending no span"
    );
    assert_eq!(
        vec![
            (1, "no_such.yaml".to_string()),
            (1, "rules.guard".to_string())
        ],
        prose.fixtures,
        "every file-shaped name that is not an allowlisted example"
    );
    assert_eq!(
        vec![(1, "IN".to_string())],
        prose.odd,
        "a backticked name in a span's strict part that is no fn, source or source:fn (`NOT IN` sits past the `;`)"
    );
    // the failures of that prose against the real index: the first cell citation names a case the fn
    // lacks, the fn-shaped word and the bound fn past the `;` are undefined (three failures); the cell
    // citation with real cases and the Guard function past the `;` draw nothing
    let prose_text = format!(
        "A line (pinned by `eval_tests.rs:{} (cases \"statement_is_a_list\", \"statement_is_a_single_map\")`; the `match_all` spelling keeps `a_fourth_fn`) and another (pinned by `eval_tests.rs:{} (case \"a label no case carries\")`; `eval_tests.rs:a_bound_tail_fn`).\n",
        REMEDY_TEST, REMEDY_TEST
    );
    let failures = prose_failures(&index, "README.md", "README.md", &prose_text);
    assert_eq!(
        3,
        failures.len(),
        "the cell citation with a case the fn lacks, the fn-shaped word past the `;` and the bound undefined fn fail; the good cell citation and `match_all` do not: {:?}",
        failures
    );
    assert!(
        failures[0].starts_with("README.md:1: the prose cites `eval_tests.rs:")
            && failures[0].contains("a label no case carries")
            && failures[1].contains("`a_fourth_fn`")
            && failures[1].contains("no cited test source defines `fn a_fourth_fn(`")
            && failures[2].contains("`a_bound_tail_fn`")
            && failures[2].contains("eval_tests.rs defines no `fn a_bound_tail_fn(`"),
        "each failure names the document, the line and the citation: {:?}",
        failures
    );
    // A second "pinned by" written inside an earlier span, before its `)`, is a strict span of its own,
    // so an unbound name there is checked (a CLAUSES membership row has this shape); read as the first
    // span's relaxed tail it would have been prose and a renamed test would have passed unnoticed.
    let nested = prose_citations(
        "A line (pinned by `first_span_fn`; the passing clause carries no failing child record, pinned by `second_span_fn`).\n",
    );
    assert_eq!(
        vec![
            (1, String::new(), "first_span_fn".to_string()),
            (1, String::new(), "second_span_fn".to_string()),
        ],
        nested.fns,
        "the fn of a second \"pinned by\" inside the first span's `)` is read unbound, as the first one is"
    );
    // and the second span is STRICT: a Guard word there is odd, where the first span's relaxed tail
    // would have let it pass (so this control tells a span of its own from a longer relaxed tail)
    let nested_guard_word = prose_citations(
        "A line (pinned by `first_span_fn`; the `match_all` spelling keeps it, pinned by `IN`).\n",
    );
    assert_eq!(
        vec![(1, "IN".to_string())],
        nested_guard_word.odd,
        "a Guard word in a second span is odd, as in any strict part; `match_all` in the first span's tail is not"
    );
    let nested_text = format!(
        "A line (pinned by `eval_tests.rs:{}`; the passing clause carries no failing child record, pinned by `a_second_span_fn_no_source_defines`).\n",
        REMEDY_TEST
    );
    let failures = prose_failures(&index, "README.md", "README.md", &nested_text);
    assert!(
        failures.len() == 1
            && failures[0].contains("`a_second_span_fn_no_source_defines`")
            && failures[0]
                .contains("no cited test source defines `fn a_second_span_fn_no_source_defines(`"),
        "the undefined fn of the second span is red by itself: {:?}",
        failures
    );
    let nested_text = format!(
        "A line (pinned by `eval_tests.rs:{}`; the passing clause carries no failing child record, pinned by `{}`).\n",
        REMEDY_TEST, REMEDY_TEST
    );
    assert_eq!(
        Vec::<String>::new(),
        prose_failures(&index, "README.md", "README.md", &nested_text),
        "the same line with a defined fn in the second span is green"
    );
    // A citation wrapped onto the next line is read with the line it starts on: a cell citation whose
    // code span crosses the break and names an undefined fn is red, the same naming a defined fn and a
    // case it has is green, and a span whose names sit on both sides of the break reads them all; a
    // code span a blank line leaves unclosed is odd, never passed over.
    let wrapped_text = "A line (pinned by `eval_tests.rs:a_wrapped_undefined_fn (case\n\"statement_is_a_list\")`).\n";
    let failures = prose_failures(&index, "README.md", "README.md", wrapped_text);
    assert!(
        failures.len() == 1
            && failures[0].starts_with("README.md:1: ")
            && failures[0].contains("a_wrapped_undefined_fn"),
        "a cell citation wrapped onto the next line is read, and red when its fn is undefined: {:?}",
        failures
    );
    let wrapped_text = format!(
        "A line (pinned by `eval_tests.rs:{} (case\n\"statement_is_a_list\")`).\n",
        REMEDY_TEST
    );
    assert_eq!(
        Vec::<String>::new(),
        prose_failures(&index, "README.md", "README.md", &wrapped_text),
        "the same wrapped citation naming a defined fn and its case is green"
    );
    let across = prose_citations(
        "> A line (pinned by `first_wrapped_fn` and\n> `second_wrapped_fn`), then prose.\n",
    );
    assert_eq!(
        vec![
            (1, String::new(), "first_wrapped_fn".to_string()),
            (1, String::new(), "second_wrapped_fn".to_string()),
        ],
        across.fns,
        "a span open at a line's end continues on the next line of the same blockquote depth, the marker dropped, both names on line 1"
    );
    let unclosed = prose_citations("A line (pinned by `never_closed\n\nA new paragraph.\n");
    assert_eq!(
        vec![(1, "`never_closed".to_string())],
        unclosed.odd,
        "a backtick a span never closes before a blank line is odd"
    );
    // The join follows CommonMark's pairing, not backtick parity: a run that no run of the same length
    // closes, on its line or on the next, is literal text and joins nothing, so the fixture named on the
    // next line is read on its own line. A double run says so for an even count; a triple run says so for
    // an odd one, where a join by parity would have run the two lines together, re-paired every backtick
    // after the run and passed the fixture's name over. A fence line never joins, so prose after a fenced
    // block keeps its line; a list item, a heading and a blockquote-depth change end a join too.
    let stray = prose_citations(
        "a stray `` run sits here\nthe fixture `stray_backtick_fixture.yaml` is named on the next line.\n",
    );
    assert_eq!(
        vec![(2, "stray_backtick_fixture.yaml".to_string())],
        stray.fixtures,
        "a stray double run joins nothing, and the fixture on the next line is read on line 2"
    );
    let odd_run = prose_citations(
        "a stray ``` run sits here\nthe fixture `odd_run_fixture.yaml` is named on the next line.\n",
    );
    assert_eq!(
        vec![(2, "odd_run_fixture.yaml".to_string())],
        odd_run.fixtures,
        "a stray triple run joins nothing either, where a join by parity would have passed the fixture over"
    );
    let fenced = prose_citations(
        "```\nlet x = `inside_the_fence.guard`\n```\nA `fenced_after_fixture.yaml` follows the block.\n",
    );
    assert_eq!(
        vec![
            (2, "inside_the_fence.guard".to_string()),
            (4, "fenced_after_fixture.yaml".to_string()),
        ],
        fenced.fixtures,
        "a fence line joins nothing, so each name keeps its own line"
    );
    let blocks = prose_citations(
        "A line (pinned by `before_a_list_fn` and\n- a list item naming `in_a_list_fixture.yaml`\n> quoted (pinned by `quoted_fn` and\nunquoted `after_the_quote.yaml`\n",
    );
    assert_eq!(
        vec![
            (1, String::new(), "before_a_list_fn".to_string()),
            (3, String::new(), "quoted_fn".to_string()),
        ],
        blocks.fns,
        "an open span does not continue onto a list item or across a blockquote-depth change"
    );
    assert_eq!(
        vec![
            (2, "in_a_list_fixture.yaml".to_string()),
            (4, "after_the_quote.yaml".to_string()),
        ],
        blocks.fixtures,
        "the names on the lines that were not joined keep their own line numbers"
    );
    let heading = prose_citations(
        "A line (pinned by `fn_before_a_heading` and\n## A heading naming `heading_fixture.yaml`\n",
    );
    assert_eq!(
        (
            vec![(1, String::new(), "fn_before_a_heading".to_string())],
            vec![(2, "heading_fixture.yaml".to_string())]
        ),
        (heading.fns, heading.fixtures),
        "an open span does not continue onto a heading, which keeps its own line"
    );

    // A raw literal written with `\r\n` line breaks (a checkout that rewrote them) reads as the `\n` the
    // compiler reads, and so does a plain literal that spans source lines: both are cited in the escape
    // spelling, which is what a one-line table cell can write. A plain literal continued with a `\` at
    // the end of a source line reads as the compiler reads it, the break and the next line's leading
    // blanks dropped, while a spelled `\\` or `\"` is kept as spelled.
    let crlf = index_source_text(
        "fn reads_both() { let _ = r#\"first\r\nsecond\"#; let _ = \"third\r\nfourth\"; let _ = \"fifth\tsixth\"; let _ = \"seventh \\\n        eighth\"; let _ = \"ninth \\\\ \\\"tenth\\\"\"; }",
        "the line-ending control",
    );
    let crlf_index = Index {
        sources: HashMap::from([("eval_tests.rs", crlf)]),
        fixture_rows: HashMap::new(),
        fixture_files: HashSet::new(),
    };
    for label in [
        "first\\nsecond",
        "third\\nfourth",
        "fifth\\tsixth",
        "seventh eighth",
        "ninth \\\\ \\\"tenth\\\"",
    ] {
        assert_eq!(
            None,
            crlf_index.unresolved_label("eval_tests.rs", "reads_both", label),
            "a literal written across lines, or holding a raw tab, resolves by its escape spelling: {:?}",
            label
        );
    }

    // A placeholder stands for a carried string that is not empty: a fn that carries `""` does not make
    // the template minus its placeholder a rendering, where a carried `x` does. The control's template
    // carries twenty-one characters of its own text, well over the twelve `template_pieces` admits at
    // the least, so its refusal is the fill's and not the floor's; the floor itself is pinned below at
    // exactly twelve (admitted) and eleven (refused) characters of fixed text.
    let empty_fill = index_source_text(
        "fn writes_a_frame() { let _ = \"\"; let _ = \"x\"; \
         panic!(\"left side {} right side\", 1); panic!(\"left {} right\", 1); }",
        "the empty-fill control",
    );
    let empty_fill_index = Index {
        sources: HashMap::from([("eval_tests.rs", empty_fill)]),
        fixture_rows: HashMap::new(),
        fixture_files: HashSet::new(),
    };
    assert_eq!(
        None,
        empty_fill_index.unresolved_label(
            "eval_tests.rs",
            "writes_a_frame",
            "left side x right side"
        ),
        "a carried non-empty fill renders the template"
    );
    assert!(
        empty_fill_index
            .unresolved_label("eval_tests.rs", "writes_a_frame", "left side  right side")
            .is_some(),
        "an empty fill is refused although the fn carries the empty string"
    );
    assert!(
        empty_fill_index
            .unresolved_label("eval_tests.rs", "writes_a_frame", "left x right")
            .is_some(),
        "a template with under twelve characters of its own text renders no label"
    );
    // the floor at its exact edge: `left {} rights` carries twelve characters of fixed text and is a
    // template, `left {} right` eleven and is none
    assert_eq!(
        Some(vec!["left ".to_string(), " rights".to_string()]),
        template_pieces("left {} rights"),
        "twelve characters of fixed text, the floor, make a template"
    );
    assert_eq!(
        None,
        template_pieces("left {} right"),
        "eleven characters of fixed text, one under the floor, make no template"
    );
    assert!(
        template_pieces("left side {} right side").is_some(),
        "the control's twenty-one-character template is admitted"
    );

    // The row reader against a one-row doctored table and list: a listed label the row carries and that
    // fails is met; a listed label the row does not carry is met nowhere (the report then names it); a
    // listed label that resolves is recorded as resolving on its line; an unlisted failing label fails
    // the row, and so does a failing label listed under another row's clause cell.
    let doctored_table = format!(
        "> {}\n> |---|---|---|---|---|---|\n> | `x` | one-object | == | PASS | none | eval_tests.rs:{} (cases \"statement_is_a_list\", \"a label no case carries\") |\n",
        CLAUSE_TABLE_HEADER, REMEDY_TEST
    );
    let as_entry = |(doc, clause, cited, label): ListedKey| -> ListedEntry {
        (
            doc.to_string(),
            clause.to_string(),
            cited.to_string(),
            label.to_string(),
        )
    };
    let cited = remedy_cited.as_str();
    let carried = ("KNOWN_ISSUES.md", "`x`", cited, "a label no case carries");
    let not_carried = (
        "KNOWN_ISSUES.md",
        "`x`",
        cited,
        "a label the row does not carry",
    );
    let resolving = ("KNOWN_ISSUES.md", "`x`", cited, "statement_is_a_list");
    let other_clause = ("KNOWN_ISSUES.md", "`y`", cited, "a label no case carries");
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &doctored_table,
        &[carried, not_carried],
    );
    assert_eq!(1, reading.rows, "the doctored table holds one row");
    assert!(
        reading.unresolved.is_empty(),
        "the row passes with its failing label listed: {:?}",
        reading.unresolved
    );
    assert_eq!(
        vec![(as_entry(carried), 3)],
        reading.met,
        "the listed label the row carries and that fails is met on the row's line, and the listed label the row does not carry is met nowhere"
    );
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &doctored_table,
        &[carried, resolving],
    );
    assert_eq!(
        vec![(as_entry(resolving), 3)],
        reading.resolved,
        "a listed label that resolves is recorded as resolving on its line"
    );
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &doctored_table,
        &[resolving],
    );
    assert_eq!(
        1,
        reading.unresolved.len(),
        "the unlisted failing label fails the row: {:?}",
        reading.unresolved
    );
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &doctored_table,
        &[other_clause],
    );
    assert_eq!(
        1,
        reading.unresolved.len(),
        "a failing label listed under another row's clause cell is unlisted for this row: {:?}",
        reading.unresolved
    );
    assert!(
        reading.met.is_empty(),
        "an entry whose clause cell no row writes is met nowhere: {:?}",
        reading.met
    );
    // the document is part of the key: the same table read as another document matches no entry
    let reading = read_rows(
        &index,
        "CLAUSES.md",
        "docs/CLAUSES.md",
        &doctored_table,
        &[carried],
    );
    assert!(
        reading.met.is_empty() && reading.unresolved.len() == 1,
        "an entry of one document exempts no row of another: {:?} {:?}",
        reading.met,
        reading.unresolved
    );

    // A `|` inside a code span splits the row's cells as GitHub Flavored Markdown splits them, so such
    // a row is refused whatever the count comes to: written with six cells it reads as seven, and
    // written with five it reads as six of the wrong content; `\|` is the spelling.
    let bare_pipe_table = format!(
        "> {}\n> |---|---|---|---|---|---|\n> | `[ x | y ]` | one-object | == | PASS | none | eval_tests.rs:{} |\n",
        CLAUSE_TABLE_HEADER, REMEDY_TEST
    );
    let reading = read_rows(&index, "KNOWN_ISSUES.md", SHOWN_KI, &bare_pipe_table, &[]);
    assert_eq!(
        1,
        reading.unresolved.len(),
        "a row with a bare `|` inside a code span is refused: {:?}",
        reading.unresolved
    );
    assert!(
        reading.unresolved[0].starts_with("docs/KNOWN_ISSUES.md:3: ")
            && reading.unresolved[0].contains("inside the code span written `[ x |"),
        "the report names the bare pipe and the span it sits in, as written up to the pipe: {:?}",
        reading.unresolved
    );
    let five_cell_table = format!(
        "> {}\n> |---|---|---|---|---|---|\n> | `[ x | y ]` | == | PASS | none | eval_tests.rs:{} |\n",
        CLAUSE_TABLE_HEADER, REMEDY_TEST
    );
    let reading = read_rows(&index, "KNOWN_ISSUES.md", SHOWN_KI, &five_cell_table, &[]);
    assert!(
        reading.unresolved.len() == 1
            && reading.unresolved[0].contains("inside the code span written `[ x |")
            && reading.met.is_empty(),
        "a row written with five cells and a bare pipe is refused, not read as six cells: {:?}",
        reading.unresolved
    );
    let double_tick_table = bare_pipe_table.replace("`[ x | y ]`", "`` [ `x` | y ] ``");
    let reading = read_rows(&index, "KNOWN_ISSUES.md", SHOWN_KI, &double_tick_table, &[]);
    assert!(
        reading.unresolved.len() == 1
            && reading.unresolved[0].contains("inside the code span written `` [ `x` |"),
        "a bare pipe inside a double-backtick code span is read as inside the span, named up to the pipe: {:?}",
        reading.unresolved
    );
    // CommonMark: a backtick run no run of the same length closes is literal text and opens no span, so
    // a lone double run before a `|` leaves the cell boundary a cell boundary; a backslash inside a
    // span escapes no backtick, so `` `C:\` `` is a closed span and the `|` after it a cell boundary;
    // both rows read as six plain cells. `\|` is an escaped pipe inside a span, and a bare one is named
    // with its span as written up to it.
    let unmatched_run_table = bare_pipe_table.replace("`[ x | y ]`", "a``b");
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &unmatched_run_table,
        &[],
    );
    assert!(
        reading.unresolved.is_empty() && reading.met.is_empty(),
        "an unmatched backtick run is literal text and opens no span: {:?}",
        reading.unresolved
    );
    let backslash_table = bare_pipe_table.replace("`[ x | y ]`", "`C:\\`");
    let reading = read_rows(&index, "KNOWN_ISSUES.md", SHOWN_KI, &backslash_table, &[]);
    assert!(
        reading.unresolved.is_empty() && reading.met.is_empty(),
        "a backslash inside a span escapes no backtick, so the span closes before the cell boundary: {:?}",
        reading.unresolved
    );
    assert_eq!(
        None,
        bare_pipe_in_code_span("| `a \\| b` | c |"),
        "`\\|` inside a span is an escaped pipe"
    );
    assert_eq!(
        None,
        bare_pipe_in_code_span("| \\`a | b` | c |"),
        "a backslash-escaped backtick outside a span opens none, so the lone backtick after it is literal and the `|` between them a cell boundary"
    );
    assert_eq!(
        Some("`a |".to_string()),
        bare_pipe_in_code_span("| \\\\`a | b` | c |"),
        "`\\\\` is an escaped backslash, so the backtick after it is not escaped and opens the span that holds the bare pipe"
    );
    assert_eq!(
        Some("`a |".to_string()),
        bare_pipe_in_code_span("| `a | b` | c |"),
        "a bare pipe is named with its span as written up to it"
    );
    let escaped_pipe_table = bare_pipe_table.replace("`[ x | y ]`", "`[ x \\| y ]`");
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &escaped_pipe_table,
        &[],
    );
    assert!(
        reading.unresolved.is_empty() && reading.rows == 1,
        "the same row with the pipe written `\\|` is a six-cell row: {:?}",
        reading.unresolved
    );
    // the same rule over every other table: a three-column table whose row holds a bare pipe in a
    // code span is named by line; the escaped one, the prose around it and a clause table's rows (the
    // clause reader refuses those itself) are not
    let other_table = format!(
        "> | Clause | Reading | Result |\n> |---|---|---|\n> | `Resources[ b | ... ]` | a capture | names |\n> | `Resources[ b \\| ... ]` | a capture | names |\nA sentence with `a | b` outside any table.\n{}",
        bare_pipe_table
    );
    assert_eq!(
        vec![
            "docs/CLAUSES.md:3: a table row holds a `|` inside a code span, which GitHub renders as a cell boundary; write it `\\|`".to_string()
        ],
        bare_pipe_rows("docs/CLAUSES.md", &other_table),
        "the one row of a non-clause table with a bare pipe in a code span is named; the escaped row, the prose and the clause table's row are not"
    );

    // A listed label a cell cites twice for one test is named as a repeat; the row still counts once.
    let twice_table = format!(
        "> {}\n> |---|---|---|---|---|---|\n> | `x` | one-object | == | PASS | none | eval_tests.rs:{} (case \"a label no case carries\"); eval_tests.rs:{} (case \"a label no case carries\") |\n",
        CLAUSE_TABLE_HEADER, REMEDY_TEST, REMEDY_TEST
    );
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &twice_table,
        &[carried],
    );
    assert!(
        reading.unresolved.len() == 1
            && reading.unresolved[0].contains("twice")
            && reading.unresolved[0].ends_with("(the row's clause cell is `x`)"),
        "the repeated citation is named once: {:?}",
        reading.unresolved
    );
    assert_eq!(
        vec![(as_entry(carried), 3), (as_entry(carried), 3)],
        reading.met,
        "both citations are met on the row's line"
    );
    // and the classifier counts them as the one row the entry is listed for: nothing is miscounted,
    // missing or resolving
    let classified = classify(
        &reading.met,
        &reading.resolved,
        &reading.shape_failed,
        &[carried],
        &[],
    );
    assert_eq!(
        (0, 0, 0),
        (
            classified.miscounted.len(),
            classified.missing.len(),
            classified.resolving.len()
        ),
        "a label a cell writes twice is one row to the classifier: {:?} {:?} {:?}",
        classified.miscounted,
        classified.missing,
        classified.resolving
    );

    // The classifier's resolving arm: an entry whose label resolves on its row comes off the list, with
    // the line named; with the key naming the cited test, an entry resolves or fails alike on every row.
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
        SHOWN_KI,
        &doctored_table,
        &[resolving],
    );
    let classified = classify(
        &reading.met,
        &reading.resolved,
        &reading.shape_failed,
        &[resolving],
        &[],
    );
    assert_eq!(
        (1, 0, 0),
        (
            classified.resolving.len(),
            classified.missing.len(),
            classified.miscounted.len()
        ),
        "the resolving entry is reported once and nowhere else: {:?}",
        classified
            .resolving
            .iter()
            .chain(&classified.missing)
            .collect::<Vec<_>>()
    );
    assert!(
        classified.resolving[0].ends_with(": resolves on line(s) 3 and comes off the list")
            && classified.resolving[0].contains("`x`"),
        "the resolving line names the row's line and the entry: {:?}",
        classified.resolving
    );

    // A `const` declared inside a fn body is that fn's own: a fn reads its own, never a sibling's, and a
    // module-level item of the same name is shadowed by it. Read on a source written here, so the
    // control does not depend on which items the real sources happen to declare.
    let shadowing = index_source_text(
        r#"
        mod rows {
            const CASES: &str = "the module's row";
            fn reads_its_own() { const CASES: &str = "the first fn's row"; let _ = CASES; }
            fn reads_its_own_too() { const CASES: &str = "the second fn's row"; let _ = CASES; }
            fn reads_the_modules() { let _ = CASES; }
        }
        "#,
        "the shadowing control",
    );
    let shadowing_index = Index {
        sources: HashMap::from([("eval_tests.rs", shadowing)]),
        fixture_rows: HashMap::new(),
        fixture_files: HashSet::new(),
    };
    for (fn_name, label, resolves) in [
        ("reads_its_own", "the first fn's row", true),
        ("reads_its_own", "the second fn's row", false),
        ("reads_its_own", "the module's row", false),
        ("reads_its_own_too", "the second fn's row", true),
        ("reads_the_modules", "the module's row", true),
        ("reads_the_modules", "the first fn's row", false),
    ] {
        assert_eq!(
            resolves,
            shadowing_index
                .unresolved_label("eval_tests.rs", fn_name, label)
                .is_none(),
            "a row table resolves for the fn that declares or sees it alone: {} reads `{}`",
            fn_name,
            label
        );
    }

    // (rows, pinned rows) read per document, held against `TABLE_FLOORS` once every document is read
    let mut counts: HashMap<String, (usize, usize)> = HashMap::new();
    let mut unresolved = Vec::new();
    // listed labels that resolve after all (they come off `KNOWN_UNRESOLVED_LABELS`), and the listed
    // labels met on their rows and still failing (a listed label not met is reported by name)
    let mut met: Vec<(ListedEntry, usize)> = Vec::new();
    let mut resolved: Vec<(ListedEntry, usize)> = Vec::new();
    let mut shape_failed: Vec<(ListedEntry, usize)> = Vec::new();
    // the README sits beside the repository root, not under docs/: its prose is read, it has no tables
    let mut read: Vec<(String, PathBuf)> = documents
        .iter()
        .map(|p| {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            (name, p.clone())
        })
        .collect();
    read.push(("README.md".to_string(), crate_dir.join("../README.md")));
    for (name, path) in &read {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("the document {} is readable: {}", path.display(), e));
        let shown = shown_path(name);
        unresolved.extend(prose_failures(&index, name, &shown, &text));
        unresolved.extend(bare_pipe_rows(&shown, &text));
        let reading = read_rows(&index, name, &shown, &text, &KNOWN_UNRESOLVED_LABELS);
        counts.insert(name.clone(), (reading.rows, reading.pinned));
        unresolved.extend(reading.unresolved);
        met.extend(reading.met);
        resolved.extend(reading.resolved);
        shape_failed.extend(reading.shape_failed);
    }
    // each document's tables were read, not one document's standing in for the others'
    for (name, rows_floor, pinned_floor) in TABLE_FLOORS {
        let (rows, pinned) = counts.get(name).copied().unwrap_or_default();
        assert!(
            rows >= rows_floor && pinned >= pinned_floor,
            "the clause tables of {} were read: {} rows where at least {} are expected, {} of them pinned where at least {} are expected",
            shown_path(name),
            rows,
            rows_floor,
            pinned,
            pinned_floor
        );
    }
    // One report for every way the tables, KNOWN_UNRESOLVED_LABELS and SHARED_UNRESOLVED_ENTRIES can
    // disagree, so a change that moves, copies, re-pins or re-lists a row reads what to remove and what
    // to add in one message.
    let Classified {
        missing,
        miscounted,
        resolving,
        duplicated,
        shared_faults,
    } = classify(
        &met,
        &resolved,
        &shape_failed,
        &KNOWN_UNRESOLVED_LABELS,
        &SHARED_UNRESOLVED_ENTRIES,
    );
    let mut report = Vec::new();
    if !duplicated.is_empty() {
        report.push(format!(
            "these entries KNOWN_UNRESOLVED_LABELS writes twice (the list is a set; drop the repeat):\n{}",
            duplicated.join("\n")
        ));
    }
    if !shared_faults.is_empty() {
        report.push(format!(
            "these SHARED_UNRESOLVED_ENTRIES do not name a listed entry met on two or more rows:\n{}",
            shared_faults.join("\n")
        ));
    }
    if !missing.is_empty() {
        report.push(format!(
            "these entries of KNOWN_UNRESOLVED_LABELS were not met as a failing label of a well-formed clause-table row that writes their clause cell and cites their test, and come off the list (a row whose clause cell was reworded, or whose test was renamed and is re-cited, is re-listed with the new text, which is among the rows to add below when its label still fails, each line naming the row's clause cell; a row that is malformed or resolves is listed below or above):\n{}",
            missing.join("\n")
        ));
    }
    if !miscounted.is_empty() {
        report.push(format!(
            "these entries of KNOWN_UNRESOLVED_LABELS were met on a different number of rows than they are listed for (one row, or the count SHARED_UNRESOLVED_ENTRIES gives): a row copied or re-cited with a listed clause cell and label inherits no exemption until the entry's count says so, and a twin row that is gone brings the count down:\n{}",
            miscounted.join("\n")
        ));
    }
    if !resolving.is_empty() {
        report.push(format!(
            "these labels of KNOWN_UNRESOLVED_LABELS resolve now:\n{}",
            resolving.join("\n")
        ));
    }
    if !unresolved.is_empty() {
        report.push(format!(
            "every pinned-by cell names a test and a case it has, and every prose citation names one; these do not (a malformed cell or a wrong name is fixed in the document; a prose-labelled row of KNOWN_ISSUES.md whose clause cell was reworded is re-listed in KNOWN_UNRESOLVED_LABELS with the new text the line names):\n{}",
            unresolved.join("\n")
        ));
    }
    assert!(
        report.is_empty(),
        "the clause tables and KNOWN_UNRESOLVED_LABELS disagree:\n{}",
        report.join("\n\n")
    );
}
