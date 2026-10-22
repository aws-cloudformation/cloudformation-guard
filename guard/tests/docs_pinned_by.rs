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
//! and nothing follows it (a bare `unpinned` or an `unpinned: <what>` anywhere but last is malformed). A
//! citation by fn alone pins the row to the test and to no case of it, so it still fails on a renamed
//! test. What is checked: the file is one of the four test sources, `fn <fn>(` is defined in it, the
//! fixture file exists by name under `resources/` (not that the fn reads it), and every label is a
//! string the fn CARRIES, one of: a named rstest case `#[case::<label>(` on that fn; the string
//! arguments of one unnamed `#[case(...)]` on it, joined by `, `; a string literal anywhere in the fn's
//! body (an assertion message or a rule fragment counts as much as a case, so a resolved label proves
//! the fn writes the string, not that the fn asserts a run by that name); a string literal of a `const`
//! or `static` row table the body names (one declared in the fn's own body first, else one of the fn's
//! module or an enclosing module); a format template that is the format argument of a `format!`,
//! `panic!`, `assert!`, `assert_eq!` or `assert_ne!` call in the body, with each `{}` or `{name}`
//! placeholder standing for any string the fn carries in any slot (not the argument passed there), so a
//! placeholder text the fn never carries is refused (a brace that is not a placeholder, as in a Guard
//! rule written into a plain string, makes the literal a plain one, matched whole); or, for a fn whose
//! body names the wildcard-filter fixtures directory, a `<rules file> over <document>` row of that
//! README's Cells table. The PROSE of `docs/CLAUSES.md` and `docs/KNOWN_ISSUES.md` is read too
//! (`PROSE_CITATIONS_READ_IN`): a backticked fn name after "pinned by" is defined in a cited test source
//! and a backticked `.yaml` or `.guard` name is a file under `resources/`.
//!
//! A label is spelled as a non-raw Rust string literal would spell it: a quote inside it as `\"`, a
//! backslash as `\\`, a line break as `\n` (a `\r\n` in the source reads as `\n`). A literal the source
//! writes raw (`r#"..."#`) is read in that spelling too, so `r#"rule r { Name == "b" }"#` is cited as
//! `rule r { Name == \"b\" }`. A `|` inside a label is written `\|`, as a Markdown table cell writes a
//! pipe.
//!
//! Labels are resolved against the sources in every document. The three tables of `docs/KNOWN_ISSUES.md`
//! were written with prose labels before this check existed, and the labels that name no case, body
//! string or row of their test are listed by document, label and the row's clause cell (the text of the
//! row's first column, as written) in `KNOWN_UNRESOLVED_LABELS`: the row that carries a listed label is
//! still parsed (its shape, the test it names and the fixture files it names are checked, so a renamed
//! test or a malformed cell fails here), every other label of it must resolve, and the listed label must
//! stay unresolved, so a label that is re-pinned comes off the list in the same change and a listed
//! label no row of its clause carries is reported by name; a row whose labels are all unlisted fails
//! here as a `docs/CLAUSES.md` row does. A row that moves leaves the list as it is; a row whose clause
//! cell is reworded is re-listed with the new text; two rows of one document that write the same clause
//! and the same label share one entry, whose row count `SHARED_UNRESOLVED_ENTRIES` states, and an entry
//! met on another number of rows is reported, so a row copied with a listed clause cell and label is
//! not exempt until it is counted. The list's length is the count of distinct such entries.
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

/// The test sources a clause table may cite, by the name the table uses and the path under the crate.
const CITED_TEST_SOURCES: [(&str, &str); 4] = [
    ("eval_tests.rs", "src/rules/eval_tests.rs"),
    ("eval_context_tests.rs", "src/rules/eval_context_tests.rs"),
    ("tests/validate.rs", "tests/validate.rs"),
    ("tests/test_command.rs", "tests/test_command.rs"),
];

/// The fixture directories whose README tables a cited test reads row by row.
const CITED_FIXTURE_DIRS: [&str; 1] = ["wildcard-filter-release-verdicts"];

/// The labels known not to resolve, by document, label as the cell writes it, and the row's clause cell
/// (its first column, as written): the prose labels of the `docs/KNOWN_ISSUES.md` tables, written before
/// this check existed (the module doc). A row that carries a listed label is still parsed and its test
/// and fixture names checked, every OTHER label of it must resolve, and the listed label must FAIL to
/// resolve, so a label that is re-pinned comes off the list in the same change; a listed label no row
/// carries (its clause cell reworded, or the label dropped) is reported by name, with the rows to add,
/// each named with its clause cell. The key does not move when rows are inserted above a listed one.
/// Two rows of one document that write the same clause and the same label share one entry, listed with
/// its row count in `SHARED_UNRESOLVED_ENTRIES` (two pairs do today: a row repeated, in a later table or
/// the same one, with another verdict or notice); an entry met on another number of rows than its count
/// is reported, so no copied row inherits an exemption unlisted. Regenerate it from the test's own
/// report, or from a reading of every row's labels against the sources.
const KNOWN_UNRESOLVED_LABELS: [(&str, &str, &str); 134] = [
    (
        "KNOWN_ISSUES.md",
        r#"alias gate over a spec lacking securityContext"#,
        r#"`%s[ securityContext !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"alias gate over a spec with securityContext"#,
        r#"`%s[ securityContext !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"literal gate over the same spec: refused, fail closed"#,
        r#"`spec[ securityContext !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"literal gate over the same spec: refused, fail closed"#,
        r#"`spec[ securityContext !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the compliant mixed map, one member carrying the key"#,
        r#"`Cfg[ Owner !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the author's [*] over the spec lacking securityContext"#,
        r#"`spec[*][ securityContext !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the population alias over a section written as a lone transform, under an absence check"#,
        r#"`%r[ Properties !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"control: `this !empty` alone"#,
        r#"`labels[ this !empty ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"control: `labels.*[ env exists ] empty` over the all-scalar map"#,
        r#"`labels.*[ env exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"control: `labels.*[ this !empty ] empty`"#,
        r#"`labels.*[ this !empty ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the literal spelling over all-scalar Properties under a key the map lacks"#,
        r#"`Properties[ Foo !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the example"#,
        r#"`%p[ TagSpecifications !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-key miss at the properties map's own first key"#,
        r#"`%p[ Tags !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the common absence check over a nested collection one resource of which carries the key"#,
        r#"`%r[ DeletionPolicy !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a named map whose sub-maps share no key name is an object"#,
        r#"`%d[ MetadataOptions !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a Deployment `spec` of `selector` and `template`"#,
        r#"`%s[ securityContext !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the same `spec` as a `when` gate"#,
        r#"`%s[ securityContext !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a map of scalars: the predicate resolved no key on any entry"#,
        r#"`%md[ labels !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"bracket wildcard, a member key beside the map's own key"#,
        r#"`Resources[*][ Type == 'AWS::S3::Bucket' or BucketA exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a disjunct that never holds beside the negated own key"#,
        r#"`Rules[*][ R1 !exists or Action == 'deny' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"some after [*]: the undecided entry's marker alone answers"#,
        r#"`some Cfg[*][ Mode exists or M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty or Ref !exists ].Kind == 'k'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"inside a predicate: the refused enumeration's capture holds the refusal's marker alone"#,
        r#"`Resources.*[ Properties.Cfg[*][ x \| R1 !exists ] !empty ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[ y ][ Kind == 'k' ]`, no own key named"#,
        r#"`let sel = Cfg[ y ][ Kind == 'k' ]` and `let sel = Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`, read by `%sel !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`"#,
        r#"`let sel = Cfg[ y ][ Kind == 'k' ]` and `let sel = Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`, read by `%sel !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a later part of the same query reads the scope's root"#,
        r#"`.M[ keys == to_upper(Env) ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the own-key spelling: `%x` is bound to each held key just before that entry is walked"#,
        r#"`Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the own-key spelling, the wildcard's own capture read mid-query"#,
        r#"`Cfg[ y ][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %y ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the own-key spelling over the entries in the other order"#,
        r#"`let sel = Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]` and `let sel = Cfg[*][ x \| Kind == 'k' ].Peers[ this IN %x ]`, read by `%sel !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the regular spelling over the entries in the other order"#,
        r#"`let sel = Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]` and `let sel = Cfg[*][ x \| Kind == 'k' ].Peers[ this IN %x ]`, read by `%sel !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"an enumeration the continuation refuses"#,
        r#"`.Sub[*][ s \| R1 !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the regular spelling (`Cfg[*][ x \| Kind == 'k' ]`, no own key named)"#,
        r#"`Cfg[*][ x \| Kind == 'k' ].Sub[*][ s \| R1 !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a same-name capture another clause of the block filed before the refused walk"#,
        r#"`Cfg[ x \| Kind == 'k' ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"an undecidable the walk meets for another reason"#,
        r#"`.M[ keys == Names[*].Name ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a member named like the key alone under empty"#,
        r#"`Resources[*][ BucketA exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"tagging idiom over a transform beside two tagged buckets"#,
        r#"`%r[ Properties.Tags empty ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"tags written as a loop under `Tags[*][ Key !exists ] empty`"#,
        r#"`Tags[*][ Key !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"states written as a loop under the [*] spelling of `[ Type !exists ] empty`"#,
        r#"`States[*][ Type !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a resource's `Metadata` attribute holding only a transform"#,
        r#"`Resources.*.Metadata[ Comment !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a `Parameters` holding only a transform under `Parameters[ Value !exists ] empty`"#,
        r#"`Parameters[ Value !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a `Parameters` holding only a loop under `Parameters[ Type !exists ] empty`"#,
        r#"`Parameters[ Type !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the include alone as `Properties` under `Properties.*[ Tags !exists ] empty`"#,
        r#"`[ Tags !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a lone directive under `[*]`: the directive sentence"#,
        r#"`SecurityGroupIngress[*][ Description !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"tags written as a transform under the [*] spelling of `[ Value !exists ] empty`"#,
        r#"`Tags[*][ Value !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a ForEach list beside two members, .*: `[ this IS_LIST ] empty` selects the list"#,
        r#"`Resources.*[ this IS_LIST ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-key `Fn::If` tag list, .*: `Tags.*[ Key !exists ] empty`"#,
        r#"`Tags.*[ Key !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-key `Fn::FindInMap` scalar list, [*]: `Target[*][ Name !exists ] empty`"#,
        r#"`Target[*][ Name !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a transform beside the region entries of `Mappings.RegionMap`"#,
        r#"`Mappings.RegionMap.*[ AMI !exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a parameter named like the key, `Default !exists ] !empty`"#,
        r#"`Parameters.*[ Default !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a parameter named like the key, `Default exists ] empty`: no parameter declares one"#,
        r#"`Parameters.*[ Default exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"bracket wildcard, a member named like the key negated: every resource is kept"#,
        r#"`Resources[*][ BucketA !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"control: a site whose probe read a hold (`%r[*]`: the bound map itself)"#,
        r#"`%r[*]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a key the document holds and no member holds (`AWSTemplateFormatVersion exists`)"#,
        r#"`Resources[*][ AWSTemplateFormatVersion exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a member key conjoined with a key the map lacks under `empty`"#,
        r#"`Resources[*][ BucketA exists Type == 'AWS::S3::Bucket' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the same hold under `!empty`: the verdict agrees"#,
        r#"`Resources[*][ Tags !exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a hold by the absence of a key the document lacks (`Tags !exists`)"#,
        r#"`Resources[*][ Tags !exists ].Type == 'AWS::S3::Bucket'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"an undecidable member under `empty`: fails closed"#,
        r#"`Resources[*][ BucketA !exists M[ keys == Tags[ Key == 'Env' ].Value ] !empty ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the Init shape under `exists ] empty`: nothing selected"#,
        r#"`Resources.*.Metadata[*][ "AWS::CloudFormation::Init" exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a container's resources of limits beside requests under `exists ] empty`"#,
        r#"`resources[*][ limits exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the Init shape under `.*` and `exists ] empty`"#,
        r#"`Resources.*.Metadata.*[ "AWS::CloudFormation::Init" exists ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the resource's own key `Type` asked of its Metadata members under `[*]` and `!empty`"#,
        r#"`Resources.*.Metadata[*][ Type exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the projecting binding over all-structure Properties, gate polarity"#,
        r#"`%p[*][ BucketEncryption exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the block after the bracket wildcard reads the map itself"#,
        r#"`Parameters[*] { Default !exists }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`BucketA exists`, !empty: the selection keeps nothing"#,
        r#"`Resources[*][ BucketA exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a member named like the key alone under empty"#,
        r#"`Resources[*][ BucketA exists ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a `Resources` holding only a loop, in a `Templates` list"#,
        r#"`Templates[*].Resources`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"an include beside `BucketName` under `Properties.*[ Name == 'AWS::Include' ] empty`"#,
        r#"`Resources.*.Properties.*[ Name == 'AWS::Include' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"must-flag: over `Env: prod` the fallback read holds the key filter on `PROD`"#,
        r#"`Cfg[ Owner !exists this[ keys == to_upper(Env) ] !empty ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"must-flag: a refusal raised inside the predicate is carried out of the probe"#,
        r#"`Cfg[ Owner !exists this[ Owner !exists ] !empty ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"dot wildcard over the spec with replicas beside the sub-maps"#,
        r#"`spec.*[ securityContext !exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under `== 'prod'`"#,
        r#"`Properties.Tags[*][ Key == 'Env' ].Value == 'prod'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the same identity-policy statement with a part after the filter that reads `Effect`"#,
        r#"`Statement[*][ Principal == '*' ].Effect == 'Deny'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a `NotAction` statement under `[ Action == '*' ].Condition exists`"#,
        r#"`[ Action == '*' ].Condition exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a chained filter whose predicate names `Effect`, a key the object holds"#,
        r#"`Statement[*][ Principal == '*' ][ Effect == 'Allow' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a chained filter whose predicate names `Sid`, a key the object also lacks"#,
        r#"`[ Principal == '*' ][ Sid == 'x' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"inside a predicate, `[ Principal.AWS == '*' ].Effect == 'Allow'`"#,
        r#"`Resources.*[ Properties.PolicyDocument.Statement[*][ Principal.AWS == '*' ].Effect == 'Allow' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"inside a predicate, a chained filter `[ Principal.AWS == '*' ][ Effect == 'Allow' ] !empty`"#,
        r#"`[ Principal.AWS == '*' ][ Effect == 'Allow' ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under a binding to `[ Key IN ['Env', 'Environment'] ]`"#,
        r#"`[ Key IN ['Env', 'Environment'] ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"two tags under `[ Key != 'Env' ]`"#,
        r#"`[ Key != 'Env' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"list tags `dev` under `[ Key == 'Env' Value == 'prod' ] empty`"#,
        r#"`[ Key == 'Env' Value == 'prod' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under a bare `[ Key == 'Env' ] exists`"#,
        r#"`Tags[*][ Key == 'Env' ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"list tags `dev` under `[ Key == 'Env' Value == 'prod' ] empty`"#,
        r#"`[ Key == 'Env' Value == 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags with no compared entry under `[ Key == 'Owner'  Value == 'Team' ] empty`"#,
        r#"`[ Key == 'Owner' Value == 'Team' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags with no compared entry under `[ Key NOT IN ['Env', 'Environment'] ] empty`"#,
        r#"`[ Key NOT IN ['Env', 'Environment'] ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags with no compared entry under a NEGATED bare `[ Key != 'Env' ] empty`"#,
        r#"`[ Key != 'Env' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `prod` under `[ Key != 'Env' or Value != 'prod' ] empty`"#,
        r#"`[ Key != 'Env' or Value != 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `prod` under `[ Value == 'prod'  Key != 'Env' ] empty`"#,
        r#"`[ Value == 'prod' Key != 'Env' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags with no compared entry under `[ Key != 'Env' or Action != '*' ] empty`"#,
        r#"`[ Key != 'Env' or Action != '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"an env-var map keyed by name under `Env[*][ Name != 'x' ] empty`"#,
        r#"`Env[*][ Name != 'x' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"an env-var map keyed by name under `Env[*][ Values != 'x' ] empty`"#,
        r#"`[ Values != 'x' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object `NotAction` statement under `[ Action != '*' ] empty`"#,
        r#"`[ Action != '*' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags with no compared entry under a negation on the value"#,
        r#"`[ Value != 'platform' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under `[ Value != 'platform' ] empty`"#,
        r#"`[ Value != 'platform' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object `NotAction` statement under `[ Action != '*' ] empty`"#,
        r#"`Statement[*][ Action != '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags with no compared entry under `[ Key == 'Env'  Value != 'prod' ] empty`"#,
        r#"`[ Key == 'Env' Value != 'prod' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"an identity-policy statement under `[ Principal == '*' ] empty`"#,
        r#"`Statement[*][ Principal == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a `NotAction` statement under `[ Action == '*' ] empty`"#,
        r#"`[ Action == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a trust-policy statement under `[ Resource == '*' ] empty`"#,
        r#"`[ Resource == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the same statement under `[ Principal.AWS == '*' ] empty`"#,
        r#"`[ Principal.AWS == '*' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"select the violators, assert none"#,
        r#"`Resources.*[ Properties.Tags[*][ Key == 'Env' ].Value != 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"`[ Key exists ] !empty` over map tags"#,
        r#"`Tags[*][ Key exists ] !empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under `== 'prod'`"#,
        r#"`Tags[*][ Key == 'Env' ].Value == 'prod'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under `[ Key == %w ] !empty`"#,
        r#"`[ Key == %w ] !empty` where `%w` is the capture of an earlier clause"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under a filter capture read later"#,
        r#"`let env = Resources.*.Properties.Tags[*][ t \| Key == 'Env' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under a filter capture and a bare `exists` in the filter's own clause"#,
        r#"`Tags[*][ t \| Key == 'Env' ] exists` (the first clause of a rule whose second clause is `%t.Value == 'prod'`)"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under the block form `{ check(this) }`"#,
        r#"`Tags[*][ Key == 'Env' ] { check(this) }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement under `[ Principal == '*' ] { Effect == 'Allow'  Condition exists }`"#,
        r#"`Statement[*][ Principal == '*' ] { Effect == 'Allow' Condition exists }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the inline chained `[ Sid == 'x' or %flag == true ] empty`"#,
        r#"`[ Sid == 'x' or %flag == true ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"two functions, one map-shaped and one list-shaped, both `prod`, under `some` and the block form"#,
        r#"`some Resources.*.Properties.Tags[*][ Key == 'Env' ] { Value == 'prod' }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the control"#,
        r#"`Statement[*][ Principal == '*' ].Condition exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under a binding to `[ Key == /^(?!aws:)/ ]`"#,
        r#"`[ Key == /^(?!aws:)/ ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `{ Env1: dev }` under a bare `[ Key == /^[A-Za-z]+[0-9]$/ ] empty`"#,
        r#"`Tags[*][ Key == /^[A-Za-z]+[0-9]$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement under `[ Principal == '*' or Sid == /^\w+$/ ] empty`"#,
        r#"`[ Principal == '*' or Sid == /^\w+$/ ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement under a bare `[ Sid == /^\w+$/ ] empty`"#,
        r#"`[ Sid == /^\w+$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement under a bare `[ Sid == /^\w+$/ ] !exists`"#,
        r#"`[ Sid == /^\w+$/ ] !exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement without `Sid`"#,
        r#"`Resources.*[ Properties.PolicyDocument.Statement[*][ Sid == /^\w+$/ ] is_struct ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement under `[ Sid == /.+/ ].Effect == 'Deny'`"#,
        r#"`Statement[*][ Sid == /.+/ ].Effect == 'Deny'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement under `[ Sid == /^[A-Za-z0-9]+$/ ].Effect == 'Deny'`"#,
        r#"`Statement[*][ Sid == /^[A-Za-z0-9]+$/ ].Effect == 'Deny'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"statement `{ Effect: Allow }` under a bare `[ Sid == /^[A-Za-z]+$/ ] exists`"#,
        r#"`Statement[*][ Sid == /^[A-Za-z]+$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"mixed map under a bare `[ Key == /^[A-Za-z]+$/ ] exists`"#,
        r#"`Tags[*][ Key == /^[A-Za-z]+$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement under a bare `[ Sid == /^\w+$/ ] empty`"#,
        r#"`Statement[*][ Sid == /^\w+$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"mixed map under a bare `[ Key == /^[A-Za-z]+$/ ] empty`"#,
        r#"`[ Key == /^[A-Za-z]+$/ ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"mixed map `{ Env: { Ref }, Team: platform }` under a bare `[ Key == /^[Ee][Nn][Vv]$/ ] exists`"#,
        r#"`Tags[*][ Key == /^[Ee][Nn][Vv]$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"mixed map `{ Env: dev, ENV: { Ref } }` under a bare `[ Key == /^[[:alpha:]]+$/ ] exists`"#,
        r#"`Tags[*][ Key == /^[[:alpha:]]+$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"statement `{ Effect: Allow }` under a bare `[ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists`"#,
        r#"`Statement[*][ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"statement `{ Effect: Allow }` under a bare `[ Sid == /^\w+s?$/ ] exists`"#,
        r#"`[ Sid == /^\w+s?$/ ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a one-object statement holding `Effect`, `Env` and `Action` under `[ Sid == /^E/ ].Effect == 'Deny'`"#,
        r#"`[ Sid == /^E/ ].Effect == 'Deny'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under the block form `[ Key == 'Env' ] { Value == 'prod' }`"#,
        r#"`Tags[*][ Key == 'Env' ] { Value == 'prod' }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `Team` and `Value` under `%env[ Value == 'x' ] empty`"#,
        r#"`%env[ Value == 'x' ]`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"two functions, one map-shaped and one list-shaped, both `prod`, under `some` and the inline spelling"#,
        r#"`some Resources.*.Properties.Tags[*][ Key == 'Env' ].Value == 'prod'`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"the presence-guarded spelling is not applicable over the statement with no principal"#,
        r#"`Statement[*] { when Principal exists { Principal.AWS != '*' } }`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under a bare `[ Key == 'Env' ] exists`"#,
        r#"`[ Key == 'Env' ] exists`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under `[ Key != 'Env' ] empty`"#,
        r#"`[ Key != 'Env' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `{ Team: prod }` under `[ Value == 'prod' ] empty`"#,
        r#"`[ Value == 'prod' ] empty`"#,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"map tags `dev` under a filter capture read later"#,
        r#"`[ t \| Key == 'Env' ]`"#,
    ),
];

/// The entries of `KNOWN_UNRESOLVED_LABELS` that more than one row writes, with the number of rows: a
/// row repeated, in a later table or the same one, with another verdict or notice. Every other entry is
/// met on exactly one row. The test counts the rows each entry is met on and reports a count that
/// differs, so a row copied with a listed clause cell and label does not inherit the exemption in
/// silence (it is listed here by its count) and a twin row that is gone brings the count down.
const SHARED_UNRESOLVED_ENTRIES: [(&str, &str, &str, usize); 2] = [
    (
        "KNOWN_ISSUES.md",
        r#"literal gate over the same spec: refused, fail closed"#,
        r#"`spec[ securityContext !exists ]`"#,
        2,
    ),
    (
        "KNOWN_ISSUES.md",
        r#"a `NotAction` statement under `[ Action == '*' ].Condition exists`"#,
        r#"`[ Action == '*' ].Condition exists`"#,
        2,
    ),
];

/// The number of rows a listed entry is met on: its `SHARED_UNRESOLVED_ENTRIES` count, else one.
fn rows_listed_for(entry: &(&str, &str, &str)) -> usize {
    SHARED_UNRESOLVED_ENTRIES
        .iter()
        .find(|(doc, label, clause, _)| (doc, label, clause) == (&entry.0, &entry.1, &entry.2))
        .map_or(1, |(_, _, _, rows)| *rows)
}

/// The documents whose PROSE citations are read too (`prose_citations`): a backticked fn name after
/// "pinned by" is defined in one of the cited test sources, and a backticked `.yaml` or `.guard` name is a
/// file under `resources/`. The README names example files that are not fixtures, so it is not read.
const PROSE_CITATIONS_READ_IN: [&str; 2] = ["CLAUSES.md", "KNOWN_ISSUES.md"];

/// The fewest clause-table rows, and the fewest of them pinned, each document is read to hold: the
/// document's counts when the floors were set (`CLAUSES.md` 131 rows, 117 pinned; `KNOWN_ISSUES.md` 253
/// rows, 235 pinned) less about a tenth. A document whose tables were deleted or whose cells were all
/// made `none` fails here by name, where one floor over the documents together was met by the larger
/// document alone. A change that shrinks a table below its floor on purpose lowers the floor with it.
const TABLE_FLOORS: [(&str, usize, usize); 2] =
    [("CLAUSES.md", 120, 105), ("KNOWN_ISSUES.md", 240, 215)];

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
    // a plain literal written across source lines carries its line breaks as bytes too
    raw[1..raw.len() - 1].replace("\r\n", "\n")
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
/// string. Every position of each piece is tried, so a piece that also occurs inside a fill cannot hide
/// the split that works.
fn fills_are_carried(text: &str, pieces: &[String], carried: &HashSet<&str>) -> bool {
    let Some((piece, rest)) = pieces.split_first() else {
        return carried.contains(text);
    };
    let mut from = 0;
    while let Some(found) = text[from..].find(piece.as_str()) {
        let at = from + found;
        if carried.contains(&text[..at])
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

/// The cells of one clause-table row, `|`s inside backticks and `\|`s left alone, each cell trimmed;
/// `None` for a line that is not a row. A leading `> ` (the tables sit inside block quotes) is dropped
/// first.
fn clause_table_cells(line: &str) -> Option<Vec<&str>> {
    let body = line.trim_start().trim_start_matches('>').trim();
    let body = body.strip_prefix('|')?;
    let mut cells = Vec::new();
    let mut start = 0;
    let mut in_code = false;
    let mut escaped = false;
    for (i, ch) in body.char_indices() {
        match ch {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '`' => in_code = !in_code,
            '|' if !in_code => {
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
                let rows = text
                    .lines()
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

    /// Why a `pinned by` cell does not name tests and cases they have, or `None` when every citation of
    /// it does.
    fn unresolved_cell(&self, cell: &str) -> Option<String> {
        self.unresolved_cell_in(cell, true)
    }

    /// `unresolved_cell`, with the labels read and resolved (`resolve_labels`) or read alone: a cell
    /// whose labels are read alone still has its shape, its tests and its fixture files checked.
    fn unresolved_cell_in(&self, cell: &str, resolve_labels: bool) -> Option<String> {
        self.unresolved_cell_with(cell, resolve_labels, &|_| false, &mut Vec::new())
    }

    /// `unresolved_cell_in` with the known-unresolved labels of the row (`exempt`): a label the closure
    /// admits is not a failure when it does not resolve, and every such label is pushed onto
    /// `exempt_hits` as `(label, still fails)`, so the caller can see a listed label that resolves after
    /// all (and comes off the list) and a listed label the row no longer carries (absent from the hits).
    fn unresolved_cell_with(
        &self,
        cell: &str,
        resolve_labels: bool,
        exempt: &dyn Fn(&str) -> bool,
        exempt_hits: &mut Vec<(String, bool)>,
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
            if let Some(mut labels_text) = after_fn.strip_prefix(" (") {
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
                if resolve_labels {
                    // every label is read, so a listed one is recorded as met whether or not an
                    // unlisted one failed before it; the first failure is the cell's
                    let mut first_failure = None;
                    for label in labels {
                        // a label listed as known-unresolved must still fail, and is recorded as met;
                        // one that resolves after all is recorded so it comes off the list
                        let listed = exempt(label);
                        match (listed, self.unresolved_label(file, fn_name, label)) {
                            (false, Some(why)) => {
                                if first_failure.is_none() {
                                    first_failure = Some(why);
                                }
                            }
                            (true, Some(_)) => exempt_hits.push((label.to_string(), true)),
                            (true, None) => exempt_hits.push((label.to_string(), false)),
                            (false, None) => {}
                        }
                    }
                    if first_failure.is_some() {
                        return first_failure;
                    }
                } else {
                    let Some(source) = self.sources.get(file) else {
                        return Some(format!(
                            "`{}` is not a test source the tables may cite",
                            file
                        ));
                    };
                    if !source.fns.contains_key(fn_name) {
                        return Some(format!("no `fn {}(` in {}", fn_name, file));
                    }
                }
                after_fn = labels_text;
            } else {
                // a citation by fn alone: the fn is defined, no case is named
                let Some(source) = self.sources.get(file) else {
                    return Some(format!(
                        "`{}` is not a test source the tables may cite",
                        file
                    ));
                };
                if !source.fns.contains_key(fn_name) {
                    return Some(format!("no `fn {}(` in {}", fn_name, file));
                }
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
        None
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

/// A listed entry as a row names it: `(document, label, clause cell)`.
type ListedEntry = (String, String, String);

/// What reading one document's clause tables yields: the rows that fail (a line whose labels were read
/// names the row's clause cell, the key an entry for it is written with), the listed entries met on a
/// row with the label still failing and the entries whose label resolved on a row, each with the row's
/// line, and the row counts.
#[derive(Default)]
struct RowsReading {
    unresolved: Vec<String>,
    met: Vec<(ListedEntry, usize)>,
    resolved: Vec<(ListedEntry, usize)>,
    rows: usize,
    pinned: usize,
}

/// Reads one document's clause tables against the index and the known-unresolved labels (`list`, keyed
/// by document, label and the row's clause cell): every row's shape, test and fixture names first, its
/// labels second, with a listed label admitted when it fails, recorded when it resolves, and every other
/// label required to resolve. Written as a fn of its inputs so a doctored document and list are read the
/// same way as the real ones.
fn read_rows(index: &Index, name: &str, text: &str, list: &[(&str, &str, &str)]) -> RowsReading {
    let mut reading = RowsReading::default();
    for (number, row) in clause_table_rows(text) {
        reading.rows += 1;
        match row {
            Err(why) => reading
                .unresolved
                .push(format!("docs/{}:{}: {}", name, number, why)),
            Ok((clause, cell)) => {
                if cell != "none" {
                    reading.pinned += 1;
                }
                // the shape, the fn and the fixture names first, for every row alike
                if let Some(why) = index.unresolved_cell_in(&cell, false) {
                    reading
                        .unresolved
                        .push(format!("docs/{}:{}: {}", name, number, why));
                    continue;
                }
                // then the labels: a listed one (by document, label and the row's clause cell) must
                // still fail, every other one must resolve
                let listed_here = |label: &str| {
                    list.iter()
                        .any(|(doc, l, c)| *doc == name && *l == label && *c == clause)
                };
                let mut hits = Vec::new();
                if let Some(why) = index.unresolved_cell_with(&cell, true, &listed_here, &mut hits)
                {
                    // the line names the clause cell, so the entry to add can be copied from it
                    reading.unresolved.push(format!(
                        "docs/{}:{}: {} (the row's clause cell is {})",
                        name, number, why, clause
                    ));
                }
                for (label, still_fails) in hits {
                    let entry = (name.to_string(), label, clause.clone());
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

/// What a document's PROSE cites, outside the clause tables, each with its line number: the test fns
/// named inside a `pinned by` span (from "pinned by `" to the next `)` or `;`, whichever comes first),
/// the fixture files named where the prose says "fixture" (a backticked file name ending in `.yaml` or
/// `.guard` with the word within the 80 characters before it, so an illustrative `rules.guard` elsewhere
/// is prose), and the backticked names inside a `pinned by` span that are none of a fn name (snake_case
/// with an underscore), a cited source name or `<source>:<fn>`, which the caller reports rather than
/// skips. The prose of `docs/CLAUSES.md` and `docs/KNOWN_ISSUES.md` names tests the same way the tables
/// do, so a renamed test or a renamed fixture fails here as a table cell does; the README's examples name
/// files that are not fixtures, so the README is not read.
struct ProseCitations {
    fns: Vec<ProseCitation>,
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
        fixtures: Vec::new(),
        odd: Vec::new(),
    };
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        let stripped = line.trim_start().trim_start_matches('>').trim_start();
        if stripped.starts_with('|') {
            continue;
        }
        // every backticked name of the line, in order, with the text before it
        let mut at = 0;
        while let Some(found) = line[at..].find('`') {
            let open = at + found;
            let after = &line[open + 1..];
            let Some(close) = after.find('`') else {
                break;
            };
            let name = &after[..close];
            let before: String = line[..open]
                .chars()
                .rev()
                .take(80)
                .collect::<Vec<char>>()
                .into_iter()
                .rev()
                .collect();
            if is_file_name(name)
                && (name.ends_with(".yaml") || name.ends_with(".guard"))
                && before.to_ascii_lowercase().contains("fixture")
            {
                cited.fixtures.push((number, name.to_string()));
            }
            at = open + 1 + close + 1;
        }
        let mut from = 0;
        while let Some(found) = line[from..].find("pinned by `") {
            let start = from + found + "pinned by ".len();
            let span_end = line[start..]
                .find([')', ';'])
                .map_or(line.len(), |at| start + at);
            let span = &line[start..span_end];
            let mut span_rest = span;
            while let Some(open) = span_rest.find('`') {
                let after = &span_rest[open + 1..];
                let Some(close) = after.find('`') else {
                    break;
                };
                let name = &after[..close];
                if is_fn_name(name) {
                    cited.fns.push((number, name.to_string()));
                } else if is_source_name(name) {
                    // the source named beside its fn (`tests/validate.rs`'s `fn`)
                } else if let Some((source, fn_name)) = name.split_once(':') {
                    if is_source_name(source) && is_fn_name(fn_name) {
                        cited.fns.push((number, fn_name.to_string()));
                    } else {
                        cited.odd.push((number, name.to_string()));
                    }
                } else {
                    cited.odd.push((number, name.to_string()));
                }
                span_rest = &after[close + 1..];
            }
            from = span_end.max(start);
        }
    }
    cited
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
        "eval_tests.rs:a_bound_map_filter_that_left_only_undecidable_entries_says_so (case \"let m = Resources.Only\\nrule r { %m[ Type exists or M[ keys == Tags[ Key == 'Env' ].Value ] !empty ] empty }\")".to_string(),
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
    let listed_fault = format!(
        "eval_tests.rs:{} (cases \"statement_is_a_list\", \"a label no case carries\")",
        REMEDY_TEST
    );
    let mut hits = Vec::new();
    assert_eq!(
        None,
        index.unresolved_cell_with(
            &listed_fault,
            true,
            &|label| label == "a label no case carries",
            &mut hits
        ),
        "a cell whose failing label is listed passes: {}",
        listed_fault
    );
    assert_eq!(
        vec![("a label no case carries".to_string(), true)],
        hits,
        "the listed label is recorded as met and still failing"
    );
    let mut hits = Vec::new();
    assert_eq!(
        None,
        index.unresolved_cell_with(
            &listed_fault,
            true,
            &|label| label == "a label no case carries" || label == "statement_is_a_list",
            &mut hits
        ),
        "a listed label that resolves is no failure of the cell: {}",
        listed_fault
    );
    assert!(
        hits.contains(&("statement_is_a_list".to_string(), false)),
        "the listed label that resolves is recorded as resolving (it comes off the list): {:?}",
        hits
    );
    assert!(
        index
            .unresolved_cell_with(
                &listed_fault,
                true,
                &|label| label == "statement_is_a_list",
                &mut Vec::new()
            )
            .is_some(),
        "an unlisted failing label still fails the cell: {}",
        listed_fault
    );
    // every label of the cell is read: a listed label after an unlisted failing one is still recorded
    // as met, so the report never says to drop an exemption the row still needs
    let listed_after_a_failure = format!(
        "eval_tests.rs:{} (cases \"an unlisted label no case carries\", \"a label no case carries\")",
        REMEDY_TEST
    );
    let mut hits = Vec::new();
    assert!(
        index
            .unresolved_cell_with(
                &listed_after_a_failure,
                true,
                &|label| label == "a label no case carries",
                &mut hits
            )
            .is_some_and(|why| why.contains("an unlisted label no case carries")),
        "the cell fails on its first unlisted failing label: {}",
        listed_after_a_failure
    );
    assert_eq!(
        vec![("a label no case carries".to_string(), true)],
        hits,
        "the listed label after the failure is still recorded as met"
    );

    // The row reader against a doctored table and list: an entry is met once per row that writes its
    // clause cell and carries its label still failing, so a copied row shows as a second met line; a
    // listed label the rows do not carry is met nowhere; an unlisted failing label fails its row with a
    // line that names the row's clause cell.
    let doctored_rows = format!(
        "> {}\n> |---|---|---|---|---|---|\n> | `x` | one-object | == | PASS | none | eval_tests.rs:{} (case \"a label no case carries\") |\n> | `x` | one-object | == | FAIL | none | eval_tests.rs:{} (case \"a label no case carries\") |\n> | `y` | one-object | == | PASS | none | eval_tests.rs:{} (case \"a label no case carries\") |\n",
        CLAUSE_TABLE_HEADER, REMEDY_TEST, REMEDY_TEST, REMEDY_TEST
    );
    let listed_x = ("KNOWN_ISSUES.md", "a label no case carries", "`x`");
    let listed_elsewhere = ("KNOWN_ISSUES.md", "a label no case carries", "`z`");
    let reading = read_rows(
        &index,
        "KNOWN_ISSUES.md",
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
    let (shared_doc, shared_label, shared_clause, shared_rows) = SHARED_UNRESOLVED_ENTRIES[0];
    assert_eq!(
        (1, shared_rows),
        (
            rows_listed_for(&("KNOWN_ISSUES.md", "a label no case carries", "`x`")),
            rows_listed_for(&(shared_doc, shared_label, shared_clause))
        ),
        "an entry is listed for one row unless SHARED_UNRESOLVED_ENTRIES counts it"
    );

    // The prose reader: a fn name after "pinned by", a `<source>:<fn>` there, and a fixture named as one
    // are read; a sentence that ends in `.yaml`, a file named with no "fixture" before it, and the text
    // past a `;` in a span are not; a backticked name in a `pinned by` span that is no fn, source or
    // `<source>:<fn>` is odd.
    let prose = prose_citations(
        "An illustrative `rules.guard` sits in a line (pinned by `no_such_test_fn` and `tests/validate.rs`'s `another_missing_fn`; the `NOT IN` gate) that names the fixture `no_such.yaml` and the trailer example (`and 195 more, not t60.yaml`) (pinned by `IN` and `eval_tests.rs:a_third_fn`).\n| a | table | row | is | not | read (pinned by `skipped_fn`) |\n",
    );
    assert_eq!(
        vec![
            (1, "no_such_test_fn".to_string()),
            (1, "another_missing_fn".to_string()),
            (1, "a_third_fn".to_string()),
        ],
        prose.fns,
        "the fn names of the prose spans, the text past `;` and the table row skipped"
    );
    assert_eq!(
        vec![(1, "no_such.yaml".to_string())],
        prose.fixtures,
        "the one file named as a fixture"
    );
    assert_eq!(
        vec![(1, "IN".to_string())],
        prose.odd,
        "a backticked name in a span that is no fn, source or source:fn"
    );

    // A raw literal written with `\r\n` line breaks (a checkout that rewrote them) reads as the `\n` the
    // compiler reads, and so does a plain literal that spans source lines.
    let crlf = index_source_text(
        "fn reads_both() { let _ = r#\"first\r\nsecond\"#; let _ = \"third\r\nfourth\"; }",
        "the line-ending control",
    );
    let crlf_index = Index {
        sources: HashMap::from([("eval_tests.rs", crlf)]),
        fixture_rows: HashMap::new(),
        fixture_files: HashSet::new(),
    };
    // the raw literal is cited in the escape spelling; the plain one keeps its line break as the
    // compiler reads it, a bare line feed
    for label in ["first\\nsecond", "third\nfourth"] {
        assert_eq!(
            None,
            crlf_index.unresolved_label("eval_tests.rs", "reads_both", label),
            "a literal written across lines resolves the same whatever the source's line ending: {:?}",
            label
        );
    }

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
    // the list is a set of (document, label, clause cell): an entry a regeneration wrote twice is
    // reported, not met twice; and every shared entry is one of the list's
    let distinct: HashSet<&(&str, &str, &str)> = KNOWN_UNRESOLVED_LABELS.iter().collect();
    assert_eq!(
        distinct.len(),
        KNOWN_UNRESOLVED_LABELS.len(),
        "KNOWN_UNRESOLVED_LABELS lists an entry twice"
    );
    for (doc, label, clause, rows) in SHARED_UNRESOLVED_ENTRIES {
        assert!(
            rows > 1 && distinct.contains(&(doc, label, clause)),
            "a shared entry names more than one row and is in KNOWN_UNRESOLVED_LABELS: {:?}",
            (doc, label, clause, rows)
        );
    }
    for document in &documents {
        let text = fs::read_to_string(document)
            .unwrap_or_else(|e| panic!("the document {} is readable: {}", document.display(), e));
        let name = document
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        // the prose of the two clause-table documents names tests and fixtures as the tables do
        if PROSE_CITATIONS_READ_IN.contains(&name) {
            let prose = prose_citations(&text);
            for (number, fn_name) in prose.fns {
                if !index
                    .sources
                    .values()
                    .any(|source| source.fns.contains_key(&fn_name))
                {
                    unresolved.push(format!(
                        "docs/{}:{}: the prose names `{}` after \"pinned by\" and no cited test source defines `fn {}(`",
                        name, number, fn_name, fn_name
                    ));
                }
            }
            for (number, fixture) in prose.fixtures {
                if !index.fixture_files.contains(&fixture) {
                    unresolved.push(format!(
                        "docs/{}:{}: the prose names the fixture `{}` and no file of that name is under guard/resources/",
                        name, number, fixture
                    ));
                }
            }
            for (number, odd) in prose.odd {
                unresolved.push(format!(
                    "docs/{}:{}: the prose names `{}` after \"pinned by\", which is no test fn name (lower-case words joined by `_`), no cited test source and no `<source>:<fn>`",
                    name, number, odd
                ));
            }
        }
        let reading = read_rows(&index, name, &text, &KNOWN_UNRESOLVED_LABELS);
        counts.insert(name.to_string(), (reading.rows, reading.pinned));
        unresolved.extend(reading.unresolved);
        met.extend(reading.met);
        resolved.extend(reading.resolved);
    }
    // each document's tables were read, not one document's standing in for the others'
    for (name, rows_floor, pinned_floor) in TABLE_FLOORS {
        let (rows, pinned) = counts.get(name).copied().unwrap_or_default();
        assert!(
            rows >= rows_floor && pinned >= pinned_floor,
            "the clause tables of docs/{} were read: {} rows where at least {} are expected, {} of them pinned where at least {} are expected",
            name,
            rows,
            rows_floor,
            pinned,
            pinned_floor
        );
    }
    // Per listed entry, the rows it was met on (the label still failing) and the rows its label resolved
    // on; then one report for the four ways the tables and KNOWN_UNRESOLVED_LABELS can disagree, so a
    // change that moves, copies or re-pins a listed row reads what to remove and what to add in one
    // message.
    let mut met_on: HashMap<ListedEntry, Vec<usize>> = HashMap::new();
    for (entry, line) in met {
        met_on.entry(entry).or_default().push(line);
    }
    let mut resolved_on: HashMap<ListedEntry, Vec<usize>> = HashMap::new();
    for (entry, line) in resolved {
        resolved_on.entry(entry).or_default().push(line);
    }
    let lines = |numbers: &[usize]| {
        numbers
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut missing = Vec::new();
    let mut miscounted = Vec::new();
    let mut resolving = Vec::new();
    for entry in &KNOWN_UNRESOLVED_LABELS {
        let (doc, label, clause) = entry;
        let key = (doc.to_string(), label.to_string(), clause.to_string());
        let met_lines = met_on.get(&key).map_or(&[][..], Vec::as_slice);
        let resolved_lines = resolved_on.get(&key).map_or(&[][..], Vec::as_slice);
        let expected = rows_listed_for(entry);
        let named = format!(
            "docs/{}: {:?} on the row whose clause is {}",
            doc, label, clause
        );
        match (met_lines.is_empty(), resolved_lines.is_empty()) {
            (true, true) => missing.push(named),
            (false, true) if met_lines.len() != expected => miscounted.push(format!(
                "{}: met on {} row(s) (line(s) {}) where the list allows {}",
                named,
                met_lines.len(),
                lines(met_lines),
                expected
            )),
            (false, true) => {}
            (true, false) => resolving.push(format!(
                "{}: resolves on line(s) {} and comes off the list",
                named,
                lines(resolved_lines)
            )),
            (false, false) => resolving.push(format!(
                "{}: resolves on line(s) {} and still fails on line(s) {}; re-pin the failing row(s) too, or keep the entry (with its row count in SHARED_UNRESOLVED_ENTRIES) while a row still carries the label unresolved",
                named,
                lines(resolved_lines),
                lines(met_lines)
            )),
        }
    }
    let mut report = Vec::new();
    if !missing.is_empty() {
        report.push(format!(
            "these entries of KNOWN_UNRESOLVED_LABELS were not met as a failing label of a well-formed clause-table row that writes their clause cell, and come off the list (a row whose clause cell was reworded is re-listed with the new text, which is among the rows to add below when its label still fails, each line naming the row's clause cell; a row that is malformed or resolves is listed below or above):\n{}",
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
