use super::{validate_and_return_json, ValidateInput};
use std::collections::BTreeSet;

/// Runs the public `run_checks` entry point on one document and returns the report's status with the
/// names in its `compliant` list.
///
/// Only the names are read, not the rest of the report, because the question every test here asks is
/// which rules passed on which route: the same bytes through `validate` are the reference answer.
fn status_and_compliant(data: &str, file_name: &str, rules: &str) -> (String, BTreeSet<String>) {
    let report = validate_and_return_json(
        ValidateInput {
            content: data,
            file_name,
        },
        ValidateInput {
            content: rules,
            file_name: "rules.guard",
        },
        false,
    )
    .unwrap_or_else(|e| panic!("run_checks refused {}: {}", file_name, e));

    let json: serde_json::Value =
        serde_json::from_str(&report).expect("run_checks returns a JSON document");
    let status = json["status"]
        .as_str()
        .expect("the report has a status")
        .to_string();
    let compliant = json["compliant"]
        .as_array()
        .expect("the report lists the compliant rules")
        .iter()
        .map(|name| name.as_str().expect("a rule name").to_string())
        .collect();

    (status, compliant)
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| name.to_string()).collect()
}

/// Two things, measured separately: `run_checks` reads a document carrying `!!` tags from another
/// dialect and evaluates it as if untagged, and the loader's warning list for the same bytes holds
/// one entry per tagged node with the three texts a caller prints. The second half is asserted on
/// `values::read_from_with_warnings` directly; it does not inspect `run_checks`' report, which has no
/// channel for the list (no writer, no `notices` field), so the list is dropped there.
///
/// The loader hands the list back rather than writing one `eprintln!` line per such tag, which would
/// reach this entry point's caller's stderr with no way to capture or suppress it, and `validate`
/// writes it through its writer. Surfacing it in `run_checks`' report would take a channel the report
/// does not have, a `notices` array on the ffi helper's result, and the duplicate-key warnings are
/// dropped there the same way today; the process-stderr side is pinned by `tests/cli_stderr.rs` against
/// the built binary.
#[test]
fn run_checks_reads_a_foreign_tagged_document_and_the_loader_lists_one_warning_per_node() {
    let data = "A: !!python/str Foo\nB:\n  !!python/list\n  - !!python/str a\n";

    let (status, compliant) = status_and_compliant(
        data,
        "three_foreign_tags.yaml",
        "rule a_is_a_string { A is_string }",
    );
    assert_eq!("PASS", status, "the tagged nodes load as if untagged");
    assert_eq!(names(&["a_is_a_string"]), compliant);

    let mut warnings = vec![];
    crate::rules::values::read_from_with_warnings(data, &mut warnings)
        .expect("the same bytes load through the loader");
    let texts: Vec<String> = warnings
        .iter()
        .map(|warning| warning.in_file("data file three_foreign_tags.yaml"))
        .collect();
    assert_eq!(
        vec![
            "Warning: cfn-guard does not read the YAML tag `!!python/str` at L:1,C:4 in data file three_foreign_tags.yaml; the node is read as if it had no tag.",
            "Warning: cfn-guard does not read the YAML tag `!!python/list` at L:3,C:3 in data file three_foreign_tags.yaml; the node is read as if it had no tag.",
            "Warning: cfn-guard does not read the YAML tag `!!python/str` at L:4,C:5 in data file three_foreign_tags.yaml; the node is read as if it had no tag.",
        ],
        texts
    );
}

const MERGE_KEY_RULES: &str = r#"
rule quoted_key_is_literal { Resources.A.Properties["<<"] exists }
rule hoisted_is_absent { Resources.A.Properties.hoisted !exists }
"#;

/// A quoted `"<<"` is an ordinary key on YAML text through `run_checks`, as it is through `validate`.
///
/// YAML resolves the merge key from a plain scalar only, and the libyaml loader `validate` reads with
/// records the style to tell the two apart. This entry point read YAML text through `serde_yaml`,
/// whose value model keeps no scalar style, so a quoted `"<<"` was merged: the key vanished and its
/// contents were hoisted, and both rules below reported FAIL where `validate` reported PASS on the
/// same bytes. JSON text took a different parser and was already literal; it is the control.
#[test]
fn a_quoted_merge_key_is_a_literal_key_on_yaml_text() {
    let yaml = r#"
Resources:
  A:
    Type: X
    Properties:
      "<<":
        hoisted: "yes"
      kept: 1
"#;
    let json = r#"{"Resources":{"A":{"Type":"X","Properties":{"<<":{"hoisted":"yes"},"kept":1}}}}"#;

    let (status, compliant) = status_and_compliant(yaml, "quoted.yaml", MERGE_KEY_RULES);
    assert_eq!(
        (
            "PASS".to_string(),
            names(&["hoisted_is_absent", "quoted_key_is_literal"])
        ),
        (status, compliant),
        "a quoted \"<<\" in YAML text must stay the key the document wrote"
    );

    let (status, compliant) = status_and_compliant(json, "quoted.json", MERGE_KEY_RULES);
    assert_eq!(
        (
            "PASS".to_string(),
            names(&["hoisted_is_absent", "quoted_key_is_literal"])
        ),
        (status, compliant),
        "the JSON text control must keep the key too"
    );
}

/// The plain `<<` still merges on this route: the merge is narrowed to the spelling YAML gives it, not
/// removed.
#[test]
fn a_plain_merge_key_still_merges_on_yaml_text() {
    let yaml = r#"
Resources:
  A:
    Type: X
    Properties:
      <<:
        hoisted: "yes"
      kept: 1
"#;

    let (status, compliant) = status_and_compliant(yaml, "plain.yaml", MERGE_KEY_RULES);
    assert_eq!(
        ("FAIL".to_string(), names(&[])),
        (status, compliant),
        "a plain << must be merged, so the key is gone and `hoisted` is present"
    );
}

const FLOAT_RULES: &str = r#"
rule zero { A == 0 }
rule is_str { A is_string }
rule is_flt { A is_float }
"#;

/// A float literal that underflowed to zero keeps its text through `run_checks`, on YAML and JSON
/// text alike, as it does through `validate`.
///
/// `1e-400` parses to `0.0` and says nothing about it. The libyaml loader sees the non-zero mantissa
/// digit and keeps the literal, so `A == 0` is a refused comparison under `validate`. The serde value
/// models this entry point read through keep no source text, so the same document answered `A == 0`
/// with a PASS here. A genuine `0.0` is the control and stays a float on every route.
#[test]
fn a_float_that_underflowed_keeps_its_text_on_yaml_and_json_text() {
    for (data, file_name) in [
        ("A: 1e-400\n", "under.yaml"),
        (r#"{"A": 1e-400}"#, "under.json"),
    ] {
        let (status, compliant) = status_and_compliant(data, file_name, FLOAT_RULES);
        assert_eq!(
            ("FAIL".to_string(), names(&["is_str"])),
            (status, compliant),
            "{file_name}: 1e-400 must keep its text, so only `is_str` passes"
        );
    }

    let (status, compliant) = status_and_compliant("A: 0.0\n", "zero.yaml", FLOAT_RULES);
    assert_eq!(
        ("FAIL".to_string(), names(&["is_flt", "zero"])),
        (status, compliant),
        "a genuine zero is still a float that equals 0"
    );
}

/// An integer wider than `i64` keeps its digits through `run_checks` on JSON text, as it does through
/// `validate` and through this entry point on YAML text.
///
/// A JSON route that took `serde_json` first would not: an integer in `(i64::MAX, u64::MAX]` would go
/// through `as i64`, so `18446744073709551615` would be exactly -1 and `9223372036854775808` exactly
/// `i64::MIN`, and `A < 0` would pass on a positive input, while an integer past `u64::MAX` would already
/// be a float, so two distinct integers would compare equal. Both keep their digits here, so a numeric
/// comparison refuses and the type checks answer as `validate` answers them.
#[test]
fn an_integer_past_i64_keeps_its_digits_on_json_text() {
    let sign_rules = r#"
rule a_neg { A < 0 }
rule b_neg { B < 0 }
rule a_str { A is_string }
"#;
    let (status, compliant) = status_and_compliant(
        r#"{"A": 18446744073709551615, "B": 9223372036854775808}"#,
        "u64.json",
        sign_rules,
    );
    assert_eq!(
        ("FAIL".to_string(), names(&["a_str"])),
        (status, compliant),
        "an integer above i64::MAX is its digits, not a negative number"
    );

    let wide_rules = r#"
rule eq { A == B }
rule gt { A > 0 }
rule is_str { A is_string }
rule is_flt { A is_float }
"#;
    let (status, compliant) = status_and_compliant(
        r#"{"A": 18446744073709551616, "B": 18446744073709551617}"#,
        "wide.json",
        wide_rules,
    );
    assert_eq!(
        ("FAIL".to_string(), names(&["is_str"])),
        (status, compliant),
        "two distinct integers past u64::MAX must not compare equal"
    );

    let (status, compliant) = status_and_compliant(r#"{"A": 5, "B": 6}"#, "small.json", wide_rules);
    assert_eq!(
        ("FAIL".to_string(), names(&["gt"])),
        (status, compliant),
        "an ordinary integer is still an integer"
    );
}

const ENCRYPTED_RULES: &str = r#"
rule encrypted { Resources.*.Properties.Encrypted == true }
"#;

/// A YAML anchor and alias in the data resolve through `run_checks`, as they did before the loader
/// routing, in the bare form and under a merge key.
///
/// `serde_yaml` resolved aliases, so a template that shares a block through `&a` / `*a` evaluated
/// here. Reading the data through the data-file loader refused it, which turned an input that passed
/// into an error for every FFI and Lambda caller. Every route resolves them now, within the same
/// budget, and this is the entry point's half of that pin; `validate`'s and the `test` command's sit
/// in their own tests over the same `Base: &base {Type: X}` document.
#[test]
fn an_alias_in_yaml_text_resolves_through_run_checks() {
    let bare = r#"
Resources:
  A: &a
    Type: X
    Properties:
      Encrypted: true
  B: *a
"#;
    let (status, compliant) = status_and_compliant(bare, "alias.yaml", ENCRYPTED_RULES);
    assert_eq!(
        ("PASS".to_string(), names(&["encrypted"])),
        (status, compliant),
        "the aliased resource is a copy of the anchored one"
    );

    let merged = r#"
Shared: &shared
  Encrypted: true
Resources:
  A:
    Type: X
    Properties:
      <<: *shared
      Name: a
"#;
    let (status, compliant) = status_and_compliant(merged, "merge.yaml", ENCRYPTED_RULES);
    assert_eq!(
        ("PASS".to_string(), names(&["encrypted"])),
        (status, compliant),
        "a merge key given an alias brings the anchored keys in"
    );

    let type_rules = "rule a_type_is_x { Resources.A.Type == \"X\" }";
    let (status, compliant) = status_and_compliant(
        "Base: &base {Type: X}\nResources: {A: *base}\n",
        "type.yaml",
        type_rules,
    );
    assert_eq!(
        ("PASS".to_string(), names(&["a_type_is_x"])),
        (status, compliant),
        "the document every route is pinned on resolves here too"
    );
}

/// An alias `run_checks` cannot resolve is refused with the loader's reason, the same reason
/// `validate` and the `test` command give for the same document: an anchor no earlier node declares,
/// or a copy past the budget, which on a data document is one budget for the whole document.
///
/// Every loader failure leaves this entry point as a `ParseError` naming the file, so both refusals
/// do, with the loader's message under the one prefix.
#[test]
fn an_alias_run_checks_cannot_resolve_is_a_parse_error_with_the_loaders_reason() {
    let mut chain = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
    for (name, previous) in [('b', 'a'), ('c', 'b'), ('d', 'c'), ('e', 'd'), ('f', 'e')] {
        chain.push_str(&format!(
            "{name}: &{name} [{}]\n",
            std::iter::repeat(format!("*{previous}"))
                .take(10)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    chain.push_str("Resources: {A: {Type: X}}\n");

    for (data, file_name, reasons) in [
        (
            "Resources: {A: *nope}\n".to_string(),
            "undeclared.yaml",
            &["`*nope`", "declares"][..],
        ),
        (
            chain,
            "chain.yaml",
            &["through aliases", "`*e`", "in one document"][..],
        ),
    ] {
        let result = validate_and_return_json(
            ValidateInput {
                content: &data,
                file_name,
            },
            ValidateInput {
                content: "rule a_type_is_x { Resources.A.Type == \"X\" }",
                file_name: "rules.guard",
            },
            false,
        );
        let message = match result {
            Err(crate::rules::errors::Error::ParseError(message)) => message,
            other => panic!(
                "{}: an alias the loader cannot resolve is a ParseError, got {:?}",
                file_name, other
            ),
        };
        assert!(
            message.starts_with(&format!(
                "Unable to process data in file {file_name}, Error "
            )),
            "{}: the message names the file once:\n{}",
            file_name,
            message
        );
        for reason in reasons {
            assert!(
                message.contains(reason),
                "{}: the refusal must carry `{reason}`:\n{}",
                file_name,
                message
            );
        }
    }
}

/// Data that holds no document evaluates as a null document through `run_checks`, as it did before
/// the loader routing.
///
/// `serde_yaml` read an empty string as null and the rules ran against it. The loader reports the
/// same text as a missing document, and wrapping that as a parse error turned an input that produced
/// a report into an error for every FFI and Lambda caller. The null document is restored: a rule that
/// needs a property fails, and a document that has it is the control.
#[test]
fn data_that_holds_no_document_evaluates_as_null_through_run_checks() {
    let rules = "rule a_exists { A exists }";
    for (data, file_name) in [
        ("", "empty.yaml"),
        ("# nothing but a comment\n", "comment.yaml"),
    ] {
        let (status, compliant) = status_and_compliant(data, file_name, rules);
        assert_eq!(
            ("FAIL".to_string(), names(&[])),
            (status, compliant),
            "{file_name}: a null document has no `A`, and the rules still run against it"
        );
    }

    let (status, compliant) = status_and_compliant("A: 1\n", "present.yaml", rules);
    assert_eq!(
        ("PASS".to_string(), names(&["a_exists"])),
        (status, compliant),
        "a document that has `A` passes"
    );
}

/// A YAML key written twice keeps its last value through `run_checks`, as it does through
/// `validate`.
///
/// `serde_yaml` refused the document outright. The loader keeps both entries and the conversion keeps
/// the last one, which is what `validate` evaluates, with a warning on its terminal. This entry point
/// has no terminal, and the conversion it calls drops the duplicate list, so the last value is kept
/// in silence here; the notice that names the duplicated key is the FFI area's to add. The pin is on
/// the value.
#[test]
fn a_key_written_twice_keeps_the_last_value_through_run_checks() {
    let rules = r#"
rule last { A == 2 }
rule first { A == 1 }
"#;
    let (status, compliant) = status_and_compliant("A: 1\nA: 2\n", "twice.yaml", rules);
    assert_eq!(
        ("FAIL".to_string(), names(&["last"])),
        (status, compliant),
        "the last value of a duplicated key is the one evaluated"
    );
}

/// A document the loader cannot parse is refused as a `ParseError` naming the file, with the
/// loader's text under one prefix and no trailing punctuation, and with the position libyaml stopped
/// at; the JSON reader's line and column follow when the text begins like JSON and that reader read
/// at least as far.
///
/// The inner message is the error's own text, wrapped once: "Parser Error when parsing `Unable to
/// process data in file d.yaml, Error error parsing file: ... at L:2,C:1 ...`", not a display of a
/// display, which would carry two prefixes and a trailing comma. The variant is `ParseError`, which
/// is an FFI code of its own (a `YamlError` is another), and this pins which.
#[test]
fn malformed_data_through_run_checks_is_a_parse_error_naming_the_file_once() {
    let rules = "rule r { A == 1 }";
    for (data, file_name, yaml_position, json_position) in [
        ("A: [1, 2\n", "d.yaml", " at L:2,C:1", None),
        // libyaml stops after scanning `"B"`, the JSON reader at its quote, earlier: libyaml's
        // position alone.
        ("{\"A\": 1\n \"B\": 2}\n", "d.json", " at L:2,C:5", None),
        // Both readers stop at the member that follows the missing comma: the JSON reader's line and
        // column follow libyaml's.
        (
            "{\n  \"R\": {\n    \"B\": {\n      \"Type\": \"X\"\n      \"P\": {}\n    }\n  }\n}\n",
            "e.json",
            " at L:5,C:7",
            Some("line 5 column 7"),
        ),
    ] {
        let result = validate_and_return_json(
            ValidateInput {
                content: data,
                file_name,
            },
            ValidateInput {
                content: rules,
                file_name: "rules.guard",
            },
            false,
        );
        let message = match result {
            Err(crate::rules::errors::Error::ParseError(message)) => message,
            other => panic!(
                "{}: a document the loader cannot parse is a ParseError, got {:?}",
                file_name, other
            ),
        };
        assert!(
            message.starts_with(&format!(
                "Unable to process data in file {file_name}, Error "
            )),
            "{}: the message names the file once:\n{}",
            file_name,
            message
        );
        assert!(
            !message.contains("Parser Error when parsing") && !message.ends_with(','),
            "{}: one prefix and no trailing punctuation:\n{}",
            file_name,
            message
        );
        assert!(
            !message.ends_with("error parsing file"),
            "{}: the loader's text says what libyaml expected:\n{}",
            file_name,
            message
        );
        assert!(
            message.contains(yaml_position),
            "{}: the loader's text says where libyaml stopped:\n{}",
            file_name,
            message
        );
        match json_position {
            Some(position) => assert!(
                message.contains("Read as JSON as well") && message.contains(position),
                "{}: the JSON reader read as far as libyaml, so its line and column follow:\n{}",
                file_name,
                message
            ),
            None => assert!(
                !message.contains("JSON"),
                "{}: nothing from a JSON reader that stopped earlier than libyaml, or on YAML:\n{}",
                file_name,
                message
            ),
        }
    }
}

/// The rule synthesized for top-level clauses is `<rules file name>/default` through this entry point,
/// as it is through `validate`, and a plain `default` when the caller gives the rules no name.
///
/// A caller of `run_checks` chooses the rules' `file_name`, and a caller of the public entry point may
/// pass an empty one. The plain `default` is the name such callers have always read back in the
/// report's `compliant` and `not_compliant` lists and keyed on, so it is kept byte for byte. The
/// `<name>/default` spelling with an empty name, `/default`, was tried and rejected for that reason.
///
/// The cost of keeping it is an ambiguity this test names rather than fixes: `default` is a legal rule
/// name, so with no rules file name an author's own `rule default { .. }` beside top-level clauses is
/// two rules called `default`, and the file is refused as a duplicate definition. The same bytes under
/// a rules file name are two rules, `<name>/default` and `default`, and evaluate. Callers that want a
/// file with both to parse give the rules a name, as `validate` and `test` always do.
#[test]
fn the_default_rule_is_named_after_the_rules_file_name_and_is_default_when_there_is_none() {
    let rules = "Resources EXISTS\n";
    let data = r#"{"Resources": {"A": {"Type": "X"}}}"#;
    for (file_name, expected) in [("", "default"), ("rules.guard", "rules.guard/default")] {
        let report = validate_and_return_json(
            ValidateInput {
                content: data,
                file_name: "data.json",
            },
            ValidateInput {
                content: rules,
                file_name,
            },
            false,
        )
        .unwrap_or_else(|e| panic!("run_checks refused rules named {:?}: {}", file_name, e));
        let json: serde_json::Value =
            serde_json::from_str(&report).expect("run_checks returns a JSON document");
        let compliant: Vec<&str> = json["compliant"]
            .as_array()
            .expect("the report lists the compliant rules")
            .iter()
            .map(|name| name.as_str().expect("a rule name"))
            .collect();
        assert_eq!(vec![expected], compliant, "rules file name {:?}", file_name);
    }

    // The ambiguity, named: an author's `rule default` beside the implicit one.
    let both = "Resources EXISTS\nrule default { Resources EXISTS }\n";
    let refused = validate_and_return_json(
        ValidateInput {
            content: data,
            file_name: "data.json",
        },
        ValidateInput {
            content: both,
            file_name: "",
        },
        false,
    );
    match refused {
        Err(e) => assert!(
            e.to_string()
                .contains("Rule default is defined more than once"),
            "with no rules file name the two rules share the name `default`, got: {}",
            e
        ),
        Ok(report) => panic!(
            "two rules named `default` must not evaluate as though one of them had been chosen: {}",
            report
        ),
    }
    let report = validate_and_return_json(
        ValidateInput {
            content: data,
            file_name: "data.json",
        },
        ValidateInput {
            content: both,
            file_name: "rules.guard",
        },
        false,
    )
    .expect("under a rules file name the two rules have distinct names");
    let json: serde_json::Value =
        serde_json::from_str(&report).expect("run_checks returns a JSON document");
    let compliant: BTreeSet<String> = json["compliant"]
        .as_array()
        .expect("the report lists the compliant rules")
        .iter()
        .map(|name| name.as_str().expect("a rule name").to_string())
        .collect();
    assert_eq!(names(&["default", "rules.guard/default"]), compliant);
}
