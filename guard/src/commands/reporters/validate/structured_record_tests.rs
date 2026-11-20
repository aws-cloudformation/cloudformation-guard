//! The two record tests that drive this crate's structured `validate` reporter over the evaluator.
//! They lived beside the evaluator's own tests; when the evaluator was extracted into `guard-lang`
//! they moved here, because that crate cannot depend on this one. The helpers they read are copies
//! of the evaluator tests' own (`rule_record`, `skipped_reference_record`, the gate-role builders),
//! kept small here so the two files cannot drift on anything but text.

use crate::commands::reporters::validate::structured::StructuredEvaluator;
use crate::commands::validate::{DataFile, OutputFormatType, RuleFileInfo};
use crate::rules::{
    eval_rules_file, root_scope, BlockCheck, EventRecord, GuardClause, NamedStatus, PathAwareValue,
    RecordType, Result, RuleClause, RulesFile, Status,
};
use crate::utils::writer::{WriteBuffer, Writer};
use std::convert::TryFrom;
use std::rc::Rc;

/// The evaluator tests' cell harness, reduced to what these tables use: every cell is compared and
/// the table aborts once, at its conclusion, naming every disagreeing cell.
#[derive(Default)]
struct CellFailures {
    seen: usize,
    disagreed: Vec<String>,
}

impl CellFailures {
    /// `check` with a diagnostic (a record dump, say) built ONLY when the cell disagrees, so an
    /// agreeing table formats nothing and a red cell still names what it read.
    fn check_with<T: PartialEq + std::fmt::Debug>(
        &mut self,
        label: &str,
        expected: T,
        actual: T,
        diagnostic: impl FnOnce() -> String,
    ) {
        self.seen += 1;
        if expected != actual {
            self.disagreed.push(format!(
                "{label}: wanted {expected:?}, got {actual:?}; {}",
                diagnostic()
            ));
        }
    }

    fn assert_all_agreed(self) {
        assert!(
            self.disagreed.is_empty(),
            "{} of {} cells disagree:\n  {}",
            self.disagreed.len(),
            self.seen,
            self.disagreed.join("\n  ")
        );
    }
}

/// Rule `rule_name`'s own record among the top-level rule checks of `top`, with its status.
fn rule_record<'r, 'v>(top: &'r EventRecord<'v>, rule_name: &str) -> (Status, &'r EventRecord<'v>) {
    let own = top
        .children
        .iter()
        .find(|child| {
            matches!(
                &child.container,
                Some(RecordType::RuleCheck(NamedStatus { name, .. })) if *name == rule_name
            )
        })
        .unwrap_or_else(|| panic!("no rule named {} in the record tree", rule_name));
    let status = match &own.container {
        Some(RecordType::RuleCheck(NamedStatus { status, .. })) => *status,
        _ => unreachable!("the record found is the rule's"),
    };
    (status, own)
}

/// The `custom_message` of the first SKIP block check under `record` whose sentence is a reference's
/// skip reason, depth first; `None` when no such record is there.
fn skipped_reference_record(record: &EventRecord<'_>) -> Option<Option<String>> {
    if let Some(RecordType::GuardClauseBlockCheck(BlockCheck {
        status: Status::SKIP,
        message: Some(message),
        custom_message,
        ..
    })) = &record.container
    {
        if message.contains("the rule did not apply because it referenced rule") {
            return Some(custom_message.clone());
        }
    }
    record.children.iter().find_map(skipped_reference_record)
}

/// The `custom_message` of the first fail-closed `not` block check under `record`, depth first;
/// `None` when no such record is there.
fn fail_closed_block_message(record: &EventRecord<'_>) -> Option<Option<String>> {
    if let Some(RecordType::GuardClauseBlockCheck(BlockCheck {
        message: Some(message),
        custom_message,
        ..
    })) = &record.container
    {
        if message.contains("failed only on reads it could not decide") {
            return Some(custom_message.clone());
        }
    }
    record.children.iter().find_map(fail_closed_block_message)
}

/// The budget marker on the RIGHT, bound at rule level, as the evaluator tests build it.
const GATE_ROLE_BUDGET_INTO_M: &str = "let m = Maps.M[ keys == /(?!x)((a+)+)b/ ]";

/// The refused walk of the gate-role shape: the own-key marker lands in `%y`.
const GATE_ROLE_REFUSED_WALK_INTO_Y: &str =
    "Cfg2[*][ y | Mode exists or Kind == 'k' ].Sub[*][ s | R1 !exists ] !empty or Cfg2.Other exists";

/// The binds whose walk is refused, so the gate's block reads `%y` beside the budget marker in `%m`.
fn gate_role_refused_binds() -> String {
    format!("Cfg2[ y | Kind == 'k' ] !empty  {GATE_ROLE_REFUSED_WALK_INTO_Y}")
}

/// One gate rule text: `header` (`rule check`, or `rule check(p)`), `binds`, the rule-level budget
/// `let`, and `body`.
fn gate_role_block(header: &str, binds: &str, body: &str) -> String {
    format!("{header} {{ {binds}\n{GATE_ROLE_BUDGET_INTO_M}\n{body} }}")
}

/// The gate-role document, and the same with a second `Items` entry (`I2`, `Name: n2`).
fn gate_role_documents() -> (String, String) {
    let spends_the_budget = "a".repeat(30);
    let document = format!(
        r#"{{
    "Cfg2": {{
        "Mode": {{ "Ref": "ModeParam" }},
        "Other": {{ "Kind": "k" }},
        "C": {{ "Kind": "k", "Sub": {{ "R1": {{ "Ref": "P" }}, "P": {{ "Kind": "k" }}, "Q": {{ "Kind": "k" }} }} }},
        "D": {{ "Kind": "k", "Sub": {{ "R1": {{ "Ref": "P" }}, "P": {{ "Kind": "k" }}, "Q": {{ "Kind": "k" }} }} }}
    }},
    "Items": {{ "I1": {{ "Name": "n1" }} }},
    "Maps": {{ "M": {{ "{spends_the_budget}": 1, "PROD": 1 }} }}
}}"#
    );
    let document_two = document.replace(
        r#""Items": { "I1": { "Name": "n1" } }"#,
        r#""Items": { "I1": { "Name": "n1" }, "I2": { "Name": "n2" } }"#,
    );
    assert_ne!(
        document_two, document,
        "the two-entry document holds a second item"
    );
    (document, document_two)
}

/// The sentence a block records against a refused one-object selection met beside sibling values, in
/// the assertion role, reaches the structured output: `rule check { Resources.*.Tags[*][ Key == 'Env' ]
/// { Value == 'prod' } }` over a map-shaped `Tags` beside a list-shaped one (the "SP" shape of the
/// assertion test) under `-o json` exits at the validation failure code and writes "The block's body read
/// the empty selection a one-object filter left" exactly once: the refused value's per-value record has no
/// child to speak for it, so the structured reporter falls back to the record's own message, as it does
/// for every block-shaped record with none (the same fallback the console summary takes). The read proof
/// of that record's sentence for the census of recorded explanations
/// (`every_recorded_explanation_has_a_rendering_path`).
#[test]
fn a_refused_values_record_beside_a_sibling_reaches_the_structured_output() -> Result<()> {
    const TWO_TAGS: &str = r#"{ Resources: { M: { Tags: { Env: 'dev', ENV: { Ref: 'Stage' } } }, L: { Tags: [ { Key: 'Env', Value: 'prod' } ] } } }"#;
    const THE_BLOCKS_RECORD: &str =
        "The block's body read the empty selection a one-object filter left";
    let rules = "rule check { Resources.*.Tags[*][ Key == 'Env' ] { Value == 'prod' } }";
    let rule_info = [RuleFileInfo {
        content: rules.to_string(),
        file_name: "rules.guard".to_string(),
    }];
    let data = vec![DataFile {
        content: TWO_TAGS.to_string(),
        path_value: PathAwareValue::try_from(TWO_TAGS)?,
        name: "template.json".to_string(),
    }];
    let mut writer = Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![]))?;
    let mut evaluator = StructuredEvaluator {
        rule_info: &rule_info,
        input_params: None,
        data,
        output: OutputFormatType::JSON,
        writer: &mut writer,
        exit_code: 0,
    };
    let exit_code = evaluator.evaluate()?;
    let output = writer.stripped()?;
    let mut cells = CellFailures::default();
    cells.check_with(
        "(SPj) `rule check { Resources.*.Tags[*][ Key == 'Env' ] { Value == 'prod' } }` over a map-shaped `Tags` beside a list-shaped one, `-o json`: the validation failure code, and the refused value's sentence written exactly once",
        (crate::commands::FAILURE_STATUS_CODE, 1),
        (exit_code, output.matches(THE_BLOCKS_RECORD).count()),
        || format!("the output read: {output}"),
    );
    cells.assert_all_agreed();
    Ok(())
}

/// The author's `<< >>` message on a reference or a clause travels on the record exactly as the parser
/// read it, one rule for every writer (the dependent-rule record clones the clause's field; the
/// fail-closed `not`'s record, the access clause's own block-shaped records and the call's argument
/// record do the same), and the validate report carries it once. Rows: "WS" a whitespace-only `<<   >>`
/// on `not check` and on `not check(1)`, whose record field equals the parsed field byte for byte; "J" the
/// fail-closed `not`'s message in `-o json`, written exactly once beside the refusal sentence; "A" an
/// access clause whose own query raises (a `let` the function could not convert), `%n == 1 << msg >>`,
/// whose block-shaped record carries the message into `-o json` once; "Q" an access clause decided over an
/// empty selection (`Resources[ Type == 'Nope' ] !empty << msg >>`, a filter that kept nothing), once in
/// `-o json`; "U" an access clause whose comparison raised and failed closed (`some Items.*.Name IN %m
/// << msg >>` against the budget marker), once; "C" a call whose argument could not be evaluated (the
/// key arm's own-key refusal over an ambiguous map, `check(Resources.*.Cfg[*].Limits) << msg >>`'s
/// argument record), once; "SK" a `<< msg >>` reference to a rule that did not apply, asserting ABSENCE:
/// the SKIP record carries no `custom_message` (the author's text explains a failure) and its sentence is
/// the rule's skip reason, unchanged.
#[test]
fn an_authors_message_travels_on_every_record_whose_clause_carries_one() -> Result<()> {
    const AUTHORS: &str = "the helper must fail for a reason the template can show";
    const FAILED_CLOSED_RECORD: &str = "failed only on reads it could not decide";
    /// The `-o json` output of `validate` over `rules` and `doc`, and its exit code.
    fn json_output(rules: &str, doc: &str) -> Result<(i32, String)> {
        let rule_info = [RuleFileInfo {
            content: rules.to_string(),
            file_name: "rules.guard".to_string(),
        }];
        let data = vec![DataFile {
            content: doc.to_string(),
            path_value: PathAwareValue::try_from(doc)?,
            name: "template.json".to_string(),
        }];
        let mut writer = Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![]))?;
        let mut evaluator = StructuredEvaluator {
            rule_info: &rule_info,
            input_params: None,
            data,
            output: OutputFormatType::JSON,
            writer: &mut writer,
            exit_code: 0,
        };
        let exit_code = evaluator.evaluate()?;
        Ok((exit_code, writer.stripped()?))
    }
    /// The parsed `custom_message` of the first clause of `rule main`, by reference spelling.
    fn parsed_message(rules_file: &RulesFile<'_>) -> Option<String> {
        let main = rules_file
            .guard_rules
            .iter()
            .find(|rule| rule.rule_name == "main")
            .expect("`rule main` is in the file");
        match main.block.conjunctions.first().and_then(|d| d.first()) {
            Some(RuleClause::Clause(GuardClause::NamedRule(gnc))) => gnc.custom_message.clone(),
            Some(RuleClause::Clause(GuardClause::ParameterizedNamedRule(prc))) => {
                prc.named_rule.custom_message.clone()
            }
            other => panic!(
                "`rule main`'s first clause is a reference, read {:?}",
                other
            ),
        }
    }
    let (_, document_two) = gate_role_documents();
    let refused = "some %y NOT IN %m";
    let mut cells = CellFailures::default();
    // (WS) Whitespace only, both spellings: the record's field is the parsed field.
    let label = "WS";
    for (spelling, header, reference) in [
        ("named", "rule check", "check"),
        ("parameterized", "rule check(p)", "check(1)"),
    ] {
        let rules = format!(
            "{}\nrule main {{ not {reference} <<   >> }}",
            gate_role_block(header, &gate_role_refused_binds(), refused)
        );
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let parsed = parsed_message(&rules_file);
        let mut root = root_scope(
            &rules_file,
            Rc::new(PathAwareValue::try_from(document_two.as_str())?),
        );
        eval_rules_file(&rules_file, &mut root, None)?;
        let top = root.reset_recorder().extract();
        let (status, record) = rule_record(&top, "main");
        let recorded = fail_closed_block_message(record);
        cells.check_with(
            &format!("({label}, {spelling}) `not {reference} <<   >>`: FAIL closed, and the record's author's message is the parsed field byte for byte (one rule for every writer: no trim, no filter)"),
            (Status::FAIL, Some(parsed.clone())),
            (status, recorded),
            || format!("the parsed field: {parsed:?}"),
        );
    }
    // (J) The fail-closed `not`'s message in `-o json`, once.
    let label = "J";
    let rules = format!(
        "{}\nrule main {{ not check << {AUTHORS} >> }}",
        gate_role_block("rule check", &gate_role_refused_binds(), refused)
    );
    let (exit_code, output) = json_output(&rules, &document_two)?;
    cells.check_with(
        &format!("({label}) `rule main {{ not check << .. >> }}` under `-o json`: the validation failure code, the author's text written exactly once, beside the refusal sentence"),
        (crate::commands::FAILURE_STATUS_CODE, 1, true),
        (
            exit_code,
            output.matches(AUTHORS).count(),
            output.contains(FAILED_CLOSED_RECORD),
        ),
        || format!("the output read: {output}"),
    );
    // (A, Q, U, C) The other block-shaped records of a clause that carries a message, each under `-o json`
    // with the author's text written exactly once: "A" an access clause whose own query raises (a `let`
    // the function could not convert); "Q" an access clause decided over an empty selection (`!empty` over
    // a filter that kept nothing); "U" an access clause whose comparison raised and failed closed (`some
    // .. IN %m` against the budget marker, the one strict shape that raises); "C" a call whose argument
    // could not be evaluated (the key arm's own-key refusal over an ambiguous map).
    let one_ambiguous_cfg =
        r#"{ Resources: { R1: { Cfg: { Limits: { cpu: '1' }, Other: { cpu: '2' } } } } }"#;
    for (label, rules, doc) in [
        (
            "A",
            format!("rule check {{ let n = parse_int(Resources.R.Name)\n %n == 1 << {AUTHORS} >> }}"),
            r#"{ Resources: { R: { Name: 'abc' } } }"#.to_string(),
        ),
        (
            "Q",
            format!("rule check {{ Resources[ Type == 'Nope' ] !empty << {AUTHORS} >> }}"),
            r#"{ Resources: { R: { Type: 'X' } } }"#.to_string(),
        ),
        (
            "U",
            gate_role_block(
                "rule check",
                &gate_role_refused_binds(),
                &format!("some Items.*.Name IN %m << {AUTHORS} >>"),
            ),
            document_two.clone(),
        ),
        (
            "C",
            format!(
                "rule check(p) {{ %p exists }}\nrule main {{ check(Resources.*.Cfg[*].Limits) << {AUTHORS} >> }}"
            ),
            one_ambiguous_cfg.to_string(),
        ),
    ] {
        let (exit_code, output) = json_output(&rules, &doc)?;
        cells.check_with(
            &format!("({label}) `{}` under `-o json`: the validation failure code and the author's text written exactly once", rules.replace('\n', "  ")),
            (crate::commands::FAILURE_STATUS_CODE, 1),
            (exit_code, output.matches(AUTHORS).count()),
            || format!("the output read: {output}"),
        );
    }
    // (SK) A reference that did not apply keeps its skip reason and takes no author's message: the text
    // explains a failure, and this record is a SKIP whose sentence is the rule's reason.
    let label = "SK";
    let rules = format!(
        "rule helper when Resources.Nope exists {{ Resources exists }}\nrule main {{ helper << {AUTHORS} >> }}"
    );
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let mut root = root_scope(
        &rules_file,
        Rc::new(PathAwareValue::try_from(
            r#"{ Resources: { R: { Type: 'X' } } }"#,
        )?),
    );
    eval_rules_file(&rules_file, &mut root, None)?;
    let top = root.reset_recorder().extract();
    let (status, record) = rule_record(&top, "main");
    let skip_record = skipped_reference_record(record);
    cells.check_with(
        &format!("({label}) `rule main {{ helper << .. >> }}` over a `helper` that did not apply: `main` SKIP, its reference's record the skip reason naming `helper`, with no author's message on it"),
        (Status::SKIP, Some(None)),
        (status, skip_record),
        || format!("the record tree: {top:?}"),
    );
    cells.assert_all_agreed();
    Ok(())
}
