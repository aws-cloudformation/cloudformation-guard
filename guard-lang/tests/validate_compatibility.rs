use cloudformation_guard_lang as guard_lang;
use guard_lang::eval::eval_rules_file;
use guard_lang::eval_context::{
    root_scope, simplified_json_from_root, BinaryCheck, ClauseReport, GuardClauseReport, Messages,
    UnaryCheck,
};
use guard_lang::exprs::{Block, GuardClause, Rule, RuleClause, RulesFile};
use guard_lang::parser::{rules_file, Span};
use guard_lang::path_value::{Path as GuardPath, PathAwareValue};
use guard_lang::{Status, UnResolved};
use std::convert::TryFrom;
use std::rc::Rc;

#[test]
fn validate_consumer_can_parse_evaluate_and_read_failure_report() {
    let source = r#"
        rule expected_region {
            Region == "us-east-1"
            <<Region must be us-east-1>>
        }
    "#;
    let rules = parse_rules(source, "regions.guard");
    let rule = &rules.guard_rules[0];
    assert_eq!(
        first_custom_message(rule).as_deref(),
        Some("Region must be us-east-1")
    );

    let template = serde_json::json!({ "Region": "us-west-2" });
    let root = PathAwareValue::try_from((&template, GuardPath::root())).unwrap();
    let mut scope = root_scope(&rules, Rc::new(root));

    let status = eval_rules_file(&rules, &mut scope, Some("template.json")).unwrap();
    assert_eq!(status, Status::FAIL);

    let mut recorder = scope.reset_recorder();
    let record = recorder.final_event.take().unwrap();
    let report = simplified_json_from_root(&record).unwrap();
    let failed_rule = report.not_compliant.first().unwrap();
    let failure = first_failure(failed_rule).unwrap();

    assert_eq!(failure.path.as_deref(), Some("Region"));
    assert_eq!(
        failure.custom_message.as_deref(),
        Some("Region must be us-east-1")
    );
}

fn parse_rules<'source>(source: &'source str, name: &'source str) -> RulesFile<'source> {
    rules_file(Span::new_extra(source, name)).unwrap().unwrap()
}

fn first_custom_message(rule: &Rule<'_>) -> Option<String> {
    rule.block
        .conjunctions
        .iter()
        .flatten()
        .find_map(|clause| match clause {
            RuleClause::Clause(guard_clause) => guard_clause_custom_message(guard_clause),
            RuleClause::WhenBlock(_, block) => block_custom_message(block),
            RuleClause::TypeBlock(type_block) => block_custom_message(&type_block.block),
        })
}

fn block_custom_message(block: &Block<'_, GuardClause<'_>>) -> Option<String> {
    block
        .conjunctions
        .iter()
        .flatten()
        .find_map(guard_clause_custom_message)
}

fn guard_clause_custom_message(clause: &GuardClause<'_>) -> Option<String> {
    match clause {
        GuardClause::Clause(access) => access.access_clause.custom_message.clone(),
        GuardClause::NamedRule(named) => named.custom_message.clone(),
        GuardClause::ParameterizedNamedRule(parameterized) => {
            parameterized.named_rule.custom_message.clone()
        }
        GuardClause::BlockClause(block) => block_custom_message(&block.block),
        GuardClause::WhenBlock(_, block) => block_custom_message(block),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Failure {
    path: Option<String>,
    custom_message: Option<String>,
}

fn first_failure(report: &ClauseReport<'_>) -> Option<Failure> {
    match report {
        ClauseReport::Rule(rule) => rule.checks.iter().find_map(first_failure),
        ClauseReport::Disjunctions(alternatives) => {
            alternatives.checks.iter().find_map(first_failure)
        }
        ClauseReport::Block(block) => Some(Failure {
            path: block.unresolved.as_ref().map(unresolved_path),
            custom_message: custom_message(&block.messages),
        }),
        ClauseReport::Clause(GuardClauseReport::Unary(unary)) => Some(Failure {
            path: match &unary.check {
                UnaryCheck::Resolved(comparison) => Some(template_path(&comparison.value)),
                UnaryCheck::UnResolved(unresolved) => Some(unresolved_path(&unresolved.value)),
                UnaryCheck::UnResolvedContext(_) => None,
            },
            custom_message: custom_message(&unary.messages),
        }),
        ClauseReport::Clause(GuardClauseReport::Binary(binary)) => Some(Failure {
            path: Some(match &binary.check {
                BinaryCheck::Resolved(comparison) => template_path(&comparison.from),
                BinaryCheck::InResolved(comparison) => template_path(&comparison.from),
                BinaryCheck::UnResolved(unresolved) => unresolved_path(&unresolved.value),
            }),
            custom_message: custom_message(&binary.messages),
        }),
    }
}

fn unresolved_path(unresolved: &UnResolved) -> String {
    let _missing_query = &unresolved.remaining_query;
    template_path(&unresolved.traversed_to)
}

fn template_path(value: &PathAwareValue) -> String {
    value.self_path().0.trim_start_matches('/').to_string()
}

fn custom_message(messages: &Messages) -> Option<String> {
    messages
        .custom_message
        .as_deref()
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .map(str::to_string)
}
