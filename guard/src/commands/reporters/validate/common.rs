use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::rules::eval_context::{
    find_skip_reason, BinaryCheck, BinaryComparison, ClauseReport, EventRecord, FileReport,
    GuardClauseReport, InComparison, UnaryCheck, UnaryComparison, ValueComparisons,
    ValueUnResolved,
};

use crate::rules::values::CmpOperator;
use crate::rules::{
    BlockCheck, ClauseCheck, EvaluationType, NamedStatus, QueryResult, RecordType, Status,
    UnResolved,
};
use fancy_regex::Regex;
use lazy_static::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::io::Write;

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct Comparison {
    pub(super) operator: CmpOperator,
    pub(super) not_operator_exists: bool,
}

impl From<(CmpOperator, bool)> for Comparison {
    fn from(input: (CmpOperator, bool)) -> Self {
        Comparison {
            operator: input.0,
            not_operator_exists: input.1,
        }
    }
}

/// The message, if it says anything.
///
/// A clause that carries no custom message records `Some("")` rather than `None`, so a plain `or` over
/// the two message slots reports a blank reason -- which reads as a rendering bug rather than as a
/// message nobody wrote.
///
/// A function rather than a closure: a closure taking `&Option<String>` and returning `Option<&str>`
/// cannot express that the two lifetimes are the same one, and rustc rejects it.
fn non_empty_message(message: &Option<String>) -> Option<&str> {
    message.as_deref().filter(|text| !text.trim().is_empty())
}

/// Every context the per-resource output is going to render, given the resources it aggregated.
///
/// `pprint_clauses` renders a clause only when it is in that resource's own set, so the union of those sets
/// is exactly what gets shown. Collected as context strings rather than node identities because the
/// comparison wanted downstream is "has this text already been shown", and two clause reports that share a
/// context are the same finding to a reader even when they are separate nodes -- which is the case the
/// evaluator produces for a comparison it resolved one way and could not resolve another.
pub(super) fn rendered_contexts<'a, 'record: 'a, 'value: 'record>(
    resources: impl Iterator<Item = &'a LocalResourceAggr<'record, 'value>>,
) -> HashSet<String> {
    resources
        .flat_map(|resource| resource.clauses.iter())
        .filter_map(|held| report_context(held.key))
        .collect()
}

/// The context a report would be shown under, for the two kinds that carry one.
fn report_context(report: &ClauseReport<'_>) -> Option<String> {
    match report {
        ClauseReport::Clause(GuardClauseReport::Unary(unary)) => {
            Some(unary.context.trim().to_string())
        }
        ClauseReport::Clause(GuardClauseReport::Binary(binary)) => {
            Some(binary.context.trim().to_string())
        }
        ClauseReport::Block(block) => Some(block.context.trim().to_string()),
        ClauseReport::Rule(_) | ClauseReport::Disjunctions(_) => None,
    }
}

/// Collect `(context, explanation)` for failed blocks the per-resource output did not render.
///
/// The gate is what the reporter actually showed, not what a path predicts it will show. It used to be
/// `unresolved.is_none()`, on the reasoning that a block which failed while traversing a query keeps the
/// value it got to and gets rendered through it. That is true only when the value has a path: of the four
/// constructors of a block report, `MissingBlockValue` sets `unresolved: Some(..)`, and when the query fails
/// at the *document root* the value it traversed to has an empty path. Such a block was then rendered by
/// nobody and collected by nobody -- `pprint_clauses` had no bucket for it and this guard skipped it -- so a
/// rule querying a top-level property against a CloudFormation template exited 19 saying nothing, taking the
/// author's own `<< >>` message with it. That is the everyday shape of the very defect this section exists
/// for, in block syntax.
///
/// Here rather than in one reporter because every reporter that groups findings by resource needs it, and
/// for the same reason: a finding that belongs to no resource has no bucket to be rendered in, so a reporter
/// that only walks buckets exits 19 having said nothing. `cfn.rs` grew this first; `tf.rs` had the identical
/// gap and no fixture reaching it.
pub(super) fn collect_unattributed_explanations(
    clause: &ClauseReport<'_>,
    rendered: &HashSet<String>,
    out: &mut Vec<(String, String)>,
) {
    match clause {
        ClauseReport::Block(blk) => {
            let context = blk.context.trim().to_string();
            if !rendered.contains(&context) {
                // Both messages and both bounded, for the same reasons as the clause path: the author's
                // `<< >>` text is the half a reader can act on, and a block whose query failed at the
                // document root carries the whole document in its `error_message`.
                let explanation = [
                    non_empty_message(&blk.messages.custom_message),
                    non_empty_message(&blk.messages.error_message),
                ]
                .iter()
                .filter_map(|message| *message)
                .map(shortened)
                .collect::<Vec<_>>()
                .join(" ");
                if !explanation.is_empty() {
                    out.push((context, explanation));
                }
            }
        }

        // Not here. A clause is collected by `collect_clause_explanations`, which the caller reaches for
        // every clause the reporter did not render rather than for every clause under an unrendered rule.
        ClauseReport::Clause(_) => {}
        ClauseReport::Rule(rule) => {
            // A rule that failed on its own condition has no clause findings underneath it, so the
            // per-resource output has nothing to render and this message is the only account of why
            // the rule failed. `checks.is_empty()` is the discriminator: a rule whose clauses produced
            // findings has them rendered per resource already, and repeating the rule-level message
            // there would duplicate rather than explain.
            //
            // Reached when a condition cannot be answered across a rule boundary -- a gate whose
            // referenced or parameterized rule is undecidable. The evaluator records the explanation
            // on the rule, the JSON reporter has always printed it, and the console reporter printed
            // "Number of non-compliant resources 0" and nothing else: a run that exits 19 and does
            // not say why.
            if rule.checks.is_empty() {
                if let Some(explanation) = &rule.messages.custom_message {
                    out.push((format!("rule {}", rule.name), explanation.clone()));
                }
            }
            for child in &rule.checks {
                collect_unattributed_explanations(child, rendered, out);
            }
        }
        ClauseReport::Disjunctions(ors) => {
            for child in &ors.checks {
                collect_unattributed_explanations(child, rendered, out);
            }
        }
    }
}

/// The longest clause explanation this section prints, in characters.
///
/// A clause's `error_message` embeds the value its query traversed to, and for a query that resolved to
/// nothing at the document root that value is the whole document -- tens of kilobytes on one line, which
/// is not a report. The reason is at the front of the message, so a prefix carries it. Chosen to hold the
/// longest whole message in the fixture corpus, the 196-character `EMPTY`-on-an-int explanation.
///
/// Nothing is lost by it: the JSON and YAML reports print the message untruncated and always have.
const LONGEST_CLAUSE_EXPLANATION: usize = 240;

/// The explanation, cut to a length a console can show.
///
/// Cut at whitespace, so a word is never split in half. That also drops a *compactly serialised* value
/// whole, because such a value contains no whitespace and is therefore one word -- but only such a value.
/// A document containing a string with a space in it, which is any template with a `Description` or a tag
/// value, has whitespace inside the blob and the cut lands there instead, so up to the cap of unrelated
/// content can still appear. The length is what bounds the output; the whitespace rule only decides where
/// within that bound the cut falls.
///
/// Cutting mid-word would also put half a word into the fixture output, where the spell checker reads it
/// as a misspelling and fails the build. Half of "ServerSideEncryptionConfiguration" did exactly that.
///
/// By character rather than by byte, so a multi-byte character straddling the cut cannot panic.
fn shortened(explanation: &str) -> String {
    let cut = match explanation.char_indices().nth(LONGEST_CLAUSE_EXPLANATION) {
        Some((at, _)) => at,
        None => return explanation.to_string(),
    };

    let kept = &explanation[..cut];
    let kept = match kept.rfind(char::is_whitespace) {
        Some(at) => &kept[..at],
        None => kept,
    };

    format!("{}...", kept.trim_end())
}

/// Collect `(context, explanation)` for every clause the per-resource output did not render.
///
/// Per clause, against the set of contexts the reporter showed. It used to be per *rule*, on the reasoning
/// that one placed sibling renders the whole rule and carries its pathless siblings with it. That is false:
/// `pprint_clauses` gates every clause individually on membership of the resource's own set, so a clause
/// with no path is skipped there even when its rule renders -- and the rule-level gate then suppressed the
/// only other place it could have appeared. A rule with one located finding and one pathless one showed the
/// first and lost the second entirely, from the console and from the section both, while the JSON carried
/// its reason.
///
/// Deciding per clause on its own would print a second entry for a clause already shown, because the
/// evaluator emits two reports for one comparison it resolved one way and could not resolve another -- the
/// `join` fixture has exactly that, and it is what fails when the rule-level gate is simply removed. The
/// rendered-context set is what separates the two cases: the twin shares its context with the entry already
/// on screen, and a genuinely unreported sibling does not.
///
/// Both messages, in the order a reader wants them: the rule author's `<< >>` text first when there is one,
/// then the evaluator's account. `.or_else` on the two was dead code for the second half -- every clause arm
/// records a non-empty `error_message`, so the author's message could never win and never appeared here at
/// all, though the per-resource output prints both.
///
/// Each entry is labelled with the rule it came from, because without that the section repeats itself for
/// no reason a reader can see. Two rules that share a clause -- `seven-compliant-rules.guard` has three
/// spelling `Region == "us-east-1"` -- produce identical context and identical message, so an unlabelled
/// section printed the same two lines three times over and said nothing about which rules failed.
/// Deduplicating instead would have hidden that three rules failed rather than one, which is the fact the
/// reader is here for.
fn collect_clause_explanations(
    report: &ClauseReport<'_>,
    rule_name: Option<&str>,
    rendered: &HashSet<String>,
    out: &mut Vec<(String, String)>,
) {
    match report {
        ClauseReport::Clause(clause) => {
            let (context, messages) = match clause {
                GuardClauseReport::Unary(unary) => (&unary.context, &unary.messages),
                GuardClauseReport::Binary(binary) => (&binary.context, &binary.messages),
            };
            let context = context.trim().to_string();
            if rendered.contains(&context) {
                return;
            }
            let explanation = [
                non_empty_message(&messages.custom_message),
                non_empty_message(&messages.error_message),
            ]
            .iter()
            .filter_map(|message| *message)
            .map(shortened)
            .collect::<Vec<_>>()
            .join(" ");
            if !explanation.is_empty() {
                let labelled = match rule_name {
                    Some(name) => format!("{name}: {context}"),
                    None => context,
                };
                out.push((labelled, explanation));
            }
        }
        // A nested rule relabels: the clause belongs to the rule that spells it out, not to whichever
        // rule referred to that one.
        ClauseReport::Rule(rule) => {
            for child in &rule.checks {
                collect_clause_explanations(child, Some(rule.name), rendered, out);
            }
        }
        ClauseReport::Disjunctions(ors) => {
            for child in &ors.checks {
                collect_clause_explanations(child, rule_name, rendered, out);
            }
        }
        // Handled by `collect_unattributed_explanations`, which asks the same question of a block.
        ClauseReport::Block(_) => {}
    }
}

fn write_section(
    writer: &mut dyn Write,
    heading: &str,
    explanations: Vec<(String, String)>,
) -> crate::rules::Result<()> {
    if explanations.is_empty() {
        return Ok(());
    }

    writeln!(writer, "{heading}")?;
    for (context, message) in explanations {
        writeln!(writer, "  {context}")?;
        writeln!(writer, "    {message}")?;
    }

    Ok(())
}

/// Render the findings the per-resource output has nowhere to put, after it.
///
/// Writes nothing when there are none, so a reporter can call it unconditionally.
///
/// Two headings, because there are two reasons a finding ends up here and they are not the same answer.
/// A block or rule that failed on a condition nobody could decide has no verdict to report about the
/// data -- `Could not be evaluated`. A clause under a rule that no resource claimed was decided
/// perfectly well and merely has no bucket to be printed in; calling that "could not be evaluated" would
/// report an ordinary missing property as an undecidable one, which is the class of misreport this
/// section exists to remove.
///
/// The second case: a rule none of whose findings has a path is rendered nowhere at all, because both
/// console reporters match a rule to a resource through its findings' paths. `let numeric = 5` followed
/// by `%numeric empty` records a serviceable explanation -- "Attempting EMPTY operation on type int that
/// does not support it" -- and the JSON reporter has always printed it. The console reporter dropped it:
/// the operand is a literal, so the value has an empty path, the aggregation consumes only keys under
/// `/Resources/`, and the demotion check leaves the file here because an empty key is not a *located*
/// path outside `/Resources/`. The run exited 19 saying "Number of non-compliant resources 0" and
/// nothing else. Pre-existing rather than introduced on this branch: the merge-base does the same. A rule
/// querying a top-level property against a CloudFormation template reaches it the same way, which is how
/// four fixture pairs in `output-dir/rules_dir_against_data_dir.out` exited 19 without a reason.
///
/// Asked of every clause and block against `rendered`, the set of contexts the per-resource output showed.
/// An earlier version asked once per rule and predicted the answer from the findings' paths, which was wrong
/// in both directions: it suppressed a pathless clause whose rule happened to have a located sibling, and it
/// could not see a block whose query failed at the document root.
pub(super) fn write_unattributed_explanations(
    writer: &mut dyn Write,
    not_compliant: &[ClauseReport<'_>],
    rendered: &HashSet<String>,
) -> crate::rules::Result<()> {
    let mut undecidable = Vec::new();
    let mut unplaceable = Vec::new();
    for each_rule in not_compliant {
        collect_unattributed_explanations(each_rule, rendered, &mut undecidable);
        collect_clause_explanations(each_rule, None, rendered, &mut unplaceable);
    }

    write_section(writer, "Could not be evaluated:", undecidable)?;
    write_section(writer, "Findings that belong to no resource:", unplaceable)?;

    Ok(())
}

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct NameInfo<'a> {
    pub(super) rule: &'a str,
    pub(super) path: String,
    pub(super) provided: Option<serde_json::Value>,
    pub(super) expected: Option<serde_json::Value>,
    pub(super) comparison: Option<Comparison>,
    pub(super) message: String,
    pub(super) error: Option<String>,
}

impl<'a> Default for NameInfo<'a> {
    fn default() -> Self {
        NameInfo {
            rule: "",
            path: "".to_string(),
            provided: None,
            expected: None,
            comparison: None,
            message: "".to_string(),
            error: None,
        }
    }
}

/// Rules that did not apply, each with the evaluator's reason when it recorded one.
///
/// One map rather than a name set plus a parallel reason map: the reason belongs to the skip, and
/// two collections keyed by rule name can drift. `None` is the ordinary case -- most skips are a
/// condition that legitimately did not match -- and `Some` is for the skips where the evaluator
/// knows something the reader cannot infer from a bare "not applicable".
pub(super) type SkippedRules = HashMap<String, Option<String>>;

pub(super) trait GenericReporter: Debug {
    #[allow(clippy::too_many_arguments)]
    fn report(
        &self,
        writer: &mut dyn Write,
        rules_file_name: &str,
        data_file_name: &str,
        failed: HashMap<String, Vec<NameInfo<'_>>>,
        passed: HashSet<String>,
        skipped: SkippedRules,
        longest_rule_len: usize,
    ) -> crate::rules::Result<()>;
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub(super) enum StructureType {
    JSON,
    YAML,
}

#[derive(Debug)]
pub(super) struct StructuredSummary {
    hierarchy_type: StructureType,
}

impl StructuredSummary {
    pub(super) fn new(hierarchy_type: StructureType) -> Self {
        StructuredSummary { hierarchy_type }
    }
}

#[derive(Debug, Serialize)]
struct DataOutput<'a> {
    data_from: &'a str,
    rules_from: &'a str,
    not_compliant: HashMap<String, Vec<NameInfo<'a>>>,
    not_applicable: HashSet<String>,
    /// Omitted entirely when no skip carried a reason, which keeps the document shape identical
    /// to what consumers parse today. BTreeMap rather than HashMap so the order is stable across
    /// runs -- a reporter that reshuffles its own output on every invocation is unusable in a
    /// diff.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    not_applicable_reasons: BTreeMap<String, String>,
    compliant: HashSet<String>,
}

impl GenericReporter for StructuredSummary {
    fn report(
        &self,
        writer: &mut dyn Write,
        rules_file_name: &str,
        data_file_name: &str,
        failed: HashMap<String, Vec<NameInfo<'_>>>,
        passed: HashSet<String>,
        skipped: SkippedRules,
        _: usize,
    ) -> crate::rules::Result<()> {
        let not_applicable_reasons = skipped
            .iter()
            .filter_map(|(rule, reason)| reason.clone().map(|reason| (rule.clone(), reason)))
            .collect::<BTreeMap<String, String>>();
        let value = DataOutput {
            rules_from: rules_file_name,
            data_from: data_file_name,
            not_compliant: failed,
            compliant: passed,
            not_applicable: skipped.into_keys().collect(),
            not_applicable_reasons,
        };

        match &self.hierarchy_type {
            StructureType::JSON => writeln!(writer, "{}", serde_json::to_string(&value)?),
            StructureType::YAML => writeln!(writer, "{}", serde_yaml::to_string(&value)?),
        }?;
        Ok(())
    }
}

lazy_static! {
    static ref PATH_FROM_MSG: Regex = Regex::new(r"path\s+=\s+(?P<path>[^ ]+)").ok().unwrap();
}

pub(super) fn find_failing_clauses<'record, 'value>(
    current: &'record EventRecord<'value>,
) -> Vec<&'record EventRecord<'value>> {
    match &current.container {
        Some(RecordType::Filter(_)) | Some(RecordType::ClauseValueCheck(ClauseCheck::Success)) => {
            vec![]
        }

        Some(RecordType::ClauseValueCheck(_)) => vec![current],
        Some(RecordType::RuleCheck(NamedStatus {
            message: Some(_),
            status: Status::FAIL,
            ..
        })) => vec![current],

        // A clause that failed without producing any per-value result carries its explanation on the
        // block record instead, and there is no `ClauseValueCheck` underneath it to find. The
        // empty-reference failures are the case that matters: the comparison never ran, so nothing
        // was recorded per value, and this reporter used to walk past the block and report nothing at
        // all -- a run that exits 19 and prints an empty violation section.
        //
        // Children first, so a block that does have per-value findings still reports those. Reporting
        // the block instead would replace a path and a value with a one-line summary, which is the
        // opposite of the intent.
        Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            message: Some(_),
            status: Status::FAIL,
            ..
        })) => {
            let mut from_children = Vec::new();
            for child in &current.children {
                from_children.extend(find_failing_clauses(child));
            }
            match from_children.is_empty() {
                true => vec![current],
                false => from_children,
            }
        }

        _ => {
            let mut acc = Vec::new();
            for child in &current.children {
                acc.extend(find_failing_clauses(child));
            }
            acc
        }
    }
}

pub(super) fn extract_name_info_from_record<'record>(
    rule_name: &'record str,
    clause: &'record EventRecord<'_>,
) -> crate::rules::Result<NameInfo<'record>> {
    Ok(match &clause.container {
        Some(RecordType::RuleCheck(NamedStatus {
            message: Some(msg),
            name,
            ..
        })) => NameInfo {
            message: msg.clone(),
            rule: name,
            ..Default::default()
        },

        // The block-level counterpart of the arms below: no path and no value, because the comparison
        // never ran against one. The explanation is all there is, and printing it beats printing
        // nothing.
        Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            message: Some(msg), ..
        })) => NameInfo {
            error: Some(msg.clone()),
            rule: rule_name,
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(missing))) => NameInfo {
            error: missing.message.clone(),
            message: missing
                .custom_message
                .as_ref()
                .map_or("".to_string(), |m| m.clone()),
            rule: rule_name,
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(missing))) => NameInfo {
            rule: rule_name,
            error: missing.message.clone(),
            message: missing
                .custom_message
                .as_ref()
                .map_or("".to_string(), |s| s.clone()),
            path: missing
                .from
                .unresolved_traversed_to()
                .map_or("".to_string(), |s| s.self_path().0.clone()),
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(check))) => match &check.value.from {
            // A literal is reported as the resolved value it is. The two variants carry the same payload
            // and differ only in that a literal's path is the unlocated root.
            //
            // These three arms were `unreachable!()` and a reachability triage could not construct inputs
            // for them, for a precise reason worth recording: a unary clause with a literal left-hand side
            // died earlier, in `eval_context`, which *shadowed* these. Fixing that one made these
            // reachable -- `let numeric = 5` plus `%numeric empty` now arrives here -- so the panic simply
            // moved one layer out until this was fixed too.
            QueryResult::Literal(res) | QueryResult::Resolved(res) => {
                let (path, provided): (String, serde_json::Value) = (&**res).try_into()?;
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: check.value.message.clone(),
                    message: check
                        .value
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    path,
                    ..Default::default()
                }
            }

            QueryResult::UnResolved(unres) => {
                let (path, provided): (String, serde_json::Value) =
                    (&*unres.traversed_to).try_into()?;
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: Some(check.value.message.as_ref().map_or(
                        unres.reason.as_ref().map_or("".to_string(), |r| r.clone()),
                        |msg| msg.clone(),
                    )),
                    message: check
                        .value
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    path,
                    ..Default::default()
                }
            }
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(check))) => match &check.from {
            QueryResult::Literal(res) | QueryResult::Resolved(res) => {
                let (path, provided): (String, serde_json::Value) = (&**res).try_into()?;
                let expected: Option<(String, serde_json::Value)> = match &check.to {
                    Some(to) => match to {
                        QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                            Some((&**v).try_into()?)
                        }
                        QueryResult::UnResolved(ur) => Some((&*ur.traversed_to).try_into()?),
                    },
                    None => None,
                };
                let expected = expected.map(|(_, ex)| ex);
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: check.message.clone(),
                    message: check
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    expected,
                    path,
                }
            }

            QueryResult::UnResolved(unres) => {
                let (path, provided): (String, serde_json::Value) =
                    (&*unres.traversed_to).try_into()?;
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: Some(check.message.as_ref().map_or(
                        unres.reason.as_ref().map_or("".to_string(), |r| r.clone()),
                        |msg| msg.clone(),
                    )),
                    message: check
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    path,
                    ..Default::default()
                }
            }
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::NoValueForEmptyCheck(msg))) => NameInfo {
            rule: rule_name,
            comparison: Some(Comparison {
                not_operator_exists: false,
                operator: CmpOperator::Empty,
            }),
            message: String::from(msg.as_ref().map_or("", |s| s.as_str())),
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::InComparison(incomp))) => {
            let provided = match incomp.from.resolved() {
                Some(val) => {
                    let (_, value): (String, serde_json::Value) = (&*val).try_into()?;
                    Some(value)
                }
                None => None,
            };
            let mut to = Vec::new();
            for each in &incomp.to {
                let (_, expected): (String, serde_json::Value) = match each {
                    QueryResult::Literal(l) => (&**l).try_into()?,
                    QueryResult::Resolved(v) => (&**v).try_into()?,
                    QueryResult::UnResolved(ur) => (&*ur.traversed_to).try_into()?,
                };
                to.push(expected);
            }
            NameInfo {
                rule: rule_name,
                comparison: Some(Comparison {
                    not_operator_exists: incomp.comparison.1,
                    operator: incomp.comparison.0,
                }),
                provided,
                expected: Some(serde_json::Value::Array(to)),
                message: String::from(incomp.message.as_ref().map_or("", |s| s.as_str())),
                ..Default::default()
            }
        }

        _ => unreachable!(),
    })
}

pub(super) fn report_from_events(
    root_record: &EventRecord<'_>,
    writer: &mut dyn Write,
    data_file_name: &str,
    rules_file_name: &str,
    renderer: &dyn GenericReporter,
) -> crate::rules::Result<()> {
    let mut longest_rule_length = 0;
    let mut failed = HashMap::new();
    let mut skipped = SkippedRules::new();
    let mut success = HashSet::new();
    for each_rule in &root_record.children {
        if let Some(RecordType::RuleCheck(NamedStatus { status, name, .. })) = &each_rule.container
        {
            if name.len() > longest_rule_length {
                longest_rule_length = name.len();
            }
            match status {
                Status::FAIL => {
                    let mut clauses = Vec::new();
                    for each_clause in find_failing_clauses(each_rule) {
                        clauses.push(extract_name_info_from_record(name, each_clause)?);
                    }
                    failed.insert(name.to_string(), clauses);
                }

                Status::PASS => {
                    success.insert(name.to_string());
                }

                Status::SKIP => {
                    skipped.insert(name.to_string(), find_skip_reason(each_rule));
                }
            }
        }
    }

    renderer.report(
        writer,
        rules_file_name,
        data_file_name,
        failed,
        success,
        skipped,
        longest_rule_length,
    )?;
    Ok(())
}

pub(super) fn extract_name_info<'a>(
    rule_name: &'a str,
    each_failing_clause: &StatusContext,
) -> crate::rules::Result<NameInfo<'a>> {
    if each_failing_clause.from.is_some() {
        let value = each_failing_clause.from.as_ref().unwrap();
        let (path, from): (String, serde_json::Value) = value.try_into()?;
        Ok(NameInfo {
            rule: rule_name,
            path,
            provided: Some(from),
            expected: match &each_failing_clause.to {
                Some(to) => {
                    let (_, val): (String, serde_json::Value) = to.try_into()?;
                    Some(val)
                }
                None => None,
            },
            comparison: each_failing_clause.comparator.map(|input| input.into()),
            message: each_failing_clause
                .msg
                .as_ref()
                .map_or("".to_string(), |e| {
                    if !e.contains("DEFAULT") {
                        e.clone()
                    } else {
                        "".to_string()
                    }
                }),
            error: None,
        })
    } else {
        //
        // This is crappy, but we are going to extract information from the retrieval error message
        // see path_value.rs for retrieval error messages.
        // TODO merge the query interface to retrieve partial results along with errored one ones and then
        //      change this logic based on the reporting changes. Today we bail out for the first
        //      retrieval error, fast fail semantics
        //

        //
        // No from is how we indicate retrieval errors.
        //
        let (path, error) =
            each_failing_clause
                .msg
                .as_ref()
                .map_or(
                    ("".to_string(), "".to_string()),
                    |msg| match PATH_FROM_MSG.captures(msg) {
                        Ok(Some(cap)) => (cap["path"].to_string(), msg.clone()),
                        Ok(None) => ("".to_string(), msg.clone()),
                        Err(_) => panic!("Error while parsing retrieval errors"),
                    },
                );

        Ok(NameInfo {
            rule: rule_name,
            path,
            error: Some(error),
            ..Default::default()
        })
    }
}

pub(super) fn colored_string(status: Option<Status>) -> ColoredString {
    let status = match status {
        Some(s) => s,
        None => Status::SKIP,
    };
    match status {
        Status::PASS => "PASS".green(),
        Status::FAIL => "FAIL".red().bold(),
        Status::SKIP => "SKIP".yellow().bold(),
    }
}

pub(super) fn find_all_failing_clauses(context: &StatusContext) -> Vec<&StatusContext> {
    let mut failed = Vec::with_capacity(context.children.len());
    for each in &context.children {
        if each.status.map_or(false, |s| s == Status::FAIL) {
            match each.eval_type {
                EvaluationType::Clause | EvaluationType::BlockClause => {
                    failed.push(each);
                    if each.eval_type == EvaluationType::BlockClause {
                        failed.extend(find_all_failing_clauses(each));
                    }
                }

                EvaluationType::Filter | EvaluationType::Condition => {
                    continue;
                }

                _ => failed.extend(find_all_failing_clauses(each)),
            }
        }
    }
    failed
}

pub(super) fn print_compliant_skipped_info(
    writer: &mut dyn Write,
    passed: &HashSet<String>,
    skipped: &HashSet<String>,
    _: &str,
    data_file_name: &str,
) -> crate::rules::Result<()> {
    if !passed.is_empty() {
        writeln!(writer, "--")?;
    }
    for pass in passed {
        writeln!(
            writer,
            "Rule [{}] is compliant for template [{}]",
            pass, data_file_name
        )?;
    }
    if !skipped.is_empty() {
        writeln!(writer, "--")?;
    }
    for skip in skipped {
        writeln!(
            writer,
            "Rule [{}] is not applicable for template [{}]",
            skip, data_file_name
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn print_name_info<R, U, B>(
    writer: &mut dyn Write,
    info: &[NameInfo<'_>],
    _: usize,
    rules_file_name: &str,
    data_file_name: &str,
    retrieval_error: R,
    unary_message: U,
    binary_message: B,
) -> crate::rules::Result<()>
where
    R: Fn(&str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
    U: Fn(&str, &str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
    B: Fn(&str, &str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
{
    for each in info {
        let _ = match &each.comparison {
            Some(cmp) => (Some(cmp.operator), cmp.not_operator_exists),
            None => (None, false),
        };
        // CFN = Resource [<name>] was not compliant with [<rule-name>] for property [<path>] because provided value [<value>] did not match expected value [<value>]. Error Message [<msg>]
        // General = Violation of [<rule-name>] for property [<path>] because provided value [<value>] did not match expected value [<value>]. Error Message [<msg>]
        // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
        match each.error {
            Some(_) => {
                // Block Clause retrieval error
                writeln!(
                    writer,
                    "{}",
                    retrieval_error(rules_file_name, data_file_name, each)?
                )?;
            }

            None => {
                let (cmp, not) = match &each.comparison {
                    Some(cmp) => (cmp.operator, cmp.not_operator_exists),
                    None => {
                        // "Rule", not "Parameterized Rule". This is the arm for a failure carried on
                        // the rule rather than on a clause comparison, and at the merge-base only a
                        // parameterized rule reached it, so the wording was accurate. This branch
                        // gives ordinary rules a rule-level message -- a condition that could not be
                        // evaluated -- so an ordinary rule now arrives here and was being announced
                        // as something it is not. A parameterized rule is still a rule, so dropping
                        // the word is correct for both rather than a trade between them.
                        writeln!(
                            writer,
                            "Rule {rule_name} failed for {data}. Reason {msg}",
                            data = data_file_name,
                            rule_name = each.rule,
                            msg = each.message.replace('\n', "; ")
                        )?;
                        continue;
                    }
                };
                if cmp.is_unary() {
                    use CmpOperator::*;
                    writeln!(
                        writer,
                        "{}",
                        unary_message(
                            rules_file_name,
                            data_file_name,
                            match cmp {
                                Exists =>
                                    if !not {
                                        "did not exist"
                                    } else {
                                        "existed"
                                    },
                                Empty =>
                                    if !not {
                                        "was not empty"
                                    } else {
                                        "was empty"
                                    },
                                IsList =>
                                    if !not {
                                        "was not a list "
                                    } else {
                                        "was list"
                                    },
                                IsMap =>
                                    if !not {
                                        "was not a struct"
                                    } else {
                                        "was struct"
                                    },
                                IsString =>
                                    if !not {
                                        "was not a string "
                                    } else {
                                        "was string"
                                    },
                                IsBool =>
                                    if !not {
                                        "was not a bool"
                                    } else {
                                        "was bool"
                                    },
                                IsInt =>
                                    if !not {
                                        "was not an int"
                                    } else {
                                        "was int"
                                    },
                                IsNull =>
                                    if !not {
                                        "was not null"
                                    } else {
                                        "was null"
                                    },
                                IsFloat =>
                                    if !not {
                                        "was not a float"
                                    } else {
                                        "was float"
                                    },
                                Eq | In | Gt | Lt | Le | Ge => unreachable!(),
                            },
                            each
                        )?,
                    )?;
                } else {
                    // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
                    writeln!(
                        writer,
                        "{}",
                        binary_message(
                            rules_file_name,
                            data_file_name,
                            if not { "did" } else { "did not" },
                            each
                        )?,
                    )?;
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct DataOutputNewForm<'a, 'v> {
    data_from: &'a str,
    rules_from: &'a str,
    report: FileReport<'v>,
}

#[derive(Clone, Debug)]
pub(super) struct LocalResourceAggr<'record, 'value: 'record> {
    pub(super) name: String,
    pub(super) resource_type: &'value str,
    pub(super) cdk_path: Option<&'value str>,
    pub(super) clauses: HashSet<IdentityHash<'record, ClauseReport<'value>>>,
    pub(super) paths: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub(super) struct IdentityHash<'key, T> {
    pub(super) key: &'key T,
}

impl<'key, T> Hash for IdentityHash<'key, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(self.key, state)
    }
}

impl<'key, T> Eq for IdentityHash<'key, T> {}
impl<'key, T> PartialEq for IdentityHash<'key, T> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.key, other.key)
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(super) struct Node<'report, 'value: 'report> {
    pub(super) parent: std::rc::Rc<String>,
    pub(super) path: std::rc::Rc<String>,
    pub(super) clause: &'report ClauseReport<'value>,
}

pub(super) type RuleHierarchy<'report, 'value> =
    BTreeMap<std::rc::Rc<String>, std::rc::Rc<Node<'report, 'value>>>;

pub(super) type PathTree<'report, 'value> =
    BTreeMap<String, Vec<std::rc::Rc<Node<'report, 'value>>>>;

pub(super) fn insert_into_trees<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    parent: std::rc::Rc<String>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>,
) {
    let path = std::rc::Rc::new(clause.key(&parent));
    let node = std::rc::Rc::new(Node {
        parent,
        path: path.clone(),
        clause,
    });
    hierarchy.insert(path, node.clone());

    if let Some(from) = clause.value_from() {
        let path = from.self_path().0.to_string();
        path_tree.entry(path).or_default().push(node.clone());
    }

    if let Some(from) = clause.value_to() {
        let path = from.self_path().0.to_string();
        path_tree.entry(path).or_default().push(node);
    }
}

pub(super) fn insert_into_trees_from_parent<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    children: &'report [ClauseReport<'value>],
    parent: std::rc::Rc<String>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>,
) {
    let path = std::rc::Rc::new(clause.key(&parent));
    let node = std::rc::Rc::new(Node {
        parent,
        path: path.clone(),
        clause,
    });
    hierarchy.insert(path.clone(), node);

    for each in children {
        populate_hierarchy_path_trees(each, path.clone(), path_tree, hierarchy);
    }
}

pub(super) fn populate_hierarchy_path_trees<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    parent: std::rc::Rc<String>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>,
) {
    match clause {
        ClauseReport::Clause(_) | ClauseReport::Block(_) => {
            insert_into_trees(clause, parent, path_tree, hierarchy)
        }

        ClauseReport::Disjunctions(ors) => {
            insert_into_trees_from_parent(clause, &ors.checks, parent, path_tree, hierarchy)
        }

        ClauseReport::Rule(rr) => {
            insert_into_trees_from_parent(clause, &rr.checks, parent, path_tree, hierarchy)
        }
    }
}

fn emit_messages(
    writer: &mut dyn Write,
    prefix: &str,
    message: &str,
    error: &str,
    width: usize,
) -> crate::rules::Result<()> {
    if !message.is_empty() {
        let message: Vec<&str> = if message.contains(';') {
            message.split(';').collect()
        } else if message.contains('\n') {
            message.split('\n').collect()
        } else {
            vec![message]
        };
        let message: Vec<&str> = message
            .iter()
            .map(|s| s.trim_start().trim_end())
            .filter(|s| !s.is_empty())
            .collect();

        if message.len() > 1 {
            writeln!(
                writer,
                "{prefix}{mh:<width$} {{",
                prefix = prefix,
                mh = "Message",
                width = width
            )?;
            for each in message {
                writeln!(
                    writer,
                    "{prefix}  {message}",
                    prefix = prefix,
                    message = each,
                )?;
            }
            writeln!(writer, "{prefix}}}", prefix = prefix,)?;
        } else {
            writeln!(
                writer,
                "{prefix}{mh:<width$} = {message}",
                prefix = prefix,
                message = message[0],
                mh = "Message",
                width = width
            )?;
        }
    }

    if !error.is_empty() {
        writeln!(
            writer,
            "{prefix}{eh:<width$} = {error}",
            prefix = prefix,
            error = error,
            eh = "Error",
            width = width
        )?;
    }

    Ok(())
}

fn emit_retrieval_error(
    writer: &mut dyn Write,
    prefix: &str,
    vur: &ValueUnResolved,
    clause: &ClauseReport<'_>,
    context: &str,
    message: &str,
    err_emitter: &mut dyn ComparisonErrorWriter,
) -> crate::rules::Result<()> {
    writeln!(
        writer,
        "{prefix}Check = {cxt} {{",
        prefix = prefix,
        cxt = context
    )?;
    let check_end = format!("{}}}", prefix);
    let prefix = format!("{}  ", prefix);
    emit_messages(writer, &prefix, message, "", 0)?;

    writeln!(writer, "{prefix}RequiredPropertyError {{", prefix = prefix)?;
    let rpe_end = format!("{}}}", prefix);
    let prefix = format!("{}  ", prefix);
    writeln!(
        writer,
        "{prefix}PropertyPath = {path}",
        prefix = prefix,
        path = vur.value.traversed_to.self_path()
    )?;

    writeln!(
        writer,
        "{prefix}MissingProperty = {prop}",
        prefix = prefix,
        prop = vur.value.remaining_query
    )?;

    let reason = vur.value.reason.as_ref().map_or("", String::as_str);
    if !reason.is_empty() {
        writeln!(
            writer,
            "{prefix}Reason = {reason}",
            prefix = prefix,
            reason = reason
        )?;
    }
    err_emitter.missing_property_msg(writer, clause, Some(&vur.value), &prefix)?;
    writeln!(writer, "{}", rpe_end)?;
    writeln!(writer, "{}", check_end)?;
    Ok(())
}

pub(super) trait ComparisonErrorWriter {
    fn missing_property_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: Option<&UnResolved>,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }

    fn binary_error_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: &BinaryComparison,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }

    fn binary_error_in_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: &InComparison,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }

    fn unary_error_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: &UnaryComparison,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }
}

pub(super) fn pprint_clauses<'report, 'value: 'report>(
    writer: &mut dyn Write,
    clause: &'report ClauseReport<'value>,
    resource: &LocalResourceAggr<'report, 'value>,
    prefix: String,
    err_writer: &mut dyn ComparisonErrorWriter,
) -> crate::rules::Result<()> {
    match clause {
        ClauseReport::Rule(rr) => {
            writeln!(
                writer,
                "{prefix}Rule = {rule} {{",
                prefix = prefix,
                rule = rr.name.bright_magenta()
            )?;
            let rule_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            let message = rr
                .messages
                .custom_message
                .as_ref()
                .map_or("", String::as_str);
            let error = rr
                .messages
                .error_message
                .as_ref()
                .map_or("", String::as_str);
            emit_messages(writer, &prefix, message, error, 0)?;
            writeln!(writer, "{prefix}ALL {{", prefix = prefix)?;
            let all_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            for child in &rr.checks {
                pprint_clauses(writer, child, resource, prefix.clone(), err_writer)?;
            }
            writeln!(writer, "{}", all_end)?;
            writeln!(writer, "{}", rule_end)?;
        }

        ClauseReport::Disjunctions(ors) => {
            writeln!(writer, "{prefix}ANY {{", prefix = prefix)?;
            let end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            for child in &ors.checks {
                pprint_clauses(writer, child, resource, prefix.clone(), err_writer)?;
            }
            writeln!(writer, "{}", end)?;
        }

        ClauseReport::Block(blk) => {
            if !resource.clauses.contains(&IdentityHash { key: clause }) {
                return Ok(());
            }
            writeln!(
                writer,
                "{prefix}Check = {cxt} {{",
                prefix = prefix,
                cxt = blk.context
            )?;
            let check_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            writeln!(writer, "{prefix}RequiredPropertyError {{", prefix = prefix)?;
            let mpv_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            let (traversed_to, query) = blk.unresolved.as_ref().map_or(("", ""), |val| {
                (&val.traversed_to.self_path().0, &val.remaining_query)
            });
            let width = if !traversed_to.is_empty() {
                let width = "MissingProperty".len() + 4;
                writeln!(
                    writer,
                    "{prefix}{pp:<width$}= {path}\n{prefix}{mp:<width$}= {q}",
                    prefix = prefix,
                    pp = "PropertyPath",
                    width = width,
                    path = traversed_to,
                    mp = "MissingProperty",
                    q = query
                )?;
                width
            } else {
                "Message".len() + 4
            };
            let mut post_message: Vec<u8> = Vec::new();
            let width = std::cmp::max(
                width,
                err_writer.missing_property_msg(
                    &mut post_message,
                    clause,
                    blk.unresolved.as_ref(),
                    &prefix,
                )?,
            );
            let message = blk
                .messages
                .custom_message
                .as_ref()
                .map_or("", String::as_str);
            let error = blk
                .messages
                .error_message
                .as_ref()
                .map_or("", String::as_str);
            emit_messages(writer, &prefix, message, error, width)?;
            writeln!(
                writer,
                "{}",
                match String::from_utf8(post_message) {
                    Ok(msg) => msg,
                    Err(_) => "".to_string(),
                }
            )?;
            writeln!(writer, "{}", mpv_end)?;
            writeln!(writer, "{}", check_end)?;
        }

        ClauseReport::Clause(gac) => {
            if !resource.clauses.contains(&IdentityHash { key: clause }) {
                return Ok(());
            }
            match gac {
                GuardClauseReport::Unary(ur) => match &ur.check {
                    UnaryCheck::UnResolved(vur) => {
                        emit_retrieval_error(
                            writer,
                            &prefix,
                            vur,
                            clause,
                            &ur.context,
                            ur.messages
                                .custom_message
                                .as_ref()
                                .map_or("", String::as_str),
                            err_writer,
                        )?;
                    }

                    UnaryCheck::Resolved(re) => {
                        writeln!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = ur.context
                        )?;
                        let check_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        writeln!(writer, "{prefix}ComparisonError {{", prefix = prefix)?;
                        let ce_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        let mut post_message: Vec<u8> = Vec::new();
                        let width =
                            err_writer.unary_error_msg(&mut post_message, clause, re, &prefix)?;
                        let message = ur
                            .messages
                            .custom_message
                            .as_ref()
                            .map_or("", String::as_str);
                        let error = ur
                            .messages
                            .error_message
                            .as_ref()
                            .map_or("", String::as_str);
                        emit_messages(writer, &prefix, message, error, width)?;
                        writeln!(
                            writer,
                            "{}",
                            match String::from_utf8(post_message) {
                                Ok(msg) => msg,
                                Err(_) => "".to_string(),
                            }
                        )?;
                        writeln!(writer, "{}", ce_end)?;
                        writeln!(writer, "{}", check_end)?;
                    }

                    _ => {}
                },

                GuardClauseReport::Binary(br) => match &br.check {
                    BinaryCheck::UnResolved(vur) => {
                        emit_retrieval_error(
                            writer,
                            &prefix,
                            vur,
                            clause,
                            &br.context,
                            br.messages
                                .custom_message
                                .as_ref()
                                .map_or("", String::as_str),
                            err_writer,
                        )?;
                    }

                    BinaryCheck::Resolved(bc) => {
                        writeln!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = br.context
                        )?;
                        let check_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        writeln!(writer, "{prefix}ComparisonError {{", prefix = prefix)?;
                        let ce_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        let mut post_message: Vec<u8> = Vec::new();
                        let width =
                            err_writer.binary_error_msg(&mut post_message, clause, bc, &prefix)?;
                        let message = br
                            .messages
                            .custom_message
                            .as_ref()
                            .map_or("", String::as_str);
                        let error = br
                            .messages
                            .error_message
                            .as_ref()
                            .map_or("", String::as_str);
                        emit_messages(writer, &prefix, message, error, width)?;
                        writeln!(
                            writer,
                            "{}",
                            match String::from_utf8(post_message) {
                                Ok(msg) => msg,
                                Err(_) => "".to_string(),
                            }
                        )?;

                        writeln!(writer, "{}", ce_end)?;
                        writeln!(writer, "{}", check_end)?;
                    }

                    BinaryCheck::InResolved(inr) => {
                        writeln!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = br.context
                        )?;
                        let check_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        writeln!(writer, "{prefix}ComparisonError {{", prefix = prefix)?;
                        let ce_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        let mut post_message: Vec<u8> = Vec::new();
                        let width = err_writer.binary_error_in_msg(
                            &mut post_message,
                            clause,
                            inr,
                            &prefix,
                        )?;
                        let message = br
                            .messages
                            .custom_message
                            .as_ref()
                            .map_or("", String::as_str);
                        let error = br
                            .messages
                            .error_message
                            .as_ref()
                            .map_or("", String::as_str);
                        emit_messages(writer, &prefix, message, error, width)?;
                        writeln!(writer, "{}", ce_end)?;
                        writeln!(
                            writer,
                            "{}",
                            match String::from_utf8(post_message) {
                                Ok(msg) => msg,
                                Err(_) => "".to_string(),
                            }
                        )?;
                        writeln!(writer, "{}", check_end)?;
                    }
                },
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod shortened_tests {
    use super::{shortened, LONGEST_CLAUSE_EXPLANATION};

    #[test]
    fn leaves_a_message_that_fits_alone() {
        let message = "Check was not compliant as property [Name] is missing.";
        assert_eq!(message, shortened(message));
    }

    /// The case this exists for. A value the evaluator embedded is compact JSON, so it holds no
    /// whitespace and the cut lands in front of all of it -- the property is still named and the
    /// document is gone, rather than the first 240 bytes of the document being printed.
    #[test]
    fn drops_an_embedded_document_whole() {
        let document = format!(r#"{{"Resources":{{"{}":{{}}}}}}"#, "A".repeat(400));
        let message = format!("Property [Name] is missing. Value traversed to [{document}]");

        let short = shortened(&message);

        assert!(
            short.starts_with("Property [Name] is missing. Value traversed to"),
            "the sentence naming the property survives: {}",
            short
        );
        assert!(
            !short.contains("AAAA"),
            "and none of the document does: {}",
            short
        );
    }

    /// A cut inside a multi-byte character is a panic, not a truncation, so the boundary is found by
    /// character. The `e` is one byte and the `é` two, which puts a character boundary off every
    /// multiple of the cap.
    #[test]
    fn does_not_split_a_multi_byte_character() {
        let message = "é".repeat(LONGEST_CLAUSE_EXPLANATION * 2);

        let short = shortened(&message);

        assert!(short.ends_with("..."), "it was truncated: {}", short);
        assert!(
            short.chars().filter(|c| *c == 'é').count() <= LONGEST_CLAUSE_EXPLANATION,
            "to no more than the cap in characters: {}",
            short
        );
    }

    /// No whitespace to cut at leaves the hard limit, which is the point of having one.
    #[test]
    fn still_bounds_a_message_that_is_one_word() {
        let short = shortened(&"x".repeat(LONGEST_CLAUSE_EXPLANATION * 3));

        assert_eq!(LONGEST_CLAUSE_EXPLANATION + 3, short.len());
    }
}
