use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use crate::rules::{
    self,
    eval_context::{ClauseReport, FileReport, Messages},
    Status,
};
use serde::{Deserialize, Serialize};

const SARIF_SCHEMA_URL: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
const SARIF_SCHEMA_VERSION: &str = "2.1.0";
const ORGANIZATION: &str = "Amazon Web Services";
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct SarifRun {
    tool: SarifTool,
    /// Omitted entirely when the run had nothing to report about itself, which keeps a clean run's
    /// document byte-for-byte what it was. SARIF permits that: `runs.invocations` is not in `run`'s
    /// required set, and an absent array-valued property defaults to empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    invocations: Vec<SarifInvocation>,
    artifacts: Vec<SarifArtifact>,
    results: SarifResults,
}

impl From<&[FileReport<'_>]> for SarifRun {
    fn from(value: &[FileReport<'_>]) -> Self {
        let mut sarif_unique_artifacts: HashSet<&str> = HashSet::new();

        let mut run = value
            .iter()
            .filter(|report| matches!(report.status, Status::FAIL))
            .fold(SarifRun::default(), |mut runs, report| {
                if !sarif_unique_artifacts.contains(report.name) && !report.name.is_empty() {
                    sarif_unique_artifacts.insert(report.name);
                    let uri = sanitize_path(report.name);
                    runs.insert_artifact(uri);
                }

                report.not_compliant.iter().for_each(|failure| {
                    let sarif_results = SarifResults::from((failure, report.name));
                    runs.extend_results(sarif_results);
                });

                runs
            });

        // Outside the fold above, which only visits FAIL reports. A run whose rules did not parse
        // evaluated nothing, so every report is SKIP and the fold sees none of them -- which is
        // exactly how an unreadable ruleset came to produce the same document as a clean run.
        run.invocations = build_invocations(value);

        run
    }
}

/// The single `invocation` describing this run, when there is something about the run itself to
/// report. Empty otherwise, so the successful path is unchanged.
///
/// A rules file that will not parse is a fact about how the tool was configured rather than a
/// finding about the template under analysis, and SARIF separates the two. Filing it as a `result`
/// would make it an alert against the customer's code, which is both wrong and, for a consumer that
/// tracks alerts across runs, actively misleading.
fn build_invocations(reports: &[FileReport<'_>]) -> Vec<SarifInvocation> {
    let mut seen: HashSet<&str> = HashSet::new();
    let notifications = reports
        .iter()
        .flat_map(|report| report.rule_file_errors.iter())
        // `rule_file_errors` is repeated in every file report, because the json and yaml document is
        // an array of those and has nowhere above them to carry it. One notification per rules file
        // is what belongs here.
        .filter(|rule_file_error| seen.insert(&rule_file_error.file_name))
        .map(|rule_file_error| SarifNotification {
            level: String::from("error"),
            message: SarifMessage {
                text: format!(
                    "Rules file {} could not be parsed, so none of its rules were evaluated: {}",
                    rule_file_error.file_name, rule_file_error.error
                ),
            },
        })
        .collect::<Vec<_>>();

    if notifications.is_empty() {
        return vec![];
    }

    vec![SarifInvocation {
        execution_successful: false,
        tool_configuration_notifications: notifications,
    }]
}

impl SarifRun {
    fn insert_artifact(&mut self, location: String) {
        self.artifacts.push(SarifArtifact {
            location: SarifArtifactLocation { uri: location },
        })
    }

    fn extend_results(&mut self, results: SarifResults) {
        self.results.extend(results);
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    semantic_version: String,
    full_name: String,
    organization: String,
    download_uri: String,
    information_uri: String,
    short_description: SarifMessage,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifArtifact {
    location: SarifArtifactLocation,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifMessage {
    text: String,
}

/// SARIF's place for what happened to the tool, as opposed to what the tool found.
///
/// `executionSuccessful` is the one member `invocation` requires, and it is the property a consumer
/// reads to decide whether an empty `results` array means "nothing wrong" or "nothing checked".
/// `toolConfigurationNotifications` is for "conditions detected by the tool that are relevant to the
/// tool's configuration", which is what an unreadable rules file is -- the ruleset is Guard's
/// configuration. Its sibling `toolExecutionNotifications` is for runtime conditions during the
/// analysis, and a file rejected before any rule was loaded is not one of those.
///
/// Source: the SARIF 2.1.0 schema this report already declares in `$schema`,
/// <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json>.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tool_configuration_notifications: Vec<SarifNotification>,
}

/// A `notification`: per SARIF's own terminology a "reporting item that describes a condition
/// encountered by a tool during its execution", as distinct from a `result`.
///
/// `message` is the only required member. `level` is given explicitly because it defaults to
/// `warning`, and a ruleset that could not be read is an error.
///
/// No `locations`. The member exists, and a rules file is now known by the path it was given rather
/// than by its basename, but that path is still whatever string the caller passed -- relative to a
/// working directory the consumer of this report does not have, when the caller passed a relative one.
/// SARIF wants a `uri` a consumer can resolve to an artifact, and this is not reliably one. Naming the
/// file in the message says what is known without asserting a location that is not.
#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifNotification {
    level: String,
    message: SarifMessage,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct SarifResults(Vec<SarifResult>);

impl IntoIterator for SarifResults {
    type Item = SarifResult;
    type IntoIter = <Vec<SarifResult> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Deref for SarifResults {
    type Target = Vec<SarifResult>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SarifResults {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<(&ClauseReport<'_>, &str)> for SarifResults {
    fn from(val: (&ClauseReport<'_>, &str)) -> Self {
        let (failure, name) = val;
        // A failing rule is never absent from the report: where no check under it says anything (a rule
        // that failed on its own `when`, a call whose `<< >>` body stands over a silent failing block),
        // the rule record's own message is the result, as it is the failure text of the JUnit report
        // (`ClauseReport::get_message_with_rule_records`). It carries a refusal the rule's condition met
        // too (`; the condition also met: ..`), since the console's `Warning:` line no longer does.
        failure
            .get_message_with_rule_records_by_level()
            .into_iter()
            .fold(
                SarifResults::default(),
                |mut results, (messages, rule_level)| {
                    let mut rule_id = String::new();
                    if let rules::eval_context::ClauseReport::Rule(rule) = failure {
                        rule_id = extract_rule_id(rule.name)
                    }

                    let message = SarifMessage {
                        text: handle_messages(&messages, rule_level),
                    };

                    let locations =
                        generate_sarif_locations(name, messages.location.and_then(build_region));

                    results.push(SarifResult {
                        rule_id,
                        message,
                        level: String::from("error"),
                        locations,
                    });

                    results
                },
            )
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    /// Absent when the record carries no position. `region` is not in `physicalLocation`'s required
    /// set -- its only constraint is an `anyOf` demanding `address` or `artifactLocation`, and this
    /// always has the latter -- so a location without one is well formed and means "somewhere in this
    /// artifact".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
    /// Absent when the record's column is 0, Guard's marker for a position it does not have.
    /// `region`'s `anyOf` is satisfied by `startLine` alone, so a line without a column is well
    /// formed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_column: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifRule {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

impl SarifReport {
    pub(crate) fn new(reports: &[FileReport<'_>]) -> Self {
        Self {
            schema: String::from(SARIF_SCHEMA_URL),
            version: String::from(SARIF_SCHEMA_VERSION),
            runs: vec![SarifRun::from(reports)],
        }
    }
}

impl Default for SarifDriver {
    fn default() -> Self {
        Self {
            name: String::from(env!("CARGO_PKG_NAME")),
            semantic_version: env!("CARGO_PKG_VERSION").to_string(),
            full_name: format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"),),
            organization: String::from(ORGANIZATION),
            download_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
            information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
            short_description: SarifMessage {
                text: env!("CARGO_PKG_DESCRIPTION").to_string(),
            },
        }
    }
}

fn handle_messages(messages: &Messages, rule_level: bool) -> String {
    sarif_text(
        messages.error_message.as_deref(),
        messages.custom_message.as_deref(),
        rule_level,
    )
}

/// The text of a result. `rule_level` is decided where the result is built
/// (`ClauseReport::get_message_with_rule_records_by_level`), never from whether a field is `None`.
///
/// A clause or block result (`rule_level` false) keeps the text it always had, byte for byte: the error, a
/// space, the custom message, whatever either holds (`None` and an empty custom message both end the text
/// with that space, and a record with no error starts it with one).
///
/// A rule-level result (`rule_level` true: the rule's own record, a result of its own where no check beneath
/// speaks, with no clause text of its own to keep) is its parts joined by one space. A part that is empty or only
/// whitespace is no part, so a sentence with no body ends with no space and a body with no sentence starts
/// with none; a part is otherwise written as it is, so an author's body with spaces around it keeps them.
fn sarif_text(error: Option<&str>, custom: Option<&str>, rule_level: bool) -> String {
    match rule_level {
        false => format!(
            "{} {}",
            error.unwrap_or_default(),
            custom.unwrap_or_default()
        ),
        true => [error, custom]
            .iter()
            .flatten()
            .filter(|part| !part.trim().is_empty())
            .copied()
            .collect::<Vec<&str>>()
            .join(" "),
    }
}

#[cfg(test)]
mod sarif_text_tests {
    use super::sarif_text;

    /// A clause or block result keeps its released text byte for byte, and only a rule-level result joins
    /// its parts without a trailing or leading separator. The clause rows: an error and no custom message
    /// ends with a space (the common case, `<< >>` absent), an empty custom message the same, both parts
    /// join by one space, and no error starts with one. The rule-level rows: a sentence alone, a body alone,
    /// both, an empty or whitespace-only part dropped, and an author's body with surrounding spaces kept.
    ///
    /// Fails when a clause row loses its trailing space (a SARIF-wide text change), or when a
    /// rule-level row ends or starts with a separator.
    #[test]
    fn a_clause_result_keeps_its_released_text_and_a_rule_level_result_joins_its_parts() {
        assert_eq!(
            [
                "error ",
                "error ",
                "error body",
                " body",
                "sentence",
                "body",
                "sentence body",
                "sentence",
                "sentence",
                "",
                " body  ",
            ]
            .map(String::from)
            .to_vec(),
            vec![
                sarif_text(Some("error"), None, false),
                sarif_text(Some("error"), Some(""), false),
                sarif_text(Some("error"), Some("body"), false),
                sarif_text(None, Some("body"), false),
                sarif_text(Some("sentence"), None, true),
                sarif_text(None, Some("body"), true),
                sarif_text(Some("sentence"), Some("body"), true),
                sarif_text(Some("sentence"), Some(""), true),
                sarif_text(Some("sentence"), Some("  "), true),
                sarif_text(None, None, true),
                sarif_text(Some(""), Some(" body  "), true),
            ]
        );
    }
}

/// The rule's name, unchanged.
///
/// `ruleId` is the identity a SARIF consumer keys on: code scanning matches alerts across runs by
/// it, and suppressions and baselines are written against it. It has to be the name the rule
/// actually has.
///
/// What was here read a rule name as though it were a file name -- `split('.')`, take the first
/// part, upper-case it -- and so produced neither. `s3_versioning_enabled` came out as
/// `S3_VERSIONING_ENABLED`, a name that appears in no rules file and cannot be suppressed by name.
/// A rule declared at file scope in `My.Dotted-Rules.guard` is named
/// `My.Dotted-Rules.guard/default`, and came out as `MY`: the file stem rather than the rule, cut at
/// the first dot, colliding with every other rules file whose name starts `My.`.
///
/// Returning the name verbatim also makes the id cross-referenceable, which is the practical loss.
/// json and yaml report this same finding under `"name"` and the console prints it after `Rule =`;
/// all three now agree with sarif for the same run. Taking the half after `.guard/` -- which is what
/// junit's `<failure message>` does -- was rejected: it reduces every file-scoped rule to `default`,
/// so two rules files collide, and it matches none of the other three formats.
fn extract_rule_id(rule_name: &str) -> String {
    rule_name.to_string()
}

/// An absolute path as a `file://` URI, percent-encoded per segment. Anything that is not an
/// absolute path is returned unchanged.
///
/// `artifactLocation.uri` is declared in the SARIF schema as "A string containing a valid relative or
/// absolute URI", with `"format": "uri-reference"`. What was here removed the leading `/` from a
/// path that `validate` has already canonicalised to absolute, which produces neither: not an
/// absolute URI, because it has no scheme, and not a usable relative reference, because there is no
/// `uriBaseId` -- nor any `runs[].originalUriBaseIds` -- to say what it is relative to. So
/// `/home/me/repo/template.yaml` was emitted as `home/me/repo/template.yaml`, which resolves to a
/// real file only against `/`.
///
/// That matters for the consumer this repository ships an Action for. GitHub code scanning
/// "interprets results that are reported with relative paths as relative to the root of the
/// repository analyzed", and separately states that "if a result contains an absolute URI, the URI is
/// converted to a relative URI" using the checkout path. A stripped absolute path names nothing at
/// the repository root, so the alert had no file to attach to; a `file://` URI is converted for us.
///
/// Adding a `uriBaseId` and an `originalUriBaseIds` entry was the alternative. It was rejected
/// because Guard does not know a repository root -- it is run against arbitrary paths -- so the base
/// would have to be invented. An absolute URI needs no base.
///
/// Percent-encoding is per segment rather than over the whole string, so the `/` separators survive.
/// Without it a path containing `#` is truncated at the fragment delimiter by any URI parser, `?`
/// starts a query, a space is not legal in a URI at all, and a literal `%` is an invalid escape.
fn sanitize_path(path: &str) -> String {
    if !path.starts_with('/') {
        return path.to_string();
    }

    let encoded = path
        .split('/')
        .map(|segment| urlencoding::encode(segment).into_owned())
        .collect::<Vec<String>>()
        .join("/");

    format!("file://{encoded}")
}

/// The region for a record that has a position, or `None` for one that does not.
///
/// What was here read the position as `(0, 0)` when the record carried none, then raised both to 1
/// with `.max(1)` to satisfy the schema's `"minimum": 1` on `startLine` and `startColumn`. That
/// turns "unknown" into "line 1, column 1", which a consumer renders as a real position. Measured on
/// a template whose `Resources` sits on line 23 behind a long header, every result reported
/// `{"startLine": 1, "startColumn": 1}` while the message text of the same result located the finding
/// at `L:22,C:11` -- so code scanning annotated the `AWSTemplateFormatVersion` line for a finding
/// about `Resources`.
///
/// Omitting is the correct alternative rather than a lesser one. A `physicalLocation` with no
/// `region` says "somewhere in this artifact", which is exactly what is known. A `startLine` of 1
/// says "here", and it is not here.
///
/// A location whose line is 0 is treated as no position for the same reason: `startLine` cannot be 0,
/// so there is no line to report, and clamping it would be the same fabrication.
fn build_region(location: crate::rules::path_value::Location) -> Option<SarifRegion> {
    if location.line < 1 {
        return None;
    }

    Some(SarifRegion {
        start_line: location.line,
        start_column: (location.col >= 1).then_some(location.col),
    })
}

fn generate_sarif_locations(path_string: &str, region: Option<SarifRegion>) -> Vec<SarifLocation> {
    vec![SarifLocation {
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: sanitize_path(path_string),
            },
            region,
        },
    }]
}

#[cfg(test)]
mod rule_record_results_tests {
    use super::SarifResults;
    use crate::rules::eval_context::{report_all_failed_clauses_for_rules, EventRecord};
    use crate::rules::{BlockCheck, CustomSlot, NamedStatus, RecordType, Status};

    fn block_check() -> BlockCheck {
        BlockCheck {
            status: Status::FAIL,
            at_least_one_matches: false,
            raised: false,
            message: None,
            refusal: false,
            custom_message: None,
            gate_mark: false,
            frame_reads: Vec::new(),
        }
    }

    /// A failing rule is never absent from the SARIF report. A call whose `<< >>` body stands over a
    /// silent failing block has no check under it (the body is the rule's text and no generic block entry
    /// is listed beside it), so the results must come from the rule's own record: one result, carrying the
    /// body. Read only through `get_message`, the rule had ZERO results where it had one before the
    /// entry was dropped.
    ///
    /// Fails when there is no result for the rule, or when a result lacks the body.
    #[test]
    fn a_call_with_a_body_over_a_silent_block_still_has_a_result() {
        const BODY: &str = "the author's own body";
        let silent = EventRecord {
            context: String::from("BlockGuardClause#2"),
            container: Some(RecordType::BlockGuardCheck(block_check())),
            children: vec![EventRecord {
                context: String::from("GuardBlockAccessClause#2"),
                container: Some(RecordType::GuardClauseBlockCheck(block_check())),
                children: vec![],
            }],
        };
        let call = EventRecord {
            context: String::from("inner"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "inner",
                status: Status::FAIL,
                message: Some(BODY.to_string()),
                slot: CustomSlot::Author,
                displaced: None,
                frame_reads: Vec::new(),
                ended_by_error: false,
            })),
            children: vec![silent],
        };
        let reports = report_all_failed_clauses_for_rules(&[call]);
        assert_eq!(1, reports.len(), "one rule report");
        let results = SarifResults::from((&reports[0], "template.yaml"));
        assert_eq!(
            (1, true),
            (
                results.len(),
                results
                    .iter()
                    .all(|result| result.message.text.contains(BODY)),
            ),
            "one result for the rule, carrying the author's body"
        );
    }

    /// A call with a `<< >>` body over a type block that has no sentence and holds a gate mark is still one
    /// result, carrying the author's body and the refusal the mark names, each once: the refusal is told by
    /// the rule's own sentence, and no entry for it fills the rule's checks, which would have made the
    /// clauses speak for the rule and dropped the body from the result.
    #[test]
    fn a_call_with_a_body_over_a_type_block_with_a_mark_keeps_its_body_and_names_the_refusal_once()
    {
        use crate::rules::TypeBlockCheck;
        const BODY: &str = "the author's own body";
        const MARK: &str = "the read of `A` was refused, at path /Resources/A/Tags";
        let mark = EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                raised: true,
                message: Some(MARK.to_string()),
                refusal: true,
                gate_mark: true,
                ..block_check()
            })),
            children: vec![],
        };
        let type_check = EventRecord {
            context: String::from("TypeBlock#S3"),
            container: Some(RecordType::TypeCheck(TypeBlockCheck {
                type_name: "AWS::S3::Bucket",
                block: BlockCheck {
                    raised: true,
                    ..block_check()
                },
            })),
            children: vec![EventRecord {
                context: String::from("TypeBlock#S3/0"),
                container: Some(RecordType::TypeBlock(Status::FAIL)),
                children: vec![EventRecord {
                    context: String::from("condition"),
                    container: Some(RecordType::TypeCondition(Status::FAIL)),
                    children: vec![mark],
                }],
            }],
        };
        let call = EventRecord {
            context: String::from("inner"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "inner",
                status: Status::FAIL,
                message: Some(BODY.to_string()),
                slot: CustomSlot::Author,
                displaced: None,
                frame_reads: Vec::new(),
                ended_by_error: false,
            })),
            children: vec![type_check],
        };
        let reports = report_all_failed_clauses_for_rules(&[call]);
        assert_eq!(1, reports.len(), "one rule report");
        let results = SarifResults::from((&reports[0], "template.yaml"));
        let text = results
            .iter()
            .map(|result| result.message.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            (1, 1, 1),
            (
                results.len(),
                text.matches(BODY).count(),
                text.matches(MARK).count()
            ),
            "one result with the body and the refusal once, in: {}",
            text
        );
    }

    /// The same call with a clause that reports beside the marked type block (the mixed shape: one resource's
    /// condition fails closed on a mark, another's body fails a clause): the checks say something, so the
    /// results are the checks' and the body is not a result. The mark's refusal is
    /// an entry of the checks, so the results hold the clause's text once and the mark's refusal once.
    ///
    /// Fails when the body appears because a mark exists, or the mark is missing or repeated.
    #[test]
    fn a_bodied_call_whose_clause_reports_beside_a_marked_type_block_names_the_mark_once() {
        use crate::rules::TypeBlockCheck;
        const BODY: &str = "the author's own body";
        const MARK: &str = "the read of `A` was refused, at path /Resources/A/Tags";
        const CLAUSE: &str = "the clause that reports, on its own";
        let flagged = |message: &str, gate_mark: bool| BlockCheck {
            raised: true,
            message: Some(message.to_string()),
            refusal: true,
            gate_mark,
            ..block_check()
        };
        let reports_a_clause = EventRecord {
            context: String::from("GuardAccessClause#blockB"),
            container: Some(RecordType::GuardClauseBlockCheck(flagged(CLAUSE, false))),
            children: vec![],
        };
        let mark = EventRecord {
            context: String::from("GuardBlockAccessClause#2"),
            container: Some(RecordType::GuardClauseBlockCheck(flagged(MARK, true))),
            children: vec![],
        };
        let type_check = EventRecord {
            context: String::from("TypeBlock#S3"),
            container: Some(RecordType::TypeCheck(TypeBlockCheck {
                type_name: "AWS::S3::Bucket",
                block: BlockCheck {
                    raised: true,
                    ..block_check()
                },
            })),
            children: vec![EventRecord {
                context: String::from("TypeBlock#S3/0"),
                container: Some(RecordType::TypeBlock(Status::FAIL)),
                children: vec![EventRecord {
                    context: String::from("condition"),
                    container: Some(RecordType::TypeCondition(Status::FAIL)),
                    children: vec![mark],
                }],
            }],
        };
        let call = EventRecord {
            context: String::from("inner"),
            container: Some(RecordType::RuleCheck(NamedStatus {
                name: "inner",
                status: Status::FAIL,
                message: Some(BODY.to_string()),
                slot: CustomSlot::Author,
                displaced: None,
                frame_reads: Vec::new(),
                ended_by_error: false,
            })),
            children: vec![reports_a_clause, type_check],
        };
        let reports = report_all_failed_clauses_for_rules(&[call]);
        assert_eq!(1, reports.len(), "one rule report");
        let results = SarifResults::from((&reports[0], "template.yaml"));
        let text = results
            .iter()
            .map(|result| result.message.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            (0, 1, 1),
            (
                text.matches(BODY).count(),
                text.matches(MARK).count(),
                text.matches(CLAUSE).count()
            ),
            "no body, and the mark's refusal and the clause once each, in: {}",
            text
        );
    }

    /// A rule's OWN record is rule-level wherever the rule sits. A parameterized rule is reachable only
    /// through a call, so its results are nested under the calling rule's report: one failing on its own
    /// `when` (the evaluator's sentence) and a call with a `<< >>` body over a silent block (the body alone)
    /// both take the join without a separator, with no trailing space after the sentence and no leading one
    /// before the body, while a clause result in the same report keeps its released text.
    ///
    /// Fails when the result text reads "sentence " or " body" (the nested record was written in
    /// the clause format), or when the clause result loses its trailing space.
    #[test]
    fn a_nested_rules_own_record_is_a_rule_level_result() {
        use crate::rules::eval_context::{ClauseReport, GuardBlockReport, Messages, RuleReport};
        const SENTENCE: &str = "the called rule's own sentence";
        const BODY: &str = "the author's body";
        let nested_rule = |custom: &str, slot: CustomSlot, checks: Vec<ClauseReport<'static>>| {
            ClauseReport::Rule(RuleReport {
                name: "inner",
                messages: Messages {
                    custom_message: Some(custom.to_string()),
                    error_message: None,
                    location: None,
                    refusal: false,
                    parts: None,
                },
                custom_slot: slot,
                checks,
                ..Default::default()
            })
        };
        let silent_block = ClauseReport::Block(GuardBlockReport {
            context: String::from("BlockGuardClause#2"),
            messages: Messages {
                custom_message: None,
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            unresolved: None,
        });
        let clause_result = ClauseReport::Block(GuardBlockReport {
            context: String::from("BlockGuardClause#3"),
            messages: Messages {
                custom_message: None,
                error_message: Some(String::from("a clause failed")),
                location: None,
                refusal: false,
                parts: None,
            },
            unresolved: None,
        });
        let texts = |inner: ClauseReport<'static>| {
            let outer = ClauseReport::Rule(RuleReport {
                name: "outer",
                checks: vec![inner],
                ..Default::default()
            });
            SarifResults::from((&outer, "template.yaml"))
                .iter()
                .map(|result| result.message.text.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            vec![
                SENTENCE.to_string(),
                BODY.to_string(),
                "a clause failed ".to_string()
            ],
            vec![
                texts(nested_rule(SENTENCE, CustomSlot::Evaluator, vec![])).remove(0),
                texts(nested_rule(BODY, CustomSlot::Author, vec![silent_block])).remove(0),
                texts(clause_result).remove(0),
            ],
            "the nested rule's own results carry no separator; the clause result keeps its trailing space"
        );
    }
}
