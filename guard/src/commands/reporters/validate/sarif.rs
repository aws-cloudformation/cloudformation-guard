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
/// No `locations`. The member exists, but in this code path a rules file is known only by its bare
/// file name -- `get_file_name(file, file)` reduces it to the basename -- which is not something a
/// consumer can resolve to an artifact. Naming the file in the message says what is known without
/// asserting a location that is not.
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
        failure
            .get_message()
            .into_iter()
            .fold(SarifResults::default(), |mut results, messages| {
                let mut rule_id = String::new();
                if let rules::eval_context::ClauseReport::Rule(rule) = failure {
                    rule_id = extract_rule_id(rule.name)
                }

                let (start_line, start_column) = match messages.location {
                    Some(location) => (location.line, location.col),
                    None => (0, 0),
                };

                let message = SarifMessage {
                    text: handle_messages(&messages),
                };

                let locations = generate_sarif_locations(name, start_line, start_column);

                results.push(SarifResult {
                    rule_id,
                    message,
                    level: String::from("error"),
                    locations,
                });

                results
            })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
    start_column: usize,
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

fn handle_messages(messages: &Messages) -> String {
    format!(
        "{} {}",
        messages.error_message.clone().unwrap_or_default(),
        messages.custom_message.clone().unwrap_or_default()
    )
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

fn generate_sarif_locations(
    path_string: &str,
    start_line: usize,
    start_column: usize,
) -> Vec<SarifLocation> {
    vec![SarifLocation {
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: sanitize_path(path_string),
            },
            region: SarifRegion {
                start_line: start_line.max(1),
                start_column: start_column.max(1),
            },
        },
    }]
}
