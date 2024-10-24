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
    artifacts: Vec<SarifArtifact>,
    results: SarifResults,
}

impl From<&[FileReport<'_>]> for SarifRun {
    fn from(value: &[FileReport<'_>]) -> Self {
        let mut sarif_unique_artifacts: HashSet<&str> = HashSet::new();

        value
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
            })
    }
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

fn extract_rule_id(rule_name: &str) -> String {
    let first_part_of_rule_file_name: Vec<&str> = rule_name.split('.').collect();

    first_part_of_rule_file_name
        .first()
        .map_or(String::default(), |&s| s.to_uppercase())
}

fn sanitize_path(path: &str) -> String {
    path.strip_prefix('/').unwrap_or(path).to_string()
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
