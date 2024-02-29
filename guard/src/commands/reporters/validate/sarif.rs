use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    rules::{
        self,
        eval_context::{FileReport, Messages},
        Status,
    },
    utils::writer::Writer,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifRun {
    tool: SarifTool,
    artifacts: Vec<SarifArtifact>,
    results: Vec<SarifResult>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifDriver {
    name: String,
    #[serde(rename = "semanticVersion")]
    semantic_version: String,
    #[serde(rename = "fullName")]
    full_name: String,
    organization: String,
    #[serde(rename = "downloadUri")]
    download_uri: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    #[serde(rename = "shortDescription")]
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
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn")]
    start_column: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
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

impl SarifRun {
    fn default() -> Self {
        Self {
            tool: SarifTool {
                driver: SarifDriver::default(),
            },
            artifacts: vec![],
            results: vec![],
        }
    }
}

impl SarifDriver {
    fn default() -> Self {
        Self {
            name: String::from("CloudFormation Guard CLI"),
            semantic_version: env!("CARGO_PKG_VERSION").to_string(),
            full_name: concat!("CloudFormation Guard CLI ", env!("CARGO_PKG_VERSION")).to_string(),
            organization: String::from("Amazon Web Services"),
            download_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
            information_uri: env!("CARGO_PKG_REPOSITORY").to_string(),
            short_description: SarifMessage {
                text: env!("CARGO_PKG_DESCRIPTION").to_string(),
            },
        }
    }
}

#[derive(Default)]
pub struct SarifReportBuilder {
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

impl SarifReportBuilder {
    pub fn new() -> SarifReportBuilder {
        SarifReportBuilder {
            schema: String::from(
                "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            ),
            version: String::from("2.1.0"),
            runs: vec![SarifRun::default()],
        }
    }

    fn extract_rule_id(&self, rule_name: &str) -> String {
        let first_part_of_rule_file_name: Vec<&str> = rule_name.split('.').collect();

        let uppercase_first_part_of_rule_file_name = {
            let maybe_first_part = first_part_of_rule_file_name
                .first()
                .map(|&s| s.to_uppercase());
            match maybe_first_part {
                Some(uppercased_part) => uppercased_part,
                None => String::new(),
            }
        };

        uppercase_first_part_of_rule_file_name
    }

    fn handle_messages(&self, messages: &Messages) -> String {
        match (&messages.error_message, &messages.custom_message) {
            (Some(err), Some(cust)) => format!("{} {}", err, cust),
            (Some(err), None) => err.to_string(),
            (None, Some(cust)) => cust.to_string(),
            _ => String::new(),
        }
    }

    fn sanitize_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            match path.strip_prefix('/') {
                Some(stripped) => stripped.to_string(),
                None => path.to_string(),
            }
        } else {
            path.to_string()
        }
    }

    fn generate_sarif_locations(
        &self,
        path_string: &str,
        start_line: usize,
        start_column: usize,
    ) -> Vec<SarifLocation> {
        vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: self.sanitize_path(path_string),
                },
                region: SarifRegion {
                    start_line: if start_line == 0 { 1 } else { start_line },
                    start_column: if start_column == 0 { 1 } else { start_column },
                },
            },
        }]
    }

    pub(crate) fn results(mut self, reports: &[FileReport]) -> SarifReportBuilder {
        let mut sarif_unique_artifacts: HashSet<String> = HashSet::new();

        reports.iter().for_each(|report| {
            if report.status == Status::FAIL {
                if !sarif_unique_artifacts.contains(report.name) && !report.name.is_empty() {
                    sarif_unique_artifacts.insert(report.name.to_string());
                    self.runs[0].artifacts.push(SarifArtifact {
                        location: SarifArtifactLocation {
                            uri: report.name.to_string(),
                        },
                    });
                }
                report.not_compliant.iter().for_each(|failure| {
                    failure.get_message().into_iter().for_each(|messages| {
                        let mut rule_id = String::new();
                        if let rules::eval_context::ClauseReport::Rule(rule) = failure {
                            rule_id = self.extract_rule_id(rule.name)
                        }
                        let mut start_line = 0;
                        let mut start_column = 0;
                        if let Some(location) = messages.location {
                            start_line = location.line;
                            start_column = location.col;
                        }
                        let message = SarifMessage {
                            text: self.handle_messages(&messages),
                        };
                        let locations =
                            self.generate_sarif_locations(report.name, start_line, start_column);

                        let sarif_result = SarifResult {
                            rule_id,
                            message,
                            level: String::from("error"),
                            locations,
                        };

                        self.runs[0].results.push(sarif_result);
                    })
                });
            }
        });

        self
    }

    pub fn serialize(self, writer: &mut &mut Writer) {
        let report = self.build();

        let _ = serde_json::to_writer_pretty(writer, &report);
    }

    pub fn build(self) -> SarifReport {
        SarifReport {
            runs: self.runs,
            schema: self.schema,
            version: self.version,
        }
    }
}
