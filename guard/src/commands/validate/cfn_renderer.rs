use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;

use colored::*;
use lazy_static::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Renderer};
use crate::commands::validate::common::{find_all_failing_clauses, NameInfo, GenericRenderer, StructuredSummary, StructureType};
use crate::rules::errors::{Error, ErrorKind};

use super::EvaluationType;

lazy_static! {
    static ref CFN_RESOURCES: Regex = Regex::new(r"^/Resources/(?P<name>[^/]+)/(?P<rest>.*$)").ok().unwrap();
}

#[derive(Debug)]
pub(crate) struct CfnRender<'a> {
    data_file_name: &'a str,
    rules_file_name: &'a str,
    output_format_type: OutputFormatType,
    render: Box<dyn GenericRenderer>,
}

impl<'a> CfnRender<'a> {
    pub(crate) fn new<'r>(data_file_name: &'r str,
                          rules_file_name: &'r str,
                          output_format_type: OutputFormatType) -> CfnRender<'r> {
        CfnRender {
            data_file_name,
            rules_file_name,
            output_format_type,
            render: match output_format_type {
                OutputFormatType::SingleLineSummary => Box::new(SingleLineRenderer{}) as Box<dyn GenericRenderer>,
                OutputFormatType::JSON => Box::new(StructuredSummary::new(StructureType::JSON)) as Box<dyn GenericRenderer>,
                OutputFormatType::YAML => Box::new(StructuredSummary::new(StructureType::YAML)) as Box<dyn GenericRenderer>,
            }
        }
    }
}

impl<'a> Renderer for CfnRender<'a> {
    fn render(&self,
              writer: &mut dyn Write,
              failed_rules: &[&StatusContext],
              _passed: &[&StatusContext],
              longest_rule_name: usize) -> crate::rules::Result<()> {
        if !failed_rules.is_empty() {
            let mut by_resource_name = HashMap::new();
            for each_failed_rule in failed_rules {
                let failed = find_all_failing_clauses(each_failed_rule);
                for each_failing_clause in failed {
                    match each_failing_clause.eval_type {
                        EvaluationType::Clause |
                        EvaluationType::BlockClause => {
                            if each_failing_clause.from.is_some() {
                                let mut resource_info = super::common::extract_name_info(
                                    &each_failed_rule.context, each_failing_clause)?;
                                let (resource_name, property_path) = match CFN_RESOURCES.captures(&resource_info.path) {
                                    Some(caps) => {
                                        (caps["name"].to_string(), caps["rest"].replace("/", "."))
                                    },
                                    None => return Err(Error::new(ErrorKind::IncompatibleRetrievalError(
                                        "Expecting CFN Template format for errors".to_string()
                                    )))
                                };
                                resource_info.path = property_path;
                                by_resource_name.entry(resource_name).or_insert(Vec::new()).push(resource_info);
                            }
                        },

                        _ => unreachable!()
                    }
                }
            }
            self.render.render(writer, self.rules_file_name, self.data_file_name, by_resource_name, longest_rule_name)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SingleLineRenderer {}

impl super::common::GenericRenderer for SingleLineRenderer {
    fn render(&self,
              writer: &mut dyn Write,
              rules_file_name: &str,
              template_file_name: &str,
              by_resource_name: HashMap<String, Vec<NameInfo<'_>>>,
              longest_rule_len: usize) -> crate::rules::Result<()>
    {
        writeln!(writer, "Evaluation against template {}, number of resource failures = {}", template_file_name, by_resource_name.len())?;
        writeln!(writer, "-")?;
        for (resource, info) in by_resource_name.iter() {
            writeln!(writer, "Resource {}, failed due to the following checks", resource)?;
            for each in info {
                let (did_or_didnt, operation, cmp) = match &each.comparison {
                    Some((cmp, not)) => {
                        if *not {
                            ("did", format!("NOT {}", cmp), Some(cmp))
                        } else {
                            ("did not", format!("{}", cmp), Some(cmp))
                        }
                    },
                    None => {
                        ("did not", "NONE".to_string(), None)
                    }
                };
                match cmp {
                    None => {
                        // Block Clause retrieval error
                        writeln!(writer, "{0}/{1:<2$}{3} failed due to retrieval error, stopped at [{4}]. Error Message = [{5}]",
                                 rules_file_name,
                                 each.rule,
                                 longest_rule_len+4,
                                 operation,
                                 each.from,
                                 each.message.replace("\n", ";"))?;
                    },

                    Some(cmp) => {
                        if cmp.is_unary() {
                            writeln!(writer, "{0}/{1:<2$}{3} failed on value [{4}] at path {5}. Error Message [{6}]",
                                     rules_file_name,
                                     each.rule,
                                     longest_rule_len+4,
                                     operation,
                                     each.from,
                                     each.path,
                                     each.message.replace("\n", ";"))?;
                        }
                        else {
                            writeln!(writer, "{0}/{1:<2$}{3} failed on value [{4}] at property path {5} {6} match with [{7}]. Error Message [{8}]",
                                     rules_file_name,
                                     each.rule,
                                     longest_rule_len+4,
                                     operation,
                                     each.from,
                                     each.path,
                                     did_or_didnt,
                                     match &each.to { Some(v) => v, None => &serde_json::Value::Null },
                                     each.message.replace("\n", ";"))?;
                        }
                    }

                }
            }
            writeln!(writer, "-")?;
        }
        Ok(())
    }
}
