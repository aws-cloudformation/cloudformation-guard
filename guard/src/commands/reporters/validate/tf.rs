use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::eval_context::{
    simplified_json_from_root, BinaryComparison, ClauseReport, EventRecord, FileReport,
    InComparison, RuleReport, UnaryComparison,
};
use crate::rules::path_value::traversal::{Node, Traversal, TraversalResult};
use crate::rules::Status;
use fancy_regex::Regex;
use lazy_static::lazy_static;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::rc::Rc;

#[derive(Debug)]
pub(crate) struct TfAware<'reporter> {
    next: Option<&'reporter dyn Reporter>,
}

impl<'reporter> TfAware<'reporter> {
    pub(crate) fn new_with(next: &'reporter dyn Reporter) -> TfAware {
        TfAware { next: Some(next) }
    }
}

impl<'reporter> Reporter for TfAware<'reporter> {
    fn report(
        &self,
        _writer: &mut dyn Write,
        _status: Option<Status>,
        _failed_rules: &[&StatusContext],
        _passed_or_skipped: &[&StatusContext],
        _longest_rule_name: usize,
        _rules_file: &str,
        _data_file: &str,
        _data: &Traversal<'_>,
        _output_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        Ok(())
    }

    fn report_eval<'value>(
        &self,
        write: &mut dyn Write,
        status: Status,
        root_record: &EventRecord<'value>,
        rules_file: &str,
        data_file: &str,
        data_file_bytes: &str,
        data: &Traversal<'value>,
        output_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        let root = data.root().unwrap();
        if data.at("/resource_changes", root).is_ok() {
            let failure_report = simplified_json_from_root(root_record)?;
            match output_type {
                OutputFormatType::YAML => serde_yaml::to_writer(write, &failure_report)?,
                OutputFormatType::JSON => serde_json::to_writer_pretty(write, &failure_report)?,
                OutputFormatType::SingleLineSummary => {
                    single_line(write, data_file, rules_file, data, root, failure_report)?
                }
                OutputFormatType::Junit => unreachable!(),
                OutputFormatType::SARIF => unreachable!(),
            };

            Ok(())
        } else {
            self.next.map_or(Ok(()), |next| {
                next.report_eval(
                    write,
                    status,
                    root_record,
                    rules_file,
                    data_file,
                    data_file_bytes,
                    data,
                    output_type,
                )
            })
        }
    }
}

lazy_static! {
    static ref RESOURCE_CHANGE_EXTRACTION: Regex = Regex::new(
        "/resource_changes/(?P<index_or_name>[^/]+)/change/after/(?P<property_name>.*)?"
    )
    .ok()
    .unwrap();
}

use super::common::{
    populate_hierarchy_path_trees, IdentityHash, LocalResourceAggr, PathTree, RuleHierarchy,
};
use crate::rules::display::ValueOnlyDisplay;
use crate::rules::errors::Error;
use crate::rules::path_value::PathAwareValue;
use colored::*;
use nom::Slice;

fn single_line(
    writer: &mut dyn Write,
    data_file: &str,
    rules_file: &str,
    data: &Traversal<'_>,
    root: &Node<'_>,
    failure_report: FileReport<'_>,
) -> crate::rules::Result<()> {
    if failure_report.not_compliant.is_empty() {
        return Ok(());
    }

    let mut path_tree = PathTree::new();
    let mut hierarchy = RuleHierarchy::new();
    let root_node = std::rc::Rc::new(String::from(""));
    for each_rule in &failure_report.not_compliant {
        populate_hierarchy_path_trees(each_rule, root_node.clone(), &mut path_tree, &mut hierarchy);
    }

    let mut by_resources = HashMap::new();
    for (key, value) in path_tree.range(String::from("/resource_changes/")..) {
        let resource_ptr = match RESOURCE_CHANGE_EXTRACTION.captures(key) {
            Ok(Some(cap)) => cap.name("index_or_name").unwrap().as_str(),
            Ok(None) => unreachable!(),
            Err(e) => return Err(Error::from(Box::new(e))),
        };

        let address = format!("/resource_changes/{}", resource_ptr);
        let resource = match data.at(&address, root)? {
            TraversalResult::Value(n) => n,
            _ => unreachable!(),
        };
        let addr = match data.at("0/address", resource)? {
            TraversalResult::Value(n) => match n.value() {
                PathAwareValue::String((_, rt)) => rt.as_str(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        let dot_sep = addr.find('.').unwrap();
        let (resource_type, resource_name) = (addr.slice(0..dot_sep), addr.slice(dot_sep + 1..));
        let resource_aggr = by_resources
            .entry(resource_name)
            .or_insert(LocalResourceAggr {
                name: String::from(resource_name),
                resource_type,
                cdk_path: None,
                clauses: HashSet::new(),
                paths: BTreeSet::new(),
            });

        for node in value.iter() {
            resource_aggr
                .clauses
                .insert(IdentityHash { key: node.clause });
            resource_aggr.paths.insert(node.path.as_ref().clone());
        }
    }

    writeln!(
        writer,
        "Evaluating data {} against rules {}",
        data_file, rules_file
    )?;
    let num_of_resources = format!("{}", by_resources.len()).bold();
    writeln!(
        writer,
        "Number of non-compliant resources {}",
        num_of_resources
    )?;
    for (_, resource) in by_resources {
        writeln!(writer, "Resource = {} {{", resource.name.yellow().bold())?;
        let prefix = String::from("  ");
        writeln!(
            writer,
            "{prefix}{0:<width$}= {rt}",
            "Type",
            prefix = prefix,
            width = 10,
            rt = resource.resource_type,
        )?;
        let cdk_path = resource.cdk_path.as_ref().map_or("", |p| *p);
        if !cdk_path.is_empty() {
            writeln!(
                writer,
                "{prefix}{0:<width$}= {cdk}",
                "CDK-Path",
                prefix = prefix,
                width = 10,
                cdk = cdk_path
            )?;
        }
        for each_rule in &failure_report.not_compliant {
            let rule_name = match each_rule {
                ClauseReport::Rule(RuleReport { name, .. }) => format!("/{}", name),
                _ => unreachable!(),
            };

            let range = resource
                .paths
                .range(rule_name.clone()..)
                .take_while(|p| p.starts_with(&rule_name))
                .count();
            if range > 0 {
                struct ErrWriter {}
                impl super::common::ComparisonErrorWriter for ErrWriter {
                    fn binary_error_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _cr: &ClauseReport<'_>,
                        bc: &BinaryComparison,
                        prefix: &str,
                    ) -> crate::rules::Result<usize> {
                        let width = "PropertyPath".len() + 4;
                        let from = &bc.from.self_path().0;
                        let to = &bc.to.self_path().0;
                        let resource_based = if from.starts_with("/resource_changes") {
                            from.as_str()
                        } else {
                            to.as_str()
                        };
                        let (_res, property) = match resource_based.find("change/after/") {
                            Some(idx) => resource_based.split_at(idx),
                            None => (resource_based, ""),
                        };

                        let property = property.slice("change/after/".len()..).replace('/', ".");
                        writeln!(
                            writer,
                            "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}\n{prefix}{val:<width$}= {value}\n{prefix}{cw:<width$}= {with}",
                            width=width,
                            pp="PropertyPath",
                            op="Operator",
                            val="Value",
                            cw="ComparedWith",
                            prefix=prefix,
                            path=property,
                            value=ValueOnlyDisplay(Rc::clone(&bc.from)),
                            cmp=crate::rules::eval_context::cmp_str(bc.comparison),
                            with=ValueOnlyDisplay(Rc::clone(&bc.to))
                        )?;
                        Ok(width)
                    }

                    fn binary_error_in_msg(
                        &mut self,
                        _: &mut dyn Write,
                        _: &ClauseReport<'_>,
                        _: &InComparison,
                        _: &str,
                    ) -> crate::rules::Result<usize> {
                        todo!()
                    }

                    fn unary_error_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _cr: &ClauseReport<'_>,
                        re: &UnaryComparison,
                        prefix: &str,
                    ) -> crate::rules::Result<usize> {
                        let resource_based = re.value.self_path().0.as_str();
                        let (_res, property) = match resource_based.find("changes/after/") {
                            Some(idx) => resource_based.split_at(idx),
                            None => (resource_based, ""),
                        };

                        let property = property.replace('/', ".");
                        let width = "PropertyPath".len() + 4;
                        writeln!(
                            writer,
                            "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}",
                            width = width,
                            pp = "PropertyPath",
                            op = "Operator",
                            prefix = prefix,
                            path = property,
                            cmp = crate::rules::eval_context::cmp_str(re.comparison),
                        )?;
                        Ok(width)
                    }
                }
                let mut err_writer = ErrWriter {};
                super::common::pprint_clauses(
                    writer,
                    each_rule,
                    &resource,
                    prefix.clone(),
                    &mut err_writer,
                )?;
                //                pprint_clauses(
                //                    writer,
                //                    each_rule,
                //                    &resource,
                //                    prefix.clone()
                //                )?;
            }
        }
        writeln!(writer, "}}")?;
    }
    Ok(())
}
