use crate::commands::validate::{Reporter, OutputFormatType};
use std::io::Write;
use crate::rules::Status;
use crate::commands::tracker::StatusContext;
use crate::rules::path_value::traversal::{Traversal, TraversalResult, Node};
use crate::rules::eval_context::{EventRecord, simplifed_json_from_root, ClauseReport, GuardBlockReport, GuardClauseReport, UnaryReport, UnaryCheck, FileReport, RuleReport, BinaryComparison, BinaryCheck, UnaryComparison, InComparison};
use std::collections::{HashMap, BTreeSet, HashSet};

use lazy_static::lazy_static;

#[derive(Debug)]
pub(crate) struct TfAware<'reporter>{
    next: Option<&'reporter dyn Reporter>,
}

impl<'reporter> TfAware<'reporter> {
    pub(crate) fn new() -> TfAware<'reporter> {
        TfAware{ next: None }
    }

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
        _output_type: OutputFormatType) -> crate::rules::Result<()> {
        Ok(())
    }

    fn report_eval<'value>(
        &self,
        _write: &mut dyn Write,
        _status: Status,
        _root_record: &EventRecord<'value>,
        _rules_file: &str,
        _data_file: &str,
        _data_file_bytes: &str,
        _data: &Traversal<'value>,
        _output_type: OutputFormatType) -> crate::rules::Result<()> {

        let root = _data.root().unwrap();
        let resource_changes = _data.at("/resource_changes", root)?;
        let tf_version = _data.at("/terraform_version", root)?;
        let is_tf_plan = match tf_version {
            TraversalResult::Value(version) => match resource_changes {
                TraversalResult::Value(_) => true,
                _ => false,
            },
            _ => false
        };

        if is_tf_plan {
            let failure_report = simplifed_json_from_root(_root_record)?;
            Ok(match _output_type {
                OutputFormatType::YAML => serde_yaml::to_writer(_write, &failure_report)?,
                OutputFormatType::JSON => serde_json::to_writer_pretty(_write, &failure_report)?,
                OutputFormatType::SingleLineSummary => single_line(
                    _write, _data_file, _rules_file, _data, root, failure_report)?,
            })
        }
        else {
            self.next.map_or(
                Ok(()),
                |next| next.report_eval(
                    _write,
                    _status,
                    _root_record,
                    _rules_file,
                    _data_file,
                    _data_file_bytes,
                    _data,
                    _output_type
                )
            )
        }
    }
}

struct PropertyError<'report, 'value: 'report> {
    property: &'value str,
    clause: &'report ClauseReport<'value>
}

struct ResourceView<'report, 'value: 'report> {
    name: &'value str,
    resource_type: &'value str,
    errors: indexmap::IndexMap<&'value str, PropertyError<'report, 'value>>
}

lazy_static! {
    static ref RESOURCE_CHANGE_EXTRACTION: regex::Regex = regex::Regex::new("/resource_changes/(?P<index_or_name>[^/]+)/change/after/(?P<property_name>.*)?")
        .ok().unwrap();
}

use super::common::{
    PathTree,
    RuleHierarchy,
    populate_hierarchy_path_trees,
    LocalResourceAggr,
    IdentityHash
};
use crate::rules::path_value::PathAwareValue;
use nom::{InputTakeAtPosition, Slice};
use colored::*;
use crate::rules::display::ValueOnlyDisplay;

fn single_line(writer: &mut dyn Write,
               data_file: &str,
               rules_file: &str,
               data: &Traversal<'_>,
               root: &Node<'_>,
               failure_report: FileReport<'_>) -> crate::rules::Result<()> {
    if failure_report.not_compliant.is_empty() {
        return Ok(())
    }

    let mut path_tree = PathTree::new();
    let mut hierarchy = RuleHierarchy::new();
    let root_node = std::rc::Rc::new(String::from(""));
    for each_rule in &failure_report.not_compliant {
        populate_hierarchy_path_trees(
            each_rule,
            root_node.clone(),
            &mut path_tree,
            &mut hierarchy
        );
    }

    let mut by_resources = HashMap::new();
    for (key, value) in path_tree.range("/resource_changes/"..) {
        let resource_ptr = match RESOURCE_CHANGE_EXTRACTION.captures(*key) {
            Some(cap) => cap.name("index_or_name").unwrap().as_str(),
            None => unreachable!()
        };
        let address = format!("/resource_changes/{}", resource_ptr);
        let resource = match data.at(&address, root)? {
            TraversalResult::Value(n) => n,
            _ => unreachable!()
        };
        let addr= match data.at("0/address", resource)? {
            TraversalResult::Value(n) => match n.value() {
                PathAwareValue::String((_, rt)) => rt.as_str(),
                _ => unreachable!()
            },
            _ => unreachable!()
        };
        let dot_sep = addr.find(".").unwrap();
        let (resource_type, resource_name) = (addr.slice(0..dot_sep), addr.slice(dot_sep+1..));
        let resource_aggr = by_resources.entry(resource_name).or_insert(
            LocalResourceAggr {
                name: resource_name,
                resource_type,
                cdk_path: None,
                clauses: HashSet::new(),
                paths: BTreeSet::new(),
            }
        );

        for node in value.iter() {
            resource_aggr.clauses.insert(IdentityHash{key: node.clause});
            resource_aggr.paths.insert(node.path.as_ref().clone());
        }
    }

    writeln!(writer, "Evaluating data {} against rules {}", data_file, rules_file)?;
    let num_of_resources = format!("{}", by_resources.len()).bold();
    writeln!(writer, "Number of non-compliant resources {}", num_of_resources)?;
    for (_, resource) in by_resources {
        writeln!(writer, "Resource = {} {{", resource.name.yellow().bold())?;
        let prefix = String::from("  ");
        writeln!(
            writer,
            "{prefix}{0:<width$}= {rt}",
            "Type",
            prefix=prefix,
            width=10,
            rt=resource.resource_type,
        )?;
        let cdk_path = resource.cdk_path.as_ref().map_or("", |p| *p);
        if !cdk_path.is_empty() {
            writeln!(
                writer,
                "{prefix}{0:<width$}= {cdk}",
                "CDK-Path",
                prefix=prefix,
                width=10,
                cdk=cdk_path
            )?;
        }
        for each_rule in &failure_report.not_compliant {
            let rule_name = match each_rule {
                ClauseReport::Rule(RuleReport{name, ..}) => format!("/{}", name),
                _ => unreachable!()
            };

            let range = resource.paths.range(rule_name.clone()..)
                .take_while(|p| p.starts_with(&rule_name)).count();
            if range > 0 {
                struct ErrWriter{};
                impl super::common::ComparisonErrorWriter for ErrWriter {
                    fn binary_error_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _cr: &ClauseReport<'_>,
                        bc: &BinaryComparison<'_>,
                        prefix: &str) -> crate::rules::Result<usize> {

                        let width = "PropertyPath".len() + 4;
                        let from = &bc.from.self_path().0;
                        let to = &bc.to.self_path().0;
                        let resource_based = if from.starts_with("/resource_changes") {
                            from.as_str()
                        } else {
                            to.as_str()
                        };
                        let (_res, property)  = match resource_based.find("change/after/") {
                            Some(idx) => resource_based.split_at(idx),
                            None => (resource_based, "")
                        };

                        let property = property.slice("change/after/".len()..).replace("/", ".");
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
                            value=ValueOnlyDisplay(bc.from),
                            cmp=crate::rules::eval_context::cmp_str(bc.comparison),
                            with=ValueOnlyDisplay(bc.to)
                        )?;
                        Ok(width)

                    }

                    fn binary_error_in_msg(&mut self, writer: &mut dyn Write, cr: &ClauseReport<'_>, bc: &InComparison<'_>, prefix: &str) -> crate::rules::Result<usize> {
                        todo!()
                    }


                    fn unary_error_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _cr: &ClauseReport<'_>,
                        re: &UnaryComparison<'_>,
                        prefix: &str) -> crate::rules::Result<usize> {
                        let width = "PropertyPath".len() + 4;
                        let resource_based = re.value.self_path().0.as_str();
                        let (_res, property)  = match resource_based.find("changes/after/") {
                            Some(idx) => resource_based.split_at(idx),
                            None => (resource_based, "")
                        };

                        let property = property.replace("/", ".");
                        let width = "PropertyPath".len() + 4;
                        writeln!(
                            writer,
                            "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}",
                            width=width,
                            pp="PropertyPath",
                            op="Operator",
                            prefix=prefix,
                            path=property,
                            cmp=crate::rules::eval_context::cmp_str(re.comparison),
                        )?;
                        Ok(width)

                    }
                }
                let mut err_writer = ErrWriter{};
                super::common::pprint_clauses(
                    writer,
                    each_rule,
                    &resource,
                    prefix.clone(),
                    &mut err_writer
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

