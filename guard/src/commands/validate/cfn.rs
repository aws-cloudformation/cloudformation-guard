use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::path_value::traversal::{Traversal, TraversalResult};
use crate::rules::eval_context::{ClauseReport, EventRecord, UnaryCheck, simplifed_json_from_root, GuardClauseReport, UnaryComparison, ValueUnResolved, BinaryCheck, BinaryComparison, RuleReport, ValueComparisons, FileReport, InComparison};
use std::io::Write;
use crate::rules::Status;
use crate::commands::tracker::StatusContext;
use std::collections::{HashMap, HashSet, BTreeMap, BTreeSet};
use lazy_static::lazy_static;
use crate::rules::UnResolved;
use regex::Regex;
use crate::rules::path_value::PathAwareValue;
use crate::rules::errors::{Error, ErrorKind};
use serde::{Serialize, Serializer};
use crate::rules::values::CmpOperator;
use std::hash::{Hash, Hasher};
use serde::ser::{SerializeStruct, SerializeMap};

use std::ops::{Deref, DerefMut};
use std::cmp::{Ordering, max};
use colored::*;
use crate::rules::display::ValueOnlyDisplay;

use super::common::{
    LocalResourceAggr,
    IdentityHash,
    RuleHierarchy,
    PathTree,
    Node,
    populate_hierarchy_path_trees
};
use crate::rules::exprs::SliceDisplay;


lazy_static! {
    static ref CFN_RESOURCES: Regex = Regex::new(r"^/Resources/(?P<name>[^/]+)(/?P<rest>.*$)?").ok().unwrap();
}

#[derive(Debug)]
pub(crate) struct CfnAware<'reporter>{
    next: Option<&'reporter dyn Reporter>,
}

impl<'reporter> CfnAware<'reporter> {
    pub(crate) fn new() -> CfnAware<'reporter> {
        CfnAware{ next: None }
    }

    pub(crate) fn new_with(next: &'reporter dyn Reporter) -> CfnAware {
        CfnAware { next: Some(next) }
    }
}

impl<'reporter> Reporter for CfnAware<'reporter> {

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
        _output_format_type: OutputFormatType) -> crate::rules::Result<()> {
        Ok(())
    }

    fn report_eval<'value>(
        &self,
        write: &mut dyn Write,
        status: Status,
        root_record: &EventRecord<'value>,
        rules_file: &str,
        data_file: &str,
        data_content: &[u8],
        data: &Traversal<'value>,
        outputType: OutputFormatType) -> crate::rules::Result<()> {

        let root = data.root().unwrap();
        if let Ok(_) = data.at("/Resources", root) {
            let failure_report = simplifed_json_from_root(root_record)?;
            Ok(match outputType {
                OutputFormatType::YAML => serde_yaml::to_writer(write, &failure_report)?,
                OutputFormatType::JSON => serde_json::to_writer_pretty(write, &failure_report)?,
                OutputFormatType::SingleLineSummary => single_line(
                    write, data_file, rules_file, data, failure_report)?,
            })
        }
        else {
            self.next.map_or(
                Ok(()), |next|
                next.report_eval(
                    write,
                    status,
                    root_record,
                    rules_file,
                    data_file,
                    data_content,
                    data,
                    outputType)
                )
        }
    }
}

fn binary_err_msg(
    writer: &mut dyn Write,
    _clause: &ClauseReport<'_>,
    bc: &BinaryComparison<'_>,
    prefix: &str) -> crate::rules::Result<usize> {
    let width = "PropertyPath".len() + 4;
    writeln!(
        writer,
        "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}\n{prefix}{val:<width$}= {value}\n{prefix}{cw:<width$}= {with}",
        width=width,
        pp="PropertyPath",
        op="Operator",
        val="Value",
        cw="ComparedWith",
        prefix=prefix,
        path=bc.from.self_path(),
        value=ValueOnlyDisplay(bc.from),
        cmp=crate::rules::eval_context::cmp_str(bc.comparison),
        with=ValueOnlyDisplay(bc.to)
    )?;
    Ok(width)
}

fn unary_err_msg(
    writer: &mut dyn Write,
    _clause: &ClauseReport<'_>,
    re: &UnaryComparison<'_>,
    prefix: &str) -> crate::rules::Result<usize> {
    let width = "PropertyPath".len() + 4;
    writeln!(
        writer,
        "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}",
        width=width,
        pp="PropertyPath",
        op="Operator",
        prefix=prefix,
        path=re.value.self_path(),
        cmp=crate::rules::eval_context::cmp_str(re.comparison),
    )?;
    Ok(width)
}

fn single_line(writer: &mut dyn Write,
               data_file: &str,
               rules_file: &str,
               data: &Traversal<'_>,
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

    let root = data.root().unwrap();
    let mut by_resources = HashMap::new();
    for (key, value) in path_tree.range("/Resources/"..) {
        let resource_name = match CFN_RESOURCES.captures(*key) {
            Some(cap) => {
                cap.get(1).unwrap().as_str()
            },
            _ => unreachable!()
        };
        let resource_aggr = by_resources.entry(resource_name).or_insert_with(|| {
            let path = format!("/Resources/{}", resource_name);
            let resource = match data.at(&path, root) {
                Ok(TraversalResult::Value(val)) => val,
                _ => unreachable!()
            };
            let resource_type = match data.at("0/Type", resource) {
                Ok(TraversalResult::Value(val)) => match val.value() {
                    PathAwareValue::String((_, v)) => v.as_str(),
                    _ => unreachable!()
                }
                _ => unreachable!()
            };
            let cdk_path = match data.at("0/Metadata/aws:cdk:path", resource) {
                Ok(TraversalResult::Value(val)) => match val.value() {
                    PathAwareValue::String((_, v)) => Some(v.as_str()),
                    _ => unreachable!()
                },
                _ => None
            };
            LocalResourceAggr {
                name: resource_name,
                resource_type,
                cdk_path,
                clauses: HashSet::new(),
                paths: BTreeSet::new(),
            }
        });

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
                impl super::common::ComparionErrorWriter<'_> for ErrWriter {
                    fn binary_error_msg(
                        &self,
                        writer: &mut dyn Write,
                        cr: &ClauseReport<'_>,
                        bc: &BinaryComparison<'_>,
                        prefix: &str) -> crate::rules::Result<usize> {
                        binary_err_msg(
                            writer,
                            cr,
                            bc,
                            prefix
                        )
                    }

                    fn binary_error_in_msg(
                        &self,
                        writer: &mut dyn Write,
                        cr: &ClauseReport<'_>,
                        bc: &InComparison<'_>,
                        prefix: &str) -> crate::rules::Result<usize> {
                        let cut_off = max(bc.to.len(), 5);
                        let mut collected = Vec::with_capacity(10);
                        for (idx, each) in bc.to.iter().enumerate() {
                            collected.push(ValueOnlyDisplay(*each));
                            if idx >= cut_off {
                                break;
                            }
                        }
                        let collected = format!("{:?}", collected);
                        let width = "PropertyPath".len() + 4;
                        if cut_off >= bc.to.len() {
                            writeln!(
                                writer,
                                "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}\n{prefix}{val:<width$}= {value}\n{prefix}{cw:<width$}= {with}",
                                width=width,
                                pp="PropertyPath",
                                op="Operator",
                                val="Value",
                                cw="ComparedWith",
                                prefix=prefix,
                                path=bc.from.self_path(),
                                value=ValueOnlyDisplay(bc.from),
                                cmp=crate::rules::eval_context::cmp_str(bc.comparison),
                                with=collected
                            )?;
                        } else {
                            writeln!(
                                writer,
                                "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}\n{prefix}{total_name:<width$}= {total}\n{prefix}{val:<width$}= {value}\n{prefix}{cw:<width$}= {with}",
                                width=width,
                                pp="PropertyPath",
                                op="Operator",
                                val="Value",
                                total_name="Total",
                                cw="ComparedWith",
                                prefix=prefix,
                                path=bc.from.self_path(),
                                value=ValueOnlyDisplay(bc.from),
                                cmp=crate::rules::eval_context::cmp_str(bc.comparison),
                                total=bc.to.len(),
                                with=collected
                            )?;
                        }
                        Ok(width)

                    }


                    fn unary_error_msg(
                        &self,
                        writer: &mut dyn Write,
                        cr: &ClauseReport<'_>,
                        re: &UnaryComparison<'_>,
                        prefix: &str) -> crate::rules::Result<usize> {
                        unary_err_msg(
                            writer,
                            cr,
                            re,
                            prefix
                        )
                    }
                }
                let err_writer = ErrWriter{};
                super::common::pprint_clauses(
                    writer,
                    each_rule,
                    &resource,
                    prefix.clone(),
                    &err_writer
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