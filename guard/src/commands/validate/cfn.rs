use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::path_value::traversal::{Traversal, TraversalResult};
use crate::rules::eval_context::{ClauseReport, EventRecord, UnaryCheck, simplifed_json_from_root, GuardClauseReport, UnaryComparison, ValueUnResolved, BinaryCheck, BinaryComparison, RuleReport, ValueComparisons, FileReport};
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
use std::cmp::Ordering;
use colored::*;
use crate::rules::display::ValueOnlyDisplay;

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

#[derive(Clone, Debug)]
struct Node<'report, 'value: 'report> {
    parent: std::rc::Rc<String>,
    path: std::rc::Rc<String>,
    clause: &'report ClauseReport<'value>,
}

type RuleHierarchy<
    'report,
    'value> =
    BTreeMap<
        std::rc::Rc<String>,
        std::rc::Rc<Node<'report, 'value>>
    >;

type PathTree<
    'report,
    'value> =
    BTreeMap<
        &'value str,
        Vec<std::rc::Rc<Node<'report, 'value>>>
    >;

fn insert_into_trees<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    parent: std::rc::Rc<String>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>)
{
    let path = std::rc::Rc::new(clause.key(&parent));
    let node = std::rc::Rc::new(Node {
        parent, path: path.clone(), clause
    });
    hierarchy.insert(path, node.clone());

    if let Some(from) = clause.value_from() {
        let path = from.self_path().0.as_str();
        path_tree.entry(path).or_insert(vec![]).push(node);
    }
}

fn insert_into_trees_from_parent<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    children: &'report[ClauseReport<'value>],
    parent: std::rc::Rc<String>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>)
{
    let path = std::rc::Rc::new(clause.key(&parent));
    let node = std::rc::Rc::new(Node {
        parent, path: path.clone(), clause
    });
    hierarchy.insert(path.clone(), node);

    for each in children {
        populate_hierarchy_path_trees(
            each,
            path.clone(),
            path_tree,
            hierarchy
        );
    }
}

fn populate_hierarchy_path_trees<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    parent: std::rc::Rc<String>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>)
{
    match clause {
        ClauseReport::Clause(_) |
        ClauseReport::Block(_)  => insert_into_trees(
            clause,
            parent,
            path_tree,
            hierarchy
        ),

        ClauseReport::Disjunctions(ors) => insert_into_trees_from_parent(
            clause,
            &ors.checks,
            parent,
            path_tree,
            hierarchy
        ),

        ClauseReport::Rule(rr) => insert_into_trees_from_parent(
            clause,
            &rr.checks,
            parent,
            path_tree,
            hierarchy
        ),
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
                    data,
                    outputType)
                )
        }
    }
}

fn emit_messages(
    writer: &mut dyn Write,
    prefix: &str,
    message: &str,
    error: &str,
    width: usize) -> crate::rules::Result<()> {
    if !message.is_empty() {
        writeln!(
            writer,
            "{prefix}{mh:<width$}= {message}",
            prefix=prefix,
            message=message,
            mh="Message",
            width=width
        )?;
    }

    if !error.is_empty() {
        writeln!(
            writer,
            "{prefix}{eh:<width$}= {error}",
            prefix=prefix,
            error=error,
            eh="Error",
            width=width
        )?;
    }

    Ok(())
}

fn emit_retrieval_error(
    writer: &mut dyn Write,
    prefix: &str,
    vur: &ValueUnResolved<'_>,
    context: &str,
    message: &str) -> crate::rules::Result<()> {
    writeln!(
        writer,
        "{prefix}Check = {cxt} {{",
        prefix=prefix,
        cxt=context
    )?;
    let check_end = format!("{}}}", prefix);
    let prefix = format!("{}  ", prefix);
    emit_messages(
        writer,
        &prefix,
        message,
        "",
        0,
    )?;

    writeln!(
        writer,
        "{prefix}RequiredPropertyError {{",
        prefix=prefix
    )?;
    let rpe_end = format!("{}}}", prefix);
    let prefix = format!("{}  ", prefix);
    writeln!(
        writer,
        "{prefix}PropertyPath = {path}",
        prefix=prefix,
        path=vur.value.traversed_to.self_path()
    )?;

    writeln!(
        writer,
        "{prefix}MissingProperty = {prop}",
        prefix=prefix,
        prop=vur.value.remaining_query
    )?;

    let reason = vur.value.reason.as_ref().map_or("", String::as_str);
    if !reason.is_empty() {
        writeln!(
            writer,
            "{prefix}Reason = {reason}",
            prefix=prefix,
            reason=reason
        )?;

    }
    writeln!(writer, "{}", rpe_end)?;
    writeln!(writer, "{}", check_end)?;
    Ok(())
}

fn pprint_clauses(
    writer: &mut dyn Write,
    clause: &ClauseReport<'_>,
    resource: &LocalResourceAggr<'_, '_>,
    prefix: String) -> crate::rules::Result<()> {

    match clause {
        ClauseReport::Rule(rr) => {
            writeln!(
                writer,
                "{prefix}Rule = {rule} {{",
                prefix=prefix,
                rule=rr.name
            )?;
            let rule_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            let message = rr.messages.custom_message.as_ref().map_or("", String::as_str);
            let error = rr.messages.error_message.as_ref().map_or("", String::as_str);
            emit_messages(writer, &prefix, message, error, 0)?;
            writeln!(
                writer,
                "{prefix}ALL {{",
                prefix=prefix
            )?;
            let all_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            for child in &rr.checks {
                pprint_clauses(
                    writer,
                    child,
                    resource,
                    prefix.clone(),
                )?;
            }
            writeln!(writer, "{}", all_end)?;
            writeln!(writer, "{}", rule_end)?;
        },

        ClauseReport::Disjunctions(ors) => {
            writeln!(
                writer,
                "{prefix}ANY {{",
                prefix=prefix
            )?;
            let end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            for child in &ors.checks {
                pprint_clauses(
                    writer,
                    child,
                    resource,
                    prefix.clone(),
                )?;
            }
            writeln!(writer, "{}", end)?;
        },

        ClauseReport::Block(blk) => {
            if !resource.clauses.contains(&IdentityHash{key: clause}) {
                return Ok(())
            }
            writeln!(
                writer,
                "{prefix}Check = {cxt} {{",
                prefix=prefix,
                cxt=blk.context
            )?;
            let check_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            writeln!(
                writer,
                "{prefix}RequiredPropertyError {{",
                prefix=prefix
            )?;
            let mpv_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            let (traversed_to, query) = blk.unresolved.as_ref().map_or(
                ("", ""),
                |val| (&val.traversed_to.self_path().0, &val.remaining_query));
            let width = if !traversed_to.is_empty() {
                let width = "MissingProperty".len() + 4;
                writeln!(
                    writer,
                    "{prefix}{pp:<width$}= {path}\n{prefix}{mp:<width$}= {q}",
                    prefix=prefix,
                    pp="PropertyPath",
                    width=width,
                    path=traversed_to,
                    mp="MissingProperty",
                    q=query
                )?;
                width
            } else {
                "Message".len() + 4
            };
            let message = blk.messages.custom_message.as_ref().map_or("", String::as_str);
            let error = blk.messages.error_message.as_ref().map_or("", String::as_str);
            emit_messages(writer, &prefix, message, error, width)?;
            writeln!(writer, "{}", mpv_end)?;
            writeln!(writer, "{}", check_end)?;
        },

        ClauseReport::Clause(gac) => {
            if !resource.clauses.contains(&IdentityHash{key: clause}) {
                return Ok(())
            }
            match gac {
                GuardClauseReport::Unary(ur) => {
                    match &ur.check {
                        UnaryCheck::UnResolved(vur) => {
                            emit_retrieval_error(
                                writer,
                                &prefix,
                                vur,
                                &ur.context,
                                ur.messages.custom_message.as_ref().map_or("", String::as_str)
                            )?;
                        },

                        UnaryCheck::Resolved(re) => {
                            writeln!(
                                writer,
                                "{prefix}Check = {cxt} {{",
                                prefix=prefix,
                                cxt=ur.context
                            )?;
                            let check_end = format!("{}}}", prefix);
                            let prefix = format!("{}  ", prefix);
                            writeln!(
                                writer,
                                "{prefix}ComparisonError {{",
                                prefix=prefix
                            )?;
                            let ce_end = format!("{}}}", prefix);
                            let prefix = format!("{}  ", prefix);
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
                            let message = ur.messages.custom_message.as_ref().map_or("", String::as_str);
                            let error = ur.messages.error_message.as_ref().map_or("", String::as_str);
                            emit_messages(writer, &prefix, message, error, width)?;
                            writeln!(writer, "{}", ce_end)?;
                            writeln!(writer, "{}", check_end)?;
                        },

                        _ => {}
                    }
                },

                GuardClauseReport::Binary(br) => {
                    match &br.check {
                        BinaryCheck::UnResolved(vur) => {
                            emit_retrieval_error(
                                writer,
                                &prefix,
                                vur,
                                &br.context,
                                br.messages.custom_message.as_ref().map_or("", String::as_str)
                            )?;
                        },

                        BinaryCheck::Resolved(bc) => {
                            writeln!(
                                writer,
                                "{prefix}Check = {cxt} {{",
                                prefix=prefix,
                                cxt=br.context
                            )?;
                            let check_end = format!("{}}}", prefix);
                            let prefix = format!("{}  ", prefix);
                            writeln!(
                                writer,
                                "{prefix}ComparisonError {{",
                                prefix=prefix
                            )?;
                            let ce_end = format!("{}}}", prefix);
                            let prefix = format!("{}  ", prefix);
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
                            let message = br.messages.custom_message.as_ref().map_or("", String::as_str);
                            let error = br.messages.error_message.as_ref().map_or("", String::as_str);
                            emit_messages(writer, &prefix, message, error, width)?;
                            writeln!(writer, "{}", ce_end)?;
                            writeln!(writer, "{}", check_end)?;
                        }

                    }

                }
            }
        }
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct LocalResourceAggr<'record, 'value: 'record> {
    name: &'value str,
    resource_type: &'value str,
    cdk_path: Option<&'value str>,
    clauses: HashSet<IdentityHash<'record, ClauseReport<'value>>>,
    paths: BTreeSet<String>
}

#[derive(Clone, Debug)]
struct IdentityHash<'key, T> {
    key: &'key T
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
                pprint_clauses(
                    writer,
                    each_rule,
                    &resource,
                    prefix.clone()
                )?;
            }
        }
        writeln!(writer, "}}")?;
    }

    Ok(())
}