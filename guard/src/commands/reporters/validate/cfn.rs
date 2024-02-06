use fancy_regex::Regex;
use std::{
    cmp::max,
    collections::{BTreeSet, HashMap, HashSet},
    io::Write,
    rc::Rc,
};

use colored::*;
use lazy_static::lazy_static;

use crate::{
    commands::{
        reporters::validate::common::{
            populate_hierarchy_path_trees, IdentityHash, LocalResourceAggr, PathTree, RuleHierarchy,
        },
        tracker::StatusContext,
        validate::{OutputFormatType, Reporter},
    },
    rules::{
        self,
        display::ValueOnlyDisplay,
        errors::InternalError::UnresolvedKeyForReporter,
        eval_context::{
            simplifed_json_from_root, BinaryComparison, ClauseReport, EventRecord, FileReport,
            InComparison, RuleReport, UnaryComparison,
        },
        path_value::{
            traversal::{Node, Traversal, TraversalResult},
            PathAwareValue,
        },
        Status, UnResolved,
    },
    utils::ReadCursor,
};

lazy_static! {
    static ref CFN_RESOURCES: Regex = Regex::new(r"^/Resources/(?P<name>[^/]+)(/?P<rest>.*$)?")
        .ok()
        .unwrap();
}

#[derive(Debug)]
pub(crate) struct CfnAware<'reporter> {
    next: Option<&'reporter dyn Reporter>,
}

impl<'reporter> CfnAware<'reporter> {
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
        _output_format_type: OutputFormatType,
    ) -> rules::Result<()> {
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
    ) -> rules::Result<()> {
        let root = data.root().unwrap();

        if data.at("/Resources", root).is_ok() {
            let failure_report = simplifed_json_from_root(root_record)?;
            match output_type {
                OutputFormatType::YAML => serde_yaml::to_writer(write, &failure_report)?,
                OutputFormatType::JSON => serde_json::to_writer_pretty(write, &failure_report)?,
                OutputFormatType::SingleLineSummary => {
                    match single_line(
                        write,
                        data_file,
                        data_file_bytes,
                        rules_file,
                        data,
                        failure_report,
                    ) {
                        Err(crate::Error::InternalError(_)) => {
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
                            })?
                        }
                        Ok(_) => {}
                        Err(e) => return Err(e),
                    }
                }
                OutputFormatType::Junit => unreachable!(),
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

fn unary_err_msg(
    writer: &mut dyn Write,
    _clause: &ClauseReport<'_>,
    re: &UnaryComparison,
    prefix: &str,
) -> rules::Result<usize> {
    let width = "PropertyPath".len() + 4;
    writeln!(
        writer,
        "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}",
        width = width,
        pp = "PropertyPath",
        op = "Operator",
        prefix = prefix,
        path = re.value.self_path(),
        cmp = rules::eval_context::cmp_str(re.comparison),
    )?;
    Ok(width)
}

fn single_line(
    writer: &mut dyn Write,
    data_file: &str,
    data_content: &str,
    rules_file: &str,
    data: &Traversal<'_>,
    failure_report: FileReport<'_>,
) -> rules::Result<()> {
    if failure_report.not_compliant.is_empty() {
        return Ok(());
    }

    let mut code_segment = ReadCursor::new(data_content);
    let mut path_tree = PathTree::new();
    let mut hierarchy = RuleHierarchy::new();
    let root_node = Rc::new(String::from(""));

    for each_rule in &failure_report.not_compliant {
        populate_hierarchy_path_trees(each_rule, root_node.clone(), &mut path_tree, &mut hierarchy);
    }

    let root = data.root().unwrap();
    let mut by_resources = HashMap::new();
    for (key, value) in path_tree.range(String::from("/Resources")..) {
        let matches = key.matches('/').count();
        let mut count = 1;

        if matches > 2 {
            loop {
                if matches - count == 0 {
                    unreachable!()
                }
                let resource_name = get_resource_name(key, count, matches);

                match handle_resource_aggr(data, root, resource_name, &mut by_resources, value) {
                    Some(_) => break,
                    None => count += 1,
                };
            }
        } else {
            let resource_name = match CFN_RESOURCES.captures(key) {
                Ok(Some(cap)) => cap.get(1).unwrap().as_str(),
                _ => {
                    return Err(crate::Error::InternalError(
                        UnresolvedKeyForReporter(
                            String::from(
                                "Unable to resolve key {key} for single line-summary when expecting a cloudformation template, falling back on next reporter"
                            )
                        )
                    ));
                }
            };

            match handle_resource_aggr(
                data,
                root,
                resource_name.to_string(),
                &mut by_resources,
                value,
            ) {
                Some(_) => {}
                None => unreachable!(),
            }
        };
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

    for (_resource_name, resource) in by_resources {
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
                struct ErrWriter<'w, 'b> {
                    code_segment: &'w mut ReadCursor<'b>,
                }
                impl<'w, 'b> super::common::ComparisonErrorWriter for ErrWriter<'w, 'b> {
                    fn missing_property_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _cr: &ClauseReport<'_>,
                        bc: Option<&UnResolved>,
                        prefix: &str,
                    ) -> rules::Result<usize> {
                        if let Some(bc) = bc {
                            self.emit_code(writer, bc.traversed_to.self_path().1.line, prefix)?;
                        }
                        Ok(0)
                    }

                    fn binary_error_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _: &ClauseReport<'_>,
                        bc: &BinaryComparison,
                        prefix: &str,
                    ) -> rules::Result<usize> {
                        let width = "PropertyPath".len() + 4;
                        writeln!(
                            writer,
                            "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}\n{prefix}{val:<width$}= {value}\n{prefix}{cw:<width$}= {with}",
                            width = width,
                            pp = "PropertyPath",
                            op = "Operator",
                            val = "Value",
                            cw = "ComparedWith",
                            prefix = prefix,
                            path = bc.from.self_path(),
                            value = ValueOnlyDisplay(Rc::clone(&bc.from)),
                            cmp = rules::eval_context::cmp_str(bc.comparison),
                            with = ValueOnlyDisplay(Rc::clone(&bc.to))
                        )?;
                        self.emit_code(writer, bc.from.self_path().1.line, prefix)?;
                        Ok(width)
                    }

                    fn binary_error_in_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _: &ClauseReport<'_>,
                        bc: &InComparison,
                        prefix: &str,
                    ) -> rules::Result<usize> {
                        let cut_off = max(bc.to.len(), 5);
                        let mut collected = Vec::with_capacity(10);
                        for (idx, each) in bc.to.iter().enumerate() {
                            collected.push(ValueOnlyDisplay(Rc::clone(each)));
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
                                width = width,
                                pp = "PropertyPath",
                                op = "Operator",
                                val = "Value",
                                cw = "ComparedWith",
                                prefix = prefix,
                                path = bc.from.self_path(),
                                value = ValueOnlyDisplay(Rc::clone(&bc.from)),
                                cmp = rules::eval_context::cmp_str(bc.comparison),
                                with = collected
                            )?;
                        } else {
                            writeln!(
                                writer,
                                "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}\n{prefix}{total_name:<width$}= {total}\n{prefix}{val:<width$}= {value}\n{prefix}{cw:<width$}= {with}",
                                width = width,
                                pp = "PropertyPath",
                                op = "Operator",
                                val = "Value",
                                total_name = "Total",
                                cw = "ComparedWith",
                                prefix = prefix,
                                path = bc.from.self_path(),
                                value = ValueOnlyDisplay(Rc::clone(&bc.from)),
                                cmp = rules::eval_context::cmp_str(bc.comparison),
                                total = bc.to.len(),
                                with = collected
                            )?;
                        }
                        self.emit_code(writer, bc.from.self_path().1.line, prefix)?;
                        Ok(width)
                    }

                    fn unary_error_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        cr: &ClauseReport<'_>,
                        re: &UnaryComparison,
                        prefix: &str,
                    ) -> rules::Result<usize> {
                        let width = unary_err_msg(writer, cr, re, prefix)?;
                        self.emit_code(writer, re.value.self_path().1.line, prefix)?;
                        Ok(width)
                    }
                }
                let mut err_writer = ErrWriter {
                    code_segment: &mut code_segment,
                };
                super::common::pprint_clauses(
                    writer,
                    each_rule,
                    &resource,
                    prefix.clone(),
                    &mut err_writer,
                )?;

                impl<'w, 'b> ErrWriter<'w, 'b> {
                    fn emit_code(
                        &mut self,
                        writer: &mut dyn Write,
                        line: usize,
                        prefix: &str,
                    ) -> rules::Result<()> {
                        writeln!(writer, "{prefix}Code:", prefix = prefix)?;
                        let new_prefix = format!("{}  ", prefix);
                        if let Some((num, line)) = self.code_segment.seek_line(max(1, line - 2)) {
                            let line =
                                format!("{num:>5}.{line}", num = num, line = line).bright_green();
                            writeln!(writer, "{prefix}{line}", prefix = new_prefix, line = line)?;
                        }
                        let mut context = 5;
                        while let Some((num, line)) = self.code_segment.next() {
                            let line =
                                format!("{num:>5}.{line}", num = num, line = line).bright_green();
                            writeln!(writer, "{prefix}{line}", prefix = new_prefix, line = line)?;
                            context -= 1;

                            if context <= 0 {
                                break;
                            }
                        }
                        Ok(())
                    }
                }
            }
        }
        writeln!(writer, "}}")?;
    }

    Ok(())
}

///
/// takes a key that contains > 2 `/`, and strips all characters to the right of i = matches-count
///
/// # Arguments
///
/// * `key`: str
/// * `count`: usize
/// * `matches`: usize
///
/// returns: String
/// ```
fn get_resource_name(key: &str, count: usize, matches: usize) -> String {
    let c = &char::from_u32(0xC).unwrap().to_string();
    // count = 2; key = "/Resources/foo/bar/baz -> placeholder = "\fResources\ffoo\fbar/baz"
    let mut placeholder = str::replacen(key, "/", c, matches - count);

    // placeholder = "\fResources\ffoo\fbar/baz" -> placeholder = "/Resources/foo\fbar/baz"
    placeholder = str::replacen(&placeholder, c, "/", 2); // count = 2 -> because always need to replace the Slashes for /Resources/

    // placeholder = "/Resources/foo\fbar/baz"
    match CFN_RESOURCES.captures(&placeholder) {
        Ok(Some(cap)) => {
            // resource_name = "foo/bar"
            str::replace(cap.get(1).unwrap().as_str(), c, "/")
        }
        _ => unreachable!(),
    }
}

fn handle_resource_aggr<'record, 'value: 'record>(
    data: &'value Traversal<'_>,
    root: &'value Node<'_>,
    name: String,
    by_resources: &mut HashMap<String, LocalResourceAggr<'record, 'value>>,
    value: &[Rc<crate::commands::reporters::validate::common::Node<'record, 'value>>],
) -> Option<()> {
    let path = format!("/Resources/{}", name);
    let resource = match data.at(&path, root) {
        Ok(TraversalResult::Value(val)) => val,
        _ => return None,
    };

    let resource_type = match data.at("0/Type", resource) {
        Ok(TraversalResult::Value(val)) => match val.value() {
            PathAwareValue::String((_, v)) => v.as_str(),
            _ => unreachable!(),
        },
        _ => return None,
    };
    let cdk_path = match data.at("0/Metadata/aws:cdk:path", resource) {
        Ok(TraversalResult::Value(val)) => match val.value() {
            PathAwareValue::String((_, v)) => Some(v.as_str()),
            _ => unreachable!(),
        },
        _ => None,
    };

    let resource_aggr =
        (*by_resources)
            .entry(name.to_string())
            .or_insert_with(|| LocalResourceAggr {
                name,
                resource_type,
                cdk_path,
                clauses: HashSet::new(),
                paths: BTreeSet::new(),
            });

    for node in value.iter() {
        resource_aggr
            .clauses
            .insert(IdentityHash { key: node.clause });
        resource_aggr.paths.insert(node.path.as_ref().clone());
    }

    Some(())
}
