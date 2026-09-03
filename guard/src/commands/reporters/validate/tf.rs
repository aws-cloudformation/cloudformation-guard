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
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
                // `TfAware` did not have this fallback, which `CfnAware` has had all along: any
                // error from `single_line` propagated and ended the run. The sites below now request a
                // fallback rather than aborting, so there has to be something to fall back to.
                OutputFormatType::SingleLineSummary => {
                    match single_line(write, data_file, rules_file, data, root, failure_report) {
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
                OutputFormatType::Sarif => unreachable!(),
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
use crate::rules::errors::InternalError::UnresolvedKeyForReporter;
use crate::rules::path_value::PathAwareValue;
use colored::*;
use nom::Slice;

/// The signal that this reporter cannot organise a finding by Terraform resource change.
///
/// `report_eval` catches `InternalError` and delegates to the next reporter, so this is how a fallback
/// is requested rather than an error in the ordinary sense. Mirrors `cfn.rs`.
fn unresolved_key(key: &str) -> crate::Error {
    crate::Error::InternalError(UnresolvedKeyForReporter(format!(
        "Unable to resolve key {key} for single line-summary when expecting a terraform plan, falling \
         back on next reporter"
    )))
}

/// The property part of a plan path, as this reporter prints it.
///
/// A finding's path is `/resource_changes/<n>/change/after/<property>`, and the resource half is already
/// the heading it is printed under, so only the property half belongs on the line. A path with no
/// `change/after/` in it -- a rule on `type`, `address` or `change.actions` -- keeps nothing, which is the
/// behaviour the binary comparison arm already had; shared so the `IN` arm cannot drift from it.
fn property_of(path: &str) -> String {
    match path.find("change/after/") {
        Some(at) => path[at + "change/after/".len()..].replace('/', "."),
        None => String::new(),
    }
}

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

    // `BTreeMap`, not `HashMap`: this map is iterated to write the output, and a
    // `std::collections::HashMap` seeds its hasher per process, so the `Resource = ...` blocks
    // came out in a different order on every run. A template with three non-compliant resources
    // produced five distinct outputs in fifteen runs of one binary, which makes the output
    // undiffable in CI and made a differential over fixtures report changes that were noise.
    let mut by_resources = BTreeMap::new();

    // Same shape as `cfn.rs`, and wrong in the same two directions before this. The range had no upper
    // bound, so every key sorting after `/resource_changes/` was admitted and then failed the extraction
    // below -- `terraform_version` is a real top-level key of a plan and did exactly that. Keys sorting
    // *before* it, such as `format_version`, were excluded from the aggregation and the file then
    // reported "Number of non-compliant resources 0" while exiting 19.
    //
    // A located path outside `/resource_changes/` is one this reporter cannot place, so the file goes to
    // the next reporter. An unlocated path -- a retrieval error -- carries no key and is not lost by
    // being absent from the aggregation.
    if let Some((key, _)) = path_tree
        .iter()
        .find(|(key, _)| !key.is_empty() && !key.starts_with("/resource_changes/"))
    {
        return Err(unresolved_key(key));
    }

    for (key, value) in path_tree
        .range(String::from("/resource_changes/")..)
        .take_while(|(key, _)| key.starts_with("/resource_changes/"))
    {
        // Every one of these was an abort. The extraction regex only matches
        // `/resource_changes/<x>/change/after/<...>`, so an everyday rule on any other part of a plan --
        // `resource_changes[*].type`, `.address`, `.name`, `.change.actions` -- reached it and took the
        // process down at exit 101 with the finding lost. The fixture corpus has no plan document, so
        // nothing exercised any of it.
        let resource_ptr = match RESOURCE_CHANGE_EXTRACTION.captures(key) {
            Ok(Some(cap)) => match cap.name("index_or_name") {
                Some(m) => m.as_str(),
                None => return Err(unresolved_key(key)),
            },
            Ok(None) => return Err(unresolved_key(key)),
            Err(e) => return Err(Error::from(Box::new(e))),
        };

        let address = format!("/resource_changes/{}", resource_ptr);
        let resource = match data.at(&address, root)? {
            TraversalResult::Value(n) => n,
            _ => return Err(unresolved_key(key)),
        };
        let addr = match data.at("0/address", resource)? {
            TraversalResult::Value(n) => match n.value() {
                PathAwareValue::String((_, rt)) => rt.as_str(),
                // An `address` that is a number or a map. The reporter splits it on a dot to get the
                // type and the name, which only a string supports.
                _ => return Err(unresolved_key(key)),
            },
            _ => return Err(unresolved_key(key)),
        };
        // `find` rather than `unwrap`: an address without a dot -- `"mybucket"` rather than
        // `"aws_s3_bucket.mybucket"` -- is not this reporter's shape, and unwrapping it was the same
        // abort as the arms above wearing different clothes.
        let dot_sep = match addr.find('.') {
            Some(at) => at,
            None => return Err(unresolved_key(key)),
        };
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
    // The same question the CloudFormation reporter asks, gathered before the loop consumes the map: what
    // is the per-resource output about to render? See `Rendered`.
    let rendered = super::common::Rendered::of(by_resources.values());

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

            // A whole path segment, not a prefix of one. `starts_with` matched `/chk` against
            // `/chk2/...`, so a resource whose only findings came from rule `chk2` rendered an empty
            // `Rule = chk { ALL { } }` block as well -- and once the unattributed section existed, `chk`
            // could appear under a resource while its own finding printed as belonging to no resource.
            // Paths are `/<rule>/...`, so the segment ends at the next separator or at the end.
            let range = resource
                .paths
                .range(rule_name.clone()..)
                .take_while(|p| {
                    p.strip_prefix(&rule_name)
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                })
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
                        writeln!(
                            writer,
                            "{prefix}{pp:<width$}= {path}\n{prefix}{op:<width$}= {cmp}\n{prefix}{val:<width$}= {value}\n{prefix}{cw:<width$}= {with}",
                            width=width,
                            pp="PropertyPath",
                            op="Operator",
                            val="Value",
                            cw="ComparedWith",
                            prefix=prefix,
                            path=property_of(resource_based),
                            value=ValueOnlyDisplay(Rc::clone(&bc.from)),
                            cmp=crate::rules::eval_context::cmp_str(bc.comparison),
                            with=ValueOnlyDisplay(Rc::clone(&bc.to))
                        )?;
                        Ok(width)
                    }

                    /// An `IN` comparison that failed against a plan.
                    ///
                    /// This was `todo!()`, and it is reached by an everyday rule: `IN` on any
                    /// `resource_changes[*].change.after.<field>` that fails renders through here, so
                    /// `resource_changes[*].change.after.acl IN ['private']` against a plan whose acl is
                    /// `public-read` took the process down at exit 101 with the report cut off mid-line.
                    /// The trait's default writes nothing instead, which would have left the finding
                    /// unnamed -- the panic and the silence are the same defect wearing different
                    /// clothes, and neither is a rendering.
                    ///
                    /// The list is truncated the way `cfn.rs` truncates it, `min(len, 5)` with a `Total`
                    /// when not all of it is shown, so a rule comparing against a long denylist does not
                    /// print the whole list once per resource.
                    fn binary_error_in_msg(
                        &mut self,
                        writer: &mut dyn Write,
                        _: &ClauseReport<'_>,
                        bc: &InComparison,
                        prefix: &str,
                    ) -> crate::rules::Result<usize> {
                        let width = "PropertyPath".len() + 4;
                        let cut_off = std::cmp::min(bc.to.len(), 5);
                        let collected = bc
                            .to
                            .iter()
                            .take(cut_off)
                            .map(|each| ValueOnlyDisplay(Rc::clone(each)))
                            .collect::<Vec<_>>();
                        let collected = format!("{:?}", collected);
                        let path = property_of(&bc.from.self_path().0);
                        let cmp = crate::rules::eval_context::cmp_str(bc.comparison);
                        let value = ValueOnlyDisplay(Rc::clone(&bc.from));
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
                                path = path,
                                value = value,
                                cmp = cmp,
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
                                path = path,
                                value = value,
                                cmp = cmp,
                                total = bc.to.len(),
                                with = collected
                            )?;
                        }
                        Ok(width)
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

    // Failures that belong to no resource change.
    //
    // `cfn.rs` grew this section for a run that exited 19, printed "Number of non-compliant resources
    // 0" and gave no reason anywhere; this reporter has the same shape and had the same gap, with no
    // fixture reaching it because the inputs that produce such a finding used to fail earlier as an
    // unresolved-variable error. A clause that failed *because it had nothing to compare* points at no
    // path, so it lands in no resource bucket and the loop above cannot render it.
    super::common::write_unattributed_explanations(
        writer,
        &failure_report.not_compliant,
        &rendered,
    )?;

    Ok(())
}
