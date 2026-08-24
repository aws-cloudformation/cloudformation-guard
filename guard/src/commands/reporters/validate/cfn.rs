use fancy_regex::Regex;
use std::{
    cmp::min,
    collections::{BTreeMap, BTreeSet, HashSet},
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
            simplified_json_from_root, BinaryComparison, ClauseReport, EventRecord, FileReport,
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

/// First line of the source snippet shown above a reported violation.
///
/// Starts two lines above the violation so there is context, but never below line
/// 1 because line numbers are 1-based.
///
/// This was previously written inline as `max(1, line - 2)`, which evaluated the
/// subtraction *before* the clamp. On an unsigned line number of 0 or 1 that
/// underflows: a panic in a debug build, and a silent wrap to ~`usize::MAX` in a
/// release build, where the subsequent seek runs past EOF and the snippet is
/// dropped from the report without any diagnostic. `saturating_sub` clamps the
/// input rather than the result.
fn context_start_line(line: usize) -> usize {
    line.saturating_sub(2).max(1)
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
            let failure_report = simplified_json_from_root(root_record)?;
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

/// The signal that this reporter cannot organise a finding by CloudFormation resource.
///
/// `report_eval` catches `InternalError` from `single_line` and delegates to the next reporter, so
/// this is how the fallback is requested rather than an error in the ordinary sense.
///
/// The key is formatted in. The message used to be a `String::from` containing a literal `{key}`, so it
/// promised to name the path it could not resolve and then printed the braces.
fn unresolved_key(key: &str) -> crate::Error {
    crate::Error::InternalError(UnresolvedKeyForReporter(format!(
        "Unable to resolve key {key} for single line-summary when expecting a cloudformation \
         template, falling back on next reporter"
    )))
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
    // `BTreeMap`, not `HashMap`: this map is iterated to write the output, and a
    // `std::collections::HashMap` seeds its hasher per process, so the `Resource = ...` blocks
    // came out in a different order on every run. A template with three non-compliant resources
    // produced five distinct outputs in fifteen runs of one binary, which makes the output
    // undiffable in CI and made a differential over fixtures report changes that were noise.
    let mut by_resources = BTreeMap::new();

    // Every finding has to sit under `/Resources/` for this reporter to say anything true about the
    // file, so if one does not, the whole file goes to the next reporter.
    //
    // The range below was `range("/Resources"..)` with no upper bound, which is wrong in both
    // directions and silently so. Findings under a section sorting *before* `Resources` were dropped
    // from the aggregation and the file then reported "Number of non-compliant resources 0" while
    // exiting 19 -- a failing gate with nothing to act on, which is worse than a crash because it
    // looks like a report. Findings under a section sorting *after* it were admitted and then
    // panicked: `Rules` and `Transform` are real CloudFormation sections and both sort after
    // `Resources` ("Rules" > "Resources" at u vs e), so a SAM template with a `Transform` and a
    // failing clause under it died at exit 101.
    // Any *located* path outside `/Resources/` is what this reporter cannot place. The loop below only
    // consumes keys under `/Resources/`, so every other located path is dropped by it, and the file is
    // then described by a resource count that does not include the finding.
    //
    // Emptiness is the discriminator, and depth is not -- that took two attempts. A key more than two
    // separators deep leaves every shallower one silently lost: `Outputs.a`, `Parameters.p`,
    // `Transform.t`, `Mappings.m` and a bare `/Resources` all sit at two or fewer and all reported
    // "Number of non-compliant resources 0" with the path never named. Two of those were worse than
    // pre-existing -- the old `else` branch used to fall back for `/Transform/t` and `/Resources`, so a
    // depth test regressed them -- along with 23 fixtures whose retrieval error reads "Could not find
    // key Vol inside struct at path /Resources".
    //
    // What separates the cases is whether the finding has a path at all. A retrieval error carries an
    // empty one and is reported further down as "Property traversed until []", so it is not lost by
    // being absent from the aggregation and must not demote the file.
    if let Some((key, _)) = path_tree
        .iter()
        .find(|(key, _)| !key.is_empty() && !key.starts_with("/Resources/"))
    {
        return Err(unresolved_key(key));
    }

    for (key, value) in path_tree
        .range(String::from("/Resources/")..)
        .take_while(|(key, _)| key.starts_with("/Resources/"))
    {
        let matches = key.matches('/').count();
        let mut count = 1;

        if matches > 2 {
            loop {
                // Not `unreachable!()`. This reporter organises findings by CloudFormation resource,
                // and a path under `/Resources` need not name one: guard validates plain YAML and JSON
                // too, so `Resources.Nested.inner.key` is a perfectly good query against a document
                // where `Nested` has no `Type`. Every candidate prefix failing to resolve is that
                // case, not a broken invariant, and it panicked the process at exit 101 on a template
                // whose only fault was not being CloudFormation.
                //
                // The arm below already had the answer: hand back an `InternalError` and let
                // `report_eval` fall through to the next reporter, which does not assume the shape.
                if matches - count == 0 {
                    return Err(unresolved_key(key));
                }
                let resource_name = match get_resource_name(key, count, matches) {
                    Some(name) => name,
                    None => return Err(unresolved_key(key)),
                };

                match handle_resource_aggr(data, root, resource_name, &mut by_resources, value) {
                    Some(_) => break,
                    None => count += 1,
                };
            }
        } else {
            let resource_name = match CFN_RESOURCES.captures(key) {
                Ok(Some(cap)) => cap.get(1).unwrap().as_str(),
                _ => return Err(unresolved_key(key)),
            };

            match handle_resource_aggr(
                data,
                root,
                resource_name.to_string(),
                &mut by_resources,
                value,
            ) {
                Some(_) => {}
                // Same reasoning as above: the key matched the shape of a resource path but names
                // nothing this reporter can aggregate under.
                None => return Err(unresolved_key(key)),
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

    // What the per-resource output below is about to render, gathered before the loop consumes the map.
    //
    // `pprint_clauses` renders a clause only when it is in the resource's own set, so the union of those
    // sets *is* the rendered set. Handing it to the unattributed section lets that section ask the only
    // question that matters -- "did anything show this finding?" -- instead of predicting the answer from a
    // path, which is what it did before and got wrong in both directions.
    let rendered = super::common::rendered_contexts(by_resources.values());

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
                        // `min`, not `max`. With `max(len, 5)` the cut-off was never below the
                        // number of values, so the loop never broke early and the branch below
                        // that reports a `Total` was unreachable -- a rule comparing against a
                        // denylist of five hundred entries printed all five hundred, in every
                        // failure message, for every resource. The dead branch is what gives the
                        // intent away: it exists to say how many there were when not all are
                        // shown. Pinned by
                        // `a_long_in_comparison_is_truncated_with_a_total`.
                        let cut_off = min(bc.to.len(), 5);
                        let collected = bc
                            .to
                            .iter()
                            .take(cut_off)
                            .map(|each| ValueOnlyDisplay(Rc::clone(each)))
                            .collect::<Vec<_>>();
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
                        if let Some((num, line)) =
                            self.code_segment.seek_line(context_start_line(line))
                        {
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

    // Failures that belong to no resource.
    //
    // Everything above is organised by resource, because a violation normally points at a value in
    // the input. A clause that failed *because it had nothing to compare* points at nothing, so it
    // never reaches a resource bucket, and `pprint_clauses` renders a block through its `unresolved`
    // query, which such a block does not have either. The result was a run that correctly exited 19
    // and printed "Number of non-compliant resources 0" with no reason given anywhere -- the
    // explanation was recorded and then dropped on the floor.
    super::common::write_unattributed_explanations(
        writer,
        &failure_report.not_compliant,
        &rendered,
    )?;

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
fn get_resource_name(key: &str, count: usize, matches: usize) -> Option<String> {
    let c = &char::from_u32(0xC).unwrap().to_string();
    // count = 2; key = "/Resources/foo/bar/baz -> placeholder = "\fResources\ffoo\fbar/baz"
    let mut placeholder = str::replacen(key, "/", c, matches - count);

    // placeholder = "\fResources\ffoo\fbar/baz" -> placeholder = "/Resources/foo\fbar/baz"
    placeholder = str::replacen(&placeholder, c, "/", 2); // count = 2 -> because always need to replace the Slashes for /Resources/

    // placeholder = "/Resources/foo\fbar/baz"
    match CFN_RESOURCES.captures(&placeholder) {
        Ok(Some(cap)) => {
            // resource_name = "foo/bar"
            Some(str::replace(cap.get(1).unwrap().as_str(), c, "/"))
        }
        // `None`, not `unreachable!()`. The caller filters to keys under `/Resources/` now, so this
        // should not be reached -- but "should not" is what the panic already claimed, and it was
        // reachable through an unbounded range for as long as that range existed. A key this cannot
        // parse is one this reporter cannot describe, which is a fallback, not a crash.
        _ => None,
    }
}

fn handle_resource_aggr<'record, 'value: 'record>(
    data: &'value Traversal<'_>,
    root: &'value Node<'_>,
    name: String,
    by_resources: &mut BTreeMap<String, LocalResourceAggr<'record, 'value>>,
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
            // Matching the arm below rather than panicking. A `Type` that is not a string means this
            // is not a resource whose type this reporter can name, which is the same situation as a
            // `Type` that is absent.
            _ => return None,
        },
        _ => return None,
    };
    let cdk_path = match data.at("0/Metadata/aws:cdk:path", resource) {
        Ok(TraversalResult::Value(val)) => match val.value() {
            PathAwareValue::String((_, v)) => Some(v.as_str()),
            // As with `Type` above, and as the arm below already did for an absent key: a
            // `aws:cdk:path` that is not a string is a resource with no CDK path to show.
            _ => None,
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

#[cfg(test)]
mod context_start_line_tests {
    use super::context_start_line;

    /// These three inputs are the regression. With the original
    /// `max(1, line - 2)` they panic in a debug build (which is what a test
    /// binary is) and wrap to ~usize::MAX in release.
    #[test]
    fn does_not_underflow_at_or_below_line_two() {
        assert_eq!(1, context_start_line(0));
        assert_eq!(1, context_start_line(1));
        assert_eq!(1, context_start_line(2));
    }

    #[test]
    fn keeps_two_lines_of_context_above_the_violation() {
        assert_eq!(1, context_start_line(3));
        assert_eq!(3, context_start_line(5));
        assert_eq!(98, context_start_line(100));
    }

    /// Line numbers are 1-based, so 0 is never a valid answer.
    #[test]
    fn never_returns_zero() {
        for line in 0..16usize {
            assert!(
                context_start_line(line) >= 1,
                "context_start_line({}) returned 0, which is not a valid 1-based line",
                line
            );
        }
    }
}
