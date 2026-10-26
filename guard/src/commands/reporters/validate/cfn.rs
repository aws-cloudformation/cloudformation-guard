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
            console_field, populate_hierarchy_path_trees, IdentityHash, LocalResourceAggr,
            PathTree, RuleHierarchy,
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
            traversal::{unescape_pointer_segment, Node, Traversal, TraversalResult},
            Location, PathAwareValue,
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
/// Starts two lines above the violation so there is context, clamped to line 1 for
/// a violation on line 1 or 2, because line numbers are 1-based.
///
/// Line 0 is not a line: it is the position of a value with no source position, and
/// `emit_code` returns before writing the `Code:` header for one, so a 0 never
/// reaches this function from the reporter. The 0 case below is kept as an
/// underflow check only. This was previously written inline as `max(1, line - 2)`,
/// which evaluated the subtraction *before* the clamp. On an unsigned line number
/// of 0 or 1 that underflows: a panic in a debug build, and a silent wrap to
/// ~`usize::MAX` in a release build, where the subsequent seek runs past EOF and
/// the snippet is dropped from the report without any diagnostic. `saturating_sub`
/// clamps the input rather than the result.
fn context_start_line(line: usize) -> usize {
    line.saturating_sub(2).max(1)
}

/// Whether the reporter colours the `Code:` excerpt: the process setting the `colored` crate reads (a
/// terminal, `NO_COLOR`, `CLICOLOR_FORCE`), read once per excerpt and handed to `emit_code`.
fn colour_on() -> bool {
    colored::control::SHOULD_COLORIZE.should_colorize()
}

/// The `Code:` excerpt under a finding: the source from two lines above the finding's position, six
/// lines in all.
///
/// Nothing for a finding whose position is `L:0,C:0`. That is the position of a value that was not
/// read from the file at one place: the common path two resources share when a function joins them
/// sits above both, and the position it carries is the neutral one. Line 0 is not a line, and the
/// excerpt opened at line 1 of the file, six lines a reader had to work out were unrelated to the
/// finding above them. The `PropertyPath` line still shows the `[L:0,C:0]`, so the absence of the
/// excerpt reads as "nothing to point at" rather than as an omission. A finding with a position is
/// unchanged.
fn emit_code(
    code_segment: &mut ReadCursor<'_>,
    writer: &mut dyn Write,
    location: &Location,
    prefix: &str,
    colour: bool,
) -> rules::Result<()> {
    if location.line == 0 && location.col == 0 {
        return Ok(());
    }
    writeln!(writer, "{prefix}Code:", prefix = prefix)?;
    let new_prefix = format!("{}  ", prefix);
    // Each source line is escaped (a tab kept) BEFORE the colour is added, so a control character in the
    // template reaches the console as its escape and the colour sequence the line is wrapped in is the
    // writer's own. `colour` says whether the line is wrapped (the process setting, `colour_on`, in the
    // reporter; a cell passes it), so the output does not depend on global state a parallel test shares.
    let excerpt = |num: usize, line: &str| {
        let text = format!(
            "{num:>5}.{line}",
            num = num,
            line = crate::utils::writer::escaped_controls_for_excerpt(line)
        );
        match colour {
            true => format!(
                "{}{}{}",
                crate::utils::writer::WRITER_COLOUR_GREEN,
                text,
                crate::utils::writer::WRITER_COLOUR_RESET
            ),
            false => text,
        }
    };
    if let Some((num, line)) = code_segment.seek_line(context_start_line(location.line)) {
        let line = excerpt(num, line);
        writeln!(writer, "{prefix}{line}", prefix = new_prefix, line = line)?;
    }
    let mut context = 5;
    while let Some((num, line)) = code_segment.next() {
        let line = excerpt(num, line);
        writeln!(writer, "{prefix}{line}", prefix = new_prefix, line = line)?;
        context -= 1;

        if context <= 0 {
            break;
        }
    }
    Ok(())
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
        path = console_field(&re.value.self_path()),
        cmp = rules::eval_context::cmp_str(re.comparison),
    )?;
    Ok(width)
}

/// The signal that this reporter cannot organise a finding by CloudFormation resource.
///
/// `report_eval` catches `InternalError` from `single_line` and delegates to the next reporter, so
/// this is how the fallback is requested rather than an error in the ordinary sense.
///
/// The key is formatted in, so the message names the path it could not resolve rather than printing a
/// literal `{key}`.
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
        populate_hierarchy_path_trees(
            each_rule,
            root_node.clone(),
            data,
            &mut path_tree,
            &mut hierarchy,
        );
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
    // Emptiness is the discriminator, and depth is not. A test for a key more than two separators deep
    // leaves every shallower one silently lost: `Outputs.a`, `Parameters.p`, `Transform.t`,
    // `Mappings.m` and a bare `/Resources` all sit at two or fewer and all read as "Number of
    // non-compliant resources 0" with the path never named, and so do the 23 fixtures whose retrieval
    // error reads "Could not find key Vol inside struct at path /Resources".
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

    // The resource a finding belongs to is the segment after `/Resources/`, and nothing deeper.
    //
    // The keys are pointers: `/` separates segments, and a `/` inside a resource name is spelled
    // `~1`, so `/Resources/A~1B/Type` names the resource `A/B` and `/Resources/A/B/Type` names a key
    // `B` under the resource `A`. Before the keys were spelled this way the two were one string, and
    // the loop here peeled candidate names off the key from the longest down -- `A/B/Type`, then
    // `A/B`, then `A` -- accepting the first that resolved to a node with a `Type`. That is what made
    // a resource named with a `/` findable at all, and it had two effects beyond that. A nested
    // property map with its own `Type` key (a CodeBuild `Environment`, an ELBv2 `DefaultActions`
    // element) resolved before the resource did and was printed as a resource named
    // `R/Properties/Environment` with the inner `Type`; and in a document that is not CloudFormation
    // but groups typed items under `Resources.Group.Item`, the item was printed as the resource
    // `Group/Item`. Now the first prints under `R` with `R`'s `Type`, and the second resolves no
    // resource and hands the file to the next reporter, as any other non-CloudFormation shape does.
    //
    // Not `unreachable!()` on a segment that does not resolve. This reporter organises findings by
    // CloudFormation resource, and a path under `/Resources` need not name one: guard validates plain
    // YAML and JSON too. The arm below hands back an `InternalError` and `report_eval` falls through
    // to the next reporter, which does not assume the shape; a panic here would end the process at
    // exit 101 on a document whose only fault was not being CloudFormation.
    for (key, value) in path_tree
        .range(String::from("/Resources/")..)
        .take_while(|(key, _)| key.starts_with("/Resources/"))
    {
        let resource_segment = match CFN_RESOURCES.captures(key) {
            Ok(Some(cap)) => cap.get(1).unwrap().as_str(),
            _ => return Err(unresolved_key(key)),
        };

        if handle_resource_aggr(data, root, resource_segment, &mut by_resources, value).is_none() {
            return Err(unresolved_key(key));
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

    // What the per-resource output below is about to render, gathered before the loop consumes the map.
    //
    // `pprint_clauses` renders a clause only when it is in the resource's own set, so the union of those
    // sets *is* the rendered set. Handing it to the unattributed section lets that section ask the only
    // question that matters -- "did anything show this finding?" -- instead of predicting the answer from a
    // path, which is what it did before and got wrong in both directions.
    let rendered = super::common::Rendered::of(by_resources.values());

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
                            emit_code(
                                self.code_segment,
                                writer,
                                &bc.traversed_to.self_path().1,
                                prefix,
                                colour_on(),
                            )?;
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
                            path = console_field(&bc.from.self_path()),
                            value = console_field(&ValueOnlyDisplay(Rc::clone(&bc.from))),
                            cmp = rules::eval_context::cmp_str(bc.comparison),
                            with = console_field(&ValueOnlyDisplay(Rc::clone(&bc.to)))
                        )?;
                        emit_code(
                            self.code_segment,
                            writer,
                            &bc.from.self_path().1,
                            prefix,
                            colour_on(),
                        )?;
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
                        let collected = console_field(&collected);
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
                                path = console_field(&bc.from.self_path()),
                                value = console_field(&ValueOnlyDisplay(Rc::clone(&bc.from))),
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
                                path = console_field(&bc.from.self_path()),
                                value = console_field(&ValueOnlyDisplay(Rc::clone(&bc.from))),
                                cmp = rules::eval_context::cmp_str(bc.comparison),
                                total = bc.to.len(),
                                with = collected
                            )?;
                        }
                        emit_code(
                            self.code_segment,
                            writer,
                            &bc.from.self_path().1,
                            prefix,
                            colour_on(),
                        )?;
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
                        emit_code(
                            self.code_segment,
                            writer,
                            &re.value.self_path().1,
                            prefix,
                            colour_on(),
                        )?;
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

/// `resource_segment` is the resource's name as one pointer segment, as it came out of the path tree's
/// key: already spelled for the lookup, and read back to the name for the report.
fn handle_resource_aggr<'record, 'value: 'record>(
    data: &'value Traversal<'_>,
    root: &'value Node<'_>,
    resource_segment: &str,
    by_resources: &mut BTreeMap<String, LocalResourceAggr<'record, 'value>>,
    value: &[Rc<crate::commands::reporters::validate::common::Node<'record, 'value>>],
) -> Option<()> {
    let name = unescape_pointer_segment(resource_segment).into_owned();
    let path = format!("/Resources/{}", resource_segment);
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
    ///
    /// The 0 input is an underflow check, not an intended answer: line 0 means
    /// "no source position", and `emit_code` returns before this function is
    /// reached for one (see `code_excerpt_tests`). Lines 1 and 2 are the real
    /// clamp cases.
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

#[cfg(test)]
mod code_excerpt_tests {
    use super::emit_code;
    use crate::rules::path_value::Location;
    use crate::utils::ReadCursor;

    const SOURCE: &str =
        "Resources:\n  A:\n    Type: X\n    Size: 2000\n  B:\n    Type: Y\n    Size: 3000\n";

    fn excerpt_for(location: Location) -> String {
        let mut cursor = ReadCursor::new(SOURCE);
        let mut out: Vec<u8> = Vec::new();
        emit_code(&mut cursor, &mut out, &location, "  ", false)
            .expect("writing to a Vec cannot fail");
        String::from_utf8(crate::utils::writer::strip_escape_sequences(&out)).expect("utf8")
    }

    /// A finding at a position in the file shows the source around it, from two lines above.
    #[test]
    fn a_located_finding_shows_the_source_around_it() {
        let text = excerpt_for(Location::new(4, 11));
        assert!(text.starts_with("  Code:\n"), "got: {:?}", text);
        assert!(
            text.contains("    2.  A:\n") && text.contains("    4.    Size: 2000\n"),
            "the excerpt starts two lines above line 4, got: {:?}",
            text
        );
    }

    /// A finding with no source position shows no excerpt at all.
    ///
    /// `L:0,C:0` is what a value gets when it was not read from the file at a single place: the path
    /// two resources share when a function joins them, for one. Line 0 is not a line, and an excerpt
    /// opening at line 1 of the file would show its first six lines under a finding they have
    /// nothing to do with. A reader sees the `PropertyPath` with its `[L:0,C:0]` and no `Code:`, which
    /// is the reporter's way of saying there is nothing to point at.
    #[test]
    fn a_finding_without_a_source_position_shows_no_excerpt() {
        let text = excerpt_for(Location::default());
        assert_eq!(text, "", "no `Code:` header and no lines, got: {:?}", text);
    }

    /// A source line holding a control reaches the console as its escape, escaped BEFORE the colour is
    /// added: the only escape byte left in the excerpt is the writer's own colour sequence (green and its
    /// reset), and a tab, which neither ends nor hides a line, is kept as it is written. The ESC is built
    /// with `char::from`, since the source holds no raw control.
    ///
    /// Expected, not yet run. Red: a raw ESC byte beside the colour sequences, the control written as
    /// text with no escape, or the tab written as `\t`.
    #[test]
    fn a_control_in_a_source_line_is_escaped_before_the_colour_and_a_tab_is_kept() {
        let esc = char::from(0x1b);
        let source = format!("Resources:\n  A:\n\tTab: {esc}[31mred\n  B: 1\n");
        let mut cursor = ReadCursor::new(&source);
        let mut out: Vec<u8> = Vec::new();
        // The colour is a parameter, so the cell reads no global setting that a parallel test shares.
        emit_code(&mut cursor, &mut out, &Location::new(3, 1), "  ", true)
            .expect("writing to a Vec cannot fail");
        let written = String::from_utf8(out).expect("utf8");
        let without_colour = written
            .replace(&format!("{esc}[92m"), "")
            .replace(&format!("{esc}[0m"), "");
        assert!(
            !without_colour.contains(esc),
            "the only ESC bytes are the writer's colour: {:?}",
            written
        );
        assert!(
            written.contains("\\u{1b}[31mred"),
            "the source ESC is written as its escape: {:?}",
            written
        );
        assert!(
            written.contains("\tTab: "),
            "the tab is kept: {:?}",
            written
        );
        assert!(
            written.contains(&format!("{esc}[92m")),
            "the colour is on, so the writer's own sequence is in the output: {:?}",
            written
        );
    }

    /// A real coloured excerpt, run through the backstop every comparison writer's buffer takes
    /// (`writer_output`), comes out byte for byte as `emit_code` wrote it: the green that opens each
    /// source line and the reset that closes it are the two sequences the backstop keeps
    /// (`WRITER_COLOUR_SEQUENCES`), and the source's own ESC is already written as its escape. The cell
    /// runs the writer, not a hand-built sequence, so a colour `emit_code` starts writing that the
    /// backstop does not keep turns it red, where a backstop test that builds its own sequence would stay
    /// green while every coloured `Code:` line printed the sequence as text.
    ///
    /// Expected, not yet run. Red: the backstop's output differs from the writer's (a colour sequence the
    /// writer emits is written as text), or the excerpt holds no colour at all.
    #[test]
    fn a_coloured_excerpt_passes_the_writers_backstop_unchanged() {
        let esc = char::from(0x1b);
        let source = format!("Resources:\n  A:\n    Note: {esc}[8mhidden\n  B: 1\n");
        let mut cursor = ReadCursor::new(&source);
        let mut out: Vec<u8> = Vec::new();
        emit_code(&mut cursor, &mut out, &Location::new(3, 1), "  ", true)
            .expect("writing to a Vec cannot fail");
        let written = String::from_utf8(out.clone()).expect("utf8");
        assert!(
            written.contains(crate::utils::writer::WRITER_COLOUR_GREEN)
                && written.contains(crate::utils::writer::WRITER_COLOUR_RESET),
            "the excerpt is coloured: {:?}",
            written
        );
        assert_eq!(
            written,
            crate::commands::reporters::validate::common::writer_output(out),
            "the backstop keeps every sequence the writer emits"
        );
    }
}
