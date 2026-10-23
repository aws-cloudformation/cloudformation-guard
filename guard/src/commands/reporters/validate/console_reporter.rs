use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::eval_context::{unresolved_comparison_sentence, EventRecord};
use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use crate::rules::{
    BlockCheck, ClauseCheck, ComparisonClauseCheck, NamedStatus, QueryResult, RecordType, Status,
    TypeBlockCheck, UnaryValueCheck, ValueCheck,
};
use std::io::Write;
use std::rc::Rc;

#[derive(Debug)]
pub(crate) struct ConsoleReporter {}

//
// https://vallentin.dev/2019/05/14/pretty-print-tree
//
fn pprint_failed_sub_tree(
    current: &EventRecord<'_>,
    prefix: String,
    last: bool,
    rules_file_name: &str,
    data_file_name: &str,
    writer: &mut dyn Write,
) -> crate::rules::Result<()> {
    let prefix_current = if last { "`- " } else { "|- " };
    let increment_prefix = match &current.container {
        Some(RecordType::TypeBlock(Status::FAIL))
        | Some(RecordType::BlockGuardCheck(BlockCheck {
            status: Status::FAIL,
            ..
        }))
        | Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            status: Status::FAIL,
            ..
        }))
        | Some(RecordType::TypeCheck(TypeBlockCheck {
            block:
                BlockCheck {
                    status: Status::FAIL,
                    ..
                },
            ..
        }))
        | Some(RecordType::WhenCheck(BlockCheck {
            status: Status::FAIL,
            ..
        })) => false,
        Some(RecordType::FileCheck(NamedStatus {
            status: Status::FAIL,
            ..
        }))
        | Some(RecordType::RuleCheck(NamedStatus {
            status: Status::FAIL,
            ..
        }))
        | Some(RecordType::Disjunction(BlockCheck {
            status: Status::FAIL,
            ..
        })) => {
            writeln!(writer, "{}{}{}", prefix, prefix_current, current)?;
            true
        }

        Some(RecordType::ClauseValueCheck(check)) => {
            match check {
                ClauseCheck::NoValueForEmptyCheck(check) => {
                    let custom_message = check
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |s| s.replace('\n', ";"));

                    // This record is written only when a `!empty` selected nothing, so the selection
                    // was empty and the line says so. It names the
                    // query the record carries, filters spelled out, so two clauses that filter one
                    // collection differently read differently here as they do in the summary.
                    writeln!(
                        writer,
                        "{}{}Check was not compliant as the query [{}] selected no values to test. Message [{}]",
                        prefix,
                        prefix_current,
                        check.query,
                        custom_message
                    )?;
                }

                ClauseCheck::Success => {}

                ClauseCheck::DependentRule(missing) => {
                    writeln!(
                        writer,
                        "{prefix}{prefix_current}Check was not compliant as dependent rule [{rule}] evaluated to FAIL in [{file}]. Context [{cxt}]",
                        prefix=prefix,
                        prefix_current=prefix_current,
                        rule=missing.rule,
                        file=rules_file_name,
                        cxt=current.context
                    )?;
                }

                ClauseCheck::MissingBlockValue(missing) => {
                    let (property, far) = match &missing.from {
                        QueryResult::UnResolved(ur) => {
                            (ur.remaining_query.as_str(), Rc::clone(&ur.traversed_to))
                        }
                        _ => unreachable!(),
                    };
                    writeln!(
                        writer,
                        "{}{}Check was not compliant as property [{}] is missing in data [{}]. Value traversed to [{}]",
                        prefix,
                        prefix_current,
                        property,
                        data_file_name,
                        far
                    )?;
                }

                ClauseCheck::Unary(UnaryValueCheck {
                    comparison: (cmp, not),
                    value:
                        ValueCheck {
                            status: Status::FAIL,
                            from,
                            message,
                            custom_message,
                            ..
                        },
                }) => {
                    let cmp_msg = match cmp {
                        CmpOperator::Exists => {
                            if *not {
                                "existed"
                            } else {
                                "did not exist"
                            }
                        }
                        CmpOperator::Empty => {
                            if *not {
                                "was empty"
                            } else {
                                "was not empty"
                            }
                        }
                        CmpOperator::IsList => {
                            if *not {
                                "was a list "
                            } else {
                                "was not list"
                            }
                        }
                        CmpOperator::IsMap => {
                            if *not {
                                "was a struct"
                            } else {
                                "was not struct"
                            }
                        }
                        CmpOperator::IsString => {
                            if *not {
                                "was a string "
                            } else {
                                "was not string"
                            }
                        }
                        _ => unreachable!(),
                    };

                    let custom_message = custom_message.as_ref().map_or("".to_string(), |s| {
                        format!(" Message = [{}]", s.replace('\n', ";"))
                    });

                    let error_message = message
                        .as_ref()
                        .map_or("".to_string(), |s| format!(" Error = [{}]", s));

                    match from {
                        QueryResult::Literal(_) => unreachable!(),
                        QueryResult::Resolved(res) => {
                            writeln!(
                                writer,
                                "{}{}Check was not compliant as property [{prop}] {cmp_msg}.{err}{msg}",
                                prefix,
                                prefix_current,
                                prop=res.self_path(),
                                cmp_msg=cmp_msg,
                                err=error_message,
                                msg=custom_message
                            )?;
                        }

                        QueryResult::UnResolved(unres) => {
                            writeln!(
                                writer,
                                "{}{}Check was not compliant as property [{remain}] is missing. Value traversed to [{tr}].{err}{msg}",
                                prefix,
                                prefix_current,
                                remain=unres.remaining_query,
                                tr=unres.traversed_to,
                                err=error_message,
                                msg=custom_message
                            )?;
                        }
                    }
                }

                ClauseCheck::Comparison(
                    check @ ComparisonClauseCheck {
                        status: Status::FAIL,
                        ..
                    },
                ) => {
                    let ComparisonClauseCheck {
                        custom_message,
                        message,
                        comparison: (cmp, not),
                        from,
                        to,
                        ..
                    } = check;
                    let custom_message = custom_message.as_ref().map_or("".to_string(), |s| {
                        format!(" Message = [{}]", s.replace('\n', ";"))
                    });

                    let error_message = message
                        .as_ref()
                        .map_or("".to_string(), |s| format!(" Error = [{}]", s));

                    // An unresolved operand on either side: the ONE sentence builder shared with the
                    // structured report (`unresolved_comparison_sentence`), which names a refused
                    // left-hand read first, else reads the right-hand operand first where it is
                    // unresolved, and words the sentence by the operand's kind (refused, missing,
                    // undecided), so this tree and `-o json` name the same operand for one record; the
                    // tree quotes a traversed value as it is.
                    if let Some((sentence, _)) =
                        unresolved_comparison_sentence(check, &|value: &PathAwareValue| {
                            value.to_string()
                        })
                    {
                        writeln!(
                            writer,
                            "{}{}{sentence}{err}{msg}",
                            prefix,
                            prefix_current,
                            err = error_message,
                            msg = custom_message
                        )?;
                        return Ok(());
                    }

                    let to_result = match to {
                        Some(QueryResult::Resolved(to_res)) => Some(Rc::clone(to_res)),
                        Some(QueryResult::Literal(_)) => unreachable!(),
                        Some(QueryResult::UnResolved(_)) => {
                            unreachable!("an unresolved right-hand operand is reported above")
                        }
                        None => None,
                    };

                    match from {
                        QueryResult::Literal(_) => unreachable!(),
                        QueryResult::UnResolved(_) => {
                            unreachable!("an unresolved left-hand operand is reported above")
                        }

                        QueryResult::Resolved(res) => {
                            writeln!(
                                writer,
                                "{}{}Check was not compliant as property value [{from}] {op_msg} value [{to}].{err}{msg}",
                                prefix,
                                prefix_current,
                                from=res,
                                to=to_result.map_or("NULL".to_string(), |t| format!("{}", t)),
                                op_msg=match cmp {
                                    CmpOperator::Eq => if *not { "equal to" } else { "not equal to" },
                                    CmpOperator::Le => if *not { "less than equal to" } else { "not less than equal to" },
                                    CmpOperator::Lt => if *not { "less than" } else { "not less than" },
                                    CmpOperator::Ge => if *not { "greater than equal to" } else { "not greater than equal" },
                                    CmpOperator::Gt => if *not { "greater than" } else { "not greater than" },
                                    CmpOperator::In => if *not { "in" } else { "not in" },
                                    _ => unreachable!()
                                },
                                err=error_message,
                                msg=custom_message
                            )?;
                        }
                    }
                }

                _ => return Ok(()), // Success skip
            }
            false
        }

        _ => return Ok(()),
    };

    let prefix = if increment_prefix {
        let prefix_child = if last { "   " } else { "|  " };
        prefix + prefix_child
    } else {
        prefix
    };

    if !current.children.is_empty() {
        let last_child = current.children.len() - 1;
        for (i, child) in current.children.iter().enumerate() {
            pprint_failed_sub_tree(
                child,
                prefix.clone(),
                i == last_child,
                rules_file_name,
                data_file_name,
                writer,
            )?;
        }
    }
    Ok(())
}

impl Reporter for ConsoleReporter {
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
    ) -> crate::rules::Result<()> {
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
        _output_type: OutputFormatType,
    ) -> crate::rules::Result<()> {
        pprint_failed_sub_tree(
            _root_record,
            "".to_string(),
            true,
            _rules_file,
            _data_file,
            _write,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::pprint_failed_sub_tree;
    use crate::rules::eval::eval_rules_file;
    use crate::rules::eval_context::root_scope;
    use crate::rules::exprs::RulesFile;
    use crate::rules::path_value::PathAwareValue;
    use crate::rules::Status;
    use std::convert::TryFrom;
    use std::rc::Rc;

    /// The failed-clause tree says an empty selection selected nothing, and names the query.
    ///
    /// This arm said the selection "was not empty", the opposite of why the clause failed, and named
    /// the clause's own rendering, which stands `(filter-clauses)` in for every filter, so two rules
    /// that filter one collection differently printed one line. Each rule now gets a line that spells
    /// its own filter, with its literals in the rule language. The record is also written for a lone
    /// variable bound to an empty selection, whose line names the variable.
    #[test]
    fn an_empty_selection_names_its_query_in_the_failed_tree() -> crate::rules::Result<()> {
        let data = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
            "Items:\n  - Name: a\n  - Name: b\n",
        )?)?;
        let rules = RulesFile::try_from(
            r#"
            let v = Items[ Name == 'zzz' ]
            rule first_filter { Items[ Name == 'zzz' ] !empty }
            rule second_filter { Items[ Name == 'yyy' ] !empty }
            rule lone_variable { %v !empty }
            "#,
        )?;
        let mut scope = root_scope(&rules, Rc::new(data));
        assert_eq!(Status::FAIL, eval_rules_file(&rules, &mut scope, None)?);
        let root = scope.reset_recorder().extract();

        let mut out = Vec::new();
        pprint_failed_sub_tree(&root, String::new(), true, "rules", "data", &mut out)?;
        let printed = String::from_utf8(out).expect("the tree is text");

        for sentence in [
            "the query [Items[ Name EQUALS 'zzz' ]] selected no values to test",
            "the query [Items[ Name EQUALS 'yyy' ]] selected no values to test",
            "the query [%v] selected no values to test",
        ] {
            assert_eq!(
                1,
                printed.matches(sentence).count(),
                "each filter's line names its own query once, expected {:?} in:\n{}",
                sentence,
                printed
            );
        }
        assert!(
            !printed.contains("was not empty"),
            "an empty selection must not be reported as not empty, in:\n{}",
            printed
        );
        Ok(())
    }

    /// The failed-clause tree's line for a LEFT-hand value that is a REFUSAL's marker, decided by a
    /// right-hand side the document lacks, says the value to compare from could not be read (the refused
    /// read is the finding, and the shared sentence builder reads a refused left-hand operand first) and
    /// carries, in its one error, the absence named with its side before the refusal: `%x != Cfg.Missing`
    /// with the keys and the refusal's marker in the capture `%x` (the document and the refused walk are
    /// the ones the evaluator's own cells use for this shape), `Missing` a key the document lacks. With
    /// the error's lead "The right-hand value is absent: Could not find key Missing ..." the line no
    /// longer reads that key as the left value's absence, which it did when the error began with the
    /// retrieval's reason alone. One line holds the refusal; it names the right side, the key and the
    /// refusal, the absence first; the refusal is printed once in the whole tree; no line reads the
    /// marker as a property the template lacks ("to compare from is missing"), and the keys' own pairs
    /// keep the missing-property wording for the right-hand side.
    #[test]
    fn a_left_refusal_beside_an_absent_right_hand_side_prints_the_absence_and_the_refusal_once(
    ) -> crate::rules::Result<()> {
        const THE_REFUSAL: &str = "then no kept entry holds a key the predicate names";
        const THE_RIGHT_SIDE: &str = "The right-hand value is absent";
        let data = PathAwareValue::try_from(
            r#"{
                "Cfg": {
                    "Mode": { "Ref": "ModeParam" },
                    "Fallback": { "Kind": "k" },
                    "A": { "Kind": "k", "Sub": { "R1": { "Ref": "P" }, "P": { "Kind": "k" }, "Q": { "Kind": "k" } } },
                    "B": { "Kind": "k", "Sub": { "R1": { "Ref": "P" }, "P": { "Kind": "k" }, "Q": { "Kind": "k" } } }
                }
            }"#,
        )?;
        let rules = RulesFile::try_from(
            r#"
            rule r {
                Cfg[ x | Kind == 'k' ] !empty
                Cfg[*][ x | Mode exists or Kind == 'k' ].Sub[*][ s | R1 !exists ] !empty or Cfg.Fallback exists
                %x != Cfg.Missing
            }
            "#,
        )?;
        let mut scope = root_scope(&rules, Rc::new(data));
        assert_eq!(Status::FAIL, eval_rules_file(&rules, &mut scope, None)?);
        let root = scope.reset_recorder().extract();

        let mut out = Vec::new();
        pprint_failed_sub_tree(&root, String::new(), true, "rules", "data", &mut out)?;
        let printed = String::from_utf8(out).expect("the tree is text");

        let with_the_refusal: Vec<&str> = printed
            .lines()
            .filter(|line| line.contains(THE_REFUSAL))
            .collect();
        assert_eq!(
            1,
            with_the_refusal.len(),
            "one line carries the refusal, in:\n{}",
            printed
        );
        let line = with_the_refusal[0];
        assert!(
            line.contains("the value to compare from could not be read")
                && line.contains(THE_RIGHT_SIDE)
                && line.contains("Could not find key Missing"),
            "that line names the refused left-hand read in its sentence and the right-hand side as absent in its error, got:\n{}",
            line
        );
        assert!(
            line.find(THE_RIGHT_SIDE) < line.find("Could not find key Missing")
                && line.find("Could not find key Missing") < line.find(THE_REFUSAL),
            "the side, then the absence, then the refusal, got:\n{}",
            line
        );
        assert!(
            !printed.contains("to compare from is missing"),
            "no line reads the marker as a property the template lacks, in:\n{}",
            printed
        );
        Ok(())
    }

    /// The failed-clause tree's lines for a KEY FILTER's marker on the left (the marker a key filter
    /// leaves for a map whose key spent the regex budget, no refusal), in both shapes. Beside a RIGHT-hand
    /// side the document lacks (`%cfg != Resources.R.Properties.Missing`), the record carries the absent
    /// value as what the marker was compared with and its message leads with the right-hand absence, so
    /// the line names the right side as the missing one ("property [Missing] to compare to is missing")
    /// and its error names the side, the key and the marker's reason. Beside a PRESENT right-hand side
    /// (`%cfg != 'zzz'`), the pair is a FAIL status asserted, decided by its record alone, and the record
    /// carries the marker's reason as its message, so the line names the value as one that could not be
    /// decided ("the value to compare from could not be decided", the wording for a marker of the key
    /// filter's kind) with the reason in its error; before, that record had no message and the line read
    /// "property [] to compare from is missing" with the reason nowhere in the output. The reason is a
    /// key filter's, no refusal, so neither record is flagged and neither line says a value could not be
    /// read.
    #[test]
    fn a_key_filters_marker_on_the_left_prints_its_reason_in_both_shapes(
    ) -> crate::rules::Result<()> {
        const THE_LEFT_MARKER: &str = "stands among the left-hand values";
        let spends_the_budget = "a".repeat(30);
        let data = Rc::new(PathAwareValue::try_from(
            format!(
                "{{ Resources: {{ R: {{ Type: 'AWS::IAM::Role', Properties: {{ Maps: {{ M1: {{ {spends_the_budget}: 'z' }}, M2: {{ aab: 'x' }} }} }} }} }} }}"
            )
            .as_str(),
        )?);
        let printed = |clause: &str| -> crate::rules::Result<String> {
            let text = format!(
                "let cfg = Resources.R.Properties.Maps.*[ keys == /(?!x)((a+)+)b/ ].*\nrule r {{ {clause} }}"
            );
            let rules = RulesFile::try_from(text.as_str())?;
            let mut scope = root_scope(&rules, Rc::clone(&data));
            assert_eq!(Status::FAIL, eval_rules_file(&rules, &mut scope, None)?);
            let root = scope.reset_recorder().extract();
            let mut out = Vec::new();
            pprint_failed_sub_tree(&root, String::new(), true, "rules", "data", &mut out)?;
            Ok(String::from_utf8(out).expect("the tree is text"))
        };

        let absent = printed("%cfg != Resources.R.Properties.Missing")?;
        let with_the_marker: Vec<&str> = absent
            .lines()
            .filter(|line| line.contains(THE_LEFT_MARKER))
            .collect();
        assert_eq!(
            1,
            with_the_marker.len(),
            "one line names the marker beside the absent right-hand side, in:\n{}",
            absent
        );
        assert!(
            with_the_marker[0].contains("property [Missing] to compare to is missing")
                && with_the_marker[0].contains("The right-hand value is absent")
                && with_the_marker[0].contains("Could not find key Missing"),
            "that line names the right-hand side as the missing one, got:\n{}",
            with_the_marker[0]
        );
        assert!(
            !absent.contains("to compare from") && !absent.contains("could not be read"),
            "the marker is neither the missing value nor an unread one, in:\n{}",
            absent
        );

        let present = printed("%cfg != 'zzz'")?;
        let undecided_lines: Vec<&str> = present
            .lines()
            .filter(|line| line.contains("the value to compare from could not be decided"))
            .collect();
        assert_eq!(
            1,
            undecided_lines.len(),
            "one line is the marker's pair against the present right-hand side, named as a value that could not be decided, in:\n{}",
            present
        );
        // The marker's own reason, not the opener alone: a line reading ` Error = [` with any text in
        // it would pass on a reason that is not this marker's.
        assert!(
            undecided_lines[0].contains(" Error = [")
                && undecided_lines[0].contains("The regular expression could not be evaluated"),
            "that line carries the marker's reason (the regex engine's refusal) in its error, got:\n{}",
            undecided_lines[0]
        );
        assert!(
            !present.contains("to compare from is missing")
                && !present.contains("could not be read"),
            "a key filter's marker is neither a property the template lacks nor a refusal, in:\n{}",
            present
        );
        Ok(())
    }
}
