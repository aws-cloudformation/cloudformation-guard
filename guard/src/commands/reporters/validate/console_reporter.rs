use crate::commands::tracker::StatusContext;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::eval_context::{names_a_refused_read, EventRecord};
use crate::rules::path_value::traversal::Traversal;
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

                ClauseCheck::Comparison(ComparisonClauseCheck {
                    custom_message,
                    message,
                    comparison: (cmp, not),
                    from,
                    status: Status::FAIL,
                    to,
                    ..
                }) => {
                    let custom_message = custom_message.as_ref().map_or("".to_string(), |s| {
                        format!(" Message = [{}]", s.replace('\n', ";"))
                    });

                    let error_message = message
                        .as_ref()
                        .map_or("".to_string(), |s| format!(" Error = [{}]", s));

                    let to_result = match to {
                        Some(to) => match to {
                            QueryResult::Literal(_) => unreachable!(),
                            QueryResult::Resolved(to_res) => Some(Rc::clone(to_res)),

                            QueryResult::UnResolved(to_unres) => {
                                // A right-hand side the evaluator REFUSED to read is named as the
                                // refusal (the error text that follows), not as a missing property
                                // spelled with the marker's remaining query; an absent right-hand
                                // value keeps the missing-property sentence, beside a refused read
                                // among the other values too, so the operand is read and not the
                                // record's flag (`names_a_refused_read`, as the report's arm reads).
                                if names_a_refused_read(to_unres, message.as_ref()) {
                                    writeln!(
                                        writer,
                                        "{}{}Check was not compliant as the value to compare to could not be read.{err}{msg}",
                                        prefix,
                                        prefix_current,
                                        err = error_message,
                                        msg = custom_message
                                    )?;
                                } else {
                                    writeln!(
                                        writer,
                                        "{}{}Check was not compliant as property [{remain}] to compare to is missing. Value traversed to [{to}].{err}{msg}",
                                        prefix,
                                        prefix_current,
                                        remain=to_unres.remaining_query,
                                        to=to_unres.traversed_to,
                                        err=error_message,
                                        msg=custom_message
                                    )?;
                                }
                                return Ok(());
                            }
                        },

                        None => None,
                    };

                    match from {
                        QueryResult::Literal(_) => unreachable!(),
                        QueryResult::UnResolved(to_unres) => {
                            // A left-hand side the evaluator REFUSED to read, whose record carries
                            // the refusal's text, is named as the refusal (the error text that
                            // follows), not as a missing property spelled with the marker's remaining
                            // query, as the right-hand arm above names its refusal; an absent
                            // left-hand value keeps the missing-property sentence.
                            if names_a_refused_read(to_unres, message.as_ref()) {
                                writeln!(
                                    writer,
                                    "{}{}Check was not compliant as the value to compare from could not be read.{err}{msg}",
                                    prefix,
                                    prefix_current,
                                    err = error_message,
                                    msg = custom_message
                                )?;
                            } else {
                                writeln!(
                                    writer,
                                    "{}{}Check was not compliant as property [{remain}] to compare from is missing. Value traversed to [{to}].{err}{msg}",
                                    prefix,
                                    prefix_current,
                                    remain=to_unres.remaining_query,
                                    to=to_unres.traversed_to,
                                    err=error_message,
                                    msg=custom_message
                                )?;
                            }
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
    /// right-hand side the document lacks, says the value could not be read and carries, in its one
    /// error, the absent right-hand key before the refusal: `%x != Cfg.Missing` with the keys and the
    /// refusal's marker in the capture `%x` (the document and the refused walk are the ones the
    /// evaluator's own cells use for this shape), `Missing` a key the document lacks. One line holds
    /// the could-not-be-read wording, `Missing` and the refusal, the refusal is printed once in the
    /// whole tree, and no line reads the marker as a property the template lacks ("to compare from is
    /// missing"); the keys' own pairs keep the missing-property wording for the right-hand side ("to
    /// compare to is missing"), since for them the key is the one place the absence is named.
    #[test]
    fn a_left_refusal_beside_an_absent_right_hand_side_prints_the_absence_and_the_refusal_once(
    ) -> crate::rules::Result<()> {
        const THE_REFUSAL: &str = "then no kept entry holds a key the predicate names";
        const COULD_NOT_BE_READ: &str = "the value to compare from could not be read";
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

        let could_not_be_read: Vec<&str> = printed
            .lines()
            .filter(|line| line.contains(COULD_NOT_BE_READ))
            .collect();
        assert_eq!(
            1,
            could_not_be_read.len(),
            "one line says the value to compare from could not be read, in:\n{}",
            printed
        );
        let line = could_not_be_read[0];
        assert!(
            line.contains("Could not find key Missing") && line.contains(THE_REFUSAL),
            "that line names the absent right-hand key and the refusal, got:\n{}",
            line
        );
        assert!(
            line.find("Could not find key Missing") < line.find(THE_REFUSAL),
            "the absence leads and the refusal follows, got:\n{}",
            line
        );
        assert_eq!(
            1,
            printed.matches(THE_REFUSAL).count(),
            "the refusal is printed once in the tree, in:\n{}",
            printed
        );
        assert!(
            !printed.contains("to compare from is missing"),
            "the marker is not read as a property the template lacks, in:\n{}",
            printed
        );
        assert!(
            printed.contains("to compare to is missing"),
            "the keys' pairs keep the missing-property wording for the absent right-hand side, in:\n{}",
            printed
        );
        Ok(())
    }
}
