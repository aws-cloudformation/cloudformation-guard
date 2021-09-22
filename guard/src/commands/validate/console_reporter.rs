use crate::commands::validate::Reporter;
use std::io::Write;
use crate::rules::{Status, RecordType, ClauseCheck, NamedStatus, BlockCheck, QueryResult, UnaryValueCheck, ValueCheck, ComparisonClauseCheck, TypeBlockCheck};
use crate::commands::tracker::StatusContext;
use crate::rules::eval_context::EventRecord;
use crate::rules::values::CmpOperator;
use std::convert::TryInto;

#[derive(Debug)]
pub(crate) struct ConsoleReporter<'a> {
    data_file_name: &'a str,
    rules_file_name: &'a str,
}

impl<'a> ConsoleReporter<'a> {
    pub(crate) fn new<'s>(data_file_name: &'s str, rules_file_name: &'s str) -> ConsoleReporter<'s> {
        ConsoleReporter {
            data_file_name, rules_file_name
        }
    }
}

//
// https://vallentin.dev/2019/05/14/pretty-print-tree
//
fn pprint_failed_sub_tree(current: &EventRecord<'_>,
                          prefix: String,
                          last: bool,
                          rules_file_name: &str,
                          data_file_name: &str,
                          writer: &mut dyn Write)
    -> crate::rules::Result<()>
{
    let prefix_current = if last { "`- " } else { "|- " };
    let increment_prefix = match &current.container {
        Some(RecordType::TypeBlock(Status::FAIL))                                           |
        Some(RecordType::BlockGuardCheck(BlockCheck{status: Status::FAIL, ..}))             |
        Some(RecordType::GuardClauseBlockCheck(BlockCheck{status: Status::FAIL, ..}))       |
        Some(RecordType::TypeBlock(Status::FAIL))                                           |
        Some(RecordType::TypeCheck(TypeBlockCheck{block: BlockCheck{status: Status::FAIL, ..}, ..})) |
        Some(RecordType::WhenCheck(BlockCheck{status: Status::FAIL, ..}))
            => false,
        Some(RecordType::FileCheck(NamedStatus{status: Status::FAIL, ..}))          |
        Some(RecordType::RuleCheck(NamedStatus{status: Status::FAIL, ..}))          |
        Some(RecordType::Disjunction(BlockCheck{status: Status::FAIL, ..}))
            => {
            writeln!(
                writer,
                "{}{}{}",
                prefix,
                prefix_current,
                current)?;
            true
        },

        Some(RecordType::ClauseValueCheck(check)) => {
            match check {
                ClauseCheck::NoValueForEmptyCheck(msg) => {
                    let custom_message = msg.as_ref()
                        .map_or("".to_string(),
                                |s| format!(" Message = [{}]", s.replace("\n", ";")));

                    writeln!(
                        writer,
                        "{}{}Check was not compliant as variable in context [{}] was not empty. Message [{}]",
                        prefix,
                        prefix_current,
                        current.context,
                        custom_message
                    )?;
                }

                ClauseCheck::Success => {},

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
                },

                ClauseCheck::MissingBlockValue(missing) => {
                    let (property, far) = match &missing.from {
                        QueryResult::UnResolved(ur) => {
                            (ur.remaining_query.as_str(), ur.traversed_to)
                        },
                        _ => unreachable!()
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
                },

                ClauseCheck::Unary(
                    UnaryValueCheck{
                        comparison: (cmp, not),
                        value: ValueCheck{
                            status: Status::FAIL,
                            from,
                            message,
                            custom_message
                        }}) => {
                    let cmp_msg = match cmp {
                        CmpOperator::Exists => if *not { "existed" } else { "did not exist" },
                        CmpOperator::Empty => if *not { "was empty"} else { "was not empty" },
                        CmpOperator::IsList => if *not { "was a list " } else { "was not list" },
                        CmpOperator::IsMap => if *not { "was a struct" } else { "was not struct" },
                        CmpOperator::IsString => if *not { "was a string " } else { "was not string" },
                        _ => unreachable!()
                    };

                    let custom_message = custom_message.as_ref()
                        .map_or("".to_string(),
                                |s| format!(" Message = [{}]", s.replace("\n", ";")));

                    let error_message = message.as_ref()
                        .map_or("".to_string(),
                                |s| format!( " Error = [{}]", s));

                    match from {
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
                        },

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
                },


                ClauseCheck::Comparison(ComparisonClauseCheck{
                    custom_message,
                    message,
                    comparison: (cmp, not),
                    from,
                    status: Status::FAIL,
                    to }) => {
                    let custom_message = custom_message.as_ref()
                        .map_or("".to_string(),
                                |s| format!(" Message = [{}]", s.replace("\n", ";")));

                    let error_message = message.as_ref()
                        .map_or("".to_string(),
                                |s| format!( " Error = [{}]", s));

                    let to_result = match to {
                        Some(to) => {
                            match to {
                                QueryResult::Resolved(to_res) => {
                                    Some(*to_res)
                                },

                                QueryResult::UnResolved(to_unres) => {
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
                                    return Ok(())
                                }
                            }
                        },

                        None => {
                            None
                        }
                    };

                    match from {
                        QueryResult::UnResolved(to_unres) => {
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
                        },

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
                                    CmpOperator::Le => if *not { "less than equal to" } else { "less than equal to" },
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
                },

                _ => {
                    return Ok(())
                } // Success skip

            }
            false
        }

        _ => {
            return Ok(())
        }
    };

    let prefix= if increment_prefix {
        let prefix_child = if last { "   " } else { "|  " };
        prefix + prefix_child
    } else { prefix };

    if !current.children.is_empty() {
        let last_child = current.children.len() - 1;
        for (i, child) in current.children.iter().enumerate() {
            pprint_failed_sub_tree(child, prefix.clone(), i == last_child, rules_file_name, data_file_name, writer)?;
        }
    }
    Ok(())
}

impl<'a> Reporter for ConsoleReporter<'a> {



    fn report(&self,
              writer: &mut dyn Write,
              _status: Option<Status>,
              failed_rules: &[&StatusContext],
              passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize) -> crate::rules::Result<()> {
        Ok(())
    }

    fn report_eval(
        &self,
        write: &mut dyn Write,
        _status: Status,
        root_record: &EventRecord<'_>) -> crate::rules::Result<()> {
        pprint_failed_sub_tree(
            root_record,
            "".to_string(),
            true,
            self.rules_file_name,
            self.data_file_name,
            write
        )
    }

}
