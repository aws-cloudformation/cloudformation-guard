use crate::rules::eval_context::EventRecord;
use crate::rules::{RecordType, BlockCheck, ClauseCheck, Status, QueryResult};
use std::fmt::Formatter;
use crate::rules::values::CmpOperator;
use crate::rules::path_value::PathAwareValue;
use std::convert::TryInto;

pub(crate) fn display_comparison((cmp, not): (CmpOperator, bool)) -> String {
    format!("{} {}", if not { "not" } else { "" }, cmp)
}

impl std::fmt::Display for PathAwareValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (path, value): (String, serde_json::Value) = match self.try_into() {
            Ok(res) => res,
            Err(_) => return Err(std::fmt::Error)
        };
        f.write_fmt(
            format_args!(
                "Path={}, Value={}",
                path,
                value
            )
        )?;
        Ok(())
    }
}

impl<'value> std::fmt::Display for QueryResult<'value> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryResult::Resolved(r) => {
                f.write_fmt(
                    format_args!("(resolved, {})", r)
                )?;
            },

            QueryResult::UnResolved(ur) => {
                f.write_fmt(
                    format_args!("(unresolved, {})", ur.traversed_to)
                )?;
            }
        }
        Ok(())
    }
}

impl<'value> std::fmt::Display for ClauseCheck<'value> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ClauseCheck::Success => {
                f.write_fmt(format_args!("GuardClauseValueCheck(Status={})", Status::PASS))?;
            },

            ClauseCheck::NoValueForEmptyCheck => {
                f.write_fmt(format_args!("GuardClause(Status={}, Empty)", Status::FAIL))?;
            },

            ClauseCheck::MissingBlockValue(missing) => {
                f.write_fmt(
                    format_args!(
                        "GuardBlockValueMissing(Status={}, Reason={}, {})",
                        missing.status,
                        missing.message.as_ref().map_or("", String::as_str),
                        missing.from.unresolved_traversed_to().map_or("", |p| p.self_path().0.as_str())
                    )
                )?;
            },

            ClauseCheck::DependentRule(dependent) => {
                f.write_fmt(
                    format_args!(
                        "GuardClauseDependentRule(Rule={}, Status={})",
                        dependent.rule,
                        dependent.status,
                    )
                )?;
            },

            ClauseCheck::Unary(unary) => {
                f.write_fmt(
                    format_args!(
                        "GuardClauseUnaryCheck(Status={}, Comparison={}, Value-At={})",
                        unary.value.status,
                        display_comparison(unary.comparison),
                        unary.value.from
                    )
                )?;
            },

            ClauseCheck::Comparison(check) => {
                f.write_fmt(
                    format_args!(
                        "GuardClauseBinaryCheck(Status={}, Comparison={}, from={}, to={})",
                        check.status,
                        display_comparison(check.comparison),
                        check.from,
                        match &check.to {
                            Some(exists) => format!("{}", exists),
                            None => "".to_string(),
                        }
                    )
                )?;
            }
        }
        Ok(())
    }
}

impl<'value> std::fmt::Display for RecordType<'value> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            //
            // has as many child events for RuleCheck as there are rules in the file
            //
            RecordType::FileCheck(status) => {
                f.write_fmt(format_args!("File({}, Status={})", status.name, status.status))?;
            }

            //
            // has one optional RuleCondition check if when condition is present
            // has as many child events for each
            // TypeCheck | WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
            //
            RecordType::RuleCheck(status) => {
                f.write_fmt(format_args!("Rule({}, Status={})", status.name, status.status))?;
            },

            //
            // has as many child events for each GuardClauseBlockCheck | Disjunction
            //
            RecordType::RuleCondition(status) => {
                f.write_fmt(format_args!("Rule/When(Status={})", status))?;
            },

            //
            // has one optional TypeCondition event if when condition is present
            // has one TypeBlock for the block associated
            //
            RecordType::TypeCheck(block_check) => {
                f.write_fmt(format_args!("Type({}, Status={})", block_check.type_name, block_check.block.status))?;
            },

            //
            // has as many child events for each GuardClauseBlockCheck | Disjunction
            //
            RecordType::TypeCondition(status) => {
                f.write_fmt(format_args!("TypeBlock/When Status={})", status))?;
            },

            //
            // has as many child events for each Type value discovered
            // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
            //
            RecordType::TypeBlock(status) => {
                f.write_fmt(format_args!("TypeBlock/Block Status={})", status))?;
            },

            //
            // has many child events for
            // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
            //
            RecordType::Filter(status) => {
                f.write_fmt(format_args!("Filter/ConjunctionsBlock(Status={})", status))?;
            },

            //
            // has one WhenCondition event
            // has as many child events for each
            // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
            //
            RecordType::WhenCheck(BlockCheck{status, ..}) => {
                f.write_fmt(format_args!("WhenConditionalBlock(Status = {})", status))?;
            },

            //
            // has as many child events for each GuardClauseBlockCheck | Disjunction
            //
            RecordType::WhenCondition(status) => {
                f.write_fmt(format_args!("WhenCondition(Status = {})", status))?;
            },

            //
            // has as many child events for each
            // TypeCheck | WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
            // TypeCheck is only present as a part of the RuleBlock
            // Used for a IN operator event as well as IN is effectively a short-form for ORs
            //
            RecordType::Disjunction(BlockCheck{ status, ..}) => {
                f.write_fmt(format_args!("Disjunction(Status = {})", status))?;
            }

            //
            // has as many child events for each
            // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
            //
            RecordType::BlockGuardCheck(BlockCheck{status, ..}) => {
                f.write_fmt(format_args!("GuardValueBlockCheck(Status = {})", status))?;
            },

            //
            // has as many child events for each ClauseValueCheck
            //
            RecordType::GuardClauseBlockCheck(BlockCheck{status, ..}) => {
                f.write_fmt(format_args!("GuardClauseBlock(Status = {})", status))?;
            },

            //
            // one per value check, unary or binary
            //
            RecordType::ClauseValueCheck(check) => {
                check.fmt(f)?;
            },

        }
        Ok(())
    }
}

impl<'value> std::fmt::Display for EventRecord<'value> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(
            format_args!(
                "{}[Context={}]",
                self.container.as_ref().unwrap(),
                self.context
            )
        )?;
        Ok(())
    }
}