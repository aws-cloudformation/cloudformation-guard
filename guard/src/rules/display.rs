use crate::rules::eval_context::EventRecord;
use crate::rules::{RecordType, BlockCheck, ClauseCheck, Status, QueryResult};
use std::fmt::{Formatter, Display};
use crate::rules::values::{CmpOperator, RangeType, LOWER_INCLUSIVE, UPPER_INCLUSIVE};
use crate::rules::path_value::PathAwareValue;
use std::convert::TryInto;
use crate::rules::exprs::SliceDisplay;

pub(crate) fn display_comparison((cmp, not): (CmpOperator, bool)) -> String {
    format!("{} {}", if not { "not" } else { "" }, cmp)
}


fn write_range<T: Display + PartialOrd>(
    formatter: &mut Formatter<'_>,
    range: &RangeType<T>) -> std::fmt::Result
{
    if range.inclusive & LOWER_INCLUSIVE != 0 {
        formatter.write_str("[")?;
    }
    else {
        formatter.write_str("(")?;
    }
    range.lower.fmt(formatter)?;
    formatter.write_str(",")?;
    range.upper.fmt(formatter)?;
    if range.inclusive & UPPER_INCLUSIVE != 0 {
        formatter.write_str("]")?;
    }
    else {
        formatter.write_str(")")?;
    }
    Ok(())
}

pub(crate) struct ValueOnlyDisplay<'value>(pub(crate) &'value PathAwareValue);

impl<'value> std::fmt::Debug for ValueOnlyDisplay<'value> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let as_display = self as &dyn Display;
        as_display.fmt(f)
    }
}


impl<'value> Display for ValueOnlyDisplay<'value> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            PathAwareValue::Null(_path)                         => formatter.write_str("\"NULL\"")?,
            PathAwareValue::String((_path, value))      => formatter.write_fmt(
                format_args!("\"{}\"", value))?,
            PathAwareValue::Regex((_path, value))       => formatter.write_fmt(
                format_args!("\"/{}/\"", value))?,
            PathAwareValue::Bool((_path, value))        => formatter.write_fmt(
                format_args!("{}", value))?,
            PathAwareValue::Int((_path, value))             => formatter.write_fmt(
                format_args!("{}", value))?,
            PathAwareValue::Float((_path, value))                   => formatter.write_fmt(
                format_args!("{}", value))?,
            PathAwareValue::Char((_path, value))         => formatter.write_fmt(
                format_args!("\'{}\'", value))?,
            PathAwareValue::List((_path, list))         => {
                formatter.write_str("[")?;
                if !list.is_empty() {
                    let last = list.len()-1;
                    for (idx, each) in list.iter().enumerate() {
                        ValueOnlyDisplay(each).fmt(formatter)?;
                        if last != idx {
                            formatter.write_str(",")?;
                        }
                    }
                }
                formatter.write_str("]")?;
            },

            PathAwareValue::Map((_path, map))          => {
                formatter.write_str("{")?;
                if !map.is_empty() {
                    let last = map.values.len()-1;
                    for (idx, (key, value)) in map.values.iter().enumerate() {
                        formatter.write_fmt(
                            format_args!("\"{}\"", key))?;
                        formatter.write_str(":")?;
                        ValueOnlyDisplay(value).fmt(formatter)?;
                        if last != idx {
                            formatter.write_str(",")?;
                        }
                    }
                }
                formatter.write_str("}")?;

            },

            PathAwareValue::RangeInt((_path, value))    => write_range(formatter, value)?,
            PathAwareValue::RangeFloat((_path, value))   => write_range(formatter, value)?,
            PathAwareValue::RangeChar((_path, value))    => write_range(formatter, value)?,
        }
        Ok(())
    }
}

impl std::fmt::Display for PathAwareValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt( format_args!("Path={} Value=", self.self_path()))?;
        ValueOnlyDisplay(self).fmt(f)
    }
}

impl<'value> std::fmt::Display for QueryResult<'value> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryResult::Literal(l) => {
                f.write_fmt(
                    format_args!(
                        "literal, {}", l
                    )
                )?;
            },

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

            ClauseCheck::NoValueForEmptyCheck(message) => {
                f.write_fmt(format_args!(
                    "GuardClause(Status={}, Empty, {})",
                    Status::FAIL, message.as_ref().map_or("", |s| s.as_ref())))?;
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
            },

            ClauseCheck::InComparison(check) => {
                f.write_fmt(
                    format_args!(
                        "GuardClauseInBinaryCheck(Status={}, Comparison={}, from={}, to={})",
                        check.status,
                        display_comparison(check.comparison),
                        check.from,
                        SliceDisplay(&check.to),
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