pub(crate) mod errors;
pub(crate) mod evaluate;
pub(crate) mod exprs;
pub(crate) mod parser;
pub(crate) mod values;
pub(crate) mod path_value;
pub(crate) mod eval_context;
pub(crate) mod eval;
pub(crate) mod display;
pub(crate) mod functions;

use errors::Error;

use std::fmt::Formatter;
use colored::*;
use crate::rules::path_value::PathAwareValue;
use nom::lib::std::convert::TryFrom;
use crate::rules::errors::ErrorKind;
use serde::{Serialize};
use crate::rules::values::CmpOperator;
use crate::rules::exprs::{QueryPart, GuardAccessClause, ParameterizedRule};
use crate::rules::eval_context::Scope;

pub(crate) type Result<R> = std::result::Result<R, Error>;

#[derive(Debug, Clone, PartialEq, Copy, Serialize)]
pub(crate) enum Status {
    PASS,
    FAIL,
    SKIP,
}

impl Default for Status {
    fn default() -> Self {
        Status::SKIP
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::PASS => f.write_str(&"PASS".green())?,
            Status::SKIP => f.write_str(&"SKIP".yellow())?,
            Status::FAIL => f.write_str(&"FAIL".red())?,
        }
        Ok(())
    }
}

impl TryFrom<&str> for Status {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "PASS" => Ok(Status::PASS),
            "FAIL" => Ok(Status::FAIL),
            "SKIP" => Ok(Status::SKIP),
            _ => Err(Error::new(ErrorKind::IncompatibleError(
                format!("Status code is incorrect {}", value)
            )))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Copy, Serialize)]
pub(crate) enum EvaluationType {
    File,
    Rule,
    Type,
    Condition,
    ConditionBlock,
    Filter,
    Conjunction,
    BlockClause,
    Clause
}

impl std::fmt::Display for EvaluationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationType::File => f.write_str("File")?,
            EvaluationType::Rule => f.write_str("Rule")?,
            EvaluationType::Type => f.write_str("Type")?,
            EvaluationType::Condition => f.write_str("Condition")?,
            EvaluationType::ConditionBlock => f.write_str("ConditionBlock")?,
            EvaluationType::Filter => f.write_str("Filter")?,
            EvaluationType::Conjunction => f.write_str("Conjunction")?,
            EvaluationType::BlockClause => f.write_str("BlockClause")?,
            EvaluationType::Clause => f.write_str("Clause")?,
        }
        Ok(())
    }
}


#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UnResolved<'value> {
    pub(crate) traversed_to: &'value PathAwareValue,
    pub(crate) remaining_query: String,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum QueryResult<'value> {
    Literal(&'value PathAwareValue),
    Resolved(&'value PathAwareValue),
    UnResolved(UnResolved<'value>),
}

impl<'value> QueryResult<'value> {
    pub(crate) fn resolved(&self) -> Option<&'value PathAwareValue> {
        if let QueryResult::Resolved(res) = self {
            return Some(*res)
        }
        None
    }

    pub(crate) fn unresolved_traversed_to(&self) -> Option<&'value PathAwareValue> {
        if let QueryResult::UnResolved(res) = self {
            return Some(res.traversed_to)
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ComparisonClauseCheck<'value> {
    pub(crate) comparison: (CmpOperator, bool),
    pub(crate) from: QueryResult<'value>,
    pub(crate) to: Option<QueryResult<'value>>, // happens with from is unresolved
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct InComparisonCheck<'value> {
    pub(crate) comparison: (CmpOperator, bool),
    pub(crate) from: QueryResult<'value>,
    pub(crate) to: Vec<QueryResult<'value>>, // happens with from is unresolved
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}


#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ValueCheck<'value> {
    pub(crate) from: QueryResult<'value>,
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UnaryValueCheck<'value> {
    pub(crate) value: ValueCheck<'value>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct MissingValueCheck<'value> {
    pub(crate) rule: &'value str,
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum ClauseCheck<'value> {
    Success,
    Comparison(ComparisonClauseCheck<'value>),
    InComparison(InComparisonCheck<'value>),
    Unary(UnaryValueCheck<'value>),
    NoValueForEmptyCheck(Option<String>),
    DependentRule(MissingValueCheck<'value>),
    MissingBlockValue(ValueCheck<'value>)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct TypeBlockCheck<'value> {
    pub(crate) type_name: &'value str,
    pub(crate) block: BlockCheck,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BlockCheck {
    pub(crate) at_least_one_matches: bool,
    pub(crate) status: Status,
    pub(crate) message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct NamedStatus<'value> {
    pub(crate) name: &'value str,
    pub(crate) status: Status,
    pub(crate) message: Option<String>
}

impl<'value> Default for NamedStatus<'value> {
    fn default() -> NamedStatus<'static> {
        NamedStatus {
            name: "",
            status: Status::PASS,
            message: None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum RecordType<'value> {
    //
    // has as many child events for RuleCheck as there are rules in the file
    //
    FileCheck(NamedStatus<'value>),

    //
    // has one optional RuleCondition check if when condition is present
    // has as many child events for each
    // TypeCheck | WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    RuleCheck(NamedStatus<'value>),

    //
    // has as many child events for each GuardClauseBlockCheck | Disjunction
    //
    RuleCondition(Status),

    //
    // has one optional TypeCondition event if when condition is present
    // has one TypeBlock for the block associated
    //
    TypeCheck(TypeBlockCheck<'value>),

    //
    // has as many child events for each GuardClauseBlockCheck | Disjunction
    //
    TypeCondition(Status),

    //
    // has as many child events for each Type value discovered
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    TypeBlock(Status),

    //
    // has many child events for
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    Filter(Status),

    //
    // has one WhenCondition event
    // has as many child events for each
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    WhenCheck(BlockCheck),

    //
    // has as many child events for each GuardClauseBlockCheck | Disjunction
    //
    WhenCondition(Status),

    //
    // has as many child events for each
    // TypeCheck | WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    // TypeCheck is only present as a part of the RuleBlock
    // Used for a IN operator event as well as IN is effectively a short-form for ORs
    //
    Disjunction(BlockCheck),  // in operator is a short-form for Disjunctions

    //
    // has as many child events for each
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    BlockGuardCheck(BlockCheck),

    //
    // has as many child events for each ClauseValueCheck
    //
    GuardClauseBlockCheck(BlockCheck),

    //
    // one per value check, unary or binary
    //
    ClauseValueCheck(ClauseCheck<'value>)
}

struct ParameterRuleResult<'value, 'loc> {
    rule: &'value ParameterizedRule<'loc>
}

pub(crate) trait RecordTracer<'value> {
    fn start_record(&mut self, context: &str) -> Result<()>;
    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()>;
}

pub(crate) trait EvalContext<'value, 'loc: 'value> : RecordTracer<'value> {
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>>;
    //fn resolve(&self, guard_clause: &GuardAccessClause<'_>) -> Result<Vec<QueryResult<'value>>>;
    fn find_parameterized_rule(&mut self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>>;
    fn root(&mut self) -> &'value PathAwareValue;
    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status>;
    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>>;
    fn add_variable_capture_key(&mut self, variable_name: &'value str, key: &'value PathAwareValue) -> Result<()>;
    fn add_variable_capture_index(&mut self, variable_name: &str, index: &'value PathAwareValue) -> Result<()> { Ok(()) }
}

pub(crate) trait EvaluationContext {
    fn resolve_variable(&self,
                        variable: &str) -> Result<Vec<&PathAwareValue>>;

    fn rule_status(&self, rule_name: &str) -> Result<Status>;

    fn end_evaluation(
        &self,
        eval_type: EvaluationType,
        context: &str,
        msg: String,
        from: Option<PathAwareValue>,
        to: Option<PathAwareValue>,
        status: Option<Status>,
        comparator: Option<(CmpOperator, bool)>
    );

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str);
}

pub(crate) trait Evaluate {
    fn evaluate<'s>(&self,
                context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status>;
}
