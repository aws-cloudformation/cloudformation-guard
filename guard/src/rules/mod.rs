#![allow(deprecated)]
pub(crate) mod display;
pub(crate) mod errors;
pub(crate) mod eval;
pub(crate) mod eval_context;
pub(crate) mod evaluate;
pub(crate) mod exprs;
pub(crate) mod functions;
mod libyaml;
pub(crate) mod parser;
pub(crate) mod path_value;
pub(crate) mod values;

use errors::Error;

use crate::rules::exprs::{ParameterizedRule, QueryPart};
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use colored::*;
use lazy_static::lazy_static;
use nom::lib::std::convert::TryFrom;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fmt::Formatter;
use std::rc::Rc;

pub(crate) type Result<R> = std::result::Result<R, Error>;

lazy_static! {
    pub static ref SHORT_FORM_TO_LONG_MAPPING: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Ref", "Ref");
        m.insert("GetAtt", "Fn::GetAtt");
        m.insert("Base64", "Fn::Base64");
        m.insert("Sub", "Fn::Sub");
        m.insert("GetAZs", "Fn::GetAZs");
        m.insert("ImportValue", "Fn::ImportValue");
        m.insert("Condition", "Condition");
        m.insert("RefAll", "Fn::RefAll");
        m.insert("Select", "Fn::Select");
        m.insert("Split", "Fn::Split");
        m.insert("Join", "Fn::Join");
        m.insert("FindInMap", "Fn::FindInMap");
        m.insert("And", "Fn::And");
        m.insert("Equals", "Fn::Equals");
        m.insert("Contains", "Fn::Contains");
        m.insert("EachMemberIn", "Fn::EachMemberIn");
        m.insert("EachMemberEquals", "Fn::EachMemberEquals");
        m.insert("ValueOf", "Fn::ValueOf");
        m.insert("If", "Fn::If");
        m.insert("Not", "Fn::Not");
        m.insert("Or", "Fn::Or");
        m
    };
    static ref SINGLE_VALUE_FUNC_REF: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("Ref");
        set.insert("Base64");
        set.insert("Sub");
        set.insert("GetAZs");
        set.insert("ImportValue");
        set.insert("GetAtt");
        set.insert("Condition");
        set.insert("RefAll");
        set
    };
    static ref SEQUENCE_VALUE_FUNC_REF: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("GetAtt");
        set.insert("Sub");
        set.insert("Select");
        set.insert("Split");
        set.insert("Join");
        set.insert("FindInMap");
        set.insert("And");
        set.insert("Equals");
        set.insert("Contains");
        set.insert("EachMemberIn");
        set.insert("EachMemberEquals");
        set.insert("ValueOf");
        set.insert("If");
        set.insert("Not");
        set.insert("Or");
        set
    };
}

#[derive(Debug, Clone, PartialEq, Copy, Serialize, Default)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum Status {
    PASS,
    FAIL,
    #[default]
    SKIP,
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
            _ => Err(Error::IncompatibleError(format!(
                "Status code is incorrect {value}",
            ))),
        }
    }
}
impl Status {
    fn and(&self, status: Status) -> Status {
        match self {
            Status::FAIL => Status::FAIL,
            Status::PASS => match status {
                Status::FAIL => status,
                _ => Status::PASS,
            },
            Status::SKIP => status,
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
    Clause,
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
pub(crate) struct UnResolved {
    pub(crate) traversed_to: Rc<PathAwareValue>,
    pub(crate) remaining_query: String,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum QueryResult {
    Literal(Rc<PathAwareValue>),
    Resolved(Rc<PathAwareValue>),
    UnResolved(UnResolved),
}

impl QueryResult {
    pub(crate) fn resolved(&self) -> Option<Rc<PathAwareValue>> {
        if let QueryResult::Resolved(res) = self {
            return Some(Rc::clone(res));
        }
        None
    }

    pub(crate) fn unresolved_traversed_to(&self) -> Option<Rc<PathAwareValue>> {
        if let QueryResult::UnResolved(res) = self {
            return Some(Rc::clone(&res.traversed_to));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ComparisonClauseCheck {
    pub(crate) comparison: (CmpOperator, bool),
    pub(crate) from: QueryResult,
    pub(crate) to: Option<QueryResult>, // happens with from is unresolved
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct InComparisonCheck {
    pub(crate) comparison: (CmpOperator, bool),
    pub(crate) from: QueryResult,
    pub(crate) to: Vec<QueryResult>, // happens with from is unresolved
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ValueCheck {
    pub(crate) from: QueryResult,
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UnaryValueCheck {
    pub(crate) value: ValueCheck,
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
    Comparison(ComparisonClauseCheck),
    InComparison(InComparisonCheck),
    Unary(UnaryValueCheck),
    NoValueForEmptyCheck(Option<String>),
    DependentRule(MissingValueCheck<'value>),
    MissingBlockValue(ValueCheck),
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
    pub(crate) message: Option<String>,
}

impl<'value> Default for NamedStatus<'value> {
    fn default() -> NamedStatus<'static> {
        NamedStatus {
            name: "",
            status: Status::PASS,
            message: None,
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
    Disjunction(BlockCheck), // in operator is a short-form for Disjunctions

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
    ClauseValueCheck(ClauseCheck<'value>),
}

pub(crate) trait RecordTracer<'value> {
    fn start_record(&mut self, context: &str) -> Result<()>;
    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()>;
}

pub(crate) trait EvalContext<'value, 'loc: 'value>: RecordTracer<'value> {
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>>;
    //fn resolve(&self, guard_clause: &GuardAccessClause<'_>) -> Result<Vec<QueryResult>>;
    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>>;
    fn root(&mut self) -> Rc<PathAwareValue>;
    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status>;
    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>>;
    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()>;
    fn add_variable_capture_index(&mut self, _: &str, _: Rc<PathAwareValue>) -> Result<()> {
        Ok(())
    }
}

pub(crate) trait EvaluationContext {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>>;

    fn rule_status(&self, rule_name: &str) -> Result<Status>;

    #[allow(clippy::too_many_arguments)]
    fn end_evaluation(
        &self,
        eval_type: EvaluationType,
        context: &str,
        msg: String,
        from: Option<PathAwareValue>,
        to: Option<PathAwareValue>,
        status: Option<Status>,
        comparator: Option<(CmpOperator, bool)>,
    );

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str);
}

pub(crate) trait Evaluate {
    fn evaluate<'s>(
        &self,
        context: &'s PathAwareValue,
        var_resolver: &'s dyn EvaluationContext,
    ) -> Result<Status>;
}

pub fn short_form_to_long(fn_ref: &str) -> &'static str {
    match SHORT_FORM_TO_LONG_MAPPING.get(fn_ref) {
        Some(fn_ref) => fn_ref,
        _ => unreachable!(),
    }
}
