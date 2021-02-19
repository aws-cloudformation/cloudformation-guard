pub(crate) mod errors;
pub(crate) mod evaluate;
pub(crate) mod exprs;
pub(crate) mod parser;
pub(crate) mod values;
pub(crate) mod path_value;


use errors::Error;
use values::Value;
use std::fmt::Formatter;
use colored::*;
use crate::rules::path_value::PathAwareValue;
use nom::lib::std::convert::TryFrom;
use crate::rules::errors::ErrorKind;
use serde::{Serialize};

pub(crate) type Result<R> = std::result::Result<R, Error>;

#[derive(Debug, Clone, PartialEq, Copy, Serialize)]
pub(crate) enum Status {
    PASS,
    FAIL,
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
            EvaluationType::Clause => f.write_str("Clause")?,
        }
        Ok(())
    }
}


pub(crate) trait EvaluationContext {
    fn resolve_variable(&self,
                        variable: &str) -> Result<Vec<&PathAwareValue>>;

    fn rule_status(&self, rule_name: &str) -> Result<Status>;

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<PathAwareValue>, to: Option<PathAwareValue>, status: Option<Status>);

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str);
}

pub(crate) trait Evaluate {
    fn evaluate<'s>(&self,
                context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status>;
}
