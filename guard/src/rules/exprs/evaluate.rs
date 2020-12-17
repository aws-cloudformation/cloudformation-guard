use std::collections::hash_map::DefaultHasher;
use std::collections::hash_map::Entry;
use std::hash::{Hash, Hasher};

use crate::errors::{Error, ErrorKind};
use crate::rules::exprs::query::resolve_query;
use crate::rules::values::{CmpOperator, Value};

use super::scope::Scope;
use super::types::*;
use regex::internal::Input;

fn negation_status(r: bool, clause_not: bool, not: bool) -> Status {
    let status = if clause_not { !r } else { r };
    let status = if not { !status } else { status };
    if status { Status::PASS } else { Status::FAIL }
}

fn invert_status(status: Status, not: bool) -> Status {
    if not {
        return match status {
            Status::FAIL => Status::PASS,
            Status::PASS => Status::FAIL,
            Status::SKIP => Status::SKIP,
        }
    }
    status
}

#[derive(PartialEq, Debug, Clone)]
enum ValueType<'c> {
    Single(&'c Value),
    Query(&'c ResolvedValues<'c>)
}


impl GuardAccessClause<'_> {

    pub(super) fn evaluate<'c>(&'c self,
                               scope: &Scope<'_>,
                               eval_context: &mut EvalContext<'c>,
                               context: &'c Value,
                               path: Path) -> Result<EvalStatus, Error> {
        let key = Key{ query_key: &self.access_clause.query, context };
        let lhs = match eval_context.query_cache.get(&key) {
            Some(val) => Some(val),
            None => {
                match resolve_query(
                    &self.access_clause.query, context, scope, path.clone(), eval_context) {
                    Ok(r) => Some(&*eval_context.query_cache.entry(key).or_insert(r)),
                    Err(Error(ErrorKind::RetrievalError(_))) => None,
                    Err(e) => return Err(e),
                }
            }
        };

        //
        // Special case EXISTS, !EXISTS,
        //
        if CmpOperator::Exists == self.access_clause.comparator.0 {
            return Ok(EvalStatus::Unary(
                negation_status(lhs.is_some(),
                                 self.access_clause.comparator.1,
                                self.negation)));
        }

        //
        // Special case == null or != null
        //
        if let Some(LetValue::Value(Value::Null)) = &self.access_clause.compare_with {
            if CmpOperator::Eq == self.access_clause.comparator.0 {
                return Ok(EvalStatus::Unary(negation_status(
                    lhs.is_none(),
                    self.access_clause.comparator.1,
                    self.negation)))
            }
        }

        //
        // FAIL if LHS wasn't there
        //
        let lhs = match lhs {
            Some(v) => v,
            None => return Err(Error::new(ErrorKind::RetrievalError(
                format!("When check for {:?}, could for retrieve value for {:?}",
                        self.access_clause.comparator.0, self.access_clause.query)
            )))
        };

        //
        // The 2 other unary operators
        //
        match &self.access_clause.comparator {
            (CmpOperator::Empty, negation) |
            (CmpOperator::KeysEmpty, negation) => {
                return Ok(EvalStatus::Unary(
                    negation_status(lhs.is_empty(), *negation, self.negation)))
            }

            (_, _) => {}
        }

        //
        // Get RHS
        //

        //
        // Next comparison operations
        //


        Ok(EvalStatus::Unary(Status::FAIL))
    }

    pub(super) fn path(&self) -> Path {
        let line = self.access_clause.location.line.to_string();
        let col = self.access_clause.location.column.to_string();
        Path::new(&["rule", "clause", self.access_clause.location.file_name, &line, &col])
    }
}

impl GuardNamedRuleClause<'_> {

    pub(super) fn evaluate(&self,
                           eval_context: &mut EvalContext<'_>) -> Result<EvalStatus<'_>, Error> {
        match eval_context.rule_resolutions.get(&self.dependent_rule) {
            Some(status) => Ok(
                    EvalStatus::Unary(invert_status(*status, self.negation))),
            None => Err(Error::new(ErrorKind::MissingValue(
                format!("Dependent rule name {} does not exist", self.dependent_rule)
            )))
        }
    }

    pub(super) fn path(&self) -> Path {
        let line = self.location.line.to_string();
        let col = self.location.column.to_string();
        Path::new(&["rule", "clause", self.location.file_name, &line, &col])
    }
}

impl GuardClause<'_> {

    pub(super) fn evaluate<'c>(&'c self,
                               scope: &Scope<'_>,
                               eval_context: &mut EvalContext<'c>,
                               context: &'c Value,
                               path: Path) -> Result<EvalStatus<'c>, Error> {

        let status = match self {
            GuardClause::Clause(clause) => clause.evaluate(scope, eval_context, context, path)?,
            GuardClause::NamedRule(named) => named.evaluate(eval_context)?
        };
        eval_context.resolutions.insert(ResolutionKey{clause: self}, status.clone());
        Ok(status)
    }

    pub(super) fn path(&self) -> Path {
        match self {
            GuardClause::NamedRule(named) => named.path(),
            GuardClause::Clause(clause) => clause.path(),
        }
    }

}
