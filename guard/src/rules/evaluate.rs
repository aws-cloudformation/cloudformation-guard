use std::collections::{
    hash_map::Entry,
    HashMap
};
use std::convert::TryFrom;
use std::fmt::Formatter;

use colored::Colorize;

use crate::rules::{Evaluate, EvaluationContext, Result, Status};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::exprs::{GuardClause, GuardNamedRuleClause, RuleClause, TypeBlock};
use crate::rules::exprs::{AccessQuery, Block, Conjunctions, GuardAccessClause, LetExpr, LetValue, QueryPart, Rule, RulesFile, SliceDisplay};
use crate::rules::parser::AccessQueryWrapper;
use crate::rules::values::*;

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
//  Implementation for Guard Evaluations                                                        //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////

fn resolve_variable<'s, 'loc>(variable: &str,
                              queries: &HashMap<&'s str, &'s AccessQuery<'loc>>,
                              cache: &mut HashMap<&'s str, Vec<&'s Value>>,
                              context: &'s Value,
                              var_resolver: &dyn EvaluationContext) -> Result<Vec<&'s Value>> {

    return if let Some((key, query)) = queries.get_key_value(variable) {
        let values = context.query(0, *query, var_resolver)?;
        cache.insert(*key, values.clone());
        Ok(values)
    } else {
        Err(Error::new(ErrorKind::MissingVariable(
            format!("Could not resolve variable {}", variable)
        )))
    }
}

fn resolve_query<'s, 'loc>(query: &'s AccessQuery<'loc>,
                           context: &'s Value,
                           var_resolver: &'s dyn EvaluationContext) -> Result<Vec<&'s Value>> {

    let (resolved, index) = if let Some(var) = query[0].variable() {
        (var_resolver.resolve_variable(var)?, 1 as usize)
    } else {
        (vec![context], 0 as usize)
    };

    let mut expanded = Vec::with_capacity(resolved.len());
    for each in resolved {
        expanded.extend(each.query(index, query, var_resolver)?)
    }
    Ok(expanded)
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

fn negation_status(r: bool, clause_not: bool, not: bool) -> Status {
    let status = if clause_not { !r } else { r };
    let status = if not { !status } else { status };
    if status { Status::PASS } else { Status::FAIL }
}


fn compare<F>(lhs: &Vec<&Value>, rhs: &Vec<&Value>, compare: F, any: bool) -> Result<(bool, Option<Value>, Option<Value>)>
    where F: Fn(&Value, &Value) -> Result<bool>
{
    loop {
        'lhs:
        for lhs_value in lhs {
            for rhs_value in rhs {
                let check = compare(*lhs_value, *rhs_value)?;
                if any && check {
                    continue 'lhs
                }

                if !any && !check {
                    return Ok((false, Some((*lhs_value).clone()), Some((*rhs_value).clone())))
                }
            }
            //
            // We are only hear in the "all" case when all of them checked out. For the any case
            // it would be a failure to be here
            //
            if any {
                return Ok((false, Some((*lhs_value).clone()), None))
            }
        }
        break;
    };
    Ok((true, None, None))
}

impl<'loc> Evaluate for GuardAccessClause<'loc> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        let clause = self;

        let lhs = match resolve_query(
            &clause.access_clause.query,  context, var_resolver) {
            Ok(values) => Some(values),
            Err(Error(ErrorKind::RetrievalError(_))) => None,
            Err(e) => return Err(e),
        };

        let result = match &clause.access_clause.comparator.0 {
            CmpOperator::Empty |
            CmpOperator::KeysEmpty=>
                match &lhs { None => Some(false), Some(l) => Some(l.is_empty()) }

            CmpOperator::Exists => match &lhs { None => Some(false), Some(_) => Some(true) }

            CmpOperator::Eq => match &clause.access_clause.compare_with {
                Some(LetValue::Value(Value::Null)) =>
                    match &lhs { None => Some(true), Some(_) => Some(false), }
                _ => None
            }

            _ => None
        };

        if let Some(r) = result {
            let status = negation_status(r, clause.access_clause.comparator.1, clause.negation);
            let message = format!("Guard@{}", self.access_clause.location);
            var_resolver.report_status(message, None, None, status);
            return Ok(status)
        }

        let lhs = match lhs {
            None => return Err(Error::new(ErrorKind::RetrievalError(
                format!("Expecting a resolved LHS {} for comparison and did not find one, Clause@{}",
                        SliceDisplay(&clause.access_clause.query),
                        clause.access_clause.location)
            ))),

            Some(l) => l,
        };

        let rhs = match &clause.access_clause.compare_with {
            None => return Err(Error::new(ErrorKind::IncompatibleError(
                format!("Expecting a RHS for comparison and did not find one, clause@{}",
                        clause.access_clause.location)
            ))),

            Some(expr) => {
                match expr {
                    LetValue::Value(v) => {
                        if let Value::List(l) = v {
                            l.iter().collect()
                        } else {
                            vec![v]
                        }
                    },
                    LetValue::AccessClause(query) =>
                        resolve_query(query, context, var_resolver)?,
                }
            }
        };

        let result = match &clause.access_clause.comparator.0 {
            //
            // ==, !=
            //
            CmpOperator::Eq =>
                compare(&lhs, &rhs, compare_eq, false)?,

            //
            // >
            //
            CmpOperator::Gt =>
                compare(&lhs, &rhs, compare_gt, false)?,

            //
            // >=
            //
            CmpOperator::Ge =>
                compare(&lhs, &rhs, compare_ge, false)?,

            //
            // <
            //
            CmpOperator::Lt =>
                compare(&lhs, &rhs, compare_lt, false)?,

            //
            // <=
            //
            CmpOperator::Le =>
                compare(&lhs, &rhs, compare_le, false)?,

            //
            // IN, !IN
            //
            CmpOperator::In =>
                compare(&lhs, &rhs, compare_eq, true)?,

            CmpOperator::KeysEq |
            CmpOperator::KeysIn => {
                let mut lhs_vec_keys = Vec::with_capacity(lhs.len());
                for lhs_value in lhs {
                    if let Value::Map(index) = lhs_value {
                        for keys in index.keys() {
                            lhs_vec_keys.push(Value::String(keys.to_string()));
                        }
                    }
                    else {
                        return Err(Error::new(ErrorKind::IncompatibleError(
                            format!("Attempting to resolve Clause@{} for query {}, expecting map-type for KEYS comparator found {}",
                                    clause.access_clause.location,
                                    SliceDisplay(&clause.access_clause.query),
                                    type_info(lhs_value)
                            )
                        )))
                    }
                }

                let lhs_vec_ref = lhs_vec_keys.iter()
                    .map(|v| v).collect::<Vec<&Value>>();

                if clause.access_clause.comparator.0 == CmpOperator::KeysIn {
                    compare(&lhs_vec_ref, &rhs, compare_eq, true)?
                }
                else {
                    compare(&lhs_vec_ref, &rhs, compare_eq, false)?
                }
            }

            _ => unreachable!()

        };

        let status = negation_status(result.0, clause.access_clause.comparator.1, clause.negation);
        let message = format!("Guard@{}, Status = {}, Clause = {}, Message = {}", clause.access_clause.location,
            match status {
                Status::PASS => "PASS".green(),
                Status::FAIL => "FAIL".red(),
                Status::SKIP => "SKIP".yellow()
            },
            SliceDisplay(&clause.access_clause.query),
            match &clause.access_clause.custom_message {
                Some(msg) => msg,
                None => "(default completed evaluation)"
            }
        );
        var_resolver.report_status(message, result.1, result.2, status);
        Ok(status)
    }
}

impl<'loc> Evaluate for GuardNamedRuleClause<'loc> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        Ok(invert_status(
            var_resolver.rule_status(&self.dependent_rule)?,
            self.negation))
    }
}

impl<'loc> Evaluate for GuardClause<'loc> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        match self {
            GuardClause::Clause(gac) => gac.evaluate(context, var_resolver),
            GuardClause::NamedRule(nr) => nr.evaluate(context, var_resolver),
        }
    }
}

impl<T: Evaluate> Evaluate for Conjunctions<T> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        'conjunction:
        for conjunction in self {
            for disjunction in conjunction {
                if Status::PASS == disjunction.evaluate(context, var_resolver)? {
                    continue 'conjunction;
                }
            }
            return Ok(Status::FAIL);
        }
        Ok(Status::PASS)
    }
}

impl<'loc> Evaluate for TypeBlock<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
        if let Some(conditions) = &self.conditions {
            match conditions.evaluate(context, var_resolver)? {
                Status::PASS => {},
                _ => return Ok(Status::SKIP)
            }
        }

        let query = format!("Resources.*[ Type == \"{}\" ]", self.type_name);
        let cfn_query = AccessQueryWrapper::try_from(query.as_str())?.0;
        let values = match context.query(0, &cfn_query, var_resolver) {
            Ok(v) => if v.is_empty() { vec![context] } else { v }
            Err(_) => vec![context]
        };
        for each in values {
            let block_scope = BlockScope::new(&self.block, each, var_resolver);
            if Status::FAIL == self.block.conjunctions.evaluate(each, &block_scope)? {
                return Ok(Status::FAIL)
            }
        }
        Ok(Status::PASS)
    }
}

impl<'loc> Evaluate for RuleClause<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
        match self {
            RuleClause::Clause(gc) => gc.evaluate(context, var_resolver),
            RuleClause::TypeBlock(tb) => tb.evaluate(context, var_resolver),
            RuleClause::WhenBlock(conditions, block) =>
                match conditions.evaluate(context, var_resolver)? {
                    Status::PASS => {
                        let block_scope = BlockScope::new(block, context, var_resolver);
                        block.conjunctions.evaluate(context, &block_scope)
                    },
                    _ => Ok(Status::SKIP)
                }
        }
    }
}

impl<'loc> Evaluate for Rule<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
        if let Some(conds) = &self.conditions {
            match conds.evaluate(context, var_resolver)? {
                Status::PASS => {},
                _ => return Ok(Status::SKIP)
            }
        }

        let block_scope = BlockScope::new(&self.block, context, var_resolver);
        match self.block.conjunctions.evaluate(context, &block_scope) {
            Ok(status) => {
                let message = format!("Rule@{}, Status = {:?}", self.rule_name, status);
                var_resolver.report_status(message, None, None, status);
                return Ok(status)
            },
            other => other
        }
    }
}

impl<'loc> Evaluate for RulesFile<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
        let mut overall = Status::PASS;
        for rule in &self.guard_rules {
            if Status::FAIL == rule.evaluate(context, var_resolver)? {
                overall = Status::FAIL
            }
        }
        Ok(overall)
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
// Evaluation Context implementations for scoped variables                                      //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////


fn extract_variables<'s, 'loc>(expressions: &'s Vec<LetExpr<'loc>>,
                               vars: &mut HashMap<&'s str, Vec<&'s Value>>,
                               queries: &mut HashMap<&'s str, &'s AccessQuery<'loc>>) {
    for each in expressions {
        match &each.value {
            LetValue::Value(v) => {
                vars.insert(&each.var, vec![v]);
            },

            LetValue::AccessClause(query) => {
                queries.insert(&each.var, query);
            }
        }
    }
}

pub(crate) struct RootScope<'s, 'loc> {
    rules: &'s RulesFile<'loc>,
    input_context: &'s Value,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'loc>>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s Value>>>,
    rule_by_name: HashMap<&'s str, &'s Rule<'loc>>,
    rule_statues: std::cell::RefCell<HashMap<&'s str, Status>>,
}

impl<'s, 'loc> RootScope<'s, 'loc> {
    pub(crate) fn new(rules: &'s RulesFile<'loc>,
                      value: &'s Value) -> Self {
        let mut literals = HashMap::new();
        let mut pending = HashMap::new();
        extract_variables(&rules.assignments,
                          &mut literals,
                          &mut pending);
        let mut lookup_cache = HashMap::with_capacity(rules.guard_rules.len());
        for rule in &rules.guard_rules {
            lookup_cache.insert(rule.rule_name.as_str(), rule);
        }
        RootScope {
            rules,
            input_context: value,
            pending_queries: pending,
            variables: std::cell::RefCell::new(literals),
            rule_by_name: lookup_cache,
            rule_statues: std::cell::RefCell::new(HashMap::with_capacity(rules.guard_rules.len())),
        }
    }
}

impl<'s, 'loc> EvaluationContext for RootScope<'s, 'loc> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }
        return if let Some((key, query)) = self.pending_queries.get_key_value(variable) {
            let values = self.input_context.query(0, *query, self)?;
            self.variables.borrow_mut().insert(*key, values.clone());
            Ok(values)
        } else {
            Err(Error::new(ErrorKind::MissingVariable(
                format!("Could not resolve variable {}", variable)
            )))
        }
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        if let Some(status) = self.rule_statues.borrow().get(rule_name) {
            return Ok(*status)
        }

        if let Some((name, rule)) = self.rule_by_name.get_key_value(rule_name) {
            let status = (*rule).evaluate(self.input_context, self)?;
            self.rule_statues.borrow_mut().insert(*name, status);
            return Ok(status)
        }

        Err(Error::new(ErrorKind::MissingValue(
            format!("Attempting to resolve rule_status for rule = {}, rule not found", rule_name)
        )))
    }

    fn report_status(&self, msg: String, from: Option<Value>, to: Option<Value>, status: Status) {}
}

pub(crate) struct BlockScope<'s, T> {
    block_type: &'s Block<'s, T>,
    input_context: &'s Value,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'s>>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s Value>>>,
    parent: &'s dyn EvaluationContext,
}

impl<'s, T> BlockScope<'s, T> {
    pub(crate) fn new(block_type: &'s Block<'s, T>, context: &'s Value, parent: &'s dyn EvaluationContext) -> Self {
        let mut literals = HashMap::new();
        let mut pending = HashMap::new();
        extract_variables(&block_type.assignments,
                          &mut literals,
                          &mut pending);
        BlockScope {
            block_type,
            input_context: context,
            parent,
            variables: std::cell::RefCell::new(literals),
            pending_queries: pending,
        }
    }
}

impl<'s, T> EvaluationContext for BlockScope<'s, T> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }

        return if let Some((key, query)) = self.pending_queries.get_key_value(variable) {
            let values = self.input_context.query(0, *query, self)?;
            self.variables.borrow_mut().insert(*key, values.clone());
            Ok(values)
        } else {
            self.parent.resolve_variable(variable)
        }
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn report_status(&self, msg: String, from: Option<Value>, to: Option<Value>, status: Status) {
        self.parent.report_status(msg, from, to, status)
    }
}

#[cfg(test)]
#[path = "evaluate_tests.rs"]
mod evaluate_tests;
