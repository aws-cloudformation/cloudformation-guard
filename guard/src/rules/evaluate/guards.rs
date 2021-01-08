use super::traits::*;

use std::collections::{
    HashMap,
    hash_map::Entry
};
use crate::rules::{
    values::*,
    exprs::{RulesFile, LetExpr, LetValue, Block, Rule, QueryPart, AccessQuery, GuardAccessClause, Conjunctions, SliceDisplay}
};

use crate::errors::{Error, ErrorKind};
use std::fmt::Formatter;
use crate::rules::exprs::{GuardNamedRuleClause, GuardClause};


struct FileScope<'s, 'loc> {
    rules: &'s RulesFile<'loc>,
    input_context: &'s Value,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'loc>>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s Value>>>,
    query_resolver: &'s dyn QueryResolver,
}

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

fn resolve_variable<'s, 'loc>(variable: &str,
                              queries: &HashMap<&'s str, &'s AccessQuery<'loc>>,
                              cache: &mut HashMap<&'s str, Vec<&'s Value>>,
                              context: &'s Value,
                              resolver: &dyn QueryResolver,
                              var_resolver: &dyn Resolver) -> Result<Vec<&'s Value>> {

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
                           var_resolver: &'s dyn Resolver) -> Result<Vec<&'s Value>> {

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

trait ChildScope : Resolver {
    fn resolve_variable(&self,
                        variable: &str) -> Result<Vec<&Value>> {
        match self.resolve_local(variable) {
            Ok(values) => Ok(values),
            Err(Error(ErrorKind::MissingVariable(e))) => match self.parent() {
                Some(parent) => parent.resolve_variable(variable),
                None => return Err(Error::new(ErrorKind::MissingVariable(e))),
            },
            Err(e) => return Err(e)
        }
    }

    fn resolve_local(&self,
                     variable: &str) -> Result<Vec<&Value>>;

    fn parent(&self) -> Option<&dyn Resolver>;
}

impl<'s, 'loc> FileScope<'s, 'loc> {
    pub(crate) fn new(rules: &'s RulesFile<'loc>,
                      value: &'s Value,
                      resolver: &'s dyn QueryResolver) -> Self {
        let mut variables = HashMap::new();
        let mut pending = HashMap::new();
        extract_variables(&rules.assignments,
                          &mut variables,
                          &mut pending);
        FileScope {
            rules,
            input_context: value,
            pending_queries: pending,
            variables: std::cell::RefCell::new(variables),
            query_resolver: resolver
        }
    }
}

impl<'s, 'loc> Resolver for FileScope<'s, 'loc> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }
        return if let Some((key, query)) = self.pending_queries.get_key_value(variable) {
            let values = self.query_resolver.resolve(0, *query, self, self.input_context)?;
            self.variables.borrow_mut().insert(*key, values.clone());
            Ok(values)
        } else {
            Err(Error::new(ErrorKind::MissingVariable(
                format!("Could not resolve variable {}", variable)
            )))
        }
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        unimplemented!()
    }
}

struct RuleScope<'r, 'loc> {
    rule: &'r Rule<'loc>,
    input_context: &'r Value,
    variables: std::cell::RefCell<HashMap<&'r str, Vec<&'r Value>>>,
    query_resolver: &'r dyn QueryResolver,
    parent: &'r dyn Resolver,
}

struct GuardAccessClauseScope<'r, 'loc> {
    guard: &'r GuardAccessClause<'loc>,
    input_context: &'r Value,
    query_resolver: &'r dyn QueryResolver,
    var_resolver: &'r dyn Resolver,
}

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

fn compare<F>(lhs: &Vec<&Value>, rhs: &Vec<&Value>, compare: F, any: bool) -> Result<(bool, Option<Value>, Option<Value>)>
    where F: Fn(&Value, &Value) -> Result<bool>
{
    let result = loop {
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
                var_resolver: &dyn Resolver) -> Result<Status> {
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
            return Ok(negation_status(r, clause.access_clause.comparator.1, clause.negation));
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
                    LetValue::Value(v) => vec![v],
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

        Ok(Status::PASS)
    }
}

impl<'loc> Evaluate for GuardNamedRuleClause<'loc> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn Resolver) -> Result<Status> {
        Ok(invert_status(
            var_resolver.rule_status(&self.dependent_rule)?,
            self.negation))
    }
}

impl<'loc> Evaluate for GuardClause<'loc> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn Resolver) -> Result<Status> {
        match self {
            GuardClause::Clause(gac) => gac.evaluate(context, var_resolver),
            GuardClause::NamedRule(nr) => nr.evaluate(context, var_resolver),
        }
    }
}

impl<'loc> Evaluate for Conjunctions<GuardClause<'loc>> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn Resolver) -> Result<Status> {
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

impl<'loc> Evaluate for RulesFile<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn Resolver) -> Result<Status> {
        struct InnerResolver{};
        impl QueryResolver for InnerResolver {
            fn resolve<'r>(&self, index: usize, query: &[QueryPart<'_>], var_resolver: &dyn Resolver, context: &'r Value) -> Result<Vec<&'r Value>> {
                Ok(vec![])
            }
        };
        let resolver = InnerResolver{};
        let file_scope = FileScope::new(self, context, &resolver);
        let resolved = file_scope.resolve_variable("var")?;
        println!("{:?}", resolved);
        Ok(Status::PASS)
    }
}

#[cfg(test)]
#[path = "guards_tests.rs"]
mod guards_tests;
